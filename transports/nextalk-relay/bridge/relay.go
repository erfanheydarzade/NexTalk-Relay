// Relay HTTP client: Router (/register, /resolve) + shard (/send, /read).
//
// Semantics mirror NexTalk's internal/relay/worker adapter exactly — same
// signed-message formats, same base64 framing — so the bridge behaves like
// any other Relay client. The difference is identity: the bridge signs with
// its own courier/scoped keys (see main.go), never user keys. The true
// sender lives inside the opaque E2E frame.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type capability struct {
	MailboxID        string   `json:"mailbox_id"`
	ReadSecret       string   `json:"read_secret"`
	ShardURL         string   `json:"shard_url"`
	ReplicaShardURLs []string `json:"replica_shard_urls"`
	ExpiresAt        int64    `json:"expires_at"`
	TableVersion     int      `json:"table_version"`
}

type resolution struct {
	MailboxID        string   `json:"mailbox_id"`
	ShardURL         string   `json:"shard_url"`
	ReplicaShardURLs []string `json:"replica_shard_urls"`
	Era              int      `json:"era"`
	TableVersion     int      `json:"table_version"`
	// Note is set by the Router when it could not confirm the mailbox
	// exists on any era and is returning a current-era guess instead
	// (router.js handleResolve, final return). The response is still 200
	// with a well-formed mailbox_id, so without reading this field the
	// miss stays invisible until the shard answers 404 on /send.
	Note string `json:"note"`
}

// errMailboxNotRegistered means the pubkey resolves to a well-formed address
// that has never been provisioned — the recipient has not registered this
// identity with the Router. Distinct from a transport failure: retrying will
// not help until they register.
var errMailboxNotRegistered = errors.New("recipient mailbox is not registered on the relay (they must register this identity's pubkey with the Router)")

type senderAuth struct {
	PubKey    string `json:"pubkey"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

type relayClient struct {
	http *http.Client
}

func newRelayClient() *relayClient {
	return &relayClient{http: &http.Client{Timeout: 15 * time.Second}}
}

// signRegister proves ownership of priv to the Router:
// `register:{pubkeyLowerHex}:{timestampMs}` (see router.js handleRegister).
func signRegister(priv ed25519.PrivateKey) (pubHex, timestamp, sigHex string) {
	pub := priv.Public().(ed25519.PublicKey)
	pubHex = hex.EncodeToString(pub)
	timestamp = strconv.FormatInt(time.Now().UnixMilli(), 10)
	sig := ed25519.Sign(priv, []byte("register:"+pubHex+":"+timestamp))
	return pubHex, timestamp, hex.EncodeToString(sig)
}

func (c *relayClient) register(ctx context.Context, routerURL string, priv ed25519.PrivateKey) (*capability, error) {
	pubHex, ts, sig := signRegister(priv)
	raw, _ := json.Marshal(map[string]string{"pubkey": pubHex, "timestamp": ts, "signature": sig})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(routerURL, "/")+"/register", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, readRelayError(resp)
	}
	var cap capability
	if err := json.NewDecoder(resp.Body).Decode(&cap); err != nil {
		return nil, fmt.Errorf("register: decode: %w", err)
	}
	if cap.MailboxID == "" || cap.ReadSecret == "" || cap.ShardURL == "" {
		return nil, fmt.Errorf("register: incomplete capability")
	}
	return &cap, nil
}

func (c *relayClient) resolve(ctx context.Context, routerURL string, recipientPub []byte) (*resolution, error) {
	target := fmt.Sprintf("%s/resolve?pubkey=%s", strings.TrimRight(routerURL, "/"), url.QueryEscape(hex.EncodeToString(recipientPub)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, readRelayError(resp)
	}
	var res resolution
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("resolve: decode: %w", err)
	}
	if res.MailboxID == "" || res.ShardURL == "" {
		return nil, fmt.Errorf("resolve: incomplete resolution")
	}
	// Unconfirmed guess: fail here with a diagnosis rather than letting the
	// caller send into a mailbox that does not exist and get a bare 404.
	if res.Note != "" {
		return &res, fmt.Errorf("resolve %s: %w (router: %s)",
			hex.EncodeToString(recipientPub), errMailboxNotRegistered, res.Note)
	}
	return &res, nil
}

// buildSenderAuth signs the message a shard's /send handler verifies:
// `send:{senderPubkeyLowerHex}:{mailboxIdLowerHex}:{timestamp}:{sha256hex(message)}`
// where message is the exact base64 string transmitted (see shard/worker.js
// handleSend and NexTalk's relay.BuildSenderAuth).
func buildSenderAuth(priv ed25519.PrivateKey, mailboxID, message string) senderAuth {
	pub := priv.Public().(ed25519.PublicKey)
	senderHex := hex.EncodeToString(pub)
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	sum := sha256.Sum256([]byte(message))
	signed := fmt.Sprintf("send:%s:%s:%s:%s", senderHex, strings.ToLower(mailboxID), timestamp, hex.EncodeToString(sum[:]))
	sig := ed25519.Sign(priv, []byte(signed))
	return senderAuth{PubKey: senderHex, Timestamp: timestamp, Signature: hex.EncodeToString(sig)}
}

type sendBody struct {
	MailboxID string     `json:"mailbox_id"`
	Message   string     `json:"message"`
	Sender    senderAuth `json:"sender"`
}

// sendToShard delivers one opaque frame to a full relay mailbox_id.
// Frames cross the relay base64-wrapped; the shard hashes the exact string.
func (c *relayClient) sendToShard(ctx context.Context, shardURL, mailboxID string, frame, senderPriv []byte) error {
	encoded := base64.StdEncoding.EncodeToString(frame)
	auth := buildSenderAuth(ed25519.PrivateKey(senderPriv), mailboxID, encoded)
	raw, _ := json.Marshal(sendBody{MailboxID: strings.ToLower(mailboxID), Message: encoded, Sender: auth})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(shardURL, "/")+"/send", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("send to %s: %w", shardURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return readRelayError(resp)
	}
	var result struct {
		Success bool `json:"success"`
		Queued  int  `json:"queued"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("send: decode: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("send: shard %s rejected the message", shardURL)
	}
	return nil
}

type readResponse struct {
	Messages []struct {
		ID           string `json:"id"`
		Time         int64  `json:"time"`
		Message      string `json:"message"`
		SenderPubkey string `json:"senderPubkey"`
	} `json:"messages"`
	Count     int   `json:"count"`
	CreatedAt int64 `json:"createdAt"`
	Consumed  bool  `json:"consumed"`
}

// readFromShard drains one full relay mailbox_id via its read_secret bearer.
// Returns opaque frames (base64-decoded; non-base64 bodies pass through raw,
// matching the worker adapter's tolerance).
func (c *relayClient) readFromShard(ctx context.Context, shardURL, mailboxID, readSecret string) ([][]byte, error) {
	q := url.Values{"mailbox_id": {mailboxID}, "read_secret": {readSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(shardURL, "/")+"/read?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read from %s: %w", shardURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, readRelayError(resp)
	}
	var parsed readResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("read: decode: %w", err)
	}
	out := make([][]byte, 0, len(parsed.Messages))
	for _, m := range parsed.Messages {
		decoded, err := base64.StdEncoding.DecodeString(m.Message)
		if err != nil {
			decoded = []byte(m.Message)
		}
		out = append(out, decoded)
	}
	return out, nil
}

// candidateShardURLs returns primary followed by any other replicas, no
// duplicates — tolerates single-shard deployments (empty replica list).
func candidateShardURLs(primary string, replicas []string) []string {
	seen := map[string]bool{primary: true}
	out := []string{primary}
	for _, u := range replicas {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

type relayErrorBody struct {
	Error string `json:"error"`
}

func readRelayError(resp *http.Response) error {
	const maxSnippet = 200
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxSnippet+1))
	var apiErr relayErrorBody
	if json.Unmarshal(raw, &apiErr) == nil && apiErr.Error != "" {
		return fmt.Errorf("relay status %d: %s", resp.StatusCode, apiErr.Error)
	}
	if len(raw) > 0 {
		return fmt.Errorf("relay status %d: %q", resp.StatusCode, string(raw))
	}
	return fmt.Errorf("relay status %d", resp.StatusCode)
}