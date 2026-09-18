// Command nextalk-relay-bridge is the NexTalk runtime transport for
// NexTalk-Relay (Cloudflare Workers mailbox relay).
//
// Courier model: the bridge owns its own throwaway ed25519 identities and
// never sees user private keys. Core passes opaque frames, recipient
// pubkeys, per-mailbox read_secret bearers, and URLs:
//
//   - send: the bridge signs the shard /send auth with its COURIER key
//     (courier.key next to the binary, 0600). The true sender lives inside
//     the E2E-encrypted NexTalk frame, which the bridge treats as opaque.
//   - register: per-user-tag SCOPED keys (scoped-<tag>.key, 0600) prove
//     ownership to the Router's /register. They control mailbox
//     registration and courier-signed sends only — they cannot decrypt
//     NexTalk traffic and cannot impersonate the NexTalk identity.
//
// Mailbox aliasing: Relay mailbox IDs are 32 bytes (HMAC-SHA256 hex) but the
// transport API fixes mailbox fields at 16 bytes. The bridge therefore hands
// core deterministic 16-byte aliases (aliasFor = sha256(fullID)[:16]) and
// keeps the alias → full-ID binding in mailbox-map.json (0600) next to the
// binary. Every alias the bridge ever returns (register, resolve) is
// recorded there; attach/send/poll expand aliases back before talking HTTP.
//
// Usage: nextalk-relay-bridge --ntx-serve   (stdio RPC; stderr = logs)
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

type binding struct {
	MailboxID  string `json:"mailbox_id"`             // full relay mailbox id (lowercase hex)
	ReadSecret string `json:"read_secret,omitempty"`  // full read secret (hex), when known
	ShardURL   string `json:"shard_url"`
	RouterURL  string `json:"router_url,omitempty"`
}

type bridge struct {
	mu        sync.Mutex
	running   bool
	courierPriv ed25519.PrivateKey
	scoped    map[string]ed25519.PrivateKey // userTag -> key
	routerURL string                        // default from initialize config
	relay     *relayClient
	dir       string
	aliases   map[string]*binding // aliasHex -> binding
	attached  map[string]*binding // aliasHex -> live attachment (secret + shard)
}

type bridgeConfig struct {
	RouterURL string `json:"router_url"`
	ShardURL  string `json:"shard_url"`
}

var tagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// aliasFor derives the deterministic 16-byte transport alias for a full
// relay mailbox ID (32 raw bytes). One-way: the reverse lookup lives in
// mailbox-map.json, written at every register/resolve/attach.
func aliasFor(fullMailboxID []byte) []byte {
	sum := sha256.Sum256(fullMailboxID)
	return sum[:16]
}

func bridgeDir() string {
	if v := os.Getenv("NTX_BRIDGE_DIR"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return "."
}

func newBridge() *bridge {
	return &bridge{
		relay:    newRelayClient(),
		dir:      bridgeDir(),
		scoped:   map[string]ed25519.PrivateKey{},
		aliases:  map[string]*binding{},
		attached: map[string]*binding{},
	}
}

func main() {
	// Helper: nextalk-relay-bridge wrap --type 3 -f payload.bin > frame.bin
	// prepends the layer-1 type byte (offer=1 answer=2 message=3 multimsg=4).
	if len(os.Args) > 1 && os.Args[1] == "wrap" {
		fs := flag.NewFlagSet("wrap", flag.ExitOnError)
		typ := fs.Int("type", 3, "frame type byte (1..4)")
		file := fs.String("f", "", "payload file")
		_ = fs.Parse(os.Args[2:])
		if *typ < 1 || *typ > 4 || *file == "" {
			fmt.Fprintln(os.Stderr, "wrap: --type 1..4 and -f file required")
			os.Exit(2)
		}
		raw, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wrap:", err)
			os.Exit(1)
		}
		out := make([]byte, 1+len(raw))
		out[0] = byte(*typ)
		copy(out[1:], raw)
		if _, err := os.Stdout.Write(out); err != nil {
			os.Exit(1)
		}
		return
	}
	serve := flag.Bool("ntx-serve", false, "serve NexTalk transport RPC on stdio")
	flag.Parse()
	if !*serve {
		fmt.Fprintln(os.Stderr, "usage: nextalk-relay-bridge --ntx-serve")
		os.Exit(2)
	}
	b := newBridge()
	if err := b.loadOrCreateCourierKey(); err != nil {
		fmt.Fprintln(os.Stderr, "courier key:", err)
		os.Exit(1)
	}
	b.loadAliases()
	b.serveLoop()
}

// loadOrCreateCourierKey keeps the courier identity next to the binary
// (NTX_BRIDGE_DIR overrides for tests).
func (b *bridge) loadOrCreateCourierKey() error {
	path := filepath.Join(b.dir, "courier.key")
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) == ed25519.PrivateKeySize {
			b.courierPriv = ed25519.PrivateKey(append([]byte(nil), raw...))
			return nil
		}
		return fmt.Errorf("bad courier.key length %d", len(raw))
	}
	if !os.IsNotExist(err) {
		return err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return err
	}
	b.courierPriv = priv
	return nil
}

// scopedKey loads or mints the per-user-tag identity used for Router
// /register. Distinct from the NexTalk identity by construction.
func (b *bridge) scopedKey(userTag string) (ed25519.PrivateKey, error) {
	if !tagRe.MatchString(userTag) {
		return nil, fmt.Errorf("bad user tag %q", userTag)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if k, ok := b.scoped[userTag]; ok {
		return k, nil
	}
	path := filepath.Join(b.dir, "scoped-"+userTag+".key")
	if raw, err := os.ReadFile(path); err == nil {
		if len(raw) == ed25519.PrivateKeySize {
			k := ed25519.PrivateKey(append([]byte(nil), raw...))
			b.scoped[userTag] = k
			return k, nil
		}
		return nil, fmt.Errorf("bad scoped key file")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, err
	}
	b.scoped[userTag] = priv
	return priv, nil
}

// bgCtx bounds relay HTTP calls. The underlying http.Client already carries
// a 15s timeout; the context exists so future cancellation has one place.
func bgCtx() context.Context { return context.Background() }

func (b *bridge) aliasPath() string { return filepath.Join(b.dir, "mailbox-map.json") }

func (b *bridge) loadAliases() {
	raw, err := os.ReadFile(b.aliasPath())
	if err != nil {
		return
	}
	var all map[string]*binding
	if json.Unmarshal(raw, &all) != nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, v := range all {
		if len(k) == 32 && v != nil && v.MailboxID != "" && v.ShardURL != "" {
			b.aliases[k] = v
		}
	}
}

func (b *bridge) saveAliases() {
	b.mu.Lock()
	raw, err := json.Marshal(b.aliases)
	b.mu.Unlock()
	if err != nil {
		return
	}
	_ = os.WriteFile(b.aliasPath(), raw, 0o600)
}

// recordAlias stores alias → full-ID binding (call without holding b.mu).
func (b *bridge) recordAlias(alias []byte, bind *binding) {
	b.mu.Lock()
	b.aliases[hex.EncodeToString(alias)] = bind
	b.mu.Unlock()
	b.saveAliases()
}

// expandAlias returns the binding for a 16-byte transport alias.
func (b *bridge) expandAlias(alias []byte) (*binding, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	bind, ok := b.aliases[hex.EncodeToString(alias)]
	if !ok {
		return nil, fmt.Errorf("unknown mailbox alias (re-run register/resolve for this bridge)")
	}
	return bind, nil
}

func (b *bridge) serveLoop() {
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(os.Stdin, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > maxRPCBytes {
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(os.Stdin, body); err != nil {
			return
		}
		env, err := unmarshalEnvelope(body)
		if err != nil {
			return
		}
		respOp, payload := b.dispatch(env.op, env.payload)
		rbody, err := marshalEnvelope(respOp, env.reqID, payload)
		if err != nil {
			return
		}
		if _, err := os.Stdout.Write(frameMessage(rbody)); err != nil {
			return
		}
	}
}

func (b *bridge) dispatch(op uint8, payload []byte) (uint8, []byte) {
	switch op {
	case opInitialize:
		return opInitialize, b.onInitialize(payload)
	case opCapabilities:
		return opCapabilities, marshalCaps()
	case opStartStop:
		return b.onStartStop(payload)
	case opSend:
		return b.onSend(payload)
	case opAttach:
		return b.onAttach(payload)
	case opDetach:
		return b.onDetach(payload)
	case opPoll:
		return b.onPoll(payload)
	case opStatus:
		b.mu.Lock()
		running := b.running
		b.mu.Unlock()
		if running {
			return opStatus, marshalStatus(true, "relay courier running")
		}
		return opStatus, marshalStatus(false, "stopped")
	case opRegister:
		return b.onRegister(payload)
	case opResolve:
		return b.onResolve(payload)
	default:
		return opError, errPayload(errUnsupported, "unknown op")
	}
}

func (b *bridge) onInitialize(payload []byte) []byte {
	init, err := unmarshalInitialize(payload)
	if err != nil {
		return marshalInitResult(false, err.Error(), transportAPIVer)
	}
	if init.transportID != bridgeID {
		return marshalInitResult(false, "transport id mismatch", transportAPIVer)
	}
	if init.apiVersion != transportAPIVer {
		return marshalInitResult(false, "api version mismatch", transportAPIVer)
	}
	if len(init.config) > 0 {
		var cfg bridgeConfig
		if err := json.Unmarshal(init.config, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "bridge: ignoring invalid config %q: %v (want e.g. {\"router_url\":\"https://...\"})\n", string(init.config), err)
		} else {
			b.mu.Lock()
			b.routerURL = cfg.RouterURL
			b.mu.Unlock()
		}
	}
	return marshalInitResult(true, "", transportAPIVer)
}

func (b *bridge) onStartStop(payload []byte) (uint8, []byte) {
	action, err := unmarshalStartStop(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	b.mu.Lock()
	b.running = action == actionStart
	b.mu.Unlock()
	return opStartStop, marshalAck(true, "")
}

func (b *bridge) requireRunning() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.running {
		return fmt.Errorf("not started")
	}
	return nil
}

func (b *bridge) defaultRouter() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.routerURL
}

// effectiveRouter returns the configured router, falling back to any
// router_url learned via attach (live) or register/resolve (persisted
// alias map). This keeps pubkey routing working after a bridge restart
// even when the initialize config is missing, and when core replays
// attachments in a different order. Single lock: never call defaultRouter
// from inside here.
func (b *bridge) effectiveRouter() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.routerURL != "" {
		return b.routerURL
	}
	for _, at := range b.attached {
		if at != nil && at.RouterURL != "" {
			return at.RouterURL
		}
	}
	for _, al := range b.aliases {
		if al != nil && al.RouterURL != "" {
			return al.RouterURL
		}
	}
	return ""
}

// onSend delivers one opaque frame. Either the recipient pubkey is given
// (resolved via the Router here) or an explicit (alias, shard) address the
// recipient shared out-of-band (expanded via the alias map).
func (b *bridge) onSend(payload []byte) (uint8, []byte) {
	if err := b.requireRunning(); err != nil {
		return opError, errPayload(errNotReady, err.Error())
	}
	req, err := unmarshalSend(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	ctx := bgCtx()
	if len(req.mailboxID) == 16 && req.shardURL != "" {
		bind, err := b.expandAlias(req.mailboxID)
		if err != nil {
			return opError, errPayload(errTransport, err.Error())
		}
		if err := b.relay.sendToShard(ctx, req.shardURL, bind.MailboxID, req.frame, b.courierPriv); err != nil {
			return opError, errPayload(errTransport, err.Error())
		}
		return opSend, marshalAck(true, "")
	}
	if len(req.recipientPub) != 32 {
		return opError, errPayload(errTransport, "recipient_pub must be 32 bytes (or pass mailbox+shard)")
	}
	routerURL := b.effectiveRouter()
	if routerURL == "" {
		return opError, errPayload(errTransport, "no router_url: set via config or attach first")
	}
	res, err := b.relay.resolve(ctx, routerURL, req.recipientPub)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	// Remember the peer's full mailbox so explicit-address sends work later.
	if full, err := hex.DecodeString(res.MailboxID); err == nil && len(full) == 32 {
		b.recordAlias(aliasFor(full), &binding{MailboxID: res.MailboxID, ShardURL: res.ShardURL, RouterURL: routerURL})
	}
	var lastErr error
	for _, shardURL := range candidateShardURLs(res.ShardURL, res.ReplicaShardURLs) {
		if err := b.relay.sendToShard(ctx, shardURL, res.MailboxID, req.frame, b.courierPriv); err == nil {
			return opSend, marshalAck(true, "")
		} else {
			lastErr = err
		}
	}
	return opError, errPayload(errTransport, lastErr.Error())
}

func (b *bridge) onAttach(payload []byte) (uint8, []byte) {
	if err := b.requireRunning(); err != nil {
		return opError, errPayload(errNotReady, err.Error())
	}
	req, err := unmarshalAttach(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	bind, err := b.expandAlias(req.mailboxID)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	aliasHex := hex.EncodeToString(req.mailboxID)
	b.mu.Lock()
	b.attached[aliasHex] = &binding{
		MailboxID:  bind.MailboxID,
		ReadSecret: hex.EncodeToString(req.readSecret),
		ShardURL:   req.shardURL,
		RouterURL:  req.routerURL,
	}
	if b.routerURL == "" && req.routerURL != "" {
		b.routerURL = req.routerURL
	}
	b.mu.Unlock()
	// Backfill the secret so the alias map stays useful across restarts.
	b.recordAlias(req.mailboxID, &binding{
		MailboxID:  bind.MailboxID,
		ReadSecret: hex.EncodeToString(req.readSecret),
		ShardURL:   req.shardURL,
		RouterURL:  req.routerURL,
	})
	return opAttach, marshalAck(true, "")
}

func (b *bridge) onDetach(payload []byte) (uint8, []byte) {
	id, err := unmarshalDetach(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	b.mu.Lock()
	delete(b.attached, hex.EncodeToString(id))
	b.mu.Unlock()
	return opDetach, marshalAck(true, "")
}

// onPoll fetches relay batches and returns the inner opaque frames.
func (b *bridge) onPoll(payload []byte) (uint8, []byte) {
	if err := b.requireRunning(); err != nil {
		return opError, errPayload(errNotReady, err.Error())
	}
	req, err := unmarshalPoll(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	b.mu.Lock()
	var targets []*binding
	if len(req.mailboxID) == 16 {
		if mb, ok := b.attached[hex.EncodeToString(req.mailboxID)]; ok {
			targets = append(targets, mb)
		}
	} else {
		for _, mb := range b.attached {
			targets = append(targets, mb)
		}
	}
	b.mu.Unlock()
	// Note: req.limit is intentionally not applied — see below.
	var frames [][]byte
	ctx := bgCtx()
	for _, mb := range targets {
		// Relay /read is burn-after-read full-drain (no server-side limit),
		// so the bridge returns the whole backlog: dropping consumed
		// messages to honor a poll hint would lose mail. Core dispatches
		// batches, and mailboxes cap at 50 server-side.
		got, err := b.relay.readFromShard(ctx, mb.ShardURL, mb.MailboxID, mb.ReadSecret)
		if err != nil {
			return opError, errPayload(errTransport, err.Error())
		}
		frames = append(frames, got...)
	}
	return opPoll, marshalPollResult(frames)
}

// onRegister mints a relay mailbox for the bridge's scoped identity and
// returns the transport alias + bearer core needs for attach/poll.
func (b *bridge) onRegister(payload []byte) (uint8, []byte) {
	req, err := unmarshalRegisterReq(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	routerURL := req.routerURL
	if routerURL == "" {
		routerURL = b.effectiveRouter()
	}
	if routerURL == "" {
		return opError, errPayload(errTransport, "no router_url")
	}
	priv, err := b.scopedKey(req.userTag)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	cap, err := b.relay.register(bgCtx(), routerURL, priv)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	fullID, err := hex.DecodeString(cap.MailboxID)
	if err != nil || len(fullID) != 32 {
		return opError, errPayload(errTransport, "relay returned bad mailbox_id")
	}
	secret, err := hex.DecodeString(cap.ReadSecret)
	if err != nil || len(secret) != 32 {
		return opError, errPayload(errTransport, "relay returned bad read_secret")
	}
	alias := aliasFor(fullID)
	b.recordAlias(alias, &binding{
		MailboxID:  cap.MailboxID,
		ReadSecret: cap.ReadSecret,
		ShardURL:   cap.ShardURL,
		RouterURL:  routerURL,
	})
	return opRegister, marshalRegisterResult(alias, secret, cap.ShardURL, routerURL)
}

// onResolve maps a recipient pubkey to its transport alias + shard.
func (b *bridge) onResolve(payload []byte) (uint8, []byte) {
	req, err := unmarshalResolveReq(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	routerURL := req.routerURL
	if routerURL == "" {
		routerURL = b.effectiveRouter()
	}
	if routerURL == "" {
		return opError, errPayload(errTransport, "no router_url")
	}
	res, err := b.relay.resolve(bgCtx(), routerURL, req.recipientPub)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	fullID, err := hex.DecodeString(res.MailboxID)
	if err != nil || len(fullID) != 32 {
		return opError, errPayload(errTransport, "relay returned bad mailbox_id")
	}
	alias := aliasFor(fullID)
	b.recordAlias(alias, &binding{MailboxID: res.MailboxID, ShardURL: res.ShardURL, RouterURL: routerURL})
	return opResolve, marshalResolveResult(alias, res.ShardURL)
}
