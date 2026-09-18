// Tests for the nextalk-relay courier bridge. No network beyond httptest
// fakes: the fake Router verifies the exact signed-message formats the real
// Router enforces, and the fake shard verifies the /send auth the real
// shard enforces — so signature-format drift fails here, not in prod.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/erfanheydarzade/nanopack"
)

const (
	testMailboxFull = "abababababababababababababababababababababababababababababababab" // 32B
	testSecretFull  = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" // 32B
)

func encPair(id byte, v []byte) func(*nanopack.Encoder) {
	return func(e *nanopack.Encoder) { e.AddID(id, v) }
}

func mustEncode(t *testing.T, fns ...func(*nanopack.Encoder)) []byte {
	t.Helper()
	enc := &nanopack.Encoder{}
	for _, fn := range fns {
		fn(enc)
	}
	b, err := enc.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fieldByID(t *testing.T, body []byte, id byte) []byte {
	t.Helper()
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fields {
		if f.ID == id {
			return f.Data
		}
	}
	t.Fatalf("field %d missing", id)
	return nil
}

func testBridge(t *testing.T) *bridge {
	t.Helper()
	b := newBridge()
	b.dir = t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b.courierPriv = priv
	b.running = true
	return b
}

func TestEnvelopeRoundTrip(t *testing.T) {
	body, err := marshalEnvelope(opSend, 42, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := unmarshalEnvelope(body)
	if err != nil {
		t.Fatal(err)
	}
	if env.op != opSend || env.reqID != 42 || string(env.payload) != "payload" {
		t.Fatalf("bad envelope: %+v", env)
	}
}

func TestCapsDeclareMessageOnly(t *testing.T) {
	blob := string(fieldByID(t, marshalCaps(), 1))
	if !strings.Contains(blob, "message") {
		t.Fatalf("caps must declare message: %q", blob)
	}
	if strings.Contains(blob, "binary-transfer") {
		t.Fatalf("relay bridge must not declare binary-transfer: %q", blob)
	}
	if got := string(fieldByID(t, marshalCaps(), 2)); got != bridgeID {
		t.Fatalf("caps id = %q, want %q", got, bridgeID)
	}
}

func TestAliasDeterministic16(t *testing.T) {
	full, _ := hex.DecodeString(testMailboxFull)
	a1, a2 := aliasFor(full), aliasFor(full)
	if len(a1) != 16 || string(a1) != string(a2) {
		t.Fatalf("alias must be deterministic 16B: %x", a1)
	}
	other, _ := hex.DecodeString(strings.Repeat("ef", 32))
	if string(aliasFor(other)) == string(a1) {
		t.Fatal("distinct mailboxes must alias distinctly")
	}
}

func TestSenderAuthFormat(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	mbox := strings.ToUpper(testMailboxFull) // mixed case must still verify
	msg := base64.StdEncoding.EncodeToString([]byte("frame"))
	auth := buildSenderAuth(priv, mbox, msg)
	sum := sha256.Sum256([]byte(msg))
	signed := fmt.Sprintf("send:%s:%s:%s:%s", hex.EncodeToString(pub), strings.ToLower(mbox), auth.Timestamp, hex.EncodeToString(sum[:]))
	sig, _ := hex.DecodeString(auth.Signature)
	if !ed25519.Verify(pub, []byte(signed), sig) {
		t.Fatal("sender auth signature does not verify over canonical message")
	}
}

func TestSignRegisterFormat(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubHex, ts, sigHex := signRegister(priv)
	pub, _ := hex.DecodeString(pubHex)
	sig, _ := hex.DecodeString(sigHex)
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte("register:"+pubHex+":"+ts), sig) {
		t.Fatal("register signature does not verify over canonical message")
	}
}

// fakeRelay returns a Router + shard pair enforcing the real auth formats.
func fakeRelay(t *testing.T) (routerURL, shardURL string, close func()) {
	t.Helper()
	var shard string
	shardMux := http.NewServeMux()
	shardMux.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			MailboxID string     `json:"mailbox_id"`
			Message   string     `json:"message"`
			Sender    senderAuth `json:"sender"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"bad json"}`, 400)
			return
		}
		if body.MailboxID != testMailboxFull {
			http.Error(w, `{"error":"mailbox not found"}`, 404)
			return
		}
		sum := sha256.Sum256([]byte(body.Message))
		signed := fmt.Sprintf("send:%s:%s:%s:%s",
			strings.ToLower(body.Sender.PubKey), strings.ToLower(body.MailboxID),
			body.Sender.Timestamp, hex.EncodeToString(sum[:]))
		pub, err1 := hex.DecodeString(body.Sender.PubKey)
		sig, err2 := hex.DecodeString(body.Sender.Signature)
		if err1 != nil || err2 != nil || !ed25519.Verify(ed25519.PublicKey(pub), []byte(signed), sig) {
			http.Error(w, `{"error":"sender auth failed: signature verification failed"}`, 401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "queued": 1})
	})
	shardMux.HandleFunc("/read", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("mailbox_id") != testMailboxFull || q.Get("read_secret") != testSecretFull {
			http.Error(w, `{"error":"invalid read_secret"}`, 401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []any{map[string]any{
				"id": "m1", "time": 1,
				"message":      base64.StdEncoding.EncodeToString([]byte{0x03, 'h', 'i'}),
				"senderPubkey": strings.Repeat("0", 64),
			}},
			"count": 1, "createdAt": 1, "consumed": true,
		})
	})
	shardSrv := httptest.NewServer(shardMux)
	shard = shardSrv.URL

	routerMux := http.NewServeMux()
	capResp := func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"mailbox_id": testMailboxFull, "read_secret": testSecretFull,
			"shard_url": shard, "replica_shard_urls": []string{shard},
			"expires_at": 9999999999999, "table_version": 1,
		})
	}
	routerMux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Pubkey, Timestamp, Signature string
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		pub, err1 := hex.DecodeString(body.Pubkey)
		sig, err2 := hex.DecodeString(body.Signature)
		if err1 != nil || err2 != nil ||
			!ed25519.Verify(ed25519.PublicKey(pub), []byte("register:"+strings.ToLower(body.Pubkey)+":"+body.Timestamp), sig) {
			http.Error(w, `{"error":"signature verification failed"}`, 401)
			return
		}
		capResp(w)
	})
	routerMux.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Query().Get("pubkey")) != 64 {
			http.Error(w, `{"error":"pubkey required"}`, 400)
			return
		}
		capResp(w)
	})
	routerSrv := httptest.NewServer(routerMux)
	return routerSrv.URL, shardSrv.URL, func() { routerSrv.Close(); shardSrv.Close() }
}

func TestBridgeEndToEnd(t *testing.T) {
	routerURL, shardURL, close := fakeRelay(t)
	defer close()
	b := testBridge(t)

	// initialize with router config
	initPayload := mustEncode(t,
		encPair(1, []byte(bridgeID)),
		encPair(2, []byte{transportAPIVer}),
		encPair(3, []byte(`{"router_url":"`+routerURL+`"}`)),
	)
	if out := b.onInitialize(initPayload); len(fieldByID(t, out, 1)) != 1 || fieldByID(t, out, 1)[0] != 1 {
		t.Fatalf("initialize rejected: %q", out)
	}

	// register → alias + bearer
	regPayload := mustEncode(t, encPair(1, []byte("alice")), encPair(2, []byte(routerURL)))
	op, regRes := b.onRegister(regPayload)
	if op != opRegister {
		t.Fatalf("register failed: op=%d %q", op, regRes)
	}
	alias := fieldByID(t, regRes, 1)
	secret := fieldByID(t, regRes, 2)
	if len(alias) != 16 || len(secret) != 32 {
		t.Fatalf("bad register sizes: alias=%d secret=%d", len(alias), len(secret))
	}
	full, _ := hex.DecodeString(testMailboxFull)
	if string(alias) != string(aliasFor(full)) {
		t.Fatal("register alias is not the deterministic alias")
	}
	if got := string(fieldByID(t, regRes, 3)); got != shardURL {
		t.Fatalf("shard = %q, want %q", got, shardURL)
	}

	// resolve → same alias
	peerPub := make([]byte, 32)
	for i := range peerPub {
		peerPub[i] = byte(i)
	}
	resPayload := mustEncode(t, encPair(1, peerPub), encPair(2, []byte(routerURL)))
	op, resRes := b.onResolve(resPayload)
	if op != opResolve || string(fieldByID(t, resRes, 1)) != string(alias) {
		t.Fatalf("resolve failed: op=%d", op)
	}

	// attach the alias
	attPayload := mustEncode(t,
		encPair(1, alias), encPair(2, secret),
		encPair(3, []byte(shardURL)), encPair(4, []byte(routerURL)),
	)
	if op, out := b.onAttach(attPayload); op != opAttach {
		t.Fatalf("attach failed: op=%d %q", op, out)
	}

	// send via pubkey (bridge resolves itself)
	frame := []byte{0x03, 'h', 'e', 'l', 'l', 'o'}
	sendPayload := mustEncode(t, encPair(1, frame), encPair(2, peerPub))
	if op, out := b.onSend(sendPayload); op != opSend {
		t.Fatalf("send via pubkey failed: op=%d %q", op, out)
	}

	// send via explicit alias+shard
	sendAlias := mustEncode(t, encPair(1, frame), encPair(4, alias), encPair(5, []byte(shardURL)))
	if op, out := b.onSend(sendAlias); op != opSend {
		t.Fatalf("send via alias failed: op=%d %q", op, out)
	}

	// poll the alias → the canned frame back
	pollPayload := mustEncode(t, encPair(1, []byte{32}), encPair(2, alias))
	op, pollRes := b.onPoll(pollPayload)
	if op != opPoll {
		t.Fatalf("poll failed: op=%d %q", op, pollRes)
	}
	blob := fieldByID(t, pollRes, 1)
	if len(blob) < 4 || binary.BigEndian.Uint32(blob[:4]) != uint32(len(blob)-4) {
		t.Fatalf("bad poll blob framing: %x", blob)
	}
	if string(blob[4:]) != string([]byte{0x03, 'h', 'i'}) {
		t.Fatalf("bad poll frame: %x", blob[4:])
	}
	if cnt := binary.BigEndian.Uint32(fieldByID(t, pollRes, 2)); cnt != 1 {
		t.Fatalf("poll count = %d, want 1", cnt)
	}

	// detach + unknown op
	detPayload := mustEncode(t, encPair(1, alias))
	if op, _ := b.onDetach(detPayload); op != opDetach {
		t.Fatalf("detach op = %d", op)
	}
	if op, _ := b.dispatch(99, nil); op != opError {
		t.Fatalf("unknown op must answer op 0, got %d", op)
	}
}

func TestAttachUnknownAliasFails(t *testing.T) {
	b := testBridge(t)
	attPayload := mustEncode(t,
		encPair(1, bytes_16()), encPair(2, make([]byte, 32)),
		encPair(3, []byte("http://x")),
	)
	if op, _ := b.onAttach(attPayload); op != opError {
		t.Fatal("attach of an unregistered alias must fail closed")
	}
}

func TestInvalidConfigIgnoredNotFatal(t *testing.T) {
	b := testBridge(t)
	for _, bad := range []string{
		`{router_url:https://x}`,
		`{'router_url':'https://x'}`,
		`not json`,
	} {
		initPayload := mustEncode(t,
			encPair(1, []byte(bridgeID)),
			encPair(2, []byte{transportAPIVer}),
			encPair(3, []byte(bad)),
		)
		if out := b.onInitialize(initPayload); len(fieldByID(t, out, 1)) != 1 || fieldByID(t, out, 1)[0] != 1 {
			t.Fatalf("invalid config %q must not refuse initialize: %q", bad, out)
		}
		if got := b.effectiveRouter(); got != "" {
			t.Fatalf("invalid config %q must not set router, got %q", bad, got)
		}
	}
}

func TestEffectiveRouterFallback(t *testing.T) {
	b := testBridge(t)
	if got := b.effectiveRouter(); got != "" {
		t.Fatalf("empty bridge router = %q, want empty", got)
	}
	// Attached binding wins when no config.
	b.attached["aa"] = &binding{MailboxID: testMailboxFull, ShardURL: "s", RouterURL: "https://gw-a"}
	if got := b.effectiveRouter(); got != "https://gw-a" {
		t.Fatalf("attached fallback = %q, want gw-a", got)
	}
	// Config wins over attach.
	b.routerURL = "https://gw-cfg"
	if got := b.effectiveRouter(); got != "https://gw-cfg" {
		t.Fatalf("config must win, got %q", got)
	}
	// Alias map survives restart (mailbox-map.json): fresh bridge with no
	// config but persisted aliases still routes.
	b2 := testBridge(t)
	full, _ := hex.DecodeString(testMailboxFull)
	b2.recordAlias(aliasFor(full), &binding{MailboxID: testMailboxFull, ShardURL: "s", RouterURL: "https://gw-alias"})
	if got := b2.effectiveRouter(); got != "https://gw-alias" {
		t.Fatalf("alias fallback = %q, want gw-alias", got)
	}
}

func TestSendViaPubkeyUsesAttachFallback(t *testing.T) {
	routerURL, _, close := fakeRelay(t)
	defer close()
	b := testBridge(t)
	// No initialize config: register with explicit router, attach, then
	// clear the in-memory default to simulate a restart that kept only
	// persisted aliases + replayed attaches.
	regPayload := mustEncode(t, encPair(1, []byte("alice")), encPair(2, []byte(routerURL)))
	op, regRes := b.onRegister(regPayload)
	if op != opRegister {
		t.Fatalf("register failed: op=%d", op)
	}
	alias := fieldByID(t, regRes, 1)
	secret := fieldByID(t, regRes, 2)
	attPayload := mustEncode(t,
		encPair(1, alias), encPair(2, secret),
		encPair(3, []byte("http://shard")), encPair(4, []byte(routerURL)),
	)
	if op, out := b.onAttach(attPayload); op != opAttach {
		t.Fatalf("attach failed: op=%d %q", op, out)
	}
	b.mu.Lock()
	b.routerURL = ""
	b.mu.Unlock()
	peerPub := make([]byte, 32)
	for i := range peerPub {
		peerPub[i] = byte(i)
	}
	frame := []byte{0x03, 'h', 'i'}
	sendPayload := mustEncode(t, encPair(1, frame), encPair(2, peerPub))
	if op, out := b.onSend(sendPayload); op != opSend {
		t.Fatalf("send must use attach fallback router: op=%d %q", op, out)
	}
}

func bytes_16() []byte { return []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16} }

// TestServeLoopStdio drives the real serveLoop over pipes: framed request
// in, framed response out — the exact bytes NexTalk core's process runtime
// exchanges with the entry binary.
func TestServeLoopStdio(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NTX_BRIDGE_DIR", dir)

	stdinR, stdinW, _ := os.Pipe()
	stdoutR, stdoutW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = stdinR, stdoutW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	b := newBridge()
	if err := b.loadOrCreateCourierKey(); err != nil {
		t.Fatal(err)
	}
	b.loadAliases()
	go b.serveLoop()

	call := func(op uint8, payload []byte) (uint8, []byte) {
		t.Helper()
		body, err := marshalEnvelope(op, 7, payload)
		if err != nil {
			t.Fatal(err)
		}
		frame := make([]byte, 4+len(body))
		binary.BigEndian.PutUint32(frame, uint32(len(body)))
		copy(frame[4:], body)
		if _, err := stdinW.Write(frame); err != nil {
			t.Fatal(err)
		}
		var hdr [4]byte
		if _, err := io.ReadFull(stdoutR, hdr[:]); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, binary.BigEndian.Uint32(hdr[:]))
		if _, err := io.ReadFull(stdoutR, resp); err != nil {
			t.Fatal(err)
		}
		env, err := unmarshalEnvelope(resp)
		if err != nil {
			t.Fatal(err)
		}
		if env.reqID != 7 {
			t.Fatalf("reqID mismatch: %d", env.reqID)
		}
		return env.op, env.payload
	}

	initPayload := mustEncode(t,
		encPair(1, []byte(bridgeID)),
		encPair(2, []byte{transportAPIVer}),
	)
	if op, out := call(opInitialize, initPayload); op != opInitialize || fieldByID(t, out, 1)[0] != 1 {
		t.Fatalf("stdio initialize failed: op=%d", op)
	}
	if op, out := call(opCapabilities, []byte{0x00}); op != opCapabilities ||
		!strings.Contains(string(fieldByID(t, out, 1)), "message") {
		t.Fatalf("stdio capabilities failed: op=%d", op)
	}
	startPayload := mustEncode(t, encPair(1, []byte{actionStart}))
	if op, _ := call(opStartStop, startPayload); op != opStartStop {
		t.Fatalf("stdio start failed: op=%d", op)
	}
	if op, out := call(opStatus, []byte{0x00}); op != opStatus || fieldByID(t, out, 1)[0] != 1 {
		t.Fatalf("stdio status after start must report running: op=%d", op)
	}
}
