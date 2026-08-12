# NexTalk-Relay

[![CI](https://github.com/erfanheydarzade/NexTalk-Relay/actions/workflows/ci.yml/badge.svg)](https://github.com/erfanheydarzade/NexTalk-Relay/actions/workflows/ci.yml)
[![Release](https://github.com/erfanheydarzade/NexTalk-Relay/actions/workflows/release.yml/badge.svg)](https://github.com/erfanheydarzade/NexTalk-Relay/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/runtime-Cloudflare%20Workers-f38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)

> The Cloudflare Workers relay backend for [NexTalk](https://github.com/erfanheydarzade/NexTalk) — an anonymous, one-time, burn-after-read mailbox service that NexTalk clients use to exchange encrypted handshake and message envelopes.

NexTalk-Relay is **not a chat server**. It never sees plaintext, never stores identities, and doesn't know who's talking to whom beyond a pubkey-derived mailbox ID. It's a thin, authenticated, self-expiring mailbox: clients drop encrypted envelopes off, other clients pick them up, and the relay forgets everything on read or TTL expiry — whichever comes first.

---

## How It Fits Into NexTalk

NexTalk's protocol runtime (crypto, sessions, ratcheting) lives in the main [NexTalk](https://github.com/erfanheydarzade/NexTalk) Go repo and is completely transport-agnostic. NexTalk-Relay is one such transport: the `worker` mode in the NexTalk CLI talks to this service to deliver `offer` / `answer` / `message` envelopes between peers who aren't online at the same time.

```
NexTalk client A  ──encrypt──▶  NexTalk-Relay  ──burn-after-read──▶  NexTalk client B
      (Go)                    (Cloudflare Worker)                        (Go)
```

The relay only ever sees ciphertext-shaped JSON envelopes and the sender's Ed25519 public key — it has no way to decrypt anything, and every request is signature-authenticated to stop spoofing and replay.

---

## Two Deployment Modes

This repo contains **two independent Workers** that can be deployed separately or together:

| Worker | Path | Purpose |
|---|---|---|
| **Shard** | [`shard/worker.js`](shard/worker.js) | Owns one KV namespace. Handles `/create`, `/send`, `/read`, `/health`. Can run completely standalone. |
| **Router** | [`router/router.js`](router/router.js) | Sits in front of N shards (optionally across different Cloudflare accounts), routes each request to the shard that owns a given pubkey by consistent-ish hashing, and provides backward-compatible routing across resizes. |

**If you just want a single relay**, deploy only `shard/` and skip the router entirely — every shard works standalone with no router configured.

**If you need horizontal scaling** (multiple KV namespaces, possibly across Cloudflare accounts), deploy several `shard/` instances plus one `router/` instance in front of them.

---

## Quick Start (Standalone Shard)

This is the fastest path to a working relay for personal use or testing.

### 1. Prerequisites
- A [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier is enough)
- [Node.js](https://nodejs.org/) and `npm`
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/): `npm install -g wrangler`

### 2. Clone and configure
```bash
git clone https://github.com/erfanheydarzade/NexTalk-Relay.git
cd NexTalk-Relay/shard

cp wrangler.toml.example wrangler.toml
```

### 3. Create the KV namespace
```bash
wrangler kv namespace create MAILBOX_KV
```
Copy the returned `id` into `wrangler.toml` under `[[kv_namespaces]]`.

### 4. Set required secrets
```bash
wrangler secret put SERVER_SECRET
wrangler secret put ADMIN_SECRET
```
`SERVER_SECRET` derives mailbox IDs from public keys via HMAC — treat it like any other credential. `ADMIN_SECRET` is reserved for future admin operations.

### 5. Deploy
```bash
wrangler deploy
```

You now have a working relay at `https://<your-worker-name>.<your-subdomain>.workers.dev`. Point your NexTalk client's worker config at this URL.

### 6. Run locally (optional)
```bash
wrangler dev
```
Serves the same routes on `http://localhost:8787`.

---

## API Reference

All responses are JSON. CORS is intentionally open (`Access-Control-Allow-Origin: *`) — there is no cookie/session state, every write is authenticated by a per-request Ed25519 signature instead, so there is nothing for a foreign origin to steal.

### `POST /create`
Create (or no-op if it already exists) a mailbox for a pubkey.

```jsonc
// Request body
{
  "pubkey": "<64-char lowercase hex Ed25519 pubkey>",
  "timestamp": "<unix ms as string>",
  "signature": "<128-char hex Ed25519 signature over 'pubkey:timestamp'>"
}
```
```jsonc
// Response — expires_in reflects MAILBOX_TTL_SECONDS (the mailbox record's
// sliding TTL), not the shorter message-backlog TTL
{ "read_token": "<mailbox id>", "expires_in": 31536000, "created": true }
```
Calling `/create` again on an existing mailbox is not an error — it's treated as activity and slides the mailbox's TTL forward, same as `/send` or `/read`.

### `POST /send`
Deliver an encrypted envelope to a recipient's mailbox. Requires proof the sender controls their claimed key — the signature binds sender identity to this exact recipient and message content, so a captured signature can't be replayed elsewhere.

```jsonc
// Request body
{
  "pubkey": "<recipient's 64-char hex pubkey>",
  "message": "<ciphertext / JSON envelope as a string>",
  "sender": {
    "pubkey": "<sender's 64-char hex pubkey>",
    "timestamp": "<unix ms as string>",
    "signature": "<hex sig over 'send:<senderPubkey>:<recipientPubkey>:<timestamp>:<sha256(message)>'>"
  }
}
```
```jsonc
// Response
{ "success": true, "queued": 3 }
```

### `GET /read?pubkey=&timestamp=&signature=&peek=`
Burn-after-read by default — fetching a mailbox empties it. Pass `peek=1` to read without consuming.

```jsonc
// Response
{ "messages": [ { "id": "...", "time": 173..., "message": "...", "senderPubkey": "..." } ], "count": 1, "createdAt": 173..., "consumed": true }
```

### `GET /health`
Liveness + KV-reachability probe. If `ROUTER_SHARED_SECRET` is set, requires `Authorization: Bearer <secret>` — this is what the router uses to check a shard before routing to it.

### `GET /status` (router only)
Aggregate health of every configured shard.

---

## Security Model

- **No plaintext, ever.** The relay stores whatever opaque string a client sends as `message` — it has no keys to decrypt anything.
- **Mailbox IDs are not public keys.** IDs are `HMAC-SHA256(pubkey, SERVER_SECRET)`, so knowing someone's pubkey doesn't let you enumerate or guess their mailbox ID without the server secret.
- **Every write is signed.** `/create` and `/send` require an Ed25519 signature over a specific, purpose-bound message (see API reference above) — this stops both spoofed sends and replaying a captured request against a different recipient.
- **Replay protection.** Every `(pubkey, timestamp, signature)` triple is cached in KV for the clock-skew window, so it can't be reused even if intercepted.
- **Burn-after-read.** Reading a mailbox empties it by default; nothing lingers longer than necessary.
- **Two-tier, TTL-bounded storage.** Unread message backlogs expire after `TTL_SECONDS` (default 14 days) of no one reading them, independent of the mailbox itself. The mailbox record — its pubkey-to-mailbox-id binding — has its own much longer `MAILBOX_TTL_SECONDS` (default 365 days), and that TTL is **sliding**: any `/create`, `/send`, or `/read` touching a mailbox renews its full window. An actively-used identity never loses its mailbox; one abandoned for a year is reclaimed automatically, keeping KV from filling up with dead keys nobody's using. See `worker.js` for the exact accounting.
- **Rate-limited** per authenticated sender identity, per recipient, and per IP — defense in depth against abuse even from rotating IPs.
- **Cross-account trust** (router ↔ shards) is a single shared bearer secret (`ROUTER_SHARED_SECRET`) over HTTPS, since Cloudflare Service Bindings don't work across accounts.

This is a relay, not a security boundary for message *content* — that guarantee comes entirely from NexTalk's client-side end-to-end encryption. The relay's job is transport availability and metadata minimization, not confidentiality of payloads (which it can't read anyway).

---

## Scaling to Multiple Shards

If one KV namespace and one Worker isn't enough, add more shards behind the router:

1. Deploy additional `shard/` Workers (each with its own KV namespace, optionally in different Cloudflare accounts).
2. In each shard's `wrangler.toml`, set `SHARD_URLS` (the full ring, same order everywhere) and `SELF_URL` (that shard's own URL) so clients can connect directly to their assigned shard and bypass the router's request-rate ceiling.
3. Set the same `ROUTER_SHARED_SECRET` on every shard and on the router.
4. Deploy `router/` with `SHARD_URLS` pointing at every shard.

**Growing the cluster later:** `SHARD_URLS` is append-only — never reorder or remove existing entries, only add new ones at the end. Set `PRIOR_SHARD_COUNTS` on the router so it can still find mailboxes created under the old shard count (see the detailed rationale in [`router.js`](router/router.js)'s file header). This fallback naturally becomes irrelevant on its own once every pre-resize mailbox has expired under `TTL_SECONDS`.

---

## Configuration Reference

Set as `[vars]` in `wrangler.toml` (all optional, shard defaults shown):

| Variable | Default | Description |
|---|---|---|
| `MAX_MESSAGES` | `50` | Max queued messages per mailbox |
| `MAX_MSG_BYTES` | `32768` | Max size of a single message body |
| `TTL_SECONDS` | `1209600` (14 days) | Unread **message backlog** TTL — clears unclaimed queued messages, does not delete the mailbox |
| `MAILBOX_TTL_SECONDS` | `31536000` (365 days) | Whole **mailbox record** TTL — sliding, renewed on every `/create`, `/send`, `/read` |
| `MAX_CLOCK_SKEW` | `30000` (30s) | Allowed timestamp drift / replay window |
| `MAX_SENDS_PER_SENDER` | `30` | Sends per 60s, keyed by sender identity |
| `MAX_SENDS_PER_TARGET` | `60` | Sends per 60s, keyed by recipient |
| `MAX_SENDS_PER_IP` | `120` | Sends per 60s, keyed by IP |
| `MAX_CREATES_PER_IP` | `20` | Mailbox creations per 60s, keyed by IP |
| `SHARD_URLS` | — | JSON array of shard URLs (multi-shard only) |
| `SELF_URL` | — | This shard's own URL (multi-shard only) |
| `PRIOR_SHARD_COUNTS` | — | Router only — historical shard counts for backward-compatible routing |

Secrets (set via `wrangler secret put`, never in `wrangler.toml`):

| Secret | Required on | Purpose |
|---|---|---|
| `SERVER_SECRET` | every shard | HMAC key for deriving mailbox IDs |
| `ADMIN_SECRET` | every shard | Reserved for admin operations |
| `ROUTER_SHARED_SECRET` | shards behind a router + the router | Cross-account trust boundary |

---

## Repository Structure

```
NexTalk-Relay/
├── shard/
│   ├── worker.js              # Mailbox logic — /create, /send, /read, /health
│   ├── deploy.bat             # Windows setup/deploy helper (menu-driven)
│   └── wrangler.toml.example  # Copy to wrangler.toml and fill in
├── router/
│   ├── router.js              # Multi-shard request router — /routing_table.json, /register, /resolve
│   ├── deploy.bat             # Windows setup/deploy helper (menu-driven)
│   └── wrangler.toml.example  # Copy to wrangler.toml and fill in
├── combined/
│   ├── worker.js              # Single-file shard + router for simple one-Worker deployments
│   └── wrangler.toml.example  # Config for the combined deployment
├── scripts/
│   ├── generate.py            # Generate all Router secrets (SERVER_SECRET, signing keypair)
│   ├── generate.html          # Browser-based version of the same generator
│   └── solve.py               # Solve the PoW challenge locally for shard self-registration
├── docs/
│   └── RELEASING.md           # How to cut a release
└── .github/
    ├── workflows/
    │   ├── ci.yml             # Syntax check + wrangler dry-run on push/PR
    │   └── release.yml        # Button-triggered release with auto-generated changelog
    ├── CONTRIBUTING.md
    ├── SECURITY.md
    └── PULL_REQUEST_TEMPLATE.md
```

---

## Releasing

Releases are cut with one button — see [`docs/RELEASING.md`](docs/RELEASING.md). The changelog is generated automatically from Conventional Commit messages.

---

## Status

Research-grade relay backend, developed alongside NexTalk. Not independently security-audited — review [`shard/worker.js`](shard/worker.js) and [`router/router.js`](router/router.js) yourself before relying on this for anything sensitive. Portions of this codebase were developed with AI assistance.

Found a security issue? See [`.github/SECURITY.md`](.github/SECURITY.md) — please report privately, not as a public issue.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
