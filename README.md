# NexTalk-Relay

[![CI](https://github.com/erfanheydarzade/NexTalk-Relay/actions/workflows/ci.yml/badge.svg)](https://github.com/erfanheydarzade/NexTalk-Relay/actions/workflows/ci.yml)
[![Release](https://github.com/erfanheydarzade/NexTalk-Relay/actions/workflows/release.yml/badge.svg)](https://github.com/erfanheydarzade/NexTalk-Relay/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/runtime-Cloudflare%20Workers-f38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)

> The Cloudflare Workers relay backend for [NexTalk](https://github.com/erfanheydarzade/NexTalk) — an anonymous, one-time, burn-after-read mailbox service that NexTalk clients use to exchange encrypted handshake and message envelopes.

NexTalk-Relay is **not a chat server**. It never sees plaintext, never stores identities, and doesn't know who's talking to whom beyond a pubkey-derived mailbox ID. It's a thin, authenticated, self-expiring mailbox: clients drop encrypted envelopes off, other clients pick them up, and the relay forgets everything on read or TTL expiry, whichever comes first.

- [Prebuilt packages](#prebuilt-packages-no-build-needed) · [Which setup do I need?](#which-setup-do-i-need)
- [Troubleshooting](#troubleshooting)
- [Quick start: standalone shard](#quick-start-standalone-shard) · [Quick start: chat by peer ID (`.ntx`)](#quick-start-chat-by-peer-id-with-the-ntx-transport)
- [Local development](#local-development) · [API reference](#api-reference)
- [Security model](#security-model) · [Scaling to multiple shards](#scaling-to-multiple-shards)
- [Configuration reference](#configuration-reference) · [Repository structure](#repository-structure) · [Releasing](#releasing)

---

## How it fits into NexTalk

NexTalk's protocol runtime (crypto, sessions, ratcheting) lives in the main [NexTalk](https://github.com/erfanheydarzade/NexTalk) Go repo and is completely transport-agnostic. NexTalk-Relay is one such transport: it delivers `offer` / `answer` / `message` envelopes between peers who aren't online at the same time.

```
NexTalk client A  ──encrypt──▶  NexTalk-Relay  ──burn-after-read──▶  NexTalk client B
      (Go)                    (Cloudflare Worker)                        (Go)
```

The relay only ever sees ciphertext-shaped JSON envelopes and the sender's Ed25519 public key. It cannot decrypt anything, and every request is signature-authenticated to stop spoofing and replay.

---

## Prebuilt packages (no build needed)

The NexTalk transport (`.ntx`) is already built for you. Download it from the [**Releases page**](https://github.com/erfanheydarzade/NexTalk-Relay/releases/latest): there is one `.ntx` per OS/CPU, a browser `.wasm` demo package, and a SHA-256 checksum file. You only need Go if you want to change the bridge. Install steps are in the [quick start](#quick-start-chat-by-peer-id-with-the-ntx-transport).

The Cloudflare Workers (shard, router, combined) are deployed from this repo's source with `wrangler`; the releases also include the tagged Worker source.

---

## Which setup do I need?

This repo contains **three deployables**: a **shard** (stores mailboxes), a **router** (decides which shard owns a pubkey and hands out mailbox capabilities), and a **combined** single-file Worker that does both.

| I want to… | Deploy | Client side |
|---|---|---|
| Try it, or use the built-in `worker` mode of the NexTalk CLI | **Shard** only | `nextalk worker listen` with `WORKER_URL` pointing at the shard |
| Chat by **peer ID** (`peer connect <id>`, `message send`) through the installable NexTalk transport | **Router + shard**, or the **combined** Worker | Install `nextalk-relay.ntx`, then `transport register-identity` ([quick start](#quick-start-chat-by-peer-id-with-the-ntx-transport)) |
| Scale beyond one KV namespace, possibly across Cloudflare accounts | Several **shards** + one **router** | Same as above ([scaling](#scaling-to-multiple-shards)) |

The `.ntx` transport needs the **router**: its `register` and `resolve` calls go to the router, not to a bare shard.

---

## Quick start: standalone shard

The fastest path to a working relay for personal use or testing.

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
`SERVER_SECRET` derives mailbox IDs from public keys via HMAC, so treat it like any other credential and **don't rotate it casually**: changing it orphans every existing mailbox. `ADMIN_SECRET` is reserved for future admin operations.

### 5. Deploy
```bash
wrangler deploy
```

You now have a working relay at `https://<your-worker-name>.<your-subdomain>.workers.dev`. Point your NexTalk client's worker config at this URL.

---

## Quick start: chat by peer ID with the `.ntx` transport

Use this when you want `peer connect <peer-id>` to just work. You need a **router** in front of at least one shard (or the combined Worker), plus the installable transport from [`transports/nextalk-relay/`](transports/nextalk-relay/README.md).

**1. Deploy the router and shard(s).** Generate the router secrets with `scripts/generate.py` (or `scripts/generate.html` in a browser), then use each folder's `deploy.bat` or `wrangler deploy`. Shards need the router's public signing key so they can verify capabilities.

**2. Install the transport and point it at your router.** Download the prebuilt `.ntx` for your OS from the [latest release](https://github.com/erfanheydarzade/NexTalk-Relay/releases/latest) (verify it with the release's checksum file), or build it yourself:

```bash
# optional: build from source instead of downloading
cd transports/nextalk-relay && ./package.sh      # -> nextalk-relay.ntx   (Windows: .\package.ps1)
```

```bash
nextalk transport install nextalk-relay.ntx --enable
nextalk transport config nextalk-relay '{"router_url":"https://<your-router>.workers.dev"}'
```

PowerShell needs the inner quotes escaped:

```powershell
.\nextalk.exe transport config nextalk-relay '{\"router_url\":\"https://<your-router>.workers.dev\"}'
```

**3. Every person registers their own identity on the same router.** Both sides must do this, not just you.

```bash
nextalk transport register-identity nextalk-relay -i <YOU> --router https://<your-router>.workers.dev
nextalk transport resolve nextalk-relay --to <YOU> --router https://<your-router>.workers.dev   # verify
```

**4. Chat.** In the NexTalk shell:

```
identity load <YOU>
use relay nextalk-relay
peer connect <PEER>        # the peer must have done step 3
transport poll             # both sides poll to finish the handshake
message send <PEER> hello
```

> **`register` vs `register-identity`.** Plain `transport register` mints a mailbox under the bridge's throwaway key. Nobody can derive its address from your peer ID, so it only works if you hand the alias + shard to the sender out-of-band. For `peer connect`, use `register-identity`. Details and the two-user offline scenario are in the [transport README](transports/nextalk-relay/README.md).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `recipient mailbox is not registered on the relay` | The **peer** has no identity mailbox on this router. | They run `transport register-identity` against the **same** router. Check with `transport resolve --to <their-id>`. |
| Registered, but resolve still says "not confirmed to exist" | You registered on a different router (for example local vs deployed), or the router's `SERVER_SECRET` changed. Mailbox IDs are `HMAC(pubkey, SERVER_SECRET)`, so they differ per router. | Use one router URL everywhere; register again after any secret change. |
| `unknown mailbox alias` / `replay attach …` on every command | NexTalk's saved attachments are stale after you reset the router/shard or wiped local data. | `transport detach nextalk-relay --mailbox <32-hex>` for each, then register again (see the transport README). |
| Router can't reach the shard locally | Router and shard both default to port 8787. | Start the shard with `--port 8788`. See [Local development](#local-development). |
| `timestamp outside allowed skew` / `401` | Client clock differs from the server by more than `MAX_CLOCK_SKEW` (30 s). | Fix the system clock. |
| Messages "disappear" | They are burn-after-read, or the backlog TTL (`TTL_SECONDS`, 14 days) expired. | Use `peek=1` when you only want to look. |

---

## Local development

Run the router and shard side by side:

| Service | Command | Address |
|---|---|---|
| Router | `wrangler dev` (in `router/`) | `http://127.0.0.1:8787` |
| Shard | `wrangler dev --port 8788` (in `shard/`) | `http://127.0.0.1:8788` |

- Set the shard's `SELF_URL` and the router's `SHARD_URLS` to the `8788` address.
- `wrangler dev` keeps its data under `.wrangler/state`. Deleting it, or changing `SERVER_SECRET`, invalidates every registration. Clear NexTalk's stale attachments and register again.
- A standalone shard on its own serves the same routes on `http://localhost:8787`.

---

## API reference

All responses are JSON. CORS is intentionally open (`Access-Control-Allow-Origin: *`): there is no cookie/session state, and every write is authenticated by a per-request Ed25519 signature, so there is nothing for a foreign origin to steal.

### Shard

#### `POST /create`
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
// Response. expires_in reflects MAILBOX_TTL_SECONDS (the mailbox record's
// sliding TTL), not the shorter message-backlog TTL
{ "read_token": "<mailbox id>", "expires_in": 31536000, "created": true }
```
Calling `/create` again on an existing mailbox is not an error. It counts as activity and slides the mailbox's TTL forward, same as `/send` or `/read`.

#### `POST /send`
Deliver an encrypted envelope to a recipient's mailbox. The signature binds sender identity to this exact recipient and message content, so a captured signature can't be replayed elsewhere.

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

#### `GET /read?pubkey=&timestamp=&signature=&peek=`
Burn-after-read by default: fetching a mailbox empties it. Pass `peek=1` to read without consuming.

```jsonc
// Response
{ "messages": [ { "id": "...", "time": 173..., "message": "...", "senderPubkey": "..." } ], "count": 1, "createdAt": 173..., "consumed": true }
```

#### `GET /health`
Liveness + KV-reachability probe. If `ROUTER_SHARED_SECRET` is set, requires `Authorization: Bearer <secret>`; this is what the router uses to check a shard before routing to it.

### Router

| Endpoint | Purpose |
|---|---|
| `POST /register` | Prove ownership of a pubkey (Ed25519 signature over `register:<pubkey>:<timestamp>`, ±30 s). The router mints the opaque `mailbox_id` and a random `read_secret` capability, then asks the owning shard to create the mailbox **without telling the shard the pubkey**. Clients cache the response. Safe to repeat for the same pubkey. |
| `GET /resolve?pubkey=<64-hex>` | Where does this pubkey's mailbox live? No ownership proof needed: a pubkey is a public address. Returns `mailbox_id`, `shard_url`, replicas and era. If the router can't confirm the mailbox exists on any known era it still answers, but with a `note` saying so, which is what the NexTalk client reports as "not registered". |
| `GET /routing_table.json` | The signed routing table (shard list, version). |
| `GET /status` | Aggregate health of every configured shard. |

Shard self-registration and admin routes (`/server_hello`, `/pow_challenge`, `/register_shard`, `/rotate_shard_key`, `/admin/*`) are covered in [`router/router.js`](router/router.js)'s header.

---

## Security model

- **No plaintext, ever.** The relay stores whatever opaque string a client sends as `message`; it has no keys to decrypt anything.
- **Mailbox IDs are not public keys.** IDs are `HMAC-SHA256(pubkey, SERVER_SECRET)`, so knowing someone's pubkey doesn't let you enumerate or guess their mailbox ID without the server secret. Behind a router, the shard never learns the pubkey at all.
- **Every write is signed.** `/create`, `/send` and the router's `/register` require an Ed25519 signature over a specific, purpose-bound message. This stops both spoofed sends and replaying a captured request against a different recipient.
- **Replay protection.** Every `(pubkey, timestamp, signature)` triple is cached in KV for the clock-skew window, so it can't be reused even if intercepted.
- **Burn-after-read.** Reading a mailbox empties it by default; nothing lingers longer than necessary.
- **Two-tier, TTL-bounded storage.** Unread message backlogs expire after `TTL_SECONDS` (default 14 days) of no one reading them, independent of the mailbox itself. The mailbox record (its pubkey-to-mailbox-id binding) has its own much longer `MAILBOX_TTL_SECONDS` (default 365 days), and that TTL is **sliding**: any `/create`, `/send` or `/read` touching a mailbox renews its full window. An actively-used identity never loses its mailbox; one abandoned for a year is reclaimed automatically. See `worker.js` for the exact accounting.
- **Rate-limited** per authenticated sender identity, per recipient, and per IP: defense in depth against abuse even from rotating IPs.
- **Cross-account trust** (router ↔ shards) is a single shared bearer secret (`ROUTER_SHARED_SECRET`) over HTTPS, since Cloudflare Service Bindings don't work across accounts.

This is a relay, not a security boundary for message *content*. That guarantee comes entirely from NexTalk's client-side end-to-end encryption. The relay's job is transport availability and metadata minimization, not confidentiality of payloads (which it can't read anyway).

---

## Scaling to multiple shards

If one KV namespace and one Worker isn't enough, add more shards behind the router:

1. Deploy additional `shard/` Workers (each with its own KV namespace, optionally in different Cloudflare accounts).
2. In each shard's `wrangler.toml`, set `SHARD_URLS` (the full ring, same order everywhere) and `SELF_URL` (that shard's own URL) so clients can connect directly to their assigned shard and bypass the router's request-rate ceiling.
3. Set the same `ROUTER_SHARED_SECRET` on every shard and on the router.
4. Deploy `router/` with `SHARD_URLS` pointing at every shard.

**Growing the cluster later:** `SHARD_URLS` is append-only. Never reorder or remove existing entries, only add new ones at the end. Set `PRIOR_SHARD_COUNTS` on the router so it can still find mailboxes created under the old shard count (see the rationale in [`router.js`](router/router.js)'s file header). If you forget, existing users show up as "not registered" until they register again. This fallback becomes irrelevant on its own once every pre-resize mailbox has expired under `TTL_SECONDS`.

---

## Configuration reference

Set as `[vars]` in `wrangler.toml` (all optional, shard defaults shown):

| Variable | Default | Description |
|---|---|---|
| `MAX_MESSAGES` | `50` | Max queued messages per mailbox |
| `MAX_MSG_BYTES` | `32768` | Max size of a single message body |
| `TTL_SECONDS` | `1209600` (14 days) | Unread **message backlog** TTL: clears unclaimed queued messages, does not delete the mailbox |
| `MAILBOX_TTL_SECONDS` | `31536000` (365 days) | Whole **mailbox record** TTL: sliding, renewed on every `/create`, `/send`, `/read` |
| `MAX_CLOCK_SKEW` | `30000` (30 s) | Allowed timestamp drift / replay window |
| `MAX_SENDS_PER_SENDER` | `30` | Sends per 60 s, keyed by sender identity |
| `MAX_SENDS_PER_TARGET` | `60` | Sends per 60 s, keyed by recipient |
| `MAX_SENDS_PER_IP` | `120` | Sends per 60 s, keyed by IP |
| `MAX_CREATES_PER_IP` | `20` | Mailbox creations per 60 s, keyed by IP |
| `SHARD_URLS` | none | JSON array of shard URLs (multi-shard only) |
| `SELF_URL` | none | This shard's own URL (multi-shard only) |

Router-only variables (see `router/wrangler.toml.example` and the header of `router.js` for defaults):

| Variable | Purpose |
|---|---|
| `SHARD_URLS` | The shard ring, append-only |
| `PRIOR_SHARD_COUNTS` | Historical shard counts, so older mailboxes can still be found after a resize |
| `REPLICATION_FACTOR` | How many shards hold each mailbox |
| `ROUTING_TABLE_VERSION` | Bump it when `SHARD_URLS` changes, then trigger `POST /admin/push_routing_table` (or wait for the 5-minute cron) |
| `SHARD_POW_DIFFICULTY_BITS`, `MAX_REGISTERED_SHARDS` | Proof-of-work difficulty and cap for shard self-registration (`scripts/solve.py`) |

Secrets (set via `wrangler secret put`, never in `wrangler.toml`):

| Secret | Required on | Purpose |
|---|---|---|
| `SERVER_SECRET` | every shard, and the router | HMAC key for deriving mailbox IDs. **Rotating it orphans every mailbox.** |
| `ADMIN_SECRET` | every shard | Reserved for admin operations |
| `ROUTER_SHARED_SECRET` | shards behind a router + the router | Cross-account trust boundary |
| `ROUTER_SIGNING_KEY` | router | Signs mailbox capabilities |
| `ROUTER_SIGNING_PUBLIC` | shards | Verifies the router's capabilities (the public half; generated together by `scripts/generate.py`) |

The router also needs a KV binding named `ROUTER_ADMIN_KV`.

---

## Repository structure

```
NexTalk-Relay/
├── shard/
│   ├── worker.js              # Mailbox logic: /create, /send, /read, /health
│   ├── deploy.bat             # Windows setup/deploy helper (menu-driven)
│   └── wrangler.toml.example  # Copy to wrangler.toml and fill in
├── router/
│   ├── router.js              # Multi-shard router: /routing_table.json, /register, /resolve
│   ├── deploy.bat             # Windows setup/deploy helper (menu-driven)
│   └── wrangler.toml.example  # Copy to wrangler.toml and fill in
├── combined/
│   ├── worker.js              # Single-file shard + router for simple one-Worker deployments
│   └── wrangler.toml.example  # Config for the combined deployment
├── transports/
│   ├── nextalk-relay/         # Installable NexTalk transport (.ntx): courier bridge,
│   │   │                      #   manifest, package scripts (see its README)
│   │   ├── manifest.json      # Package metadata (manifest.windows.json for .exe)
│   │   ├── bridge/            # Go stdio-RPC ↔ Relay-JSON bridge (message ops 1–10)
│   │   ├── wasm/              # Browser (.wasm) package of the extension (loopback queue)
│   │   └── package.sh / package.ps1   # Build nextalk-relay.ntx
│   ├── build-wasm.mjs         # Build every browser package -> transports/dist (Node only)
│   ├── tools/                 # .ntx packer, manifest validator, WASM ABI v1 verifier
│   └── test/                  # Offline tests for the browser packages
├── scripts/
│   ├── generate.py            # Generate all Router secrets (SERVER_SECRET, signing keypair)
│   ├── generate.html          # Browser-based version of the same generator
│   └── solve.py               # Solve the PoW challenge locally for shard self-registration
├── docs/
│   └── RELEASING.md           # How to cut a release
└── .github/
    ├── workflows/
    │   ├── ci.yml             # Syntax check + wrangler dry-run on push/PR
    │   ├── wasm-extension.yml # Build + verify the browser (.wasm) extension
    │   └── release.yml        # Button-triggered release with auto-generated changelog
    ├── CONTRIBUTING.md
    ├── SECURITY.md
    └── PULL_REQUEST_TEMPLATE.md
```

---

## Releasing

Releases are cut with one button; see [`docs/RELEASING.md`](docs/RELEASING.md). Each immutable release contains the tagged Worker source revision plus six cross-platform `.ntx` courier transport bundles, the browser (`.wasm`) extension bundle, and a SHA-256 checksum file covering all seven. The release notes are generated automatically from the commits included in the release.

## Interop with the NexTalk transport runtime

NexTalk clients reach this relay in two ways, and both flow through the same shared dispatch (`internal/dispatch`) as every external transport, so an offer, answer or message behaves identically no matter which transport carried it:

- the built-in **`worker`** transport (`WORKER_URL`): talks to a shard directly (`nextalk worker listen`);
- the installable **`nextalk-relay`** transport (`.ntx`): talks to the router and shards ([quick start](#quick-start-chat-by-peer-id-with-the-ntx-transport)). It is message-only and uses the same pattern as FileRelay's `transports/filerelay/`.

This relay stays the JSON API above. The binary-first [FileRelay](https://github.com/erfanheydarzade/NexTalk-FileRelay) is a separate transport with its own repo, wire protocol and runnable server (`filerelayd`). You can run both side by side during migration (`nextalk worker listen` for this relay, `nextalk transport poll filerelay` for FileRelay), with history shared per identity.

The bridge signs with its own courier/scoped keys (never your identity key) and hands NexTalk deterministic 16-byte mailbox aliases for the relay's 32-byte mailbox IDs. See [`transports/nextalk-relay/README.md`](transports/nextalk-relay/README.md) for the trust model, aliasing and the two-user scenario.

---

## Status

Research-grade relay backend, developed alongside NexTalk. Not independently security-audited. Review [`shard/worker.js`](shard/worker.js) and [`router/router.js`](router/router.js) yourself before relying on this for anything sensitive. Portions of this codebase were developed with AI assistance.

Found a security issue? See [`.github/SECURITY.md`](.github/SECURITY.md) and please report privately, not as a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE).