# NexTalk Relay — HTTP-Independent Security Architecture

NexTalk does not depend on HTTPS for application-level trust.
HTTPS may be used and is recommended, but the protocol remains
cryptographically authenticated over plain HTTP.

---

## Core Principle

> Transport carries bytes. Cryptography establishes identity and trust.

The network is treated as hostile. An attacker who can read, modify,
replay, redirect, or drop traffic must still be unable to:

- Read end-to-end encrypted message contents.
- Impersonate a client or relay.
- Forge routing information or server responses.
- Replay authenticated requests.

---

## Trust Model

```
Client
  |
  | Pinned Router Public Key
  v
Router  (signs routing table)
  |
  | Signed Routing Table
  v
Relay Identity = Ed25519 Public Key
  |
  | Server Hello (challenge/response)
  v
Authenticated Relay
  |
  v
Encrypted Messages → Untrusted HTTP/TCP
```

---

## Server Identity

A NexTalk relay's identity is its **Ed25519 public key**, not its IP
address, DNS name, or TLS certificate. Location and identity are
deliberately separated:

```
Location (where):   relay.example.com
Identity (who):     Ed25519 public key (hex)
```

The Router's public key is `ROUTER_SIGNING_PUBLIC` (published in
`wrangler.toml` and in `routing_table.json`). Each shard generates its
own identity keypair on first boot, stored in its KV namespace. The
Router includes each shard's public key in the signed routing table.

---

## Endpoints

### `POST /server_hello` — Server Identity Verification

Both the Router and every shard expose this endpoint. Before trusting
any relay, a client should perform this handshake:

**Request:**
```json
{
  "nonce": "<random hex, 8–256 chars>",
  "protocol": "nextalk/v1"
}
```

**Response:**
```json
{
  "version": 1,
  "type": "server_hello",
  "protocol": "nextalk/v1",
  "server_public_key": "<hex Ed25519 public key>",
  "challenge": "<the nonce you sent>",
  "timestamp": "<unix ms>",
  "signature": "<hex Ed25519 signature>"
}
```

The `signature` covers:
```
"NexTalk Server Authentication:" + protocol + ":" + nonce + ":" + server_public_key + ":" + timestamp
```

**Client verification:**
1. Obtain the expected public key from the signed routing table.
2. Call `POST /server_hello` with a fresh random nonce.
3. Verify `signature` using the expected public key over the signed payload.
4. Reject if verification fails — do not proceed.

The nonce binds the response to this specific challenge, preventing replay
of a captured server hello for a different nonce.

---

### Signed Request Envelope — `/send`

Every `/send` request is authenticated with the sender's Ed25519 key.
The signed message covers `send:{sender_pubkey}:{mailbox_id}:{timestamp}:{message_hash}`,
preventing MITM modification of the target, message body, or identity.

Optional signed response: include `"request_id": "<random id>"` in the
send body. The shard wraps its response in a signed envelope (see below).

---

### Signed Responses — `/send` and `/read`

A MITM between client and shard could fabricate:

- `{"messages": []}` to suppress message delivery
- `{"success": false}` to make a delivered message appear to fail
- `401 Unauthorized` to stop a client from communicating

When the client includes a `request_id`, the shard signs its response:

**Triggered by:**
- `/send` body: `"request_id": "<random 128-bit hex>"`
- `/read` query: `?request_id=<random 128-bit hex>`

**Response envelope:**
```json
{
  "version": 1,
  "request_id": "...",
  "status": 200,
  "timestamp": "...",
  "body_hash": "<SHA-256 of JSON-stringified body>",
  "body": { ... },
  "server_public_key": "<shard's Ed25519 public key>",
  "signature": "<hex Ed25519 signature>"
}
```

The `signature` covers: `request_id + ":" + status + ":" + timestamp + ":" + body_hash`

The same pattern applies to the Router's `/register` response when a
`request_id` is included in the register body (signed with the Router key).

---

## Capability Format (v2)

Router-minted capabilities now bind to the mailbox owner's public key
and an explicit operation scope:

```
cap:v2:{mailbox_id}:{client_pubkey}:{scope}:{cap_exp}:{nonce}
```

Where `scope` is one of:
- `mailbox.create` — authorises `/create` on the shard
- *(future)* `mailbox.read`, `mailbox.send`

**Properties:**
- A captured `mailbox.create` capability cannot be repurposed to read.
- A capability stolen from one client cannot be used by another (pubkey binding).
- The nonce prevents capability reuse across sessions.

V1 capabilities (`cap:{mailbox_id}:{read_secret_hash}:{cap_exp}`) are
still accepted by shards for backward compatibility.

---

## Shard Key Rotation

### `POST /admin/rotate_key` (on the shard)

Generates a new identity keypair locally and notifies the Router.
Requires `SELF_URL` and optionally `ROUTER_URL` to be configured.

**Response:**
```json
{
  "rotated": true,
  "old_pubkey": "...",
  "new_pubkey": "...",
  "router_notified": true,
  "router_response": { ... }
}
```

### `POST /rotate_shard_key` (on the Router)

Called by a shard (or its operator) when rotating its identity key.
Requires two signatures:

| Field           | Signs                                                                      |
|-----------------|---------------------------------------------------------------------------|
| `old_signature` | `key_rotation:{shard_url}:{old_pubkey}:{new_pubkey}:{timestamp}`          |
| `new_signature` | `key_rotation_accept:{shard_url}:{old_pubkey}:{new_pubkey}:{timestamp}`   |

The old key proves the current identity holder authorized the migration.
The new key proves the caller actually controls it.
Neither alone is sufficient.

On success, the Router updates the registered-shard record and bumps the
routing table version so peers pick up the change on the next push.

---

## Two-Stage Trust Chain

```
Client knows: Router public key (hardcoded or out-of-band)
    ↓
Fetches routing_table.json (Router-signed)
    ↓
Learns: shard URLs + each shard's public key
    ↓
Connects to shard, calls POST /server_hello with nonce
    ↓
Shard signs nonce with its identity key
    ↓
Client verifies signature using shard pubkey from routing table
    ↓
Shard is authenticated: it genuinely holds the private key
   matching the routing table entry the Router endorsed
```

A compromised routing response alone cannot impersonate a shard —
the attacker must also hold the shard's private key.

---

## Replay Protection

Every authenticated send includes:

- `timestamp` — rejected outside ±MAX\_CLOCK\_SKEW of server time.
- `signature` — Ed25519 over the full request content.
- Replay key: `SHA-256(pubkey + ":" + timestamp + ":" + signature)` stored in KV
  for the duration of the clock-skew window; duplicate submissions are rejected.

Optional `request_id` on send/read ties each signed response uniquely
to the specific request that triggered it.

---

## Protocol Layers

```
Layer 7 — NexTalk Application Protocol
         Messages / Mailboxes / Handshake

Layer 6 — NexTalk Server Authentication
         POST /server_hello
         Ed25519 challenge / response
         Key pinning via routing table

Layer 5 — NexTalk Request Authentication
         Request IDs / Timestamps / Signatures
         Signed Responses / Replay Protection
         Scoped Capabilities (v2)

Layer 4 — End-to-End Cryptography
         (client responsibility: X25519 / Kyber768 / HKDF / AEAD)

Layer 3 — Relay / Router Trust
         Signed Routing Tables
         Signed Capabilities
         Signed Shard Identities
         Key Rotation Records

Layer 2 — Transport
         HTTP / HTTPS / QUIC / Tor / other

Layer 1 — Network (potentially hostile)
```

Security does not collapse when the transport changes from HTTPS to HTTP
because **identity, authorization, integrity, replay protection, and
message confidentiality all exist above the transport layer**.
