/**
 * Mailbox Mesh Router — Cloudflare Worker  (v2: capability architecture)
 *
 * ─────────────────────────────────────────────────────────────────────────
 * This Router is deliberately OFF the hot path. It is contacted:
 *
 *   1. Rarely, by every client, for GET /routing_table.json — a small
 *      signed, cacheable document describing shard topology. Clients cache
 *      this and route locally (hash(pubkey) % N, with era fallback for
 *      pubkeys registered before a resize) instead of asking the Router
 *      per-request.
 *
 *   2. Once per identity, for POST /register — mints a capability
 *      (opaque mailbox_id + read_secret) and forwards mailbox creation to
 *      the owning shard. The client caches the result forever.
 *
 *   3. Once per (client, peer) pair, for GET /resolve — tells a SENDER
 *      which opaque mailbox_id/shard a recipient pubkey maps to, without
 *      requiring any proof of key ownership (a pubkey is a public mailing
 *      address; anyone may look up where to deliver to it). The client
 *      caches this per-peer forever.
 *
 * The Router NEVER proxies /send or /read. Those go client → shard
 * directly, forever, until a routing_table version bump forces a refresh.
 *
 * Required secret: SERVER_SECRET
 *   HMAC key for mailbox_id = HMAC_SHA256(pubkey, SERVER_SECRET). ONLY the
 *   Router ever holds this. Shards never see it and never see pubkeys in
 *   the mailbox-storage path — see adapter's capability model below.
 *
 * Required secret: ROUTER_SIGNING_KEY
 *   Ed25519 private key (PKCS8, base64), used to sign routing_table.json
 *   and per-mailbox capabilities. Shards verify with the corresponding
 *   ROUTER_SIGNING_PUBLIC (a PUBLIC key — safe to hardcode/publish, and the
 *   only "trust" a community shard operator needs to configure).
 *
 * Required var: ROUTER_SIGNING_PUBLIC (hex, 32 bytes) — the public half.
 *
 * Required var: SHARD_URLS  (JSON array, APPEND-ONLY — see original design
 *   notes; still true here, since shard *placement* still uses mod-N.)
 *
 * Optional var: PRIOR_SHARD_COUNTS — same semantics as v1, used both for
 *   client-side era fallback (published in routing_table.json) and for
 *   Router-side /resolve probing of older eras.
 *
 * Required var: ROUTING_TABLE_VERSION — integer, bumped by the operator on
 *   every SHARD_URLS/PRIOR_SHARD_COUNTS change. This is the signal clients
 *   use to know their cached table is stale, on top of expires_at.
 *
 * Optional secret: ROUTER_SHARED_SECRET — still used for the /status
 *   health-aggregation endpoint (operator-facing), NOT part of the client
 *   trust model anymore.
 *
 * Optional KV namespace binding: ROUTER_ADMIN_KV
 *   If bound, SHARD_URLS / PRIOR_SHARD_COUNTS / ROUTING_TABLE_VERSION are
 *   read from this KV namespace FIRST (keys "shard_urls",
 *   "prior_shard_counts", "routing_table_version"), falling back to the
 *   wrangler.toml vars of the same name if the KV key is absent. This is
 *   what lets an operator add a shard or bump the table version with a
 *   single `wrangler kv key put` — no redeploy, no restart, live within
 *   HEALTH_CACHE_TTL_MS-scale latency. See router-admin.bat.
 *
 * ─── Routing-table PUSH (v2.1) ──────────────────────────────────────────
 * GET /routing_table.json still works directly on the Router (bootstrap /
 * fallback — a client has to learn of a shard from *somewhere*, and if
 * every shard happens to be behind on a push this keeps clients working).
 * It's just no longer meant to be the common path.
 *
 * The Router still computes + signs the table alone (SHARD_URLS /
 * PRIOR_SHARD_COUNTS / ROUTING_TABLE_VERSION all still live here) and now
 * PUSHES that signed document out to every shard's POST
 * /internal/routing_table. Shards cache whatever they're given and serve
 * GET /routing_table.json themselves from that cache — see
 * shard/worker.js. Clients then read the table from a shard instead of
 * hitting the Router on every refresh.
 *
 * The push happens two ways:
 *   1. On a Cron Trigger (see wrangler.toml [triggers] crons) on an
 *      interval comfortably shorter than ROUTING_TABLE_TTL_SECONDS, so
 *      shard caches never go stale under normal operation.
 *   2. On demand via POST /admin/push_routing_table (ROUTER_SHARED_SECRET-
 *      protected), for right after an operator bumps SHARD_URLS /
 *      ROUTING_TABLE_VERSION in ROUTER_ADMIN_KV and doesn't want to wait
 *      for the next cron tick.
 *
 * Shards authenticate the push using the exact same ROUTER_SIGNING_PUBLIC
 * key they already hold for capability verification — no new secret is
 * shared between Router and shards for this.
 *
 * ─── Shard self-registration, PoW-gated (v2.2) ──────────────────────────
 * Shards no longer need an operator to hand-edit SHARD_URLS. A shard can
 * introduce itself: GET /pow_challenge, solve it (CPU-bound proof of
 * work), then POST /register_shard with its URL, its own self-generated
 * Ed25519 pubkey, the PoW solution, and a signature proving it holds the
 * matching private key. This is the anti-flooding gate — minting a
 * proof takes real, tunable CPU time (SHARD_POW_DIFFICULTY_BITS), so
 * spinning up thousands of junk shards costs real resources, and
 * MAX_REGISTERED_SHARDS caps the mesh size as defense in depth on top of
 * that. The Router never asks *who* is running the shard — no identity,
 * no payment — only that the PoW toll was paid and the key is genuinely
 * held. Registered shards (and their pubkeys) are stored in
 * ROUTER_ADMIN_KV and become part of the signed routing_table, which is
 * what lets a *shard* later trust a *replicate* push claiming to come
 * from another shard (see shard/worker.js handleReplicate) — the trust is
 * transitive through the Router, never a secret shared peer-to-peer.
 * This feature requires ROUTER_ADMIN_KV; without it, /pow_challenge and
 * /register_shard return 501 and topology stays fully static/manual.
 *
 * ─── Replication factor (v2.2) ──────────────────────────────────────────
 * /register and /resolve now return a whole replica SET (REPLICATION_FACTOR
 * shard URLs, consecutive on the hash ring starting at the primary) instead
 * of a single shard. The client only ever talks to replicas[0] (primary);
 * the primary shard itself fans a copy of every accepted message out to
 * the rest of the set (see shard/worker.js). The Router itself never
 * proxies message bytes — it only decides *which* shards form a set.
 */

const ROUTING_TABLE_TTL_SECONDS = 3600      // how long clients may cache the table
const CAPABILITY_TTL_SECONDS = 31_536_000 // must match shard MAILBOX_TTL_SECONDS
const HEALTH_CACHE_TTL_MS = 10_000

const POW_DIFFICULTY_BITS_DEFAULT = 20        // ~1M average hash attempts — seconds of CPU
const POW_CHALLENGE_TTL_SECONDS = 120
const MAX_REGISTERED_SHARDS_DEFAULT = 200
const REGISTER_SHARD_RATE_LIMIT_PER_HOUR = 6
const POW_CHALLENGE_RATE_LIMIT_PER_HOUR = 30
const REPLICATION_FACTOR_DEFAULT = 1

let healthCache = { checkedAt: 0, healthyUrls: null }

// ─── Encoding / crypto helpers ──────────────────────────────────────────────

function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("")
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

async function sha256Hex(str) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str))
  return bytesToHex(new Uint8Array(digest))
}

async function hmacHex(message, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  )
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message))
  return bytesToHex(new Uint8Array(sig))
}

/** hash(pubkey) % n, same algorithm as the original router — public, no secret. */
async function hashPoint(str) {
  const hex = await sha256Hex(str)
  return parseInt(hex.slice(0, 8), 16)
}
async function ownerForEra(pubkey, n, shardUrls) {
  const point = await hashPoint(pubkey.toLowerCase())
  return shardUrls[point % n]
}
function eraCountsDescending(shardUrls, priorCounts) {
  const currentN = shardUrls.length
  const all = [currentN, ...(priorCounts || [])].filter(n => Number.isInteger(n) && n > 0 && n <= shardUrls.length)
  return [...new Set(all)].sort((a, b) => b - a)
}

// Ed25519 signing (Router's own key) — used for routing_table.json and capabilities.
async function importSigningKey(pkcs8Base64) {
  const raw = Uint8Array.from(atob(pkcs8Base64), c => c.charCodeAt(0))
  return crypto.subtle.importKey("pkcs8", raw, { name: "Ed25519" }, false, ["sign"])
}
async function signHex(privKey, message) {
  const sig = await crypto.subtle.sign("Ed25519", privKey, new TextEncoder().encode(message))
  return bytesToHex(new Uint8Array(sig))
}

async function verifyEd25519(pubkeyHex, message, sigHex) {
  try {
    const key = await crypto.subtle.importKey("raw", hexToBytes(pubkeyHex), { name: "Ed25519" }, false, ["verify"])
    return await crypto.subtle.verify("Ed25519", key, hexToBytes(sigHex), new TextEncoder().encode(message))
  } catch {
    return false
  }
}

function randomHex(bytes = 32) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)))
}

function leadingZeroBits(bytes) {
  let bits = 0
  for (const b of bytes) {
    if (b === 0) { bits += 8; continue }
    let x = b
    while ((x & 0x80) === 0) { bits++; x <<= 1 }
    break
  }
  return bits
}

/** Replica set for a hash point: primary plus the next (r-1) shards on the ring. */
function replicaSetForEra(point, n, shardUrls, r) {
  const start = point % n
  const set = []
  for (let i = 0; i < r; i++) set.push(shardUrls[(start + i) % n])
  return set
}
async function replicasForEra(pubkeyOrId, n, shardUrls, r) {
  const point = await hashPoint(String(pubkeyOrId).toLowerCase())
  return replicaSetForEra(point, n, shardUrls, r)
}
function replicationFactor(env, n) {
  const want = Number(env.REPLICATION_FACTOR || REPLICATION_FACTOR_DEFAULT)
  return Math.max(1, Math.min(want, n))
}

// ─── Shard health (unchanged from v1, operator-facing only) ────────────────

async function checkShardHealth(shardUrl, secret) {
  try {
    const headers = secret ? { Authorization: `Bearer ${secret}` } : {}
    const resp = await fetch(`${shardUrl}/health`, { headers, signal: AbortSignal.timeout(3000) })
    return resp.ok
  } catch {
    return false
  }
}
async function getHealthyShards(shardUrls, secret) {
  const now = Date.now()
  if (healthCache.healthyUrls && now - healthCache.checkedAt < HEALTH_CACHE_TTL_MS) return healthCache.healthyUrls
  const results = await Promise.all(shardUrls.map(u => checkShardHealth(u, secret)))
  const healthy = shardUrls.filter((_, i) => results[i])
  healthCache = { checkedAt: now, healthyUrls: healthy.length ? healthy : shardUrls }
  return healthCache.healthyUrls
}

// ─── Live-updatable config (KV-backed, falls back to wrangler.toml vars) ────
//
// Reading these from KV (when ROUTER_ADMIN_KV is bound) is what lets an
// operator change shard topology or bump the routing table version without
// a redeploy. KV reads are fast/cached at Cloudflare's edge, so this adds
// negligible latency to /routing_table.json and /register.

// Static/manual shards (from KV override or the wrangler.toml var) form the
// stable low indices of the mesh; self-registered shards (see
// handleRegisterShard) are appended after, in registration order — this
// keeps the whole list APPEND-ONLY, same invariant the original mod-N /
// era-fallback design already depended on.
async function getShardUrls(env) {
  let base
  if (env.ROUTER_ADMIN_KV) {
    const raw = await env.ROUTER_ADMIN_KV.get("shard_urls")
    if (raw) {
      const parsed = JSON.parse(raw)
      if (Array.isArray(parsed) && parsed.length > 0) base = parsed
    }
  }
  if (!base) {
    try { base = JSON.parse(env.SHARD_URLS || "[]") } catch { base = [] }
  }

  const registered = (await getRegisteredShards(env)).map(s => s.url)
  const merged = [...base]
  for (const url of registered) if (!merged.includes(url)) merged.push(url)
  return merged
}

async function getRegisteredShards(env) {
  if (!env.ROUTER_ADMIN_KV) return []
  const raw = await env.ROUTER_ADMIN_KV.get("registered_shards")
  if (!raw) return []
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

async function getShardPubkeys(env) {
  const registered = await getRegisteredShards(env)
  const map = {}
  for (const s of registered) map[s.url] = s.pubkey
  return map
}

async function adminRateLimit(env, bucketKey, limit, windowSeconds) {
  if (!env.ROUTER_ADMIN_KV) return true // no KV bound → self-registration is disabled anyway
  const key = `rl:${bucketKey}:${Math.floor(Date.now() / (windowSeconds * 1000))}`
  const current = Number((await env.ROUTER_ADMIN_KV.get(key)) || "0")
  if (current >= limit) return false
  await env.ROUTER_ADMIN_KV.put(key, String(current + 1), { expirationTtl: windowSeconds + 5 })
  return true
}

async function getPriorShardCounts(env) {
  if (env.ROUTER_ADMIN_KV) {
    const raw = await env.ROUTER_ADMIN_KV.get("prior_shard_counts")
    if (raw) {
      try {
        const parsed = JSON.parse(raw)
        if (Array.isArray(parsed)) return parsed
      } catch { /* fall through to var */ }
    }
  }
  if (!env.PRIOR_SHARD_COUNTS) return []
  try {
    const parsed = JSON.parse(env.PRIOR_SHARD_COUNTS)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

async function getRoutingTableVersion(env) {
  if (env.ROUTER_ADMIN_KV) {
    const raw = await env.ROUTER_ADMIN_KV.get("routing_table_version")
    if (raw && /^\d+$/.test(raw.trim())) return Number(raw.trim())
  }
  return Number(env.ROUTING_TABLE_VERSION || 1)
}

// ─── Response helpers ────────────────────────────────────────────────────────

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
}
function jsonOk(data, extraHeaders = {}) {
  return Response.json(data, { headers: { ...CORS_HEADERS, ...extraHeaders } })
}
function jsonErr(message, status) {
  return Response.json({ error: message }, { status, headers: CORS_HEADERS })
}

// ─── GET /routing_table.json ────────────────────────────────────────────────
//
// Public, signed, cacheable. Clients download this ONCE and reuse it for
// every routing decision until expires_at or a version bump. This is the
// single biggest lever for keeping Router traffic flat as shard count grows:
// the exact same bytes serve every client, regardless of how many mailboxes
// or messages exist.

// buildSignedRoutingTable is the ONE place the routing table document is
// assembled and signed. Both the Router's own GET /routing_table.json
// (bootstrap/fallback) and the push-to-shards path (the now-primary
// distribution path) call this, so they can never drift out of sync with
// each other.
async function buildSignedRoutingTable(env) {
  const shardUrls = await getShardUrls(env)
  const priorCounts = await getPriorShardCounts(env)
  const version = await getRoutingTableVersion(env)
  const pubkeys = await getShardPubkeys(env)
  const now = Date.now()

  const body = {
    version,
    generated_at: now,
    expires_at: now + ROUTING_TABLE_TTL_SECONDS * 1000,
    algorithm: "sha256-hashpoint-modn-era-fallback-v1",
    shard_urls: shardUrls,
    // `shards` pairs each URL with the self-registered identity pubkey (see
    // handleRegisterShard) it proved ownership of, when one exists. Shards
    // without a pubkey here (manually configured, never self-registered)
    // simply can't participate as a verified `/internal/replicate` origin —
    // they still work fine for direct client Send/Read.
    shards: shardUrls.map(url => ({ url, pubkey: pubkeys[url] || null })),
    replication_factor: replicationFactor(env, shardUrls.length),
    prior_shard_counts: priorCounts,
    router_public_key: env.ROUTER_SIGNING_PUBLIC,
  }

  // JSON.stringify is deterministic because key order is fixed above.
  const canonical = JSON.stringify(body)

  const signingKey = await importSigningKey(env.ROUTER_SIGNING_KEY)
  const signature = await signHex(signingKey, canonical)

  return { ...body, signature }
}

async function handleRoutingTable(env) {
  const signed = await buildSignedRoutingTable(env)
  return jsonOk(signed, {
    "Content-Type": "application/json",
    "Cache-Control": `public, max-age=${ROUTING_TABLE_TTL_SECONDS}, s-maxage=${ROUTING_TABLE_TTL_SECONDS}`,
  })
}

// ─── Push routing table to shards ──────────────────────────────────────────
//
// Called from the `scheduled` cron handler and from the on-demand admin
// endpoint. Shards verify the signature themselves (see shard/worker.js
// handleRoutingTablePush) — a shard that's down or misbehaving just fails
// its own push and keeps serving its last-known-good cached copy; it does
// NOT block or slow down the other shards' pushes.
async function pushRoutingTableToShards(env, shardUrls) {
  const signed = await buildSignedRoutingTable(env)
  const body = JSON.stringify(signed)

  const results = await Promise.all(
    shardUrls.map(async shardUrl => {
      try {
        const resp = await fetch(`${shardUrl}/internal/routing_table`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
          signal: AbortSignal.timeout(5000),
        })
        return { shardUrl, ok: resp.ok, status: resp.status }
      } catch (e) {
        return { shardUrl, ok: false, error: String(e) }
      }
    })
  )

  return { version: signed.version, results }
}

// ─── POST /register ──────────────────────────────────────────────────────────
//
// One-time-per-identity. Requires proof of pubkey ownership. Mints the
// opaque mailbox_id (only the Router can compute this — SERVER_SECRET never
// leaves the Router) and a random read_secret capability, then asks the
// owning shard to create the mailbox WITHOUT ever telling the shard the
// pubkey. The client caches everything in the response forever.

async function handleRegister(request, env, shardUrls) {
  let body
  try { body = await request.json() } catch { return jsonErr("Request body must be valid JSON", 400) }

  const { pubkey, timestamp, signature } = body || {}
  if (!pubkey || !/^[0-9a-f]{64}$/i.test(pubkey)) return jsonErr("pubkey must be 64-char hex", 400)
  if (!timestamp || !/^\d+$/.test(timestamp)) return jsonErr("timestamp required", 400)
  if (!signature || !/^[0-9a-f]{128}$/i.test(signature)) return jsonErr("signature must be 128-char hex", 400)

  const skewMs = 30_000
  if (Math.abs(Date.now() - Number(timestamp)) > skewMs) return jsonErr("timestamp outside allowed skew", 401)

  const ok = await verifyEd25519(pubkey, `register:${pubkey.toLowerCase()}:${timestamp}`, signature)
  if (!ok) return jsonErr("signature verification failed", 401)

  const mailboxId = await hmacHex(pubkey.toLowerCase(), env.SERVER_SECRET)
  const r = replicationFactor(env, shardUrls.length)
  // Always the current era for new registrations — replicas[0] is primary.
  const replicas = await replicasForEra(pubkey, shardUrls.length, shardUrls, r)
  const shardUrl = replicas[0]

  const readSecret = randomHex(32)
  const readSecretHash = await sha256Hex(readSecret)
  const capExp = Date.now() + CAPABILITY_TTL_SECONDS * 1000

  const signingKey = await importSigningKey(env.ROUTER_SIGNING_KEY)
  const capSig = await signHex(signingKey, `cap:${mailboxId}:${readSecretHash}:${capExp}`)

  // The capability itself carries no shard-specific data, so the exact same
  // signed cap can be presented to every replica's /create — that's what
  // lets us fan this out to the whole replica set in one shot instead of
  // needing a distinct capability per shard.
  const createBody = JSON.stringify({
    mailbox_id: mailboxId,
    read_secret_hash: readSecretHash,
    cap_exp: capExp,
    cap_sig: capSig,
    replica_shard_urls: replicas,
  })

  const createResults = await Promise.all(
    replicas.map(url =>
      fetch(`${url}/create`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: createBody,
        signal: AbortSignal.timeout(10_000),
      })
        .then(resp => ({ url, ok: resp.ok }))
        .catch(() => ({ url, ok: false })),
    ),
  )

  if (!createResults[0].ok) {
    return jsonErr("Failed to create mailbox on primary shard", 502)
  }
  const failedReplicas = createResults.slice(1).filter(res => !res.ok)
  if (failedReplicas.length) {
    // Best-effort: the primary succeeded, so the mailbox is usable now.
    // Any replica that missed /create here will be caught up the first
    // time the primary replicates an actual message to it (see
    // shard/worker.js handleReplicate, which creates a shell record if
    // needed) — we don't fail registration over a replica hiccup.
    console.error("register: some replicas failed /create", failedReplicas)
  }

  const response = {
    mailbox_id: mailboxId,
    read_secret: readSecret,
    shard_url: shardUrl,
    replica_shard_urls: replicas,
    expires_at: capExp,
    table_version: await getRoutingTableVersion(env),
  };

  console.log("REGISTER RESPONSE:");
  console.log(JSON.stringify(response));

  return jsonOk(response);
}

// ─── GET /resolve?pubkey=... ─────────────────────────────────────────────────
//
// No proof of ownership required — a pubkey is a public mailing address,
// and knowing where to deliver to it is not itself sensitive (the shard
// still never learns the mapping; only the sender's own client does, and
// only for peers it actually messages). Cacheable per-peer, indefinitely,
// by the caller.
//
// Tries the current era first, then walks PRIOR_SHARD_COUNTS, probing each
// candidate shard for the mailbox's existence — this is the only place the
// Router still makes outbound calls on a "hot-ish" path, but it is bounded
// (number of eras, typically 1) and its result is cached by the client
// forever after, so its amortized cost trends to zero.

async function handleResolve(request, env, shardUrls) {
  const url = new URL(request.url)
  const pubkey = url.searchParams.get("pubkey")
  if (!pubkey || !/^[0-9a-f]{64}$/i.test(pubkey)) return jsonErr("pubkey (64-char hex) query param required", 400)

  const mailboxId = await hmacHex(pubkey.toLowerCase(), env.SERVER_SECRET)

  const priorCounts = await getPriorShardCounts(env)
  const eras = eraCountsDescending(shardUrls, priorCounts)

  for (const n of eras) {
    const r = replicationFactor(env, n)
    const replicas = await replicasForEra(pubkey, n, shardUrls, r)
    const shardUrl = replicas[0]
    // HEAD-style existence probe against the primary only: shards don't
    // expose pubkeys, so we can only ask "does this opaque mailbox_id
    // exist here" — a lightweight, unauthenticated existence check the
    // shard is free to rate-limit.
    try {
      const resp = await fetch(`${shardUrl}/exists?mailbox_id=${mailboxId}`, { signal: AbortSignal.timeout(3000) })
      if (resp.ok) {
        return jsonOk({
          mailbox_id: mailboxId,
          shard_url: shardUrl,
          replica_shard_urls: replicas,
          era: n,
          table_version: await getRoutingTableVersion(env),
        })
      }
    } catch { /* try next era */ }
  }

  // Nothing found in any era — still return the current-era guess so a
  // client can retry after the recipient registers (mailbox may simply not
  // exist yet).
  const currentR = replicationFactor(env, shardUrls.length)
  const currentReplicas = await replicasForEra(pubkey, shardUrls.length, shardUrls, currentR)
  return jsonOk({
    mailbox_id: mailboxId,
    shard_url: currentReplicas[0],
    replica_shard_urls: currentReplicas,
    era: shardUrls.length,
    table_version: await getRoutingTableVersion(env),
    note: "mailbox not confirmed to exist yet on any known era",
  })
}

// ─── GET /pow_challenge — step 1 of shard self-registration ────────────────
//
// Cheap to issue, rate-limited per IP anyway (issuing challenges is nearly
// free, so this rate limit is just to stop challenge-request spam, not the
// actual anti-flooding gate — that's the PoW work itself, checked in
// handleRegisterShard). Requires ROUTER_ADMIN_KV to store the single-use
// nonce; without it, self-registration is simply unavailable.
async function handlePowChallenge(request, env) {
  if (!env.ROUTER_ADMIN_KV) {
    return jsonErr("shard self-registration is disabled on this Router (no ROUTER_ADMIN_KV bound)", 501)
  }

  const ip = request.headers.get("CF-Connecting-IP") || "unknown"
  const okIp = await adminRateLimit(env, `pow-challenge-ip:${ip}`, POW_CHALLENGE_RATE_LIMIT_PER_HOUR, 3600)
  if (!okIp) return jsonErr("too many challenge requests, slow down", 429)

  const nonce = randomHex(16)
  const difficulty = Number(env.SHARD_POW_DIFFICULTY_BITS || POW_DIFFICULTY_BITS_DEFAULT)
  const expiresAt = Date.now() + POW_CHALLENGE_TTL_SECONDS * 1000

  await env.ROUTER_ADMIN_KV.put(
    `pow_nonce:${nonce}`,
    JSON.stringify({ difficulty, expiresAt }),
    { expirationTtl: POW_CHALLENGE_TTL_SECONDS + 5 },
  )

  return jsonOk({ nonce, difficulty, expires_at: expiresAt })
}

// ─── POST /register_shard — step 2 of shard self-registration ─────────────
//
// This is the actual anti-flooding gate. A registration is only accepted
// if ALL of these hold:
//   1. The nonce is a real, unexpired, not-yet-consumed challenge this
//      Router issued (single-use — deleted the moment it's redeemed).
//   2. sha256(nonce:shard_url:solution) has at least `difficulty` leading
//      zero bits — real, tunable CPU cost, paid fresh per registration.
//   3. The self-signature over (shard_url, shard_pubkey, timestamp) is
//      valid for shard_pubkey — proves the caller genuinely holds that
//      private key, not just that they picked a random-looking pubkey.
//   4. The mesh isn't already at MAX_REGISTERED_SHARDS (unless this is a
//      re-registration / key-rotation for an already-known URL).
// On success the shard is appended to ROUTER_ADMIN_KV's registered list —
// which is what getShardUrls()/buildSignedRoutingTable() read from — and
// the routing_table version is bumped so the change propagates on the
// very next scheduled push (or immediately via /admin/push_routing_table).
async function handleRegisterShard(request, env) {
  if (!env.ROUTER_ADMIN_KV) {
    return jsonErr("shard self-registration is disabled on this Router (no ROUTER_ADMIN_KV bound)", 501)
  }

  let body
  try { body = await request.json() } catch { return jsonErr("Request body must be valid JSON", 400) }

  const { shard_url: shardUrl, shard_pubkey: shardPubkey, nonce, solution, timestamp, signature } = body || {}

  if (!shardUrl || typeof shardUrl !== "string" || !/^https?:\/\/\S+$/i.test(shardUrl)) {
    return jsonErr("shard_url must be a valid http(s) URL", 400)
  }
  if (!shardPubkey || !/^[0-9a-f]{64}$/i.test(shardPubkey)) return jsonErr("shard_pubkey must be 64-char hex", 400)
  if (!nonce || typeof nonce !== "string") return jsonErr("nonce is required", 400)
  if (!solution || typeof solution !== "string") return jsonErr("solution is required", 400)
  if (!timestamp || !/^\d+$/.test(timestamp)) return jsonErr("timestamp required", 400)
  if (!signature || !/^[0-9a-f]{128}$/i.test(signature)) return jsonErr("signature must be 128-char hex", 400)

  const ip = request.headers.get("CF-Connecting-IP") || "unknown"
  const ipOk = await adminRateLimit(env, `register-shard-ip:${ip}`, REGISTER_SHARD_RATE_LIMIT_PER_HOUR, 3600)
  if (!ipOk) return jsonErr("too many shard registration attempts from this IP, slow down", 429)

  // 1 & 2: consume the challenge, check PoW difficulty.
  const challengeRaw = await env.ROUTER_ADMIN_KV.get(`pow_nonce:${nonce}`)
  if (!challengeRaw) return jsonErr("unknown, expired, or already-used nonce — request a fresh /pow_challenge", 401)
  let challenge
  try { challenge = JSON.parse(challengeRaw) } catch { return jsonErr("internal challenge storage error", 500) }
  if (Date.now() > challenge.expiresAt) return jsonErr("PoW challenge expired", 401)

  const powDigest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${nonce}:${shardUrl}:${solution}`)),
  )
  if (leadingZeroBits(powDigest) < challenge.difficulty) {
    return jsonErr("proof-of-work does not meet required difficulty", 401)
  }
  await env.ROUTER_ADMIN_KV.delete(`pow_nonce:${nonce}`) // single-use, regardless of outcome below

  // 3: self-signature, proving key ownership.
  if (Math.abs(Date.now() - Number(timestamp)) > 60_000) return jsonErr("timestamp outside allowed skew", 401)
  const signedMessage = `register_shard:${shardUrl}:${shardPubkey.toLowerCase()}:${timestamp}`
  const sigOk = await verifyEd25519(shardPubkey, signedMessage, signature)
  if (!sigOk) return jsonErr("self-signature verification failed", 401)

  // 4: mesh size cap (defense in depth beyond the PoW toll itself).
  const existing = await getRegisteredShards(env)
  const maxShards = Number(env.MAX_REGISTERED_SHARDS || MAX_REGISTERED_SHARDS_DEFAULT)
  const already = existing.find(s => s.url === shardUrl)
  if (!already && existing.length >= maxShards) {
    return jsonErr(`mesh is at capacity (${maxShards} shards) — contact the Router operator`, 403)
  }

  const updated = already
    ? existing.map(s =>
        s.url === shardUrl
          ? { url: shardUrl, pubkey: shardPubkey.toLowerCase(), registered_at: s.registered_at, updated_at: Date.now() }
          : s,
      )
    : [...existing, { url: shardUrl, pubkey: shardPubkey.toLowerCase(), registered_at: Date.now() }]

  await env.ROUTER_ADMIN_KV.put("registered_shards", JSON.stringify(updated))

  const currentVersion = await getRoutingTableVersion(env)
  await env.ROUTER_ADMIN_KV.put("routing_table_version", String(currentVersion + 1))

  return jsonOk({
    registered: true,
    shard_url: shardUrl,
    shard_count: updated.length,
    table_version: currentVersion + 1,
  })
}

// ─── /status (operator-facing, unchanged in spirit) ─────────────────────────

async function handleStatus(env, shardUrls) {
  const healthy = await getHealthyShards(shardUrls, env.ROUTER_SHARED_SECRET)
  return jsonOk({
    totalShards: shardUrls.length,
    healthyShards: healthy.length,
    shards: shardUrls.map(u => ({ url: u, healthy: healthy.includes(u) })),
  })
}

// ─── Main fetch handler ──────────────────────────────────────────────────────

export default {
  // Cron Trigger entry point (see wrangler.toml [triggers] crons). Keeps
  // shard-cached routing tables fresh without any client ever having to
  // ask the Router directly. Interval should be comfortably shorter than
  // ROUTING_TABLE_TTL_SECONDS (3600s) — every 5-10 minutes is plenty.
  async scheduled(controller, env, ctx) {
    if (!env.SERVER_SECRET || !env.ROUTER_SIGNING_KEY || !env.ROUTER_SIGNING_PUBLIC) {
      console.error("Router misconfiguration: cannot push routing table")
      return
    }
    let shardUrls
    try {
      shardUrls = await getShardUrls(env)
      if (!Array.isArray(shardUrls) || shardUrls.length === 0) throw new Error("empty")
    } catch {
      console.error("SHARD_URLS is missing or invalid — skipping scheduled routing table push")
      return
    }
    const outcome = await pushRoutingTableToShards(env, shardUrls)
    const failed = outcome.results.filter(r => !r.ok)
    if (failed.length) {
      console.error(`routing_table push: ${failed.length}/${outcome.results.length} shards failed`, failed)
    } else {
      console.log(`routing_table push: v${outcome.version} delivered to ${outcome.results.length} shards`)
    }
  },

  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS })

    if (!env.SERVER_SECRET || !env.ROUTER_SIGNING_KEY || !env.ROUTER_SIGNING_PUBLIC) {
      console.error("Router misconfiguration: SERVER_SECRET / ROUTER_SIGNING_KEY / ROUTER_SIGNING_PUBLIC required")
      return jsonErr("Router misconfiguration", 500)
    }

    let shardUrls
    try {
      shardUrls = await getShardUrls(env)
      if (!Array.isArray(shardUrls) || shardUrls.length === 0) throw new Error("empty")
    } catch {
      console.error("SHARD_URLS is missing or invalid (checked ROUTER_ADMIN_KV then env var)")
      return jsonErr("Router misconfiguration", 500)
    }

    const url = new URL(request.url)

    try {
      if (url.pathname === "/routing_table.json" && request.method === "GET") {
        return await handleRoutingTable(env)
      }
      if (url.pathname === "/register" && request.method === "POST") {
        return await handleRegister(request, env, shardUrls)
      }
      if (url.pathname === "/resolve" && request.method === "GET") {
        return await handleResolve(request, env, shardUrls)
      }
      if (url.pathname === "/status" && request.method === "GET") {
        return await handleStatus(env, shardUrls)
      }
      if (url.pathname === "/pow_challenge" && request.method === "GET") {
        return await handlePowChallenge(request, env)
      }
      if (url.pathname === "/register_shard" && request.method === "POST") {
        return await handleRegisterShard(request, env)
      }
      // Force an immediate push of the current signed routing table to
      // every shard, instead of waiting for the next cron tick. Handy right
      // after bumping SHARD_URLS / ROUTING_TABLE_VERSION in ROUTER_ADMIN_KV.
      if (url.pathname === "/admin/push_routing_table" && request.method === "POST") {
        if (env.ROUTER_SHARED_SECRET) {
          const authHeader = request.headers.get("Authorization") || ""
          const match = authHeader.match(/^Bearer\s+(.+)$/i)
          if (!match || match[1] !== env.ROUTER_SHARED_SECRET) return jsonErr("Unauthorized", 401)
        }
        const outcome = await pushRoutingTableToShards(env, shardUrls)
        return jsonOk(outcome)
      }
      // Read-only introspection for admin tooling (router-admin.bat). Not
      // secret-sensitive — mirrors what /routing_table.json already
      // discloses, plus raw KV-vs-var provenance for debugging.
      if (url.pathname === "/admin/config" && request.method === "GET") {
        if (env.ROUTER_SHARED_SECRET) {
          const authHeader = request.headers.get("Authorization") || ""
          const match = authHeader.match(/^Bearer\s+(.+)$/i)
          if (!match || match[1] !== env.ROUTER_SHARED_SECRET) return jsonErr("Unauthorized", 401)
        }
        return jsonOk({
          shard_urls: shardUrls,
          registered_shards: await getRegisteredShards(env),
          prior_shard_counts: await getPriorShardCounts(env),
          routing_table_version: await getRoutingTableVersion(env),
          replication_factor: replicationFactor(env, shardUrls.length),
          source: env.ROUTER_ADMIN_KV ? "ROUTER_ADMIN_KV (falls back to vars if key absent)" : "wrangler.toml vars only",
        })
      }
    } catch (e) {
      console.error("Unhandled router error:", e)
      return jsonErr("Internal router error", 500)
    }

    return new Response("Not Found", { status: 404, headers: CORS_HEADERS })
  },
}