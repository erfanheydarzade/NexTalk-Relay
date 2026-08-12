/**
 * Anonymous One-Time Mailbox — Cloudflare Worker (shard node)  (v2)
 *
 * This node is a "dumb", untrusted, community-hostable storage shard. It
 * NEVER learns which pubkey owns a mailbox. It knows only:
 *
 *   - opaque mailbox_id values, minted and signed by the Router
 *   - a read_secret_hash per mailbox (a capability check, not an identity)
 *   - sender pubkeys on individual /send calls (needed for anti-spam;
 *     this is the sender's own disclosed identity, not the recipient's)
 *
 * Required var:    ROUTER_SIGNING_PUBLIC  (hex, 32-byte Ed25519 public key)
 *   Used to verify that a /create request's capability was genuinely minted
 *   by the Router. This is PUBLIC data — safe to hardcode, no secret-sharing
 *   with the Router required. This REPLACES SERVER_SECRET entirely.
 *
 * Required KV namespace binding: MAILBOX_KV
 * Optional secret: ROUTER_SHARED_SECRET — if set, /health requires it.
 *
 * Environment variables (optional, set in wrangler.toml):
 * MAX_MESSAGES / MAX_MSG_BYTES / TTL_SECONDS / MAILBOX_TTL_SECONDS /
 * MAX_CLOCK_SKEW — same meaning as v1.
 *
 * ─── Routing-table cache (v2.1) ─────────────────────────────────────────
 * The Router still computes and signs the routing table alone — this
 * shard has no say in shard topology. But instead of every client asking
 * the Router directly, the Router PUSHES its signed table here
 * (POST /internal/routing_table) and this shard caches it in MAILBOX_KV
 * and serves it back out at GET /routing_table.json. This is pure
 * distribution: the shard doesn't compute anything, only stores and
 * re-serves exactly the bytes the Router signed, verifying the signature
 * with the same ROUTER_SIGNING_PUBLIC key already used for capabilities.
 *
 * ─── Self-registration (v2.2) ────────────────────────────────────────────
 * This shard can introduce itself to the Router with zero manual
 * coordination: on first boot it generates its own Ed25519 identity
 * keypair (stored only in its own MAILBOX_KV — never shared with anyone),
 * solves a proof-of-work challenge from the Router (GET /pow_challenge),
 * and registers (POST /register_shard) with a self-signature proving key
 * ownership. Requires ROUTER_URL and SELF_URL to be set; if either is
 * missing, self-registration is simply skipped and this shard behaves
 * exactly like v2.1 (fully static, manually-added to SHARD_URLS).
 *
 * ─── Replication (v2.2) ──────────────────────────────────────────────────
 * A client only ever talks to ONE shard per mailbox (its primary, from
 * Router's /register or /resolve). That primary shard is handed the full
 * replica set at /create time and, after every successfully accepted
 * /send, fans a signed copy of the message out to the rest of the set
 * (POST /internal/replicate) — fire-and-forget, never blocking the
 * client's response. A receiving shard only accepts a replicate push if
 * the claimed origin shard's pubkey appears in the Router-signed routing
 * table this shard already has cached — trust is transitive through the
 * Router, never a secret shared directly between shards.
 */

const DEFAULTS = {
  MAX_MESSAGES:        50,
  MAX_MSG_BYTES:       32768,
  TTL_SECONDS:         1_209_600,
  MAILBOX_TTL_SECONDS: 31_536_000,
  MAX_CLOCK_SKEW:      30_000,
  MAX_SENDS_PER_SENDER: 30,
  MAX_SENDS_PER_TARGET: 60,
  MAX_SENDS_PER_IP:     120,
  MAX_CREATES_PER_IP:   20,
  MAX_REPLICATES_PER_ORIGIN: 200,
}

const SELF_REGISTER_MIN_INTERVAL_MS = 12 * 60 * 60 * 1000 // re-assert at least twice a day
const SELF_REGISTER_KV_KEY = "shard_self_registration"
const SHARD_IDENTITY_KV_KEY = "shard_identity"
const POW_SOLVE_MAX_ATTEMPTS = 8_000_000

const ALLOWED_ENVELOPE_TYPES = new Set(["offer", "answer", "message", "finish"])
const MAX_JSON_DEPTH = 8

// ─── Encoding helpers ────────────────────────────────────────────────────────

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("odd-length hex")
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("")
}

function constantTimeEqual(a, b) {
  const enc = new TextEncoder()
  const aBytes = enc.encode(String(a))
  const bBytes = enc.encode(String(b))
  const len = Math.max(aBytes.length, bBytes.length, 32)
  const aPad = new Uint8Array(len)
  const bPad = new Uint8Array(len)
  aPad.set(aBytes)
  bPad.set(bBytes)
  let diff = aBytes.length ^ bBytes.length
  for (let i = 0; i < len; i++) diff |= aPad[i] ^ bPad[i]
  return diff === 0
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

async function verifyEd25519Message(pubkeyHex, signedMessage, sigHex) {
  try {
    const pubkeyBytes = hexToBytes(pubkeyHex)
    const sigBytes = hexToBytes(sigHex)
    const message = new TextEncoder().encode(signedMessage)
    const key = await crypto.subtle.importKey("raw", pubkeyBytes, { name: "Ed25519" }, false, ["verify"])
    return await crypto.subtle.verify("Ed25519", key, sigBytes, message)
  } catch {
    return false
  }
}

async function sha256Hex(str) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str))
  return bytesToHex(new Uint8Array(digest))
}

/**
 * Verifies a Router-minted mailbox capability:
 *   cap:{mailbox_id}:{read_secret_hash}:{cap_exp}
 * signed by ROUTER_SIGNING_PUBLIC. This is what lets a shard trust that a
 * mailbox_id was legitimately assigned, WITHOUT the shard ever learning
 * which pubkey it belongs to — the pubkey never appears in this message.
 */
async function verifyCapability(mailboxId, readSecretHash, capExp, capSig, routerPublicHex) {
  if (Date.now() > Number(capExp)) return false
  const message = `cap:${mailboxId}:${readSecretHash}:${capExp}`
  return verifyEd25519Message(routerPublicHex, message, capSig)
}

async function verifySenderAuth(auth, env, maxSkewMs, signedMessage) {
  const { pubkey, timestamp, signature } = auth ?? {}

  if (!pubkey || typeof pubkey !== "string" || !/^[0-9a-f]{64}$/i.test(pubkey)) {
    return "sender.pubkey must be a 64-char lowercase hex Ed25519 public key"
  }
  if (!timestamp || typeof timestamp !== "string" || !/^\d+$/.test(timestamp)) {
    return "sender.timestamp must be a unix millisecond timestamp string"
  }
  if (!signature || typeof signature !== "string" || !/^[0-9a-f]{128}$/i.test(signature)) {
    return "sender.signature must be a 128-char lowercase hex Ed25519 signature"
  }

  const tsMs = Number(timestamp)
  const nowMs = Date.now()
  if (Math.abs(nowMs - tsMs) > maxSkewMs) {
    return `timestamp is outside the ±${maxSkewMs}ms window (clock skew or replay)`
  }

  const replayKeyMaterial = `${pubkey.toLowerCase()}:${timestamp}:${signature.toLowerCase()}`
  const replayDigest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(replayKeyMaterial))
  const replayKey = `replay:${bytesToHex(new Uint8Array(replayDigest))}`

  const alreadySeen = await env.MAILBOX_KV.get(replayKey)
  if (alreadySeen) return "request already used (replay detected)"

  const valid = await verifyEd25519Message(pubkey, signedMessage, signature)
  if (!valid) return "signature verification failed"

  await env.MAILBOX_KV.put(replayKey, "1", { expirationTtl: Math.max(60, Math.ceil(maxSkewMs / 1000)) })
  return null
}

function randomHex(bytes = 16) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)))
}

// ─── Shard self-identity ──────────────────────────────────────────────────
//
// A shard's own Ed25519 keypair, used ONLY for two things: proving key
// ownership during self-registration, and signing outgoing
// /internal/replicate pushes so a sibling shard can verify they really
// came from this shard (per the Router-signed routing table). Generated
// once, lazily, and persisted in this shard's own KV — never transmitted
// anywhere except the public half.
async function ensureShardIdentity(env) {
  const raw = await env.MAILBOX_KV.get(SHARD_IDENTITY_KV_KEY)
  if (raw) return JSON.parse(raw)

  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])
  const pubBytes = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey))
  const privBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey))
  const identity = {
    publicKeyHex: bytesToHex(pubBytes),
    privateKeyPkcs8Base64: btoa(String.fromCharCode(...privBytes)),
  }
  await env.MAILBOX_KV.put(SHARD_IDENTITY_KV_KEY, JSON.stringify(identity))
  return identity
}

async function importShardPrivateKey(pkcs8Base64) {
  const raw = Uint8Array.from(atob(pkcs8Base64), c => c.charCodeAt(0))
  return crypto.subtle.importKey("pkcs8", raw, { name: "Ed25519" }, false, ["sign"])
}
async function signWithShardKey(privKey, message) {
  const sig = await crypto.subtle.sign("Ed25519", privKey, new TextEncoder().encode(message))
  return bytesToHex(new Uint8Array(sig))
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

async function solvePow(nonce, shardUrl, difficulty) {
  for (let i = 0; i < POW_SOLVE_MAX_ATTEMPTS; i++) {
    const solution = String(i)
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${nonce}:${shardUrl}:${solution}`)),
    )
    if (leadingZeroBits(digest) >= difficulty) return solution
  }
  throw new Error("failed to solve PoW within attempt budget")
}

/**
 * Opportunistically (re-)registers this shard with the Router. Cheap to
 * call on every request — it no-ops unless ROUTER_URL/SELF_URL are both
 * configured AND it's been more than SELF_REGISTER_MIN_INTERVAL_MS since
 * the last successful registration. Always called via ctx.waitUntil so it
 * never adds latency to the request that triggered it.
 */
async function ensureSelfRegistered(env) {
  if (!env.ROUTER_URL || !env.SELF_URL) return // static mesh only — nothing to do

  const lastRaw = await env.MAILBOX_KV.get(SELF_REGISTER_KV_KEY)
  if (lastRaw && Date.now() - Number(lastRaw) < SELF_REGISTER_MIN_INTERVAL_MS) return

  try {
    const identity = await ensureShardIdentity(env)

    const challengeResp = await fetch(
      `${env.ROUTER_URL}/pow_challenge?shard_url=${encodeURIComponent(env.SELF_URL)}`,
      { signal: AbortSignal.timeout(5000) },
    )
    if (!challengeResp.ok) throw new Error(`pow_challenge failed with status ${challengeResp.status}`)
    const { nonce, difficulty } = await challengeResp.json()

    const solution = await solvePow(nonce, env.SELF_URL, difficulty)

    const timestamp = String(Date.now())
    const privKey = await importShardPrivateKey(identity.privateKeyPkcs8Base64)
    const signature = await signWithShardKey(
      privKey,
      `register_shard:${env.SELF_URL}:${identity.publicKeyHex}:${timestamp}`,
    )

    const regResp = await fetch(`${env.ROUTER_URL}/register_shard`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        shard_url: env.SELF_URL,
        shard_pubkey: identity.publicKeyHex,
        nonce,
        solution,
        timestamp,
        signature,
      }),
      signal: AbortSignal.timeout(15_000),
    })
    if (!regResp.ok) {
      console.error("self-registration with Router failed:", regResp.status, await regResp.text().catch(() => ""))
      return
    }
    await env.MAILBOX_KV.put(SELF_REGISTER_KV_KEY, String(Date.now()))
    console.log("self-registered with Router successfully")
  } catch (e) {
    console.error("self-registration error:", e)
  }
}

// ─── Envelope structural validation (unchanged) ──────────────────────────────

function jsonDepth(value, depth = 0) {
  if (depth > MAX_JSON_DEPTH) return depth
  if (value === null || typeof value !== "object") return depth
  const children = Array.isArray(value) ? value : Object.values(value)
  let max = depth
  for (const child of children) {
    const d = jsonDepth(child, depth + 1)
    if (d > max) max = d
    if (max > MAX_JSON_DEPTH) break
  }
  return max
}
function validateEnvelopeShape(parsed) {
  if (!parsed || typeof parsed !== "object") return "message must decode to a JSON object"
  if (typeof parsed.type === "string" && !ALLOWED_ENVELOPE_TYPES.has(parsed.type)) {
    return `envelope type '${parsed.type}' is not recognized`
  }
  if (jsonDepth(parsed) > MAX_JSON_DEPTH) return `envelope exceeds max nesting depth (${MAX_JSON_DEPTH})`
  return null
}

// ─── Rate limiting (unchanged) ────────────────────────────────────────────────

async function rateLimit(env, bucketKey, limit, windowSeconds) {
  const key = `rl:${bucketKey}:${Math.floor(Date.now() / (windowSeconds * 1000))}`
  const current = Number((await env.MAILBOX_KV.get(key)) || "0")
  if (current >= limit) return false
  await env.MAILBOX_KV.put(key, String(current + 1), { expirationTtl: windowSeconds + 5 })
  return true
}
function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown"
}

// ─── Response helpers ─────────────────────────────────────────────────────────

const CORS_HEADERS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
}
function json(data, status = 200, extraHeaders = {}) {
  return Response.json(data, { status, headers: { ...CORS_HEADERS, "Cache-Control": "no-store", ...extraHeaders } })
}
function err(message, status = 400, extraHeaders = {}) {
  return json({ error: message }, status, extraHeaders)
}

function isBacklogStale(enqueuedAt, ttlSeconds) {
  if (enqueuedAt == null) return false
  return Math.floor((Date.now() - enqueuedAt) / 1000) >= ttlSeconds
}

// ─── Route handlers ───────────────────────────────────────────────────────────

/**
 * /create — called ONLY by the Router, never directly by a client. Body
 * carries a Router-signed capability over an opaque mailbox_id; this shard
 * never sees, and never needs to see, the pubkey that owns it.
 */
async function handleCreate(request, env, cfg) {
  let body
  try { body = await request.json() } catch { return err("Request body must be valid JSON") }

  const {
    mailbox_id: mailboxId,
    read_secret_hash: readSecretHash,
    cap_exp: capExp,
    cap_sig: capSig,
    replica_shard_urls: replicaShardUrls,
  } = body || {}

  if (!mailboxId || typeof mailboxId !== "string" || !/^[0-9a-f]{16,128}$/i.test(mailboxId)) {
    return err("mailbox_id must be a hex string")
  }
  if (!readSecretHash || typeof readSecretHash !== "string" || !/^[0-9a-f]{64}$/i.test(readSecretHash)) {
    return err("read_secret_hash must be a 64-char hex SHA-256 digest")
  }
  if (!capExp || !Number.isFinite(Number(capExp))) return err("cap_exp is required")
  if (!capSig || typeof capSig !== "string") return err("cap_sig is required")

  const capOk = await verifyCapability(mailboxId.toLowerCase(), readSecretHash.toLowerCase(), Number(capExp), capSig, env.ROUTER_SIGNING_PUBLIC)
  if (!capOk) return err("invalid or expired Router capability", 401)

  const ipOk = await rateLimit(env, `create-ip:${clientIp(request)}`, cfg.MAX_CREATES_PER_IP, 60)
  if (!ipOk) return err("Too many create requests, slow down", 429, { "Retry-After": "60" })

  // Only the Router ever calls /create (see verifyCapability above), so
  // this list is trusted as-is — it's what tells this shard which siblings
  // to fan replicated messages out to later, in handleSend.
  const safeReplicas = Array.isArray(replicaShardUrls) ? replicaShardUrls.filter(u => typeof u === "string") : []

  const kvKey = `mailbox:${mailboxId.toLowerCase()}`
  const existingRaw = await env.MAILBOX_KV.get(kvKey)

  if (existingRaw) {
    // Re-registration (e.g. client lost its cached capability and asked the
    // Router to mint a fresh one) — refresh the read_secret_hash and TTL,
    // keep any queued messages.
    let stored
    try { stored = JSON.parse(existingRaw) } catch { stored = { messages: [], createdAt: Date.now(), messagesEnqueuedAt: null } }
    stored.readSecretHash = readSecretHash.toLowerCase()
    if (safeReplicas.length) stored.replicaShardUrls = safeReplicas
    await env.MAILBOX_KV.put(kvKey, JSON.stringify(stored), { expirationTtl: cfg.MAILBOX_TTL_SECONDS })
    return json({ mailbox_id: mailboxId.toLowerCase(), expires_in: cfg.MAILBOX_TTL_SECONDS, created: false })
  }

  await env.MAILBOX_KV.put(
    kvKey,
    JSON.stringify({
      readSecretHash: readSecretHash.toLowerCase(),
      messages: [],
      createdAt: Date.now(),
      messagesEnqueuedAt: null,
      replicaShardUrls: safeReplicas,
    }),
    { expirationTtl: cfg.MAILBOX_TTL_SECONDS },
  )
  return json({ mailbox_id: mailboxId.toLowerCase(), expires_in: cfg.MAILBOX_TTL_SECONDS, created: true })
}

/**
 * /exists — lightweight, unauthenticated existence probe used ONLY by the
 * Router's /resolve era-fallback walk. Reveals nothing beyond "a mailbox
 * with this opaque id exists here" — no owner information.
 */
async function handleExists(request, env) {
  const url = new URL(request.url)
  const mailboxId = url.searchParams.get("mailbox_id")
  if (!mailboxId || !/^[0-9a-f]{16,128}$/i.test(mailboxId)) return err("mailbox_id required", 400)

  const okIp = await rateLimit(env, `exists-ip:${clientIp(request)}`, 300, 60)
  if (!okIp) return err("Too many requests", 429, { "Retry-After": "60" })

  const raw = await env.MAILBOX_KV.get(`mailbox:${mailboxId.toLowerCase()}`)
  if (!raw) return err("not found", 404)
  return json({ exists: true })
}

async function handleSend(request, env, cfg, ctx) {
  let body
  try { body = await request.json() } catch { return err("Request body must be valid JSON") }

  const { mailbox_id: mailboxId, message, sender } = body || {}

  if (!mailboxId || typeof mailboxId !== "string" || !/^[0-9a-f]{16,128}$/i.test(mailboxId)) {
    return err("mailbox_id must be a hex string")
  }
  if (!message || typeof message !== "string") return err("message is required and must be a string")
  if (new TextEncoder().encode(message).length > cfg.MAX_MSG_BYTES) {
    return err(`message exceeds ${cfg.MAX_MSG_BYTES} byte limit`)
  }

  const { pubkey: senderPubkey, timestamp: senderTimestamp, signature: senderSignature } = sender ?? {}
  if (!senderPubkey || typeof senderPubkey !== "string" || !/^[0-9a-f]{64}$/i.test(senderPubkey)) {
    return err("sender.pubkey must be a 64-char lowercase hex Ed25519 public key")
  }

  const messageHash = await sha256Hex(message)
  // NOTE: the signed message now binds to the opaque mailbox_id, not the
  // recipient's pubkey — the shard (and this signature) never involve the
  // recipient's identity at all.
  const sendSignedMessage = `send:${senderPubkey.toLowerCase()}:${mailboxId.toLowerCase()}:${senderTimestamp}:${messageHash}`
  const authError = await verifySenderAuth(sender, env, cfg.MAX_CLOCK_SKEW, sendSignedMessage)
  if (authError) return err(`sender auth failed: ${authError}`, 401)

  const senderOk = await rateLimit(env, `send-sender:${senderPubkey.toLowerCase()}`, cfg.MAX_SENDS_PER_SENDER, 60)
  if (!senderOk) return err("Too many messages sent from this identity, slow down", 429, { "Retry-After": "60" })

  const targetOk = await rateLimit(env, `send-target:${mailboxId.toLowerCase()}`, cfg.MAX_SENDS_PER_TARGET, 60)
  if (!targetOk) return err("Too many messages to this recipient, slow down", 429, { "Retry-After": "60" })

  const ipOk = await rateLimit(env, `send-ip:${clientIp(request)}`, cfg.MAX_SENDS_PER_IP, 60)
  if (!ipOk) return err("Too many send requests, slow down", 429, { "Retry-After": "60" })

  try {
    const parsed = JSON.parse(message)
    const shapeError = validateEnvelopeShape(parsed)
    if (shapeError) return err(shapeError)
  } catch {
    // Not JSON — treated as raw opaque ciphertext, which is fine.
  }

  const kvKey = `mailbox:${mailboxId.toLowerCase()}`
  const raw = await env.MAILBOX_KV.get(kvKey)
  if (!raw) return err(`Mailbox not found or expired`, 404)

  let stored
  try { stored = JSON.parse(raw) } catch { return err("Internal storage error", 500) }

  if (isBacklogStale(stored.messagesEnqueuedAt, cfg.TTL_SECONDS)) {
    stored.messages = []
    stored.messagesEnqueuedAt = null
  }
  if (stored.messages.length >= cfg.MAX_MESSAGES) {
    return err(`Mailbox is full (limit: ${cfg.MAX_MESSAGES} messages)`, 429, { "Retry-After": "3600" })
  }

  const newEntry = { id: randomHex(8), time: Date.now(), message, senderPubkey: senderPubkey.toLowerCase() }
  stored.messages.push(newEntry)
  if (stored.messagesEnqueuedAt == null) stored.messagesEnqueuedAt = Date.now()

  await env.MAILBOX_KV.put(kvKey, JSON.stringify(stored), { expirationTtl: cfg.MAILBOX_TTL_SECONDS })

  // Fire-and-forget: never blocks or fails the client's /send response.
  // If this shard wasn't handed a replica set (single-shard deployment, or
  // legacy mailbox created before v2.2), this is simply a no-op.
  if (ctx && Array.isArray(stored.replicaShardUrls) && stored.replicaShardUrls.length > 1) {
    ctx.waitUntil(replicateToSiblings(env, mailboxId.toLowerCase(), newEntry, stored.replicaShardUrls))
  }

  return json({ success: true, queued: stored.messages.length })
}


/**
 * GET /admin/shard_info — exposes the shard's self-generated public key and
 * (if configured) the Router URL so solve.py can find them without the
 * operator having to copy-paste anything.
 *
 * Protected by ROUTER_SHARED_SECRET when set (same bearer-token check used
 * by /health). Safe to leave open if you don't mind your shard pubkey being
 * public — it's already disclosed to the Router on registration anyway.
 */
async function handleAdminShardInfo(request, env) {
  if (env.ROUTER_SHARED_SECRET) {
    const authHeader = request.headers.get("Authorization") || ""
    const match = authHeader.match(/^Bearer\s+(.+)$/i)
    if (!match || !constantTimeEqual(match[1], env.ROUTER_SHARED_SECRET)) {
      return err("Unauthorized", 401)
    }
  }

  const identity = await ensureShardIdentity(env)
  return json({
    shard_pubkey: identity.publicKeyHex,
    router_url: env.ROUTER_URL || null,   // null if not configured
    self_url: env.SELF_URL || null,
  })
}

/**
 * POST /admin/register — accepts a pre-solved PoW from solve.py, signs the
 * registration payload with this shard's own private key (from KV), and
 * calls the Router's /register_shard.  The private key never leaves this
 * worker.
 *
 * Body: { nonce: string, solution: string, router_url: string }
 *
 * Protected by ROUTER_SHARED_SECRET when set.
 */
async function handleAdminRegister(request, env) {
  if (env.ROUTER_SHARED_SECRET) {
    const authHeader = request.headers.get("Authorization") || ""
    const match = authHeader.match(/^Bearer\s+(.+)$/i)
    if (!match || !constantTimeEqual(match[1], env.ROUTER_SHARED_SECRET)) {
      return err("Unauthorized", 401)
    }
  }

  let body
  try { body = await request.json() } catch { return err("Request body must be valid JSON") }

  const { nonce, solution, router_url: routerUrl } = body || {}

  if (!nonce   || typeof nonce   !== "string") return err("nonce is required")
  if (!solution || typeof solution !== "string") return err("solution is required")

  // Allow overriding the router URL at call time (handy for testing), but
  // fall back to the configured ROUTER_URL so the caller doesn't strictly
  // need to supply it if it's already in the environment.
  const targetRouter = (routerUrl || env.ROUTER_URL || "").replace(/\/$/, "")
  if (!targetRouter) return err("router_url is required (or set ROUTER_URL in wrangler.toml)")

  const selfUrl = env.SELF_URL
  if (!selfUrl) return err("SELF_URL is not configured on this shard")

  const identity = await ensureShardIdentity(env)
  const privKey  = await importShardPrivateKey(identity.privateKeyPkcs8Base64)

  const timestamp = String(Date.now())
  const signature = await signWithShardKey(
    privKey,
    `register_shard:${selfUrl}:${identity.publicKeyHex}:${timestamp}`,
  )

  let regResp
  try {
    regResp = await fetch(`${targetRouter}/register_shard`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        shard_url:    selfUrl,
        shard_pubkey: identity.publicKeyHex,
        nonce,
        solution,
        timestamp,
        signature,
      }),
      signal: AbortSignal.timeout(15_000),
    })
  } catch (e) {
    return err(`Could not reach Router: ${e.message}`, 502)
  }

  if (!regResp.ok) {
    const text = await regResp.text().catch(() => "")
    return err(`Router rejected registration (${regResp.status}): ${text}`, 502)
  }

  // Persist the timestamp so the background ensureSelfRegistered() won't
  // immediately try to redo this (it checks SELF_REGISTER_KV_KEY).
  await env.MAILBOX_KV.put(SELF_REGISTER_KV_KEY, String(Date.now()))

  const result = await regResp.json().catch(() => ({}))
  return json({ registered: true, router_response: result })
}

/**
 * Pushes a just-accepted message out to every OTHER shard in the mailbox's
 * replica set, signed with this shard's own self-identity key (see
 * ensureShardIdentity). Best-effort: a sibling being down or slow doesn't
 * affect the client, who already got their success response.
 */
async function replicateToSiblings(env, mailboxId, entry, replicaShardUrls) {
  const siblings = replicaShardUrls.filter(u => u !== env.SELF_URL)
  if (!siblings.length) return

  try {
    const identity = await ensureShardIdentity(env)
    const privKey = await importShardPrivateKey(identity.privateKeyPkcs8Base64)
    const timestamp = String(Date.now())
    const payload = {
      mailbox_id: mailboxId,
      entry,
      replica_shard_urls: replicaShardUrls,
      origin_shard_pubkey: identity.publicKeyHex,
      timestamp,
    }
    const canonical = JSON.stringify(payload)
    const signature = await signWithShardKey(privKey, `replicate:${canonical}`)
    const body = JSON.stringify({ ...payload, signature })

    await Promise.all(
      siblings.map(url =>
        fetch(`${url}/internal/replicate`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
          signal: AbortSignal.timeout(8000),
        }).catch(e => console.error(`replicate to ${url} failed:`, e)),
      ),
    )
  } catch (e) {
    console.error("replicateToSiblings error:", e)
  }
}

/**
 * POST /internal/replicate — called ONLY by a sibling shard that just
 * accepted a /send for a mailbox this shard also holds a replica of.
 * Shards never share a secret with each other; trust here is transitive
 * through the Router instead: the origin shard signs with its own
 * self-generated identity key, and this handler only accepts the
 * signature if that exact pubkey appears in the Router-signed routing
 * table this shard has cached (see handleRoutingTablePush /
 * getCachedRoutingTable). A shard whose pubkey isn't recognized there —
 * because it never self-registered, or is impersonating someone else's
 * URL — is rejected outright.
 */
async function handleReplicate(request, env, cfg) {
  let body
  try { body = await request.json() } catch { return err("Request body must be valid JSON") }

  const {
    mailbox_id: mailboxId,
    entry,
    replica_shard_urls: replicaShardUrls,
    origin_shard_pubkey: originPubkey,
    timestamp,
    signature,
  } = body || {}

  if (!mailboxId || typeof mailboxId !== "string" || !/^[0-9a-f]{16,128}$/i.test(mailboxId)) {
    return err("mailbox_id must be a hex string")
  }
  if (!entry || typeof entry !== "object" || typeof entry.id !== "string" || typeof entry.message !== "string") {
    return err("entry must include id and message")
  }
  if (!originPubkey || !/^[0-9a-f]{64}$/i.test(originPubkey)) return err("origin_shard_pubkey must be 64-char hex")
  if (!timestamp || !/^\d+$/.test(timestamp)) return err("timestamp required")
  if (!signature || !/^[0-9a-f]{128}$/i.test(signature)) return err("signature must be 128-char hex")
  if (Math.abs(Date.now() - Number(timestamp)) > 60_000) return err("timestamp outside allowed skew", 401)

  const originOk = await rateLimit(env, `replicate-origin:${originPubkey.toLowerCase()}`, cfg.MAX_REPLICATES_PER_ORIGIN, 60)
  if (!originOk) return err("Too many replicate requests from this origin, slow down", 429, { "Retry-After": "60" })

  const cachedTable = await getCachedRoutingTable(env)
  const knownShard = cachedTable?.shards?.find(s => s.pubkey && s.pubkey.toLowerCase() === originPubkey.toLowerCase())
  if (!knownShard) return err("origin shard is not a Router-recognized identity", 401)

  const { signature: _sig, ...unsigned } = body
  const canonical = JSON.stringify(unsigned)
  const sigOk = await verifyEd25519Message(originPubkey, `replicate:${canonical}`, signature)
  if (!sigOk) return err("replicate signature verification failed", 401)

  const kvKey = `mailbox:${mailboxId.toLowerCase()}`
  const raw = await env.MAILBOX_KV.get(kvKey)
  let stored
  if (!raw) {
    // Declared as a replica but never saw /create (e.g. the Router's
    // fan-out to us raced or failed) — build a shell record rather than
    // drop the message; readSecretHash stays empty until a future
    // re-registration backfills it, but the message itself isn't lost.
    stored = { readSecretHash: "", messages: [], createdAt: Date.now(), messagesEnqueuedAt: null, replicaShardUrls: replicaShardUrls || [] }
  } else {
    try { stored = JSON.parse(raw) } catch { return err("Internal storage error", 500) }
  }

  if (stored.messages.some(m => m.id === entry.id)) {
    return json({ replicated: true, deduped: true }) // idempotent retry
  }

  stored.messages.push(entry)
  if (stored.messagesEnqueuedAt == null) stored.messagesEnqueuedAt = Date.now()

  await env.MAILBOX_KV.put(kvKey, JSON.stringify(stored), { expirationTtl: cfg.MAILBOX_TTL_SECONDS })
  return json({ replicated: true })
}

/**
 * /read — authenticated via the bearer-style read_secret capability, NOT
 * via an Ed25519 signature over the owner's pubkey. This is the crux of
 * the privacy improvement: the shard is never handed the reader's pubkey,
 * only proof that they hold the secret paired with this opaque mailbox_id
 * at creation time. Compare via SHA-256(provided) against the stored hash
 * so a KV dump doesn't itself yield usable read credentials.
 */
async function handleRead(request, env, cfg) {
  const url = new URL(request.url)
  const params = url.searchParams

  const mailboxId = params.get("mailbox_id")
  const readSecret = params.get("read_secret")
  const peek = params.get("peek") === "1"

  if (!mailboxId || !/^[0-9a-f]{16,128}$/i.test(mailboxId)) return err("mailbox_id required", 400)
  if (!readSecret || typeof readSecret !== "string") return err("read_secret required", 400)

  const ipOk = await rateLimit(env, `read-ip:${clientIp(request)}`, 300, 60)
  if (!ipOk) return err("Too many read requests, slow down", 429, { "Retry-After": "60" })

  const kvKey = `mailbox:${mailboxId.toLowerCase()}`
  const raw = await env.MAILBOX_KV.get(kvKey)
  if (!raw) return err(`Mailbox not found or expired`, 404)

  let stored
  try { stored = JSON.parse(raw) } catch { return err("Internal storage error", 500) }

  const providedHash = await sha256Hex(readSecret)
  if (!constantTimeEqual(providedHash, stored.readSecretHash || "")) {
    return err("invalid read_secret", 401)
  }

  const backlogWasStale = isBacklogStale(stored.messagesEnqueuedAt, cfg.TTL_SECONDS)
  if (backlogWasStale) {
    stored.messages = []
    stored.messagesEnqueuedAt = null
  }

  const messagesToReturn = stored.messages
  if (!peek) {
    stored.messages = []
    stored.messagesEnqueuedAt = null
  }

  await env.MAILBOX_KV.put(kvKey, JSON.stringify(stored), { expirationTtl: cfg.MAILBOX_TTL_SECONDS })

  return json({
    messages: messagesToReturn,
    count: messagesToReturn.length,
    createdAt: stored.createdAt,
    consumed: !peek,
  })
}

async function handleHealth(request, env) {
  if (env.ROUTER_SHARED_SECRET) {
    const authHeader = request.headers.get("Authorization") || ""
    const match = authHeader.match(/^Bearer\s+(.+)$/i)
    const provided = match ? match[1] : null
    if (!provided || !constantTimeEqual(provided, env.ROUTER_SHARED_SECRET)) return err("Unauthorized", 401)
  }
  try {
    await env.MAILBOX_KV.get("__health_check__")
    return json({ status: "ok", time: Date.now() })
  } catch (e) {
    return err(`KV unreachable: ${e.message}`, 503)
  }
}

// ─── Routing-table cache (pushed by Router, served to clients) ───────────────

const ROUTING_TABLE_KV_KEY = "routing_table_cache"
const ROUTING_TABLE_SERVE_MAX_AGE = 300 // shorter than the Router's own TTL —
                                         // this is a cached copy one hop old

/**
 * POST /internal/routing_table — called ONLY by the Router (push), never by
 * a client or another shard. Verifies the Router's own signature over the
 * canonical body (same ROUTER_SIGNING_PUBLIC already trusted for mailbox
 * capabilities) before caching it, so a shard can't be tricked into serving
 * a forged shard list by anyone who isn't holding ROUTER_SIGNING_KEY.
 */
async function handleRoutingTablePush(request, env) {
  let body
  try { body = await request.json() } catch { return err("Request body must be valid JSON") }

  const { signature, ...unsigned } = body || {}
  if (!signature || typeof signature !== "string" || !/^[0-9a-f]{128}$/i.test(signature)) {
    return err("signature must be a 128-char hex Ed25519 signature", 400)
  }
  if (!Array.isArray(unsigned.shard_urls) || unsigned.shard_urls.length === 0) {
    return err("shard_urls must be a non-empty array", 400)
  }
  if (!Number.isFinite(Number(unsigned.expires_at))) {
    return err("expires_at is required", 400)
  }

  // Reconstruct exactly what the Router signed: JSON.stringify over the
  // same object shape (key order fixed by buildSignedRoutingTable), minus
  // the signature field itself.
  const canonical = JSON.stringify(unsigned)
  const ok = await verifyEd25519Message(env.ROUTER_SIGNING_PUBLIC, canonical, signature)
  if (!ok) return err("routing table signature verification failed", 401)

  if (Date.now() > Number(unsigned.expires_at)) {
    return err("pushed routing table is already expired", 400)
  }

  await env.MAILBOX_KV.put(ROUTING_TABLE_KV_KEY, JSON.stringify(body))
  return json({ cached: true, version: unsigned.version })
}

/**
 * GET /routing_table.json — served from the cached copy the Router last
 * pushed here. This shard never computes shard topology itself; it only
 * re-serves exactly the signed bytes it was given. If nothing has been
 * pushed yet (fresh deploy, or this shard was unreachable for every push
 * since the last cache eviction), tells the client to fall back to asking
 * the Router directly rather than serving nothing.
 */
async function getCachedRoutingTable(env) {
  const raw = await env.MAILBOX_KV.get(ROUTING_TABLE_KV_KEY)
  if (!raw) return null
  try { return JSON.parse(raw) } catch { return null }
}

async function handleRoutingTableServe(env) {
  const cached = await getCachedRoutingTable(env)
  if (!cached) {
    return err("no routing table cached on this shard yet — fall back to the Router's /routing_table.json", 503, {
      "Retry-After": "30",
    })
  }

  // Serve stale-but-present rather than nothing; the client's own
  // Expired() check against `expires_at` decides whether to trust it.
  return json(cached, 200, {
    "Cache-Control": `public, max-age=${ROUTING_TABLE_SERVE_MAX_AGE}, s-maxage=${ROUTING_TABLE_SERVE_MAX_AGE}`,
  })
}

// ─── Main fetch handler ───────────────────────────────────────────────────────

export default {
  // Optional cron entry point (see wrangler.toml [triggers] crons). Not
  // required — ensureSelfRegistered is also attempted opportunistically on
  // every incoming request via ctx.waitUntil below — but a cron keeps a
  // quiet, low-traffic shard's registration fresh even if nobody happens
  // to hit it for a while.
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(ensureSelfRegistered(env))
  },

  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS })

    if (!env.ROUTER_SIGNING_PUBLIC) {
      console.error("ROUTER_SIGNING_PUBLIC is not set")
      return err("Server misconfiguration", 500)
    }
    if (!env.MAILBOX_KV || typeof env.MAILBOX_KV.get !== "function") {
      console.error("MAILBOX_KV binding is missing or misconfigured")
      return err("Server misconfiguration: MAILBOX_KV binding is not set up", 500)
    }

    // Cheap no-op unless ROUTER_URL/SELF_URL are set and re-registration is
    // actually due — never adds latency, since it runs after the response.
    ctx.waitUntil(ensureSelfRegistered(env))

    const cfg = {
      MAX_MESSAGES:         Number(env.MAX_MESSAGES         ?? DEFAULTS.MAX_MESSAGES),
      MAX_MSG_BYTES:        Number(env.MAX_MSG_BYTES        ?? DEFAULTS.MAX_MSG_BYTES),
      TTL_SECONDS:          Number(env.TTL_SECONDS          ?? DEFAULTS.TTL_SECONDS),
      MAILBOX_TTL_SECONDS:  Number(env.MAILBOX_TTL_SECONDS  ?? DEFAULTS.MAILBOX_TTL_SECONDS),
      MAX_CLOCK_SKEW:       Number(env.MAX_CLOCK_SKEW       ?? DEFAULTS.MAX_CLOCK_SKEW),
      MAX_SENDS_PER_SENDER: Number(env.MAX_SENDS_PER_SENDER ?? DEFAULTS.MAX_SENDS_PER_SENDER),
      MAX_SENDS_PER_TARGET: Number(env.MAX_SENDS_PER_TARGET ?? DEFAULTS.MAX_SENDS_PER_TARGET),
      MAX_SENDS_PER_IP:     Number(env.MAX_SENDS_PER_IP     ?? DEFAULTS.MAX_SENDS_PER_IP),
      MAX_CREATES_PER_IP:   Number(env.MAX_CREATES_PER_IP   ?? DEFAULTS.MAX_CREATES_PER_IP),
      MAX_REPLICATES_PER_ORIGIN: Number(env.MAX_REPLICATES_PER_ORIGIN ?? DEFAULTS.MAX_REPLICATES_PER_ORIGIN),
    }

    const url = new URL(request.url)

    try {
      if (url.pathname === "/health" && request.method === "GET") return await handleHealth(request, env)
      if (url.pathname === "/create" && request.method === "POST") return await handleCreate(request, env, cfg)
      if (url.pathname === "/exists" && request.method === "GET") return await handleExists(request, env)
      if (url.pathname === "/send" && request.method === "POST") return await handleSend(request, env, cfg, ctx)
      if (url.pathname === "/read" && request.method === "GET") return await handleRead(request, env, cfg)
      if (url.pathname === "/internal/routing_table" && request.method === "POST") return await handleRoutingTablePush(request, env)
      if (url.pathname === "/internal/replicate" && request.method === "POST") return await handleReplicate(request, env, cfg)
      if (url.pathname === "/routing_table.json" && request.method === "GET") return await handleRoutingTableServe(env)
      if (url.pathname === "/admin/shard_info" && request.method === "GET")  return await handleAdminShardInfo(request, env)
      if (url.pathname === "/admin/register"   && request.method === "POST") return await handleAdminRegister(request, env)
    } catch (e) {
      console.error("Unhandled error:", e)
      return err("Internal server error", 500)
    }

    return new Response("Not Found", { status: 404, headers: CORS_HEADERS })
  },
}