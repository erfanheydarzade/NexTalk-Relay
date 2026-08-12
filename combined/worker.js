const ROUTING_TABLE_TTL_SECONDS = 3600
const CAPABILITY_TTL_SECONDS = 31_536_000
const HEALTH_CACHE_TTL_MS = 10_000
const POW_DIFFICULTY_BITS_DEFAULT = 20
const POW_CHALLENGE_TTL_SECONDS = 120
const MAX_REGISTERED_SHARDS_DEFAULT = 200
const REGISTER_SHARD_RATE_LIMIT_PER_HOUR = 6
const POW_CHALLENGE_RATE_LIMIT_PER_HOUR = 30
const REPLICATION_FACTOR_DEFAULT = 1
const ROUTING_TABLE_KV_KEY = "routing_table_cache"
const ROUTING_TABLE_SERVE_MAX_AGE = 300
const SHARD_IDENTITY_KV_KEY = "shard_identity"
const SELF_REGISTER_KV_KEY = "shard_self_registration"
const SELF_REGISTER_MIN_INTERVAL_MS = 12 * 60 * 60 * 1000
const POW_SOLVE_MAX_ATTEMPTS = 8_000_000
const ALLOWED_ENVELOPE_TYPES = new Set(["offer", "answer", "message", "finish"])
const MAX_JSON_DEPTH = 8

const DEFAULTS = {
  MAX_MESSAGES: 50,
  MAX_MSG_BYTES: 32768,
  TTL_SECONDS: 1_209_600,
  MAILBOX_TTL_SECONDS: 31_536_000,
  MAX_CLOCK_SKEW: 30_000,
  MAX_SENDS_PER_SENDER: 30,
  MAX_SENDS_PER_TARGET: 60,
  MAX_SENDS_PER_IP: 120,
  MAX_CREATES_PER_IP: 20,
  MAX_REPLICATES_PER_ORIGIN: 200,
}

let healthCache = { checkedAt: 0, healthyUrls: null }

function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("")
}
function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("odd-length hex")
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
async function sha256Hex(str) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str))
  return bytesToHex(new Uint8Array(digest))
}
async function hmacHex(message, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message))
  return bytesToHex(new Uint8Array(sig))
}
function randomHex(bytes = 32) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)))
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
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${nonce}:${shardUrl}:${solution}`)))
    if (leadingZeroBits(digest) >= difficulty) return solution
  }
  throw new Error("failed to solve PoW within attempt budget")
}

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

async function hashPoint(str) {
  const hex = await sha256Hex(str)
  return parseInt(hex.slice(0, 8), 16)
}
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
function eraCountsDescending(shardUrls, priorCounts) {
  const currentN = shardUrls.length
  const all = [currentN, ...(priorCounts || [])].filter(n => Number.isInteger(n) && n > 0 && n <= shardUrls.length)
  return [...new Set(all)].sort((a, b) => b - a)
}

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
  if (env.SELF_URL && !merged.includes(env.SELF_URL)) merged.push(env.SELF_URL)
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
  if (!env.ROUTER_ADMIN_KV) return true
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
      } catch {}
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

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
}
function json(data, status = 200, extraHeaders = {}) {
  return Response.json(data, { status, headers: { ...CORS_HEADERS, "Cache-Control": "no-store", ...extraHeaders } })
}
function err(message, status = 400, extraHeaders = {}) {
  return json({ error: message }, status, extraHeaders)
}
function jsonOk(data, extraHeaders = {}) {
  return Response.json(data, { headers: { ...CORS_HEADERS, ...extraHeaders } })
}

async function buildSignedRoutingTable(env) {
  const shardUrls = await getShardUrls(env)
  const priorCounts = await getPriorShardCounts(env)
  const version = await getRoutingTableVersion(env)
  const pubkeys = await getShardPubkeys(env)
  const now = Date.now()
  const selfIdentity = await ensureShardIdentity(env)

  const body = {
    version,
    generated_at: now,
    expires_at: now + ROUTING_TABLE_TTL_SECONDS * 1000,
    algorithm: "sha256-hashpoint-modn-era-fallback-v1",
    shard_urls: shardUrls,
    shards: shardUrls.map(url => ({
      url,
      pubkey: url === env.SELF_URL ? selfIdentity.publicKeyHex : (pubkeys[url] || null),
    })),
    replication_factor: replicationFactor(env, shardUrls.length),
    prior_shard_counts: priorCounts,
    router_public_key: env.ROUTER_SIGNING_PUBLIC,
  }

  const canonical = JSON.stringify(body)
  const signingKey = await importSigningKey(env.ROUTER_SIGNING_KEY)
  const signature = await signHex(signingKey, canonical)
  return { ...body, signature }
}

async function handleRoutingTable(env) {
  const signed = await buildSignedRoutingTable(env)
  await env.MAILBOX_KV.put(ROUTING_TABLE_KV_KEY, JSON.stringify(signed))
  return jsonOk(signed, {
    "Content-Type": "application/json",
    "Cache-Control": `public, max-age=${ROUTING_TABLE_TTL_SECONDS}, s-maxage=${ROUTING_TABLE_TTL_SECONDS}`,
  })
}

async function pushRoutingTableToShards(env, shardUrls) {
  const signed = await buildSignedRoutingTable(env)
  const body = JSON.stringify(signed)

  const results = await Promise.all(
    shardUrls.map(async shardUrl => {
      if (shardUrl === env.SELF_URL) {
        await env.MAILBOX_KV.put(ROUTING_TABLE_KV_KEY, body)
        return { shardUrl, ok: true, status: 200 }
      }
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

async function localCreate(env, cfg, mailboxId, readSecretHash, capExp, capSig, replicas) {
  const capOk = await verifyCapability(mailboxId.toLowerCase(), readSecretHash.toLowerCase(), Number(capExp), capSig, env.ROUTER_SIGNING_PUBLIC)
  if (!capOk) return { ok: false }
  const safeReplicas = Array.isArray(replicas) ? replicas.filter(u => typeof u === "string") : []
  const kvKey = `mailbox:${mailboxId.toLowerCase()}`
  const existingRaw = await env.MAILBOX_KV.get(kvKey)
  if (existingRaw) {
    let stored
    try { stored = JSON.parse(existingRaw) } catch { stored = { messages: [], createdAt: Date.now(), messagesEnqueuedAt: null } }
    stored.readSecretHash = readSecretHash.toLowerCase()
    if (safeReplicas.length) stored.replicaShardUrls = safeReplicas
    await env.MAILBOX_KV.put(kvKey, JSON.stringify(stored), { expirationTtl: cfg.MAILBOX_TTL_SECONDS })
    return { ok: true, created: false }
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
  return { ok: true, created: true }
}

async function createOnReplica(env, cfg, replicaUrl, createBody) {
  if (replicaUrl === env.SELF_URL) {
    const parsed = JSON.parse(createBody)
    const res = await localCreate(env, cfg, parsed.mailbox_id, parsed.read_secret_hash, parsed.cap_exp, parsed.cap_sig, parsed.replica_shard_urls)
    return { url: replicaUrl, ok: res.ok }
  }
  try {
    const resp = await fetch(`${replicaUrl}/create`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: createBody,
      signal: AbortSignal.timeout(10_000),
    })
    return { url: replicaUrl, ok: resp.ok }
  } catch {
    return { url: replicaUrl, ok: false }
  }
}

async function handleRegister(request, env, shardUrls, cfg) {
  let body
  try { body = await request.json() } catch { return err("Request body must be valid JSON", 400) }

  const { pubkey, timestamp, signature } = body || {}
  if (!pubkey || !/^[0-9a-f]{64}$/i.test(pubkey)) return err("pubkey must be 64-char hex", 400)
  if (!timestamp || !/^\d+$/.test(timestamp)) return err("timestamp required", 400)
  if (!signature || !/^[0-9a-f]{128}$/i.test(signature)) return err("signature must be 128-char hex", 400)

  const skewMs = 30_000
  if (Math.abs(Date.now() - Number(timestamp)) > skewMs) return err("timestamp outside allowed skew", 401)

  const ok = await verifyEd25519(pubkey, `register:${pubkey.toLowerCase()}:${timestamp}`, signature)
  if (!ok) return err("signature verification failed", 401)

  const mailboxId = await hmacHex(pubkey.toLowerCase(), env.SERVER_SECRET)
  const r = replicationFactor(env, shardUrls.length)
  const replicas = await replicasForEra(pubkey, shardUrls.length, shardUrls, r)
  const shardUrl = replicas[0]

  const readSecret = randomHex(32)
  const readSecretHash = await sha256Hex(readSecret)
  const capExp = Date.now() + CAPABILITY_TTL_SECONDS * 1000

  const signingKey = await importSigningKey(env.ROUTER_SIGNING_KEY)
  const capSig = await signHex(signingKey, `cap:${mailboxId}:${readSecretHash}:${capExp}`)

  const createBody = JSON.stringify({
    mailbox_id: mailboxId,
    read_secret_hash: readSecretHash,
    cap_exp: capExp,
    cap_sig: capSig,
    replica_shard_urls: replicas,
  })

  const createResults = await Promise.all(replicas.map(url => createOnReplica(env, cfg, url, createBody)))

  if (!createResults[0].ok) return err("Failed to create mailbox on primary shard", 502)
  const failedReplicas = createResults.slice(1).filter(res => !res.ok)
  if (failedReplicas.length) console.error("register: some replicas failed /create", failedReplicas)

  const response = {
    mailbox_id: mailboxId,
    read_secret: readSecret,
    shard_url: shardUrl,
    replica_shard_urls: replicas,
    expires_at: capExp,
    table_version: await getRoutingTableVersion(env),
  }
  return json(response)
}

async function existsOnReplica(env, replicaUrl, mailboxId) {
  if (replicaUrl === env.SELF_URL) {
    const raw = await env.MAILBOX_KV.get(`mailbox:${mailboxId.toLowerCase()}`)
    return !!raw
  }
  try {
    const resp = await fetch(`${replicaUrl}/exists?mailbox_id=${mailboxId}`, { signal: AbortSignal.timeout(3000) })
    return resp.ok
  } catch {
    return false
  }
}

async function handleResolve(request, env, shardUrls) {
  const url = new URL(request.url)
  const pubkey = url.searchParams.get("pubkey")
  if (!pubkey || !/^[0-9a-f]{64}$/i.test(pubkey)) return err("pubkey (64-char hex) query param required", 400)

  const mailboxId = await hmacHex(pubkey.toLowerCase(), env.SERVER_SECRET)
  const priorCounts = await getPriorShardCounts(env)
  const eras = eraCountsDescending(shardUrls, priorCounts)

  for (const n of eras) {
    const r = replicationFactor(env, n)
    const replicas = await replicasForEra(pubkey, n, shardUrls, r)
    const shardUrl = replicas[0]
    const exists = await existsOnReplica(env, shardUrl, mailboxId)
    if (exists) {
      return jsonOk({
        mailbox_id: mailboxId,
        shard_url: shardUrl,
        replica_shard_urls: replicas,
        era: n,
        table_version: await getRoutingTableVersion(env),
      })
    }
  }

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

async function handlePowChallenge(request, env) {
  if (!env.ROUTER_ADMIN_KV) return err("shard self-registration is disabled on this Router (no ROUTER_ADMIN_KV bound)", 501)

  const ip = request.headers.get("CF-Connecting-IP") || "unknown"
  const okIp = await adminRateLimit(env, `pow-challenge-ip:${ip}`, POW_CHALLENGE_RATE_LIMIT_PER_HOUR, 3600)
  if (!okIp) return err("too many challenge requests, slow down", 429)

  const nonce = randomHex(16)
  const difficulty = Number(env.SHARD_POW_DIFFICULTY_BITS || POW_DIFFICULTY_BITS_DEFAULT)
  const expiresAt = Date.now() + POW_CHALLENGE_TTL_SECONDS * 1000

  await env.ROUTER_ADMIN_KV.put(`pow_nonce:${nonce}`, JSON.stringify({ difficulty, expiresAt }), { expirationTtl: POW_CHALLENGE_TTL_SECONDS + 5 })
  return jsonOk({ nonce, difficulty, expires_at: expiresAt })
}

async function handleRegisterShard(request, env) {
  if (!env.ROUTER_ADMIN_KV) return err("shard self-registration is disabled on this Router (no ROUTER_ADMIN_KV bound)", 501)

  let body
  try { body = await request.json() } catch { return err("Request body must be valid JSON", 400) }

  const { shard_url: shardUrl, shard_pubkey: shardPubkey, nonce, solution, timestamp, signature } = body || {}

  if (!shardUrl || typeof shardUrl !== "string" || !/^https?:\/\/\S+$/i.test(shardUrl)) return err("shard_url must be a valid http(s) URL", 400)
  if (!shardPubkey || !/^[0-9a-f]{64}$/i.test(shardPubkey)) return err("shard_pubkey must be 64-char hex", 400)
  if (!nonce || typeof nonce !== "string") return err("nonce is required", 400)
  if (!solution || typeof solution !== "string") return err("solution is required", 400)
  if (!timestamp || !/^\d+$/.test(timestamp)) return err("timestamp required", 400)
  if (!signature || !/^[0-9a-f]{128}$/i.test(signature)) return err("signature must be 128-char hex", 400)

  const ip = request.headers.get("CF-Connecting-IP") || "unknown"
  const ipOk = await adminRateLimit(env, `register-shard-ip:${ip}`, REGISTER_SHARD_RATE_LIMIT_PER_HOUR, 3600)
  if (!ipOk) return err("too many shard registration attempts from this IP, slow down", 429)

  const challengeRaw = await env.ROUTER_ADMIN_KV.get(`pow_nonce:${nonce}`)
  if (!challengeRaw) return err("unknown, expired, or already-used nonce — request a fresh /pow_challenge", 401)
  let challenge
  try { challenge = JSON.parse(challengeRaw) } catch { return err("internal challenge storage error", 500) }
  if (Date.now() > challenge.expiresAt) return err("PoW challenge expired", 401)

  const powDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${nonce}:${shardUrl}:${solution}`)))
  if (leadingZeroBits(powDigest) < challenge.difficulty) return err("proof-of-work does not meet required difficulty", 401)
  await env.ROUTER_ADMIN_KV.delete(`pow_nonce:${nonce}`)

  if (Math.abs(Date.now() - Number(timestamp)) > 60_000) return err("timestamp outside allowed skew", 401)
  const signedMessage = `register_shard:${shardUrl}:${shardPubkey.toLowerCase()}:${timestamp}`
  const sigOk = await verifyEd25519(shardPubkey, signedMessage, signature)
  if (!sigOk) return err("self-signature verification failed", 401)

  const existing = await getRegisteredShards(env)
  const maxShards = Number(env.MAX_REGISTERED_SHARDS || MAX_REGISTERED_SHARDS_DEFAULT)
  const already = existing.find(s => s.url === shardUrl)
  if (!already && existing.length >= maxShards) return err(`mesh is at capacity (${maxShards} shards) — contact the Router operator`, 403)

  const updated = already
    ? existing.map(s => s.url === shardUrl ? { url: shardUrl, pubkey: shardPubkey.toLowerCase(), registered_at: s.registered_at, updated_at: Date.now() } : s)
    : [...existing, { url: shardUrl, pubkey: shardPubkey.toLowerCase(), registered_at: Date.now() }]

  await env.ROUTER_ADMIN_KV.put("registered_shards", JSON.stringify(updated))
  const currentVersion = await getRoutingTableVersion(env)
  await env.ROUTER_ADMIN_KV.put("routing_table_version", String(currentVersion + 1))

  return jsonOk({ registered: true, shard_url: shardUrl, shard_count: updated.length, table_version: currentVersion + 1 })
}

async function handleStatus(env, shardUrls) {
  const healthy = await getHealthyShards(shardUrls, env.ROUTER_SHARED_SECRET)
  return jsonOk({ totalShards: shardUrls.length, healthyShards: healthy.length, shards: shardUrls.map(u => ({ url: u, healthy: healthy.includes(u) })) })
}

async function ensureShardIdentity(env) {
  const raw = await env.MAILBOX_KV.get(SHARD_IDENTITY_KV_KEY)
  if (raw) return JSON.parse(raw)

  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])
  const pubBytes = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey))
  const privBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey))
  const identity = { publicKeyHex: bytesToHex(pubBytes), privateKeyPkcs8Base64: btoa(String.fromCharCode(...privBytes)) }
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

async function ensureSelfRegistered(env) {
  if (!env.ROUTER_URL || !env.SELF_URL) return
  if (env.ROUTER_URL === env.SELF_URL) return

  const lastRaw = await env.MAILBOX_KV.get(SELF_REGISTER_KV_KEY)
  if (lastRaw && Date.now() - Number(lastRaw) < SELF_REGISTER_MIN_INTERVAL_MS) return

  try {
    const identity = await ensureShardIdentity(env)
    const challengeResp = await fetch(`${env.ROUTER_URL}/pow_challenge?shard_url=${encodeURIComponent(env.SELF_URL)}`, { signal: AbortSignal.timeout(5000) })
    if (!challengeResp.ok) throw new Error(`pow_challenge failed with status ${challengeResp.status}`)
    const { nonce, difficulty } = await challengeResp.json()
    const solution = await solvePow(nonce, env.SELF_URL, difficulty)
    const timestamp = String(Date.now())
    const privKey = await importShardPrivateKey(identity.privateKeyPkcs8Base64)
    const signature = await signWithShardKey(privKey, `register_shard:${env.SELF_URL}:${identity.publicKeyHex}:${timestamp}`)

    const regResp = await fetch(`${env.ROUTER_URL}/register_shard`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ shard_url: env.SELF_URL, shard_pubkey: identity.publicKeyHex, nonce, solution, timestamp, signature }),
      signal: AbortSignal.timeout(15_000),
    })
    if (!regResp.ok) {
      console.error("self-registration with Router failed:", regResp.status, await regResp.text().catch(() => ""))
      return
    }
    await env.MAILBOX_KV.put(SELF_REGISTER_KV_KEY, String(Date.now()))
  } catch (e) {
    console.error("self-registration error:", e)
  }
}

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
  if (typeof parsed.type === "string" && !ALLOWED_ENVELOPE_TYPES.has(parsed.type)) return `envelope type '${parsed.type}' is not recognized`
  if (jsonDepth(parsed) > MAX_JSON_DEPTH) return `envelope exceeds max nesting depth (${MAX_JSON_DEPTH})`
  return null
}

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
function isBacklogStale(enqueuedAt, ttlSeconds) {
  if (enqueuedAt == null) return false
  return Math.floor((Date.now() - enqueuedAt) / 1000) >= ttlSeconds
}

async function verifyCapability(mailboxId, readSecretHash, capExp, capSig, routerPublicHex) {
  if (Date.now() > Number(capExp)) return false
  const message = `cap:${mailboxId}:${readSecretHash}:${capExp}`
  return verifyEd25519(routerPublicHex, message, capSig)
}

async function verifySenderAuth(auth, env, maxSkewMs, signedMessage) {
  const { pubkey, timestamp, signature } = auth ?? {}

  if (!pubkey || typeof pubkey !== "string" || !/^[0-9a-f]{64}$/i.test(pubkey)) return "sender.pubkey must be a 64-char lowercase hex Ed25519 public key"
  if (!timestamp || typeof timestamp !== "string" || !/^\d+$/.test(timestamp)) return "sender.timestamp must be a unix millisecond timestamp string"
  if (!signature || typeof signature !== "string" || !/^[0-9a-f]{128}$/i.test(signature)) return "sender.signature must be a 128-char lowercase hex Ed25519 signature"

  const tsMs = Number(timestamp)
  const nowMs = Date.now()
  if (Math.abs(nowMs - tsMs) > maxSkewMs) return `timestamp is outside the ±${maxSkewMs}ms window (clock skew or replay)`

  const replayKeyMaterial = `${pubkey.toLowerCase()}:${timestamp}:${signature.toLowerCase()}`
  const replayDigest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(replayKeyMaterial))
  const replayKey = `replay:${bytesToHex(new Uint8Array(replayDigest))}`

  const alreadySeen = await env.MAILBOX_KV.get(replayKey)
  if (alreadySeen) return "request already used (replay detected)"

  const valid = await verifyEd25519(pubkey, signedMessage, signature)
  if (!valid) return "signature verification failed"

  await env.MAILBOX_KV.put(replayKey, "1", { expirationTtl: Math.max(60, Math.ceil(maxSkewMs / 1000)) })
  return null
}

async function handleCreate(request, env, cfg) {
  let body
  try { body = await request.json() } catch { return err("Request body must be valid JSON") }

  const { mailbox_id: mailboxId, read_secret_hash: readSecretHash, cap_exp: capExp, cap_sig: capSig, replica_shard_urls: replicaShardUrls } = body || {}

  if (!mailboxId || typeof mailboxId !== "string" || !/^[0-9a-f]{16,128}$/i.test(mailboxId)) return err("mailbox_id must be a hex string")
  if (!readSecretHash || typeof readSecretHash !== "string" || !/^[0-9a-f]{64}$/i.test(readSecretHash)) return err("read_secret_hash must be a 64-char hex SHA-256 digest")
  if (!capExp || !Number.isFinite(Number(capExp))) return err("cap_exp is required")
  if (!capSig || typeof capSig !== "string") return err("cap_sig is required")

  const ipOk = await rateLimit(env, `create-ip:${clientIp(request)}`, cfg.MAX_CREATES_PER_IP, 60)
  if (!ipOk) return err("Too many create requests, slow down", 429, { "Retry-After": "60" })

  const result = await localCreate(env, cfg, mailboxId, readSecretHash, capExp, capSig, replicaShardUrls)
  if (!result.ok) return err("invalid or expired Router capability", 401)
  return json({ mailbox_id: mailboxId.toLowerCase(), expires_in: cfg.MAILBOX_TTL_SECONDS, created: result.created })
}

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

  if (!mailboxId || typeof mailboxId !== "string" || !/^[0-9a-f]{16,128}$/i.test(mailboxId)) return err("mailbox_id must be a hex string")
  if (!message || typeof message !== "string") return err("message is required and must be a string")
  if (new TextEncoder().encode(message).length > cfg.MAX_MSG_BYTES) return err(`message exceeds ${cfg.MAX_MSG_BYTES} byte limit`)

  const { pubkey: senderPubkey, timestamp: senderTimestamp } = sender ?? {}
  if (!senderPubkey || typeof senderPubkey !== "string" || !/^[0-9a-f]{64}$/i.test(senderPubkey)) return err("sender.pubkey must be a 64-char lowercase hex Ed25519 public key")

  const messageHash = await sha256Hex(message)
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
  } catch {}

  const kvKey = `mailbox:${mailboxId.toLowerCase()}`
  const raw = await env.MAILBOX_KV.get(kvKey)
  if (!raw) return err(`Mailbox not found or expired`, 404)

  let stored
  try { stored = JSON.parse(raw) } catch { return err("Internal storage error", 500) }

  if (isBacklogStale(stored.messagesEnqueuedAt, cfg.TTL_SECONDS)) {
    stored.messages = []
    stored.messagesEnqueuedAt = null
  }
  if (stored.messages.length >= cfg.MAX_MESSAGES) return err(`Mailbox is full (limit: ${cfg.MAX_MESSAGES} messages)`, 429, { "Retry-After": "3600" })

  const newEntry = { id: randomHex(8), time: Date.now(), message, senderPubkey: senderPubkey.toLowerCase() }
  stored.messages.push(newEntry)
  if (stored.messagesEnqueuedAt == null) stored.messagesEnqueuedAt = Date.now()

  await env.MAILBOX_KV.put(kvKey, JSON.stringify(stored), { expirationTtl: cfg.MAILBOX_TTL_SECONDS })

  if (ctx && Array.isArray(stored.replicaShardUrls) && stored.replicaShardUrls.length > 1) {
    ctx.waitUntil(replicateToSiblings(env, mailboxId.toLowerCase(), newEntry, stored.replicaShardUrls))
  }

  return json({ success: true, queued: stored.messages.length })
}

async function replicateToSiblings(env, mailboxId, entry, replicaShardUrls) {
  const siblings = replicaShardUrls.filter(u => u !== env.SELF_URL)
  if (!siblings.length) return

  try {
    const identity = await ensureShardIdentity(env)
    const privKey = await importShardPrivateKey(identity.privateKeyPkcs8Base64)
    const timestamp = String(Date.now())
    const payload = { mailbox_id: mailboxId, entry, replica_shard_urls: replicaShardUrls, origin_shard_pubkey: identity.publicKeyHex, timestamp }
    const canonical = JSON.stringify(payload)
    const signature = await signWithShardKey(privKey, `replicate:${canonical}`)
    const body = JSON.stringify({ ...payload, signature })

    await Promise.all(siblings.map(url => fetch(`${url}/internal/replicate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(8000),
    }).catch(e => console.error(`replicate to ${url} failed:`, e))))
  } catch (e) {
    console.error("replicateToSiblings error:", e)
  }
}

async function handleReplicate(request, env, cfg) {
  let body
  try { body = await request.json() } catch { return err("Request body must be valid JSON") }

  const { mailbox_id: mailboxId, entry, replica_shard_urls: replicaShardUrls, origin_shard_pubkey: originPubkey, timestamp, signature } = body || {}

  if (!mailboxId || typeof mailboxId !== "string" || !/^[0-9a-f]{16,128}$/i.test(mailboxId)) return err("mailbox_id must be a hex string")
  if (!entry || typeof entry !== "object" || typeof entry.id !== "string" || typeof entry.message !== "string") return err("entry must include id and message")
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
  const sigOk = await verifyEd25519(originPubkey, `replicate:${canonical}`, signature)
  if (!sigOk) return err("replicate signature verification failed", 401)

  const kvKey = `mailbox:${mailboxId.toLowerCase()}`
  const raw = await env.MAILBOX_KV.get(kvKey)
  let stored
  if (!raw) {
    stored = { readSecretHash: "", messages: [], createdAt: Date.now(), messagesEnqueuedAt: null, replicaShardUrls: replicaShardUrls || [] }
  } else {
    try { stored = JSON.parse(raw) } catch { return err("Internal storage error", 500) }
  }

  if (stored.messages.some(m => m.id === entry.id)) return json({ replicated: true, deduped: true })

  stored.messages.push(entry)
  if (stored.messagesEnqueuedAt == null) stored.messagesEnqueuedAt = Date.now()

  await env.MAILBOX_KV.put(kvKey, JSON.stringify(stored), { expirationTtl: cfg.MAILBOX_TTL_SECONDS })
  return json({ replicated: true })
}

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
  if (!constantTimeEqual(providedHash, stored.readSecretHash || "")) return err("invalid read_secret", 401)

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

  return json({ messages: messagesToReturn, count: messagesToReturn.length, createdAt: stored.createdAt, consumed: !peek })
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

async function handleRoutingTablePush(request, env) {
  let body
  try { body = await request.json() } catch { return err("Request body must be valid JSON") }

  const { signature, ...unsigned } = body || {}
  if (!signature || typeof signature !== "string" || !/^[0-9a-f]{128}$/i.test(signature)) return err("signature must be a 128-char hex Ed25519 signature", 400)
  if (!Array.isArray(unsigned.shard_urls) || unsigned.shard_urls.length === 0) return err("shard_urls must be a non-empty array", 400)
  if (!Number.isFinite(Number(unsigned.expires_at))) return err("expires_at is required", 400)

  const canonical = JSON.stringify(unsigned)
  const ok = await verifyEd25519(env.ROUTER_SIGNING_PUBLIC, canonical, signature)
  if (!ok) return err("routing table signature verification failed", 401)
  if (Date.now() > Number(unsigned.expires_at)) return err("pushed routing table is already expired", 400)

  await env.MAILBOX_KV.put(ROUTING_TABLE_KV_KEY, JSON.stringify(body))
  return json({ cached: true, version: unsigned.version })
}

async function getCachedRoutingTable(env) {
  const raw = await env.MAILBOX_KV.get(ROUTING_TABLE_KV_KEY)
  if (!raw) return null
  try { return JSON.parse(raw) } catch { return null }
}

async function handleRoutingTableServe(env) {
  if (env.ROUTER_SIGNING_KEY) return handleRoutingTable(env)
  const cached = await getCachedRoutingTable(env)
  if (!cached) return err("no routing table cached on this shard yet — fall back to the Router's /routing_table.json", 503, { "Retry-After": "30" })
  return json(cached, 200, { "Cache-Control": `public, max-age=${ROUTING_TABLE_SERVE_MAX_AGE}, s-maxage=${ROUTING_TABLE_SERVE_MAX_AGE}` })
}

async function handleAdminShardInfo(request, env) {
  if (env.ROUTER_SHARED_SECRET) {
    const authHeader = request.headers.get("Authorization") || ""
    const match = authHeader.match(/^Bearer\s+(.+)$/i)
    if (!match || !constantTimeEqual(match[1], env.ROUTER_SHARED_SECRET)) return err("Unauthorized", 401)
  }
  const identity = await ensureShardIdentity(env)
  return json({ shard_pubkey: identity.publicKeyHex, router_url: env.ROUTER_URL || null, self_url: env.SELF_URL || null })
}

async function handleAdminRegister(request, env) {
  if (env.ROUTER_SHARED_SECRET) {
    const authHeader = request.headers.get("Authorization") || ""
    const match = authHeader.match(/^Bearer\s+(.+)$/i)
    if (!match || !constantTimeEqual(match[1], env.ROUTER_SHARED_SECRET)) return err("Unauthorized", 401)
  }

  let body
  try { body = await request.json() } catch { return err("Request body must be valid JSON") }
  const { nonce, solution, router_url: routerUrl } = body || {}
  if (!nonce || typeof nonce !== "string") return err("nonce is required")
  if (!solution || typeof solution !== "string") return err("solution is required")

  const targetRouter = (routerUrl || env.ROUTER_URL || "").replace(/\/$/, "")
  if (!targetRouter) return err("router_url is required (or set ROUTER_URL in wrangler.toml)")

  const selfUrl = env.SELF_URL
  if (!selfUrl) return err("SELF_URL is not configured on this shard")

  const identity = await ensureShardIdentity(env)
  const privKey = await importShardPrivateKey(identity.privateKeyPkcs8Base64)
  const timestamp = String(Date.now())
  const signature = await signWithShardKey(privKey, `register_shard:${selfUrl}:${identity.publicKeyHex}:${timestamp}`)

  let regResp
  try {
    regResp = await fetch(`${targetRouter}/register_shard`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ shard_url: selfUrl, shard_pubkey: identity.publicKeyHex, nonce, solution, timestamp, signature }),
      signal: AbortSignal.timeout(15_000),
    })
  } catch (e) {
    return err(`Could not reach Router: ${e.message}`, 502)
  }

  if (!regResp.ok) {
    const text = await regResp.text().catch(() => "")
    return err(`Router rejected registration (${regResp.status}): ${text}`, 502)
  }

  await env.MAILBOX_KV.put(SELF_REGISTER_KV_KEY, String(Date.now()))
  const result = await regResp.json().catch(() => ({}))
  return json({ registered: true, router_response: result })
}

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(ensureSelfRegistered(env))
    if (!env.SERVER_SECRET || !env.ROUTER_SIGNING_KEY || !env.ROUTER_SIGNING_PUBLIC) return
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
    if (failed.length) console.error(`routing_table push: ${failed.length}/${outcome.results.length} shards failed`, failed)
  },

  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS })

    if (!env.MAILBOX_KV || typeof env.MAILBOX_KV.get !== "function") {
      console.error("MAILBOX_KV binding is missing or misconfigured")
      return err("Server misconfiguration: MAILBOX_KV binding is not set up", 500)
    }

    const isRouter = !!(env.SERVER_SECRET && env.ROUTER_SIGNING_KEY && env.ROUTER_SIGNING_PUBLIC)
    if (!env.ROUTER_SIGNING_PUBLIC) {
      console.error("ROUTER_SIGNING_PUBLIC is not set")
      return err("Server misconfiguration", 500)
    }

    ctx.waitUntil(ensureSelfRegistered(env))

    const cfg = {
      MAX_MESSAGES: Number(env.MAX_MESSAGES ?? DEFAULTS.MAX_MESSAGES),
      MAX_MSG_BYTES: Number(env.MAX_MSG_BYTES ?? DEFAULTS.MAX_MSG_BYTES),
      TTL_SECONDS: Number(env.TTL_SECONDS ?? DEFAULTS.TTL_SECONDS),
      MAILBOX_TTL_SECONDS: Number(env.MAILBOX_TTL_SECONDS ?? DEFAULTS.MAILBOX_TTL_SECONDS),
      MAX_CLOCK_SKEW: Number(env.MAX_CLOCK_SKEW ?? DEFAULTS.MAX_CLOCK_SKEW),
      MAX_SENDS_PER_SENDER: Number(env.MAX_SENDS_PER_SENDER ?? DEFAULTS.MAX_SENDS_PER_SENDER),
      MAX_SENDS_PER_TARGET: Number(env.MAX_SENDS_PER_TARGET ?? DEFAULTS.MAX_SENDS_PER_TARGET),
      MAX_SENDS_PER_IP: Number(env.MAX_SENDS_PER_IP ?? DEFAULTS.MAX_SENDS_PER_IP),
      MAX_CREATES_PER_IP: Number(env.MAX_CREATES_PER_IP ?? DEFAULTS.MAX_CREATES_PER_IP),
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
      if (url.pathname === "/admin/shard_info" && request.method === "GET") return await handleAdminShardInfo(request, env)
      if (url.pathname === "/admin/register" && request.method === "POST") return await handleAdminRegister(request, env)

      if (url.pathname === "/routing_table.json" && request.method === "GET") return await handleRoutingTableServe(env)

      if (isRouter) {
        let shardUrls
        try {
          shardUrls = await getShardUrls(env)
          if (!Array.isArray(shardUrls) || shardUrls.length === 0) throw new Error("empty")
        } catch {
          console.error("SHARD_URLS is missing or invalid (checked ROUTER_ADMIN_KV then env var)")
          return err("Router misconfiguration", 500)
        }

        if (url.pathname === "/register" && request.method === "POST") return await handleRegister(request, env, shardUrls, cfg)
        if (url.pathname === "/resolve" && request.method === "GET") return await handleResolve(request, env, shardUrls)
        if (url.pathname === "/status" && request.method === "GET") return await handleStatus(env, shardUrls)
        if (url.pathname === "/pow_challenge" && request.method === "GET") return await handlePowChallenge(request, env)
        if (url.pathname === "/register_shard" && request.method === "POST") return await handleRegisterShard(request, env)

        if (url.pathname === "/admin/push_routing_table" && request.method === "POST") {
          if (env.ROUTER_SHARED_SECRET) {
            const authHeader = request.headers.get("Authorization") || ""
            const match = authHeader.match(/^Bearer\s+(.+)$/i)
            if (!match || match[1] !== env.ROUTER_SHARED_SECRET) return err("Unauthorized", 401)
          }
          const outcome = await pushRoutingTableToShards(env, shardUrls)
          return jsonOk(outcome)
        }

        if (url.pathname === "/admin/config" && request.method === "GET") {
          if (env.ROUTER_SHARED_SECRET) {
            const authHeader = request.headers.get("Authorization") || ""
            const match = authHeader.match(/^Bearer\s+(.+)$/i)
            if (!match || match[1] !== env.ROUTER_SHARED_SECRET) return err("Unauthorized", 401)
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
      }
    } catch (e) {
      console.error("Unhandled error:", e)
      return err("Internal server error", 500)
    }

    return new Response("Not Found", { status: 404, headers: CORS_HEADERS })
  },
}