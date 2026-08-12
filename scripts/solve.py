#!/usr/bin/env python3
"""
solve.py — Solve the Router PoW challenge on your local machine,
then hand the proof back to the shard so it can complete self-registration.

The shard's private key never leaves its KV store.  This script only does
the CPU-intensive grinding and passes the result through.

Usage
-----
    python solve.py --shard-url https://shard.example.workers.dev

    # if the shard has ROUTER_SHARED_SECRET set:
    python solve.py --shard-url https://shard.example.workers.dev --secret YOUR_SECRET

    # override the Router URL (auto-read from the shard otherwise):
    python solve.py --shard-url https://shard.example.workers.dev \
                    --router-url https://router.example.workers.dev

Requirements
------------
Python 3.8+, no third-party packages needed.

How it works
------------
1. GET  {shard}/admin/shard_info      → learn shard pubkey + router URL
2. GET  {router}/pow_challenge        → get a single-use nonce + difficulty
3. grind sha256({nonce}:{shard_url}:{i}) until leading-zero-bits >= difficulty
4. POST {shard}/admin/register        → pass {nonce, solution, router_url}
   The shard signs with its own private key (from KV) and calls the Router.
"""

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


# ─── PoW ─────────────────────────────────────────────────────────────────────

def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for b in digest:
        if b == 0:
            bits += 8
            continue
        x = b
        while (x & 0x80) == 0:
            bits += 1
            x <<= 1
        break
    return bits


def solve_pow(nonce: str, shard_url: str, difficulty: int) -> str:
    """
    Find the smallest non-negative integer i such that
        sha256("{nonce}:{shard_url}:{i}")
    has at least `difficulty` leading zero bits.

    At difficulty=20 this takes ~1 M iterations on average (~1–3 s on a
    modern laptop).  At difficulty=24 it's ~16 M (~10–30 s).  Either way
    vastly faster than the Worker's 30 ms CPU budget.
    """
    prefix = f"{nonce}:{shard_url}:".encode()
    target = difficulty

    print(f"  difficulty : {target} leading-zero bits")
    print(f"  nonce      : {nonce[:16]}…")
    print(f"  shard_url  : {shard_url}")
    print()

    i = 0
    t0 = time.time()
    report_every = 500_000

    while True:
        candidate = prefix + str(i).encode()
        digest = hashlib.sha256(candidate).digest()
        if leading_zero_bits(digest) >= target:
            elapsed = time.time() - t0
            rate = i / elapsed if elapsed else 0
            print(f"\r  ✓ solved in {i + 1:,} attempts ({elapsed:.1f}s, {rate / 1e6:.2f} Mhash/s)")
            return str(i)

        i += 1
        if i % report_every == 0:
            elapsed = time.time() - t0
            rate = i / elapsed if elapsed else 0
            print(f"\r  … {i / 1_000_000:.1f} M attempts, {rate / 1e6:.2f} Mhash/s …", end="", flush=True)


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

def http_get(url: str, secret: str | None = None, timeout: int = 10) -> dict:
    req = urllib.request.Request(url)
    if secret:
        req.add_header("Authorization", f"Bearer {secret}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach {url}: {exc.reason}") from exc


def http_post(url: str, payload: dict, secret: str | None = None, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if secret:
        req.add_header("Authorization", f"Bearer {secret}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach {url}: {exc.reason}") from exc


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Solve the Router PoW challenge locally and register this shard."
    )
    parser.add_argument(
        "--shard-url", required=True,
        help="This shard's public base URL, e.g. https://shard-a.example.workers.dev",
    )
    parser.add_argument(
        "--router-url",
        help="Router base URL (auto-detected from the shard's /admin/shard_info if omitted)",
    )
    parser.add_argument(
        "--secret",
        help="Value of ROUTER_SHARED_SECRET (if set on the shard — gates /admin/* endpoints)",
    )
    args = parser.parse_args()

    shard_url = args.shard_url.rstrip("/")
    secret    = args.secret

    # ── Step 1: fetch shard identity ─────────────────────────────────────────
    print("=" * 60)
    print("[1/4] Fetching shard identity")
    print("=" * 60)
    info_url = f"{shard_url}/admin/shard_info"
    print(f"  GET {info_url}")
    try:
        info = http_get(info_url, secret)
    except RuntimeError as exc:
        sys.exit(f"\nERROR: {exc}\n\n"
                 "Make sure the shard is deployed and /admin/shard_info is wired up\n"
                 "(see the worker.js additions in the README).")

    shard_pubkey = info.get("shard_pubkey", "")
    if not shard_pubkey:
        sys.exit("ERROR: shard_info response missing 'shard_pubkey' — is the shard running worker v2.2+?")

    router_url = (args.router_url or info.get("router_url") or "").rstrip("/")
    if not router_url:
        sys.exit(
            "ERROR: Router URL unknown.\n"
            "Either set ROUTER_URL in the shard's wrangler.toml or pass --router-url."
        )

    print(f"  shard_pubkey = {shard_pubkey}")
    print(f"  router_url   = {router_url}")
    print()

    # ── Step 2: get PoW challenge ─────────────────────────────────────────────
    print("=" * 60)
    print("[2/4] Requesting PoW challenge from Router")
    print("=" * 60)
    challenge_url = f"{router_url}/pow_challenge?shard_url={urllib.parse.quote(shard_url, safe='')}"
    print(f"  GET {challenge_url}")
    try:
        challenge = http_get(challenge_url)
    except RuntimeError as exc:
        sys.exit(f"\nERROR: {exc}\n\n"
                 "Make sure the Router has ROUTER_ADMIN_KV bound and /pow_challenge enabled.")

    nonce      = challenge.get("nonce", "")
    difficulty = int(challenge.get("difficulty", 0))
    expires_at = challenge.get("expires_at", 0)

    if not nonce or not difficulty:
        sys.exit(f"ERROR: unexpected challenge response: {challenge}")

    print(f"  nonce      = {nonce}")
    print(f"  difficulty = {difficulty} bits")
    print(f"  expires_at = {expires_at} (ms unix)")
    print()

    # ── Step 3: solve ─────────────────────────────────────────────────────────
    print("=" * 60)
    print("[3/4] Solving proof-of-work  (CPU-bound, may take a few seconds)")
    print("=" * 60)
    solution = solve_pow(nonce, shard_url, difficulty)
    print()

    # ── Step 4: hand solution back to the shard ───────────────────────────────
    print("=" * 60)
    print("[4/4] Posting solution to shard for signing + registration")
    print("=" * 60)
    register_url = f"{shard_url}/admin/register"
    print(f"  POST {register_url}")
    try:
        result = http_post(
            register_url,
            {"nonce": nonce, "solution": solution, "router_url": router_url},
            secret,
        )
    except RuntimeError as exc:
        sys.exit(f"\nERROR: {exc}")

    print()
    print("✓ Registration complete!")
    print()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()