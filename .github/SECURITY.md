# Security Policy

## Scope

NexTalk-Relay is a research-grade relay backend. It is **not independently security-audited**. The following issues are in scope for responsible disclosure:

- Signature bypass: a sender can forge requests without a valid Ed25519 signature
- Replay attacks: a captured `(pubkey, timestamp, signature)` triple can be reused beyond the clock-skew window
- Mailbox enumeration: a caller can enumerate or guess mailbox IDs without the server secret
- Cross-tenant reads: a caller can read another mailbox they don't own
- Denial-of-service via oversized payloads or rate-limit bypass
- Parser panics / crashes on malformed input (JSON depth, truncated bodies)
- Any vector that lets an unauthenticated caller delete or corrupt messages

Out of scope:
- Content confidentiality — the relay is intentionally unable to decrypt payloads; that guarantee lives in NexTalk's end-to-end encryption layer
- Issues that require the attacker to already hold `SERVER_SECRET` or `ROUTER_SIGNING_KEY`
- Theoretical timing side-channels with no practical exploit path

## Reporting

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities privately via a [GitHub Security Advisory](https://github.com/erfanheydarzade/NexTalk-Relay/security/advisories/new). You'll get a response within a few days. Include:

- A clear description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept request
- The affected component (`shard/worker.js`, `router/router.js`, `combined/worker.js`, or a specific endpoint)

## Disclosure Timeline

- **Day 0** — Report received, acknowledged within 72 hours
- **Day 0–14** — Issue assessed and fix developed
- **Day 14–30** — Fix released, advisory published

If a fix takes longer than 30 days, we'll communicate the delay and revised timeline.

## Supported Versions

Only the latest tagged release on the `main` branch is supported. Older versions receive no security patches.
