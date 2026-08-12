# Contributing to NexTalk-Relay

Thanks for taking the time to contribute. NexTalk-Relay is the Cloudflare Workers relay backend for [NexTalk](https://github.com/erfanheydarzade/NexTalk), and contributions are welcome — whether that's a bug report, a security hardening idea, or a clean PR.

## Setup

You need:

- [Node.js](https://nodejs.org/) (LTS is fine) and `npm`
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/): `npm install -g wrangler`
- A Cloudflare account for live testing (the free tier is enough); local dev with `wrangler dev` works without one

```bash
git clone https://github.com/erfanheydarzade/NexTalk-Relay.git
cd NexTalk-Relay

# Shard — local dev
cp shard/wrangler.toml.example shard/wrangler.toml
cd shard && wrangler dev --port 8788

# Router — local dev (separate terminal)
cp router/wrangler.toml.example router/wrangler.toml
cd router && wrangler dev --port 8787
```

Syntax check everything before opening a PR:

```bash
node --check shard/worker.js
node --check router/router.js
node --check combined/worker.js
```

The CI does this (plus a `wrangler deploy --dry-run`) on every push and PR.

## Commit Convention

This repo uses **Conventional Commits** because the release changelog is generated directly from commit messages. Stick to this format:

```
<type>(<scope>): <short summary>
```

Common types:

| Type | When to use |
|---|---|
| `feat` | New behaviour visible to operators or clients |
| `fix` | Bug fix |
| `docs` | README, comments, docstrings only |
| `refactor` | Internal cleanup with no behaviour change |
| `perf` | Performance improvement |
| `build` | CI, wrangler config, tooling |
| `test` | Test-only changes |
| `chore` | Housekeeping (bump versions, etc.) |

Examples:

```
feat(shard): add /exists endpoint for non-consuming mailbox probe
fix(router): handle empty PRIOR_SHARD_COUNTS gracefully
docs: clarify ROUTER_SIGNING_PUBLIC setup in README
build(ci): add concurrency cancellation to CI workflow
```

Breaking changes get a `!` after the type/scope and a `BREAKING CHANGE:` footer:

```
feat(shard)!: replace SERVER_SECRET with capability-based mailbox IDs

BREAKING CHANGE: Existing mailboxes created under v1 will not resolve
under v2. Clients must re-register.
```

## Security

If you discover a vulnerability, please report it privately. See [SECURITY.md](SECURITY.md).

**Never open a public issue for a security bug.** Open a GitHub Security Advisory instead, or email the maintainer directly.

## Wire Format Stability

The `message` envelope format (type byte + payload) is a **wire contract** — once deployed in the field, changing the framing or the set of allowed envelope types (`offer`, `answer`, `message`, `finish`) breaks compatibility with live clients. Treat these with the same care you'd give a public API.

If a change is unavoidably breaking, it needs a major version bump and a migration path described in the PR.

## Pull Requests

- Keep PRs focused: one logical change per PR.
- Update `README.md` if the change affects the API, configuration, or deployment steps.
- The CI must pass (syntax check + dry-run deploy) before merging.
- Add a clear description of what the change does and why.
