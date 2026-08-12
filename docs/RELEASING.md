# Releasing NexTalk-Relay

NexTalk-Relay releases are source-only — there are no compiled artifacts. A "release" is a tagged commit on `main` paired with a GitHub Release whose notes are generated automatically from Conventional Commit messages.

## How to cut a release

1. Make sure `main` is in the state you want to ship.

2. Go to **Actions → Release → Run workflow** on GitHub.

3. Fill in the version field (e.g. `v1.2.0`). It must start with `v` and follow [semver](https://semver.org/).

4. Optionally tick **Mark as pre-release** for a beta or release candidate.

5. Click **Run workflow**. The workflow will:
   - Validate the version string
   - Create and push an annotated git tag (no-op if the tag already exists)
   - Syntax-check all three workers (`shard`, `router`, `combined`)
   - Generate a grouped changelog from Conventional Commit messages since the previous tag
   - Create (or update) a GitHub Release with those notes

That's it. No manual tagging, no manual `gh release create`.

## Traditional tag flow

If you prefer tagging locally:

```bash
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin v1.2.0
```

The `release.yml` workflow also triggers on `push: tags: v*.*.*`, so it will run automatically and publish the GitHub Release the same way.

## Commit convention

The changelog groups commits by type — the grouping only works correctly if commits follow [Conventional Commits](../.github/CONTRIBUTING.md#commit-convention):

| Prefix | Changelog group |
|--------|-----------------|
| `feat:` / `feat(scope):` | Features |
| `fix:` / `fix(scope):` | Fixes |
| `docs:` | Documentation |
| `build:` / `perf:` / `refactor:` | Build & tooling |
| everything else (non-`ci:`, non-merge) | Other |

CI and merge commits are filtered out of the changelog automatically.

## Versioning policy

NexTalk-Relay follows **semantic versioning** from the operator's perspective:

- **Patch** (`v1.2.x`) — bug fixes and internal changes with no API or config changes
- **Minor** (`v1.x.0`) — new endpoints, new optional config keys, backward-compatible changes
- **Major** (`vX.0.0`) — breaking API changes, wire-format changes, removed endpoints, or renamed required config keys

## Deploying after a release

A GitHub Release tag is a stable reference you can pin in deployment automation:

```bash
# Check out the release tag
git checkout v1.2.0

# Deploy shard
cd shard && wrangler deploy

# Deploy router
cd ../router && wrangler deploy
```

The `wrangler.toml.example` files in each directory document every required and optional configuration key for that version.
