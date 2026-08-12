## What does this PR do?

<!-- A short description of the change and why it's needed. -->

## Type of change

- [ ] Bug fix
- [ ] New feature / endpoint
- [ ] Breaking change (wire format, API, or configuration)
- [ ] Documentation / comments only
- [ ] Refactor / internal cleanup
- [ ] CI / tooling

## Checklist

- [ ] `node --check shard/worker.js router/router.js combined/worker.js` passes locally
- [ ] `wrangler deploy --dry-run` passes for the affected worker(s)
- [ ] README updated if the change affects the API, config reference, or deployment steps
- [ ] Commits follow the [Conventional Commits](../.github/CONTRIBUTING.md#commit-convention) format
- [ ] No wire-format–breaking changes (or the PR description explains the migration path)
- [ ] No secrets or real `wrangler.toml` files committed

## Related issues

<!-- Closes #NNN -->
