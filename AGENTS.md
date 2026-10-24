## Before opening a PR

Done when `composer test` passes in a clean checkout (`git worktree add`): a stale local `vendor/` can mask failures that CI's fresh checkout hits. Plugin code outside `tests/` must also meet the `WordPress` coding standard; CI checks it with WPCS, and `phpcs` is not installed locally.

## Dependencies

`vendor/` is gitignored. The Release workflow builds it with `composer install --no-dev`, so everything in `require` ships to WordPress.org; test and build tools go in `require-dev`.

## Releases

The `Version:` header, `Stable tag`, "Tested up to" and changelog entries are written by the Prepare release workflow; leave them as they are in other changes. Merging a release PR deploys to WordPress.org. See `README.md` and `docs/adr/0001-release-from-a-release-pr.md`.

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues for andrewheberle/wordpress-ah-jwt-auth, using the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Uses the default labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
