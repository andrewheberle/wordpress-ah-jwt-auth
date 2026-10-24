# Release by merging a release PR

WordPress.org serves whatever the `Stable tag` in SVN trunk's `readme.txt` names and shows its changelog, so every release needs the `Version:` header, `Stable tag` and changelog updated together. Rather than editing these by hand, a manual **Prepare release** workflow makes the edits on a `release/X.Y.Z` branch, and merging that PR is the release: the **Release** workflow deploys whenever the `Version:` header on `main` is newer than the latest tag. This keeps the repo's files matching what is live, so the readme sync can push `main`'s readme as-is.

## Considered Options

- **Stamp the version at deploy time** from a tag, leaving the repo's files stale. Rejected: the between-release readme sync would have to reconstruct the stable tag and the whole changelog, or publish a readme missing recent entries.
- **Hand edits guarded by a CI check.** Rejected: safe, but keeps the chore.
- **release-please.** Rejected: needs conventional-commit titles, does not write the `readme.txt` changelog format, and generates developer-facing text that would be rewritten anyway.

## Consequences

The workflow pushes the release branch and you open the PR, because a PR opened with `GITHUB_TOKEN` does not trigger the PR checks the `main` ruleset requires. For the same reason a GitHub release created by a workflow cannot trigger other workflows, so tests, deploy, GitHub release and SBOM all run in the one Release workflow.
