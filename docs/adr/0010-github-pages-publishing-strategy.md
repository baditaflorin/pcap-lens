# 0010 - GitHub Pages Publishing Strategy

## Status

Accepted

## Context

The live GitHub Pages URL is a first-class deliverable from the first commit. The repository must not use GitHub Actions, and all build checks run locally through Make targets and git hooks.

GitHub Pages can publish directly from `main` branch `/docs`. This keeps the static artifact visible and easy to verify.

## Decision

Publish GitHub Pages from the `main` branch and `/docs` directory.

The Vite build writes production assets directly into `docs/`. The app uses the base path `/pcap-lens/`, hashed assets, and a copied `404.html` fallback for SPA routes. The `.gitignore` intentionally does not ignore `docs/`.

The public URL is:

https://baditaflorin.github.io/pcap-lens/

The repository URL is:

https://github.com/baditaflorin/pcap-lens

## Consequences

- Publishing is a normal git push after `make build`.
- Rollback is a normal revert of the publishing commit.
- Build artifacts are committed, which makes diffs larger but avoids a CI dependency.
- The build must be run locally before releases and before pushes through the pre-push hook.

## Alternatives Considered

- `gh-pages` branch. Rejected because it would add branch-management complexity without CI.
- `main` repository root. Rejected because source files and generated assets would be mixed at the same level.
- GitHub Actions Pages deployment. Rejected because the project requires no GitHub Actions.
