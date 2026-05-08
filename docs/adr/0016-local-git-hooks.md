# 0016 - Local Git Hooks

## Status

Accepted

## Context

The project does not use GitHub Actions. Local hooks must catch formatting, lint, type, secret, test, build, and smoke failures before commits and pushes.

## Decision

Use plain `.githooks/` scripts wired through:

```sh
git config core.hooksPath .githooks
```

Provide Make targets for:

- `make install-hooks`
- `make hooks-pre-commit`
- `make hooks-commit-msg`
- `make hooks-pre-push`

Use `gitleaks protect --staged` in pre-commit and a shell Conventional Commits validator in commit-msg.

## Consequences

- Hooks are transparent and require no extra hook framework.
- Contributors can run hook checks manually.
- Quality gates stay local and fast.

## Alternatives Considered

- Lefthook. Rejected to avoid another moving part.
- Husky. Rejected because plain hooks are sufficient and package-manager agnostic.
