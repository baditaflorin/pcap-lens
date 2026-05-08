# 0013 - Testing Strategy

## Status

Accepted

## Context

Packet parsing and IDS matching are easy to regress. The project has no GitHub Actions, so local tests and hooks must carry quality gates.

## Decision

Use:

- Vitest unit tests for parser, protocol, flow, and rule modules.
- React Testing Library where component-level behavior needs DOM coverage.
- Playwright for one browser happy path.
- `scripts/smoke.sh` to build, serve `docs/`, and run the Playwright smoke test.
- `make test`, `make build`, `make smoke`, and `make lint` as the local contract.

## Consequences

- Tests run quickly enough for pre-push.
- Parser fixtures are synthetic and safe to commit.
- Browser rendering is verified before publishing.

## Alternatives Considered

- Manual browser-only testing. Rejected because parser correctness needs deterministic tests.
- GitHub Actions. Rejected by project constraints.
