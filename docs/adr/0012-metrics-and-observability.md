# 0012 - Metrics and Observability

## Status

Accepted

## Context

Mode A has no backend metrics. Analytics would provide usage insight but adds privacy tradeoffs, especially for a tool handling packet captures.

## Decision

Do not add analytics in v1.

Observability consists of local UI status, clear error messages, test coverage, smoke tests, and GitHub Pages availability checks.

## Consequences

- No PII or usage data is collected.
- There is no dashboard for usage or performance metrics.
- Users can inspect and run everything locally.

## Alternatives Considered

- Plausible analytics. Deferred because usage insight is not essential for v1.
- Custom beacon endpoint. Rejected because it would add infrastructure and privacy obligations.
