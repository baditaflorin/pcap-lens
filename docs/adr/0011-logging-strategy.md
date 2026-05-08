# 0011 - Logging Strategy

## Status

Accepted

## Context

Mode A has no server logs. Browser console output can be useful during development but should not leak capture data or create noisy production output.

## Decision

Use minimal browser logging:

- Development may log non-sensitive diagnostics.
- Production shows user-facing errors in the UI.
- Production console output is limited to unexpected fatal errors that contain no packet payloads.

## Consequences

- Users get actionable feedback without inspecting DevTools.
- Sensitive packet contents are not printed to the console by default.
- Debugging production issues may require a user-provided reproduction file.

## Alternatives Considered

- Verbose client logs. Rejected because captures may contain private data.
- Server-side structured logs. Rejected by ADR 0001.
