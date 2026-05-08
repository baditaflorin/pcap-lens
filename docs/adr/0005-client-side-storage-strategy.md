# 0005 - Client-Side Storage Strategy

## Status

Accepted

## Context

The app should remember user preferences and edited IDS rules, but it should not persist packet captures by default because captures may contain sensitive data.

## Decision

Use `localStorage` for small non-sensitive preferences:

- Rule editor contents.
- Last selected UI tab.
- Theme preference if added.

Do not store packet captures, decoded packet payloads, or analysis results in v1. Users can reload a capture manually when needed.

## Consequences

- Persistence remains simple and transparent.
- No browser quota management is required.
- Sensitive captures are not silently retained.
- Cross-device sync is out of scope.

## Alternatives Considered

- IndexedDB. Rejected for v1 because retained captures would raise privacy and lifecycle concerns.
- OPFS. Rejected for the same reason and because no large local workspace is needed.
- Server persistence. Rejected by ADR 0001.
