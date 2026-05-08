# 0014 - Error Handling Conventions

## Status

Accepted

## Context

Users will encounter unsupported capture formats, truncated files, malformed packets, invalid rules, and browser memory limits. Errors need to be understandable and safe.

## Decision

Use typed `AnalysisError` values in logic modules and map them to concise UI messages. Recoverable packet-level decode errors become packet warnings rather than whole-capture failures when possible.

Rule parser errors include line numbers. File parser errors include the format stage, but do not include raw packet bytes.

## Consequences

- One bad packet does not usually block the entire capture.
- Invalid rules can be fixed in the editor.
- Error details remain privacy-conscious.

## Alternatives Considered

- Throw raw JavaScript errors through the UI. Rejected because messages are inconsistent and may expose internals.
- Silently skip bad input. Rejected because users need to trust analysis results.
