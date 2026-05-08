# 0009 - Configuration and Secrets Management

## Status

Accepted

## Context

The app is a static frontend and must never contain secrets. It does need public configuration for repository links, PayPal support URL, base path, and build metadata.

## Decision

Use Vite environment variables only for public values prefixed with `VITE_`.

Committed `.env.example` documents allowed public values. Real `.env` files are gitignored. The frontend rejects any design that requires embedded API keys, encrypted secrets, or obfuscated credentials.

## Consequences

- No secret rotation is required for v1.
- Public links can be changed at build time.
- Any future secret-dependent feature must move to an offline generator or a justified Mode C backend.

## Alternatives Considered

- Runtime config endpoint. Rejected because there is no backend.
- Commit encrypted secrets. Rejected because frontend secrets are still secrets exposed to users.
