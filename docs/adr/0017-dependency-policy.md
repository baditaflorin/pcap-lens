# 0017 - Dependency Policy

## Status

Accepted

## Context

The app handles security-sensitive file formats in the browser. Dependencies must be mature, actively maintained, and necessary.

## Decision

Use production-ready libraries only:

- React, Vite, TypeScript, Tailwind CSS, Zod, TanStack Query, Lucide React.
- Vitest, Testing Library, Playwright, ESLint, Prettier for local quality.

Avoid large parsing engines unless they unlock a clear capability that TypeScript modules cannot handle safely. Keep bundle size visible through build output and lazy-load heavy code behind user action.

## Consequences

- Dependency surface stays explainable.
- Bundle size remains easier to control.
- Security review is practical for v1.

## Alternatives Considered

- Bring in Pyodide/Scapy. Rejected by ADR 0006.
- Compile native dissectors to WASM. Deferred until justified by a specific feature gap.
