# 0003 - Frontend Framework and Build Tooling

## Status

Accepted

## Context

The app needs a rich file-drop UI, stateful analysis results, accessible tables, graph rendering, local persistence, and a production build that works from GitHub Pages under `/pcap-lens/`.

## Decision

Use React, TypeScript strict mode, and Vite.

Supporting tools:

- Tailwind CSS for focused utility styling.
- Zod for validating stored settings and imported rule text where needed.
- TanStack Query for version/metadata fetching with stable cache keys.
- Lucide React for icons.
- Vitest for unit tests.
- Playwright for smoke and happy-path e2e tests.

## Consequences

- Vite can build directly into `docs/`.
- TypeScript strict mode protects parser and rule-engine contracts.
- React keeps the interactive analysis workspace manageable.
- The app remains static and Pages-friendly.

## Alternatives Considered

- Vanilla TypeScript. Rejected because the UI has enough state and interaction to benefit from React.
- Next.js. Rejected because static export and base-path behavior add unnecessary complexity for this v1.
- Svelte. Reasonable, but React has broader ecosystem coverage for the chosen testing and UI tooling.
