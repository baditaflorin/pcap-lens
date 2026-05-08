# 0015 - Deployment Topology

## Status

Accepted

## Context

ADR 0001 selected Mode A. The topology must therefore be GitHub Pages only.

## Decision

Deploy only static files from `main` branch `/docs`.

There is no Docker backend, nginx layer, server database, Prometheus service, or server-side API. The browser loads HTML, CSS, JavaScript, service worker, manifest, and static metadata from GitHub Pages.

## Consequences

- Public surface area is only GitHub Pages.
- Operational cost is effectively zero.
- No server runbook is required beyond Pages publishing and rollback.

## Alternatives Considered

- Docker Compose backend on port 25342. Rejected because Mode C is not justified for v1.
- Static frontend plus offline data pipeline. Rejected because no shared dataset is needed.
