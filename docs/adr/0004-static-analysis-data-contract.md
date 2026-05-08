# 0004 - Static Analysis Data Contract

## Status

Accepted

## Context

Mode A has no server-side API and no scheduled static dataset. The primary input is a user-selected `.pcap` or `.pcapng` file. The app still needs stable internal contracts so parsers, workers, UI, and tests agree.

## Decision

Define a versioned in-browser analysis contract:

- Input file types: classic PCAP and PCAPNG.
- Supported link types: Ethernet, Linux cooked capture v1, and raw IPv4/IPv6.
- Analysis schema version: `analysis.v1`.
- Output entities: capture summary, decoded packets, flows, graph nodes, graph edges, rule definitions, and rule matches.
- Static metadata endpoint: `version.json`, generated during build and fetched by the frontend.

No sample capture data is committed unless it is synthetic and generated from tests or demo code.

## Consequences

- The frontend can show a clear unsupported-format error.
- Future breaking schema changes can become `analysis.v2`.
- The live page can show version and commit metadata without a backend.

## Alternatives Considered

- Store analysis output as static JSON. Rejected because captures are user-provided and privacy-sensitive.
- Upload captures for server processing. Rejected by ADR 0001.
