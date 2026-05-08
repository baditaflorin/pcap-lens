# 0002 - Architecture Overview and Module Boundaries

## Status

Accepted

## Context

The application needs to parse packet captures, decode common protocols, derive flows, visualize traffic, and evaluate a v1 subset of Suricata-compatible rules. All of this must run in the browser under Mode A.

## Decision

Use a feature-oriented frontend architecture with pure logic modules separated from React UI:

- `features/capture`: file loading, PCAP and PCAPNG parsing, packet normalization.
- `features/protocols`: Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and TLS metadata decoding.
- `features/flows`: flow keying, aggregation, endpoint graph construction.
- `features/rules`: Suricata-style rule parsing and packet matching.
- `features/analyzer`: orchestration across parser, decoders, flows, and rules.
- `features/ui`: dropzone, packet table, flow graph, rule editor, findings, and app shell.
- `workers`: analysis worker boundary for CPU-heavy work.
- `lib`: shared utilities, formatting, errors, metadata, and storage.

Pure modules own the packet-analysis behavior. React components own presentation and interaction only.

## Consequences

- Parser and rule-engine tests can run without a DOM.
- The UI can evolve without rewriting analysis logic.
- Web Worker adoption is straightforward because the analysis contract is serializable.
- There is no backend module boundary in v1.

## Alternatives Considered

- Single-file prototype. Rejected because parsers and rule engines become risky without unit boundaries.
- Backend-centered architecture. Rejected by ADR 0001.
