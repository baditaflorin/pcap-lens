# 0006 - WASM Modules

## Status

Accepted

## Context

The bootstrap requested a GitHub Pages-first design and allows WASM where useful. Native Wireshark/libpcap and Suricata internals are large and not browser-native. The v1 target is practical triage, not full engine parity.

## Decision

Do not ship WASM in v1.

Implement the v1 parser, protocol decoders, flow aggregation, and Suricata-style rule subset in TypeScript. Run analysis behind a Web Worker boundary so larger captures do not block the UI.

Reconsider WASM only if a specific parser or rule-engine capability proves too expensive or too risky to maintain in TypeScript.

## Consequences

- Smaller initial payload and simpler GitHub Pages deployment.
- No COOP/COEP requirement for v1.
- No Pyodide or native engine bundle size tax.
- Full Wireshark and Suricata compatibility remains a non-goal.

## Alternatives Considered

- Compile libpcap or Suricata components to WASM. Rejected for v1 because bundle size and integration complexity are high.
- Use Pyodide plus Scapy. Rejected because startup cost and payload size conflict with the v1 asset budget.
