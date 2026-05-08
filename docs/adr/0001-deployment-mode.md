# 0001 - Deployment Mode

## Status

Accepted

## Context

`pcap-lens` needs to replace the everyday convenience of a Wireshark install plus a Suricata Docker workflow for quick packet-capture triage. Users should be able to drop a `.pcap` or `.pcapng` into the app, inspect decoded protocols, see flow relationships, and run IDS-style rules.

The bootstrap requirement says every decision must prefer GitHub Pages, browser APIs, WASM, and static assets before introducing a runtime backend.

Packet captures are often sensitive. Uploading them to a server would create privacy, storage, auth, retention, and abuse-handling obligations that are unnecessary for v1.

## Decision

Use Mode A: Pure GitHub Pages.

The app is a static TypeScript frontend hosted from the repository's `docs/` directory. Capture parsing, protocol decoding, flow construction, and Suricata-style rule matching happen locally in the browser. Heavy parsing runs behind a Web Worker boundary so the UI remains responsive.

No runtime backend, Docker image, server database, server auth, nginx configuration, or Prometheus endpoint is part of v1.

## Consequences

- Captures remain on the user's machine.
- The live app can be hosted entirely at https://baditaflorin.github.io/pcap-lens/.
- The repo does not need deployed infrastructure, secrets, or server maintenance.
- Browser memory and CPU limits define the practical capture-size ceiling.
- Full Suricata engine parity and full Wireshark dissector parity remain out of scope for v1.

## Alternatives Considered

- Mode B: GitHub Pages plus pre-built data. Rejected because user-provided captures are local, not a public dataset that benefits from scheduled preprocessing.
- Mode C: GitHub Pages plus Docker backend. Rejected for v1 because server-side parsing would upload sensitive captures and introduce auth, storage, and operational complexity without a required v1 feature.
