# Postmortem

## What Was Built

`pcap-lens` v0.1.0 is a Mode A GitHub Pages packet capture analyzer at:

https://baditaflorin.github.io/pcap-lens/

It includes a React/Vite frontend, local PCAP and PCAPNG parsing, protocol decoding, flow aggregation, SVG flow graph rendering, a v1 Suricata-style rule parser and matcher, local rule persistence, PWA metadata, local hooks, unit tests, Playwright smoke tests, and committed Pages output under `docs/`.

The live app links to:

https://github.com/baditaflorin/pcap-lens

https://www.paypal.com/paypalme/florinbadita

It shows app version and commit metadata in the UI.

## Was Mode A Correct?

Yes. Mode A was the correct v1 choice.

The core workflow is local capture inspection. A backend would have introduced capture-upload privacy risk, server storage decisions, authentication questions, deployment operations, and abuse handling without unlocking a required v1 feature. TypeScript in a Web Worker was enough for the target protocol subset and rule subset.

Mode C may become justified later only if the project needs full Suricata parity, very large captures beyond browser memory limits, shared team workspaces, or server-side capture indexing.

## What Worked

- GitHub Pages from `main` `/docs` gave a working public URL quickly.
- Keeping parser, decoder, flow, and rule logic as pure modules made tests straightforward.
- The synthetic capture fixture covers HTTP, DNS, TLS metadata, TCP, and UDP without committing sensitive traffic.
- Playwright smoke testing caught a real selector issue before release.

## What Did Not Work

- Vite preview moved ports automatically during the first smoke run, so the script now uses `--strictPort`.
- The first Tailwind install pulled v4, while the project config was written for v3. Pinning Tailwind 3.4 restored the intended build path.
- TypeScript 6 requires an explicit deprecation silence for `baseUrl` path mapping.

## What Surprised Us

- GitHub Pages became reachable quickly after enabling it from the API.
- Lucide React no longer exposes a GitHub brand icon, so the UI uses a neutral star icon for the repository link.

## Accepted Tech Debt

- PCAPNG timestamp-resolution options are not fully interpreted.
- IPv6 extension headers are not walked.
- TLS decoding is metadata-only.
- Suricata compatibility is an explicit v1 subset, not an engine clone.
- Flow graph layout is deterministic and lightweight, not force-directed.

## Next Improvements

1. Add TCP stream reassembly for stronger HTTP and content-rule matching.
2. Expand Suricata keyword support for `flow`, `offset`, `depth`, `distance`, `within`, `pcre`, and metadata fields.
3. Add optional IndexedDB analysis snapshots with a clear privacy toggle.

## Time Spent vs Estimate

Estimated: 3-5 hours for a polished v1 scaffold and browser analyzer.

Actual: about 2 hours for implementation, tests, live Pages verification, and release preparation.
