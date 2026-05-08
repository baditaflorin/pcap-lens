# pcap-lens

Live app: https://baditaflorin.github.io/pcap-lens/

Repository: https://github.com/baditaflorin/pcap-lens

Support: https://www.paypal.com/paypalme/florinbadita

Browser-based PCAP analyzer with protocol decoding, flow graphs, and Suricata-style rule matching.

`pcap-lens` is a pure GitHub Pages app for local packet-capture triage. Drop a `.pcap` or `.pcapng` file into the browser to decode common protocols, build conversations, and run a documented subset of Suricata-compatible IDS rules without installing Wireshark or running a Suricata container.

## Status

This repository is being scaffolded as Mode A: Pure GitHub Pages. The first published page is intentionally minimal; the full analyzer is implemented in subsequent commits.

## Quickstart

```sh
npm install
make install-hooks
make dev
make test
make build
```

## Documentation

Architecture: https://github.com/baditaflorin/pcap-lens/blob/main/docs/architecture.md

ADRs: https://github.com/baditaflorin/pcap-lens/tree/main/docs/adr

Deploy guide: https://github.com/baditaflorin/pcap-lens/blob/main/docs/deploy.md
