# Architecture

`pcap-lens` is a Mode A GitHub Pages application. Captures are parsed locally in the browser and are not uploaded.

Live app:

https://baditaflorin.github.io/pcap-lens/

Repository:

https://github.com/baditaflorin/pcap-lens

## Context

```mermaid
C4Context
  title pcap-lens system context
  Person(user, "Analyst", "Drops local packet captures and IDS rules into the browser")
  System_Boundary(pages, "GitHub Pages") {
    System(app, "pcap-lens", "Static React app with local packet analysis")
  }
  System_Ext(github, "GitHub Repository", "Source, issues, stars, releases")
  System_Ext(paypal, "PayPal", "Optional project support")
  Rel(user, app, "Uses in browser")
  Rel(app, github, "Links to repository and fetches public commit metadata")
  Rel(app, paypal, "Links to support page")
```

## Container

```mermaid
flowchart LR
  user["Analyst browser"]
  pages["GitHub Pages static files"]
  app["React app shell"]
  worker["Analysis worker"]
  parser["PCAP/PCAPNG parser"]
  protocols["Protocol decoders"]
  flows["Flow aggregator"]
  rules["Suricata-style rule matcher"]
  storage["localStorage preferences"]
  github["Public GitHub API"]

  user --> pages
  pages --> app
  app --> worker
  worker --> parser
  worker --> protocols
  worker --> flows
  worker --> rules
  app --> storage
  app --> github
```

## Module Boundaries

- `features/capture`: capture file parsing and packet frame normalization.
- `features/protocols`: packet protocol decoders.
- `features/flows`: flow aggregation and graph construction.
- `features/rules`: Suricata-style rule parsing and matching.
- `features/analyzer`: orchestration and result shaping.
- `workers`: browser worker contract.
- `lib`: metadata, formatting, local storage, and shared errors.

## Pages Boundary

Everything served to users is static content from `/docs`. There is no runtime API, server database, Docker backend, nginx proxy, or secret-bearing process in v1.
