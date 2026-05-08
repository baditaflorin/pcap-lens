# Contributing

Thanks for helping improve `pcap-lens`.

## Local Setup

```sh
npm install
make install-hooks
make test
make build
```

## Commit Style

Use Conventional Commits:

- `feat: add packet decoder`
- `fix: handle empty pcapng blocks`
- `docs: update data contract`
- `test: cover rule matching`
- `chore: refresh build output`

## Pull Request Expectations

- Keep changes focused.
- Add or update tests for parser, rule engine, and UI behavior.
- Do not commit secrets, real captures with sensitive traffic, or private infrastructure details.
- Run `make test`, `make build`, and `make smoke` before pushing.
