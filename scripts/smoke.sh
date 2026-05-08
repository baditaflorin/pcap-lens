#!/usr/bin/env bash
set -euo pipefail

npm run build

PORT="${PORT:-4173}"
npx vite preview --host 127.0.0.1 --port "${PORT}" --strictPort > /tmp/pcap-lens-smoke.log 2>&1 &
SERVER_PID=$!

cleanup() {
  kill "${SERVER_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ready=0
for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${PORT}/pcap-lens/" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.25
done

if [[ "${ready}" -ne 1 ]]; then
  cat /tmp/pcap-lens-smoke.log
  exit 1
fi

PLAYWRIGHT_BASE_URL="http://127.0.0.1:${PORT}" npx playwright test e2e/pcap-lens.spec.ts
