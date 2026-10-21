#!/bin/bash
# Start a local in-memory `vault server -dev` (no containers) on 127.0.0.1:${VAULT_DEV_PORT:-8250},
# root token ${VAULT_DEV_ROOT_TOKEN:-root}, with compose/plugins as the plugin directory.
# State, log and pid live in .tmp/vault-dev. Idempotent: a running server is left alone.
set -euo pipefail

PORT="${VAULT_DEV_PORT:-8250}"
DIR=".tmp/vault-dev"
PID_FILE="${DIR}/vault.pid"
ADDR="http://127.0.0.1:${PORT}"

command -v vault >/dev/null || { echo "error: vault CLI not found (https://developer.hashicorp.com/vault/install)" >&2; exit 1; }
mkdir -p "$DIR"

if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "vault dev server already running (pid $(cat "$PID_FILE")) on ${ADDR}"
  exit 0
fi
if curl -s -o /dev/null "${ADDR}/v1/sys/health"; then
  echo "error: port ${PORT} is already in use (set VAULT_DEV_PORT, or task down for the container)" >&2
  exit 1
fi

# plugin_directory must be absolute, so the config is generated per checkout. The rest seeds
# VP-CFG-002/003: a long lease ceiling and a second loopback listener serving metrics without a
# token (PORT+1 is the dev cluster port, so it takes PORT+2).
cat >"${DIR}/dev.hcl" <<EOF
plugin_directory = "$(pwd)/compose/plugins"
max_lease_ttl = "8760h"
listener "tcp" {
  address = "127.0.0.1:$((PORT + 2))"
  tls_disable = true
  telemetry {
    unauthenticated_metrics_access = true
  }
}
EOF
nohup vault server -dev \
  -dev-root-token-id="${VAULT_DEV_ROOT_TOKEN:-root}" \
  -dev-listen-address="127.0.0.1:${PORT}" \
  -dev-no-store-token \
  -config="${DIR}/dev.hcl" >"${DIR}/vault.log" 2>&1 &
echo $! >"$PID_FILE"

for _ in $(seq 1 30); do
  if curl -s -o /dev/null "${ADDR}/v1/sys/health"; then
    echo "vault dev server running (pid $(cat "$PID_FILE"), $(vault version | cut -d' ' -f2)) on ${ADDR}"
    exit 0
  fi
  kill -0 "$(cat "$PID_FILE")" 2>/dev/null || break
  sleep 0.5
done
echo "error: vault dev server did not start; see ${DIR}/vault.log" >&2
tail -5 "${DIR}/vault.log" >&2
exit 1
