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

# plugin_directory must be absolute, so the config is generated per checkout.
printf 'plugin_directory = "%s"\n' "$(pwd)/compose/plugins" >"${DIR}/dev.hcl"
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
