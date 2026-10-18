#!/bin/bash
# Stop the local `vault server -dev` started by scripts/dev_up.sh (idempotent). In memory: all state goes.
set -euo pipefail

PID_FILE=".tmp/vault-dev/vault.pid"
if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  kill "$(cat "$PID_FILE")"
  echo "stopped vault dev server (pid $(cat "$PID_FILE"))"
else
  echo "vault dev server not running"
fi
rm -f "$PID_FILE"
