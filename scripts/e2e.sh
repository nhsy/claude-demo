#!/bin/bash
# Full end-to-end run against a fresh Community dev server: up, seed, token, unit + integration
# tests, down. The container is removed on exit. ENT=1 uses the Enterprise service instead.
set -euo pipefail

CONTAINER_CLI="${CONTAINER_CLI:-docker}"
if [[ "${ENT:-0}" == "1" ]]; then
  SERVICE=vault-ent PROFILE=(--profile ent)
  export VAULT_ADDR="http://127.0.0.1:${VAULT_ENT_PORT:-8260}"
else
  SERVICE=vault PROFILE=()
  export VAULT_ADDR="http://127.0.0.1:${VAULT_CE_PORT:-8250}"
fi
COMPOSE=("$CONTAINER_CLI" compose "${PROFILE[@]}")

trap '"${COMPOSE[@]}" rm -sf "$SERVICE" >/dev/null 2>&1 || true' EXIT
"${COMPOSE[@]}" up -d --wait --force-recreate "$SERVICE"
scripts/seed_findings.sh
scripts/posture_token.sh
VAULT_TOKEN="$(cat .tmp/posture-token)" uv run pytest -q -m "integration or not integration"
