#!/bin/bash
# Full end-to-end run on a fresh dev server: start, seed, mint the read-only token, run unit +
# integration tests, stop. MODE=local (default) uses `vault server -dev`; MODE=compose a
# container (ENT=1 for Enterprise). The server is stopped on exit either way.
set -euo pipefail

MODE="${MODE:-local}"
CONTAINER_CLI="${CONTAINER_CLI:-docker}"
case "$MODE" in
  local)
    export VAULT_ADDR="http://127.0.0.1:${VAULT_DEV_PORT:-8250}"
    trap 'scripts/dev_down.sh >/dev/null 2>&1 || true' EXIT
    scripts/dev_down.sh >/dev/null
    scripts/dev_up.sh
    ;;
  compose)
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
    ;;
  *)
    echo "error: MODE must be local or compose" >&2
    exit 1
    ;;
esac

scripts/seed_findings.sh
scripts/posture_token.sh
VAULT_TOKEN="$(cat .tmp/posture-token)" uv run pytest -q -m "integration or not integration" --cov=vault_posture --cov-fail-under=90
