#!/bin/bash
# Seed a dev server (root token) with configuration that trips every live-testable VP rule:
#   VP-QUOTA-003/004  a path-scoped rate-limit quota, rate-limit audit logging off
#   VP-QUOTA-002      no lease-count quota (Enterprise only)
#   VP-SEC-001/002    a root token generation and an unseal-key rekey left in progress
#   VP-SEC-004        dev servers have no rotation interval
#   VP-PLUG-001/002   an external plugin registered without a version
# VP-QUOTA-001 and VP-SEC-003 can't coexist with the above on one server (or need a year-old
# key); unit tests cover them. Idempotent.
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
export VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN:-root}"
PLUGIN="compose/plugins/posture-dummy"

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

vault auth list -format=json | jq -e '."userpass/"' >/dev/null || vault auth enable userpass >/dev/null
vault write sys/quotas/rate-limit/userpass-login path=auth/userpass/ rate=50 >/dev/null
vault write sys/quotas/config enable_rate_limit_audit_logging=false >/dev/null

vault plugin register -sha256="$(sha256 "$PLUGIN")" secret posture-dummy >/dev/null

if [[ "$(vault read -field=started sys/generate-root/attempt)" != "true" ]]; then
  vault operator generate-root -init -format=json >/dev/null  # discard the OTP
fi
if [[ "$(vault read -field=started sys/rekey/init)" != "true" ]]; then
  vault operator rekey -init -key-shares=1 -key-threshold=1 >/dev/null
fi
echo "Seeded ${VAULT_ADDR}: rate-limit quota on auth/userpass/, external plugin posture-dummy, generate-root and rekey in progress"
