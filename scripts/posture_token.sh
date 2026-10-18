#!/bin/bash
# Write the vault-posture-readonly policy and mint a 1h orphan token into .tmp/posture-token (0600).
# Uses the dev root token; TOKEN_FILE overrides the output file.
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
export VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN:-root}"
POLICY="vault-posture-readonly"
TOKEN_FILE="${TOKEN_FILE:-.tmp/posture-token}"

mkdir -p "$(dirname "$TOKEN_FILE")"
vault policy write "$POLICY" "skills/vault-posture/policies/${POLICY}.hcl" >/dev/null
umask 077
vault token create -policy="$POLICY" -no-default-policy -orphan \
  -ttl=1h -explicit-max-ttl=1h -display-name=vault-posture -field=token >"$TOKEN_FILE"
echo "Wrote ${TOKEN_FILE} (policy ${POLICY}, ttl 1h)"
