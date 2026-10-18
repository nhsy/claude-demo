#!/bin/bash
# Write the vault-posture policies and mint a 1h orphan token into .tmp/posture-token (0600).
# Uses the dev root token; TOKEN_FILE overrides the output file. The token gets the base
# vault-posture-readonly policy plus the vault-posture-pki-reader add-on; PKI_READER=0 leaves it out.
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8250}"
export VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN:-root}"
POLICIES=(vault-posture-readonly)
[[ "${PKI_READER:-1}" == "1" ]] && POLICIES+=(vault-posture-pki-reader)
TOKEN_FILE="${TOKEN_FILE:-.tmp/posture-token}"

mkdir -p "$(dirname "$TOKEN_FILE")"
policy_flags=()
for policy in "${POLICIES[@]}"; do
  vault policy write "$policy" "skills/vault-posture/policies/${policy}.hcl" >/dev/null
  policy_flags+=("-policy=${policy}")
done
umask 077
vault token create "${policy_flags[@]}" -no-default-policy -orphan \
  -ttl=1h -explicit-max-ttl=1h -display-name=vault-posture -field=token >"$TOKEN_FILE"
echo "Wrote ${TOKEN_FILE} (policies ${POLICIES[*]}, ttl 1h)"
