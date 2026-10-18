#!/bin/bash
# Seed a dev server (root token) with configuration that trips every live-testable VP rule:
#   VP-QUOTA-003/004  a path-scoped rate-limit quota, rate-limit audit logging off
#   VP-QUOTA-002      no lease-count quota (Enterprise only)
#   VP-SEC-001/002    a root token generation and an unseal-key rekey left in progress
#   VP-SEC-004        dev servers have no rotation interval
#   VP-PLUG-001/002   an external plugin registered without a version
#   VP-ROLE-001..009  JWT, Kubernetes, AppRole and token roles with loose bindings
#   VP-PKI-002..006/008  short-lived issuers, no AIA URLs, auto-tidy off, CRL+OCSP off, leaf_not_after=permit
# Unit tests cover what a dev server can't show: VP-QUOTA-001 (conflicts with 003), VP-SEC-003
# (year-old key), VP-PKI-001 (expired issuer) and VP-PKI-007 (Vault refuses weak keys). Idempotent.
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8250}"
export VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN:-root}"
PLUGIN="compose/plugins/posture-dummy"

# vault write without its advisory warnings (several seeded roles trigger them on purpose);
# errors are still shown and fail the script.
write() {
  local out
  if ! out="$(vault write "$@" 2>&1 >/dev/null)"; then
    echo "$out" >&2
    return 1
  fi
}

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

vault auth list -format=json | jq -e '."userpass/"' >/dev/null || vault auth enable userpass >/dev/null
write sys/quotas/rate-limit/userpass-login path=auth/userpass/ rate=50
write sys/quotas/config enable_rate_limit_audit_logging=false

vault plugin register -sha256="$(sha256 "$PLUGIN")" secret posture-dummy >/dev/null

if [[ "$(vault read -field=started sys/generate-root/attempt)" != "true" ]]; then
  vault operator generate-root -init -format=json >/dev/null  # discard the OTP
fi
if [[ "$(vault read -field=started sys/rekey/init)" != "true" ]]; then
  vault operator rekey -init -key-shares=1 -key-threshold=1 -format=json >/dev/null
fi
# ---- auth roles
enable_auth() { vault auth list -format=json | jq -e --arg p "$1/" '.[$p]' >/dev/null || vault auth enable "$1" >/dev/null; }
enable_auth jwt
enable_auth kubernetes
enable_auth approle
# A throwaway validation key: the JWT roles are never logged into.
pubkey="$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null | openssl pkey -pubout)"
write auth/jwt/config jwt_validation_pubkeys="$pubkey" bound_issuer=https://token.actions.githubusercontent.com
write auth/jwt/role/ci-audience-only role_type=jwt user_claim=sub bound_audiences=https://github.com/acme token_policies=deploy
write auth/jwt/role/ci-wildcard - <<'JSON'
{"role_type": "jwt", "user_claim": "sub", "bound_audiences": ["https://github.com/acme"],
 "bound_claims_type": "glob", "bound_claims": {"repository": "acme/*"}, "token_policies": ["deploy"]}
JSON
write auth/jwt/role/break-glass role_type=jwt user_claim=sub bound_subject=repo:acme/ops:ref:refs/heads/main token_policies=root
write auth/jwt/role/sso role_type=oidc user_claim=sub allowed_redirect_uris=http://localhost:8250/oidc/callback verbose_oidc_logging=true
write auth/kubernetes/role/any-pod bound_service_account_names='*' bound_service_account_namespaces='*' token_policies=app
write auth/kubernetes/role/any-ns bound_service_account_names=app bound_service_account_namespaces='*' token_policies=app
write auth/kubernetes/role/scoped bound_service_account_names=app bound_service_account_namespaces=prod token_policies=app
write auth/approle/role/role-id-only bind_secret_id=false secret_id_bound_cidrs=10.0.0.0/8 token_policies=app
write auth/approle/role/forever-secret secret_id_ttl=0 token_policies=app token_period=24h
write auth/token/roles/ops-root allowed_policies=root orphan=true

# ---- PKI
enable_pki() { vault secrets list -format=json | jq -e --arg p "$1/" '.[$p]' >/dev/null || vault secrets enable -path="$1" pki >/dev/null; }
enable_pki pki
enable_pki pki_off
if ! vault list pki/issuers >/dev/null 2>&1; then  # exit 2 when there are none
  write pki/root/generate/internal common_name="posture critical CA" issuer_name=critical ttl=240h
  write pki/root/generate/internal common_name="posture warning CA" issuer_name=warning ttl=1440h
fi
vault patch pki/issuer/critical leaf_not_after_behavior=permit >/dev/null  # patch: a write would reset issuer_name
write pki_off/config/crl disable=true ocsp_disable=true

echo "Seeded ${VAULT_ADDR}: rate-limit quota on auth/userpass/, external plugin posture-dummy, generate-root and rekey in progress, auth roles, PKI issuers"
