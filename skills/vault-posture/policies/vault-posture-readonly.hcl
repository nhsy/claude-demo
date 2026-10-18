# vault-posture-readonly: the only policy the vault-posture skill's token needs.
#
# Grants read/list on exactly the endpoints vault_posture.py reads, nothing else.
# Load once (root namespace) and mint a short-lived token for each session:
#   vault policy write vault-posture-readonly vault-posture-readonly.hcl
#   vault token create -policy=vault-posture-readonly -no-default-policy -orphan -ttl=1h
#
# Never add create/update/patch/delete/sudo here. tests/test_policy.py fails if a read path
# the script uses is missing, or if any grant goes beyond read/list.

# Token validation (the script calls lookup-self before any other read).
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# ---- quotas
path "sys/quotas/config" {
  capabilities = ["read"]
}

path "sys/quotas/rate-limit/*" {
  capabilities = ["read", "list"]
}

# Enterprise only; Community answers 404 and the script reports the scope as unsupported.
path "sys/quotas/lease-count/*" {
  capabilities = ["read", "list"]
}

# ---- security: status of seal-key operations (the script keeps started/progress/required only)
path "sys/generate-root/attempt" {
  capabilities = ["read"]
}

path "sys/generate-recovery-token/attempt" {
  capabilities = ["read"]
}

path "sys/rekey/init" {
  capabilities = ["read"]
}

path "sys/rekey-recovery-key/init" {
  capabilities = ["read"]
}

# ---- security: barrier key and plugins
path "sys/key-status" {
  capabilities = ["read"]
}

path "sys/rotate/config" {
  capabilities = ["read"]
}

path "sys/plugins/catalog" {
  capabilities = ["read"]
}

# ---- defence in depth: if this policy is ever attached next to broader ones, these
# credential-minting and token-consuming endpoints stay closed to the token.
path "+/creds/*" {
  capabilities = ["deny"]
}

path "+/issue/*" {
  capabilities = ["deny"]
}

path "+/sign/*" {
  capabilities = ["deny"]
}

path "sys/wrapping/unwrap" {
  capabilities = ["deny"]
}

path "sys/generate-root/update" {
  capabilities = ["deny"]
}

path "sys/rekey/update" {
  capabilities = ["deny"]
}
