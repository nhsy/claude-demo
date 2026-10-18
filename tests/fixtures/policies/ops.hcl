/* Ops: broad access with a wildcard segment */
path "secret/data/+/*" {
  capabilities = ["create", "read", "update"]
}

path "secret/data/app/*" {
  capabilities = ["update"] // merges with app.hcl's rule for the same glob
}

path "sys/policies/acl/*" {
  capabilities = ["read", "list"]
  allowed_parameters = {
    "policy" = []
  }
}

path "secret/data/exact" {
  capabilities = ["read"]
}
