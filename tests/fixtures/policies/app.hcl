# App team: read their secrets, but never the admin subtree.
path "secret/data/app/*" {
  capabilities = ["read", "list"]
}

path "secret/data/app/admin/*" {
  capabilities = ["deny"]
}

path "secret/metadata/+/config" {
  capabilities = ["read"]
}
