# vault-posture skill

> **READ-ONLY. Observe and report only: this skill NEVER makes changes to Vault.** It never writes, cancels, rotates, patches, registers or tunes anything, never mints or revokes tokens, and never runs the fixes it drafts. An operator runs them.

A read-only HashiCorp Vault **security posture** review for Claude Code. Ask Claude whether Vault is configured safely, whether any GitHub Actions or Kubernetes login role is too loose, whether a CA is about to expire, or which policy lets someone write a path. A bundled script reads Vault (GET only) and writes small JSON files; Claude reads them, explains the findings and drafts fixes as text.

It complements [vault-ops](https://github.com/nhsy-hcp/vault-ops-skill) (health, inventory, policies, entities, client counts). Where the two overlap, the rule catalogue names the vault-ops rule that reports the same thing.

## Prerequisites

- [Claude Code](https://code.claude.com)
- [uv](https://docs.astral.sh/uv/getting-started/installation/): the script runs with `uv run --script` and installs its pinned dependencies (`hvac`, `requests`, `cryptography`) on first use
- Network access to Vault (Enterprise for namespaces and lease-count quotas; Community works with fewer checks)
- A short-lived token from the bundled read-only policies, never a root token. The offline `access` subcommand needs neither Vault nor a token.

## Install

```text
/plugin marketplace add nhsy/claude-demo
/plugin install vault-posture@vault-posture-skill
```

## Setup

An admin loads the policies once, in the root namespace:

```bash
vault policy write vault-posture-readonly policies/vault-posture-readonly.hcl
vault policy write vault-posture-pki-reader policies/vault-posture-pki-reader.hcl   # optional: PKI checks
```

`vault-posture-pki-reader` is a separate add-on because PKI mounts can have any name: its `+/issuer/+` style grants would also match secrets stored at those paths on a KV v1 mount. Leave it out if that matters; the PKI checks are then reported as not covered.

Each session, export the environment and start Claude:

```bash
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_CACERT=/path/to/ca.pem
export VAULT_TOKEN="$(vault token create -policy=vault-posture-readonly -policy=vault-posture-pki-reader -no-default-policy -orphan -ttl=1h -field=token)"
claude
```

| Variable | Required | Purpose |
| --- | --- | --- |
| `VAULT_ADDR` | yes (live) | Vault address |
| `VAULT_TOKEN` | yes (live) | Token from the read-only policies (1h TTL recommended) |
| `VAULT_CACERT` | recommended | CA bundle for TLS verification |
| `VAULT_SKIP_VERIFY` | dev only | `true` disables TLS verification |
| `VAULT_NAMESPACE` | no | Namespace to start `roles` / `pki` / `audit` from (default: root); children are included |
| `VAULT_POSTURE_OUTPUT_DIR` | no | Where results are written (default `.tmp/vault-posture/` in the working directory) |

## Ask Claude

- "Review our Vault security posture."
- "Are any of our GitHub Actions JWT roles bound only by audience?"
- "Do any Kubernetes auth roles accept every service account?"
- "Which PKI CAs expire in the next 90 days?"
- "Is anyone generating a root token right now?"
- "Using the policies in `terraform/vault/policies`, who can update `secret/data/payments/db`?"

## What it checks

| Subcommand | Rules | Looks at |
| --- | --- | --- |
| `roles` | VP-ROLE-001..009 | Roles that yield or mint root; JWT roles bound only by audience or by wildcard claims; verbose OIDC logging; Kubernetes roles open to any service account or namespace; AppRoles without secret IDs or with secret IDs that never expire; periodic tokens with no max TTL |
| `pki` | VP-PKI-001..008 | Expired or expiring issuers (30/90 days); weak CA keys or SHA-1; no AIA URL; auto-tidy off; CRL and OCSP both off; leaves allowed to outlive the CA |
| `quotas` | VP-QUOTA-001..004 | No rate-limit or lease-count quota; only path-scoped quotas; throttled requests not audit-logged |
| `security` | VP-SEC-001..004, VP-PLUG-001..002 | Root/recovery token generation or rekey in progress; barrier key age; no rotation interval; external and unversioned plugins |
| `audit` | all of the above | One combined file |
| `access` | none (offline) | Effective capabilities of ACL policy files on paths, evaluated with Vault's own matching rules |
| `diff` | none (offline) | New, resolved and unchanged findings between two result files, by fingerprint |
| `report` | none (offline) | A Markdown report from one or more result files of one cluster, with the drafted fixes from `references/rules.md` filled in |

Every rule, with its meaning and a drafted fix, is in [`references/rules.md`](references/rules.md).

## Files

| Path | Purpose |
| --- | --- |
| `SKILL.md` | Instructions Claude follows |
| `scripts/vault_posture.py` | The single-file collector (PEP 723, `uv run --script`) |
| `references/rules.md` | Rule catalogue with severities and operator remediation |
| `schemas/findings.schema.json`, `schemas/access.schema.json`, `schemas/diff.schema.json` | Output document schemas |
| `policies/vault-posture-readonly.hcl`, `policies/vault-posture-pki-reader.hcl` | Read-only token policies (generated) |
