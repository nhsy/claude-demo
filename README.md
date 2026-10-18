# vault-posture

> **READ-ONLY.** This skill never changes Vault: it never writes, cancels, rotates, registers or tunes anything, never mints tokens, and never runs the fixes it drafts. An operator runs them.

A read-only HashiCorp Vault **security posture** review skill for Claude Code. It complements [vault-ops](https://github.com/nhsy-hcp/vault-ops-skill): vault-ops asks *"is the cluster running well?"*, vault-posture asks *"is it configured safely?"*.

A single-file `uv run --script` Python program (`hvac`, `requests`) reads Vault with HTTP GET only and writes small JSON files. Claude reads them, explains the findings and drafts fixes as text.

## What it checks

| Subcommand | Rules | Looks at |
| --- | --- | --- |
| `quotas` | VP-QUOTA-001..004 | No rate-limit or lease-count quota, only path-scoped quotas, throttled requests not audited |
| `security` | VP-SEC-001..004, VP-PLUG-001..002 | Root/recovery token generation or rekey in progress, barrier key age, no rotation interval, external plugins (unversioned) |
| `audit` | all of the above | One combined `*-posture-*.json` |

The full catalogue with remediation is in [`skills/vault-posture/references/rules.md`](skills/vault-posture/references/rules.md).

## Use it

```text
/plugin marketplace add nhsy/claude-demo
/plugin install vault-posture@vault-posture-skill
```

An admin loads the read-only policy once; each session gets a short-lived token:

```bash
vault policy write vault-posture-readonly skills/vault-posture/policies/vault-posture-readonly.hcl
export VAULT_ADDR=https://vault.example.com:8200 VAULT_CACERT=/path/to/ca.pem
export VAULT_TOKEN="$(vault token create -policy=vault-posture-readonly -no-default-policy -orphan -ttl=1h -field=token)"
claude   # then: "review our Vault security posture"
```

| Variable | Required | Purpose |
| --- | --- | --- |
| `VAULT_ADDR` | yes | Vault address |
| `VAULT_TOKEN` | yes | Token from `vault-posture-readonly` (1h TTL recommended) |
| `VAULT_CACERT` | recommended | CA bundle for TLS verification |
| `VAULT_SKIP_VERIFY` | dev only | `true` disables TLS verification |
| `VAULT_POSTURE_OUTPUT_DIR` | no | Results directory (default `.tmp/vault-posture/`) |

### How read-only is enforced

1. **Token policy**: [`vault-posture-readonly.hcl`](skills/vault-posture/policies/vault-posture-readonly.hcl) grants `read`/`list` on exactly the endpoints the script reads and denies credential-minting paths. This is the hard boundary.
2. **Code**: `Reader` is the script's only route to Vault and only sends GET (lists use `?list=true`). Status endpoints are allowlisted field by field, so nonces, OTPs and encoded tokens never reach a file.
3. **Skill**: `allowed-tools` pre-approves only the script. For defence in depth, also deny `Bash(vault write:*)`, `Bash(vault delete:*)`, `Bash(vault operator:*)` and `Bash(curl:*)` in your Claude Code `permissions.deny`.

## Develop

Needs [uv](https://docs.astral.sh/uv/), [Task](https://taskfile.dev), Docker (or Podman) with compose, and the `vault` CLI.

```bash
task init                 # uv sync, pre-commit hooks, .env from template
task test                 # unit tests, no Vault needed (coverage gate 90%)
task up seed token        # Community dev server on :8250, seed findings, mint read-only token
task test:integration     # live tests with the read-only token
task skill:run -- audit   # run the script by hand
task down
task test:e2e             # all of the above on a fresh server (ENT=1 for Enterprise on :8260)
```

`compose.yaml` runs throwaway in-memory `vault server -dev` containers: `vault` (Community, default) and `vault-ent` (profile `ent`, needs `VAULT_LICENSE`). `scripts/seed_findings.sh` configures them to trip every live-testable rule.

### Tests

| File | Covers |
| --- | --- |
| `tests/test_checks.py` | Each rule fires on its trigger and stays quiet on its control; every rule is in `rules.md` |
| `tests/test_collect.py` | Coverage classification (denied, absent, Enterprise-only, not applicable, error) and field allowlisting |
| `tests/test_readonly.py` | Through real hvac/requests with the transport patched: only GET is sent, no token or seal secret in output |
| `tests/test_cli.py` | Output files (0600, `.gitignore`), exit codes, setup errors, schema validation |
| `tests/test_policy.py` | The policy grants every path the script reads and nothing beyond read/list |
| `tests/test_integration.py` | `-m integration`: live seeded server, coverage complete with the read-only token, writes denied |
