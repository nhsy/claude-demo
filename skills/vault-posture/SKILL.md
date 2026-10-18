---
name: vault-posture
description: READ-ONLY, observe-only HashiCorp Vault security posture review. Use when the user asks whether Vault is configured safely, about rate-limit or lease-count quotas, whether a root token generation or rekey is in progress, barrier/encryption key age or automatic key rotation, or external plugins in the plugin catalogue. Also use when given vault-posture JSON files to interpret. For cluster health, inventory, policies, entities or client counts use the vault-ops skill instead. Observes and reports only; NEVER makes changes to Vault.
allowed-tools: Bash(uv run --script *vault_posture.py *), Read, Glob
---

# vault-posture (READ-ONLY: observe and report)

> **NEVER make changes.** This skill only observes Vault and reports what it sees. You NEVER create, update, delete, enable, disable, tune, rotate, cancel, seal, unseal, rekey, register or deregister anything in Vault, and you NEVER run a remediation command, not even when the user asks you to in this session. You never mint, renew or revoke tokens. If the user asks for a change, say this skill is observe-only, give them the drafted command and tell them an operator must run it.

Code collects and checks; you interpret. All Vault access goes through the bundled script, which only sends HTTP GET requests (lists are `GET ?list=true`), and the token policy grants only `read`/`list`.

| You DO (observe) | You NEVER do (change) |
| --- | --- |
| Run `vault_posture.py` subcommands: `audit`, `quotas`, `security` | Run `vault` CLI commands, `curl` or any other client against Vault |
| Read the JSON files the script writes | Cancel a root generation or rekey, rotate a key, write a quota, register a plugin |
| Explain findings and their impact | Execute a remediation command, even when asked |
| Draft remediation as text for an operator | Mint, renew, revoke or look up tokens |

## Hard rules

- Only run `uv run --script ${CLAUDE_SKILL_DIR}/scripts/vault_posture.py <subcommand> ...`. Never run any other command against Vault.
- Never read, print or echo `.env`, token files, `VAULT_TOKEN` or any environment variable value. The user provides credentials via the environment before the session.
- Remediation is **drafted as text** and labelled "for an operator to run". Take commands from `references/rules.md`, filling placeholders from the finding. Never invent endpoints or flags; if the catalogue has none, describe the change in words.
- VP-SEC-001 (root token generation in progress) is urgent but may be a planned break-glass ceremony: tell the user to confirm with the key holders before anyone cancels it.

## Subcommands

| Ask | Command | Output (path printed on stdout) |
| --- | --- | --- |
| Posture review / "is Vault configured safely" | `audit [--key-age-days 365]` | `*-posture-*.json` |
| Quotas / noisy clients / lease explosions | `quotas` | `*-quotas-*.json` |
| Root generation or rekey in progress / barrier key / plugins | `security [--key-age-days 365]` | `*-security-*.json` |

Every subcommand also takes `--redact-addr`, `--fail-on <severity>` (exit 3) and `--fail-on-gaps` (exit 2). Results go to `$VAULT_POSTURE_OUTPUT_DIR` if set, else `.tmp/vault-posture/` in the working directory; `--output-dir` overrides both. The script adds a `.gitignore` to a directory it creates, so results are never committed. Never move or copy them elsewhere in the project.

## Setup problems

The script itself is the preflight. Map its failures to setup help and stop; never work around them:

| Symptom | Tell the user |
| --- | --- |
| `uv: command not found` | Install uv (https://docs.astral.sh/uv/getting-started/installation/), then retry. |
| `VAULT_ADDR and VAULT_TOKEN must be set` | Exit Claude, export them in the shell, restart (example below). Never ask them to paste a token into the chat. |
| `token rejected (403 on auth/token/lookup-self)` / `token validation failed` | The token is expired or lacks the policy; mint a new one with the command below. |
| `is sealed` / `not initialized` / `DR secondary` | This node can't serve authenticated reads. Unsealing is an operator task; never run or offer it. For DR, run against the primary. |
| `cannot reach Vault ... SSLError` | Set `VAULT_CACERT=/path/to/ca.pem`, or for a dev server only `VAULT_SKIP_VERIFY=true`. |
| `cannot reach Vault ... ConnectionError` | Vault is not reachable (VPN, address, port). Offer file mode: interpret vault-posture JSON produced elsewhere. |

```bash
export VAULT_ADDR=https://vault.example.com:8200 VAULT_CACERT=/path/to/ca.pem
vault policy write vault-posture-readonly <this skill>/policies/vault-posture-readonly.hcl   # once, by an admin
export VAULT_TOKEN="$(vault token create -policy=vault-posture-readonly -no-default-policy -orphan -ttl=1h -field=token)"
claude
```

## Workflow

1. **Files first.** If the user points at existing vault-posture JSON files, use them and skip to step 3. For "the last review", look for the newest `*-posture-*.json` in the output directory.
2. **Run** the matching subcommand. On exit 1, report the stderr message (see Setup problems) and stop.
3. **Read** the JSON file in full with the Read tool (they are small).
4. **Coverage first.** If `coverage.complete` is false, open with the `denied` or `error` scopes and say the results are partial; a denied scope means the token lacks `vault-posture-readonly`. `unsupported` (Enterprise-only on Community) and `not_applicable` (e.g. recovery keys on a Shamir seal) are complete answers: mention them under "Not covered", not as gaps.
5. **Explain.** Rank findings using the Ranking section of `references/rules.md`. For each: what it is, why it matters on this cluster, the evidence, and a drafted remediation command for an operator to run.
6. **Finish** with a summary table (rule, severity, count), the path of the file written, and one line saying the review was read-only and nothing in Vault was changed.

## Reading the files

- `run`: cluster, address, Vault version and `edition`. On `community`, VP-QUOTA-002 is never judged.
- `coverage.scopes[]`: `{scope, status}` per read; statuses `ok`, `absent` (none defined), `denied`, `unsupported`, `not_applicable`, `error`.
- `findings[]`: `rule_id`, `severity`, `object`, `detail`, `evidence`, ranked high first. `fingerprint` is stable across runs.
- `data.quotas`: the quota definitions and quota config. `data.security`: `started/progress/required` for root generation and rekey (nonces, OTPs and encoded tokens are never collected), barrier key `term`/`install_time`, rotation config, external plugins.

## Scope

This version reads root-namespace endpoints only. Not yet covered (say so if asked): auth role bindings (JWT/OIDC, Kubernetes, AppRole), PKI issuer expiry, quotas created inside child namespaces, and "who can reach this path" analysis. For cluster health, inventory, ACL/Sentinel policies, entities and client counts, use the **vault-ops** skill.
