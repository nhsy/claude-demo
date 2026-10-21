---
name: vault-posture
description: READ-ONLY, observe-only HashiCorp Vault security posture review. ALWAYS load this skill before answering any question about a vault-posture review or its results ("my last posture review", "the last review", files in .tmp/vault-posture/ or named *-posture-*, *-roles-*, *-pki-*, *-quotas-*, *-security-*, *-diff-*, access-*.json), even when the file could be read directly. Use when the user asks whether Vault is configured safely; about auth role bindings (JWT/OIDC or GitHub Actions roles, Kubernetes service-account roles, AWS IAM or EC2 roles, GCP IAM or GCE roles, Azure managed identity roles, TLS certificate (cert) roles, AppRole, token roles, roles that yield root); PKI CA or issuer expiry, weak CA keys, CRL/OCSP/AIA or tidy settings; rate-limit or lease-count quotas; whether a root token generation or rekey is in progress; barrier key age or rotation; external plugins; or which ACL policies grant a capability on a path ("who can write secret/x", "why am I denied"). Also use when given vault-posture JSON files to interpret or compare ("what changed since my last review"). For cluster health, inventory, entities or client counts use the vault-ops skill instead. Observes and reports only; NEVER makes changes to Vault.
allowed-tools: Bash(uv run --script *vault_posture.py *), Read, Glob
---

# vault-posture (READ-ONLY: observe and report)

> **NEVER make changes.** This skill only observes Vault and reports what it sees. You NEVER create, update, delete, enable, disable, tune, rotate, cancel, seal, unseal, rekey, register, deregister or patch anything in Vault, and you NEVER run a remediation command, not even when the user asks you to in this session. You never mint, renew or revoke tokens. If the user asks for a change, say this skill is observe-only, give them the drafted command and tell them an operator must run it.

Code collects and checks; you interpret. All Vault access goes through the bundled script, which only sends HTTP GET requests (lists are `GET ?list=true`), and the token policies grant only `read`/`list`.

| You DO (observe) | You NEVER do (change) |
| --- | --- |
| Run `vault_posture.py` subcommands: `audit`, `quotas`, `security`, `roles`, `pki`, `access`, `diff`, `report` | Run `vault` CLI commands, `curl` or any other client against Vault |
| Read the JSON files the script writes | Cancel a root generation or rekey, rotate a key, write a role, quota or issuer, register a plugin |
| Explain findings and their impact | Execute a remediation command, even when asked |
| Draft remediation as text for an operator | Mint, renew, revoke or look up tokens |

## Every answer about findings

Whether you just ran the script or are reading an existing file, each answer that reports findings must:

1. **Read `references/rules.md` first** (with the Read tool, from this skill's directory). It holds each rule's meaning, its ranking and the remediation command; don't answer from the JSON alone.
2. **Rank** by the Ranking section of `references/rules.md`, high severity first.
3. **Draft a fix for every finding you raise**: the command from `references/rules.md` with its placeholders filled from the finding, in a code block headed **"For an operator to run"**. The catalogue's commands are the checked ones: use them as given, without hedging about whether a flag exists. Where the catalogue has no command, describe the change in words.
4. **Say what was not covered**: `unsupported` and `not_applicable` scopes (for example Enterprise-only lease-count quotas on Community, recovery keys on a Shamir seal) go under "Not covered", never as problems. `denied` or `error` scopes mean the results are partial: open with them.
5. **End** with one line saying the review was read-only and nothing in Vault was changed.

## Hard rules

- Only run `uv run --script ${CLAUDE_SKILL_DIR}/scripts/vault_posture.py <subcommand> ...`. Never run any other command against Vault.
- Never read, print or echo `.env`, token files, `VAULT_TOKEN` or any environment variable value. The user provides credentials via the environment before the session.
- **Never reveal or help retrieve credentials**: no tokens, role IDs, secret IDs, secret ID accessors, unseal or recovery keys, OTPs or private keys, and no commands that would fetch or mint them (for example `vault read …/role-id`, `vault write …/secret-id`, `vault token create`, `vault token lookup`, `vault unwrap`, `cat .env`), not even "to run in your own shell". The review never collects role IDs or secret IDs, so they are not in its files: say so, decline, and carry on with the findings by role name.
- When you decline a change or a credential request, the reason is that this skill is **observe-only by design**, not that a tool is unavailable in this session.
- Remediation is **drafted as text** and labelled "for an operator to run". Take commands from `references/rules.md`, filling placeholders from the finding (add `-namespace=<ns>` outside the root namespace). Never invent endpoints or flags; if the catalogue has none, describe the change in words.
- VP-SEC-001 (root token generation in progress) is urgent but may be a planned break-glass ceremony: tell the user to confirm with the key holders, and check the audit log for who started it, before anyone cancels it.
- Output files hold role names, mount paths and CA names. Never copy them elsewhere in the project.

## Subcommands

| Ask | Command | Output (path printed on stdout) |
| --- | --- | --- |
| Posture review / "is Vault configured safely" | `audit [--namespace ns]` | `*-posture-*.json` |
| Auth role bindings (JWT/OIDC, Kubernetes, AWS, GCP, Azure, cert, AppRole, token roles) | `roles [--namespace ns]` | `*-roles-*.json` |
| CA / issuer expiry, PKI hygiene | `pki [--namespace ns] [--pki-critical-days 30] [--pki-warning-days 90]` | `*-pki-*.json` |
| Quotas / noisy clients / lease explosions | `quotas` | `*-quotas-*.json` |
| Root generation or rekey in progress / barrier key / plugins | `security [--key-age-days 365]` | `*-security-*.json` |
| "Who can do X on path Y?" / "why is this denied?" from policy files | `access --policy <file-or-dir> --path <path> [--path ...] [--capability update]` | `access-*.json` |
| "What changed since the last review?" | `diff <older.json> <newer.json>` | `*-diff-*.json` |
| "Write up / give me a report of the review" (Markdown) | `report <result.json> [...] [--diff <diff.json>]` | `*-report-*.md` |

- Live subcommands take `--redact-addr`, `--fail-on <severity>` (exit 3) and `--fail-on-gaps` (exit 2). `roles`, `pki` and `audit` walk the start namespace (default `VAULT_NAMESPACE` or root) and every child namespace, five levels deep.
- `access` is **offline**: it needs no Vault, token or network. It evaluates ACL policy files (`.hcl` or `.json`, e.g. from the user's Terraform or policy repo) the way Vault does: an exact path beats a wildcard, the highest-priority wildcard decides, identical paths merge, deny wins. Use it for "which policy grants this" and "why is this denied" questions. It cannot see policies that only exist in Vault, nor identity-group or Sentinel effects: say so.
- `diff` is **offline** too: it compares two result files of the same kind (for example two `*-posture-*.json`) by fingerprint. Pass the older file first.
- `report` is **offline**: it turns one or more result files from one cluster (any mix of `audit`, `roles`, `pki`, `quotas`, `security`; repeated findings appear once) into a Markdown report, with the commands from `references/rules.md` filled in. `--diff` adds the changes since an earlier run. It writes no PDF.
- Results go to `$VAULT_POSTURE_OUTPUT_DIR` if set, else `.tmp/vault-posture/` in the working directory; `--output-dir` overrides both. The script adds a `.gitignore` to a directory it creates.

## Setup problems

The script itself is the preflight. Map its failures to setup help and stop; never work around them:

| Symptom | Tell the user |
| --- | --- |
| `uv: command not found` | Install uv (https://docs.astral.sh/uv/getting-started/installation/), then retry. |
| `VAULT_ADDR and VAULT_TOKEN must be set` | Exit Claude, export them in the shell, restart (example below). Never ask them to paste a token into the chat. `access` needs neither. |
| `token rejected (403 on auth/token/lookup-self)` / `token validation failed` | The token is expired or lacks the policy; mint a new one with the command below. |
| `is sealed` / `not initialized` / `DR secondary` | This node can't serve authenticated reads. Unsealing is an operator task; never run or offer it. For DR, run against the primary. |
| `cannot reach Vault ... SSLError` | Set `VAULT_CACERT=/path/to/ca.pem`, or for a dev server only `VAULT_SKIP_VERIFY=true`. |
| `cannot reach Vault ... ConnectionError` | Vault is not reachable (VPN, address, port). Offer file mode: interpret vault-posture JSON produced elsewhere, or `access` on policy files. |
| Coverage denies scope `mounts` (PKI) | The token lacks the read-only PKI add-on: an admin loads `policies/vault-posture-pki-reader.hcl` and adds `-policy=vault-posture-pki-reader` to the token. No VP-PKI rule was judged. |

```bash
export VAULT_ADDR=https://vault.example.com:8200 VAULT_CACERT=/path/to/ca.pem
# once, by an admin, in the root namespace:
vault policy write vault-posture-readonly <this skill>/policies/vault-posture-readonly.hcl
vault policy write vault-posture-pki-reader <this skill>/policies/vault-posture-pki-reader.hcl
export VAULT_TOKEN="$(vault token create -policy=vault-posture-readonly -policy=vault-posture-pki-reader -no-default-policy -orphan -ttl=1h -field=token)"
claude
```

## Workflow

1. **Files first.** If the user points at existing vault-posture JSON files, use them and skip to step 3. For "the last review", look for the newest `*-posture-*.json` (or the subcommand's file) in the output directory.
2. **Run** the matching subcommand. On exit 1, report the stderr message (see Setup problems) and stop.
3. **Compare.** If the output directory holds an earlier file of the same kind for the same cluster (the `{cluster}-{kind}-` prefix), or the user asks what changed, run `diff <older> <newer>` and read its file too. Report new and resolved findings first, then the rest.
4. **Read** the JSON file and `references/rules.md` with the Read tool. For a large estate, read `summary` and `findings` first; `data` holds the raw (allowlisted) inventory.
5. **Coverage first.** If `coverage.complete` is false, open with the `denied` or `error` scopes (and their namespaces) and say the results are partial. `unsupported` (Enterprise-only on Community) and `not_applicable` (e.g. recovery keys on a Shamir seal) are complete answers: list them under "Not covered", not as gaps.
6. **Explain**, following "Every answer about findings" above. For each finding: what it is, why it matters here, the namespace and object, the evidence, and its "For an operator to run" command. Group repeated rules (e.g. ten audience-only JWT roles) with a count and up to three examples.
7. **Finish** with a summary table (rule, severity, count), the path of the file read or written, "Not covered", and the read-only closing line.
8. **Asked for a report or write-up?** Run `report` on the result files (and the `diff` file, if one exists) instead of composing a report by hand, then give the user its path and the top findings in a few lines.

## Reading the files

- `run`: cluster, address, Vault version, `edition` and `start_namespace`. On `community`, VP-QUOTA-002 is never judged and only the root namespace exists.
- `coverage.scopes[]`: `{namespace, scope, status}` per read; statuses `ok`, `absent` (none defined), `denied`, `unsupported`, `not_applicable`, `error`.
- `findings[]`: `rule_id`, `severity`, `namespace`, `object`, `detail`, `evidence`, ranked high first. `fingerprint` is stable across runs, so two files can be compared by fingerprint.
- `data.roles.roles[]`: each role's allowlisted binding fields (never role IDs or secret IDs). `data.pki`: per mount `auto_tidy`/`crl`/`urls`, per issuer the parsed certificate facts (`not_after`, key type and size, signature hash; never the PEM). `data.security`: `started/progress/required` only for root generation and rekey.
- `*-diff-*.json`: `runs.old` and `runs.new` (each file's `run` block), `warnings[]` (read these first: a different cluster, namespace or edition, incomplete coverage in either run, or files in the wrong order), `summary` (`new` and `resolved` counted by severity and rule, `unchanged` and `rotated` counts) and `findings.new`, `findings.resolved`, `findings.unchanged`, `findings.rotated`. A `rotated` pair is the same PKI rule on a CA that was re-issued under the same name: report it as still open, not as fixed. With incomplete coverage, a resolved finding may just be unread: say so.
- `access-*.json`: `queries[]` with `combined` (what a token holding all the given policies gets: `capabilities`, `decision` = allow / explicit_deny / implicit_deny, `matched_path`, `policies`), `per_policy` (each policy alone) and, with `--capability`, `granted_by`. `policies.unparsed` lists files that could not be read.

## Scope

Mount paths are covered up to three segments deep (`auth/k8s/prod/eu/`, `ca/int/`). The policies don't reach roles or issuers on deeper mounts, so those reads show up as `denied` scopes (`roles.<mount>`, `pki.<mount>issuers`); report them as not judged and don't suggest widening the token.

Not covered (say so if asked): auth methods other than JWT/OIDC, Kubernetes, AWS, GCP, Azure, TLS certificate, AppRole and token roles; the AWS, GCP and Azure secrets engines; Azure Key Vault seals; the cert auth trusted CA itself (expiry, key strength); quotas created inside child namespaces; ACL policies stored only in Vault (use the vault-ops `policies` subcommand); Sentinel. For cluster health, inventory, ACL/Sentinel policy hygiene, entities and client counts, use the **vault-ops** skill.
