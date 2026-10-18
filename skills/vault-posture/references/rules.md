# vault-posture rule catalogue

Every finding carries a `rule_id` from this table. Remediation commands are **drafted for an operator to run**; the skill never runs them. Fill `<placeholders>` from the finding's `object` and `evidence`. When a row says "No catalogue command", describe the change in words and tell the operator to confirm the exact command in the Vault documentation.

## Quotas

| Rule | Severity | Meaning | Remediation (for an operator to run) | Caveats |
| --- | --- | --- | --- | --- |
| VP-QUOTA-001 | medium | No rate-limit quota exists anywhere in the cluster. One noisy or compromised client can saturate Vault for everyone. | `vault write sys/quotas/rate-limit/global rate=<requests-per-second>` (size from current peak traffic plus headroom) | Set the rate from observed load (`vault.core.handle_request` metrics), not a guess: too low a global rate causes an outage. Health, seal-status and unseal paths are exempt by default. |
| VP-QUOTA-002 | medium | No lease-count quota exists (Enterprise). Nothing stops a client or mount from creating leases without bound, which is how lease explosions start. | `vault write sys/quotas/lease-count/global max_leases=<limit>` | Enterprise only: on Community the scope is `unsupported` and this rule is not judged. Count current leases per mount first so the limit doesn't block normal issuance. |
| VP-QUOTA-003 | low | Quotas of this type exist, but every one is scoped to a path, namespace or role (`evidence.paths`). Traffic outside those paths has no ceiling. | `vault write sys/quotas/<quota_type>/global <rate=…\|max_leases=…>` alongside the scoped ones | Scoped quotas are good practice; this only asks for a cluster-wide backstop as well. |
| VP-QUOTA-004 | info | Rate-limit quotas exist, but requests they reject are not written to the audit log. A client being throttled is invisible to the SOC. | `vault write sys/quotas/config enable_rate_limit_audit_logging=true` | Adds audit volume during an incident, which is usually when it's wanted. |

## Security

| Rule | Severity | Meaning | Remediation (for an operator to run) | Caveats |
| --- | --- | --- | --- | --- |
| VP-SEC-001 | high | A root token generation (`sys/generate-root/attempt`) or recovery token generation is in progress (`evidence.progress` of `evidence.required` key shares). Anyone completing it gets a root or recovery token. | If nobody on the operator team started it: `vault operator generate-root -cancel` (recovery: `vault operator generate-root -generate-recovery-token -cancel`), then treat it as an incident and review the audit log for who called `sys/generate-root/attempt`. | A planned break-glass ceremony also shows up here: confirm with the key holders before cancelling. |
| VP-SEC-002 | medium | A rekey of the unseal keys (`sys/rekey/init`) or recovery keys is in progress. | If not planned: `vault operator rekey -cancel` (recovery keys: `vault operator rekey -target=recovery -cancel`). | A stale, forgotten rekey blocks the next planned one; a live one is an expected part of key-holder rotation. |
| VP-SEC-003 | low | The barrier encryption key (`evidence.term`) was installed more than `evidence.threshold_days` days ago (`evidence.age_days`). | `vault operator rotate` | Online and non-disruptive. Rotation is cheap; also set an interval (VP-SEC-004) so it doesn't need remembering. |
| VP-SEC-004 | info | Automatic barrier key rotation has no time interval (`evidence.interval_seconds` 0) or is disabled; the key rotates only after `evidence.max_operations` encryptions or by hand. | `vault write sys/rotate/config enabled=true interval=<e.g. 2160h>` | The operation-count trigger alone almost never fires on a typical cluster. |

## Plugins

| Rule | Severity | Meaning | Remediation (for an operator to run) | Caveats |
| --- | --- | --- | --- | --- |
| VP-PLUG-001 | low | An external plugin (`evidence.plugin_type`/`evidence.plugin_name`) is registered without a version, so which binary runs can't be tracked or pinned across upgrades. | `vault plugin register -sha256=<sha> -version=<semver> <type> <name>`, then `vault plugin reload -plugin=<name>` | Registering a versioned entry doesn't switch mounts to it: each mount pins its plugin version (`vault secrets tune -plugin-version=…`). |
| VP-PLUG-002 | info | External (non-builtin) plugins are registered (`evidence.plugins`). Each one runs third-party code inside Vault's trust boundary. | No catalogue command: review each plugin's source, owner and update cadence; deregister unused ones with `vault plugin deregister -version=<v> <type> <name>` after confirming no mount uses them. | Inventory for supply-chain review, not a defect. |

## Ranking

When reporting, group in this order:

1. VP-SEC-001 (possible unauthorised root), VP-SEC-002.
2. VP-QUOTA-001/002 (no protection from noisy clients or lease explosions).
3. VP-QUOTA-003, VP-SEC-003, VP-PLUG-001.
4. Info: VP-QUOTA-004, VP-SEC-004, VP-PLUG-002.
