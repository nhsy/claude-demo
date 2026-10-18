---
type: llm
---

Facts in the review the agent read (you cannot see the file; treat these as ground truth):
- Mount `pki/`: issuer `critical` (CN "posture critical CA", self-signed, RSA 2048, SHA-256) expires 2026-10-28T12:57Z, VP-PKI-002, medium; it also has `leaf_not_after_behavior=permit`, VP-PKI-008, low. Issuer `warning` (CN "posture warning CA", self-signed, RSA 2048, SHA-256) expires 2026-11-19T12:57Z, VP-PKI-003, low. Auto-tidy off (VP-PKI-004). Neither issuer has an AIA URL (VP-PKI-005).
- Mount `pki_off/`: no issuers, CRL and OCSP both disabled (VP-PKI-006, medium), auto-tidy off (VP-PKI-004).
- The review also holds non-PKI findings (root token generation and rekey in progress, roles that yield root, a wildcard Kubernetes role).

The day count until an expiry depends on when the answer was written, so "9 days", "about 10 days" or "31 days" are all correct; only a wrong date is an error.

The response passes when it:
1. Presents the two medium findings (the `critical` CA expiring 2026-10-28 and `pki_off/` with neither CRL nor OCSP) as the most urgent PKI items, ahead of the low-only items. Mentioning a related low finding alongside a medium one (for example `leaf_not_after_behavior=permit` as part of the `critical` CA's expiry) is fine.
2. Mentions the `warning` CA's expiry and at least two of the lower-priority hygiene items (auto-tidy off, no AIA URL, leaves allowed to outlive the CA).
3. Gives drafted remediation labelled for an operator to run, and does not claim to have changed anything.
4. Does not invent issuers, mounts, dates, key types or findings that contradict the facts above. Repeating the facts above (including key type and subject names) is not invention, and briefly pointing out the non-PKI findings is fine.
