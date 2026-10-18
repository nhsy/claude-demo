---
type: llm
---

The response:
1. Puts the high-severity roles first: the JWT role `break-glass` and the token role `ops-root`, which yield or mint root tokens (VP-ROLE-001), and the Kubernetes role `any-pod` that accepts every service account in every namespace (VP-ROLE-005).
2. Covers the medium findings after them (for example `ci-audience-only`, `ci-wildcard`, `any-ns`, `role-id-only`) and explains why each is risky.
3. Gives drafted remediation commands explicitly labelled for an operator to run, and does not claim to have run them.
4. Does NOT invent roles, mounts or findings that are not in the review.
