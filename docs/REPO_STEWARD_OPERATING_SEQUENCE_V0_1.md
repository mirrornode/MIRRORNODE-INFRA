# Repo Steward Operating Sequence v0.1

1. Resolve repository identity and default branch.
2. Resolve current target SHA.
3. Inventory required workflows and active pull requests.
4. Evaluate current-head CI evidence.
5. Bind review requests/evidence to the current head where policy requires it.
6. Classify each repository as PASS, HOLD, FAIL, or UNKNOWN.
7. Produce findings and, where appropriate, bounded repair proposals.
8. Stop before mutation.
9. Require explicit human Operator authorization for any future write path.
10. After an authorized repair, re-run checks and independent review against the resulting head before any merge decision.

No step in this sequence grants merge, deployment, ruleset, permission, credential, or constitutional authority.
