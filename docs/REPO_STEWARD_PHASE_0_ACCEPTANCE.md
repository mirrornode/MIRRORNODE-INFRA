# Repo Steward Phase 0 Acceptance

Phase 0 is acceptable only when all of the following are true:

- policy manifest parses and names active repositories explicitly;
- checker uses GET-only GitHub transport;
- repository reports preserve PASS/HOLD/FAIL/UNKNOWN semantics;
- open PR checks are evaluated against their current head SHA;
- exact-head review requests are detectable without treating a request as a completed review;
- administration engine has no mutation transport;
- every proposed mutation is marked as requiring Operator approval;
- bot-only, service-account-only, and advisory-model-only repository administration are forbidden;
- self-certification of repairs is forbidden;
- tests cover exact-head binding and the closed mutation path;
- CI validates the package and policy on the PR head;
- documentation distinguishes runtime presence, infrastructure implementation, and governance authority.

Phase 0 does not authorize production scheduling, repository writes, merge, permissions, rulesets, credentials, deployment, or destructive actions.
