# Repo Steward Phase 0 Acceptance

Phase 0 is acceptable only when all of the following are true:

- policy manifest parses and names active repositories explicitly;
- checker uses GET-only GitHub transport;
- repository reports preserve PASS/HOLD/FAIL/UNKNOWN semantics;
- open PR checks are evaluated against their current head SHA;
- exact-head review requests are authenticated and kept distinct from completed review evidence;
- configured required workflows have successful completed runs on the exact PR head;
- protection checks fail closed on privileged bypasses, missing required check identities, and unobservable destructive controls;
- administration engine has no mutation transport;
- every proposed mutation is marked as requiring explicit human Operator authorization;
- every proposed mutation is marked as requiring at least one independent approved advisory attestation bound to the same target/action;
- Operator-only mutation is forbidden;
- advisory-only, bot-only, service-account-only, and coding-agent-only repository administration are forbidden;
- self-certification of repairs is forbidden;
- tests cover exact-head binding, required-workflow identity, reviewer independence, protection bypasses, non-PASS CLI behavior, and the closed mutation path;
- CI validates the package and policy on the PR head;
- documentation distinguishes runtime presence, infrastructure implementation, governance authority, and platform enforcement.

Phase 0 does not authorize production scheduling, repository writes, merge, permissions, rulesets, credentials, deployment, or destructive actions. Platform protections remain a separate prerequisite and may not be inferred from application-level dual-control documentation.
