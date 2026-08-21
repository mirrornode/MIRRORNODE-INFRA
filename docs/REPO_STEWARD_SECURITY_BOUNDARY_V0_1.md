# Repo Steward Security Boundary v0.1

**Status:** IMPLEMENTED BOUNDARY / WRITE TRANSPORT ABSENT

Repo Steward exists to reduce repository drift without creating a new autonomous administrator.

## Closed-door rule

Repository mutation is closed by default. No autonomous agent, bot identity, service account, coding agent, scheduled job, or advisory model may independently cross the repository-write boundary.

Every future Repo Steward repository write requires **dual control**: explicit human Operator authorization **plus at least one independent attestation from an approved OpenAI, Perplexity, or Claude advisory lane**. The advisory lane does not become an authorizer; it is the required second review/witness side of the control. Neither side alone is sufficient inside the governed Repo Steward write path.

## Mutation eligibility invariant

> **A Repo Steward mutation is eligible only when the exact proposed state is authorized by the Operator, independently attested by an approved advisory lane, review-valid at the current head, CI-valid, and enforceable through GitHub's active platform protections; otherwise it must HOLD or FAIL.**

Eligibility is not execution. It means all preconditions required to consider a mutation have been observed. The actual mutation remains separately gated and auditable.

## v0.1 enforcement

- `GitHubReader` exposes GET only.
- `RepoAdmin.execute()` always fails.
- no GitHub write credential is required or consumed by Repo Steward v0.1;
- all administrative objects are proposals, not executions;
- every proposed mutation carries `requires_operator_approval=true` and `requires_advisory_attestation=true`;
- approved advisory lanes are explicitly enumerated;
- merge, direct default-branch write, permission expansion, ruleset/branch-protection mutation, credential changes, deployment enablement, destructive actions, and authority-affecting changes remain closed;
- a generic branch `protected` flag is insufficient for PASS when effective required controls cannot be inspected;
- absent or contradictory required protections produce FAIL; incompletely observable protection produces HOLD.

## Future write adapter requirements

A future write adapter is non-conformant unless all of the following are true:

1. the exact repository and target state are verified;
2. the requested action is allowed by the repository policy manifest;
3. human Operator authorization is explicit, current, scoped, and independently verifiable;
4. at least one approved advisory attestation is independently bound to the same proposed action and target state;
5. failure to verify either side of the dual-control pair results in no mutation;
6. active GitHub platform controls enforce the required PR/review/check boundary;
7. the action cannot write directly to the default branch unless separately authorized under an equally strong or stronger policy;
8. the action emits an immutable audit record;
9. the resulting head is re-checked and independently reviewed where policy requires it;
10. the component that prepared the repair cannot treat its own output as clearance.

## MOPCON repository-administration ledger

When projected into MOPCON, a Repo Steward Work Card should bind at minimum:

- repository, branch, PR, intended target SHA, and proposed post-state;
- Operator authorization type, scope, expiry, and revocation state;
- advisory attestation identity, lane, basis, target SHA, and timestamp;
- each participating lane's immutable position, including objection or uncertainty;
- CI receipts and exact-head review state;
- effective platform-policy evaluation result;
- execution receipt, merge actor, resulting SHA, verification result, and residuals.

MOPCON is the collaboration and evidence surface. It displays and organizes these records; it does not create their authority.

## Threats explicitly addressed

- bot-only repository administration;
- Operator-only control-plane mutation without a second independent advisory witness;
- agent self-expansion through permissions or rulesets;
- stale or recycled authorization or attestation;
- ancestor-SHA review reuse after a head changes;
- self-certifying repairs;
- direct-main bypass;
- CI-as-authority confusion;
- advisory-model output being mistaken for human approval;
- service-account privilege becoming standing administrative authority;
- treating `protected: true` as proof of a fully compliant effective policy.

## Platform enforcement note

This contract closes the Repo Steward control plane. GitHub account-level enforcement still depends on repository rulesets, branch protection, credentials, and account permissions. Until those controls enforce the same dual-control policy directly, any platform capability that could bypass Repo Steward must be treated as a separate residual risk rather than assumed closed by this document.

## Authority statement

Repo Steward is a control-plane observer and proposal coordinator. The Operator remains the required human authorizing party; an approved advisory attestation is a mandatory second control, not a transfer of authority. Nothing in Repo Steward creates constitutional, deployment, merge, or permission authority.
