# Repo Steward Security Boundary v0.1

**Status:** IMPLEMENTED BOUNDARY / WRITE TRANSPORT ABSENT

Repo Steward exists to reduce repository drift without creating a new autonomous administrator.

## Closed-door rule

Repository mutation is closed by default. No autonomous agent, bot identity, service account, coding agent, scheduled job, or advisory model may independently cross the repository-write boundary.

Every future repository write requires explicit human Operator authorization. Advisory assistance from approved OpenAI, Perplexity, or Claude lanes may be used to inspect, recommend, prepare, or independently review a proposed action, but advisory participation does not create authority and cannot substitute for the Operator.

## v0.1 enforcement

- `GitHubReader` exposes GET only.
- `RepoAdmin.execute()` always fails.
- no GitHub write credential is required or consumed by Repo Steward v0.1;
- all administrative objects are proposals, not executions;
- all proposed mutation actions carry `requires_operator_approval=true`;
- merge, direct default-branch write, permission expansion, ruleset/branch-protection mutation, credential changes, deployment enablement, destructive actions, and authority-affecting changes remain closed.

## Future write adapter requirements

A future write adapter is non-conformant unless all of the following are true:

1. the exact repository and target state are verified;
2. the requested action is allowed by the repository policy manifest;
3. the human Operator authorization is explicit, current, scoped, and independently verifiable;
4. the action cannot write directly to the default branch unless separately and explicitly authorized by a stronger policy;
5. the action emits an immutable audit record;
6. the resulting head is re-checked and independently reviewed where policy requires it;
7. the component that prepared the repair cannot treat its own output as clearance;
8. failure to establish identity, authorization, target, or current state results in no mutation.

## Threats explicitly addressed

- bot-only repository administration;
- agent self-expansion through permissions or rulesets;
- stale or recycled authorization;
- ancestor-SHA review reuse after a head changes;
- self-certifying repairs;
- direct-main bypass;
- CI-as-authority confusion;
- advisory-model output being mistaken for human approval;
- service-account privilege becoming standing administrative authority.

## Authority statement

Repo Steward is a control-plane observer and proposal coordinator. The Operator remains the required human authorizing party for repository administration. Nothing in Repo Steward creates constitutional, deployment, merge, or permission authority.
