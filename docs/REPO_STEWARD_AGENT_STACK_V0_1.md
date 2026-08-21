# Repo Steward Agent Stack v0.1

**Status:** IMPLEMENTED / PROPOSAL-ONLY ADMINISTRATION

Repo Steward is MIRRORNODE's repository-integrity and repository-administration control-plane presence. It observes repository state, evaluates policy, produces evidence-bound findings, and prepares bounded administrative proposals. It does not create authority and does not approve its own repairs.

## Stack

| Presence | Function | Authority boundary |
|---|---|---|
| **REPO STEWARD** | Integrating coordinator for repository health and administrative proposals | Coordinates only; cannot merge, expand permission, or certify its own repair |
| **SURVEYOR** | Repository census, stack detection, workflow/config inventory | Read-only observation |
| **SENTINEL** | Code/check/CI integrity evaluation and PASS/HOLD/FAIL/UNKNOWN classification | Read-only evaluation; FAIL/HOLD may block recommendation but cannot create merge authority |
| **NOTARY** | Immutable-head, review-binding, provenance, and evidence packet verification | Evidence binding only; cannot substitute review authority |
| **CUSTODIAN** | Prepares workflow/template/config/ruleset repair proposals | Proposal-only in v0.1; no GitHub mutation transport |
| **WARDEN** | Permission, branch/ruleset, secret-risk and self-expansion boundary review | Defensive veto/recommendation; no unilateral permission changes |

## Processing sequence

`SURVEYOR -> SENTINEL -> NOTARY -> WARDEN -> REPO STEWARD -> CUSTODIAN proposal -> Operator gate`

A repository report is valid only for the observed target state. If a PR head moves, exact-head review evidence and applicable CI evidence must be recomputed.

## Verdict vocabulary

- `PASS` — required observable conditions are satisfied for the checked scope.
- `HOLD` — completion depends on a pending or absent required condition.
- `FAIL` — a required invariant is violated.
- `UNKNOWN` — evidence is insufficient to classify safely.

No verdict is equivalent to approval or merge authority.

## Administrative classes

### Read-only / automatic

Repository inventory, workflow inventory, default-head resolution, CI inspection, review-binding inspection, thread/evidence inspection, policy comparison, and report generation.

### Proposal-producing

Missing workflow/template proposals, bounded branch/PR plans, review requests, dependency/config repair plans, and repository-policy remediation packets.

### Operator-gated

Merge, ruleset or branch-protection mutation, permission expansion, credential changes, deployment enablement, destructive repository actions, and any change that could alter constitutional or production authority.

## Anti-self-certification invariant

The component that detects or repairs a defect cannot treat its own output as sufficient clearance. Repairs require independent checks/review according to the owning repository policy, and the Operator remains the final merge authority.

## Implementation

- `repo_steward/checker.py` — GET-only GitHub evidence collection and normalized repository reports.
- `repo_steward/admin.py` — mutation proposal model with execution intentionally absent.
- `repo_steward/cli.py` — machine-readable estate check entrypoint.
- `manifests/repo-steward-policy.json` — active repository policy and authority boundary.

## Future phases

Phase 1 may add a write adapter limited to branch creation, file proposals, PR opening, and review requests. Each mutation must be policy-allowed, auditable, and incapable of writing directly to protected/default branches. Merge/ruleset/permission operations remain explicit Operator actions.
