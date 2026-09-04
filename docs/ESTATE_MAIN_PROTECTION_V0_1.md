# MIRRORNODE Estate Main Protection v0.1

## Status

**PROPOSED / ENFORCEMENT TOOLING INCLUDED / PLATFORM MUTATION REQUIRES ADMIN TOKEN**

## Purpose

Define one reproducible minimum protection contract for MIRRORNODE repositories whose default branch carries governance, production, control-plane, runtime, continuity, or commercial authority.

This contract exists because repository policy must be mechanically enforced rather than inferred from human or agent discipline.

## Required default-branch invariants

For each repository in `manifests/estate-main-protection.v0.1.json`:

- pull request required before merge;
- multi-operator repositories require at least one approving review;
- multi-operator repositories dismiss stale approvals when the head changes and require approval after the most recent push;
- repositories explicitly listed in `single_operator_repositories` may use zero required human approvals and no last-push approval requirement;
- all review conversations resolved before merge;
- branch deletion prohibited;
- non-fast-forward updates prohibited;
- linear history required;
- squash is the allowed merge method;
- no bypass actor is introduced by this contract.

Existing repository-specific required status checks and other rules must be preserved. This contract must not replace or weaken stronger local policy.

## Single-operator exception

`mirrornode/MIRRORNODE-INFRA` is explicitly designated as a single-operator repository. Its human-approval floor is zero because no independent repository collaborator is authorized. This exception does not create a bypass actor and does not weaken the required exact-head `validate` check, review-thread resolution, deletion protection, non-fast-forward protection, linear history, or squash-only merge policy.

The estate-wide default remains one approving review with last-push approval. The exception is repository-specific and cannot lower stronger protection already present on any repository.

## Exact-head consequence

Any push that changes the pull-request head invalidates predecessor-head evidence. Where human approval is required, predecessor-head approval evidence is invalidated as well. A successor head must satisfy its own checks and applicable review requirements. No correction, reconciliation, or other subject-changing update may inherit ancestor-head clearance.

## Tool

`scripts/estate_protection.py` is read-only by default.

Audit:

```bash
GH_TOKEN=... python3 scripts/estate_protection.py
```

Apply and verify:

```bash
GH_TOKEN=... python3 scripts/estate_protection.py --apply
```

The token must have repository administration permission for every target repository. The tool first evaluates the complete readable effective default-branch protection surface, including applicable active rulesets and relevant classic branch protection. When `--apply` is explicitly authorized, it discovers the named baseline ruleset, preserves its non-PR rules, and monotonically strengthens only the `pull_request` parameters. If the named ruleset is absent, it may create the minimal baseline declared by the manifest. After any write, it re-reads the complete effective protection surface and verifies the manifest invariants fail-closed.

`required_status_checks.mode = preserve_existing_nonempty` does not authorize the tool to invent a required-check identity. If no effective required status check is readable, audit remains HOLD and `--apply` does not manufacture one.

## Failure semantics

- Missing token: fail closed.
- API read/write failure: fail closed.
- Post-write verification mismatch: fail closed.
- Repository not listed in the manifest: out of scope; no mutation.
- Existing stronger non-PR rule: preserved.

## Current target set

The v0.1 manifest covers CORE-HUB, INFRA, agent-runtime, platform, operator-console, Theia Special, workspace, Osiris, and supply continuity. Expansion is an explicit manifest change and should be reviewed like any other authority-surface change.
