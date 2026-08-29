# MIRRORNODE Estate Main Protection v0.1

## Status

**PROPOSED / ENFORCEMENT TOOLING INCLUDED / PLATFORM MUTATION REQUIRES ADMIN TOKEN**

## Purpose

Define one reproducible minimum protection contract for MIRRORNODE repositories whose default branch carries governance, production, control-plane, runtime, continuity, or commercial authority.

This contract exists because repository policy must be mechanically enforced rather than inferred from human or agent discipline.

## Required default-branch invariants

For each repository in `manifests/estate-main-protection.v0.1.json`:

- pull request required before merge;
- at least one approving review required;
- stale approvals dismissed when the head changes;
- approval required from someone other than the actor responsible for the most recent push;
- all review conversations resolved before merge;
- branch deletion prohibited;
- non-fast-forward updates prohibited;
- linear history required;
- squash is the allowed merge method;
- no bypass actor is introduced by this contract.

Existing repository-specific required status checks and other rules must be preserved. This contract must not replace or weaken stronger local policy.

## Exact-head consequence

Any push that changes the pull-request head invalidates approval evidence for the predecessor head. A successor head must satisfy its own checks and review requirements. No correction, reconciliation, or other subject-changing update may inherit ancestor-head clearance.

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

The token must have repository administration permission for every target repository. The tool discovers the named ruleset, preserves all non-PR rules, strengthens only the `pull_request` parameters, then re-reads the ruleset and verifies the desired state. If the named ruleset is absent, it creates the minimal baseline declared by the manifest.

## Failure semantics

- Missing token: fail closed.
- API read/write failure: fail closed.
- Post-write verification mismatch: fail closed.
- Repository not listed in the manifest: out of scope; no mutation.
- Existing stronger non-PR rule: preserved.

## Current target set

The v0.1 manifest covers CORE-HUB, INFRA, agent-runtime, platform, operator-console, Theia Special, workspace, Osiris, and supply continuity. Expansion is an explicit manifest change and should be reviewed like any other authority-surface change.
