# Phase II Estate Reconciliation — 2026-08-09

## Confirmed production mappings

### Public product

- Vercel project: `mirrornode-platform`
- GitHub source: `mirrornode/mirrornode-platform`
- Production branch: `main`
- Custom domain: `mirrornode.xyz`
- Status: READY production deployment observed

### Public API

- Vercel project: `mirrornode-backend`
- GitHub source: `mirrornode/mirrornode-py`
- Production branch: `main`
- Custom domain: `api.mirrornode.xyz`
- Status: READY production deployment observed

This is an important naming mismatch: the Vercel project is named `mirrornode-backend`, while its current Git source is `mirrornode-py`.

## Confirmed service mappings

- `mirrornode-oracle` is sourced from `mirrornode/mirrornode` on `main`.
- `mirrornode` is sourced from `mirrornode/mirrornode` on `main`.
- `osiris` has an established production history sourced from `mirrornode/osiris` on `main`.

## Current architectural inference

The estate already behaves like a multi-project system around a smaller number of source repositories. Vercel project names therefore cannot be treated as repository authority. The wrapper must track the relationship explicitly.

The public product center of gravity is now clearly `mirrornode-platform`, while `mirrornode-backend` provides the `api.mirrornode.xyz` service from `mirrornode-py`. Historical Osiris-specific deployment surfaces remain live enough that they should be classified and retired only after traffic/domain/function comparison.

## Candidate cleanup groups

These are **candidates only**, not deletion approvals:

### Public-surface overlap

- `mirrornode-homepage`
- `public`
- `mirrornode-hub`

Compare each against `mirrornode-platform` before consolidation.

### Oracle overlap

- `oracle`
- `mirrornode-oracle`

`mirrornode-oracle` is verified as current Git-backed service. `oracle` remains unresolved.

### Osiris overlap

- `osiris`
- `osiris-ui`
- `osiris-ui-gl6f`
- `osiris-ui-agent`
- `osiris-pay`

The public Osiris offer now lives within `mirrornode-platform`, but these deployments may still represent API, legacy, payment, or prototype responsibilities. No deletion should occur until those responsibilities are traced.

### ROTAN/prototype overlap

- `rotan-resonance`
- `rotan-resonance-zx1o`
- `rotan-neural-modality-kids-game`
- other named prototype projects

These should remain classified as experimental or duplicate candidates until their intended retention policy is explicit.

## Database boundary

Supabase production deploy remains OFF. This reconciliation does not change database state or GitHub→Supabase integration.

## Next execution slice

1. Verify the unresolved Vercel project source mappings.
2. Compare live aliases/domains and recent deployment activity.
3. Mark each project `retain`, `archive_candidate`, or `consolidate_candidate`.
4. Create a domain registry so custom domains become first-class estate objects.
5. Recover Supabase migration source after deployment topology is stable.

No destructive action is authorized by this document.
