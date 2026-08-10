# MIRRORNODE Estate Wrapper Contract v0.1

## Purpose

The estate wrapper provides one legible control surface for MIRRORNODE projects, websites, deployments, and shared services while preserving implementation ownership in the repositories that actually build each surface.

## Layers

### 1. Source layer — GitHub

Each deployable surface must map to one source repository and one default production branch. Repository ownership remains local to that project.

### 2. Deployment layer — Vercel

Each Vercel project must be classified as exactly one of:

- `production`
- `active_service`
- `preview_or_staging`
- `historical`
- `historical_candidate`
- `duplicate_candidate`
- `experimental`
- `unclassified`

Classification meanings:

- `production` — verified current production deployment with declared source mapping or custom production domain.
- `active_service` — verified active service deployment without evidence yet that it is a public website.
- `preview_or_staging` — explicitly non-production preview or staging surface.
- `historical` — verified retained historical deployment with no current production responsibility.
- `historical_candidate` — appears superseded, but is not safe to retire until source, domain, and traffic ownership are verified.
- `duplicate_candidate` — overlaps another surface by name or role; deletion is prohibited until source, domain, and traffic ownership are verified.
- `experimental` — prototype, demo, generated, or intentionally experimental surface.
- `unclassified` — observed but not yet sufficiently reconciled.

No project is deleted merely because its name resembles another project. Consolidation requires evidence of repository, domain, and deployment ownership.

### 3. Shared service layer — Supabase

Supabase is shared estate infrastructure. Database migration ownership is declared separately from runtime consumption. Production deployment remains disabled until canonical migrations are versioned and replay-tested.

### 4. Governance layer

Cross-project changes must state:

- affected repositories
- affected deployment surfaces
- affected shared services
- rollback path
- production mutation status

## Wrapper behavior

The wrapper is initially **declarative and validating**, not an autonomous deployment engine. It should make drift visible before it gains mutation authority.

Future adapters may inspect GitHub, Vercel, Supabase, Stripe, DNS, and monitoring providers and compare observed state to the manifest. Any write-capable adapter must remain behind an explicit approval boundary.

## Required invariants

1. One production surface → one declared source repository.
2. One shared database → one declared canonical migration source.
3. Unclassified resources remain visible; they are not silently discarded.
4. Duplicate-looking resources are candidates, not conclusions.
5. Secrets never enter the estate manifest.
6. Production mutations are disabled by default until explicitly enabled by reviewed policy.
