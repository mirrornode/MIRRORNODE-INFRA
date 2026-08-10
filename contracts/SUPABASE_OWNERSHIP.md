# Supabase Ownership Contract v0.1

## Current state

MIRRORNODE currently has one observed healthy Supabase project, logically named **Mirrornode OS**. Its live schema includes application payment/subscription state and Khepri witness-state structures. The live project contains an existing migration history.

GitHub production deployment is intentionally **disabled** until a canonical migration source is established in version control.

## Ownership rule

Supabase is a **shared estate service**, not the property of whichever application happens to consume it first.

- Application repositories may consume approved Supabase interfaces.
- Application repositories may propose schema changes.
- MIRRORNODE-INFRA records which repository is the canonical migration source.
- No repository gains schema authority merely because it contains a Supabase client.
- Production migration execution requires an explicit reviewed change path.

## Candidate source

`mirrornode-platform` is currently the strongest observed runtime consumer of Supabase and is a candidate host for a `supabase/` directory. It is **not yet designated** as canonical migration authority.

The designation requires:

1. Baseline the current production migration history.
2. Reconstruct or import migration SQL into version control.
3. Confirm no other repository currently owns newer schema definitions.
4. Validate local/preview migration replay against a non-production database.
5. Review security advisors and resolve or disposition material findings.
6. Only then configure GitHub integration and consider production deployment.

## Required GitHub integration state

Until the above gates pass:

- connected repository: informational only
- working directory: unresolved
- deploy to production: **OFF**
- preview branching: optional only after canonical migrations exist

## Production invariant

A merge to an application repository must never become an implicit permission to mutate the shared production database unless the change passes the canonical migration source and its review boundary.
