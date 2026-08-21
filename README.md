# MIRRORNODE-INFRA

Estate-level infrastructure wrapper for MIRRORNODE projects, websites, deployment surfaces, shared service dependencies, and repository-integrity controls.

## Purpose

This repository is the integration boundary above individual application repositories. It describes and validates how projects connect to shared infrastructure without making any single application repository the authority for the whole estate.

## Scope

- project and website registry
- deployment topology
- shared service ownership boundaries
- environment contracts
- database migration ownership policy
- CI/CD and release invariants
- repository-integrity policy and evidence
- public-safe infrastructure documentation

## Repo Steward

`Repo Steward v0.1` is the repository-integrity control-plane presence implemented here. Its stack is:

- **REPO STEWARD** — integration and coordination
- **SURVEYOR** — repository census and topology observation
- **SENTINEL** — code/check/CI integrity classification
- **NOTARY** — exact-head and provenance binding
- **CUSTODIAN** — bounded repair proposals
- **WARDEN** — permissions, secret-risk, and self-expansion review

The checker is GET-only. The administration engine is proposal-only and deliberately has no GitHub mutation transport in v0.1.

Every future repository write requires explicit human Operator authorization. No autonomous agent, bot identity, service account, coding agent, or advisory model may independently administer repositories. Approved OpenAI, Perplexity, and Claude lanes may inspect, recommend, prepare, or independently review, but do not acquire repository authority from that role.

See `docs/REPO_STEWARD_AGENT_STACK_V0_1.md` and `manifests/repo-steward-policy.json`.

## Non-goals

- storing secrets or credentials
- embedding production service identifiers that do not need to be public
- bypassing application-level repositories
- autonomous repository administration
- bot-only mutation or merge paths
- self-certifying repairs
- automatically mutating production infrastructure without an explicit approval boundary

## Authority model

Application repositories own their implementation. MIRRORNODE-INFRA owns the cross-project contract that describes how those implementations connect. Repo Steward may observe, classify, and propose; it does not create approval, merge, deployment, or constitutional authority. Production database changes remain disabled from automatic GitHub deployment until a canonical migration source is established and reviewed.

## Estate adapters

1. **GitHub** — source repositories, change provenance, CI, and review evidence.
2. **Vercel** — websites, applications, previews, and production deployments.
3. **Supabase** — shared database, authentication, storage, and migration history.

Machine-readable manifests and validation rules must remain credential-free and fail closed where ownership, authority, or evidence is unresolved.
