# MIRRORNODE-INFRA

Estate-level infrastructure wrapper for MIRRORNODE projects, websites, deployment surfaces, and shared service dependencies.

## Purpose

This repository is the integration boundary above individual application repositories. It exists to describe and validate how projects connect to shared infrastructure without making any single application repository the authority for the whole estate.

## Scope

- project and website registry
- deployment topology
- shared service ownership boundaries
- environment contracts
- database migration ownership policy
- CI/CD and release invariants
- public-safe infrastructure documentation

## Non-goals

- storing secrets or credentials
- embedding production service identifiers that do not need to be public
- bypassing application-level repositories
- automatically mutating production infrastructure without an explicit approval boundary

## Authority model

Application repositories own their implementation. MIRRORNODE-INFRA owns the cross-project contract that describes how those implementations connect. Production database changes remain disabled from automatic GitHub deployment until a canonical migration source is established and reviewed.

## Initial estate model

The wrapper is organized around three adapters:

1. **GitHub** — source repositories and change provenance.
2. **Vercel** — websites, applications, previews, and production deployments.
3. **Supabase** — shared database, authentication, storage, and migration history.

The implementation branch will add machine-readable manifests and validation rules without exposing credentials or sensitive service identifiers.
