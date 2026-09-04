# Execution Entrypoint Safety v0.1

## Status

Operational infrastructure invariant. This document is non-constitutional and does not expand authority.

## Invariant

Setup and scaffold operations may create or regenerate implementation artifacts only when explicitly invoked for that purpose.

Runtime and observation entrypoints — including serve, inspect, relay, register, audit, and validate modes — MUST NOT implicitly rewrite, regenerate, or replace the implementation or tested inputs they are executing or observing.

## Why

Implicit regeneration breaks exact-head reasoning: code can pass deterministic tests, then be silently replaced by an execution wrapper before live use. A runtime result would then no longer correspond to the implementation that was reviewed and tested.

## Required behavior

- Separate setup/scaffold from runtime execution.
- Runtime commands operate on the existing working tree without rewriting it.
- If generation is required, it is an explicit operator action before validation.
- Validation evidence binds to the exact implementation subsequently executed.
- Any implementation rewrite invalidates prior exact-head evidence and requires fresh validation.

## ORACLE P004 finding

During ORACLE-WORK-PILOT-004, the local handoff wrapper regenerated `src/ingress.py` when `serve` and `inspect` were invoked. That restored an older case-sensitive webhook implementation after an 8/8 passing corrective test run.

The live GitHub webhook transport proof succeeded only after the corrected implementation was restored and the receiver was launched directly without the regenerating wrapper.

This finding establishes the invariant above; it does not itself authorize ORACLE deployment, GitHub App installation, provider execution, canon mutation, repository mutation beyond this documentation change, or autonomous action.
