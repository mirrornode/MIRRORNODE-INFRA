#!/usr/bin/env python3
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests" / "estate.json"
RECONCILIATION = ROOT / "manifests" / "vercel-reconciliation.json"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    data = json.loads(MANIFEST.read_text())

    if data.get("schema_version") != "0.1.0":
        fail("unexpected schema_version")

    shared = data.get("shared_services", {})
    supabase = shared.get("supabase", {})
    if supabase.get("github_production_deploy") is not False:
        fail("Supabase production deployment must remain disabled in v0.1")

    repos = data.get("core_repositories", [])
    names = [entry.get("name") for entry in repos]
    if len(names) != len(set(names)):
        fail("duplicate core repository entry")
    if "MIRRORNODE-INFRA" not in names:
        fail("estate wrapper repository is not registered")

    projects = data.get("vercel_projects_observed", [])
    if len(projects) != len(set(projects)):
        fail("duplicate Vercel project entry")
    observed = shared.get("vercel", {}).get("observed_project_count")
    if observed != len(projects):
        fail(f"Vercel count mismatch: manifest says {observed}, list contains {len(projects)}")

    if not RECONCILIATION.exists():
        fail("Vercel reconciliation manifest is missing")
    reconciliation = json.loads(RECONCILIATION.read_text())
    mapped = reconciliation.get("projects", [])
    mapped_names = [entry.get("name") for entry in mapped]
    if len(mapped_names) != len(set(mapped_names)):
        fail("duplicate Vercel reconciliation entry")
    if set(mapped_names) != set(projects):
        missing = sorted(set(projects) - set(mapped_names))
        extra = sorted(set(mapped_names) - set(projects))
        fail(f"Vercel reconciliation coverage mismatch: missing={missing} extra={extra}")

    for entry in mapped:
        if entry.get("classification") is None:
            fail(f"Vercel project has no classification: {entry.get('name')}")
        if entry.get("source_verified") is True and not entry.get("source_repo"):
            fail(f"verified Vercel source has no repository: {entry.get('name')}")

    safety = reconciliation.get("safety", {})
    for key in ("delete_projects", "change_domains", "change_production_deployments", "change_supabase"):
        if safety.get(key) is not False:
            fail(f"Phase II safety boundary must remain false: {key}")

    invariants = data.get("invariants", [])
    if not invariants:
        fail("no estate invariants declared")

    verified = sum(1 for entry in mapped if entry.get("source_verified") is True)
    print(
        f"OK: estate={data['estate']} repos={len(repos)} "
        f"vercel_projects={len(projects)} verified_sources={verified} "
        "supabase_prod_deploy=off destructive_actions=off"
    )


if __name__ == "__main__":
    main()
