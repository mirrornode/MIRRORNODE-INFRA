#!/usr/bin/env python3
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests" / "estate.json"


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

    invariants = data.get("invariants", [])
    if not invariants:
        fail("no estate invariants declared")

    print(
        f"OK: estate={data['estate']} repos={len(repos)} "
        f"vercel_projects={len(projects)} supabase_prod_deploy=off"
    )


if __name__ == "__main__":
    main()
