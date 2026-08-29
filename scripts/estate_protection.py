#!/usr/bin/env python3
"""Audit or strengthen MIRRORNODE default-branch rulesets.

Default mode is read-only audit. Use --apply only with an admin-capable GitHub token.
Existing rules are preserved; only the pull_request rule is strengthened to match
manifests/estate-main-protection.v0.1.json. If the named ruleset is absent, a
minimal baseline is created for the default branch.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.github.com"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "manifests" / "estate-main-protection.v0.1.json"


def request(token: str, method: str, url: str, payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "mirrornode-estate-protection-v0.1",
        },
    )
    try:
        with urllib.request.urlopen(req) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub {method} {url} failed: {exc.code} {detail}") from exc


def find_ruleset(token: str, repo: str, name: str):
    rulesets = request(token, "GET", f"{API}/repos/{repo}/rulesets")
    for item in rulesets:
        if item.get("name") == name:
            return request(token, "GET", f"{API}/repos/{repo}/rulesets/{item['id']}")
    return None


def desired_pull_request(existing: dict | None, policy: dict) -> dict:
    params = dict((existing or {}).get("parameters") or {})
    params.update(policy)
    params.setdefault("required_reviewers", [])
    return {"type": "pull_request", "parameters": params}


def strengthen_rules(existing_rules: list[dict], policy: dict) -> list[dict]:
    result = []
    replaced = False
    for rule in existing_rules:
        if rule.get("type") == "pull_request":
            result.append(desired_pull_request(rule, policy))
            replaced = True
        else:
            result.append(rule)
    if not replaced:
        result.append(desired_pull_request(None, policy))
    return result


def create_payload(manifest: dict) -> dict:
    return {
        "name": manifest["ruleset_name"],
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "ref_name": {"include": [manifest["target"]], "exclude": []}
        },
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "required_linear_history"},
            desired_pull_request(None, manifest["review_policy"]),
        ],
        "bypass_actors": [],
    }


def update_payload(ruleset: dict, manifest: dict) -> dict:
    return {
        "name": ruleset["name"],
        "target": ruleset["target"],
        "enforcement": ruleset["enforcement"],
        "conditions": ruleset["conditions"],
        "rules": strengthen_rules(ruleset.get("rules", []), manifest["review_policy"]),
        "bypass_actors": ruleset.get("bypass_actors", []),
    }


def compliance(ruleset: dict | None, policy: dict) -> tuple[bool, list[str]]:
    if not ruleset:
        return False, ["ruleset missing"]
    pr = next((r for r in ruleset.get("rules", []) if r.get("type") == "pull_request"), None)
    if not pr:
        return False, ["pull_request rule missing"]
    params = pr.get("parameters", {})
    drift = [f"{key}: observed={params.get(key)!r} expected={value!r}"
             for key, value in policy.items() if params.get(key) != value]
    return not drift, drift


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--apply", action="store_true", help="mutate repository rulesets")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print("ERROR: GITHUB_TOKEN or GH_TOKEN is required", file=sys.stderr)
        return 2

    manifest = json.loads(Path(args.manifest).read_text())
    failed = False

    for repo in manifest["repositories"]:
        ruleset = find_ruleset(token, repo, manifest["ruleset_name"])
        ok, drift = compliance(ruleset, manifest["review_policy"])
        print(f"{repo}: {'PASS' if ok else 'DRIFT'}")
        for item in drift:
            print(f"  - {item}")

        if args.apply and not ok:
            if ruleset:
                payload = update_payload(ruleset, manifest)
                request(token, "PUT", f"{API}/repos/{repo}/rulesets/{ruleset['id']}", payload)
                print("  applied: strengthened existing ruleset; preserved other rules")
            else:
                request(token, "POST", f"{API}/repos/{repo}/rulesets", create_payload(manifest))
                print("  applied: created baseline ruleset")
            refreshed = find_ruleset(token, repo, manifest["ruleset_name"])
            verified, remaining = compliance(refreshed, manifest["review_policy"])
            if not verified:
                failed = True
                print("  VERIFY FAIL")
                for item in remaining:
                    print(f"    - {item}")
            else:
                print("  verify: PASS")
        elif not ok:
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
