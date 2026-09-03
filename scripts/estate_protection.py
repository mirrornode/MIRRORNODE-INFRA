#!/usr/bin/env python3
"""Audit or monotonically strengthen MIRRORNODE default-branch protection.

Read-only audit is the default. ``--apply`` may only strengthen the named
baseline ruleset; it never treats the manifest as a replacement policy.
All compliance decisions are fail-closed and are based on the complete
effective default-branch protection surface that can be read.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API = "https://api.github.com"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "manifests" / "estate-main-protection.v0.1.json"

RESTRICTIVE_TRUE_KEYS = {
    "dismiss_stale_reviews_on_push",
    "require_code_owner_review",
    "require_last_push_approval",
    "required_review_thread_resolution",
    "require_extra_approval_for_unattributed_changes",
}
ALLOWED_REVIEW_KEYS = RESTRICTIVE_TRUE_KEYS | {
    "required_approving_review_count",
    "allowed_merge_methods",
    "required_reviewers",
}
REQUIRED_RULE_TYPES = {"deletion", "non_fast_forward"}


def select_token(env: dict[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    gh = env.get("GH_TOKEN")
    github = env.get("GITHUB_TOKEN")
    if gh and github and gh != github:
        raise RuntimeError("ambiguous credentials: set exactly one of GH_TOKEN or GITHUB_TOKEN")
    token = gh or github
    if not token:
        raise RuntimeError("GH_TOKEN or GITHUB_TOKEN is required")
    return token


def request(token: str, method: str, url: str, payload=None, allow_404: bool = False):
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
        if allow_404 and exc.code == 404:
            return None
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub {method} {url} failed: {exc.code} {detail}") from exc


def paginate(token: str, url: str) -> list[dict]:
    out: list[dict] = []
    page = 1
    while True:
        sep = "&" if "?" in url else "?"
        batch = request(token, "GET", f"{url}{sep}per_page=100&page={page}")
        if not isinstance(batch, list):
            raise RuntimeError(f"expected paginated list from {url}")
        out.extend(batch)
        if len(batch) < 100:
            return out
        page += 1


def validate_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []
    required = {"version", "ruleset_name", "target", "review_policy", "required_status_checks", "preserve_existing_rules", "repositories"}
    missing = sorted(required - set(manifest))
    if missing:
        errors.append(f"missing required fields: {', '.join(missing)}")
    if manifest.get("target") != "~DEFAULT_BRANCH":
        errors.append("target must be ~DEFAULT_BRANCH")
    if manifest.get("preserve_existing_rules") is not True:
        errors.append("preserve_existing_rules must be true")
    repos = manifest.get("repositories")
    if not isinstance(repos, list) or not repos or any(not isinstance(x, str) or "/" not in x for x in repos):
        errors.append("repositories must be a non-empty owner/repo string list")
    policy = manifest.get("review_policy")
    if not isinstance(policy, dict):
        errors.append("review_policy must be an object")
        return errors
    unknown = sorted(set(policy) - ALLOWED_REVIEW_KEYS)
    if unknown:
        errors.append(f"unsupported review policy fields: {', '.join(unknown)}")
    if not isinstance(policy.get("required_approving_review_count"), int) or policy.get("required_approving_review_count", 0) < 1:
        errors.append("required_approving_review_count must be >= 1")
    for key in ("dismiss_stale_reviews_on_push", "require_last_push_approval", "required_review_thread_resolution"):
        if policy.get(key) is not True:
            errors.append(f"{key} must be true")
    methods = policy.get("allowed_merge_methods")
    if not isinstance(methods, list) or not methods or any(x not in {"merge", "squash", "rebase"} for x in methods):
        errors.append("allowed_merge_methods must be a non-empty supported list")
    status_decl = manifest.get("required_status_checks")
    if status_decl != {"mode": "preserve_existing_nonempty"}:
        errors.append("required_status_checks must declare mode=preserve_existing_nonempty")
    if manifest.get("bypass_actors", []) not in ([], None):
        errors.append("baseline must not permit bypass actors")
    return errors


def merge_restrictive_policy(existing: dict | None, floor: dict) -> dict:
    existing = dict(existing or {})
    unknown = set(floor) - ALLOWED_REVIEW_KEYS
    if unknown:
        raise ValueError(f"unknown protection parameter ordering: {sorted(unknown)}")
    result = dict(existing)
    for key, desired in floor.items():
        current = existing.get(key)
        if key == "required_approving_review_count":
            result[key] = max(int(current or 0), int(desired))
        elif key in RESTRICTIVE_TRUE_KEYS:
            result[key] = bool(current) or bool(desired)
        elif key == "allowed_merge_methods":
            desired_set = set(desired or [])
            current_set = set(current or [])
            result[key] = sorted(current_set & desired_set) if current_set else sorted(desired_set)
            if not result[key]:
                raise ValueError("allowed_merge_methods reconciliation would remove every merge method")
        elif key == "required_reviewers":
            by_key = {}
            for item in list(current or []) + list(desired or []):
                marker = json.dumps(item, sort_keys=True)
                by_key[marker] = item
            result[key] = list(by_key.values())
    result.setdefault("required_reviewers", [])
    return result


def desired_pull_request(existing: dict | None, policy: dict) -> dict:
    params = merge_restrictive_policy((existing or {}).get("parameters") or {}, policy)
    return {"type": "pull_request", "parameters": params}


def strengthen_rules(existing_rules: list[dict], policy: dict) -> list[dict]:
    result: list[dict] = []
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


def list_all_rulesets(token: str, repo: str) -> list[dict]:
    summaries = paginate(token, f"{API}/repos/{repo}/rulesets")
    details: list[dict] = []
    for item in summaries:
        ruleset_id = item.get("id")
        if not ruleset_id:
            raise RuntimeError(f"ruleset without id in {repo}")
        details.append(request(token, "GET", f"{API}/repos/{repo}/rulesets/{ruleset_id}"))
    return details


def ref_condition_applies(ruleset: dict, default_branch: str) -> bool | None:
    if ruleset.get("target") != "branch":
        return False
    cond = (ruleset.get("conditions") or {}).get("ref_name")
    if not cond:
        return True
    ref = f"refs/heads/{default_branch}"
    include = cond.get("include") or []
    exclude = cond.get("exclude") or []

    def matches(pattern: str) -> bool:
        if pattern in {"~ALL", "~DEFAULT_BRANCH"}:
            return True
        return fnmatch.fnmatch(ref, pattern)

    if any(matches(p) for p in exclude):
        return False
    if not include:
        return True
    return any(matches(p) for p in include)


def effective_default_branch_protection(token: str, repo: str) -> dict:
    repo_info = request(token, "GET", f"{API}/repos/{repo}")
    default_branch = repo_info.get("default_branch")
    if not default_branch:
        return {"complete": False, "diagnostics": ["default branch unavailable"], "repo": repo}
    diagnostics: list[str] = []
    applicable: list[dict] = []
    try:
        rulesets = list_all_rulesets(token, repo)
    except Exception as exc:
        return {"complete": False, "diagnostics": [f"ruleset discovery unreadable: {exc}"], "repo": repo, "default_branch": default_branch}
    for ruleset in rulesets:
        if ruleset.get("enforcement") != "active":
            continue
        applies = ref_condition_applies(ruleset, default_branch)
        if applies is None:
            diagnostics.append(f"ruleset {ruleset.get('id')} applicability indeterminate")
        elif applies:
            applicable.append(ruleset)
    try:
        classic = request(token, "GET", f"{API}/repos/{repo}/branches/{default_branch}/protection", allow_404=True)
    except Exception as exc:
        return {"complete": False, "diagnostics": [f"classic protection unreadable: {exc}"], "repo": repo, "default_branch": default_branch}
    return {
        "complete": not diagnostics,
        "diagnostics": diagnostics,
        "repo": repo,
        "default_branch": default_branch,
        "rulesets": applicable,
        "classic": classic,
    }


def _aggregate_effective(surface: dict) -> dict:
    aggregate = {
        "rule_types": set(),
        "review": {},
        "status_checks": set(),
        "bypass_actors": [],
    }
    for ruleset in surface.get("rulesets", []):
        aggregate["bypass_actors"].extend(ruleset.get("bypass_actors") or [])
        for rule in ruleset.get("rules", []):
            rtype = rule.get("type")
            aggregate["rule_types"].add(rtype)
            params = rule.get("parameters") or {}
            if rtype == "pull_request":
                aggregate["review"] = merge_restrictive_policy(aggregate["review"], {k: v for k, v in params.items() if k in ALLOWED_REVIEW_KEYS})
            elif rtype == "required_status_checks":
                for check in params.get("required_status_checks") or []:
                    context = check.get("context")
                    if context:
                        aggregate["status_checks"].add(context)
    classic = surface.get("classic") or {}
    if classic:
        if classic.get("allow_deletions", {}).get("enabled") is False:
            aggregate["rule_types"].add("deletion")
        if classic.get("allow_force_pushes", {}).get("enabled") is False:
            aggregate["rule_types"].add("non_fast_forward")
        reviews = classic.get("required_pull_request_reviews") or {}
        if reviews:
            classic_policy = {
                "required_approving_review_count": reviews.get("required_approving_review_count", 0),
                "dismiss_stale_reviews_on_push": reviews.get("dismiss_stale_reviews", False),
                "require_code_owner_review": reviews.get("require_code_owner_reviews", False),
                "require_last_push_approval": reviews.get("require_last_push_approval", False),
            }
            aggregate["review"] = merge_restrictive_policy(aggregate["review"], classic_policy)
        checks = classic.get("required_status_checks") or {}
        for check in checks.get("checks") or []:
            context = check.get("context")
            if context:
                aggregate["status_checks"].add(context)
    return aggregate


def validate_effective_protection(surface: dict, manifest: dict) -> tuple[bool, list[str]]:
    diagnostics = list(surface.get("diagnostics") or [])
    if not surface.get("complete"):
        diagnostics.append("effective protection surface incomplete")
        return False, diagnostics
    aggregate = _aggregate_effective(surface)
    missing_rules = REQUIRED_RULE_TYPES - aggregate["rule_types"]
    if missing_rules:
        diagnostics.append(f"missing required rules: {', '.join(sorted(missing_rules))}")
    if aggregate["bypass_actors"]:
        diagnostics.append("effective bypass actor present")
    if manifest.get("required_status_checks") == {"mode": "preserve_existing_nonempty"} and not aggregate["status_checks"]:
        diagnostics.append("no effective required status check")
    policy = manifest["review_policy"]
    observed = aggregate["review"]
    if int(observed.get("required_approving_review_count") or 0) < int(policy["required_approving_review_count"]):
        diagnostics.append("approval count below manifest floor")
    for key in RESTRICTIVE_TRUE_KEYS:
        if policy.get(key) is True and observed.get(key) is not True:
            diagnostics.append(f"{key} not effectively enforced")
    return not diagnostics, diagnostics


def find_named_ruleset(rulesets: list[dict], name: str) -> dict | None:
    matches = [r for r in rulesets if r.get("name") == name]
    if len(matches) > 1:
        raise RuntimeError(f"duplicate named rulesets found: {name}")
    return matches[0] if matches else None


def create_payload(manifest: dict) -> dict:
    return {
        "name": manifest["ruleset_name"],
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": [manifest["target"]], "exclude": []}},
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "required_linear_history"},
            desired_pull_request(None, manifest["review_policy"]),
        ],
        "bypass_actors": [],
    }


def update_payload(ruleset: dict, manifest: dict) -> dict:
    if ruleset.get("bypass_actors"):
        raise RuntimeError("named ruleset contains bypass actors; refusing mutation")
    return {
        "name": ruleset["name"],
        "target": ruleset["target"],
        "enforcement": "active",
        "conditions": ruleset["conditions"],
        "rules": strengthen_rules(ruleset.get("rules", []), manifest["review_policy"]),
        "bypass_actors": [],
    }


def evaluate_exact_head_approval(pr: dict, reviews: list[dict], commits: list[dict], expected_sha: str) -> tuple[bool, list[str]]:
    errors: list[str] = []
    current = ((pr.get("head") or {}).get("sha"))
    if current != expected_sha:
        return False, [f"PR head mismatch: current={current} expected={expected_sha}"]
    author = ((pr.get("user") or {}).get("login"))
    last_commit = commits[-1] if commits else {}
    latest_actor = ((last_commit.get("author") or {}).get("login")) or ((last_commit.get("committer") or {}).get("login"))
    eligible = []
    for review in reviews:
        if review.get("state") != "APPROVED":
            continue
        if review.get("commit_id") != expected_sha:
            continue
        reviewer = ((review.get("user") or {}).get("login"))
        if not reviewer or reviewer == author or (latest_actor and reviewer == latest_actor):
            continue
        eligible.append(reviewer)
    if not eligible:
        errors.append("no eligible approval bound to exact current head SHA")
    return not errors, errors


def read_exact_head_approval(token: str, repo: str, pr_number: int, expected_sha: str) -> tuple[bool, list[str]]:
    pr = request(token, "GET", f"{API}/repos/{repo}/pulls/{pr_number}")
    reviews = paginate(token, f"{API}/repos/{repo}/pulls/{pr_number}/reviews")
    commits = paginate(token, f"{API}/repos/{repo}/pulls/{pr_number}/commits")
    return evaluate_exact_head_approval(pr, reviews, commits, expected_sha)


def evaluate_latest_runs(runs: list[dict], required_workflows: list[str]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    for name in required_workflows:
        candidates = [r for r in runs if r.get("name") == name]
        if not candidates:
            errors.append(f"required workflow missing: {name}")
            continue
        latest = max(candidates, key=lambda r: (int(r.get("run_attempt") or 1), r.get("created_at") or "", int(r.get("id") or 0)))
        if latest.get("status") != "completed" or latest.get("conclusion") != "success":
            errors.append(f"latest workflow non-success: {name} status={latest.get('status')} conclusion={latest.get('conclusion')}")
    return not errors, errors


def latest_run_status(token: str, repo: str, sha: str, required_workflows: list[str]) -> tuple[bool, list[str]]:
    payload = request(token, "GET", f"{API}/repos/{repo}/actions/runs?head_sha={sha}&event=pull_request&per_page=100")
    runs = (payload or {}).get("workflow_runs") or []
    return evaluate_latest_runs(runs, required_workflows)



def _operator_debt(code: str, subject: str, detail: str, evidence: list[dict]) -> dict:
    return {
        "id": "github-ops:" + subject + ":" + code,
        "code": code,
        "subject": subject,
        "severity": "blocking",
        "detail": detail,
        "evidence": evidence,
        "resolution": "collect fresh complete evidence satisfying the named gate",
    }


def build_read_only_snapshot(token: str, repo: str, pr_number: int, expected_sha: str, required_workflows: list[str], manifest: dict) -> dict:
    """Collect one immutable-input, read-only GitHub Ops projection."""
    collected_at = datetime.now(timezone.utc).isoformat()
    policy_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()
    pr = request(token, "GET", API + "/repos/" + repo + "/pulls/" + str(pr_number))
    reviews = paginate(token, API + "/repos/" + repo + "/pulls/" + str(pr_number) + "/reviews")
    commits = paginate(token, API + "/repos/" + repo + "/pulls/" + str(pr_number) + "/commits")
    runs_payload = request(token, "GET", API + "/repos/" + repo + "/actions/runs?head_sha=" + expected_sha + "&event=pull_request&per_page=100")
    runs = (runs_payload or {}).get("workflow_runs") or []
    protection = effective_default_branch_protection(token, repo)
    approval_ok, approval_errors = evaluate_exact_head_approval(pr, reviews, commits, expected_sha)
    workflow_ok, workflow_errors = evaluate_latest_runs(runs, required_workflows)
    protection_ok, protection_errors = validate_effective_protection(protection, manifest)
    evidence = {
        "head_sha": ((pr.get("head") or {}).get("sha")),
        "review_ids": [r.get("id") for r in reviews if r.get("id") is not None],
        "workflow_runs": [
            {"id": r.get("id"), "name": r.get("name"), "run_attempt": r.get("run_attempt"), "status": r.get("status"), "conclusion": r.get("conclusion"), "head_sha": r.get("head_sha")}
            for r in runs
        ],
    }
    debt: list[dict] = []
    if not protection_ok:
        debt.append(_operator_debt("protection-hold", repo, "; ".join(protection_errors), [{"kind": "protection", "repository": repo}]))
    if not approval_ok:
        debt.append(_operator_debt("exact-head-review-hold", repo + "#" + str(pr_number), "; ".join(approval_errors), [{"kind": "pull_request", "number": pr_number, "head_sha": evidence["head_sha"]}]))
    if not workflow_ok:
        debt.append(_operator_debt("workflow-hold", expected_sha, "; ".join(workflow_errors), [{"kind": "workflow_run", **item} for item in evidence["workflow_runs"]]))
    return {
        "schema_version": "github-ops.snapshot.v0.1",
        "repository": repo,
        "pull_request": pr_number,
        "expected_head_sha": expected_sha,
        "observed_head_sha": evidence["head_sha"],
        "observed_at": collected_at,
        "collector": {"mode": "read-only", "credential_source": "environment"},
        "policy": {"version": manifest.get("version"), "sha256": policy_sha256},
        "completeness": {
            "protection": "complete" if protection.get("complete") else "partial",
            "reviews": "complete",
            "workflows": "complete" if len(runs) < 100 else "partial",
            "dependencies_security": "not_collected",
        },
        "evidence": evidence,
        "operator_debt": debt,
        "status": "PASS" if not debt else "HOLD",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--apply", action="store_true", help="monotonically strengthen the named ruleset")
    parser.add_argument("--validate-manifest-only", action="store_true")
    parser.add_argument("--snapshot-json", action="store_true", help="emit a read-only GitHub Ops snapshot")
    parser.add_argument("--repo")
    parser.add_argument("--pr-number", type=int)
    parser.add_argument("--expected-sha")
    parser.add_argument("--required-workflow", action="append", default=[])
    args = parser.parse_args()

    try:
        manifest = json.loads(Path(args.manifest).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: manifest unreadable: {exc}", file=sys.stderr)
        return 2
    errors = validate_manifest(manifest)
    if errors:
        for item in errors:
            print(f"ERROR: {item}", file=sys.stderr)
        return 2
    if args.validate_manifest_only:
        print("estate main protection manifest: PASS")
        return 0

    try:
        token = select_token()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.snapshot_json:
        if not args.repo or not args.pr_number or not args.expected_sha or not args.required_workflow:
            print("ERROR: --snapshot-json requires --repo, --pr-number, --expected-sha, and --required-workflow", file=sys.stderr)
            return 2
        if args.repo not in manifest["repositories"]:
            print("ERROR: snapshot repository is outside the manifest", file=sys.stderr)
            return 2
        try:
            snapshot = build_read_only_snapshot(token, args.repo, args.pr_number, args.expected_sha, args.required_workflow, manifest)
        except Exception as exc:
            print(json.dumps({"schema_version": "github-ops.snapshot.v0.1", "status": "HOLD", "error": str(exc)}, sort_keys=True))
            return 1
        print(json.dumps(snapshot, sort_keys=True))
        return 0 if snapshot["status"] == "PASS" else 1

    failed = False
    for repo in manifest["repositories"]:
        surface = effective_default_branch_protection(token, repo)
        ok, drift = validate_effective_protection(surface, manifest)
        print(f"{repo}: {'PASS' if ok else 'HOLD'}")
        for item in drift:
            print(f"  - {item}")

        if args.apply and not ok:
            if not surface.get("complete"):
                failed = True
                print("  APPLY REFUSED: effective state incomplete")
                continue
            all_rulesets = list_all_rulesets(token, repo)
            named = find_named_ruleset(all_rulesets, manifest["ruleset_name"])
            if named:
                applies = ref_condition_applies(named, surface["default_branch"])
                if applies is not True:
                    failed = True
                    print("  APPLY REFUSED: named ruleset does not target default branch")
                    continue
                payload = update_payload(named, manifest)
                request(token, "PUT", f"{API}/repos/{repo}/rulesets/{named['id']}", payload)
                print("  applied: monotonic pull-request strengthening; non-PR rules preserved")
            else:
                request(token, "POST", f"{API}/repos/{repo}/rulesets", create_payload(manifest))
                print("  applied: created restrictive baseline ruleset")
            refreshed = effective_default_branch_protection(token, repo)
            verified, remaining = validate_effective_protection(refreshed, manifest)
            if not verified:
                failed = True
                print("  VERIFY HOLD")
                for item in remaining:
                    print(f"    - {item}")
            else:
                print("  verify: PASS")
        elif not ok:
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
