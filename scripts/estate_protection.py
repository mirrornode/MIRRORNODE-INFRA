#!/usr/bin/env python3
"""Audit or monotonically strengthen MIRRORNODE default-branch protection.

Read-only audit is the default. ``--apply`` may only strengthen the named
baseline ruleset; it never treats the manifest as a replacement policy.
All compliance decisions are fail-closed and are based on the complete
effective default-branch protection surface that can be read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
REQUIRED_RULE_TYPES = {"deletion", "non_fast_forward", "required_linear_history"}
REVIEW_ELIGIBLE_PERMISSIONS = {"admin", "maintain", "write"}


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


def paginate_object_items(token: str, url: str, key: str) -> list[dict]:
    out: list[dict] = []
    page = 1
    while True:
        sep = "&" if "?" in url else "?"
        payload = request(token, "GET", f"{url}{sep}per_page=100&page={page}")
        batch = (payload or {}).get(key)
        if not isinstance(batch, list):
            raise RuntimeError(f"expected paginated {key} list from {url}")
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
        # GitHub ruleset ref patterns use pathname-aware wildcards: `*` cannot
        # cross `/`, while `**` can.
        pieces: list[str] = []
        index = 0
        while index < len(pattern):
            char = pattern[index]
            if char == "*" and index + 1 < len(pattern) and pattern[index + 1] == "*":
                pieces.append(".*")
                index += 2
            elif char == "*":
                pieces.append("[^/]*")
                index += 1
            elif char == "?":
                pieces.append("[^/]")
                index += 1
            else:
                pieces.append(re.escape(char))
                index += 1
        return re.fullmatch("".join(pieces), ref) is not None

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
            if "bypass_actors" not in ruleset:
                diagnostics.append(f"ruleset {ruleset.get('id')} bypass inventory unavailable")
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
        "repository": repo_info,
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
    repo_info = surface.get("repository") or {}
    repo_methods = []
    if repo_info.get("allow_squash_merge"):
        repo_methods.append("squash")
    if repo_info.get("allow_merge_commit"):
        repo_methods.append("merge")
    if repo_info.get("allow_rebase_merge"):
        repo_methods.append("rebase")
    if repo_methods:
        aggregate["review"]["allowed_merge_methods"] = repo_methods
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
                "required_review_thread_resolution": (classic.get("required_conversation_resolution") or {}).get("enabled", False),
            }
            aggregate["review"] = merge_restrictive_policy(aggregate["review"], classic_policy)
        if (classic.get("enforce_admins") or {}).get("enabled") is not True:
            aggregate["bypass_actors"].append({"kind": "classic_admin_bypass"})
        allowances = reviews.get("bypass_pull_request_allowances") or {}
        if any(allowances.get(kind) for kind in ("users", "teams", "apps")):
            aggregate["bypass_actors"].append({"kind": "classic_pull_request_bypass"})
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
    desired_methods = set(policy.get("allowed_merge_methods") or [])
    observed_methods = set(observed.get("allowed_merge_methods") or [])
    if not observed_methods or not observed_methods.issubset(desired_methods):
        diagnostics.append("effective merge methods exceed manifest restriction")
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


def latest_reviews_by_reviewer(reviews: list[dict]) -> dict[str, dict]:
    """Return each reviewer's latest submitted state, not their best historical state."""
    latest: dict[str, dict] = {}
    for review in reviews:
        reviewer = ((review.get("user") or {}).get("login") or "").lower()
        if not reviewer:
            continue
        marker = (review.get("submitted_at") or "", int(review.get("id") or 0))
        current = latest.get(reviewer)
        current_marker = (current.get("submitted_at") or "", int(current.get("id") or 0)) if current else ("", 0)
        if current is None or marker > current_marker:
            latest[reviewer] = review
    return latest


def read_reviewer_permissions(token: str, repo: str, reviews: list[dict]) -> tuple[dict[str, str], list[str]]:
    permissions: dict[str, str] = {}
    errors: list[str] = []
    reviewers = sorted({((r.get("user") or {}).get("login") or "").lower() for r in reviews} - {""})
    for reviewer in reviewers:
        try:
            payload = request(token, "GET", f"{API}/repos/{repo}/collaborators/{reviewer}/permission")
            permission = (payload or {}).get("permission")
            if permission:
                permissions[reviewer] = permission
            else:
                errors.append(f"reviewer permission unavailable: {reviewer}")
        except Exception as exc:
            errors.append(f"reviewer permission unreadable: {reviewer}: {exc}")
    return permissions, errors


def evaluate_exact_head_approval(
    pr: dict,
    reviews: list[dict],
    expected_sha: str,
    latest_push_actor: str | None,
    reviewer_permissions: dict[str, str],
    required_count: int,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    current = ((pr.get("head") or {}).get("sha"))
    if current != expected_sha:
        return False, [f"PR head mismatch: current={current} expected={expected_sha}"]
    if not latest_push_actor:
        errors.append("trusted latest push actor evidence unavailable")
    author = (((pr.get("user") or {}).get("login")) or "").lower()
    pusher = (latest_push_actor or "").lower()
    eligible: set[str] = set()
    for reviewer, review in latest_reviews_by_reviewer(reviews).items():
        if review.get("state") != "APPROVED":
            continue
        if review.get("commit_id") != expected_sha:
            continue
        if reviewer == author or reviewer == pusher:
            continue
        if reviewer_permissions.get(reviewer) not in REVIEW_ELIGIBLE_PERMISSIONS:
            continue
        eligible.add(reviewer)
    if len(eligible) < required_count:
        errors.append(
            f"eligible exact-head approvals below effective requirement: "
            f"observed={len(eligible)} required={required_count}"
        )
    return not errors, errors


def read_exact_head_approval(token: str, repo: str, pr_number: int, expected_sha: str) -> tuple[bool, list[str]]:
    pr = request(token, "GET", f"{API}/repos/{repo}/pulls/{pr_number}")
    reviews = paginate(token, f"{API}/repos/{repo}/pulls/{pr_number}/reviews")
    permissions, permission_errors = read_reviewer_permissions(token, repo, reviews)
    ok, errors = evaluate_exact_head_approval(pr, reviews, expected_sha, None, permissions, 1)
    return ok and not permission_errors, permission_errors + errors


def evaluate_latest_runs(runs: list[dict], required_workflows: list[str]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    for name in required_workflows:
        candidates = [r for r in runs if r.get("name") == name]
        if not candidates:
            errors.append(f"required workflow missing: {name}")
            continue
        # A retry attempt orders executions of one run; it must never outrank a
        # newer run. created_at/id establish run chronology, then attempt breaks
        # ties for reruns of that same run.
        latest = max(candidates, key=lambda r: (r.get("created_at") or "", int(r.get("id") or 0), int(r.get("run_attempt") or 1)))
        if latest.get("status") != "completed" or latest.get("conclusion") != "success":
            errors.append(f"latest workflow non-success: {name} status={latest.get('status')} conclusion={latest.get('conclusion')}")
    return not errors, errors


def latest_run_status(token: str, repo: str, sha: str, required_workflows: list[str]) -> tuple[bool, list[str]]:
    runs = paginate_object_items(token, f"{API}/repos/{repo}/actions/runs?head_sha={sha}&event=pull_request", "workflow_runs")
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


def build_read_only_snapshot(
    token: str,
    repo: str,
    pr_number: int,
    expected_sha: str,
    required_workflows: list[str],
    manifest: dict,
    *,
    trusted_latest_push_actor: str | None = None,
) -> dict:
    """Collect one immutable-input, read-only GitHub Ops projection."""
    collected_at = datetime.now(timezone.utc).isoformat()
    policy_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()
    pr = request(token, "GET", API + "/repos/" + repo + "/pulls/" + str(pr_number))
    reviews = paginate(token, API + "/repos/" + repo + "/pulls/" + str(pr_number) + "/reviews")
    reviewer_permissions, permission_errors = read_reviewer_permissions(token, repo, reviews)
    runs = paginate_object_items(token, API + "/repos/" + repo + "/actions/runs?head_sha=" + expected_sha + "&event=pull_request", "workflow_runs")
    protection = effective_default_branch_protection(token, repo)
    aggregate = _aggregate_effective(protection) if protection.get("complete") else {"review": {}, "status_checks": set()}
    required_count = int((aggregate.get("review") or {}).get("required_approving_review_count") or 0)
    approval_ok, approval_errors = evaluate_exact_head_approval(
        pr,
        reviews,
        expected_sha,
        trusted_latest_push_actor,
        reviewer_permissions,
        required_count,
    )
    approval_errors = permission_errors + approval_errors
    approval_ok = approval_ok and not permission_errors
    workflow_ok, workflow_errors = evaluate_latest_runs(runs, required_workflows)
    protection_ok, protection_errors = validate_effective_protection(protection, manifest)
    effective_checks = set(aggregate.get("status_checks") or [])
    if set(required_workflows) != effective_checks:
        workflow_ok = False
        workflow_errors.append(
            "workflow request is not exactly bound to effective required checks: "
            f"requested={sorted(required_workflows)} effective={sorted(effective_checks)}"
        )
    base = pr.get("base") or {}
    base_repo = ((base.get("repo") or {}).get("full_name") or "").lower()
    base_ref = base.get("ref")
    expected_base_ref = protection.get("default_branch")
    base_ok = base_repo == repo.lower() and base_ref == expected_base_ref
    base_errors = [] if base_ok else [
        f"PR base is not the protected repository default branch: "
        f"observed={base_repo}:{base_ref} expected={repo.lower()}:{expected_base_ref}"
    ]
    final_pr = request(token, "GET", API + "/repos/" + repo + "/pulls/" + str(pr_number))
    final_head_sha = ((final_pr.get("head") or {}).get("sha"))
    head_stable = final_head_sha == expected_sha
    head_errors = [] if head_stable else [
        f"PR head changed during collection: final={final_head_sha} expected={expected_sha}"
    ]
    evidence = {
        "head_sha": ((pr.get("head") or {}).get("sha")),
        "final_head_sha": final_head_sha,
        "latest_push_actor": trusted_latest_push_actor,
        "reviewer_permissions": reviewer_permissions,
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
    if not base_ok:
        debt.append(_operator_debt("protected-base-hold", repo + "#" + str(pr_number), "; ".join(base_errors), [{"kind": "pull_request", "number": pr_number, "base_ref": base_ref, "base_repo": base_repo}]))
    if not head_stable:
        debt.append(_operator_debt("head-stability-hold", repo + "#" + str(pr_number), "; ".join(head_errors), [{"kind": "pull_request", "number": pr_number, "final_head_sha": final_head_sha}]))
    return {
        "schema_version": "github-ops.snapshot.v0.1",
        "repository": repo,
        "pull_request": pr_number,
        "expected_head_sha": expected_sha,
        "observed_head_sha": evidence["head_sha"],
        "final_observed_head_sha": final_head_sha,
        "observed_at": collected_at,
        "collector": {"mode": "read-only", "credential_source": "environment"},
        "policy": {"version": manifest.get("version"), "sha256": policy_sha256},
        "completeness": {
            "protection": "complete" if protection.get("complete") else "partial",
            "reviews": "complete" if not permission_errors else "partial",
            "workflows": "complete",
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
