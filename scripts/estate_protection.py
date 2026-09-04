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
from urllib.parse import quote
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

    def matches(pattern: str) -> bool | None:
        if not isinstance(pattern, str):
            return None
        if pattern in {"~ALL", "~DEFAULT_BRANCH"}:
            return True
        if any(ch in pattern for ch in "[]\\"):
            return None
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

    exclude_results = [matches(pattern) for pattern in exclude]
    if any(result is True for result in exclude_results):
        return False
    if any(result is None for result in exclude_results):
        return None
    if not include:
        return True
    include_results = [matches(pattern) for pattern in include]
    if any(result is True for result in include_results):
        return True
    if any(result is None for result in include_results):
        return None
    return False


def effective_default_branch_protection(token: str, repo: str) -> dict:
    repo_info = request(token, "GET", f"{API}/repos/{repo}")
    if not isinstance(repo_info, dict):
        return {"complete": False, "diagnostics": ["repository metadata malformed"], "repo": repo}
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
        if not isinstance(ruleset, dict):
            diagnostics.append("ruleset detail malformed")
            continue
        if ruleset.get("enforcement") != "active":
            continue
        applies = ref_condition_applies(ruleset, default_branch)
        if applies is None:
            diagnostics.append(f"ruleset {ruleset.get('id')} applicability indeterminate")
        elif applies:
            if "bypass_actors" not in ruleset:
                diagnostics.append(f"ruleset {ruleset.get('id')} bypass inventory unavailable")
            applicable.append(ruleset)
    encoded_branch = quote(default_branch, safe="")
    classic_state = "unknown"
    try:
        classic = request(token, "GET", f"{API}/repos/{repo}/branches/{encoded_branch}/protection", allow_404=True)
        if classic is None:
            classic_state = "absent"
        elif isinstance(classic, dict):
            classic_state = "observed"
        else:
            diagnostics.append("classic protection payload malformed")
            classic_state = "malformed"
            classic = None
    except Exception as exc:
        return {
            "complete": False,
            "diagnostics": [f"classic protection unreadable: {exc}"],
            "repo": repo,
            "default_branch": default_branch,
            "repository": repo_info,
            "rulesets": applicable,
            "classic": None,
            "classic_state": "denied_or_unreadable",
        }
    return {
        "complete": not diagnostics,
        "diagnostics": diagnostics,
        "repo": repo,
        "default_branch": default_branch,
        "repository": repo_info,
        "rulesets": applicable,
        "classic": classic,
        "classic_state": classic_state,
    }


def _required_check_identity(context: str, *, producer_kind: str, producer_id, source: str, field_present: bool = True) -> dict:
    if not field_present:
        producer_kind = "unknown"
        bound = None
    else:
        bound = producer_id is not None
        if not bound:
            producer_kind = "unspecified"
    return {
        "context": context,
        "producer": {
            "kind": producer_kind,
            "id": producer_id,
            "source": source,
            "bound": bound,
        },
    }


def _aggregate_effective(surface: dict) -> dict:
    aggregate = {
        "rule_types": set(),
        "review": {},
        "status_checks": [],
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
        ruleset_id = ruleset.get("id")
        for rule in ruleset.get("rules", []):
            rtype = rule.get("type")
            aggregate["rule_types"].add(rtype)
            params = rule.get("parameters") or {}
            if rtype == "pull_request":
                aggregate["review"] = merge_restrictive_policy(
                    aggregate["review"],
                    {k: v for k, v in params.items() if k in ALLOWED_REVIEW_KEYS},
                )
            elif rtype == "required_status_checks":
                for check in params.get("required_status_checks") or []:
                    context = check.get("context")
                    if context:
                        aggregate["status_checks"].append(
                            _required_check_identity(
                                context,
                                producer_kind="integration",
                                producer_id=check.get("integration_id"),
                                source=f"ruleset:{ruleset_id}:required_status_checks.integration_id",
                                field_present="integration_id" in check,
                            )
                        )
    classic = surface.get("classic") or {}
    if classic:
        if classic.get("allow_deletions", {}).get("enabled") is False:
            aggregate["rule_types"].add("deletion")
        if classic.get("allow_force_pushes", {}).get("enabled") is False:
            aggregate["rule_types"].add("non_fast_forward")
        if classic.get("required_linear_history", {}).get("enabled") is True:
            aggregate["rule_types"].add("required_linear_history")
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
                aggregate["status_checks"].append(
                    _required_check_identity(
                        context,
                        producer_kind="github_app",
                        producer_id=check.get("app_id"),
                        source="classic_branch_protection.required_status_checks.checks[].app_id",
                        field_present="app_id" in check,
                    )
                )
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



def read_reviewer_permissions(token: str, repo: str, reviews: list[dict]) -> tuple[dict[str, dict], list[str]]:
    permissions: dict[str, dict] = {}
    errors: list[str] = []
    reviewers = sorted({((r.get("user") or {}).get("login") or "").lower() for r in reviews} - {""})
    collected_at = datetime.now(timezone.utc).isoformat()
    for reviewer in reviewers:
        try:
            payload = request(token, "GET", f"{API}/repos/{repo}/collaborators/{reviewer}/permission")
            permission = (payload or {}).get("permission")
            if permission:
                permissions[reviewer] = {
                    "repository": repo,
                    "reviewer": reviewer,
                    "permission": permission,
                    "source": "repos/{repo}/collaborators/{username}/permission",
                    "collected_at": collected_at,
                    "inheritance": "unknown",
                }
            else:
                errors.append(f"reviewer permission unavailable: {reviewer}")
        except Exception as exc:
            errors.append(f"reviewer permission unreadable: {reviewer}: {exc}")
    return permissions, errors


def _permission_value(value) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("permission")
    return None


def evaluate_exact_head_approval(
    pr: dict,
    reviews: list[dict],
    expected_sha: str,
    latest_push_actor: str | None,
    reviewer_permissions: dict,
    required_count: int,
    effective_review: dict | None = None,
    review_decision: str | None = None,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    current = ((pr.get("head") or {}).get("sha"))
    if current != expected_sha:
        return False, [f"PR head mismatch: current={current} expected={expected_sha}"]
    if not latest_push_actor:
        errors.append("authoritative latest push actor evidence unavailable")
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
        if _permission_value(reviewer_permissions.get(reviewer)) not in REVIEW_ELIGIBLE_PERMISSIONS:
            continue
        eligible.add(reviewer)
    if len(eligible) < required_count:
        errors.append(
            f"eligible exact-head approvals below effective requirement: "
            f"observed={len(eligible)} required={required_count}"
        )
    effective_review = effective_review or {}
    stronger_reviewer_constraint = bool(
        effective_review.get("require_code_owner_review")
        or effective_review.get("required_reviewers")
    )
    if stronger_reviewer_constraint and review_decision != "APPROVED":
        errors.append(
            "authoritative GitHub review decision does not prove effective "
            "code-owner/required-reviewer constraints satisfied"
        )
    return not errors, errors


def read_review_gate_state(token: str, repo: str, pr_number: int) -> dict:
    owner, name = repo.split("/", 1)
    query = """
    query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          reviewDecision
          reviewThreads(first: 100, after: $cursor) {
            nodes { id isResolved isOutdated }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }
    """
    cursor = None
    threads: list[dict] = []
    review_decision = None
    while True:
        payload = request(
            token,
            "POST",
            f"{API}/graphql",
            {
                "query": query,
                "variables": {"owner": owner, "name": name, "number": pr_number, "cursor": cursor},
            },
        )
        if not isinstance(payload, dict) or payload.get("errors"):
            raise RuntimeError(f"review thread GraphQL response invalid: {(payload or {}).get('errors')}")
        pull = (((payload.get("data") or {}).get("repository") or {}).get("pullRequest"))
        if not isinstance(pull, dict):
            raise RuntimeError("pull request review state unavailable")
        if review_decision is None:
            review_decision = pull.get("reviewDecision")
        connection = pull.get("reviewThreads") or {}
        nodes = connection.get("nodes")
        page_info = connection.get("pageInfo") or {}
        if not isinstance(nodes, list) or "hasNextPage" not in page_info:
            raise RuntimeError("review thread pagination schema unavailable")
        for node in nodes:
            if not isinstance(node, dict) or not node.get("id") or "isResolved" not in node:
                raise RuntimeError("review thread node malformed")
            threads.append(
                {
                    "id": node.get("id"),
                    "is_resolved": bool(node.get("isResolved")),
                    "is_outdated": bool(node.get("isOutdated")),
                }
            )
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")
        if not cursor:
            raise RuntimeError("review thread pagination cursor missing")
    return {
        "collection_state": "complete",
        "review_decision": review_decision,
        "total_discovered": len(threads),
        "unresolved_current": sum(1 for t in threads if not t["is_resolved"] and not t["is_outdated"]),
        "unresolved_outdated": sum(1 for t in threads if not t["is_resolved"] and t["is_outdated"]),
        "threads": threads,
    }


def read_latest_push_evidence(token: str, repo: str, pr: dict, expected_sha: str) -> dict:
    head = pr.get("head") or {}
    head_repo = ((head.get("repo") or {}).get("full_name") or repo)
    head_ref = head.get("ref")
    if not head_ref:
        raise RuntimeError("PR head ref unavailable for push provenance")
    target_ref = f"refs/heads/{head_ref}"
    events = paginate(token, f"{API}/repos/{head_repo}/events")
    matches = []
    for event in events:
        if event.get("type") != "PushEvent":
            continue
        event_payload = event.get("payload") or {}
        resulting_sha = event_payload.get("head") or event_payload.get("after")
        if event_payload.get("ref") == target_ref and resulting_sha == expected_sha:
            actor = ((event.get("actor") or {}).get("login") or "").lower()
            if actor:
                matches.append(
                    {
                        "event_id": event.get("id"),
                        "repository": head_repo,
                        "ref": target_ref,
                        "resulting_head_sha": resulting_sha,
                        "event_type": "PushEvent",
                        "actor": actor,
                        "event_timestamp": event.get("created_at"),
                    }
                )
    actors = {item["actor"] for item in matches}
    if not matches:
        raise RuntimeError("authoritative push event for exact PR head not found")
    if len(actors) != 1:
        raise RuntimeError(f"ambiguous authoritative push actors for exact PR head: {sorted(actors)}")
    receipt_bytes = json.dumps(matches, sort_keys=True, separators=(",", ":")).encode()
    return {
        **max(matches, key=lambda item: (item.get("event_timestamp") or "", item.get("event_id") or "")),
        "source_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
    }


def read_required_check_evidence(token: str, repo: str, expected_sha: str) -> dict:
    check_runs = paginate_object_items(
        token,
        f"{API}/repos/{repo}/commits/{expected_sha}/check-runs?filter=latest",
        "check_runs",
    )
    statuses = paginate(token, f"{API}/repos/{repo}/commits/{expected_sha}/statuses")
    return {"check_runs": check_runs, "statuses": statuses}


def evaluate_required_checks(
    required_checks: list[dict],
    check_runs: list[dict],
    statuses: list[dict],
    expected_sha: str,
) -> tuple[str, list[str]]:
    errors: list[str] = []
    indeterminate: list[str] = []
    for required in required_checks:
        context = required.get("context")
        producer = required.get("producer") or {}
        bound = producer.get("bound")
        producer_id = producer.get("id")
        if not context:
            indeterminate.append("required check context unavailable")
            continue
        if bound is None:
            indeterminate.append(f"required check producer visibility unavailable: {context}")
            continue
        exact_runs = [
            run for run in check_runs
            if run.get("name") == context and run.get("head_sha") == expected_sha
        ]
        if bound:
            matching = [
                run for run in exact_runs
                if ((run.get("app") or {}).get("id")) == producer_id
            ]
            if not matching:
                if exact_runs:
                    errors.append(
                        f"required check producer mismatch: {context} expected_producer={producer_id}"
                    )
                else:
                    errors.append(f"required check missing: {context}")
                continue
            latest = max(
                matching,
                key=lambda run: (
                    run.get("completed_at") or run.get("started_at") or "",
                    int(run.get("id") or 0),
                ),
            )
            if latest.get("status") != "completed" or latest.get("conclusion") != "success":
                errors.append(
                    f"required check non-success: {context} "
                    f"status={latest.get('status')} conclusion={latest.get('conclusion')}"
                )
            continue
        matching_statuses = [status for status in statuses if status.get("context") == context]
        observations = [
            ("check_run", run.get("status") == "completed" and run.get("conclusion") == "success")
            for run in exact_runs
        ] + [
            ("commit_status", status.get("state") == "success")
            for status in matching_statuses
        ]
        if not observations:
            errors.append(f"required check missing: {context}")
        elif not all(ok for _, ok in observations):
            errors.append(f"required check has non-success exact-head evidence: {context}")
    if errors:
        return "UNSATISFIED", errors + indeterminate
    if indeterminate:
        return "INDETERMINATE", indeterminate
    return "SATISFIED", []


def read_exact_head_approval(token: str, repo: str, pr_number: int, expected_sha: str) -> tuple[bool, list[str]]:
    pr = request(token, "GET", f"{API}/repos/{repo}/pulls/{pr_number}")
    reviews = paginate(token, f"{API}/repos/{repo}/pulls/{pr_number}/reviews")
    permissions, permission_errors = read_reviewer_permissions(token, repo, reviews)
    try:
        push = read_latest_push_evidence(token, repo, pr, expected_sha)
        latest_actor = push.get("actor")
        push_errors: list[str] = []
    except Exception as exc:
        latest_actor = None
        push_errors = [str(exc)]
    ok, errors = evaluate_exact_head_approval(pr, reviews, expected_sha, latest_actor, permissions, 1)
    all_errors = permission_errors + push_errors + errors
    return ok and not all_errors, all_errors


def evaluate_latest_runs(
    runs: list[dict],
    required_workflows: list[str],
    expected_sha: str | None = None,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    for name in required_workflows:
        candidates = [r for r in runs if r.get("name") == name]
        if not candidates:
            errors.append(f"required workflow missing: {name}")
            continue
        if expected_sha is not None:
            wrong_scope = [
                r for r in candidates
                if r.get("head_sha") != expected_sha or r.get("event") != "pull_request"
            ]
            if wrong_scope:
                errors.append(f"workflow scope mismatch for {name}")
                continue
            identities = {
                (r.get("workflow_id"), r.get("path"))
                for r in candidates
            }
            if any(workflow_id is None or path is None for workflow_id, path in identities):
                errors.append(f"workflow identity unavailable: {name}")
                continue
            if len(identities) != 1:
                errors.append(f"workflow identity ambiguous: {name}")
                continue
        latest = max(
            candidates,
            key=lambda r: (
                int(r.get("run_number") or 0),
                r.get("created_at") or "",
                int(r.get("id") or 0),
                int(r.get("run_attempt") or 1),
            ),
        )
        if latest.get("status") != "completed" or latest.get("conclusion") != "success":
            errors.append(
                f"latest workflow non-success: {name} "
                f"status={latest.get('status')} conclusion={latest.get('conclusion')}"
            )
    return not errors, errors


def latest_run_status(token: str, repo: str, sha: str, required_workflows: list[str]) -> tuple[bool, list[str]]:
    runs = paginate_object_items(token, f"{API}/repos/{repo}/actions/runs?head_sha={sha}&event=pull_request", "workflow_runs")
    return evaluate_latest_runs(runs, required_workflows, sha)

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
    governed_repo_ok = repo in (manifest.get("repositories") or [])

    pr = request(token, "GET", API + "/repos/" + repo + "/pulls/" + str(pr_number))
    reviews = paginate(token, API + "/repos/" + repo + "/pulls/" + str(pr_number) + "/reviews")
    reviewer_permissions, permission_errors = read_reviewer_permissions(token, repo, reviews)

    unknown_reasons: list[str] = list(permission_errors)
    try:
        review_gate = read_review_gate_state(token, repo, pr_number)
        review_gate_error = None
    except Exception as exc:
        review_gate = {
            "collection_state": "unknown",
            "review_decision": None,
            "total_discovered": None,
            "unresolved_current": None,
            "unresolved_outdated": None,
            "threads": [],
        }
        review_gate_error = str(exc)
        unknown_reasons.append("review thread evidence unavailable: " + review_gate_error)

    try:
        push_evidence = read_latest_push_evidence(token, repo, pr, expected_sha)
        push_error = None
    except Exception as exc:
        push_evidence = None
        push_error = str(exc)
        unknown_reasons.append("latest push provenance unavailable: " + push_error)

    if trusted_latest_push_actor and push_evidence:
        if trusted_latest_push_actor.lower() != (push_evidence.get("actor") or "").lower():
            unknown_reasons.append(
                "caller-supplied latest push actor conflicts with authoritative GitHub push evidence"
            )

    try:
        runs = paginate_object_items(
            token,
            API + "/repos/" + repo + "/actions/runs?head_sha=" + expected_sha + "&event=pull_request",
            "workflow_runs",
        )
        workflow_collection_error = None
    except Exception as exc:
        runs = []
        workflow_collection_error = str(exc)
        unknown_reasons.append("workflow evidence unavailable: " + workflow_collection_error)

    protection = effective_default_branch_protection(token, repo)
    aggregate = (
        _aggregate_effective(protection)
        if protection.get("complete")
        else {"review": {}, "status_checks": [], "rule_types": set(), "bypass_actors": []}
    )
    if not protection.get("complete"):
        unknown_reasons.extend(protection.get("diagnostics") or ["protection evidence incomplete"])

    try:
        check_evidence = read_required_check_evidence(token, repo, expected_sha)
        check_collection_error = None
    except Exception as exc:
        check_evidence = {"check_runs": [], "statuses": []}
        check_collection_error = str(exc)
        unknown_reasons.append("required-check evidence unavailable: " + check_collection_error)

    required_count = int((aggregate.get("review") or {}).get("required_approving_review_count") or 0)
    authoritative_push_actor = (push_evidence or {}).get("actor")
    approval_ok, approval_errors = evaluate_exact_head_approval(
        pr,
        reviews,
        expected_sha,
        authoritative_push_actor,
        reviewer_permissions,
        required_count,
        aggregate.get("review") or {},
        review_gate.get("review_decision"),
    )
    if permission_errors or push_error or review_gate_error:
        approval_ok = False

    if workflow_collection_error:
        workflow_ok = False
        workflow_errors = ["workflow evidence collection incomplete"]
    else:
        workflow_ok, workflow_errors = evaluate_latest_runs(runs, required_workflows, expected_sha)

    protection_ok, protection_errors = validate_effective_protection(protection, manifest)

    if check_collection_error or not protection.get("complete"):
        check_outcome = "INDETERMINATE"
        check_errors = ["required-check evaluation lacks complete protection/check evidence"]
    else:
        check_outcome, check_errors = evaluate_required_checks(
            aggregate.get("status_checks") or [],
            check_evidence.get("check_runs") or [],
            check_evidence.get("statuses") or [],
            expected_sha,
        )
        if check_outcome == "INDETERMINATE":
            unknown_reasons.extend(check_errors)

    thread_errors: list[str] = []
    threads_ok = review_gate_error is None
    if threads_ok:
        if int(review_gate.get("unresolved_current") or 0) > 0:
            threads_ok = False
            thread_errors.append(
                f"unresolved current review threads: {review_gate.get('unresolved_current')}"
            )
        if int(review_gate.get("unresolved_outdated") or 0) > 0:
            threads_ok = False
            thread_errors.append(
                f"unresolved outdated review threads require classification: "
                f"{review_gate.get('unresolved_outdated')}"
            )

    base = pr.get("base") or {}
    base_repo = ((base.get("repo") or {}).get("full_name") or "").lower()
    base_ref = base.get("ref")
    expected_base_ref = protection.get("default_branch")
    base_ok = bool(expected_base_ref) and base_repo == repo.lower() and base_ref == expected_base_ref
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
        "latest_push": push_evidence,
        "caller_supplied_latest_push_actor": trusted_latest_push_actor,
        "reviewer_permissions": reviewer_permissions,
        "review_ids": [r.get("id") for r in reviews if r.get("id") is not None],
        "review_gate": review_gate,
        "required_checks": aggregate.get("status_checks") or [],
        "check_runs": [
            {
                "id": r.get("id"),
                "name": r.get("name"),
                "head_sha": r.get("head_sha"),
                "status": r.get("status"),
                "conclusion": r.get("conclusion"),
                "app_id": ((r.get("app") or {}).get("id")),
            }
            for r in check_evidence.get("check_runs") or []
        ],
        "workflow_runs": [
            {
                "id": r.get("id"),
                "name": r.get("name"),
                "workflow_id": r.get("workflow_id"),
                "path": r.get("path"),
                "event": r.get("event"),
                "run_number": r.get("run_number"),
                "run_attempt": r.get("run_attempt"),
                "status": r.get("status"),
                "conclusion": r.get("conclusion"),
                "head_sha": r.get("head_sha"),
            }
            for r in runs
        ],
    }

    debt: list[dict] = []
    if not governed_repo_ok:
        debt.append(_operator_debt(
            "governed-repository-hold", repo, "snapshot repository is outside the manifest",
            [{"kind": "policy", "repository": repo}],
        ))
    if not protection_ok:
        debt.append(_operator_debt(
            "protection-hold", repo, "; ".join(protection_errors),
            [{"kind": "protection", "repository": repo, "classic_state": protection.get("classic_state")}],
        ))
    if not approval_ok:
        debt.append(_operator_debt(
            "exact-head-review-hold", repo + "#" + str(pr_number),
            "; ".join(permission_errors + approval_errors + ([push_error] if push_error else []) + ([review_gate_error] if review_gate_error else [])),
            [{"kind": "pull_request", "number": pr_number, "head_sha": evidence["head_sha"]}],
        ))
    if not threads_ok:
        debt.append(_operator_debt(
            "review-thread-hold", repo + "#" + str(pr_number),
            "; ".join(thread_errors or ["review thread evidence incomplete"]),
            [{"kind": "review_threads", "state": review_gate.get("collection_state")}],
        ))
    if check_outcome != "SATISFIED":
        debt.append(_operator_debt(
            "required-check-hold", expected_sha, "; ".join(check_errors),
            [{"kind": "required_check", **item} for item in evidence["required_checks"]],
        ))
    if not workflow_ok:
        debt.append(_operator_debt(
            "workflow-hold", expected_sha, "; ".join(workflow_errors),
            [{"kind": "workflow_run", **item} for item in evidence["workflow_runs"]],
        ))
    if not base_ok:
        debt.append(_operator_debt(
            "protected-base-hold", repo + "#" + str(pr_number), "; ".join(base_errors),
            [{"kind": "pull_request", "number": pr_number, "base_ref": base_ref, "base_repo": base_repo}],
        ))
    if not head_stable:
        debt.append(_operator_debt(
            "head-stability-hold", repo + "#" + str(pr_number), "; ".join(head_errors),
            [{"kind": "pull_request", "number": pr_number, "final_head_sha": final_head_sha}],
        ))

    definite_failures = []
    if not governed_repo_ok:
        definite_failures.append("repository outside manifest")
    if protection.get("complete") and not protection_ok:
        definite_failures.append("protection control unsatisfied")
    if not permission_errors and not push_error and not review_gate_error and not approval_ok:
        definite_failures.append("review control unsatisfied")
    if review_gate_error is None and not threads_ok:
        definite_failures.append("review thread control unsatisfied")
    if check_collection_error is None and protection.get("complete") and check_outcome == "UNSATISFIED":
        definite_failures.append("required check control unsatisfied")
    if workflow_collection_error is None and not workflow_ok:
        definite_failures.append("workflow control unsatisfied")
    if expected_base_ref and not base_ok:
        definite_failures.append("governed base control unsatisfied")
    if not head_stable:
        definite_failures.append("exact head became stale")

    if not head_stable:
        evidence_state = "STALE"
    elif unknown_reasons:
        evidence_state = "UNKNOWN"
    elif not governed_repo_ok:
        evidence_state = "HOLD"
    else:
        evidence_state = "VERIFIED"

    if definite_failures:
        control_outcome = "UNSATISFIED"
    elif unknown_reasons:
        control_outcome = "INDETERMINATE"
    else:
        control_outcome = "SATISFIED"

    readiness_status = (
        "PASS"
        if evidence_state == "VERIFIED"
        and control_outcome == "SATISFIED"
        and not debt
        and head_stable
        else "HOLD"
    )

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
        "evidence_state": evidence_state,
        "control_outcome": control_outcome,
        "readiness_status": readiness_status,
        "completeness": {
            "protection": "complete" if protection.get("complete") else "partial",
            "reviews": "complete" if not permission_errors and not review_gate_error else "partial",
            "checks": "complete" if not check_collection_error else "partial",
            "workflows": "complete" if not workflow_collection_error else "partial",
            "push_provenance": "complete" if not push_error else "partial",
            "dependencies_security": "not_collected",
        },
        "evidence": evidence,
        "operator_debt": debt,
        "status": readiness_status,
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
