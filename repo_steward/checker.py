from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Verdict(str, Enum):
    PASS = "PASS"
    HOLD = "HOLD"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


@dataclass
class Finding:
    code: str
    verdict: Verdict
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class RepoReport:
    repository: str
    verdict: Verdict
    findings: list[Finding]

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "verdict": self.verdict.value,
            "findings": [
                {"code": f.code, "verdict": f.verdict.value, "message": f.message, "evidence": f.evidence}
                for f in self.findings
            ],
        }


class GitHubReader:
    """GET-only GitHub client. No mutation methods exist in this class."""

    def __init__(self, token: str | None = None, api_base: str = "https://api.github.com") -> None:
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.api_base = api_base.rstrip("/")

    def get(self, path: str) -> Any:
        req = urllib.request.Request(f"{self.api_base}{path}", headers={"Accept": "application/vnd.github+json"})
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"github GET {path} failed: {exc.code}") from exc

    def get_optional(self, path: str) -> tuple[Any | None, int | None]:
        req = urllib.request.Request(f"{self.api_base}{path}", headers={"Accept": "application/vnd.github+json"})
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                return json.load(response), response.status
        except urllib.error.HTTPError as exc:
            return None, exc.code


class RepoChecker:
    def __init__(self, policy_path: str | Path = "manifests/repo-steward-policy.json", reader: GitHubReader | None = None) -> None:
        self.policy_path = Path(policy_path)
        self.policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        blueprint_path = self.policy_path.parent / "repo-steward-platform-ruleset-blueprint.json"
        self.ruleset_blueprint = (
            json.loads(blueprint_path.read_text(encoding="utf-8"))
            if blueprint_path.is_file()
            else None
        )
        self.reader = reader or GitHubReader()

    @staticmethod
    def _combine(findings: list[Finding]) -> Verdict:
        levels = {Verdict.FAIL: 3, Verdict.HOLD: 2, Verdict.UNKNOWN: 1, Verdict.PASS: 0}
        return max((f.verdict for f in findings), key=lambda v: levels[v], default=Verdict.UNKNOWN)

    def _get_paginated(self, path: str, list_key: str | None = None) -> list[dict[str, Any]]:
        page = 1
        out: list[dict[str, Any]] = []
        while True:
            separator = "&" if "?" in path else "?"
            payload = self.reader.get(f"{path}{separator}per_page=100&page={page}")
            items = payload.get(list_key, []) if list_key else payload
            if not isinstance(items, list):
                raise RuntimeError(f"github pagination payload is not a list: {path}")
            out.extend(items)
            if len(items) < 100:
                return out
            page += 1
            if page > 100:
                raise RuntimeError(f"github pagination exceeded safety bound: {path}")

    def _review_contributor_logins(self, full_name: str, pr_number: int) -> set[str] | None:
        try:
            commits = self._get_paginated(f"/repos/{full_name}/pulls/{pr_number}/commits")
        except RuntimeError:
            return None
        contributors: set[str] = set()
        for commit in commits:
            for field in ("author", "committer"):
                user = commit.get(field)
                login = str((user or {}).get("login") or "").lower()
                if not isinstance(user, dict) or not login or str(user.get("type") or "") != "User":
                    return None
                contributors.add(login)
            message = str(((commit.get("commit") or {}).get("message") or ""))
            if any(line.lower().startswith("co-authored-by:") for line in message.splitlines()):
                return None
        return contributors

    def _approved_human_reviewer_ids(self) -> set[int]:
        configured = self.policy.get("approved_human_reviewer_ids")
        if not isinstance(configured, list):
            return set()
        return {value for value in configured if isinstance(value, int) and value > 0}

    def _is_independent_reviewer(
        self,
        full_name: str,
        review: dict[str, Any],
        pr: dict[str, Any],
        contributors: set[str],
    ) -> bool:
        user = review.get("user") or {}
        login = str(user.get("login") or "").lower()
        author = str((pr.get("user") or {}).get("login") or "").lower()
        reviewer_id = user.get("id")
        if not login or login == author or login in contributors:
            return False
        if str(user.get("type") or "") != "User" or reviewer_id not in self._approved_human_reviewer_ids():
            return False
        if login.endswith("[bot]") or login.endswith("-bot") or login in {"github-actions", "dependabot"}:
            return False
        permission, status = self.reader.get_optional(f"/repos/{full_name}/collaborators/{login}/permission")
        if status != 200 or not isinstance(permission, dict):
            return False
        return str(permission.get("permission") or "").lower() in {"admin", "maintain", "write"}

    def _check_exact_head_review(self, full_name: str, pr: dict[str, Any], sha: str) -> list[Finding]:
        number = pr["number"]
        findings: list[Finding] = []
        comments = self._get_paginated(f"/repos/{full_name}/issues/{number}/comments")
        request_bound = False
        for comment in comments:
            body = (comment.get("body") or "").strip()
            association = str(comment.get("author_association") or "").upper()
            if body.lower().startswith("@codex review") and sha in body and association in {"OWNER", "MEMBER", "COLLABORATOR"}:
                request_bound = True
                break
        findings.append(Finding(
            "EXACT_HEAD_REVIEW_REQUEST_BOUND" if request_bound else "EXACT_HEAD_REVIEW_REQUEST_ABSENT",
            Verdict.PASS if request_bound else Verdict.HOLD,
            f"PR #{number} {'has' if request_bound else 'does not have'} an authenticated review request naming its current head.",
            {"sha": sha},
        ))

        reviews = self._get_paginated(f"/repos/{full_name}/pulls/{number}/reviews")
        exact = [r for r in reviews if r.get("commit_id") == sha and str(r.get("state", "")).upper() != "PENDING"]
        if not exact:
            findings.append(Finding("EXACT_HEAD_REVIEW_NOT_SUBMITTED", Verdict.HOLD, f"PR #{number} has no submitted review bound to its current head.", {"sha": sha}))
            return findings

        states = {str(r.get("state", "")).upper() for r in exact}
        reviewers = sorted({str((r.get("user") or {}).get("login") or "unknown") for r in exact})
        if "CHANGES_REQUESTED" in states:
            findings.append(Finding("EXACT_HEAD_REVIEW_CHANGES_REQUESTED", Verdict.FAIL, f"PR #{number} has a current-head review requesting changes.", {"sha": sha, "states": sorted(states), "reviewers": reviewers}))
            return findings

        contributors = self._review_contributor_logins(full_name, number)
        if contributors is None:
            findings.append(Finding(
                "EXACT_HEAD_REVIEW_CONTRIBUTOR_BINDING_UNOBSERVABLE",
                Verdict.HOLD,
                f"PR #{number} review contributors could not be bound, so reviewer independence cannot be established.",
                {"sha": sha},
            ))
            return findings

        independent_approvals = [
            r
            for r in exact
            if str(r.get("state", "")).upper() == "APPROVED"
            and self._is_independent_reviewer(full_name, r, pr, contributors)
        ]
        if independent_approvals:
            findings.append(Finding("EXACT_HEAD_REVIEW_APPROVED", Verdict.PASS, f"PR #{number} has an independent approving review bound to its current head.", {"sha": sha, "reviewers": sorted({(r.get('user') or {}).get('login', 'unknown') for r in independent_approvals})}))
        elif "APPROVED" in states:
            findings.append(Finding("EXACT_HEAD_REVIEW_NOT_INDEPENDENT", Verdict.HOLD, f"PR #{number} has an approval on the current head, but reviewer independence is not established.", {"sha": sha, "reviewers": reviewers}))
        else:
            findings.append(Finding("EXACT_HEAD_REVIEW_NONAPPROVING", Verdict.HOLD, f"PR #{number} has current-head review activity, but no independent approving review.", {"sha": sha, "states": sorted(states), "reviewers": reviewers}))
        return findings

    @staticmethod
    def _required_check_names(protection: dict[str, Any]) -> set[str]:
        checks = protection.get("required_status_checks")
        if not isinstance(checks, dict):
            return set()
        names = {str(x) for x in checks.get("contexts", []) if x}
        for item in checks.get("checks", []) or []:
            if isinstance(item, dict) and item.get("context"):
                names.add(str(item["context"]))
        return names

    def _trusted_check_producers(self) -> tuple[dict[str, int] | None, str | None]:
        if not isinstance(self.ruleset_blueprint, dict):
            return None, "Repo Steward ruleset blueprint is unavailable."
        dual_control = self.ruleset_blueprint.get("dual_control")
        if not isinstance(dual_control, dict):
            return None, "Repo Steward dual-control configuration is unavailable."
        check_name = dual_control.get("required_check_name")
        producer = dual_control.get("trusted_producer")
        if not isinstance(check_name, str) or not check_name or not isinstance(producer, dict):
            return None, "Repo Steward trusted-producer configuration is incomplete."
        if producer.get("binding_required") is not True or producer.get("state") != "BOUND":
            return None, "Repo Steward trusted producer remains unbound; platform protection cannot be certified."
        if producer.get("type") != "GITHUB_APP" or not isinstance(producer.get("app_id"), int) or producer["app_id"] <= 0:
            return None, "Repo Steward trusted GitHub App identity is invalid."
        return {check_name: producer["app_id"]}, None

    @staticmethod
    def _producer_bound(entries: list[dict[str, Any]], check_name: str, app_id: int, field: str) -> bool:
        return any(
            str(entry.get("context") or "") == check_name and entry.get(field) == app_id
            for entry in entries
            if isinstance(entry, dict)
        )

    def _evaluate_classic_protection(
        self,
        protection: dict[str, Any],
        required_checks: set[str],
        trusted_producers: dict[str, int],
    ) -> tuple[list[str], list[str]]:
        failures: list[str] = []
        holds: list[str] = []
        pr = protection.get("required_pull_request_reviews")
        if not isinstance(pr, dict):
            failures.append("pull request reviews are not required")
        else:
            if int(pr.get("required_approving_review_count") or 0) < 1:
                failures.append("minimum approving review count is below 1")
            if pr.get("dismiss_stale_reviews") is not True:
                failures.append("stale approvals are not dismissed")
            if pr.get("require_last_push_approval") is not True:
                failures.append("latest-push approval is not required")
            bypass = pr.get("bypass_pull_request_allowances")
            if isinstance(bypass, dict) and any(bypass.get(k) for k in ("users", "teams", "apps")):
                failures.append("pull-request bypass actors are configured")

        checks = protection.get("required_status_checks")
        if not isinstance(checks, dict):
            failures.append("required status checks are absent")
        else:
            if checks.get("strict") is not True:
                failures.append("branch-up-to-date status-check enforcement is disabled")
            observed = self._required_check_names(protection)
            missing = sorted(required_checks - observed)
            if missing:
                failures.append(f"required check identities are not enforced: {missing}")
            entries = [item for item in checks.get("checks", []) or [] if isinstance(item, dict)]
            for name, app_id in trusted_producers.items():
                if not self._producer_bound(entries, name, app_id, "app_id"):
                    failures.append(f"trusted producer binding is not enforced for required check: {name}")

        conversations = protection.get("required_conversation_resolution")
        if not isinstance(conversations, dict) or conversations.get("enabled") is not True:
            failures.append("conversation resolution is not required")

        for key, label in (("allow_force_pushes", "force-push"), ("allow_deletions", "deletion")):
            control = protection.get(key)
            if not isinstance(control, dict) or "enabled" not in control:
                holds.append(f"{label} control is not observable")
            elif control.get("enabled") is True:
                failures.append(f"{label} is allowed")

        admins = protection.get("enforce_admins")
        if not isinstance(admins, dict) or "enabled" not in admins:
            holds.append("administrator enforcement is not observable")
        elif admins.get("enabled") is not True:
            failures.append("administrators can bypass branch protection")

        restrictions = protection.get("restrictions")
        if isinstance(restrictions, dict) and any(restrictions.get(k) for k in ("users", "teams", "apps")):
            failures.append("named push actors are configured")
        return failures, holds

    @staticmethod
    def _github_ref_pattern_matches(pattern: Any, ref: str) -> bool:
        value = str(pattern)
        if value == "~DEFAULT_BRANCH":
            return True
        expression: list[str] = []
        index = 0
        while index < len(value):
            char = value[index]
            if char == "*" and index + 1 < len(value) and value[index + 1] == "*":
                expression.append(".*")
                index += 2
            elif char == "*":
                expression.append("[^/]*")
                index += 1
            elif char == "?":
                expression.append("[^/]")
                index += 1
            else:
                expression.append(re.escape(char))
                index += 1
        return re.fullmatch("".join(expression), ref) is not None

    @classmethod
    def _ruleset_applies_to_branch(cls, detail: dict[str, Any], branch: str) -> bool | None:
        conditions = detail.get("conditions")
        if not isinstance(conditions, dict):
            return None
        ref_name = conditions.get("ref_name")
        if not isinstance(ref_name, dict):
            return None
        includes = ref_name.get("include")
        excludes = ref_name.get("exclude")
        if not isinstance(includes, list) or not isinstance(excludes, list):
            return None
        ref = f"refs/heads/{branch}"

        return (
            any(cls._github_ref_pattern_matches(pattern, ref) for pattern in includes)
            and not any(cls._github_ref_pattern_matches(pattern, ref) for pattern in excludes)
        )

    def _evaluate_rulesets(
        self,
        full_name: str,
        default_branch: str,
        required_checks: set[str],
        trusted_producers: dict[str, int],
    ) -> tuple[list[str], list[str]]:
        summaries, status = self.reader.get_optional(f"/repos/{full_name}/rulesets")
        if status != 200 or not isinstance(summaries, list):
            return [], ["applicable rulesets are not observable"]
        active = [r for r in summaries if r.get("enforcement") == "active" and r.get("target") == "branch"]
        if not active:
            return ["no active branch ruleset is observable"], []

        applicable: list[dict[str, Any]] = []
        holds: list[str] = []
        for summary in active:
            detail, detail_status = self.reader.get_optional(f"/repos/{full_name}/rulesets/{summary.get('id')}")
            if detail_status != 200 or not isinstance(detail, dict):
                holds.append(f"active ruleset {summary.get('id')} could not be inspected")
                continue
            applies = self._ruleset_applies_to_branch(detail, default_branch)
            if applies is None:
                holds.append(f"active ruleset {summary.get('id')} has unobservable branch applicability")
            elif applies:
                applicable.append(detail)

        if not applicable:
            return [f"no active branch ruleset is explicitly applicable to {default_branch}"], holds

        combined_types: set[str] = set()
        check_names: set[str] = set()
        check_entries: list[dict[str, Any]] = []
        pr_ok = False
        failures: list[str] = []
        for detail in applicable:
            if detail.get("bypass_actors"):
                failures.append("active applicable ruleset contains bypass actors")
                continue
            for rule in detail.get("rules", []) or []:
                if not isinstance(rule, dict):
                    continue
                rule_type = str(rule.get("type") or "")
                combined_types.add(rule_type)
                params = rule.get("parameters") or {}
                if rule_type == "pull_request":
                    pr_ok = pr_ok or (
                        int(params.get("required_approving_review_count") or 0) >= 1
                        and params.get("dismiss_stale_reviews_on_push") is True
                        and params.get("require_last_push_approval") is True
                        and params.get("required_review_thread_resolution") is True
                    )
                elif rule_type == "required_status_checks" and params.get("strict_required_status_checks_policy") is True:
                    entries = [x for x in params.get("required_status_checks", []) or [] if isinstance(x, dict)]
                    check_entries.extend(entries)
                    check_names.update(str(x.get("context")) for x in entries if x.get("context"))

        if "deletion" not in combined_types:
            failures.append("ruleset does not block deletion")
        if "non_fast_forward" not in combined_types:
            failures.append("ruleset does not block force-push/non-fast-forward updates")
        if not pr_ok:
            failures.append("ruleset pull-request controls do not meet the review baseline")
        missing = sorted(required_checks - check_names)
        if missing:
            failures.append(f"ruleset required check identities are not enforced: {missing}")
        for name, app_id in trusted_producers.items():
            if not self._producer_bound(check_entries, name, app_id, "integration_id"):
                failures.append(f"ruleset trusted producer binding is not enforced for required check: {name}")
        return failures, holds

    def _check_platform_protection(self, full_name: str, default_branch: str, branch: dict[str, Any], required_checks: set[str]) -> list[Finding]:
        if branch.get("protected") is False:
            return [Finding("PLATFORM_PROTECTION_FAIL", Verdict.FAIL, f"Default branch `{default_branch}` is unprotected; direct platform bypass remains possible.")]
        if branch.get("protected") is not True:
            return [Finding("PLATFORM_PROTECTION_HOLD", Verdict.HOLD, f"Protection state for `{default_branch}` could not be verified.")]

        trusted_producers, producer_error = self._trusted_check_producers()
        if producer_error or trusted_producers is None:
            return [Finding(
                "PLATFORM_PROTECTION_HOLD",
                Verdict.HOLD,
                f"Default branch {default_branch} protection cannot be certified until the Repo Steward trusted producer is bound.",
                {"reason": producer_error},
            )]
        required_checks = required_checks | set(trusted_producers)

        protection, status = self.reader.get_optional(f"/repos/{full_name}/branches/{default_branch}/protection")
        if status == 200 and isinstance(protection, dict):
            failures, holds = self._evaluate_classic_protection(protection, required_checks, trusted_producers)
        else:
            failures, holds = self._evaluate_rulesets(full_name, default_branch, required_checks, trusted_producers)

        if failures:
            return [Finding("PLATFORM_PROTECTION_FAIL", Verdict.FAIL, f"`{default_branch}` protection contradicts required policy.", {"failures": failures, "holds": holds})]
        if holds:
            return [Finding("PLATFORM_PROTECTION_HOLD", Verdict.HOLD, f"`{default_branch}` protection is present but cannot yet be completely certified.", {"holds": holds})]
        return [Finding("PLATFORM_PROTECTION_PASS", Verdict.PASS, f"`{default_branch}` effective protection satisfies the observable Repo Steward baseline.")]

    def _check_required_workflow_runs(self, full_name: str, pr_number: int, sha: str, required: set[str]) -> Finding:
        runs = self._get_paginated(f"/repos/{full_name}/actions/runs?head_sha={sha}&event=pull_request", "workflow_runs")
        by_name: dict[str, list[dict[str, Any]]] = {}
        for run in runs:
            by_name.setdefault(str(run.get("name") or ""), []).append(run)
        missing = sorted(name for name in required if name not in by_name)
        pending = sorted(name for name in required if any(r.get("status") != "completed" for r in by_name.get(name, [])))
        failed = sorted(name for name in required if name in by_name and not any(r.get("status") == "completed" and r.get("conclusion") == "success" for r in by_name[name]))
        if missing:
            return Finding("PR_CI_REQUIRED_WORKFLOW_ABSENT", Verdict.HOLD, f"PR #{pr_number} is missing required workflow runs on its current head.", {"sha": sha, "workflows": missing})
        if pending:
            return Finding("PR_CI_PENDING", Verdict.HOLD, f"PR #{pr_number} has pending required workflows.", {"sha": sha, "workflows": pending})
        if failed:
            return Finding("PR_CI_FAILED", Verdict.FAIL, f"PR #{pr_number} lacks a successful completed run for required workflows.", {"sha": sha, "workflows": failed})
        return Finding("PR_CI_GREEN", Verdict.PASS, f"PR #{pr_number} has successful completed runs for every configured required workflow on its current head.", {"sha": sha, "workflows": sorted(required)})

    def check_repo(self, repo_cfg: dict[str, Any]) -> RepoReport:
        full_name = repo_cfg["repository"]
        findings: list[Finding] = []
        repo = self.reader.get(f"/repos/{full_name}")
        default_branch = repo.get("default_branch")
        if not default_branch:
            findings.append(Finding("DEFAULT_BRANCH_UNKNOWN", Verdict.FAIL, "Repository has no observable default branch."))
            return RepoReport(full_name, self._combine(findings), findings)

        branch = self.reader.get(f"/repos/{full_name}/branches/{default_branch}")
        head_sha = branch.get("commit", {}).get("sha")
        if not head_sha:
            findings.append(Finding("HEAD_UNKNOWN", Verdict.FAIL, "Default-branch head SHA could not be established."))
        else:
            findings.append(Finding("HEAD_BOUND", Verdict.PASS, "Default-branch head established.", {"sha": head_sha}))

        required_workflows = set(repo_cfg.get("required_workflows", []))
        required_checks = set(repo_cfg.get("required_status_checks", [])) or required_workflows
        if repo_cfg.get("require_protected_default_branch", False):
            findings.extend(self._check_platform_protection(full_name, default_branch, branch, required_checks))

        workflows = self.reader.get(f"/repos/{full_name}/actions/workflows").get("workflows", [])
        names = {w.get("name") for w in workflows}
        for required in required_workflows:
            findings.append(Finding("WORKFLOW_PRESENT" if required in names else "WORKFLOW_MISSING", Verdict.PASS if required in names else Verdict.FAIL, f"Required workflow {'present' if required in names else 'missing'}: {required}"))

        prs = self._get_paginated(f"/repos/{full_name}/pulls?state=open")
        for pr in prs:
            sha = pr.get("head", {}).get("sha")
            if not sha:
                findings.append(Finding("PR_HEAD_UNKNOWN", Verdict.FAIL, f"PR #{pr.get('number')} has no observable head SHA."))
                continue
            if repo_cfg.get("require_ci", True):
                findings.append(self._check_required_workflow_runs(full_name, pr["number"], sha, required_workflows))
            if repo_cfg.get("require_exact_head_review", False):
                findings.extend(self._check_exact_head_review(full_name, pr, sha))

        return RepoReport(full_name, self._combine(findings), findings)

    def check_all(self) -> dict[str, Any]:
        reports = [self.check_repo(cfg) for cfg in self.policy["repositories"] if cfg.get("enabled", True)]
        overall = self._combine([Finding("REPO", report.verdict, report.repository) for report in reports])
        return {"schema_version": "0.1.0", "overall": overall.value, "reports": [report.as_dict() for report in reports]}
