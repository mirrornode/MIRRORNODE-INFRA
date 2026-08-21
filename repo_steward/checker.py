from __future__ import annotations

import json
import os
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
        self.policy = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        self.reader = reader or GitHubReader()

    @staticmethod
    def _combine(findings: list[Finding]) -> Verdict:
        levels = {Verdict.FAIL: 3, Verdict.HOLD: 2, Verdict.UNKNOWN: 1, Verdict.PASS: 0}
        return max((f.verdict for f in findings), key=lambda v: levels[v], default=Verdict.UNKNOWN)

    def _check_exact_head_review(self, full_name: str, pr: dict[str, Any], sha: str) -> list[Finding]:
        number = pr["number"]
        findings: list[Finding] = []
        comments = self.reader.get(f"/repos/{full_name}/issues/{number}/comments?per_page=100")
        request_bound = any(
            sha in (comment.get("body") or "") and "review" in (comment.get("body") or "").lower()
            for comment in comments
        )
        findings.append(Finding(
            "EXACT_HEAD_REVIEW_REQUEST_BOUND" if request_bound else "EXACT_HEAD_REVIEW_REQUEST_ABSENT",
            Verdict.PASS if request_bound else Verdict.HOLD,
            f"PR #{number} {'has' if request_bound else 'does not have'} an observed review request naming its current head.",
            {"sha": sha},
        ))
        reviews = self.reader.get(f"/repos/{full_name}/pulls/{number}/reviews?per_page=100")
        exact = [r for r in reviews if r.get("commit_id") == sha and str(r.get("state", "")).upper() != "PENDING"]
        if not exact:
            findings.append(Finding("EXACT_HEAD_REVIEW_NOT_SUBMITTED", Verdict.HOLD, f"PR #{number} has no submitted review bound to its current head.", {"sha": sha}))
            return findings
        states = {str(r.get("state", "")).upper() for r in exact}
        reviewers = sorted({(r.get("user") or {}).get("login", "unknown") for r in exact})
        if "CHANGES_REQUESTED" in states:
            findings.append(Finding("EXACT_HEAD_REVIEW_CHANGES_REQUESTED", Verdict.FAIL, f"PR #{number} has a current-head review requesting changes.", {"sha": sha, "states": sorted(states), "reviewers": reviewers}))
        elif "APPROVED" in states:
            findings.append(Finding("EXACT_HEAD_REVIEW_APPROVED", Verdict.PASS, f"PR #{number} has an approving review bound to its current head.", {"sha": sha, "states": sorted(states), "reviewers": reviewers}))
        else:
            findings.append(Finding("EXACT_HEAD_REVIEW_NONAPPROVING", Verdict.HOLD, f"PR #{number} has current-head review activity, but no machine-verifiable approving review. Manual/provider-specific disposition is required.", {"sha": sha, "states": sorted(states), "reviewers": reviewers}))
        return findings

    def _check_platform_protection(self, full_name: str, default_branch: str, branch: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        if branch.get("protected") is False:
            return [Finding("PLATFORM_PROTECTION_FAIL", Verdict.FAIL, f"Default branch `{default_branch}` is unprotected; direct platform bypass remains possible.")]
        if branch.get("protected") is not True:
            return [Finding("PLATFORM_PROTECTION_HOLD", Verdict.HOLD, f"Protection state for `{default_branch}` could not be verified.")]

        protection, status = self.reader.get_optional(f"/repos/{full_name}/branches/{default_branch}/protection")
        if status != 200 or not isinstance(protection, dict):
            return [Finding("PLATFORM_PROTECTION_HOLD", Verdict.HOLD, f"`{default_branch}` is reported protected, but effective branch-protection controls could not be fully inspected.", {"http_status": status})]

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

        checks = protection.get("required_status_checks")
        if not isinstance(checks, dict):
            failures.append("required status checks are absent")
        elif checks.get("strict") is not True:
            failures.append("branch-up-to-date status-check enforcement is disabled")

        conversations = protection.get("required_conversation_resolution")
        if not isinstance(conversations, dict) or conversations.get("enabled") is not True:
            failures.append("conversation resolution is not required")

        if (protection.get("allow_force_pushes") or {}).get("enabled") is True:
            failures.append("force pushes are allowed")
        if (protection.get("allow_deletions") or {}).get("enabled") is True:
            failures.append("branch deletion is allowed")

        restrictions = protection.get("restrictions")
        if restrictions is None:
            holds.append("push/bypass actor restrictions are not fully observable from this protection response")

        if failures:
            findings.append(Finding("PLATFORM_PROTECTION_FAIL", Verdict.FAIL, f"`{default_branch}` protection contradicts required policy.", {"failures": failures, "holds": holds}))
        elif holds:
            findings.append(Finding("PLATFORM_PROTECTION_HOLD", Verdict.HOLD, f"`{default_branch}` protection is present but cannot yet be completely certified.", {"holds": holds}))
        else:
            findings.append(Finding("PLATFORM_PROTECTION_PASS", Verdict.PASS, f"`{default_branch}` effective branch protection satisfies the observable Repo Steward baseline."))
        return findings

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

        if repo_cfg.get("require_protected_default_branch", False):
            findings.extend(self._check_platform_protection(full_name, default_branch, branch))

        workflows = self.reader.get(f"/repos/{full_name}/actions/workflows").get("workflows", [])
        names = {w.get("name") for w in workflows}
        for required in repo_cfg.get("required_workflows", []):
            findings.append(Finding("WORKFLOW_PRESENT" if required in names else "WORKFLOW_MISSING", Verdict.PASS if required in names else Verdict.FAIL, f"Required workflow {'present' if required in names else 'missing'}: {required}"))

        prs = self.reader.get(f"/repos/{full_name}/pulls?state=open&per_page=100")
        for pr in prs:
            sha = pr.get("head", {}).get("sha")
            if not sha:
                findings.append(Finding("PR_HEAD_UNKNOWN", Verdict.FAIL, f"PR #{pr.get('number')} has no observable head SHA."))
                continue
            runs = self.reader.get(f"/repos/{full_name}/actions/runs?head_sha={sha}&event=pull_request&per_page=100").get("workflow_runs", [])
            bad = [run for run in runs if run.get("conclusion") not in (None, "success", "skipped")]
            pending = [run for run in runs if run.get("status") != "completed"]
            if bad:
                findings.append(Finding("PR_CI_FAILED", Verdict.FAIL, f"PR #{pr['number']} has failed CI on its current head.", {"sha": sha}))
            elif pending:
                findings.append(Finding("PR_CI_PENDING", Verdict.HOLD, f"PR #{pr['number']} has pending CI on its current head.", {"sha": sha}))
            elif repo_cfg.get("require_ci", True) and not runs:
                findings.append(Finding("PR_CI_ABSENT", Verdict.HOLD, f"PR #{pr['number']} has no observed pull-request workflow run on its current head.", {"sha": sha}))
            else:
                findings.append(Finding("PR_CI_GREEN", Verdict.PASS, f"PR #{pr['number']} CI is green on current head.", {"sha": sha}))
            if repo_cfg.get("require_exact_head_review", False):
                findings.extend(self._check_exact_head_review(full_name, pr, sha))

        return RepoReport(full_name, self._combine(findings), findings)

    def check_all(self) -> dict[str, Any]:
        reports = [self.check_repo(cfg) for cfg in self.policy["repositories"] if cfg.get("enabled", True)]
        overall = self._combine([Finding("REPO", report.verdict, report.repository) for report in reports])
        return {"schema_version": "0.1.0", "overall": overall.value, "reports": [report.as_dict() for report in reports]}
