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
            protected = branch.get("protected")
            if protected is True:
                findings.append(Finding("DEFAULT_BRANCH_PROTECTED", Verdict.PASS, f"Default branch `{default_branch}` is protected."))
            elif protected is False:
                findings.append(Finding("DEFAULT_BRANCH_UNPROTECTED", Verdict.FAIL, f"Default branch `{default_branch}` is not protected; direct platform bypass remains possible."))
            else:
                findings.append(Finding("DEFAULT_BRANCH_PROTECTION_UNKNOWN", Verdict.HOLD, f"Protection state for `{default_branch}` could not be verified."))

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
