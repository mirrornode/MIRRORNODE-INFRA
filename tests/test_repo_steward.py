import json
import tempfile
import unittest
from pathlib import Path

from repo_steward.admin import APPROVED_ADVISORY_LANES, AdminAction, RepoAdmin
from repo_steward.checker import RepoChecker, Verdict


BOUND_BLUEPRINT = {
    "dual_control": {
        "required_check_name": "Repo Steward Dual Control",
        "trusted_producer": {
            "type": "GITHUB_APP",
            "binding_required": True,
            "app_id": 123,
            "slug": "trusted-repo-steward",
            "state": "BOUND",
        },
    }
}


class FakeReader:
    def __init__(
        self,
        review_state="APPROVED",
        reviewer="reviewer",
        reviewer_type="User",
        reviewer_id=42,
        reviewer_permission="write",
        pr_commit_author="author",
        pr_commit_author_linked=True,
        commit_message="",
        protected=True,
        inspectable=True,
        protection_overrides=None,
        run_name="PR Validation",
        request_association="OWNER",
        rulesets=None,
        ruleset_details=None,
    ):
        self.review_state = review_state
        self.reviewer = reviewer
        self.reviewer_type = reviewer_type
        self.reviewer_id = reviewer_id
        self.reviewer_permission = reviewer_permission
        self.pr_commit_author = pr_commit_author
        self.pr_commit_author_linked = pr_commit_author_linked
        self.commit_message = commit_message
        self.protected = protected
        self.inspectable = inspectable
        self.protection_overrides = protection_overrides or {}
        self.run_name = run_name
        self.request_association = request_association
        self.rulesets = rulesets or []
        self.ruleset_details = ruleset_details or {}

    def get(self, path):
        if path.endswith("/branches/main"):
            return {"commit": {"sha": "abc123"}, "protected": self.protected}
        if path.endswith("/actions/workflows"):
            return {"workflows": [{"name": "PR Validation"}]}
        if "/pulls?state=open" in path:
            return [{"number": 7, "head": {"sha": "prsha"}, "user": {"login": "author"}}]
        if "/actions/runs?" in path:
            return {"workflow_runs": [{"name": self.run_name, "status": "completed", "conclusion": "success"}]}
        if "/issues/7/comments" in path:
            return [{"body": "@codex review exact head prsha", "author_association": self.request_association}]
        if "/pulls/7/reviews" in path:
            return [{
                "commit_id": "prsha",
                "state": self.review_state,
                "user": {"id": self.reviewer_id, "login": self.reviewer, "type": self.reviewer_type},
            }]
        if "/pulls/7/commits" in path:
            contributor = {"login": self.pr_commit_author, "type": "User"}
            return [{
                "author": contributor if self.pr_commit_author_linked else None,
                "committer": contributor,
                "commit": {"message": self.commit_message},
            }]
        if path == "/repos/mirrornode/example":
            return {"default_branch": "main"}
        raise AssertionError(path)

    def get_optional(self, path):
        if path.endswith("/branches/main/protection"):
            if not self.inspectable:
                return None, 404
            protection = {
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews": True,
                    "require_last_push_approval": True,
                    "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []},
                },
                "required_status_checks": {
                    "strict": True,
                    "contexts": ["PR Validation"],
                    "checks": [
                        {"context": "PR Validation", "app_id": 1},
                        {"context": "Repo Steward Dual Control", "app_id": 123},
                    ],
                },
                "required_conversation_resolution": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
                "enforce_admins": {"enabled": True},
                "restrictions": {"users": [], "teams": [], "apps": []},
            }
            protection.update(self.protection_overrides)
            return protection, 200
        if path.endswith("/rulesets"):
            return self.rulesets, 200
        if "/rulesets/" in path:
            ruleset_id = path.rsplit("/", 1)[-1]
            return self.ruleset_details.get(ruleset_id), 200 if ruleset_id in self.ruleset_details else 404
        if "/collaborators/" in path and path.endswith("/permission"):
            if self.reviewer_permission is None:
                return None, 404
            return {"permission": self.reviewer_permission}, 200
        raise AssertionError(path)


class RepoStewardTests(unittest.TestCase):
    @staticmethod
    def policy():
        return {
            "approved_human_reviewer_ids": [42],
            "repositories": [{
                "repository": "mirrornode/example",
                "enabled": True,
                "require_ci": True,
                "require_exact_head_review": True,
                "require_protected_default_branch": True,
                "required_workflows": ["PR Validation"],
            }]
        }

    def run_checker(self, reader, blueprint=BOUND_BLUEPRINT):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps(self.policy()), encoding="utf-8")
            (root / "repo-steward-platform-ruleset-blueprint.json").write_text(
                json.dumps(blueprint),
                encoding="utf-8",
            )
            return RepoChecker(policy_path, reader=reader).check_all()

    def test_checker_passes_fully_observed_compliant_repo(self):
        self.assertEqual(self.run_checker(FakeReader())["overall"], Verdict.PASS.value)

    def test_unprotected_default_branch_fails(self):
        self.assertEqual(self.run_checker(FakeReader(protected=False))["overall"], Verdict.FAIL.value)

    def test_protected_but_uninspectable_holds_or_fails_closed(self):
        self.assertIn(self.run_checker(FakeReader(protected=True, inspectable=False))["overall"], {Verdict.HOLD.value, Verdict.FAIL.value})

    def test_unbound_trusted_producer_holds(self):
        blueprint = json.loads(json.dumps(BOUND_BLUEPRINT))
        blueprint["dual_control"]["trusted_producer"]["state"] = "UNBOUND_FAIL_CLOSED"
        blueprint["dual_control"]["trusted_producer"]["app_id"] = None
        self.assertEqual(self.run_checker(FakeReader(), blueprint)["overall"], Verdict.HOLD.value)

    def test_untrusted_check_producer_fails(self):
        report = self.run_checker(FakeReader(protection_overrides={
            "required_status_checks": {
                "strict": True,
                "contexts": ["PR Validation", "Repo Steward Dual Control"],
                "checks": [
                    {"context": "PR Validation", "app_id": 1},
                    {"context": "Repo Steward Dual Control", "app_id": 999},
                ],
            }
        }))
        self.assertEqual(report["overall"], Verdict.FAIL.value)

    def test_missing_last_push_approval_fails(self):
        report = self.run_checker(FakeReader(protection_overrides={
            "required_pull_request_reviews": {
                "required_approving_review_count": 1,
                "dismiss_stale_reviews": True,
                "require_last_push_approval": False,
                "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []},
            }
        }))
        self.assertEqual(report["overall"], Verdict.FAIL.value)

    def test_admin_bypass_fails(self):
        self.assertEqual(self.run_checker(FakeReader(protection_overrides={"enforce_admins": {"enabled": False}}))["overall"], Verdict.FAIL.value)

    def test_missing_required_check_identity_fails(self):
        report = self.run_checker(FakeReader(protection_overrides={
            "required_status_checks": {"strict": True, "contexts": ["Unrelated"], "checks": []}
        }))
        self.assertEqual(report["overall"], Verdict.FAIL.value)

    def test_nonapproving_review_does_not_clear_head(self):
        self.assertEqual(self.run_checker(FakeReader(review_state="COMMENTED"))["overall"], Verdict.HOLD.value)

    def test_changes_requested_fails_head(self):
        self.assertEqual(self.run_checker(FakeReader(review_state="CHANGES_REQUESTED"))["overall"], Verdict.FAIL.value)

    def test_bot_approval_does_not_clear_head(self):
        self.assertEqual(self.run_checker(FakeReader(reviewer="review-bot", reviewer_type="Bot"))["overall"], Verdict.HOLD.value)

    def test_unrostered_user_approval_does_not_clear_head(self):
        self.assertEqual(self.run_checker(FakeReader(reviewer_id=99))["overall"], Verdict.HOLD.value)

    def test_non_writer_approval_does_not_clear_head(self):
        self.assertEqual(self.run_checker(FakeReader(reviewer_permission="read"))["overall"], Verdict.HOLD.value)

    def test_repair_contributor_cannot_clear_head(self):
        self.assertEqual(self.run_checker(FakeReader(reviewer="repairer", pr_commit_author="repairer"))["overall"], Verdict.HOLD.value)

    def test_unlinked_commit_attribution_does_not_clear_head(self):
        self.assertEqual(self.run_checker(FakeReader(pr_commit_author_linked=False))["overall"], Verdict.HOLD.value)

    def test_coauthored_commit_attribution_does_not_clear_head(self):
        self.assertEqual(
            self.run_checker(FakeReader(commit_message="Subject\n\nCo-authored-by: Extra <extra@example.test>"))["overall"],
            Verdict.HOLD.value,
        )

    def test_unauthenticated_review_request_does_not_clear_request_gate(self):
        self.assertEqual(self.run_checker(FakeReader(request_association="NONE"))["overall"], Verdict.HOLD.value)

    def test_missing_required_workflow_run_holds(self):
        self.assertEqual(self.run_checker(FakeReader(run_name="Unrelated Workflow"))["overall"], Verdict.HOLD.value)

    def test_unrelated_rulesets_do_not_certify_default_branch(self):
        detail = {
            "conditions": {"ref_name": {"include": ["refs/heads/release/*"], "exclude": []}},
            "rules": [
                {"type": "deletion", "parameters": {}},
                {"type": "non_fast_forward", "parameters": {}},
                {"type": "pull_request", "parameters": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews_on_push": True,
                    "require_last_push_approval": True,
                    "required_review_thread_resolution": True,
                }},
                {"type": "required_status_checks", "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": "PR Validation", "integration_id": 1},
                        {"context": "Repo Steward Dual Control", "integration_id": 123},
                    ],
                }},
            ],
        }
        report = self.run_checker(FakeReader(
            inspectable=False,
            rulesets=[{"id": 1, "enforcement": "active", "target": "branch"}],
            ruleset_details={"1": detail},
        ))
        self.assertEqual(report["overall"], Verdict.FAIL.value)

    def test_ruleset_glob_does_not_cross_path_separator(self):
        self.assertFalse(RepoChecker._github_ref_pattern_matches("refs/heads/*", "refs/heads/release/1"))
        self.assertTrue(RepoChecker._github_ref_pattern_matches("refs/heads/**", "refs/heads/release/1"))

    def test_admin_execution_is_absent(self):
        admin = RepoAdmin()
        proposal = admin.propose("mirrornode/example", AdminAction.OPEN_PR, "repair")
        self.assertTrue(proposal.requires_operator_approval)
        self.assertTrue(proposal.requires_advisory_attestation)
        with self.assertRaises(PermissionError):
            admin.execute(proposal)

    def test_all_mutations_require_dual_control(self):
        admin = RepoAdmin()
        for action in AdminAction:
            proposal = admin.propose("mirrornode/example", action, "test")
            self.assertTrue(proposal.requires_operator_approval)
            self.assertTrue(proposal.requires_advisory_attestation)
            self.assertEqual(proposal.approved_advisory_lanes, APPROVED_ADVISORY_LANES)


if __name__ == "__main__":
    unittest.main()
