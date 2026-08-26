import json
import tempfile
import unittest
from pathlib import Path

from repo_steward.admin import APPROVED_ADVISORY_LANES, AdminAction, RepoAdmin
from repo_steward.checker import RepoChecker, Verdict


class FakeReader:
    def __init__(
        self,
        review_state='APPROVED',
        reviewer='reviewer',
        protected=True,
        inspectable=True,
        protection_overrides=None,
        run_name='PR Validation',
        request_association='OWNER',
    ):
        self.review_state = review_state
        self.reviewer = reviewer
        self.protected = protected
        self.inspectable = inspectable
        self.protection_overrides = protection_overrides or {}
        self.run_name = run_name
        self.request_association = request_association

    def get(self, path):
        if path.endswith('/branches/main'):
            return {'commit': {'sha': 'abc123'}, 'protected': self.protected}
        if path.endswith('/actions/workflows'):
            return {'workflows': [{'name': 'PR Validation'}]}
        if '/pulls?state=open' in path:
            return [{'number': 7, 'head': {'sha': 'prsha'}, 'user': {'login': 'author'}}]
        if '/actions/runs?' in path:
            return {'workflow_runs': [{'name': self.run_name, 'status': 'completed', 'conclusion': 'success'}]}
        if '/issues/7/comments' in path:
            return [{'body': '@codex review exact head prsha', 'author_association': self.request_association}]
        if '/pulls/7/reviews' in path:
            return [{'commit_id': 'prsha', 'state': self.review_state, 'user': {'login': self.reviewer}}]
        if path == '/repos/mirrornode/example':
            return {'default_branch': 'main'}
        raise AssertionError(path)

    def get_optional(self, path):
        if path.endswith('/branches/main/protection'):
            if not self.inspectable:
                return None, 403
            protection = {
                'required_pull_request_reviews': {
                    'required_approving_review_count': 1,
                    'dismiss_stale_reviews': True,
                    'require_last_push_approval': True,
                    'bypass_pull_request_allowances': {'users': [], 'teams': [], 'apps': []},
                },
                'required_status_checks': {'strict': True, 'contexts': ['PR Validation']},
                'required_conversation_resolution': {'enabled': True},
                'allow_force_pushes': {'enabled': False},
                'allow_deletions': {'enabled': False},
                'enforce_admins': {'enabled': True},
                'restrictions': {'users': [], 'teams': [], 'apps': []},
            }
            protection.update(self.protection_overrides)
            return protection, 200
        if path.endswith('/rulesets'):
            return [], 200
        raise AssertionError(path)


class RepoStewardTests(unittest.TestCase):
    @staticmethod
    def policy():
        return {
            'repositories': [{
                'repository': 'mirrornode/example',
                'enabled': True,
                'require_ci': True,
                'require_exact_head_review': True,
                'require_protected_default_branch': True,
                'required_workflows': ['PR Validation'],
            }]
        }

    def run_checker(self, reader):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'policy.json'
            path.write_text(json.dumps(self.policy()), encoding='utf-8')
            return RepoChecker(path, reader=reader).check_all()

    def test_checker_passes_fully_observed_compliant_repo(self):
        report = self.run_checker(FakeReader())
        self.assertEqual(report['overall'], Verdict.PASS.value)

    def test_unprotected_default_branch_fails(self):
        report = self.run_checker(FakeReader(protected=False))
        self.assertEqual(report['overall'], Verdict.FAIL.value)

    def test_protected_but_uninspectable_holds_or_fails_closed(self):
        report = self.run_checker(FakeReader(protected=True, inspectable=False))
        self.assertIn(report['overall'], {Verdict.HOLD.value, Verdict.FAIL.value})

    def test_missing_last_push_approval_fails(self):
        report = self.run_checker(FakeReader(protection_overrides={
            'required_pull_request_reviews': {
                'required_approving_review_count': 1,
                'dismiss_stale_reviews': True,
                'require_last_push_approval': False,
                'bypass_pull_request_allowances': {'users': [], 'teams': [], 'apps': []},
            }
        }))
        self.assertEqual(report['overall'], Verdict.FAIL.value)

    def test_admin_bypass_fails(self):
        report = self.run_checker(FakeReader(protection_overrides={'enforce_admins': {'enabled': False}}))
        self.assertEqual(report['overall'], Verdict.FAIL.value)

    def test_missing_required_check_identity_fails(self):
        report = self.run_checker(FakeReader(protection_overrides={'required_status_checks': {'strict': True, 'contexts': ['Unrelated']}}))
        self.assertEqual(report['overall'], Verdict.FAIL.value)

    def test_nonapproving_review_does_not_clear_head(self):
        report = self.run_checker(FakeReader(review_state='COMMENTED'))
        self.assertEqual(report['overall'], Verdict.HOLD.value)

    def test_changes_requested_fails_head(self):
        report = self.run_checker(FakeReader(review_state='CHANGES_REQUESTED'))
        self.assertEqual(report['overall'], Verdict.FAIL.value)

    def test_bot_approval_does_not_clear_head(self):
        report = self.run_checker(FakeReader(reviewer='review-bot'))
        self.assertEqual(report['overall'], Verdict.HOLD.value)

    def test_unauthenticated_review_request_does_not_clear_request_gate(self):
        report = self.run_checker(FakeReader(request_association='NONE'))
        self.assertEqual(report['overall'], Verdict.HOLD.value)

    def test_missing_required_workflow_run_holds(self):
        report = self.run_checker(FakeReader(run_name='Unrelated Workflow'))
        self.assertEqual(report['overall'], Verdict.HOLD.value)

    def test_admin_execution_is_absent(self):
        admin = RepoAdmin()
        proposal = admin.propose('mirrornode/example', AdminAction.OPEN_PR, 'repair')
        self.assertTrue(proposal.requires_operator_approval)
        self.assertTrue(proposal.requires_advisory_attestation)
        with self.assertRaises(PermissionError):
            admin.execute(proposal)

    def test_all_mutations_require_dual_control(self):
        admin = RepoAdmin()
        for action in AdminAction:
            proposal = admin.propose('mirrornode/example', action, 'test')
            self.assertTrue(proposal.requires_operator_approval)
            self.assertTrue(proposal.requires_advisory_attestation)
            self.assertEqual(proposal.approved_advisory_lanes, APPROVED_ADVISORY_LANES)


if __name__ == '__main__':
    unittest.main()
