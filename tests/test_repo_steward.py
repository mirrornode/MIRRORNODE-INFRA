import json
import tempfile
import unittest
from pathlib import Path

from repo_steward.admin import AdminAction, RepoAdmin
from repo_steward.checker import RepoChecker, Verdict


class FakeReader:
    def get(self, path):
        if path.endswith('/branches/main'):
            return {'commit': {'sha': 'abc123'}}
        if path.endswith('/actions/workflows'):
            return {'workflows': [{'name': 'PR Validation'}]}
        if '/pulls?' in path:
            return [{'number': 7, 'head': {'sha': 'prsha'}}]
        if '/actions/runs?' in path:
            return {'workflow_runs': [{'status': 'completed', 'conclusion': 'success'}]}
        if '/issues/7/comments' in path:
            return [{'body': '@codex review exact head prsha'}]
        if path == '/repos/mirrornode/example':
            return {'default_branch': 'main'}
        raise AssertionError(path)


class RepoStewardTests(unittest.TestCase):
    def test_checker_passes_bound_green_repo(self):
        policy = {
            'repositories': [{
                'repository': 'mirrornode/example',
                'enabled': True,
                'require_ci': True,
                'require_exact_head_review': True,
                'required_workflows': ['PR Validation'],
            }]
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'policy.json'
            path.write_text(json.dumps(policy), encoding='utf-8')
            report = RepoChecker(path, reader=FakeReader()).check_all()
        self.assertEqual(report['overall'], Verdict.PASS.value)

    def test_admin_execution_is_absent(self):
        admin = RepoAdmin()
        proposal = admin.propose('mirrornode/example', AdminAction.OPEN_PR, 'repair')
        with self.assertRaises(PermissionError):
            admin.execute(proposal)

    def test_sensitive_actions_are_operator_gated(self):
        admin = RepoAdmin()
        proposal = admin.propose('mirrornode/example', AdminAction.UPDATE_RULESET, 'tighten protection')
        self.assertTrue(proposal.requires_operator_approval)


if __name__ == '__main__':
    unittest.main()
