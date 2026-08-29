#!/usr/bin/env python3

import importlib.util
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("estate_protection.py")
spec = importlib.util.spec_from_file_location("estate_protection", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_strengthen_preserves_non_pr_rules():
    existing = [
        {"type": "deletion"},
        {"type": "required_status_checks", "parameters": {"strict_required_status_checks_policy": True, "required_status_checks": [{"context": "CI"}]}},
        {"type": "pull_request", "parameters": {"required_approving_review_count": 0, "required_review_thread_resolution": False}},
    ]
    policy = {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": True,
        "require_last_push_approval": True,
        "required_review_thread_resolution": True,
        "allowed_merge_methods": ["squash"],
    }

    result = mod.strengthen_rules(existing, policy)

    status = next(r for r in result if r["type"] == "required_status_checks")
    assert status == existing[1]
    pr = next(r for r in result if r["type"] == "pull_request")
    for key, value in policy.items():
        assert pr["parameters"][key] == value


def test_compliance_reports_drift():
    policy = {"required_approving_review_count": 1, "dismiss_stale_reviews_on_push": True}
    ruleset = {
        "rules": [
            {"type": "pull_request", "parameters": {"required_approving_review_count": 0, "dismiss_stale_reviews_on_push": False}}
        ]
    }
    ok, drift = mod.compliance(ruleset, policy)
    assert not ok
    assert len(drift) == 2


if __name__ == "__main__":
    test_strengthen_preserves_non_pr_rules()
    test_compliance_reports_drift()
    print("estate protection tests: PASS")
