#!/usr/bin/env python3

import importlib.util
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("estate_protection.py")
spec = importlib.util.spec_from_file_location("estate_protection", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

FLOOR = {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews_on_push": True,
    "require_code_owner_review": False,
    "require_last_push_approval": True,
    "required_review_thread_resolution": True,
    "require_extra_approval_for_unattributed_changes": True,
    "allowed_merge_methods": ["squash"],
}

STRICT_POLICY_ABSENT = object()


def manifest():
    return {
        "version": "0.1",
        "ruleset_name": "MIRRORNODE Baseline Main Protection",
        "target": "~DEFAULT_BRANCH",
        "review_policy": dict(FLOOR),
        "single_operator_repositories": [],
        "required_status_checks": {"mode": "preserve_existing_nonempty"},
        "bypass_actors": [],
        "preserve_existing_rules": True,
        "repositories": ["mirrornode/example"],
    }


def surface(review=None, *, checks=("CI",), extra_rules=(), bypass=(), complete=True):
    rules = [
        {"type": "deletion"},
        {"type": "non_fast_forward"},
        {"type": "required_linear_history"},
        {"type": "pull_request", "parameters": review or dict(FLOOR)},
    ]
    if checks is not None:
        rules.append({"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": x} for x in checks]}})
    rules.extend(extra_rules)
    return {
        "complete": complete,
        "diagnostics": [] if complete else ["unreadable"],
        "default_branch": "main",
        "repository": {
            "allow_squash_merge": True,
            "allow_merge_commit": False,
            "allow_rebase_merge": False,
        },
        "rulesets": [{"bypass_actors": list(bypass), "rules": rules}],
        "classic": None,
    }


def test_preserves_two_approvals_over_one_approval_floor():
    merged = mod.merge_restrictive_policy({"required_approving_review_count": 2}, FLOOR)
    assert merged["required_approving_review_count"] == 2


def test_preserves_code_owner_review_when_manifest_does_not_require_it():
    merged = mod.merge_restrictive_policy({"require_code_owner_review": True}, FLOOR)
    assert merged["require_code_owner_review"] is True


def test_preserves_stronger_review_and_conversation_controls():
    existing = {
        "dismiss_stale_reviews_on_push": True,
        "require_last_push_approval": True,
        "required_review_thread_resolution": True,
    }
    merged = mod.merge_restrictive_policy(existing, FLOOR)
    for key in existing:
        assert merged[key] is True


def test_rejects_unknown_protection_parameter_ordering():
    try:
        mod.merge_restrictive_policy({}, {"mystery_setting": True})
    except ValueError:
        return
    raise AssertionError("unknown setting must fail closed")


def test_preserves_non_pr_rules():
    existing = [
        {"type": "deletion"},
        {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "CI"}]}},
        {"type": "pull_request", "parameters": {"required_approving_review_count": 2}},
    ]
    result = mod.strengthen_rules(existing, FLOOR)
    assert next(r for r in result if r["type"] == "deletion") == existing[0]
    assert next(r for r in result if r["type"] == "required_status_checks") == existing[1]
    assert next(r for r in result if r["type"] == "pull_request")["parameters"]["required_approving_review_count"] == 2


def test_paginates_ruleset_discovery():
    original = mod.request
    calls = []
    def fake(token, method, url, payload=None, allow_404=False):
        calls.append(url)
        if "&page=1" in url:
            return [{"id": i} for i in range(100)]
        if "&page=2" in url:
            return [{"id": 101}]
        raise AssertionError(url)
    mod.request = fake
    try:
        rows = mod.paginate("t", "https://example.invalid/rulesets")
        assert len(rows) == 101
        assert len(calls) == 2
    finally:
        mod.request = original


def test_rejects_inactive_named_ruleset():
    ruleset = {"target": "branch", "enforcement": "disabled", "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}}}
    assert mod.ref_condition_applies(ruleset, "main") is True
    # Inactive rulesets are excluded by effective_default_branch_protection; a surface with none cannot pass.
    ok, _ = mod.validate_effective_protection({"complete": True, "diagnostics": [], "rulesets": [], "classic": None}, manifest())
    assert not ok


def test_rejects_non_default_branch_target():
    ruleset = {"target": "branch", "conditions": {"ref_name": {"include": ["refs/heads/dev"], "exclude": []}}}
    assert mod.ref_condition_applies(ruleset, "main") is False


def test_ruleset_wildcard_does_not_cross_path_separator():
    single = {"target": "branch", "conditions": {"ref_name": {"include": ["refs/heads/*"], "exclude": []}}}
    recursive = {"target": "branch", "conditions": {"ref_name": {"include": ["refs/heads/**"], "exclude": []}}}
    assert mod.ref_condition_applies(single, "release/v1") is False
    assert mod.ref_condition_applies(recursive, "release/v1") is True


def test_rejects_missing_deletion_rule():
    s = surface()
    s["rulesets"][0]["rules"] = [r for r in s["rulesets"][0]["rules"] if r["type"] != "deletion"]
    ok, errors = mod.validate_effective_protection(s, manifest())
    assert not ok and any("deletion" in x for x in errors)


def test_rejects_missing_non_fast_forward_rule():
    s = surface()
    s["rulesets"][0]["rules"] = [r for r in s["rulesets"][0]["rules"] if r["type"] != "non_fast_forward"]
    ok, errors = mod.validate_effective_protection(s, manifest())
    assert not ok and any("non_fast_forward" in x for x in errors)


def test_rejects_missing_linear_history_rule():
    s = surface()
    s["rulesets"][0]["rules"] = [r for r in s["rulesets"][0]["rules"] if r["type"] != "required_linear_history"]
    ok, errors = mod.validate_effective_protection(s, manifest())
    assert not ok and any("required_linear_history" in x for x in errors)


def test_rejects_effective_merge_method_outside_manifest():
    permissive = dict(FLOOR)
    permissive["allowed_merge_methods"] = ["merge", "squash"]
    s = surface(review=permissive)
    s["repository"]["allow_merge_commit"] = True
    ok, errors = mod.validate_effective_protection(s, manifest())
    assert not ok and any("merge methods" in x for x in errors)


def test_rejects_effective_bypass_actor():
    ok, errors = mod.validate_effective_protection(surface(bypass=({"actor_id": 1},)), manifest())
    assert not ok and any("bypass" in x for x in errors)


def test_rejects_missing_required_status_checks():
    ok, errors = mod.validate_effective_protection(surface(checks=()), manifest())
    assert not ok and any("status check" in x for x in errors)


def test_rejects_conflicting_secondary_effective_ruleset():
    s = surface()
    s["rulesets"].append({"bypass_actors": [{"actor_id": 2}], "rules": []})
    ok, _ = mod.validate_effective_protection(s, manifest())
    assert not ok


def test_rejects_unreadable_effective_ruleset():
    ok, errors = mod.validate_effective_protection(surface(complete=False), manifest())
    assert not ok and any("incomplete" in x for x in errors)


def test_rejects_ancestor_sha_approval():
    pr = {"head": {"sha": "new"}, "user": {"login": "author"}}
    reviews = [{"state": "APPROVED", "commit_id": "old", "user": {"login": "reviewer"}}]
    ok, _ = mod.evaluate_exact_head_approval(pr, reviews, "new", "pusher", {"reviewer": "write"}, 1)
    assert not ok


def test_accepts_exact_head_approval_only_conditionally():
    pr = {"head": {"sha": "new"}, "user": {"login": "author"}}
    reviews = [{"state": "APPROVED", "commit_id": "new", "user": {"login": "reviewer"}}]
    ok, errors = mod.evaluate_exact_head_approval(
        pr,
        reviews,
        "new",
        "pusher",
        {"reviewer": "write"},
        1,
        review_decision="APPROVED",
    )
    assert ok and not errors


def test_rejects_missing_exact_head_approval():
    pr = {"head": {"sha": "new"}, "user": {"login": "author"}}
    ok, _ = mod.evaluate_exact_head_approval(pr, [], "new", "pusher", {}, 1)
    assert not ok


def test_rejects_author_or_latest_pusher_approval():
    pr = {"head": {"sha": "new"}, "user": {"login": "author"}}
    for reviewer in ("author", "pusher"):
        reviews = [{"state": "APPROVED", "commit_id": "new", "user": {"login": reviewer}}]
        ok, _ = mod.evaluate_exact_head_approval(pr, reviews, "new", "pusher", {reviewer: "write"}, 1)
        assert not ok


def test_rejects_untrusted_or_ineligible_reviewer_evidence():
    pr = {"head": {"sha": "new"}, "user": {"login": "author"}}
    reviews = [{"id": 1, "submitted_at": "2026-01-01", "state": "APPROVED", "commit_id": "new", "user": {"login": "reviewer"}}]
    ok, errors = mod.evaluate_exact_head_approval(pr, reviews, "new", None, {"reviewer": "write"}, 1)
    assert not ok and any("push actor" in x for x in errors)
    ok, _ = mod.evaluate_exact_head_approval(pr, reviews, "new", "pusher", {"reviewer": "read"}, 1)
    assert not ok


def test_latest_review_state_supersedes_historical_approval():
    pr = {"head": {"sha": "new"}, "user": {"login": "author"}}
    reviews = [
        {"id": 1, "submitted_at": "2026-01-01", "state": "APPROVED", "commit_id": "new", "user": {"login": "reviewer"}},
        {"id": 2, "submitted_at": "2026-01-02", "state": "CHANGES_REQUESTED", "commit_id": "new", "user": {"login": "reviewer"}},
    ]
    ok, _ = mod.evaluate_exact_head_approval(pr, reviews, "new", "pusher", {"reviewer": "write"}, 1)
    assert not ok


def test_enforces_effective_approval_count():
    pr = {"head": {"sha": "new"}, "user": {"login": "author"}}
    reviews = [{"id": 1, "submitted_at": "2026-01-01", "state": "APPROVED", "commit_id": "new", "user": {"login": "one"}}]
    ok, _ = mod.evaluate_exact_head_approval(pr, reviews, "new", "pusher", {"one": "write"}, 2)
    assert not ok


def test_code_owner_review_needs_direct_constraint_receipt():
    pr = {"head": {"sha": "new"}, "user": {"login": "author"}}
    reviews = [{"id": 1, "submitted_at": "2026-01-01", "state": "APPROVED", "commit_id": "new", "user": {"login": "reviewer"}}]
    ok, errors = mod.evaluate_exact_head_approval(
        pr,
        reviews,
        "new",
        "pusher",
        {"reviewer": "write"},
        1,
        {"require_code_owner_review": True},
        "APPROVED",
    )
    assert not ok
    assert any("constraint receipt" in error for error in errors)


def test_required_reviewers_need_direct_constraint_receipt():
    pr = {"head": {"sha": "new"}, "user": {"login": "author"}}
    reviews = [{"id": 1, "submitted_at": "2026-01-01", "state": "APPROVED", "commit_id": "new", "user": {"login": "reviewer"}}]
    ok, errors = mod.evaluate_exact_head_approval(
        pr,
        reviews,
        "new",
        "pusher",
        {"reviewer": "write"},
        1,
        {"required_reviewers": [{"type": "Team", "id": 7}]},
        "APPROVED",
    )
    assert not ok
    assert any("constraint receipt" in error for error in errors)


def test_rejects_latest_pending_or_failing_run_after_historical_success():
    runs = [
        {"id": 1, "name": "CI", "run_attempt": 1, "created_at": "2026-01-01", "status": "completed", "conclusion": "success"},
        {"id": 2, "name": "CI", "run_attempt": 2, "created_at": "2026-01-02", "status": "in_progress", "conclusion": None},
    ]
    ok, _ = mod.evaluate_latest_runs(runs, ["CI"])
    assert not ok
    runs[1].update(status="completed", conclusion="failure")
    ok, _ = mod.evaluate_latest_runs(runs, ["CI"])
    assert not ok


def test_accepts_latest_successful_run():
    runs = [
        {"id": 1, "name": "CI", "run_attempt": 1, "created_at": "2026-01-01", "status": "completed", "conclusion": "failure"},
        {"id": 2, "name": "CI", "run_attempt": 2, "created_at": "2026-01-02", "status": "completed", "conclusion": "success"},
    ]
    ok, errors = mod.evaluate_latest_runs(runs, ["CI"])
    assert ok and not errors


def test_newer_run_outranks_older_high_attempt_retry():
    runs = [
        {"id": 10, "name": "CI", "run_attempt": 9, "created_at": "2026-01-01", "status": "completed", "conclusion": "success"},
        {"id": 11, "name": "CI", "run_attempt": 1, "created_at": "2026-01-02", "status": "completed", "conclusion": "failure"},
    ]
    ok, _ = mod.evaluate_latest_runs(runs, ["CI"])
    assert not ok


def test_rejects_ambiguous_token_sources():
    try:
        mod.select_token({"GH_TOKEN": "a", "GITHUB_TOKEN": "b"})
    except RuntimeError:
        pass
    else:
        raise AssertionError("different dual-token sources must fail closed")
    assert mod.select_token({"GH_TOKEN": "a"}) == "a"
    assert mod.select_token({"GITHUB_TOKEN": "b"}) == "b"


def test_manifest_is_loaded_and_semantically_validated():
    assert mod.validate_manifest(manifest()) == []
    bad = manifest()
    del bad["required_status_checks"]
    assert mod.validate_manifest(bad)
    bad = manifest()
    bad["review_policy"]["mystery"] = True
    assert mod.validate_manifest(bad)
    bad = manifest()
    bad["bypass_actors"] = [{"actor_id": 1}]
    assert mod.validate_manifest(bad)




def test_unsupported_ruleset_pattern_is_indeterminate():
    ruleset = {"target": "branch", "conditions": {"ref_name": {"include": ["refs/heads/release/[0-9]"], "exclude": []}}}
    assert mod.ref_condition_applies(ruleset, "release/1") is None


def test_unknown_exclusion_pattern_is_indeterminate():
    ruleset = {"target": "branch", "conditions": {"ref_name": {"include": ["~ALL"], "exclude": ["refs/heads/release/[0-9]"]}}}
    assert mod.ref_condition_applies(ruleset, "release/1") is None


def test_classic_branch_name_is_percent_encoded_as_one_segment():
    originals = (mod.request, mod.list_all_rulesets)
    seen = []
    def fake_request(token, method, url, payload=None, allow_404=False):
        seen.append(url)
        if url.endswith("/repos/mirrornode/example"):
            return {"default_branch": "release/v1"}
        if "/branches/release%2Fv1/protection" in url:
            return dict(mod.CONFIRMED_404)
        raise AssertionError(url)
    mod.request = fake_request
    mod.list_all_rulesets = lambda token, repo: []
    try:
        result = mod.effective_default_branch_protection("t", "mirrornode/example")
        assert result["complete"] is True
        assert result["classic_state"] == "absent_404_confirmed"
        assert any("/branches/release%2Fv1/protection" in url for url in seen)
    finally:
        mod.request, mod.list_all_rulesets = originals


def test_classic_none_is_unknown_not_confirmed_absence():
    originals = (mod.request, mod.list_all_rulesets)
    def fake_request(token, method, url, payload=None, allow_404=False):
        if url.endswith("/repos/mirrornode/example"):
            return {"default_branch": "main"}
        if "/branches/main/protection" in url:
            return None
        raise AssertionError(url)
    mod.request = fake_request
    mod.list_all_rulesets = lambda token, repo: []
    try:
        result = mod.effective_default_branch_protection("t", "mirrornode/example")
        assert result["complete"] is False
        assert result["classic_state"] == "unknown"
        assert any("confirmed 404" in item for item in result["diagnostics"])
    finally:
        mod.request, mod.list_all_rulesets = originals


def test_classic_403_is_incomplete_not_absence():
    originals = (mod.request, mod.list_all_rulesets)
    def fake_request(token, method, url, payload=None, allow_404=False):
        if url.endswith("/repos/mirrornode/example"):
            return {"default_branch": "main"}
        if "/branches/main/protection" in url:
            raise RuntimeError("GitHub GET denied: 403")
        raise AssertionError(url)
    mod.request = fake_request
    mod.list_all_rulesets = lambda token, repo: []
    try:
        result = mod.effective_default_branch_protection("t", "mirrornode/example")
        assert result["complete"] is False
        assert result["classic_state"] == "denied_or_unreadable"
        assert any("403" in item for item in result["diagnostics"])
    finally:
        mod.request, mod.list_all_rulesets = originals


def test_missing_bypass_field_is_not_empty_bypass_list():
    originals = (mod.request, mod.list_all_rulesets)
    def fake_request(token, method, url, payload=None, allow_404=False):
        if url.endswith("/repos/mirrornode/example"):
            return {"default_branch": "main"}
        if "/branches/main/protection" in url:
            return dict(mod.CONFIRMED_404)
        raise AssertionError(url)
    mod.request = fake_request
    mod.list_all_rulesets = lambda token, repo: [{"id": 1, "target": "branch", "enforcement": "active", "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}}, "rules": []}]
    try:
        missing = mod.effective_default_branch_protection("t", "mirrornode/example")
        assert missing["complete"] is False
        mod.list_all_rulesets = lambda token, repo: [{"id": 1, "target": "branch", "enforcement": "active", "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}}, "bypass_actors": [], "rules": []}]
        empty = mod.effective_default_branch_protection("t", "mirrornode/example")
        assert empty["complete"] is True
    finally:
        mod.request, mod.list_all_rulesets = originals


def test_classic_missing_bypass_fields_make_surface_incomplete():
    originals = (mod.request, mod.list_all_rulesets)
    def fake_request(token, method, url, payload=None, allow_404=False):
        if url.endswith("/repos/mirrornode/example"):
            return {"default_branch": "main"}
        if "/branches/main/protection" in url:
            return {
                "enforce_admins": {"enabled": True},
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "bypass_pull_request_allowances": {"users": [], "teams": []},
                },
            }
        raise AssertionError(url)
    mod.request = fake_request
    mod.list_all_rulesets = lambda token, repo: []
    try:
        result = mod.effective_default_branch_protection("t", "mirrornode/example")
        assert result["complete"] is False
        assert any("apps" in item and "bypass allowances" in item for item in result["diagnostics"])
    finally:
        mod.request, mod.list_all_rulesets = originals


def test_classic_bypass_evidence_preserves_source_visibility():
    classic = {
        "enforce_admins": {"enabled": False},
        "required_pull_request_reviews": {
            "bypass_pull_request_allowances": {
                "users": [{"login": "ops"}],
                "teams": [],
                "apps": [{"slug": "deploy"}],
            }
        },
    }
    evidence = mod._aggregate_effective({"repository": {}, "rulesets": [], "classic": classic})["bypass_actors"]
    sources = {item.get("source") for item in evidence}
    assert "classic_branch_protection.enforce_admins.enabled" in sources
    assert "classic_branch_protection.required_pull_request_reviews.bypass_pull_request_allowances.users" in sources
    assert "classic_branch_protection.required_pull_request_reviews.bypass_pull_request_allowances.apps" in sources


def test_classic_linear_history_contributes_required_rule():
    s = {"repository": {"allow_squash_merge": True}, "rulesets": [], "classic": {"required_linear_history": {"enabled": True}, "allow_deletions": {"enabled": False}, "allow_force_pushes": {"enabled": False}, "enforce_admins": {"enabled": True}, "required_pull_request_reviews": {}}}
    assert "required_linear_history" in mod._aggregate_effective(s)["rule_types"]


def test_required_check_identity_preserves_integration_id():
    s = surface()
    rule = next(r for r in s["rulesets"][0]["rules"] if r["type"] == "required_status_checks")
    rule["parameters"]["required_status_checks"] = [{"context": "validate", "integration_id": 12345}]
    check = mod._aggregate_effective(s)["status_checks"][0]
    assert check["context"] == "validate"
    assert check["producer"]["id"] == 12345
    assert check["producer"]["bound"] is True
    assert "integration_id" in check["producer"]["source"]


def test_ruleset_strict_required_checks_are_preserved():
    s = surface()
    rule = next(r for r in s["rulesets"][0]["rules"] if r["type"] == "required_status_checks")
    rule["parameters"]["strict_required_status_checks_policy"] = False
    s["rulesets"].append(
        {
            "id": 2,
            "bypass_actors": [],
            "rules": [
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": True,
                        "required_status_checks": [{"context": "deploy"}],
                    },
                }
            ],
        }
    )
    policy = mod._aggregate_effective(s)["strict_required_status_checks_policy"]
    assert policy["required"] is True
    assert any(item["value"] is True for item in policy["sources"])
    assert any("strict_required_status_checks_policy" in item["source"] for item in policy["sources"])


def test_classic_strict_required_checks_are_preserved():
    classic = {
        "required_status_checks": {
            "strict": True,
            "checks": [{"context": "CI", "app_id": 321}],
        }
    }
    policy = mod._aggregate_effective({"repository": {}, "rulesets": [], "classic": classic})["strict_required_status_checks_policy"]
    assert policy["required"] is True
    assert policy["sources"] == [
        {
            "source": "classic_branch_protection.required_status_checks.strict",
            "value": True,
            "available": True,
        }
    ]


def test_same_context_wrong_producer_is_unsatisfied():
    required = [mod._required_check_identity("validate", producer_kind="integration", producer_id=123, source="ruleset:1")]
    runs = [{"id": 1, "name": "validate", "head_sha": "head", "status": "completed", "conclusion": "success", "app": {"id": 999}}]
    outcome, errors = mod.evaluate_required_checks(required, runs, [], "head")
    assert outcome == "UNSATISFIED"
    assert any("producer mismatch" in error for error in errors)


def test_unknown_required_check_producer_holds():
    required = [mod._required_check_identity("validate", producer_kind="integration", producer_id=None, source="ruleset:1", field_present=False)]
    outcome, errors = mod.evaluate_required_checks(required, [], [], "head")
    assert outcome == "INDETERMINATE"
    assert any("producer visibility" in error for error in errors)


def test_read_required_check_evidence_requests_all_check_runs():
    originals = (mod.paginate_object_items, mod.paginate)
    seen = []
    def fake_paginate_object_items(token, url, key):
        seen.append(url)
        assert key == "check_runs"
        return []
    mod.paginate_object_items = fake_paginate_object_items
    mod.paginate = lambda token, url: []
    try:
        mod.read_required_check_evidence("t", "mirrornode/example", "head")
        assert any("filter=all" in url for url in seen)
        assert not any("filter=latest" in url for url in seen)
    finally:
        mod.paginate_object_items, mod.paginate = originals


def test_unbound_required_context_is_indeterminate_even_with_successful_same_named_check():
    required = [mod._required_check_identity("validate", producer_kind="integration", producer_id=None, source="ruleset:1")]
    runs = [{"id": 1, "name": "validate", "head_sha": "head", "status": "completed", "conclusion": "success", "app": {"id": 321}}]
    statuses = [{"context": "validate", "state": "success"}]
    outcome, errors = mod.evaluate_required_checks(required, runs, statuses, "head")
    assert outcome == "INDETERMINATE"
    assert any("producer unbound" in error for error in errors)


def test_bound_non_actions_check_does_not_require_actions_workflow_mapping():
    required = [mod._required_check_identity("external-ci", producer_kind="integration", producer_id=777, source="ruleset:1")]
    runs = [{"id": 1, "name": "external-ci", "head_sha": "head", "status": "completed", "conclusion": "success", "app": {"id": 777, "slug": "third-party-ci", "name": "Third Party CI"}}]
    outcome, errors = mod.evaluate_required_checks(required, runs, [], "head", [], ["validate"])
    assert outcome == "SATISFIED"
    assert errors == []


def test_github_actions_check_still_requires_resolved_workflow_provenance():
    required = [mod._required_check_identity("validate", producer_kind="integration", producer_id=321, source="ruleset:1")]
    runs = [{"id": 1, "name": "validate", "head_sha": "head", "status": "completed", "conclusion": "success", "app": {"id": 321, "slug": "github-actions", "name": "GitHub Actions"}, "check_suite": {"id": 100}}]
    workflows = [{"id": 50, "name": "validate", "workflow_id": 9, "path": ".github/workflows/validate.yml", "check_suite_id": 999, "event": "pull_request", "head_sha": "head", "run_number": 1, "run_attempt": 1, "status": "completed", "conclusion": "success"}]
    outcome, errors = mod.evaluate_required_checks(required, runs, [], "head", workflows, [".github/workflows/validate.yml"])
    assert outcome == "INDETERMINATE"
    assert any("workflow provenance unavailable" in error for error in errors)


def test_unknown_check_provider_without_workflow_mapping_is_indeterminate():
    required = [mod._required_check_identity("validate", producer_kind="integration", producer_id=321, source="ruleset:1")]
    runs = [{"id": 1, "name": "validate", "head_sha": "head", "status": "completed", "conclusion": "success", "app": {"id": 321}, "check_suite": {"id": 100}}]
    outcome, errors = mod.evaluate_required_checks(required, runs, [], "head", [], ["validate"])
    assert outcome == "INDETERMINATE"
    assert any("provider identity unavailable" in error for error in errors)


def test_unrelated_successful_workflow_cannot_satisfy_required_check_gate():
    required = [mod._required_check_identity("validate", producer_kind="integration", producer_id=321, source="ruleset:1")]
    runs = [{"id": 1, "name": "validate", "head_sha": "head", "status": "completed", "conclusion": "success", "app": {"id": 321}, "check_suite": {"id": 100}}]
    workflows = [{"id": 50, "name": "validate", "workflow_id": 9, "path": ".github/workflows/validate.yml", "check_suite_id": 999, "event": "pull_request", "head_sha": "head", "run_number": 1, "run_attempt": 1, "status": "completed", "conclusion": "success"}]
    outcome, errors = mod.evaluate_required_checks(required, runs, [], "head", workflows, [".github/workflows/validate.yml"])
    assert outcome == "INDETERMINATE"
    assert any("workflow provenance unavailable" in error for error in errors)


def test_required_check_newer_failure_outranks_older_retry_success():
    required = [mod._required_check_identity("validate", producer_kind="integration", producer_id=321, source="ruleset:1")]
    runs = [
        {"id": 10, "name": "validate", "head_sha": "head", "status": "completed", "conclusion": "success", "completed_at": "2026-01-03", "app": {"id": 321}, "check_suite": {"id": 100}},
        {"id": 11, "name": "validate", "head_sha": "head", "status": "completed", "conclusion": "failure", "completed_at": "2026-01-02", "app": {"id": 321}, "check_suite": {"id": 101}},
    ]
    workflows = [
        {"id": 50, "name": "validate", "workflow_id": 9, "path": ".github/workflows/validate.yml", "check_suite_id": 100, "event": "pull_request", "head_sha": "head", "run_number": 7, "run_attempt": 9, "status": "completed", "conclusion": "success"},
        {"id": 51, "name": "validate", "workflow_id": 9, "path": ".github/workflows/validate.yml", "check_suite_id": 101, "event": "pull_request", "head_sha": "head", "run_number": 8, "run_attempt": 1, "status": "completed", "conclusion": "failure"},
    ]
    outcome, errors = mod.evaluate_required_checks(required, runs, [], "head", workflows, [".github/workflows/validate.yml"])
    assert outcome == "UNSATISFIED"
    assert any("required check non-success" in error for error in errors)


def test_required_check_definite_failure_outranks_indeterminate_peer():
    required = [
        mod._required_check_identity("external-ci", producer_kind="integration", producer_id=777, source="ruleset:1"),
        mod._required_check_identity("unknown-ci", producer_kind="integration", producer_id=888, source="ruleset:1"),
    ]
    runs = [
        {"id": 1, "name": "external-ci", "head_sha": "head", "status": "completed", "conclusion": "failure", "app": {"id": 777, "slug": "third-party-ci", "name": "Third Party CI"}},
        {"id": 2, "name": "unknown-ci", "head_sha": "head", "status": "completed", "conclusion": "success", "app": {"id": 888}},
    ]
    outcome, errors = mod.evaluate_required_checks(required, runs, [], "head", [], ["validate"])
    assert outcome == "UNSATISFIED"
    assert any("required check non-success" in error for error in errors)
    assert any("provider identity unavailable" in error for error in errors)


def test_review_threads_paginate_to_completion():
    original = mod.request
    calls = []
    def fake_request(token, method, url, payload=None, allow_404=False):
        calls.append(payload["variables"]["cursor"])
        if payload["variables"]["cursor"] is None:
            return {"data": {"repository": {"pullRequest": {"reviewDecision": "APPROVED", "reviewThreads": {"nodes": [{"id": "T1", "isResolved": True, "isOutdated": False}], "pageInfo": {"hasNextPage": True, "endCursor": "next"}}}}}}
        return {"data": {"repository": {"pullRequest": {"reviewDecision": "APPROVED", "reviewThreads": {"nodes": [{"id": "T2", "isResolved": False, "isOutdated": False}], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}}
    mod.request = fake_request
    try:
        gate = mod.read_review_gate_state("t", "mirrornode/example", 7)
        assert calls == [None, "next"]
        assert gate["total_discovered"] == 2
        assert gate["unresolved_current"] == 1
    finally:
        mod.request = original


def test_latest_push_requires_repo_ref_and_exact_resulting_head():
    original = mod.paginate
    mod.paginate = lambda token, url: [
        {"id": "1", "type": "PushEvent", "created_at": "2026-01-01", "actor": {"login": "alice"}, "payload": {"ref": "refs/heads/feature", "head": "wrong"}},
        {"id": "2", "type": "PushEvent", "created_at": "2026-01-02", "actor": {"login": "bob"}, "payload": {"ref": "refs/heads/feature", "head": "head"}},
    ]
    pr = {"head": {"ref": "feature", "repo": {"full_name": "mirrornode/example"}}}
    try:
        evidence = mod.read_latest_push_evidence("t", "mirrornode/example", pr, "head")
        assert evidence["actor"] == "bob"
        assert evidence["resulting_head_sha"] == "head"
        assert evidence["availability"] == "observed"
        assert evidence["authority"] == "repository_events_observed_not_fully_authoritative"
    finally:
        mod.paginate = original


def test_missing_pr_head_repository_makes_push_provenance_unknown():
    original = mod.paginate
    seen = []
    def fake_paginate(token, url):
        seen.append(url)
        return []
    mod.paginate = fake_paginate
    pr = {"head": {"ref": "feature", "repo": None}}
    try:
        try:
            mod.read_latest_push_evidence("t", "mirrornode/example", pr, "head")
        except RuntimeError as exc:
            assert "head repository unavailable" in str(exc)
        else:
            raise AssertionError("missing PR head repository must fail closed")
        assert seen == []
    finally:
        mod.paginate = original


def test_workflow_scope_and_identity_are_required_for_exact_head():
    runs = [{"id": 1, "name": "CI", "workflow_id": 9, "path": ".github/workflows/ci.yml", "event": "push", "head_sha": "head", "run_number": 1, "run_attempt": 1, "created_at": "2026-01-01", "status": "completed", "conclusion": "success"}]
    ok, errors = mod.evaluate_latest_runs(runs, [".github/workflows/ci.yml"], "head")
    assert not ok and any("scope mismatch" in error for error in errors)
    runs[0]["event"] = "pull_request"
    runs.append({**runs[0], "id": 2, "workflow_id": 10})
    ok, errors = mod.evaluate_latest_runs(runs, [".github/workflows/ci.yml"], "head")
    assert not ok and any("ambiguous" in error for error in errors)


def test_exact_head_display_name_only_workflow_requirement_holds():
    runs = [
        {
            "id": 1,
            "name": "Validate Estate Wrapper",
            "workflow_id": 330861093,
            "path": ".github/workflows/validate-estate.yml",
            "event": "pull_request",
            "head_sha": "head",
            "run_number": 1,
            "run_attempt": 1,
            "created_at": "2026-01-01",
            "status": "completed",
            "conclusion": "success",
        }
    ]
    ok, errors = mod.evaluate_latest_runs(runs, ["Validate Estate Wrapper"], "head")
    assert not ok
    assert any("trusted workflow identity unavailable" in error for error in errors)


def test_exact_head_workflow_path_requirement_matches_exact_path():
    runs = [
        {
            "id": 1,
            "name": "Validate Estate Wrapper",
            "workflow_id": 330861093,
            "path": ".github/workflows/validate-estate.yml",
            "event": "pull_request",
            "head_sha": "head",
            "run_number": 1,
            "run_attempt": 1,
            "created_at": "2026-01-01",
            "status": "completed",
            "conclusion": "success",
        }
    ]
    ok, errors = mod.evaluate_latest_runs(runs, ["path:.github/workflows/validate-estate.yml"], "head")
    assert ok and not errors


def test_exact_head_workflow_id_requirement_matches_exact_id():
    runs = [
        {
            "id": 1,
            "name": "Validate Estate Wrapper",
            "workflow_id": 330861093,
            "path": ".github/workflows/validate-estate.yml",
            "event": "pull_request",
            "head_sha": "head",
            "run_number": 1,
            "run_attempt": 1,
            "created_at": "2026-01-01",
            "status": "completed",
            "conclusion": "success",
        }
    ]
    for requirement in (["330861093"], ["id:330861093"]):
        ok, errors = mod.evaluate_latest_runs(runs, requirement, "head")
        assert ok and not errors


def test_same_display_name_wrong_workflow_path_cannot_clear_gate():
    runs = [
        {
            "id": 1,
            "name": "Validate Estate Wrapper",
            "workflow_id": 42,
            "path": ".github/workflows/unrelated.yml",
            "event": "pull_request",
            "head_sha": "head",
            "run_number": 1,
            "run_attempt": 1,
            "created_at": "2026-01-01",
            "status": "completed",
            "conclusion": "success",
        }
    ]
    ok, errors = mod.evaluate_latest_runs(runs, ["path:.github/workflows/validate-estate.yml"], "head")
    assert not ok and any("required workflow missing" in error for error in errors)

    required = [mod._required_check_identity("validate", producer_kind="integration", producer_id=321, source="ruleset:1")]
    check_runs = [{"id": 1, "name": "validate", "head_sha": "head", "status": "completed", "conclusion": "success", "app": {"id": 321, "slug": "github-actions", "name": "GitHub Actions"}, "check_suite": {"id": 100}}]
    workflow_runs = [{**runs[0], "check_suite_id": 100}]
    outcome, check_errors = mod.evaluate_required_checks(
        required,
        check_runs,
        [],
        "head",
        workflow_runs,
        ["path:.github/workflows/validate-estate.yml"],
    )
    assert outcome == "INDETERMINATE"
    assert any("workflow provenance unavailable" in error for error in check_errors)


def _install_snapshot_fakes(
    *,
    head_changes=False,
    unresolved=False,
    push_available=True,
    initial_base_repo="mirrornode/example",
    initial_base_ref="main",
    initial_base_sha="base",
    final_base_repo=None,
    final_base_ref=None,
    final_base_sha=None,
    strict_required=False,
    ruleset_strict_policy=STRICT_POLICY_ABSENT,
    classic_strict_policy=STRICT_POLICY_ABSENT,
    compare_behind_by=0,
    compare_unavailable=False,
):
    state = {"reads": 0, "compare_urls": []}
    def fake_request(token, method, url, payload=None, allow_404=False):
        if "/pulls/7" in url:
            state["reads"] += 1
            sha = "changed" if head_changes and state["reads"] > 1 else "head"
            if state["reads"] > 1:
                base_repo = final_base_repo or initial_base_repo
                base_ref = final_base_ref or initial_base_ref
                base_sha = final_base_sha or initial_base_sha
            else:
                base_repo = initial_base_repo
                base_ref = initial_base_ref
                base_sha = initial_base_sha
            return {
                "head": {"sha": sha, "ref": "feature", "repo": {"full_name": "mirrornode/example"}},
                "user": {"login": "author"},
                "base": {"ref": base_ref, "sha": base_sha, "repo": {"full_name": base_repo}},
            }
        if "/compare/" in url:
            state["compare_urls"].append(url)
            if compare_unavailable:
                raise RuntimeError("compare unavailable")
            return {"behind_by": compare_behind_by}
        raise AssertionError(url)
    mod.request = fake_request
    mod.paginate = lambda token, url: [{"id": 22, "state": "APPROVED", "commit_id": "head", "user": {"login": "reviewer"}}]
    mod.paginate_object_items = lambda token, url, key: [{"id": 33, "name": "CI", "workflow_id": 9, "path": ".github/workflows/ci.yml", "check_suite_id": 9001, "event": "pull_request", "run_number": 2, "run_attempt": 1, "created_at": "2026-01-01", "status": "completed", "conclusion": "success", "head_sha": "head"}]
    mod.read_reviewer_permissions = lambda token, repo, reviews: ({"reviewer": {"permission": "write"}}, [])
    mod.read_review_gate_state = lambda token, repo, number: {"collection_state": "complete", "review_decision": "APPROVED", "total_discovered": 1 if unresolved else 0, "unresolved_current": 1 if unresolved else 0, "unresolved_outdated": 0, "threads": [{"id": "T1", "is_resolved": False, "is_outdated": False}] if unresolved else []}
    if push_available:
        mod.read_latest_push_evidence = lambda token, repo, pr, sha: {"actor": "pusher", "repository": repo, "ref": "refs/heads/feature", "resulting_head_sha": sha, "event_type": "PushEvent", "availability": "observed", "authority": "repository_events_observed_not_fully_authoritative"}
    else:
        def no_push(*args):
            raise RuntimeError("push provenance unavailable")
        mod.read_latest_push_evidence = no_push
    mod.read_required_check_evidence = lambda token, repo, sha: {"check_runs": [{"id": 44, "name": "CI", "head_sha": sha, "status": "completed", "conclusion": "success", "app": {"id": 321}, "check_suite": {"id": 9001}}], "statuses": []}
    good = surface()
    rule = next(r for r in good["rulesets"][0]["rules"] if r["type"] == "required_status_checks")
    rule["parameters"]["required_status_checks"] = [{"context": "CI", "integration_id": 321}]
    if strict_required:
        rule["parameters"]["strict_required_status_checks_policy"] = True
    if ruleset_strict_policy is not STRICT_POLICY_ABSENT:
        rule["parameters"]["strict_required_status_checks_policy"] = ruleset_strict_policy
    if classic_strict_policy is not STRICT_POLICY_ABSENT:
        good["classic"] = {
            "required_status_checks": {
                "strict": classic_strict_policy,
                "checks": [{"context": "CI", "app_id": 321}],
            }
        }
    mod.effective_default_branch_protection = lambda token, repo: good
    return state


def test_malformed_ruleset_strict_required_check_policy_makes_protection_indeterminate():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    state = _install_snapshot_fakes(ruleset_strict_policy="true")
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest())
        assert snap["status"] == "HOLD"
        assert snap["evidence_state"] == "UNKNOWN"
        assert snap["control_outcome"] == "INDETERMINATE"
        assert snap["completeness"]["protection"] == "partial"
        assert state["compare_urls"] == []
        protection_debt = next(item for item in snap["operator_debt"] if item["code"] == "protection-hold")
        assert "strict_required_status_checks_policy" in protection_debt["detail"]
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_malformed_classic_strict_required_check_policy_makes_protection_indeterminate():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    state = _install_snapshot_fakes(classic_strict_policy="true")
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest())
        assert snap["status"] == "HOLD"
        assert snap["evidence_state"] == "UNKNOWN"
        assert snap["control_outcome"] == "INDETERMINATE"
        assert snap["completeness"]["protection"] == "partial"
        assert state["compare_urls"] == []
        protection_debt = next(item for item in snap["operator_debt"] if item["code"] == "protection-hold")
        assert "classic_branch_protection.required_status_checks.strict" in protection_debt["detail"]
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_final_pr_reread_rejects_base_retarget_without_head_change():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    _install_snapshot_fakes(final_base_ref="release")
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest())
        assert snap["status"] == "HOLD"
        assert snap["evidence_state"] == "STALE"
        assert snap["control_outcome"] == "UNSATISFIED"
        assert snap["final_observed_head_sha"] == "head"
        assert snap["evidence"]["base"]["ref"] == "main"
        assert snap["evidence"]["final_base"]["ref"] == "release"
        codes = {item["code"] for item in snap["operator_debt"]}
        assert "protected-base-hold" in codes
        assert "head-stability-hold" not in codes
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_final_base_sha_change_stales_readiness_without_strict_policy():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    _install_snapshot_fakes(final_base_sha="new-base")
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest())
        assert snap["status"] == "HOLD"
        assert snap["evidence_state"] == "STALE"
        assert snap["control_outcome"] == "INDETERMINATE"
        assert snap["base_identity_stable"] is False
        assert snap["evidence"]["base"]["sha"] == "base"
        assert snap["evidence"]["final_base"]["sha"] == "new-base"
        assert snap["evidence"]["strict_required_check_synchronization"]["availability"] == "not_required"
        codes = {item["code"] for item in snap["operator_debt"]}
        assert "protected-base-hold" in codes
        assert "strict-required-check-sync-hold" not in codes
        protection_debt = next(item for item in snap["operator_debt"] if item["code"] == "protected-base-hold")
        assert "mirrornode/example:main@base" in protection_debt["detail"]
        assert "mirrornode/example:main@new-base" in protection_debt["detail"]
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_strict_required_checks_hold_when_head_is_behind_base():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    _install_snapshot_fakes(strict_required=True, compare_behind_by=2)
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest())
        assert snap["status"] == "HOLD"
        assert snap["evidence_state"] == "HOLD"
        assert snap["control_outcome"] == "UNSATISFIED"
        assert snap["evidence"]["strict_required_check_synchronization"]["behind_by"] == 2
        codes = {item["code"] for item in snap["operator_debt"]}
        assert "strict-required-check-sync-hold" in codes
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_strict_required_checks_hold_when_compare_evidence_unavailable():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    _install_snapshot_fakes(strict_required=True, compare_unavailable=True)
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest())
        assert snap["status"] == "HOLD"
        assert snap["evidence_state"] == "UNKNOWN"
        assert snap["control_outcome"] == "INDETERMINATE"
        sync = snap["evidence"]["strict_required_check_synchronization"]
        assert sync["availability"] == "unavailable"
        assert sync["error"] == "compare unavailable"
        codes = {item["code"] for item in snap["operator_debt"]}
        assert "strict-required-check-sync-hold" in codes
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_strict_required_checks_pass_only_when_not_behind_exact_base():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    state = _install_snapshot_fakes(strict_required=True, compare_behind_by=0)
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest())
        assert snap["status"] == "PASS"
        assert snap["evidence_state"] == "VERIFIED"
        assert snap["control_outcome"] == "SATISFIED"
        sync = snap["evidence"]["strict_required_check_synchronization"]
        assert sync["availability"] == "observed"
        assert sync["base_sha"] == "base"
        assert sync["expected_head_sha"] == "head"
        assert sync["behind_by"] == 0
        assert state["compare_urls"] == [sync["source_endpoint"]]
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_strict_sync_evidence_becomes_stale_if_base_sha_moves():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    _install_snapshot_fakes(strict_required=True, compare_behind_by=0, final_base_sha="new-base")
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest())
        assert snap["status"] == "HOLD"
        assert snap["evidence_state"] == "STALE"
        assert snap["control_outcome"] == "INDETERMINATE"
        sync = snap["evidence"]["strict_required_check_synchronization"]
        assert sync["availability"] == "observed"
        assert sync["base_sha"] == "base"
        assert sync["behind_by"] == 0
        assert snap["evidence"]["final_base"]["sha"] == "new-base"
        codes = {item["code"] for item in snap["operator_debt"]}
        assert "strict-required-check-sync-hold" in codes
        assert "protected-base-hold" in codes
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_read_only_snapshot_binds_verified_evidence_and_latest_runs():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    _install_snapshot_fakes()
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest())
        assert snap["status"] == "PASS"
        assert snap["evidence_state"] == "VERIFIED"
        assert snap["control_outcome"] == "SATISFIED"
        assert snap["evidence"]["latest_push"]["actor"] == "pusher"
        assert snap["evidence"]["observed_push_event_provenance"]["availability"] == "observed"
        assert snap["evidence"]["required_checks"][0]["producer"]["id"] == 321
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_snapshot_unknown_push_evidence_cannot_pass():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    _install_snapshot_fakes(push_available=False)
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest(), trusted_latest_push_actor="pusher")
        assert snap["status"] == "HOLD"
        assert snap["evidence_state"] == "UNKNOWN"
        assert snap["control_outcome"] == "INDETERMINATE"
        assert snap["evidence"]["observed_push_event_provenance"]["availability"] == "unavailable"
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_snapshot_definite_failure_remains_unsatisfied_with_unrelated_unknown_evidence():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    _install_snapshot_fakes(push_available=False)
    mod.read_required_check_evidence = lambda token, repo, sha: {"check_runs": [{"id": 44, "name": "CI", "head_sha": sha, "status": "completed", "conclusion": "failure", "app": {"id": 321}, "check_suite": {"id": 9001}}], "statuses": []}
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest(), trusted_latest_push_actor="pusher")
        assert snap["status"] == "HOLD"
        assert snap["evidence_state"] == "UNKNOWN"
        assert snap["control_outcome"] == "UNSATISFIED"
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_known_unresolved_mandatory_control_cannot_emit_overall_verified_evidence_state():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    _install_snapshot_fakes(unresolved=True)
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest())
        assert snap["status"] == "HOLD"
        assert snap["evidence_state"] == "HOLD"
        assert snap["control_outcome"] == "UNSATISFIED"
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_snapshot_holds_on_head_change_and_unresolved_thread():
    originals = (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection)
    _install_snapshot_fakes(head_changes=True, unresolved=True)
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", [".github/workflows/ci.yml"], manifest())
        assert snap["status"] == "HOLD"
        assert snap["evidence_state"] == "STALE"
        assert snap["control_outcome"] == "UNSATISFIED"
        codes = {item["code"] for item in snap["operator_debt"]}
        assert "review-thread-hold" in codes
        assert "head-stability-hold" in codes
    finally:
        (mod.request, mod.paginate, mod.paginate_object_items, mod.read_reviewer_permissions, mod.read_review_gate_state, mod.read_latest_push_evidence, mod.read_required_check_evidence, mod.effective_default_branch_protection) = originals


def test_snapshot_hardening_preserves_non_pr_rules_and_update_payload_behavior():
    existing = {"name": "MIRRORNODE Baseline Main Protection", "target": "branch", "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}}, "bypass_actors": [], "rules": [{"type": "deletion"}, {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "CI", "integration_id": 7}]}}, {"type": "pull_request", "parameters": {"required_approving_review_count": 2}}]}
    payload = mod.update_payload(existing, manifest())
    check = next(r for r in payload["rules"] if r["type"] == "required_status_checks")
    assert check == existing["rules"][1]
    assert next(r for r in payload["rules"] if r["type"] == "pull_request")["parameters"]["required_approving_review_count"] == 2


def test_single_operator_manifest_exception_is_explicit_and_repo_scoped():
    m = manifest()
    m["repositories"].append("mirrornode/MIRRORNODE-INFRA")
    m["single_operator_repositories"] = ["mirrornode/MIRRORNODE-INFRA"]
    assert mod.validate_manifest(m) == []

    normal = mod.review_policy_for_repo(m, "mirrornode/example")
    single = mod.review_policy_for_repo(m, "mirrornode/MIRRORNODE-INFRA")

    assert normal["required_approving_review_count"] == 1
    assert normal["require_last_push_approval"] is True
    assert single["required_approving_review_count"] == 0
    assert single["require_last_push_approval"] is False
    assert m["review_policy"]["required_approving_review_count"] == 1
    assert m["review_policy"]["require_last_push_approval"] is True


def test_single_operator_manifest_exception_must_be_in_repository_scope():
    m = manifest()
    m["single_operator_repositories"] = ["mirrornode/MIRRORNODE-INFRA"]
    errors = mod.validate_manifest(m)
    assert any("subset of repositories" in error for error in errors)


def test_single_operator_policy_allows_zero_approvals_without_weakening_other_controls():
    m = manifest()
    m["repositories"].append("mirrornode/MIRRORNODE-INFRA")
    m["single_operator_repositories"] = ["mirrornode/MIRRORNODE-INFRA"]
    review = dict(FLOOR)
    review["required_approving_review_count"] = 0
    review["require_last_push_approval"] = False

    ok, errors = mod.validate_effective_protection(
        surface(review=review),
        m,
        "mirrornode/MIRRORNODE-INFRA",
    )
    assert ok, errors

    ok, errors = mod.validate_effective_protection(
        surface(review=review),
        m,
        "mirrornode/example",
    )
    assert not ok
    assert any("approval count below manifest floor" in error for error in errors)
    assert any("require_last_push_approval not effectively enforced" in error for error in errors)


def test_single_operator_create_payload_is_repo_scoped():
    m = manifest()
    m["repositories"].append("mirrornode/MIRRORNODE-INFRA")
    m["single_operator_repositories"] = ["mirrornode/MIRRORNODE-INFRA"]

    single_payload = mod.create_payload(m, "mirrornode/MIRRORNODE-INFRA")
    normal_payload = mod.create_payload(m, "mirrornode/example")

    single_review = next(
        rule for rule in single_payload["rules"] if rule["type"] == "pull_request"
    )["parameters"]
    normal_review = next(
        rule for rule in normal_payload["rules"] if rule["type"] == "pull_request"
    )["parameters"]

    assert single_review["required_approving_review_count"] == 0
    assert single_review["require_last_push_approval"] is False
    assert normal_review["required_approving_review_count"] == 1
    assert normal_review["require_last_push_approval"] is True


def test_single_operator_update_payload_never_weakens_existing_stronger_review_policy():
    m = manifest()
    m["repositories"].append("mirrornode/MIRRORNODE-INFRA")
    m["single_operator_repositories"] = ["mirrornode/MIRRORNODE-INFRA"]
    existing = {
        "name": "MIRRORNODE Baseline Main Protection",
        "target": "branch",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [],
        "rules": [
            {
                "type": "pull_request",
                "parameters": dict(FLOOR),
            }
        ],
    }

    payload = mod.update_payload(existing, m, "mirrornode/MIRRORNODE-INFRA")
    review = next(
        rule for rule in payload["rules"] if rule["type"] == "pull_request"
    )["parameters"]

    assert review["required_approving_review_count"] == 1
    assert review["require_last_push_approval"] is True



def test_changes_requested_authoritative_decision_blocks_exact_head_approval():
    pr = {"head": {"sha": "head"}, "user": {"login": "author"}}
    reviews = [
        {
            "id": 1,
            "user": {"login": "reviewer"},
            "state": "APPROVED",
            "commit_id": "head",
            "submitted_at": "2026-09-04T00:00:00Z",
        }
    ]
    ok, errors = mod.evaluate_exact_head_approval(
        pr,
        reviews,
        "head",
        "pusher",
        {"reviewer": {"permission": "write"}},
        1,
        {},
        "CHANGES_REQUESTED",
    )
    assert not ok
    assert any("CHANGES_REQUESTED" in error for error in errors)


def test_single_operator_zero_approval_does_not_require_approved_review_decision():
    pr = {"head": {"sha": "head"}, "user": {"login": "author"}}
    ok, errors = mod.evaluate_exact_head_approval(
        pr,
        [],
        "head",
        "pusher",
        {},
        0,
        {"required_approving_review_count": 0},
        "REVIEW_REQUIRED",
    )
    assert ok, errors


def test_external_required_check_newer_pending_run_outranks_older_completed_success():
    required = [
        mod._required_check_identity(
            "external-ci",
            producer_kind="integration",
            producer_id=77,
            source="ruleset:1",
        )
    ]
    runs = [
        {
            "id": 100,
            "name": "external-ci",
            "head_sha": "head",
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-09-04T00:00:00Z",
            "completed_at": "2026-09-04T00:01:00Z",
            "app": {"id": 77, "slug": "external-ci"},
        },
        {
            "id": 101,
            "name": "external-ci",
            "head_sha": "head",
            "status": "in_progress",
            "conclusion": None,
            "started_at": "2026-09-04T00:02:00Z",
            "completed_at": None,
            "app": {"id": 77, "slug": "external-ci"},
        },
    ]
    outcome, errors = mod.evaluate_required_checks(
        required,
        runs,
        [],
        "head",
        [],
        [],
    )
    assert outcome == "UNSATISFIED"
    assert any("status=in_progress" in error for error in errors)


def test_bound_required_status_without_producer_receipt_is_indeterminate():
    required = [
        mod._required_check_identity(
            "external-ci",
            producer_kind="integration",
            producer_id=77,
            source="ruleset:1",
        )
    ]
    statuses = [
        {
            "id": 200,
            "context": "external-ci",
            "sha": "head",
            "state": "success",
            "created_at": "2026-09-04T00:00:00Z",
        }
    ]
    outcome, errors = mod.evaluate_required_checks(
        required,
        [],
        statuses,
        "head",
        [],
        [],
    )
    assert outcome == "INDETERMINATE"
    assert any("status producer provenance unavailable" in error for error in errors)


def test_github_successful_required_check_conclusions_include_neutral_and_skipped():
    required = [
        mod._required_check_identity(
            "external-ci",
            producer_kind="integration",
            producer_id=77,
            source="ruleset:1",
        )
    ]
    for conclusion in ("success", "neutral", "skipped"):
        runs = [
            {
                "id": 300,
                "name": "external-ci",
                "head_sha": "head",
                "status": "completed",
                "conclusion": conclusion,
                "started_at": "2026-09-04T00:00:00Z",
                "completed_at": "2026-09-04T00:01:00Z",
                "app": {"id": 77, "slug": "external-ci"},
            }
        ]
        outcome, errors = mod.evaluate_required_checks(
            required,
            runs,
            [],
            "head",
            [],
            [],
        )
        assert outcome == "SATISFIED", (conclusion, errors)


def run_all():
    tests = [(name, value) for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for name, test in sorted(tests):
        test()
        print(f"PASS {name}")
    print(f"estate protection tests: PASS ({len(tests)} tests)")


if __name__ == "__main__":
    run_all()
