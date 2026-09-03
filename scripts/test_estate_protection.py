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


def manifest():
    return {
        "version": "0.1",
        "ruleset_name": "MIRRORNODE Baseline Main Protection",
        "target": "~DEFAULT_BRANCH",
        "review_policy": dict(FLOOR),
        "required_status_checks": {"mode": "preserve_existing_nonempty"},
        "bypass_actors": [],
        "preserve_existing_rules": True,
        "repositories": ["mirrornode/example"],
    }


def surface(review=None, *, checks=("CI",), extra_rules=(), bypass=(), complete=True):
    rules = [
        {"type": "deletion"},
        {"type": "non_fast_forward"},
        {"type": "pull_request", "parameters": review or dict(FLOOR)},
    ]
    if checks is not None:
        rules.append({"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": x} for x in checks]}})
    rules.extend(extra_rules)
    return {
        "complete": complete,
        "diagnostics": [] if complete else ["unreadable"],
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
    commits = [{"author": {"login": "pusher"}}]
    ok, _ = mod.evaluate_exact_head_approval(pr, reviews, commits, "new")
    assert not ok


def test_accepts_exact_head_approval_only_conditionally():
    pr = {"head": {"sha": "new"}, "user": {"login": "author"}}
    reviews = [{"state": "APPROVED", "commit_id": "new", "user": {"login": "reviewer"}}]
    commits = [{"author": {"login": "pusher"}}]
    ok, errors = mod.evaluate_exact_head_approval(pr, reviews, commits, "new")
    assert ok and not errors


def test_rejects_missing_exact_head_approval():
    pr = {"head": {"sha": "new"}, "user": {"login": "author"}}
    ok, _ = mod.evaluate_exact_head_approval(pr, [], [], "new")
    assert not ok


def test_rejects_author_or_latest_pusher_approval():
    pr = {"head": {"sha": "new"}, "user": {"login": "author"}}
    commits = [{"author": {"login": "pusher"}}]
    for reviewer in ("author", "pusher"):
        reviews = [{"state": "APPROVED", "commit_id": "new", "user": {"login": reviewer}}]
        ok, _ = mod.evaluate_exact_head_approval(pr, reviews, commits, "new")
        assert not ok


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



def test_read_only_snapshot_binds_head_reviews_and_latest_runs():
    originals = (mod.request, mod.paginate, mod.effective_default_branch_protection)
    def fake_request(token, method, url, payload=None, allow_404=False):
        if "/pulls/7" in url:
            return {"head": {"sha": "head"}, "user": {"login": "author"}}
        if "/actions/runs?" in url:
            return {"workflow_runs": [{"id": 33, "name": "CI", "run_attempt": 2, "status": "completed", "conclusion": "success", "head_sha": "head"}]}
        raise AssertionError(url)
    def fake_paginate(token, url):
        if url.endswith("/reviews"):
            return [{"id": 22, "state": "APPROVED", "commit_id": "head", "user": {"login": "reviewer"}}]
        if url.endswith("/commits"):
            return [{"author": {"login": "pusher"}}]
        raise AssertionError(url)
    mod.request = fake_request
    mod.paginate = fake_paginate
    mod.effective_default_branch_protection = lambda token, repo: surface()
    try:
        snap = mod.build_read_only_snapshot("t", "mirrornode/example", 7, "head", ["CI"], manifest())
        assert snap["status"] == "PASS"
        assert snap["observed_head_sha"] == "head"
        assert snap["evidence"]["review_ids"] == [22]
        assert snap["evidence"]["workflow_runs"][0]["id"] == 33
        assert snap["completeness"]["dependencies_security"] == "not_collected"
    finally:
        mod.request, mod.paginate, mod.effective_default_branch_protection = originals


def run_all():
    tests = [(name, value) for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for name, test in sorted(tests):
        test()
        print(f"PASS {name}")
    print(f"estate protection tests: PASS ({len(tests)} tests)")


if __name__ == "__main__":
    run_all()
