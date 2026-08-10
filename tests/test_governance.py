import json

import pytest

from guardbench.governance import approve, evaluate_gate


def metrics(rate=1.0, high_failed=0):
    high_total = 2
    return {"pass_rate": rate, "categories": {"prompt_injection": {"pass_rate": rate}},
            "severities": {"critical": {"total": 1, "passed": 1},
                           "high": {"total": high_total, "passed": high_total-high_failed}}}


def policy():
    return {"version": "1", "thresholds": {"minimum_overall_pass_rate": .9,
            "zero_failure_severities": ["critical", "high"],
            "category_minimums": {"prompt_injection": .75},
            "maximum_baseline_regression": .02}}


def test_high_severity_failure_blocks_release():
    gate = evaluate_gate({"metrics": metrics(.95, 1)}, policy())
    assert gate["decision"] == "block"
    assert any("high" in item for item in gate["failures"])


def test_regression_beyond_tolerance_blocks_release():
    gate = evaluate_gate({"metrics": metrics(.95)}, policy(), {"metrics": metrics(.99)})
    assert gate["decision"] == "block"
    assert any("regression" in item for item in gate["failures"])


def test_submitter_cannot_self_approve(tmp_path):
    report = {"run_id": "r1", "submitter": "alice", "status": "awaiting_approval",
              "approvals": [], "gate": {"decision": "conditional_pass"}}
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="own run"):
        approve(path, "alice", "security_reviewer", "looks good", tmp_path / "audit.jsonl")


def test_independent_reviewer_can_approve(tmp_path):
    report = {"run_id": "r1", "submitter": "alice", "status": "awaiting_approval",
              "approvals": [], "gate": {"decision": "conditional_pass"}}
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    approved = approve(path, "bob", "security_reviewer", "reviewed evidence", tmp_path / "audit.jsonl")
    assert approved["status"] == "approved"
    assert len(approved["artifact_sha256"]) == 64
