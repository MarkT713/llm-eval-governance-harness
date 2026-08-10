from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .audit import append_event


def load_json(path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate_gate(report: dict, policy: dict, baseline: dict | None = None) -> dict:
    failures: list[str] = []
    warnings: list[str] = []
    metrics = report["metrics"]
    thresholds = policy["thresholds"]
    if metrics["pass_rate"] < thresholds["minimum_overall_pass_rate"]:
        failures.append("overall pass rate below policy minimum")
    for severity in thresholds["zero_failure_severities"]:
        failed = metrics["severities"].get(severity, {}).get("total", 0) - metrics["severities"].get(severity, {}).get("passed", 0)
        if failed:
            failures.append(f"{failed} {severity} case(s) failed")
    for category, minimum in thresholds["category_minimums"].items():
        actual = metrics["categories"].get(category, {}).get("pass_rate")
        if actual is None:
            failures.append(f"required category missing: {category}")
        elif actual < minimum:
            failures.append(f"{category} pass rate {actual:.2%} below {minimum:.2%}")
    if baseline:
        delta = baseline["metrics"]["pass_rate"] - metrics["pass_rate"]
        if delta > thresholds["maximum_baseline_regression"]:
            failures.append(f"overall regression {delta:.2%} exceeds tolerance")
        elif delta > 0:
            warnings.append(f"overall regression of {delta:.2%}")
    return {
        "decision": "block" if failures else "conditional_pass",
        "failures": failures, "warnings": warnings,
        "requires_human_approval": True,
        "policy_version": policy["version"],
    }


def apply_gate(report_path, policy_path, audit_path, baseline_path=None) -> dict:
    report = load_json(report_path)
    policy = load_json(policy_path)
    baseline = load_json(baseline_path) if baseline_path else None
    gate = evaluate_gate(report, policy, baseline)
    report["gate"] = gate
    report["status"] = "blocked" if gate["decision"] == "block" else "awaiting_approval"
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    append_event(audit_path, "governance.gate_evaluated", "policy-engine", {
        "run_id": report["run_id"], "decision": gate["decision"], "failures": gate["failures"],
    })
    return report


def approve(report_path, reviewer: str, role: str, rationale: str, audit_path) -> dict:
    if role not in {"risk_owner", "security_reviewer", "release_manager"}:
        raise ValueError("reviewer role is not authorized")
    report = load_json(report_path)
    if report["status"] != "awaiting_approval":
        raise ValueError("only a passing run awaiting approval can be approved")
    if reviewer == report["submitter"]:
        raise ValueError("submitter cannot approve their own run")
    if not rationale.strip():
        raise ValueError("approval rationale is required")
    approval = {
        "reviewer": reviewer, "role": role, "rationale": rationale.strip(),
        "timestamp": datetime.now(UTC).isoformat(),
    }
    report["approvals"].append(approval)
    report["status"] = "approved"
    unsigned = json.dumps(report, sort_keys=True, separators=(",", ":"))
    report["artifact_sha256"] = hashlib.sha256(unsigned.encode()).hexdigest()
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    append_event(audit_path, "governance.run_approved", reviewer, {
        "run_id": report["run_id"], "role": role, "artifact_sha256": report["artifact_sha256"],
    })
    return report
