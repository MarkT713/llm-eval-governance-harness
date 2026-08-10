from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .audit import append_event
from .schema_models import PolicySchema


def load_json(path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def compare_baseline(report: dict, baseline: dict, tolerance: float) -> dict:
    compatibility_issues = []
    if baseline.get("status") != "approved" or not baseline.get("artifact_sha256"):
        compatibility_issues.append("baseline is not an approved integrity-bound artifact")
    else:
        unsigned_baseline = dict(baseline)
        declared_hash = unsigned_baseline.pop("artifact_sha256")
        calculated_hash = hashlib.sha256(
            json.dumps(unsigned_baseline, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if declared_hash != calculated_hash:
            compatibility_issues.append("baseline artifact SHA-256 is invalid")
    for field, label in (("corpus_sha256", "corpus hash"), ("policy_version", "policy version"),
                         ("target", "target")):
        if baseline.get(field) != report.get(field):
            compatibility_issues.append(f"{label} differs")
    baseline_policy_hash = baseline.get("manifest", {}).get("policy_sha256")
    report_policy_hash = report.get("manifest", {}).get("policy_sha256")
    if baseline_policy_hash and report_policy_hash and baseline_policy_hash != report_policy_hash:
        compatibility_issues.append("policy hash differs")

    def case_outcomes(source):
        grouped: dict[str, list[bool]] = {}
        for item in source.get("results", []):
            grouped.setdefault(item["case_id"], []).append(item["passed"])
        return {case_id: all(attempts) for case_id, attempts in grouped.items()}

    baseline_cases = case_outcomes(baseline)
    candidate_cases = case_outcomes(report)
    newly_failing = sorted(
        case_id for case_id in baseline_cases.keys() & candidate_cases.keys()
        if baseline_cases[case_id] and not candidate_cases[case_id]
    )
    newly_passing = sorted(
        case_id for case_id in baseline_cases.keys() & candidate_cases.keys()
        if not baseline_cases[case_id] and candidate_cases[case_id]
    )
    missing_cases = sorted(baseline_cases.keys() - candidate_cases.keys())
    added_cases = sorted(candidate_cases.keys() - baseline_cases.keys())

    slice_regressions = []
    slice_deltas = {"categories": {}, "severities": {}}
    for dimension in ("categories", "severities"):
        keys = baseline["metrics"].get(dimension, {}).keys() | report["metrics"].get(dimension, {}).keys()
        for key in keys:
            baseline_rate = baseline["metrics"].get(dimension, {}).get(key, {}).get("pass_rate", 0.0)
            candidate_rate = report["metrics"].get(dimension, {}).get(key, {}).get("pass_rate", 0.0)
            delta = round(candidate_rate - baseline_rate, 4)
            slice_deltas[dimension][key] = delta
            if -delta > tolerance:
                slice_regressions.append(f"{dimension}.{key} regressed by {-delta:.2%}")

    return {
        "comparable": not compatibility_issues,
        "compatibility_issues": compatibility_issues,
        "newly_failing_cases": newly_failing,
        "newly_passing_cases": newly_passing,
        "missing_cases": missing_cases,
        "added_cases": added_cases,
        "slice_deltas": slice_deltas,
        "slice_regressions": slice_regressions,
        "overall_delta": round(report["metrics"]["pass_rate"] - baseline["metrics"]["pass_rate"], 4),
    }


def evaluate_gate(report: dict, policy: dict, baseline: dict | None = None) -> dict:
    failures: list[str] = []
    warnings: list[str] = []
    metrics = report["metrics"]
    thresholds = policy["thresholds"]
    evidence_gaps: list[str] = []
    total_cases = metrics.get("cases_total", metrics.get("total", sum(
        bucket.get("total", 0) for bucket in metrics["categories"].values()
    )))
    if total_cases < thresholds.get("minimum_total_cases", 1):
        evidence_gaps.append("total case count below policy evidence minimum")
    for category, minimum_count in thresholds.get("minimum_cases_by_category", {}).items():
        actual_count = metrics.get("case_counts_by_category", {}).get(
            category, metrics["categories"].get(category, {}).get("total", 0)
        )
        if actual_count < minimum_count:
            evidence_gaps.append(
                f"{category} has {actual_count} case(s); policy requires {minimum_count}"
            )
    if metrics["pass_rate"] < thresholds["minimum_overall_pass_rate"]:
        failures.append("overall pass rate below policy minimum")
    unstable = metrics.get("unstable_cases", 0)
    if unstable > thresholds.get("maximum_unstable_cases", 0):
        failures.append(
            f"{unstable} unstable case(s) exceed policy maximum "
            f"{thresholds.get('maximum_unstable_cases', 0)}"
        )
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
    comparison = None
    if baseline:
        comparison = compare_baseline(report, baseline, thresholds["maximum_baseline_regression"])
        failures.extend(f"baseline is not comparable: {item}" for item in comparison["compatibility_issues"])
        failures.extend(f"newly failing baseline case: {item}" for item in comparison["newly_failing_cases"])
        failures.extend(comparison["slice_regressions"])
        if comparison["missing_cases"]:
            failures.append("candidate is missing baseline cases")
        delta = -comparison["overall_delta"]
        if delta > thresholds["maximum_baseline_regression"]:
            failures.append(f"overall regression {delta:.2%} exceeds tolerance")
        elif delta > 0:
            warnings.append(f"overall regression of {delta:.2%}")
    if evidence_gaps:
        failures.extend(evidence_gaps)
    decision = "conditional_pass"
    if comparison and not comparison["comparable"]:
        decision = "not_comparable"
    elif failures:
        decision = "block"
    return {
        "decision": decision,
        "failures": failures, "warnings": warnings,
        "baseline_comparison": comparison,
        "evidence": {
            "scope": policy.get("evidence_scope", "unspecified"),
            "sufficient_for_declared_scope": not evidence_gaps,
            "gaps": evidence_gaps,
            "notice": "Observed corpus performance is not proof of comprehensive model safety.",
        },
        "requires_human_approval": True,
        "policy_version": policy["version"],
    }


def apply_gate(report_path, policy_path, audit_path, baseline_path=None) -> dict:
    report = load_json(report_path)
    policy = PolicySchema.model_validate_json(Path(policy_path).read_text()).model_dump()
    baseline = load_json(baseline_path) if baseline_path else None
    gate = evaluate_gate(report, policy, baseline)
    report["gate"] = gate
    report["status"] = "awaiting_approval" if gate["decision"] == "conditional_pass" else "blocked"
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
