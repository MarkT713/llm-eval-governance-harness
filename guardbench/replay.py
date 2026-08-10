from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from .audit import append_event
from .corpus import corpus_hash, load_cases
from .grading import grade
from .models import TargetOutput, ToolCall
from .runner import calculate_metrics


def _verify_bundle(report_path: Path, report: dict) -> dict:
    bundle_info = report.get("manifest", {}).get("artifact_bundle")
    if not bundle_info:
        return {"status": "legacy_report", "verified": None}
    bundle = report_path.parent / bundle_info["path"]
    if not bundle.exists():
        transient_bundle = report_path.parent / ".guardbench-runs" / bundle_info["path"]
        if transient_bundle.exists():
            bundle = transient_bundle
    manifest_path = bundle / "manifest.json"
    if not manifest_path.exists():
        return {"status": "missing", "verified": False}
    manifest_bytes = manifest_path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != bundle_info["manifest_sha256"]:
        return {"status": "manifest_hash_mismatch", "verified": False}
    manifest = json.loads(manifest_bytes)
    mismatches = []
    for relative, expected_hash in manifest["files"].items():
        artifact = bundle / relative
        if not artifact.exists() or hashlib.sha256(artifact.read_bytes()).hexdigest() != expected_hash:
            mismatches.append(relative)
    return {"status": "valid" if not mismatches else "artifact_mismatch",
            "verified": not mismatches, "mismatches": mismatches}


def replay_report(report_path, corpus_path, audit_path) -> dict:
    """Re-grade captured responses without calling a model or provider."""
    report_path = Path(report_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    actual_hash = corpus_hash(corpus_path)
    if actual_hash != report["corpus_sha256"]:
        raise ValueError("corpus hash differs from the recorded run; replay is not comparable")

    bundle_verification = _verify_bundle(report_path, report)
    if bundle_verification["verified"] is False:
        raise ValueError(f"artifact bundle integrity failure: {bundle_verification['status']}")

    cases = {case.id: case for case in load_cases(corpus_path)}
    replayed = []
    missing = []
    for stored in report["results"]:
        case = cases.get(stored["case_id"])
        if not case:
            missing.append(stored["case_id"])
            continue
        tool_calls = tuple(ToolCall(**call) for call in stored.get("tool_calls", []))
        output = TargetOutput(
            text=stored["response"], tool_calls=tool_calls,
            metadata=stored.get("output_metadata", {}),
        )
        replayed.append(grade(
            case, output, stored["latency_ms"], stored.get("trial_index", 1)
        ))

    replay_metrics = calculate_metrics(replayed)
    original_grade_view = [
        {key: value for key, value in item.items() if key != "latency_ms"}
        for item in report["results"]
    ]
    replay_grade_view = [
        {key: value for key, value in asdict(item).items() if key != "latency_ms"}
        for item in replayed
    ]
    stable = not missing and json.loads(json.dumps(original_grade_view)) == json.loads(
        json.dumps(replay_grade_view)
    )
    result = {
        "run_id": report["run_id"],
        "stable": stable,
        "missing_cases": missing,
        "corpus_sha256": actual_hash,
        "artifact_bundle": bundle_verification,
        "original_metrics": report["metrics"],
        "replay_metrics": replay_metrics,
    }
    append_event(audit_path, "evaluation.replayed", "replay-engine", {
        "run_id": report["run_id"], "stable": stable, "corpus_sha256": actual_hash,
        "artifact_bundle_verified": bundle_verification["verified"],
    })
    return result
