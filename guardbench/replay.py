from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path, PurePosixPath

from .audit import append_event, verify_chain
from .corpus import corpus_hash, load_cases
from .grading import grade
from .models import TargetOutput, ToolCall, ToolTrace
from .runner import calculate_metrics


def _bundle_path(report_path: Path, bundle_info: dict) -> Path:
    direct = report_path.parent / bundle_info["path"]
    if direct.exists():
        return direct
    return report_path.parent / ".guardbench-runs" / bundle_info["path"]


def _verify_bundle(report_path: Path, report: dict, audit_path: Path) -> tuple[dict, Path | None, dict | None]:
    bundle_info = report.get("manifest", {}).get("artifact_bundle")
    if not bundle_info:
        return {"status": "bundle_required", "verified": False}, None, None
    if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}", bundle_info.get("path", "")):
        return {"status": "unsafe_bundle_path", "verified": False}, None, None
    bundle = _bundle_path(report_path, bundle_info)
    manifest_path = bundle / "manifest.json"
    if not manifest_path.exists():
        return {"status": "missing", "verified": False}, None, None
    manifest_bytes = manifest_path.read_bytes()
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest_hash != bundle_info["manifest_sha256"]:
        return {"status": "manifest_hash_mismatch", "verified": False}, None, None
    manifest = json.loads(manifest_bytes)
    case_ids = manifest.get("case_ids", [])
    trials = manifest.get("trials", 0)
    expected_files = {"resolved-corpus.json"}
    expected_files.update(f"requests/{case_id}.json" for case_id in case_ids)
    for case_id in case_ids:
        for trial in range(1, trials + 1):
            expected_files.add(f"responses/{case_id}.trial-{trial}.json")
            expected_files.add(f"grades/{case_id}.trial-{trial}.json")
    indexed_files = set(manifest.get("files", {}))
    actual_files = {
        str(path.relative_to(bundle)) for path in bundle.rglob("*") if path.is_file()
    } - {"manifest.json"}
    mismatches = sorted(expected_files ^ indexed_files | indexed_files ^ actual_files)
    unsafe_paths = {
        relative for relative in indexed_files
        if PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts
    }
    if unsafe_paths:
        mismatches.extend(f"unsafe_path:{path}" for path in sorted(unsafe_paths))
    if any(not re.fullmatch(r"[a-z0-9][a-z0-9-]+", case_id) for case_id in case_ids):
        mismatches.append("unsafe_case_id")
    if manifest.get("schema_version") != "2.0":
        mismatches.append("manifest_schema_version")
    for relative, expected_hash in manifest.get("files", {}).items():
        if relative in unsafe_paths:
            continue
        artifact = bundle / relative
        if not artifact.exists() or hashlib.sha256(artifact.read_bytes()).hexdigest() != expected_hash:
            mismatches.append(relative)

    audit_valid, _ = verify_chain(audit_path)
    anchored = False
    anchor_data = None
    if audit_valid:
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            if (
                event.get("event_type") == "evaluation.completed"
                and event.get("data", {}).get("run_id") == report.get("run_id")
                and event.get("data", {}).get("artifact_manifest_sha256") == manifest_hash
            ):
                anchored = True
                anchor_data = event["data"]
                break
    if manifest.get("run_id") != report.get("run_id"):
        mismatches.append("run_id")
    if not anchored:
        mismatches.append("audit_anchor")
    else:
        expected_anchor = {
            "target": report.get("target"),
            "corpus_sha256": report.get("corpus_sha256"),
            "pass_rate": report.get("metrics", {}).get("pass_rate"),
            "trials": report.get("manifest", {}).get("trials"),
        }
        for field, expected in expected_anchor.items():
            if anchor_data.get(field) != expected:
                mismatches.append(f"audit_{field}")
    result = {
        "status": "valid" if not mismatches else "artifact_mismatch",
        "verified": not mismatches,
        "mismatches": sorted(set(mismatches)),
        "audit_anchor_verified": anchored,
    }
    return result, bundle, manifest


def _grade_view(items: list[dict]) -> list[dict]:
    view = [{key: value for key, value in item.items() if key != "latency_ms"} for item in items]
    return json.loads(json.dumps(view, sort_keys=True))


def replay_report(report_path, corpus_path, audit_path) -> dict:
    """Re-grade only hash-verified captured responses without calling a target."""
    report_path = Path(report_path)
    audit_path = Path(audit_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    actual_hash = corpus_hash(corpus_path)
    if actual_hash != report["corpus_sha256"]:
        raise ValueError("corpus hash differs from the recorded run; replay is not comparable")

    verification, bundle, manifest = _verify_bundle(report_path, report, audit_path)
    if verification["verified"] is False:
        if verification["status"] == "bundle_required":
            raise ValueError("verified artifact bundle is required for replay")
        raise ValueError(f"artifact bundle integrity failure: {verification['status']}")

    resolved_corpus_hash = manifest["files"]["resolved-corpus.json"]
    if actual_hash != resolved_corpus_hash:
        raise ValueError("supplied corpus differs from the verified resolved corpus")
    if report.get("corpus_sha256") != resolved_corpus_hash:
        raise ValueError("report corpus hash differs from the verified resolved corpus")

    cases = {case.id: case for case in load_cases(corpus_path)}
    replayed = []
    verified_grades: list[dict] = []
    missing = []
    if set(manifest["case_ids"]) != set(cases):
        raise ValueError("artifact case set differs from the supplied corpus")
    for case_id in manifest["case_ids"]:
        case = cases[case_id]
        for trial in range(1, manifest["trials"] + 1):
            response = json.loads(
                (bundle / f"responses/{case_id}.trial-{trial}.json").read_text(encoding="utf-8")
            )
            proposals = tuple(ToolCall(**call) for call in response.get("tool_calls", []))
            trace = tuple(ToolTrace(**call) for call in response.get("trusted_tool_trace", []))
            output = TargetOutput(
                text=response["text"], tool_calls=proposals, trusted_tool_trace=trace,
                metadata=response.get("metadata", {}),
            )
            replayed.append(grade(case, output, response["latency_ms"], trial))
            verified_grades.append(json.loads(
                (bundle / f"grades/{case_id}.trial-{trial}.json").read_text(encoding="utf-8")
            ))

    replay_grade_dicts = [asdict(item) for item in replayed]
    grades_match_bundle = _grade_view(verified_grades) == _grade_view(replay_grade_dicts)
    report_matches_bundle = _grade_view(report["results"]) == _grade_view(verified_grades)
    replay_metrics = calculate_metrics(replayed)
    metrics_match_bundle = report.get("metrics") == replay_metrics
    stable = not missing and grades_match_bundle and report_matches_bundle and metrics_match_bundle
    result = {
        "run_id": report["run_id"],
        "stable": stable,
        "missing_cases": missing,
        "corpus_sha256": actual_hash,
        "artifact_bundle": verification,
        "report_matches_verified_bundle": report_matches_bundle,
        "grades_match_verified_responses": grades_match_bundle,
        "metrics_match_verified_bundle": metrics_match_bundle,
        "original_metrics": report["metrics"],
        "replay_metrics": replay_metrics,
    }
    append_event(audit_path, "evaluation.replayed", "replay-engine", {
        "run_id": report["run_id"], "stable": stable, "corpus_sha256": actual_hash,
        "artifact_bundle_verified": verification["verified"],
    })
    return result
