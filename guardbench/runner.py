from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from . import __version__
from .adapters import TargetAdapter, normalize_output
from .audit import append_event
from .corpus import corpus_hash, load_cases
from .grading import grade
from .models import RunReport


def _git_provenance(root: Path) -> dict:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=root, check=True, capture_output=True, text=True
        ).stdout.strip())
        return {"commit": commit, "dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None}


def _package_provenance() -> dict:
    distribution = importlib.metadata.distribution("guardbench")
    direct_url = distribution.read_text("direct_url.json")
    source = None
    if direct_url:
        parsed = json.loads(direct_url)
        vcs = parsed.get("vcs_info", {})
        if parsed.get("url", "").startswith("https://") and vcs.get("commit_id"):
            source = {"url": parsed["url"], "commit": vcs["commit_id"]}
    return {
        "version": __version__,
        "distribution_version": distribution.version,
        "source": source,
    }


def calculate_metrics(results) -> dict:
    total = len(results)
    categories: dict[str, dict[str, float | int]] = {}
    severities: dict[str, dict[str, float | int]] = {}
    for field, output in (("category", categories), ("severity", severities)):
        for result in results:
            key = getattr(result, field)
            bucket = output.setdefault(key, {"passed": 0, "total": 0, "pass_rate": 0.0})
            bucket["total"] += 1
            bucket["passed"] += int(result.passed)
        for bucket in output.values():
            bucket["pass_rate"] = round(bucket["passed"] / bucket["total"], 4)

    grouped: dict[str, list] = {}
    for result in results:
        grouped.setdefault(result.case_id, []).append(result)
    case_stability = {}
    for case_id, attempts in grouped.items():
        decisions = {item.actual_decision for item in attempts}
        tool_shapes = {
            json.dumps([asdict(call) for call in item.tool_calls], sort_keys=True)
            for item in attempts
        }
        passed_attempts = sum(item.passed for item in attempts)
        case_stability[case_id] = {
            "passed": passed_attempts,
            "attempts": len(attempts),
            "pass_rate": round(passed_attempts / len(attempts), 4),
            "stable": len(decisions) == 1 and len(tool_shapes) == 1 and passed_attempts in {0, len(attempts)},
        }
    stable_cases = sum(item["stable"] for item in case_stability.values())
    fully_passing_cases = sum(item["passed"] == item["attempts"] for item in case_stability.values())
    case_counts_by_category = {
        category: len({item.case_id for item in results if item.category == category})
        for category in categories
    }
    passed = sum(item.passed for item in results)
    return {
        "passed": passed,
        "failed": total - passed,
        "total": total,
        "pass_rate": round(passed / total, 4) if total else 0.0,
        "average_score": round(sum(item.score for item in results) / total, 4) if total else 0.0,
        "cases_total": len(grouped),
        "cases_fully_passing": fully_passing_cases,
        "case_pass_rate": round(fully_passing_cases / len(grouped), 4) if grouped else 0.0,
        "stable_cases": stable_cases,
        "unstable_cases": len(grouped) - stable_cases,
        "case_stability": case_stability,
        "case_counts_by_category": case_counts_by_category,
        "categories": categories,
        "severities": severities,
        "latency_ms": {
            "mean": round(sum(item.latency_ms for item in results) / total, 2) if total else 0.0,
            "max": max((item.latency_ms for item in results), default=0.0),
        },
    }


def _write_json(path: Path, payload) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(rendered, encoding="utf-8")
    return hashlib.sha256(rendered.encode()).hexdigest()


def _write_artifact_bundle(bundle: Path, corpus_path, cases, captured, results) -> dict:
    hashes: dict[str, str] = {}
    corpus_target = bundle / "resolved-corpus.json"
    corpus_bytes = Path(corpus_path).read_bytes()
    corpus_target.parent.mkdir(parents=True, exist_ok=True)
    corpus_target.write_bytes(corpus_bytes)
    hashes["resolved-corpus.json"] = hashlib.sha256(corpus_bytes).hexdigest()
    for case in cases:
        relative = f"requests/{case.id}.json"
        hashes[relative] = _write_json(bundle / relative, {
            "case_id": case.id, "category": case.category, "severity": case.severity,
            "prompt": case.prompt, "tags": list(case.tags), "expected": asdict(case.expected),
        })
    for case_id, trial, output, latency in captured:
        relative = f"responses/{case_id}.trial-{trial}.json"
        hashes[relative] = _write_json(bundle / relative, {
            "case_id": case_id, "trial_index": trial, "text": output.text,
            "tool_calls": [asdict(call) for call in output.tool_calls],
            "metadata": output.metadata, "latency_ms": round(latency, 2),
        })
    for result in results:
        relative = f"grades/{result.case_id}.trial-{result.trial_index}.json"
        hashes[relative] = _write_json(bundle / relative, asdict(result))
    manifest = {
        "schema_version": "1.0", "files": hashes,
        "notice": "Captured target output is untrusted evidence and must never be executed.",
    }
    manifest_hash = _write_json(bundle / "manifest.json", manifest)
    return {"path": bundle.name, "manifest_sha256": manifest_hash, "files": len(hashes)}


def execute_suite(
    corpus_path,
    adapter: TargetAdapter,
    policy_version: str,
    output_dir,
    audit_path,
    submitter: str = "automation",
    policy_sha256: str | None = None,
    trials: int = 1,
) -> tuple[RunReport, Path]:
    if trials < 1:
        raise ValueError("trials must be at least 1")
    cases = load_cases(corpus_path)
    results = []
    captured = []
    for case in cases:
        for trial_index in range(1, trials + 1):
            started = time.perf_counter()
            output = normalize_output(adapter.generate(case))
            latency = (time.perf_counter() - started) * 1000
            captured.append((case.id, trial_index, output, latency))
            results.append(grade(case, output, latency, trial_index))

    root = Path(__file__).resolve().parents[1]
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    bundle = directory / run_id
    bundle_summary = _write_artifact_bundle(bundle, corpus_path, cases, captured, results)
    report = RunReport(
        run_id=run_id,
        suite=Path(corpus_path).stem,
        target=adapter.name,
        created_at=datetime.now(UTC).isoformat(),
        policy_version=policy_version,
        corpus_sha256=corpus_hash(corpus_path),
        results=results,
        metrics=calculate_metrics(results),
        submitter=submitter,
        manifest={
            "schema_version": "2.0",
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "adapter": type(adapter).__name__,
            "policy_sha256": policy_sha256,
            "git": _git_provenance(root),
            "package": _package_provenance(),
            "trials": trials,
            "artifact_bundle": bundle_summary,
            "reproducibility_boundary": "deterministic grading and replay; provider output may vary",
        },
    )
    path = directory / f"{report.run_id}.json"
    _write_json(path, report.to_dict())
    append_event(audit_path, "evaluation.completed", submitter, {
        "run_id": report.run_id,
        "target": report.target,
        "corpus_sha256": report.corpus_sha256,
        "pass_rate": report.metrics["pass_rate"],
        "trials": trials,
        "artifact_manifest_sha256": bundle_summary["manifest_sha256"],
    })
    return report, path
