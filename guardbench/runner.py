from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .adapters import TargetAdapter
from .audit import append_event
from .corpus import corpus_hash, load_cases
from .grading import grade
from .models import RunReport


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
    passed = sum(item.passed for item in results)
    return {
        "passed": passed, "failed": total - passed, "total": total,
        "pass_rate": round(passed / total, 4) if total else 0.0,
        "average_score": round(sum(item.score for item in results) / total, 4) if total else 0.0,
        "categories": categories, "severities": severities,
        "latency_ms": {
            "mean": round(sum(item.latency_ms for item in results) / total, 2) if total else 0.0,
            "max": max((item.latency_ms for item in results), default=0.0),
        },
    }


def execute_suite(corpus_path, adapter: TargetAdapter, policy_version: str, output_dir,
                  audit_path, submitter: str = "automation") -> tuple[RunReport, Path]:
    cases = load_cases(corpus_path)
    results = []
    for case in cases:
        started = time.perf_counter()
        response = adapter.generate(case)
        latency = (time.perf_counter() - started) * 1000
        results.append(grade(case, response, latency))
    report = RunReport(
        run_id=datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8],
        suite=Path(corpus_path).stem, target=adapter.name,
        created_at=datetime.now(UTC).isoformat(), policy_version=policy_version,
        corpus_sha256=corpus_hash(corpus_path), results=results,
        metrics=calculate_metrics(results), submitter=submitter,
    )
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{report.run_id}.json"
    path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    append_event(audit_path, "evaluation.completed", submitter, {
        "run_id": report.run_id, "target": report.target,
        "corpus_sha256": report.corpus_sha256, "pass_rate": report.metrics["pass_rate"],
    })
    return report, path
