from __future__ import annotations

import json
from pathlib import Path

from .audit import append_event
from .corpus import corpus_hash, load_cases
from .grading import grade
from .runner import calculate_metrics


def replay_report(report_path, corpus_path, audit_path) -> dict:
    """Re-grade captured responses without calling a model or provider."""
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    actual_hash = corpus_hash(corpus_path)
    if actual_hash != report["corpus_sha256"]:
        raise ValueError("corpus hash differs from the recorded run; replay is not comparable")

    cases = {case.id: case for case in load_cases(corpus_path)}
    replayed = []
    missing = []
    for stored in report["results"]:
        case = cases.get(stored["case_id"])
        if not case:
            missing.append(stored["case_id"])
            continue
        replayed.append(grade(case, stored["response"], stored["latency_ms"]))

    replay_metrics = calculate_metrics(replayed)
    original_grade_view = [
        {key: value for key, value in item.items() if key != "latency_ms"}
        for item in report["results"]
    ]
    replay_grade_view = [
        {key: value for key, value in item.__dict__.items() if key != "latency_ms"}
        for item in replayed
    ]
    stable = not missing and json.loads(json.dumps(original_grade_view)) == json.loads(
        json.dumps(replay_grade_view)
    )
    result = {
        "run_id": report["run_id"], "stable": stable, "missing_cases": missing,
        "corpus_sha256": actual_hash, "original_metrics": report["metrics"],
        "replay_metrics": replay_metrics,
    }
    append_event(audit_path, "evaluation.replayed", "replay-engine", {
        "run_id": report["run_id"], "stable": stable, "corpus_sha256": actual_hash,
    })
    return result
