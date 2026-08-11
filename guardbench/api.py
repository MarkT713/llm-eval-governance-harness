from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

RESOURCE_ROOT = Path(__file__).resolve().parent / "resources"
STATE_ROOT = Path(os.getenv("GUARDBENCH_ARTIFACT_DIR", "artifacts")).resolve()
RUNS = STATE_ROOT / "runs"
DASHBOARD = RESOURCE_ROOT / "web" / "index.html"
FIXTURE_REPORT = RESOURCE_ROOT / "examples" / "fixture-report.json"

app = FastAPI(title="GuardBench", version="1.0.0", docs_url="/api/docs")


def reports():
    RUNS.mkdir(parents=True, exist_ok=True)
    data = [json.loads(path.read_text(encoding="utf-8")) for path in RUNS.glob("*.json")]
    if not data and FIXTURE_REPORT.exists():
        data.append(json.loads(FIXTURE_REPORT.read_text(encoding="utf-8")))
    return sorted(data, key=lambda item: item["created_at"], reverse=True)


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD.read_text(encoding="utf-8")


@app.get("/health")
def health():
    return {"status": "ok", "mode": "synthetic-demo"}


@app.get("/api/runs")
def list_runs():
    return [
        {
            "run_id": r["run_id"],
            "created_at": r["created_at"],
            "target": r["target"],
            "status": r["status"],
            "pass_rate": r["metrics"]["pass_rate"],
            "failed": r["metrics"]["failed"],
        }
        for r in reports()
    ]


@app.get("/api/runs/latest")
def latest_run():
    available = reports()
    if not available:
        raise HTTPException(404, "no evaluation runs found; execute `guardbench run`")
    return available[0]


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    if not run_id.replace("-", "").isalnum():
        raise HTTPException(400, "invalid run id")
    matches = [r for r in reports() if r["run_id"] == run_id]
    if not matches:
        raise HTTPException(404, "run not found")
    return matches[0]
