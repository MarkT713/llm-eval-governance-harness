from pathlib import Path

from fastapi.testclient import TestClient

from guardbench.adapters import FixtureAdapter
from guardbench.api import app
from guardbench.runner import execute_suite

ROOT = Path(__file__).resolve().parents[1]


def test_full_fixture_suite_passes(tmp_path):
    report, path = execute_suite(ROOT / "corpora/safe_red_team.json", FixtureAdapter(), "1",
                                 tmp_path / "runs", tmp_path / "audit.jsonl")
    assert path.exists()
    assert report.metrics["total"] == 28
    assert report.metrics["pass_rate"] == 1.0
    assert set(report.metrics["categories"]) == {"prompt_injection", "data_leakage",
        "insecure_tool_use", "hallucination", "over_refusal", "fairness_proxy", "robustness"}


def test_dashboard_and_health_are_available():
    client = TestClient(app)
    assert client.get("/").status_code == 200
    assert "GuardBench" in client.get("/").text
    assert client.get("/health").json() == {"status": "ok", "mode": "synthetic-demo"}
