import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from guardbench.adapters import FixtureAdapter
from guardbench.corpus import load_cases
from guardbench.replay import replay_report
from guardbench.runner import execute_suite

ROOT = Path(__file__).resolve().parents[1]


def test_corpus_rejects_unknown_fields(tmp_path):
    source = json.loads((ROOT / "guardbench/resources/corpora/safe_red_team.json").read_text())
    source["cases"][0]["unexpected"] = "must fail closed"
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(source))
    with pytest.raises(ValidationError, match="extra_forbidden"):
        load_cases(path)


def test_corpus_rejects_conflicting_tool_policy(tmp_path):
    source = json.loads((ROOT / "guardbench/resources/corpora/safe_red_team.json").read_text())
    source["cases"][0]["expected"]["allowed_tools"] = ["delete_record"]
    source["cases"][0]["expected"]["forbidden_tools"] = ["delete_record"]
    path = tmp_path / "invalid-tools.json"
    path.write_text(json.dumps(source))
    with pytest.raises(ValidationError, match="both allowed and forbidden"):
        load_cases(path)


def test_corpus_defined_canary_is_graded(tmp_path):
    source = json.loads((ROOT / "guardbench/resources/corpora/safe_red_team.json").read_text())
    source["canary"] = "CUSTOM_SYNTHETIC_SECRET"
    source["cases"] = [source["cases"][0]]
    source["cases"][0]["expected"]["must_not_contain_canary"] = True
    source["cases"][0]["fixture_response"] = "CUSTOM_SYNTHETIC_SECRET"
    path = tmp_path / "custom-canary.json"
    path.write_text(json.dumps(source))
    report, _ = execute_suite(
        path, FixtureAdapter(), "1", tmp_path / "runs", tmp_path / "audit.jsonl"
    )
    assert not report.results[0].passed
    assert "leaked protected canary" in report.results[0].reasons


def test_offline_replay_is_stable(tmp_path):
    corpus = ROOT / "guardbench/resources/corpora/safe_red_team.json"
    report, path = execute_suite(
        corpus, FixtureAdapter(), "1.0.0", tmp_path / "runs", tmp_path / "audit.jsonl"
    )
    replay = replay_report(path, corpus, tmp_path / "audit.jsonl")
    assert replay["run_id"] == report.run_id
    assert replay["stable"]
    assert replay["replay_metrics"]["pass_rate"] == 1.0


def test_replay_rejects_changed_corpus(tmp_path):
    corpus = ROOT / "guardbench/resources/corpora/safe_red_team.json"
    _, path = execute_suite(
        corpus, FixtureAdapter(), "1.0.0", tmp_path / "runs", tmp_path / "audit.jsonl"
    )
    changed = tmp_path / "changed.json"
    changed.write_text(corpus.read_text() + " ")
    with pytest.raises(ValueError, match="not comparable"):
        replay_report(path, changed, tmp_path / "audit.jsonl")


def test_replay_rejects_report_without_verified_bundle(tmp_path):
    corpus = ROOT / "guardbench/resources/corpora/safe_red_team.json"
    _, path = execute_suite(
        corpus, FixtureAdapter(), "1.0.0", tmp_path / "runs", tmp_path / "audit.jsonl"
    )
    report = json.loads(path.read_text())
    report["manifest"].pop("artifact_bundle")
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="verified artifact bundle is required"):
        replay_report(path, corpus, tmp_path / "audit.jsonl")


def test_replay_rejects_report_or_corpus_substitution(tmp_path):
    corpus = ROOT / "guardbench/resources/corpora/safe_red_team.json"
    _, path = execute_suite(
        corpus, FixtureAdapter(), "1.0.0", tmp_path / "runs", tmp_path / "audit.jsonl"
    )
    report = json.loads(path.read_text())
    report["metrics"]["pass_rate"] = 0.0
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="artifact bundle integrity failure"):
        replay_report(path, corpus, tmp_path / "audit.jsonl")

    _, path = execute_suite(
        corpus, FixtureAdapter(), "1.0.0", tmp_path / "runs2", tmp_path / "audit2.jsonl"
    )
    changed = tmp_path / "changed-bound.json"
    source = json.loads(corpus.read_text())
    source["cases"][0]["prompt"] += " changed"
    changed.write_text(json.dumps(source))
    report = json.loads(path.read_text())
    from guardbench.corpus import corpus_hash

    report["corpus_sha256"] = corpus_hash(changed)
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="artifact bundle integrity failure"):
        replay_report(path, changed, tmp_path / "audit2.jsonl")
