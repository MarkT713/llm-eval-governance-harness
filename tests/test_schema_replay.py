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
    source = json.loads((ROOT / "corpora/safe_red_team.json").read_text())
    source["cases"][0]["unexpected"] = "must fail closed"
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(source))
    with pytest.raises(ValidationError, match="extra_forbidden"):
        load_cases(path)


def test_offline_replay_is_stable(tmp_path):
    corpus = ROOT / "corpora/safe_red_team.json"
    report, path = execute_suite(
        corpus, FixtureAdapter(), "1.0.0", tmp_path / "runs", tmp_path / "audit.jsonl"
    )
    replay = replay_report(path, corpus, tmp_path / "audit.jsonl")
    assert replay["run_id"] == report.run_id
    assert replay["stable"]
    assert replay["replay_metrics"]["pass_rate"] == 1.0


def test_replay_rejects_changed_corpus(tmp_path):
    corpus = ROOT / "corpora/safe_red_team.json"
    _, path = execute_suite(
        corpus, FixtureAdapter(), "1.0.0", tmp_path / "runs", tmp_path / "audit.jsonl"
    )
    changed = tmp_path / "changed.json"
    changed.write_text(corpus.read_text() + " ")
    with pytest.raises(ValueError, match="not comparable"):
        replay_report(path, changed, tmp_path / "audit.jsonl")
