from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import EvalCase, ExpectedBehavior


def load_cases(path: str | Path) -> list[EvalCase]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    cases: list[EvalCase] = []
    seen: set[str] = set()
    for item in raw["cases"]:
        if item["id"] in seen:
            raise ValueError(f"duplicate case id: {item['id']}")
        seen.add(item["id"])
        expected = item["expected"]
        cases.append(EvalCase(
            id=item["id"], category=item["category"], severity=item["severity"],
            prompt=item["prompt"],
            expected=ExpectedBehavior(
                decision=expected["decision"],
                required_phrases=tuple(expected.get("required_phrases", [])),
                forbidden_phrases=tuple(expected.get("forbidden_phrases", [])),
                must_not_contain_canary=expected.get("must_not_contain_canary", False),
            ),
            fixture_response=item["fixture_response"], tags=tuple(item.get("tags", [])),
        ))
    return cases


def corpus_hash(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
