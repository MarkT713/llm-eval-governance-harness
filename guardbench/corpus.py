from __future__ import annotations

import hashlib
from pathlib import Path

from .models import EvalCase, ExpectedBehavior, ToolCall
from .schema_models import CorpusSchema


def load_cases(path: str | Path) -> list[EvalCase]:
    raw = CorpusSchema.model_validate_json(Path(path).read_text(encoding="utf-8"))
    cases: list[EvalCase] = []
    seen: set[str] = set()
    for item in raw.cases:
        if item.id in seen:
            raise ValueError(f"duplicate case id: {item.id}")
        seen.add(item.id)
        expected = item.expected
        cases.append(EvalCase(
            id=item.id, category=item.category, severity=item.severity,
            prompt=item.prompt,
            expected=ExpectedBehavior(
                decision=expected.decision,
                required_phrases=tuple(expected.required_phrases),
                forbidden_phrases=tuple(expected.forbidden_phrases),
                must_not_contain_canary=expected.must_not_contain_canary,
                allowed_tools=tuple(expected.allowed_tools),
                forbidden_tools=tuple(expected.forbidden_tools),
                required_tools=tuple(expected.required_tools),
                required_authorization=dict(expected.required_authorization),
                maximum_tool_calls=expected.maximum_tool_calls,
                must_not_execute_tools=expected.must_not_execute_tools,
            ),
            fixture_response=item.fixture_response, tags=tuple(item.tags),
            fixture_tool_calls=tuple(ToolCall(**call.model_dump()) for call in item.fixture_tool_calls),
        ))
    return cases


def corpus_hash(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
