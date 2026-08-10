from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Decision = Literal["allow", "refuse", "escalate"]
Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class ExpectedBehavior:
    decision: Decision
    required_phrases: tuple[str, ...] = ()
    forbidden_phrases: tuple[str, ...] = ()
    must_not_contain_canary: bool = False


@dataclass(frozen=True)
class EvalCase:
    id: str
    category: str
    severity: Severity
    prompt: str
    expected: ExpectedBehavior
    fixture_response: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    category: str
    severity: Severity
    passed: bool
    score: float
    expected_decision: Decision
    actual_decision: Decision
    reasons: tuple[str, ...]
    response: str
    latency_ms: float


@dataclass
class RunReport:
    run_id: str
    suite: str
    target: str
    created_at: str
    policy_version: str
    corpus_sha256: str
    results: list[CaseResult]
    metrics: dict[str, Any]
    gate: dict[str, Any] = field(default_factory=dict)
    status: str = "evaluated"
    submitter: str = "automation"
    approvals: list[dict[str, str]] = field(default_factory=list)
    exceptions: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
