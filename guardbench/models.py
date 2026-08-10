from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Decision = Literal["allow", "refuse", "escalate"]
Severity = Literal["low", "medium", "high", "critical"]
Authorization = Literal["none", "preapproved", "user_confirmed"]


@dataclass(frozen=True)
class ToolCall:
    """Untrusted tool proposal returned by a target."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolTrace:
    """Harness-observed authorization/execution evidence."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    authorization: Authorization = "none"
    executed: bool = False
    observer: str = "harness"


@dataclass(frozen=True)
class TargetOutput:
    text: str
    tool_calls: tuple[ToolCall, ...] = ()
    trusted_tool_trace: tuple[ToolTrace, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExpectedBehavior:
    decision: Decision
    required_phrases: tuple[str, ...] = ()
    forbidden_phrases: tuple[str, ...] = ()
    must_not_contain_canary: bool = False
    allowed_tools: tuple[str, ...] = ()
    forbidden_tools: tuple[str, ...] = ()
    required_tools: tuple[str, ...] = ()
    required_authorization: dict[str, Authorization] = field(default_factory=dict)
    maximum_tool_calls: int | None = None
    must_not_execute_tools: bool = True


@dataclass(frozen=True)
class EvalCase:
    id: str
    category: str
    severity: Severity
    prompt: str
    expected: ExpectedBehavior
    fixture_response: str
    tags: tuple[str, ...] = ()
    fixture_tool_calls: tuple[ToolCall, ...] = ()
    fixture_tool_trace: tuple[ToolTrace, ...] = ()
    canary: str = "GB_CANARY_7F3A"


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
    tool_calls: tuple[ToolCall, ...] = ()
    trusted_tool_trace: tuple[ToolTrace, ...] = ()
    trial_index: int = 1
    output_metadata: dict[str, Any] = field(default_factory=dict)


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
    manifest: dict[str, Any] = field(default_factory=dict)
    gate: dict[str, Any] = field(default_factory=dict)
    status: str = "evaluated"
    submitter: str = "automation"
    approvals: list[dict[str, str]] = field(default_factory=list)
    exceptions: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
