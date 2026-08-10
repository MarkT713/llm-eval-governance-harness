from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ExpectedBehaviorSchema(StrictModel):
    decision: Literal["allow", "refuse", "escalate"]
    required_phrases: list[str] = Field(default_factory=list)
    forbidden_phrases: list[str] = Field(default_factory=list)
    must_not_contain_canary: bool = False
    allowed_tools: list[str] = Field(default_factory=list)
    forbidden_tools: list[str] = Field(default_factory=list)
    required_tools: list[str] = Field(default_factory=list)
    required_authorization: dict[str, Literal["none", "preapproved", "user_confirmed"]] = Field(
        default_factory=dict
    )
    maximum_tool_calls: int | None = Field(default=None, ge=0)
    must_not_execute_tools: bool = True

    @model_validator(mode="after")
    def validate_tool_policy(self):
        overlap = set(self.allowed_tools) & set(self.forbidden_tools)
        if overlap:
            raise ValueError(f"tools cannot be both allowed and forbidden: {sorted(overlap)}")
        if self.allowed_tools and not set(self.required_tools).issubset(self.allowed_tools):
            raise ValueError("required tools must be included in the allowlist")
        if not set(self.required_authorization).issubset(self.required_tools):
            raise ValueError("authorization requirements must refer to required tools")
        if self.maximum_tool_calls is not None and len(self.required_tools) > self.maximum_tool_calls:
            raise ValueError("maximum tool calls cannot be less than required tools")
        return self


class ToolCallSchema(StrictModel):
    name: str = Field(min_length=1, pattern=r"^[a-zA-Z][a-zA-Z0-9_.-]+$")
    arguments: dict = Field(default_factory=dict)


class ToolTraceSchema(ToolCallSchema):
    authorization: Literal["none", "preapproved", "user_confirmed"] = "none"
    executed: bool = False
    observer: str = Field(default="harness", min_length=1, max_length=120)


class EvalCaseSchema(StrictModel):
    id: str = Field(min_length=3, pattern=r"^[a-z0-9][a-z0-9-]+$")
    category: str = Field(min_length=2, pattern=r"^[a-z][a-z0-9_]+$")
    severity: Literal["low", "medium", "high", "critical"]
    prompt: str = Field(min_length=1, max_length=10_000)
    expected: ExpectedBehaviorSchema
    fixture_response: str = Field(max_length=20_000)
    tags: list[str] = Field(default_factory=list)
    fixture_tool_calls: list[ToolCallSchema] = Field(default_factory=list)
    fixture_tool_trace: list[ToolTraceSchema] = Field(default_factory=list)


class CorpusSchema(StrictModel):
    name: str
    version: str
    description: str
    canary: str = Field(min_length=8, max_length=256)
    cases: list[EvalCaseSchema] = Field(min_length=1)


class ThresholdSchema(StrictModel):
    minimum_overall_pass_rate: float = Field(ge=0, le=1)
    zero_failure_severities: list[Literal["low", "medium", "high", "critical"]]
    maximum_baseline_regression: float = Field(ge=0, le=1)
    category_minimums: dict[str, float]
    minimum_cases_by_category: dict[str, int] = Field(default_factory=dict)
    minimum_total_cases: int = Field(default=1, ge=1)
    maximum_unstable_cases: int = Field(default=0, ge=0)


class ApprovalSchema(StrictModel):
    required: bool
    separation_of_duties: bool
    authorized_roles: list[str]


class PolicySchema(StrictModel):
    name: str
    version: str
    risk_tier: Literal["experimental", "assistive", "high", "critical"]
    evidence_scope: Literal["synthetic_demo_regression_only"]
    thresholds: ThresholdSchema
    approval: ApprovalSchema
