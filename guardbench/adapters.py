from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from .models import EvalCase, TargetOutput, ToolCall


class TargetAdapter(Protocol):
    name: str

    def generate(self, case: EvalCase) -> TargetOutput | str: ...


def normalize_output(output: TargetOutput | str) -> TargetOutput:
    """Preserve compatibility with v0.1 adapters that returned plain text."""
    return output if isinstance(output, TargetOutput) else TargetOutput(text=output)


@dataclass
class FixtureAdapter:
    """Deterministic offline adapter for reproducible demonstrations and CI."""

    name: str = "fixture-safe-model-v1"

    @property
    def provenance(self) -> dict[str, str]:
        return {"fixture_adapter": self.name}

    def generate(self, case: EvalCase) -> TargetOutput:
        return TargetOutput(
            text=case.fixture_response,
            tool_calls=case.fixture_tool_calls,
            trusted_tool_trace=case.fixture_tool_trace,
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class HttpAdapter:
    """Provider-neutral HTTP adapter; target output is always untrusted."""

    endpoint: str
    target_id: str
    timeout_seconds: float = 20.0
    maximum_response_bytes: int = 1_000_000

    def __post_init__(self) -> None:
        if not self.target_id.strip():
            raise ValueError("HTTP adapter requires a non-empty immutable target_id")

    @property
    def name(self) -> str:
        return f"http:{self.target_id}"

    @property
    def provenance(self) -> dict[str, str]:
        return {"target_id": self.target_id}

    def generate(self, case: EvalCase) -> TargetOutput:
        payload = json.dumps({"prompt": case.prompt, "case_id": case.id}).encode()
        request = urllib.request.Request(
            self.endpoint, data=payload, headers={"Content-Type": "application/json"}
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        with opener.open(request, timeout=self.timeout_seconds) as response:
            content_type = response.headers.get_content_type()
            raw = response.read(self.maximum_response_bytes + 1)
        if content_type != "application/json":
            raise TypeError("target response must use application/json")
        if len(raw) > self.maximum_response_bytes:
            raise ValueError("target response exceeded maximum size")
        body = json.loads(raw)
        if not isinstance(body, dict) or set(body) - {"response", "tool_calls", "metadata"}:
            raise TypeError("target response contains unknown fields")
        if not isinstance(body.get("response"), str):
            raise TypeError("target response must contain a string 'response' field")
        calls = body.get("tool_calls", [])
        if not isinstance(calls, list):
            raise TypeError("target 'tool_calls' must be a list")
        tool_calls = []
        for call in calls:
            if not isinstance(call, dict) or set(call) - {"name", "arguments"}:
                raise TypeError("target tool call contains unknown or trusted-only fields")
            if not isinstance(call.get("name"), str):
                raise TypeError("each tool call requires a string name")
            arguments = call.get("arguments", {})
            if not isinstance(arguments, dict):
                raise TypeError("tool call arguments must be an object")
            tool_calls.append(ToolCall(name=call["name"], arguments=arguments))
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict):
            raise TypeError("target 'metadata' must be an object")
        return TargetOutput(text=body["response"], tool_calls=tuple(tool_calls), metadata=metadata)
