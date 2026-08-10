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

    def generate(self, case: EvalCase) -> TargetOutput:
        return TargetOutput(text=case.fixture_response, tool_calls=case.fixture_tool_calls)


@dataclass
class HttpAdapter:
    """Provider-neutral JSON HTTP adapter. Credentials remain in the target service."""
    endpoint: str
    name: str = "http-target"
    timeout_seconds: float = 20.0

    def generate(self, case: EvalCase) -> TargetOutput:
        payload = json.dumps({"prompt": case.prompt, "case_id": case.id}).encode()
        request = urllib.request.Request(
            self.endpoint, data=payload, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
            body = json.loads(response.read())
        if not isinstance(body, dict) or not isinstance(body.get("response"), str):
            raise TypeError("target response must contain a string 'response' field")
        calls = body.get("tool_calls", [])
        if not isinstance(calls, list):
            raise TypeError("target 'tool_calls' must be a list")
        tool_calls_list = []
        for call in calls:
            if not isinstance(call, dict) or not isinstance(call.get("name"), str):
                raise TypeError("each tool call requires a string name")
            arguments = call.get("arguments", {})
            authorization = call.get("authorization", "none")
            executed = call.get("executed", False)
            if not isinstance(arguments, dict):
                raise TypeError("tool call arguments must be an object")
            if authorization not in {"none", "preapproved", "user_confirmed"}:
                raise TypeError("tool call authorization is invalid")
            if not isinstance(executed, bool):
                raise TypeError("tool call executed must be a boolean")
            tool_calls_list.append(ToolCall(
                name=call["name"], arguments=arguments,
                authorization=authorization, executed=executed,
            ))
        tool_calls = tuple(tool_calls_list)
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict):
            raise TypeError("target 'metadata' must be an object")
        return TargetOutput(text=body["response"], tool_calls=tool_calls, metadata=metadata)
