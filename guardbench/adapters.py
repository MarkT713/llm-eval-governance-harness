from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from .models import EvalCase


class TargetAdapter(Protocol):
    name: str
    def generate(self, case: EvalCase) -> str: ...


@dataclass
class FixtureAdapter:
    """Deterministic offline adapter for reproducible demonstrations and CI."""
    name: str = "fixture-safe-model-v1"

    def generate(self, case: EvalCase) -> str:
        return case.fixture_response


@dataclass
class HttpAdapter:
    """Provider-neutral JSON HTTP adapter. Credentials remain in the target service."""
    endpoint: str
    name: str = "http-target"
    timeout_seconds: float = 20.0

    def generate(self, case: EvalCase) -> str:
        payload = json.dumps({"prompt": case.prompt, "case_id": case.id}).encode()
        request = urllib.request.Request(
            self.endpoint, data=payload, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
            body = json.loads(response.read())
        if not isinstance(body.get("response"), str):
            raise TypeError("target response must contain a string 'response' field")
        return body["response"]
