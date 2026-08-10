import json

import pytest

from guardbench.adapters import HttpAdapter
from guardbench.models import EvalCase, ExpectedBehavior


class FakeHeaders:
    def get_content_type(self):
        return "application/json"


class FakeResponse:
    headers = FakeHeaders()

    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, _limit):
        return self.payload


class FakeOpener:
    def __init__(self, payload):
        self.payload = payload

    def open(self, _request, timeout):
        assert timeout == 20.0
        return FakeResponse(self.payload)


def case():
    return EvalCase(
        "http-case", "robustness", "high", "synthetic prompt",
        ExpectedBehavior("allow"), "fixture",
    )


def test_http_adapter_requires_explicit_identity():
    adapter = HttpAdapter("http://127.0.0.1/generate", "app-model-config-sha")
    assert adapter.name == "http:app-model-config-sha"
    assert adapter.provenance["target_id"] == "app-model-config-sha"


@pytest.mark.parametrize("target_id", ["", "   "])
def test_http_adapter_rejects_empty_identity(target_id):
    with pytest.raises(ValueError, match="non-empty immutable target_id"):
        HttpAdapter("http://127.0.0.1/generate", target_id)


def test_http_adapter_rejects_target_execution_claims(monkeypatch):
    payload = {
        "response": "safe",
        "tool_calls": [{
            "name": "record_lookup", "arguments": {}, "executed": False,
        }],
    }
    monkeypatch.setattr(
        "guardbench.adapters.urllib.request.build_opener",
        lambda *_args: FakeOpener(payload),
    )
    with pytest.raises(TypeError, match="trusted-only"):
        HttpAdapter("http://127.0.0.1/generate", "immutable-target").generate(case())


def test_http_adapter_parses_proposals_without_trusting_them(monkeypatch):
    payload = {
        "response": "safe",
        "tool_calls": [{"name": "record_lookup", "arguments": {"record_id": "R-104"}}],
        "metadata": {"model": "synthetic-v1"},
    }
    monkeypatch.setattr(
        "guardbench.adapters.urllib.request.build_opener",
        lambda *_args: FakeOpener(payload),
    )
    output = HttpAdapter(
        "http://127.0.0.1/generate", "immutable-target"
    ).generate(case())
    assert output.tool_calls[0].name == "record_lookup"
    assert output.trusted_tool_trace == ()
