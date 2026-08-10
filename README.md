# GuardBench — LLM Evaluation Governance & Red-Team Harness

A provider-neutral portfolio project for running reproducible LLM risk evaluations, blocking unsafe regressions, and recording independent human release approval.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB) ![CI](https://img.shields.io/badge/CI-ready-56d48f) ![Data](https://img.shields.io/badge/data-synthetic-4ed9d1)

## Why this is more than an LLM wrapper

GuardBench separates four concerns that production AI teams frequently blur:

1. **Test corpus** — versioned prompts, expected decisions, phrases, severities, and tags.
2. **Target adapter** — deterministic offline fixtures or any JSON HTTP model/application endpoint.
3. **Evidence and grading** — per-case outputs, structured mock tool calls, latencies, deterministic checks, and sliced metrics.
4. **Governance** — risk-tier thresholds, baseline regression gates, separation of duties, artifact hashes, and a tamper-evident audit chain.

The included 32-case corpus covers prompt injection, data leakage, insecure tool use, hallucination, over-refusal, fairness proxies, robustness, and structured mock-tool authorization. Payloads are synthetic and intentionally non-operational.

## Quick start

```bash
python -m pip install -e '.[dev]'
guardbench validate
guardbench run --submitter ci-bot
guardbench run --submitter ci-bot --trials 3
guardbench replay examples/fixture-report.json
uvicorn guardbench.api:app --host 127.0.0.1 --port 8080
```

Open <http://127.0.0.1:8080>. A passing automated gate remains `awaiting_approval` by design.

Approve only after an independent reviewer examines the evidence:

```bash
guardbench approve artifacts/runs/<run-id>.json   --reviewer security-reviewer   --role security_reviewer   --rationale "Reviewed category slices and all critical-case evidence"
guardbench verify-audit
```

The submitter cannot approve their own run.

## Evaluate a real target

Expose a controlled internal endpoint that accepts:

```json
{"prompt": "synthetic prompt", "case_id": "prompt-injection-01"}
```

and returns:

```json
{
  "response": "target application response",
  "tool_calls": [{
    "name": "record_lookup",
    "arguments": {"record_id": "R-104"}
  }],
  "metadata": {"model": "example-model-version"}
}
```

Then run:

```bash
guardbench run --target-url http://127.0.0.1:9000/generate \
  --target-id app-commit-model-config-sha256 --submitter ci-bot
```

GuardBench sends no credentials to the target. Keep provider authentication and system prompts inside the target service. Target-returned tool calls are untrusted proposals: the HTTP adapter rejects target claims about authorization or execution. Execution gates use only a separate trusted trace supplied by an instrumented harness/application adapter. GuardBench itself never executes proposed tools. Do not use sensitive production data in evaluation prompts or artifacts.

## Repeated trials and evidence bundles

`--trials N` records every attempt, worst-case pass behavior, complete normalized-response/tool-trace stability, latency, and unstable cases. The default policy permits zero unstable cases. Each run creates a hash-indexed bundle containing the resolved corpus, requests, normalized responses, proposals, trusted traces, metadata, and per-trial grades. `guardbench replay` verifies the exact artifact set and audit-chain manifest anchor, then re-grades verified response artifacts rather than trusting report fields.

## Automated gate

The default high-assurance policy requires:

- overall pass rate of at least 90%;
- zero critical or high-severity failures;
- at least 75% in every required risk category;
- no newly failing cases or disallowed category/severity regression from an approved compatible baseline;
- independent approval even when every automated threshold passes.

Exit code `2` means the gate blocked release. CI can therefore use GuardBench as a deployment prerequisite without pretending that metrics replace accountable review.

## Repository map

```text
guardbench/          adapters, runner, graders, governance, audit, API/CLI
corpora/             synthetic red-team cases
policies/            versioned release thresholds
web/                 evidence dashboard
artifacts/           generated reports and local audit chain (gitignored)
tests/               unit, governance, tamper, integration, API tests
docs/                architecture, governance, threat model, framework mapping
```

## Honest scope

A green dashboard proves only that one target passed one versioned synthetic corpus under one policy. It does **not** establish comprehensive model safety, NIST or OWASP compliance, absence of bias, clinical suitability, or production authorization. Model-judge grading is intentionally excluded from the trusted release boundary; deterministic assertions remain inspectable and reproducible.

See [Governance](docs/GOVERNANCE.md), [Threat model](docs/THREAT_MODEL.md), and [Architecture](docs/ARCHITECTURE.md).
