# Architecture

```text
Versioned corpus ──┐
                   ├─> target adapter ─> captured response ─> deterministic grader
Target application ┘                                          │
                                                               v
                             JSON evidence report ─> policy gate ─> human approval
                                      │                 │               │
                                      └──────── hash-chained audit trail ┘
```

## Trust boundaries

- Corpus prompts are untrusted test input and never become code or shell arguments.
- The HTTP target is a separately controlled service; GuardBench only posts JSON and receives a string.
- Target text, metadata, and proposed tool calls are untrusted evidence. The generic HTTP adapter strictly rejects authorization/execution claims. Only an instrumented adapter can supply the separate trusted trace used for execution gates. GuardBench never executes a target-proposed tool.
- Deterministic grading and policy rules form the automated release boundary.
- A reviewer, distinct from the submitter, owns the final approval decision.
- Generated artifacts and audit logs may contain target output and therefore require access and retention controls.

## Reproducibility

Each report records corpus and policy SHA-256 values, immutable target identity/provenance, adapter and harness versions, trial count, UTC time, Git state, per-trial responses, tool evidence, checks, slices, stability, and latency. A sidecar run bundle stores an exact hash-indexed artifact set. `guardbench replay` verifies the bundle manifest, every artifact, and the manifest hash recorded in the audit chain; it reconstructs outputs from verified response files and compares regenerated grades against both verified grades and the report. The local hash chain establishes self-consistency, not third-party authenticity; production deployments should add signed remote attestations and trusted timestamps.

## Deliberate limits

The HTTP adapter is sequential and has no retry to avoid silently changing sample counts. Generic target tool calls remain proposals; execution evidence requires a separately instrumented trusted trace. Model-as-judge is not trusted for release gating because it adds nondeterminism, correlated model errors, and possible injection through evaluated output.
