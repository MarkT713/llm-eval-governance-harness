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
- Target text, metadata, and proposed tool calls are untrusted evidence. The dashboard escapes them and GuardBench never executes a target-proposed tool.
- Deterministic grading and policy rules form the automated release boundary.
- A reviewer, distinct from the submitter, owns the final approval decision.
- Generated artifacts and audit logs may contain target output and therefore require access and retention controls.

## Reproducibility

Each report records corpus and policy SHA-256 values, target and adapter names, policy version, UTC time, Git commit/dirty state, Python/platform details, per-trial responses, structured mock tool calls, checks, slices, stability, and latency. A sidecar run bundle stores hash-indexed requests, responses, metadata, and grades. `guardbench replay` verifies every artifact plus the corpus hash before re-grading without calling a provider. Fixture mode is deterministic and suitable for CI. Real model calls can vary; production usage should also pin model/provider versions, generation parameters, system-prompt hashes, and application commit identifiers in a target-specific adapter.

## Deliberate limits

The HTTP adapter is sequential and has no retry to avoid silently changing sample counts. Structured tools are mock evidence only. Model-as-judge is not trusted for release gating because it adds nondeterminism, correlated model errors, and possible injection through evaluated output.
