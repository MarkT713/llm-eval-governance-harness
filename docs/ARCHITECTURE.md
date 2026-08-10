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
- Target output is untrusted evidence. The dashboard escapes it and the grader performs no evaluation or execution.
- Deterministic grading and policy rules form the automated release boundary.
- A reviewer, distinct from the submitter, owns the final approval decision.
- Generated artifacts and audit logs may contain target output and therefore require access and retention controls.

## Reproducibility

Each report records corpus and policy SHA-256 values, target and adapter names, policy version, UTC time, Git commit/dirty state, Python/platform details, per-case response, checks, slices, and latency. `guardbench replay` verifies the corpus hash and re-grades captured responses without calling a provider. Fixture mode is deterministic and suitable for CI. Real model calls can vary; production usage should also pin model/provider versions, generation parameters, system-prompt hashes, and application commit identifiers in a target-specific adapter.

## Deliberate limits

The v0.1 HTTP adapter is sequential and has no retry to avoid silently changing sample counts. It does not execute target-proposed tools. Model-as-judge is not trusted for release gating because it adds nondeterminism, correlated model errors, and possible injection through evaluated output.
