# Threat Model

## Assets

Evaluation corpora, target configuration, model responses, risk policy, approval identity, baselines, reports, and audit history.

## Principal threats and controls

| Threat | Demonstrated control | Production gap |
|---|---|---|
| Prompt content executes locally | Prompts are JSON data only; no shell/tool execution | Egress isolation and sandboxed target runners |
| Proposed tool call causes a real action | Target calls are untrusted proposals; only harness-observed traces can establish execution | Isolated mocks, instrumented boundaries, and network-level egress denial |
| Target response injects dashboard markup | DOM output is escaped; API returns JSON | Strict CSP and separate static assets |
| Model leaks secrets into artifacts | Synthetic canaries and leakage graders; warning to avoid real data | DLP, encryption, access control, retention/deletion |
| Unsafe regression ships | Severity/category gates and nonzero exit on block | Protected deployment environments and signed attestations |
| Submitter self-approves | Explicit separation-of-duties check | Authenticated identities, RBAC, MFA |
| Report or audit tampering | Artifact SHA-256 and chained event hashes | Append-only remote store, signatures, trusted timestamps |
| Sidecar evidence is changed before replay | Per-file SHA-256 index and manifest hash verification | Signed manifests and remote immutable storage |
| Stale exception becomes permanent | No automated waiver mechanism in MVP | Expiring exception workflow and reminders |
| Judge model is manipulated | No judge model in trusted release path | Sandboxed multi-grader design if later introduced |
| Corpus overfitting | Versioned multi-category suite and honest scope statement | Hidden holdout sets, rotation, external red teams |
| Endpoint causes cost/availability issues | Timeout, sequential calls, explicit invocation | Budget caps, rate limits, cancellation, retries with provenance |

## Non-goals

GuardBench does not prove that a model is safe, unbiased, compliant, or secure. It does not attack third-party systems, execute generated code, scan production data, or authorize autonomous deployment.
