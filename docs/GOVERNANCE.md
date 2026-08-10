# Evaluation Governance

## Lifecycle

1. A corpus owner versions cases and expected behavior.
2. Automation runs the target and emits immutable-style evidence.
3. The policy engine evaluates risk-tier thresholds and optional baseline regression.
4. Any critical/high failure blocks release.
5. A passing run becomes `awaiting_approval`, never automatically `approved`.
6. An authorized reviewer who is not the submitter examines evidence and records rationale.
7. Approval adds an artifact SHA-256 and a hash-chained audit event.

## Roles

- **Submitter:** initiates the run; cannot self-approve.
- **Corpus owner:** maintains cases and expected behaviors through code review.
- **Security reviewer / risk owner:** reviews failures, category coverage, and evidence.
- **Release manager:** confirms the approved artifact is the artifact deployed.

A production deployment should enforce these identities through an IdP and repository protections. The demo CLI demonstrates the control but does not authenticate names.

## Risk tiers and exceptions

The included policy is `high` risk. It requires zero high/critical failures. This MVP intentionally does not implement automated waivers: exceptions are easy to misuse and should not quietly convert a blocked run into a pass. A production exception record should include owner, affected cases, reason, compensating control, approver, issue link, creation time, and mandatory expiry. Critical data-leakage or unauthorized-tool-action findings should not be waivable through this system.

## Baselines

Pass `--baseline <approved-report.json>` to detect overall regressions. Production policies should additionally compare each category, severity, language, customer segment, and repeated sample distributions. Baselines must be approved, versioned artifacts—not whichever run happened most recently.

## Framework crosswalk

The design is informed by, but does not claim conformance with:

- NIST AI RMF: Govern, Map, Measure, and Manage activities.
- OWASP Top 10 for LLM Applications: prompt injection, sensitive information disclosure, and excessive agency/insecure tool use.
- MITRE ATLAS: adversarial testing concepts and evidence-oriented testing.

A crosswalk is documentation, not certification. Organizational policy, legal review, production monitoring, incident response, and domain-specific validation remain outside this demo.
