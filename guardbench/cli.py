from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .adapters import FixtureAdapter, HttpAdapter
from .audit import verify_chain
from .corpus import load_cases
from .governance import apply_gate, approve
from .replay import replay_report
from .runner import execute_suite
from .schema_models import PolicySchema

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "corpora" / "safe_red_team.json"
DEFAULT_POLICY = ROOT / "policies" / "default.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "runs"
DEFAULT_AUDIT = ROOT / "artifacts" / "audit.jsonl"


def build_parser():
    parser = argparse.ArgumentParser(prog="guardbench", description="LLM evaluation governance harness")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="execute an evaluation and apply release policy")
    run.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    run.add_argument("--policy", default=str(DEFAULT_POLICY))
    run.add_argument("--target-url")
    run.add_argument("--submitter", default="automation")
    run.add_argument("--baseline")
    replay = sub.add_parser("replay", help="re-grade a captured run without provider calls")
    replay.add_argument("report")
    replay.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    validate = sub.add_parser("validate", help="strictly validate a corpus and policy")
    validate.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    validate.add_argument("--policy", default=str(DEFAULT_POLICY))
    approve_cmd = sub.add_parser("approve", help="record independent human approval")
    approve_cmd.add_argument("report")
    approve_cmd.add_argument("--reviewer", required=True)
    approve_cmd.add_argument("--role", required=True)
    approve_cmd.add_argument("--rationale", required=True)
    sub.add_parser("verify-audit", help="verify the append-only audit hash chain")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "run":
        policy_bytes = Path(args.policy).read_bytes()
        policy = PolicySchema.model_validate_json(policy_bytes).model_dump()
        adapter = HttpAdapter(args.target_url) if args.target_url else FixtureAdapter()
        _, path = execute_suite(
            args.corpus, adapter, policy["version"], DEFAULT_OUTPUT, DEFAULT_AUDIT,
            args.submitter, hashlib.sha256(policy_bytes).hexdigest()
        )
        report = apply_gate(path, args.policy, DEFAULT_AUDIT, args.baseline)
        print(json.dumps({"report": str(path), "status": report["status"], "gate": report["gate"]}, indent=2))
        return 2 if report["status"] == "blocked" else 0
    if args.command == "replay":
        result = replay_report(args.report, args.corpus, DEFAULT_AUDIT)
        print(json.dumps(result, indent=2))
        return 0 if result["stable"] else 3
    if args.command == "validate":
        cases = load_cases(args.corpus)
        policy = PolicySchema.model_validate_json(Path(args.policy).read_bytes())
        print(json.dumps({"valid": True, "cases": len(cases), "policy": policy.version}, indent=2))
        return 0
    if args.command == "approve":
        report = approve(args.report, args.reviewer, args.role, args.rationale, DEFAULT_AUDIT)
        print(json.dumps({"run_id": report["run_id"], "status": report["status"], "artifact_sha256": report["artifact_sha256"]}, indent=2))
        return 0
    valid, message = verify_chain(DEFAULT_AUDIT)
    print(message)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
