import json

from guardbench.audit import append_event, verify_chain


def test_hash_chain_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_event(path, "run", "ci", {"id": "1"})
    append_event(path, "gate", "policy", {"decision": "pass"})
    assert verify_chain(path)[0]
    lines = path.read_text().splitlines()
    event = json.loads(lines[0])
    event["data"]["id"] = "tampered"
    lines[0] = json.dumps(event)
    path.write_text("\n".join(lines) + "\n")
    valid, message = verify_chain(path)
    assert not valid
    assert "mismatch" in message
