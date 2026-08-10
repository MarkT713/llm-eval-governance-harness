from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def append_event(path: str | Path, event_type: str, actor: str, data: dict[str, Any]) -> dict:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    previous = GENESIS
    if target.exists() and target.stat().st_size:
        previous = json.loads(target.read_text(encoding="utf-8").splitlines()[-1])["hash"]
    event = {
        "timestamp": datetime.now(UTC).isoformat(), "event_type": event_type,
        "actor": actor, "data": data, "previous_hash": previous,
    }
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
    event["hash"] = hashlib.sha256(canonical.encode()).hexdigest()
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    return event


def verify_chain(path: str | Path) -> tuple[bool, str]:
    previous = GENESIS
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        event = json.loads(line)
        claimed = event.pop("hash")
        if event["previous_hash"] != previous:
            return False, f"line {number}: previous hash mismatch"
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
        actual = hashlib.sha256(canonical.encode()).hexdigest()
        if claimed != actual:
            return False, f"line {number}: event hash mismatch"
        previous = claimed
    return True, "chain valid"
