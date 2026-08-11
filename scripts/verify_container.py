from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8780"

for _ in range(50):
    try:
        health = json.load(urllib.request.urlopen(f"{BASE_URL}/health", timeout=2))
        break
    except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError):
        time.sleep(0.2)
else:
    raise SystemExit("GuardBench container did not become ready")

assert health == {"status": "ok", "mode": "synthetic-demo"}, health
dashboard = urllib.request.urlopen(f"{BASE_URL}/", timeout=2).read().decode()
assert "GuardBench" in dashboard and "Human approval always required" in dashboard
latest = json.load(urllib.request.urlopen(f"{BASE_URL}/api/runs/latest", timeout=2))
assert latest["metrics"]["total"] == 32, latest["metrics"]
assert latest["manifest"]["package"]["version"] == "1.0.0", latest["manifest"]["package"]
assert latest["gate"]["evidence"]["scope"] == "synthetic_demo_regression_only"
print("GuardBench read-only container and synthetic evidence verification passed")
