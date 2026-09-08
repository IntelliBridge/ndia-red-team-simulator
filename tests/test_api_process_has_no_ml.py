"""The API process never imports torch, ART, onnxruntime or SHAP (spec 8.4).

Runs in a subprocess so the guard sees a fresh interpreter: the ML libraries
are blocked in ``sys.modules`` before ``redsim.api.app`` is imported, the app
is built and ``GET /health`` is served. If any API-side import pulled an ML
library in, the import would raise ``ImportError`` and the check would fail.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

pytest.importorskip("fastapi")

_BLOCKED = ("torch", "torchvision", "art", "onnx", "onnxruntime", "shap", "sklearn", "xgboost")

_PROBE = r"""
import json, sys
blocked = %r
for name in blocked:
    sys.modules[name] = None
from fastapi.testclient import TestClient
from redsim.api.app import create_app
from redsim.api.settings import APISettings
app = create_app(APISettings(env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"]))
client = TestClient(app)
health = client.get("/health").status_code
scans = client.post("/v1/scans", json={}).status_code
loaded = sorted(m for m in sys.modules if m.split(".")[0] in blocked and sys.modules[m] is not None)
print(json.dumps({"health": health, "scans": scans, "loaded": loaded,
                  "paths": sorted(app.openapi()["paths"])}))
"""


def _run_probe() -> dict:
    proc = subprocess.run(
        [sys.executable, "-c", _PROBE % (_BLOCKED,)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode == 0, f"API import pulled in an ML library:\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_api_app_builds_with_ml_libraries_blocked():
    out = _run_probe()
    assert out["health"] == 200
    assert out["loaded"] == []


def test_scans_route_is_unmounted():
    out = _run_probe()
    assert out["scans"] == 404
    assert "/v1/scans" not in out["paths"]
    assert "/health" in out["paths"] and "/v1/runs" in out["paths"] and "/v1/targets" in out["paths"]
