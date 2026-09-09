"""The API process never imports torch, ART, onnxruntime or SHAP (spec 8.4, 9.1).

Runs in a subprocess so the guard sees a fresh interpreter: the ML libraries
are blocked in ``sys.modules`` before ``redsim.api.app`` is imported, the app
is built and ``GET /health`` is served. If any API-side import pulled an ML
library in, the import would raise ``ImportError`` and the check would fail.

Phase B (plan 12 section 1, TESTS_DOCS-17) widens the guard to every library
the LLM, endpoint, report and interop tracks bring in: garak and the OpenAI
client and litellm it installs (the probe runner is a worker-pool job, Pythia
the only transport), reportlab (the PDF projection renders on the worker),
pyarrow and mlcroissant (dataset export and consumption parse only in the
sandbox child). The same file pins the other half of the boundary: the
sandbox child's environment allowlist (``redsim/ml/sandbox.py``) carries no
gateway, dataset, generator or cloud credential.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

_BLOCKED = (
    # Phase A: the ml extra (spec 8.4).
    "torch", "torchvision", "art", "onnx", "onnxruntime", "shap", "sklearn", "xgboost",
    # Phase B: LLM probing (garak plus the clients it installs), PDF, interop (TESTS_DOCS-17).
    "garak", "openai", "litellm", "reportlab", "pyarrow", "mlcroissant",
)

#: Environment prefixes the sandbox child must never carry (spec 9.4; plan 12 section 1).
#: ``KAGGLE`` and ``OPENAI`` have no trailing underscore on purpose: they also match
#: ``KAGGLEHUB_*`` and garak's ``OPENAICOMPATIBLE_API_KEY``.
_FORBIDDEN_CHILD_PREFIXES = ("PYTHIA_", "KAGGLE", "OPENAI", "AWS_")

#: What a worker parent's environment may hold in Phase B. Every value is a
#: low-entropy stand-in; none is a credential of any kind.
_WORKER_PARENT_SECRETS = {
    "PYTHIA_API_KEY": "fake-pythia-key-not-real",
    "PYTHIA_BASE_URL": "https://pythia.example.invalid",
    "PYTHIA_PERSONA": "fake-persona",
    "KAGGLE_API_TOKEN": "fake-kaggle-token",
    "KAGGLE_USERNAME": "fake-kaggle-user",
    "KAGGLE_KEY": "fake-kaggle-key",
    "KAGGLEHUB_CACHE": "/nonexistent/kagglehub",
    "OPENAI_API_KEY": "fake-openai-key-not-real",
    "OPENAI_BASE_URL": "https://openai.example.invalid/v1",
    # garak's ``openai.OpenAICompatible`` generator reads this name (LLM-core track).
    "OPENAICOMPATIBLE_API_KEY": "fake-generator-key-not-real",
    "AWS_ACCESS_KEY_ID": "fake-aws-access-key-id",
    "AWS_SECRET_ACCESS_KEY": "fake-aws-secret-not-real",
    "AWS_SESSION_TOKEN": "fake-aws-session-not-real",
    "AWS_PROFILE": "fake-profile",
    "REDSIM_AUTH_PROFILES_KEY": "fake-fernet-key-not-real",
    "REDSIM_DB_URL": "postgresql://user:pw@db.invalid/redsim",
    "REDSIM_FOUNDRY_TOKEN": "fake-foundry-token",
    "REDSIM_ML_GARAK_PERSONA_KEY": "fake-garak-persona-key",
    "HF_TOKEN": "fake-hf-token",
    "HUGGING_FACE_HUB_TOKEN": "fake-hf-hub-token",
    "HTTPS_PROXY": "http://proxy.example.invalid:3128",
}

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
    assert proc.returncode == 0, f"API import pulled in a blocked library:\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_blocked_list_covers_every_phase_b_library():
    """The names Phase B brings in are all on the list (plan 12 section 1)."""
    for name in ("garak", "openai", "litellm", "reportlab", "pyarrow", "mlcroissant"):
        assert name in _BLOCKED
    for name in ("torch", "torchvision", "art", "onnx", "onnxruntime", "shap", "sklearn", "xgboost"):
        assert name in _BLOCKED


def test_api_app_builds_with_ml_libraries_blocked():
    out = _run_probe()
    assert out["health"] == 200
    assert out["loaded"] == []


def test_scans_route_is_unmounted():
    out = _run_probe()
    assert out["scans"] == 404
    assert "/v1/scans" not in out["paths"]
    assert "/health" in out["paths"] and "/v1/runs" in out["paths"] and "/v1/targets" in out["paths"]


def test_sandbox_child_env_allowlist_excludes_gateway_and_cloud_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
    """The child env is built from an allowlist; no PYTHIA_*/KAGGLE*/OPENAI*/AWS_* name survives it."""
    from redsim.ml import sandbox
    from redsim.scanners.sandbox import _SAFE_ENV_KEYS

    for key, value in _WORKER_PARENT_SECRETS.items():
        monkeypatch.setenv(key, value)

    # The allowlist itself names nothing under a credential-bearing prefix, and the
    # final sweep still covers the gateway, dataset and cloud prefixes by name.
    allowlisted = [k for k in _SAFE_ENV_KEYS if k.startswith(_FORBIDDEN_CHILD_PREFIXES + ("REDSIM_", "HF_"))]
    assert allowlisted == [], allowlisted
    for prefix in ("REDSIM_", "PYTHIA_", "KAGGLE_", "AWS_", "HF_TOKEN", "HUGGING_FACE"):
        assert prefix in sandbox._FORBIDDEN_ENV_PREFIXES

    env = sandbox._ml_child_env(
        sandbox.MlSandboxConfig(), assets=str(tmp_path / "assets"), hash_seed=0, work_dir=tmp_path,
    )

    leaked = sorted(k for k in env if k.startswith(_FORBIDDEN_CHILD_PREFIXES))
    assert leaked == [], f"credential-bearing names reached the sandbox child env: {leaked}"
    for key in _WORKER_PARENT_SECRETS:
        assert key not in env, f"{key} leaked into the sandbox child env"
    # No value smuggled under another name either.
    assert set(env.values()).isdisjoint(_WORKER_PARENT_SECRETS.values())
    # The only REDSIM_* keys are the documented pins, never a setting or a secret.
    assert sorted(k for k in env if k.startswith("REDSIM_")) == sorted(sandbox._ALLOWED_REDSIM_KEYS)
    assert env["REDSIM_DISABLE_LLM"] == "1" and env["REDSIM_PLUGINS"] == "0"
    assert not any(k.lower().endswith("_proxy") for k in env), sorted(env)
