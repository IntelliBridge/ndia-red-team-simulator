"""Review #22 finding F2: the ML catalog routes work in the API image and never fake an empty catalog.

``deploy/Dockerfile.api`` installs ``.[api,worker]`` only. The catalog registries
(``redsim.ml.attacks``, ``redsim.ml.targets``) import numpy
at module level, so numpy must ship with the ``api`` extra while torch, ART,
onnx(runtime), SHAP and scikit-learn stay in ``ml`` and are imported lazily
inside the adapters' ``run``/``load`` methods only.

Two halves are pinned here:

* the registries import, and the catalog routes serve full catalogs, in a fresh
  interpreter with every ML framework blocked in ``sys.modules`` (extends
  ``tests/test_api_process_has_no_ml.py``, which only served ``/health``);
* when a registry genuinely cannot be imported the routes answer ``503`` with
  ``ml_catalog_unavailable`` and the ImportError text, never ``200`` with ``[]``.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

_ROOT = Path(__file__).resolve().parents[1]
_BLOCKED = ("torch", "torchvision", "art", "onnx", "onnxruntime", "shap", "sklearn", "xgboost")
_AUTH = {"Authorization": "Bearer dev:reviewer@example.com"}

_ROUTES_PROBE = r"""
import json, sys
blocked = %r
for name in blocked:
    sys.modules[name] = None
from fastapi.testclient import TestClient
from redsim.api.app import create_app
from redsim.api.settings import APISettings
app = create_app(APISettings(env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"]))
client = TestClient(app)
headers = %r
out = {}
for path in ("/v1/attacks", "/v1/ml/capabilities"):
    response = client.get(path, headers=headers)
    out[path] = {"status": response.status_code, "body": response.json()}
out["loaded"] = sorted(m for m in sys.modules if m.split(".")[0] in blocked and sys.modules[m] is not None)
out["registries"] = sorted(m for m in ("redsim.ml.attacks", "redsim.ml.targets")
                           if sys.modules.get(m) is not None)
print(json.dumps(out))
"""

_REGISTRIES_PROBE = r"""
import json, sys
blocked = %r
for name in blocked:
    sys.modules[name] = None
from redsim.ml.attacks import list_attacks
from redsim.ml.targets import list_targets
from redsim.ml.targets.artifact import architecture_ids
out = {
    "attacks": sorted(a.id for a in list_attacks()),
    "targets": sorted(t.id for t in list_targets()),
    "architectures": architecture_ids(),
    "loaded": sorted(m for m in sys.modules if m.split(".")[0] in blocked and sys.modules[m] is not None),
}
print(json.dumps(out))
"""


def _run_probe(source: str, *args: Any) -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, "-c", source % args],
        capture_output=True, text=True, timeout=120, check=False, cwd=_ROOT,
    )
    assert proc.returncode == 0, f"probe failed (an API-side import pulled in an ML library?):\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


# --- half (a): the api extra carries what the catalog needs, and nothing more --------------


def _extras() -> dict[str, list[str]]:
    with (_ROOT / "pyproject.toml").open("rb") as fh:
        return dict(tomllib.load(fh)["project"]["optional-dependencies"])


def _dist_names(requirements: list[str]) -> set[str]:
    out = set()
    for req in requirements:
        name = req.split("@", 1)[0]
        for sep in "[><=!~;":
            name = name.split(sep, 1)[0]
        out.add(name.strip().lower())
    return out


def test_api_extra_ships_numpy_but_no_ml_framework() -> None:
    extras = _extras()
    assert "numpy" in _dist_names(extras["api"]), "numpy must ship with the api extra (catalog registries import it)"
    frameworks = {"torch", "torchvision", "adversarial-robustness-toolbox", "onnx", "onnxruntime", "shap",
                  "scikit-learn", "xgboost", "onnx2torch"}
    for extra in ("api", "worker"):
        leaked = frameworks & _dist_names(extras[extra])
        assert not leaked, f"{extra} extra must not pull ML frameworks into the API image: {sorted(leaked)}"
    assert frameworks - {"xgboost"} <= _dist_names(extras["ml"])


def test_catalog_registries_import_with_ml_frameworks_blocked() -> None:
    out = _run_probe(_REGISTRIES_PROBE, _BLOCKED)
    assert out["loaded"] == [], f"catalog registries imported an ML framework at module import: {out['loaded']}"
    assert {"fgsm", "pgd", "hopskipjump", "noise_control"} <= set(out["attacks"])
    assert {"vehicles_cnn", "url_trees", "cifar10_smallcnn", "endpoint_stub"} <= set(out["targets"])
    assert "smallcnn" in out["architectures"]


def test_catalog_routes_serve_full_catalogs_with_ml_frameworks_blocked() -> None:
    out = _run_probe(_ROUTES_PROBE, _BLOCKED, _AUTH)
    assert out["loaded"] == [], f"serving the catalog imported an ML framework: {out['loaded']}"
    assert out["registries"] == ["redsim.ml.attacks", "redsim.ml.targets"], (
        "the catalogs must come from the real registries, not a fallback")

    attacks = out["/v1/attacks"]
    assert attacks["status"] == 200, attacks
    ids = {row["id"] for row in attacks["body"]["attacks"]}
    assert {"fgsm", "pgd", "hopskipjump", "noise_control"} <= ids
    assert attacks["body"]["count"] == len(attacks["body"]["attacks"]) >= 4

    capabilities = out["/v1/ml/capabilities"]
    assert capabilities["status"] == 200, capabilities
    body = capabilities["body"]
    assert "smallcnn" in body["architectures"]
    assert "defenses" not in body, "the defense catalog left with the verify paradigm (2026-09-09)"
    bundled = {row["id"] for row in body["bundled_models"]}
    assert {"vehicles_cnn", "url_trees"} <= bundled
    assert "cifar10_smallcnn" not in bundled, "fixture-only targets are never advertised as demo models"
    assert "endpoint_stub" not in bundled


# --- half (b): an unimportable registry is a 503, never an empty 200 ------------------------


@pytest.fixture
def client() -> Iterator[Any]:
    from fastapi.testclient import TestClient

    from redsim.api.app import create_app
    from redsim.api.settings import APISettings

    app = create_app(APISettings(env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"]))
    with TestClient(app) as test_client:
        yield test_client


def _block_package(monkeypatch: pytest.MonkeyPatch, package: str) -> None:
    """Make ``import <package>`` (and any already-imported submodule of it) raise ImportError.

    A cached submodule is returned by the import machinery without consulting its
    parent, so blocking the package alone would not trip an already-imported
    ``redsim.ml.targets.artifact``; every loaded name under the prefix is blocked too.
    """
    monkeypatch.setitem(sys.modules, package, None)
    for name in list(sys.modules):
        if name.startswith(package + "."):
            monkeypatch.setitem(sys.modules, name, None)


@pytest.mark.parametrize(("path", "package", "payload_key"), [
    ("/v1/attacks", "redsim.ml.attacks", "attacks"),
    ("/v1/ml/capabilities", "redsim.ml.targets", "bundled_models"),
])
def test_catalog_route_refuses_when_registry_is_unimportable(
    client: Any, monkeypatch: pytest.MonkeyPatch, path: str, package: str, payload_key: str,
) -> None:
    _block_package(monkeypatch, package)
    response = client.get(path, headers=_AUTH)
    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "ml_catalog_unavailable"
    assert package in detail["reason"], detail
    assert detail["message"]
    assert payload_key not in response.json(), "an unavailable catalog must not look like an empty one"


def test_catalog_routes_recover_once_registry_imports_again(client: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as scoped:
        _block_package(scoped, "redsim.ml.attacks")
        assert client.get("/v1/attacks", headers=_AUTH).status_code == 503
    response = client.get("/v1/attacks", headers=_AUTH)
    assert response.status_code == 200
    assert response.json()["count"] >= 4
