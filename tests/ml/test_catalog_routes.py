"""G-CAP and the catalog reads: no Pythia secret in the roster, 503 instead of an empty catalog.

The capabilities route is exercised with a fully configured Pythia environment
(fake values) and the response text is searched for them; the catalog routes
are exercised with a registry made unimportable, which must be a ``503
ml_catalog_unavailable``, never a ``200`` with empty lists. ``/v1/datasets``
reports the state of the asset manifest instead of hiding it behind ``[]``.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("numpy")

from fastapi.testclient import TestClient

from redsim.api.auth import CurrentUser, get_current_user
from redsim.db.models import Organization, Project
from redsim.ml.assets.manifest import (
    MANIFEST_NAME,
    AssetManifest,
    DatasetEntry,
    FileEntry,
    SplitEntry,
    sha256_bytes,
    write_manifest,
)

PROJECT = "proj-1"
FAKE_KEY = "pk_live_thisisnotarealkey_0123456789abcdef"
FAKE_URL = "https://pythia.gateway.example.internal"


@pytest.fixture
def api(sqlite_session_factory: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SimpleNamespace]:
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings

    with sqlite_session_factory.Session() as sess:
        sess.add(Organization(id="org-1", name="Org", slug="org"))
        sess.add(Project(id=PROJECT, org_id="org-1", name="Project", slug=PROJECT))
        sess.commit()
    monkeypatch.setattr("redsim.db.session.get_session", sqlite_session_factory.session_cm)
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(tmp_path / "no-assets"))
    for key in ("PYTHIA_API_KEY", "PYTHIA_BASE_URL", "PYTHIA_PERSONA", "REDSIM_ML_LLM_MODEL"):
        monkeypatch.delenv(key, raising=False)

    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    app = create_app(APISettings(env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"]))
    user = CurrentUser(sub="dev:viewer@test", email="viewer@test", project_memberships={PROJECT: "viewer"})
    app.dependency_overrides[get_current_user] = lambda: user
    yield SimpleNamespace(client=TestClient(app), tmp_path=tmp_path)
    rl._BUCKETS.clear()


def _block_package(monkeypatch: pytest.MonkeyPatch, package: str) -> None:
    """Make ``import <package>`` and every loaded submodule raise ImportError."""
    monkeypatch.setitem(sys.modules, package, None)
    for name in list(sys.modules):
        if name.startswith(package + "."):
            monkeypatch.setitem(sys.modules, name, None)


def test_capabilities_never_leak_pythia(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHIA_API_KEY", FAKE_KEY)
    monkeypatch.setenv("PYTHIA_BASE_URL", FAKE_URL)
    monkeypatch.setenv("PYTHIA_PERSONA", "ndia-demo")
    monkeypatch.setenv("REDSIM_ML_LLM_MODEL", "pythia/auto")
    monkeypatch.setenv("REDSIM_PLUGINS_SANDBOX", "0")      # plugin switch; irrelevant to the ML sandbox

    resp = api.client.get("/v1/ml/capabilities")
    assert resp.status_code == 200, resp.text
    text = resp.text
    for secret in (FAKE_KEY, FAKE_URL, "pythia.gateway.example.internal", "ndia-demo", "pk_live"):
        assert secret not in text, f"capabilities leaked {secret!r}"
    body = resp.json()
    assert body["llm_narrative"] == {"configured": True, "gateway": "pythia", "model": "pythia/auto", "persona_set": True}
    assert body["sandbox_enabled"] is True, "the ML sandbox has no switch (spec 9.4)"
    assert body["pickle_accepted"] is False
    assert body["upload_formats"] == ["onnx", "torch_state_dict", "safetensors_state_dict"]
    assert {"small_cnn", "smallcnn", "resnet18"} <= set(body["architectures"])
    assert body["modalities"]["llm"]["status"] == "not_implemented" and body["modalities"]["llm"]["phase"] == "B"
    assert body["upload_max_mb"] == 512
    assert isinstance(body["worker_ml_extra"], bool)

    # Unconfigured: the block says so with a reason and still names nothing secret.
    for key in ("PYTHIA_API_KEY", "PYTHIA_BASE_URL", "PYTHIA_PERSONA", "REDSIM_ML_LLM_MODEL"):
        monkeypatch.delenv(key)
    body = api.client.get("/v1/ml/capabilities").json()
    assert body["llm_narrative"]["configured"] is False and body["llm_narrative"]["model"] is None
    assert body["llm_narrative"]["persona_set"] is False and body["llm_narrative"]["reason"]


@pytest.mark.parametrize(("path", "package", "payload_key"), [
    ("/v1/models?project=proj-1", "redsim.ml.targets", "models"),
    ("/v1/models/vehicles_cnn?project=proj-1", "redsim.ml.targets", "id"),
    ("/v1/ml/capabilities", "redsim.ml.targets", "bundled_models"),
    ("/v1/ml/capabilities", "redsim.ml.defenses", "defenses"),
    ("/v1/defenses", "redsim.ml.defenses", "defenses"),
])
def test_catalog_503_not_empty(
    api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, path: str, package: str, payload_key: str,
) -> None:
    with monkeypatch.context() as scoped:
        _block_package(scoped, package)
        resp = api.client.get(path)
    assert resp.status_code == 503, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "ml_catalog_unavailable" and package in detail["reason"] and detail["message"]
    assert payload_key not in resp.json(), "an unavailable catalog must not look like an empty one"
    # And the route recovers once the registry imports again.
    recovered = api.client.get(path)
    assert recovered.status_code in {200, 404}, recovered.text


def test_models_catalog_without_built_assets_is_honest(api: SimpleNamespace) -> None:
    """No asset tree: bundled entries are listed as not_implemented with the build hint, never as available."""
    body = api.client.get("/v1/models", params={"project": PROJECT}).json()
    rows = {row["id"]: row for row in body["models"]}
    assert {"vehicles_cnn", "url_trees", "endpoint_stub"} <= set(rows)
    assert "cifar10_smallcnn" not in rows
    for bundled in ("vehicles_cnn", "url_trees"):
        assert rows[bundled]["status"] == "not_implemented" and "build-assets" in rows[bundled]["reason"]
        assert rows[bundled]["registered"] is False
    assert body["count"] == len(body["models"])


def test_datasets_catalog_reports_manifest_state(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = api.client.get("/v1/datasets")
    assert missing.status_code == 200, missing.text
    assert missing.json()["datasets"] == [] and missing.json()["count"] == 0
    assert missing.json()["assets"]["status"] == "missing" and "build-assets" in missing.json()["assets"]["reason"]

    root = api.tmp_path / "assets"
    root.mkdir()
    slice_path = root / "datasets/hf--example--vehicles/rev1/test.npz"
    slice_path.parent.mkdir(parents=True)
    slice_path.write_bytes(b"npz")
    manifest = AssetManifest.new()
    manifest.datasets["hf:example/vehicles"] = DatasetEntry(
        id="hf:example/vehicles", source="huggingface", revision="rev1", license="MIT", url="https://hf.example/v",
        class_names=["a", "b"],
        splits={"test": SplitEntry(name="test", n=2, file=FileEntry(
            path="datasets/hf--example--vehicles/rev1/test.npz", sha256=sha256_bytes(b"npz"), size_bytes=3))},
        preprocessing={"resolution": 8, "layout": "NCHW"},
    )
    manifest.datasets["hf:uoft-cs/cifar10"] = DatasetEntry(
        id="hf:uoft-cs/cifar10", source="huggingface", revision="rev9", license="MIT", class_names=["c"],
        splits={"test": SplitEntry(name="test", n=500)}, fixture_only=True,
        preprocessing={"resolution": 32, "layout": "NCHW"},
    )
    manifest.datasets["kaggle:example/urls"] = DatasetEntry(
        id="kaggle:example/urls", source="kaggle", revision="rev2", license="CC0", class_names=["benign", "phishing"],
        splits={"eval": SplitEntry(name="eval", n=10)}, preprocessing={"features": ["f1"]},
    )
    write_manifest(manifest, root / MANIFEST_NAME)
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(root))

    built = api.client.get("/v1/datasets").json()
    assert built["assets"]["status"] == "built" and built["count"] == 3
    rows = {row["id"]: row for row in built["datasets"]}
    vehicles = rows["hf:example/vehicles"]
    assert vehicles["role"] == "demo" and vehicles["reachability"] == "bundled" and vehicles["bundled_splits"] == ["test"]
    assert vehicles["compatible_modalities"] == ["image"] and vehicles["classes"] == ["a", "b"] and vehicles["size"] == 2
    assert vehicles["license"] == "MIT" and vehicles["source_url"] == "https://hf.example/v" and vehicles["revision"] == "rev1"
    cifar = rows["hf:uoft-cs/cifar10"]
    assert cifar["role"] == "ci_fixture" and cifar["fixture_only"] is True and cifar["reachability"] == "manifest_only"
    assert rows["kaggle:example/urls"]["compatible_modalities"] == ["tabular"]
    assert "pk_" not in json.dumps(built)
