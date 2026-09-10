"""G-CAP and the catalog reads: no Pythia secret in the roster, 503 instead of an empty catalog.

The capabilities route is exercised with a fully configured Pythia environment
(fake values) and the response text is searched for them; the catalog routes
are exercised with a registry made unimportable, which must be a ``503
ml_catalog_unavailable``, never a ``200`` with empty lists. ``/v1/datasets``
reports the state of the asset manifest instead of hiding it behind ``[]``.
``GET /v1/attacks`` registers opt-in attack plugins (``REDSIM_PLUGINS=1``) once
per process and reports their discovery rows, and a loader failure is a ``503``.
"""

from __future__ import annotations

import importlib.metadata
import json
import sys
from collections.abc import Callable, Iterator
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
    for key in ("PYTHIA_API_KEY", "PYTHIA_BASE_URL", "PYTHIA_PERSONA", "REDSIM_ML_LLM_MODEL",
                "REDSIM_INTEGRATION_FOUNDRY_URL", "REDSIM_LLM_PROBE_HF_DETECTORS"):
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
    assert body["upload_max_mb"] == 512
    assert isinstance(body["worker_ml_extra"], bool)
    # Wave B4: the Phase B rows are read from the tree, not asserted (spec 26.24).
    for modality in ("image", "tabular"):
        assert body["modalities"][modality] == {"status": "available", "phase": "A"}
    text, detection, llm = (body["modalities"][m] for m in ("text", "detection", "llm"))
    assert text["status"] == "available" and text["phase"] == "B" and "word_substitution" in text["attacks"]
    assert detection["status"] == "available" and detection["phase"] == "B" and "dpatch" in detection["attacks"]
    assert llm["status"] == "available" and llm["phase"] == "B" and llm["kind"] == "probe"
    assert "redsim-core" in llm["probe_sets"] and llm["garak_version_expected"] and "MRI" in llm["note"]
    connector = body["endpoint_connector"]
    assert connector["status"] == "available" and connector["phase"] == "B" and connector["gradients"] is False
    assert connector["auth_kinds"] == ["bearer", "header"] and connector["contract"]["contract_version"] == "endpoint-v1"
    assert "hopskipjump" in connector["attacks"] and "fgsm" not in connector["attacks"]
    assert connector["ownership_verification"]["status"] == "not_implemented"
    assert body["explainers"] == {"image": "shap", "tabular": "shap", "text": "shap", "detection": None}
    assert body["explainer_roster"]["detection"]["status"] == "not_implemented"
    assert body["explainer_roster"]["detection"]["reason"] and "image" in body["explainer_roster"]
    interop = body["interop"]
    assert interop["dataset_export"]["status"] == "available" and interop["dataset_consume"]["modalities"] == ["image", "tabular"]
    assert interop["atlas"]["release"] and interop["atlas"]["data_sha256"]
    assert interop["integrations"]["foundry"]["status"] == "disabled", "no Foundry URL in this process"
    assert interop["integrations"]["lattice"]["status"] == "not_implemented"
    assert "REDSIM_INTEGRATION_FOUNDRY_URL" in interop["integrations"]["foundry"]["settings"]

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
    ("/v1/ml/capabilities", "redsim.ml.attacks", "modalities"),
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


# --- GET /v1/attacks: opt-in plugin adapters ---------------------------------------------

def test_attack_catalog_filters_on_capability_tags(api: SimpleNamespace) -> None:
    """``?modality=`` follows the ``modality:<domain>`` tags admission uses, not ``AttackInfo.domain`` alone."""
    everything = api.client.get("/v1/attacks")
    assert everything.status_code == 200, everything.text
    rows = {row["id"]: row for row in everything.json()["attacks"]}
    for row in rows.values():
        assert f"modality:{row['domain']}" in row["capabilities"], row["id"]
        assert row["domain"] in row["domains"] and row["domains"] == sorted(row["domains"]), row["id"]
    assert rows["hopskipjump"]["domains"] == ["image", "tabular"] and rows["pgd"]["domains"] == ["image", "tabular"]
    assert rows["fgsm"]["domains"] == ["image"]
    image = {row["id"] for row in api.client.get("/v1/attacks", params={"modality": "image"}).json()["attacks"]}
    tabular = {row["id"] for row in api.client.get("/v1/attacks", params={"modality": "tabular"}).json()["attacks"]}
    assert {"fgsm", "pgd", "hopskipjump", "noise_control"} <= image, "image HopSkipJump is listed (wave B1 tag)"
    assert {"pgd", "hopskipjump"} <= tabular, "the tabular surrogate-transfer PGD is listed"
    assert "fgsm" not in tabular
    text = api.client.get("/v1/attacks", params={"modality": "text"}).json()
    assert [row["id"] for row in text["attacks"]] == ["word_substitution"] and text["count"] == 1
    detection = {row["id"] for row in api.client.get("/v1/attacks", params={"modality": "detection"}).json()["attacks"]}
    assert "dpatch" in detection and "fgsm" not in detection
    assert api.client.get("/v1/attacks", params={"modality": "llm"}).json()["attacks"] == []
    assert api.client.get("/v1/attacks", params={"modality": "no-such-modality"}).json()["count"] == 0


FAKE_ATTACK_ID = "catalog-test-plugin-attack"
BROKEN_ATTACK_ID = "catalog-test-broken-attack"
FAKE_DIST = "catalog-fake-dist"


def _fake_plugin_entry_points() -> list[SimpleNamespace]:
    """Two ``redsim.ml.attacks`` entry points: one conformant adapter, one without ``run``."""
    from redsim.ml.schema import AttackInfo

    class FakePluginAttack:
        id = FAKE_ATTACK_ID
        domains = frozenset({"image"})
        takes_eps = True
        capabilities = frozenset({"adversarial_ml", "white_box", "takes_eps", "family:evasion", "modality:image"})

        def info(self) -> AttackInfo:
            return AttackInfo(id=self.id, name="Catalog test plugin", domain="image", family="evasion",
                              access="white-box", requires_gradients=True)

        def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
            return {}

        def run(self, target: Any, x: Any, y: Any, params: Any, seed: int) -> Any:  # pragma: no cover
            raise NotImplementedError

    class BrokenPluginAttack:
        """Non-conformant (no ``run``): must be reported, never listed."""

        id = BROKEN_ATTACK_ID

        def info(self) -> AttackInfo:
            return AttackInfo(id=self.id, name="broken", domain="image", family="evasion")

        def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
            return {}

    dist = SimpleNamespace(name=FAKE_DIST, version="0.1")
    return [
        SimpleNamespace(name="good", load=lambda: (lambda: FakePluginAttack()), dist=dist),
        SimpleNamespace(name="broken", load=lambda: (lambda: BrokenPluginAttack()), dist=dist),
    ]


def _patch_attack_entry_points(
    monkeypatch: pytest.MonkeyPatch, eps: list[SimpleNamespace],
) -> dict[str, int]:
    """Serve ``eps`` for the ``redsim.ml.attacks`` group only, counting the scans."""
    calls = {"n": 0}
    real: Callable[..., Any] = importlib.metadata.entry_points

    def fake_entry_points(**kwargs: Any) -> Any:
        if kwargs.get("group") == "redsim.ml.attacks":
            calls["n"] += 1
            return eps
        return real(**kwargs)

    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)
    return calls


def _fresh_plugin_state(monkeypatch: pytest.MonkeyPatch) -> Any:
    from redsim.api.v1 import attacks as attacks_route

    monkeypatch.setattr(attacks_route, "_PLUGIN_ROWS", None)
    for key in ("REDSIM_PLUGINS", "REDSIM_PLUGINS_ALLOW", "REDSIM_PLUGINS_REQUIRE_SIGNATURE"):
        monkeypatch.delenv(key, raising=False)
    return attacks_route


def test_attack_catalog_lists_plugin_adapters_only_behind_the_gate(
    api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redsim.ml.attacks.registry import ATTACKS

    _fresh_plugin_state(monkeypatch)
    calls = _patch_attack_entry_points(monkeypatch, _fake_plugin_entry_points())
    try:
        # Gate off: built-ins only, the group is never scanned, nothing is registered.
        off = api.client.get("/v1/attacks")
        assert off.status_code == 200, off.text
        body = off.json()
        ids = {row["id"] for row in body["attacks"]}
        assert {"fgsm", "pgd", "hopskipjump", "noise_control"} <= ids
        assert FAKE_ATTACK_ID not in ids
        assert body["plugins"] == {"enabled": False}
        assert calls["n"] == 0
        assert FAKE_ATTACK_ID not in ATTACKS

        # Gate on: the conformant plugin joins the catalog, the broken one is reported, not listed.
        monkeypatch.setenv("REDSIM_PLUGINS", "1")
        on = api.client.get("/v1/attacks")
        assert on.status_code == 200, on.text
        body = on.json()
        ids = {row["id"] for row in body["attacks"]}
        assert FAKE_ATTACK_ID in ids
        assert BROKEN_ATTACK_ID not in ids
        assert body["count"] == len(body["attacks"])
        plugin_row = next(row for row in body["attacks"] if row["id"] == FAKE_ATTACK_ID)
        assert plugin_row["name"] == "Catalog test plugin" and plugin_row["domain"] == "image"
        assert body["plugins"]["enabled"] is True
        rows = {row["name"]: row for row in body["plugins"]["rows"]}
        assert set(rows) == {FAKE_ATTACK_ID, "broken"}
        assert rows[FAKE_ATTACK_ID]["status"] == "loaded"
        assert rows[FAKE_ATTACK_ID]["kind"] == "attack" and rows[FAKE_ATTACK_ID]["group"] == "redsim.ml.attacks"
        assert rows[FAKE_ATTACK_ID]["distribution"] == FAKE_DIST and rows[FAKE_ATTACK_ID]["version"] == "0.1"
        assert rows["broken"]["status"] == "rejected" and "AttackAdapter" in rows["broken"]["detail"]
        assert calls["n"] == 1
        assert "pk_" not in on.text

        # Once per process: later requests list the plugin without rescanning the group.
        again = api.client.get("/v1/attacks")
        assert again.status_code == 200, again.text
        assert FAKE_ATTACK_ID in {row["id"] for row in again.json()["attacks"]}
        assert again.json()["plugins"] == body["plugins"]
        assert calls["n"] == 1

        # The modality filter applies to plugin adapters as it does to built-ins.
        tabular = api.client.get("/v1/attacks", params={"modality": "tabular"})
        assert tabular.status_code == 200, tabular.text
        assert FAKE_ATTACK_ID not in {row["id"] for row in tabular.json()["attacks"]}
    finally:
        ATTACKS._items.pop(FAKE_ATTACK_ID, None)


def test_attack_catalog_reports_plugin_loader_failure_and_recovers(
    api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A loader that raises is a 503 with its reason, never a 200 that looks plugin-free."""
    attacks_route = _fresh_plugin_state(monkeypatch)
    _patch_attack_entry_points(monkeypatch, [])
    monkeypatch.setenv("REDSIM_PLUGINS", "1")

    def broken_loader() -> list[Any]:
        raise RuntimeError("trusted keyring unreadable")

    with monkeypatch.context() as scoped:
        scoped.setattr("redsim.plugins.load_ml_attack_plugins", broken_loader)
        resp = api.client.get("/v1/attacks")
    assert resp.status_code == 503, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "ml_plugins_unavailable"
    assert "RuntimeError" in detail["reason"] and "trusted keyring unreadable" in detail["reason"]
    assert detail["message"]
    assert "attacks" not in resp.json(), "a failed plugin load must not look like a plugin-free catalog"
    assert attacks_route._PLUGIN_ROWS is None, "a failed load is not cached"

    # Once the loader works again the catalog recovers, with the (empty) discovery report.
    recovered = api.client.get("/v1/attacks")
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["plugins"] == {"enabled": True, "rows": []}
    assert recovered.json()["count"] >= 4
