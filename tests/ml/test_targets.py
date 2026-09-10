"""Target registry, stubs, and the bundled image / tabular targets over a synthetic asset tree.

No asset build, no network: the asset tree is written into ``tmp_path`` with a tiny torch
module injected into the architecture allowlist and a small random forest for the tabular target.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("art")
pytest.importorskip("sklearn")

import joblib
import numpy as np
import torch
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from torch import nn

from redsim.ml import errors
from redsim.ml import targets as targets_pkg
from redsim.ml.errors import ArtifactDigestMismatch, TargetUnavailable, UnsupportedArtifact
from redsim.ml.schema import AccuracyPoint, CleanAccuracy, MLModelManifest, SurrogateInfo, TargetInfo
from redsim.ml.targets import artifact, bundled, tabular, unavailable
from redsim.ml.targets.base import Target
from redsim.ml.targets.registry import TARGETS, get_target, list_targets
from tests.ml.fakes import CLASS_NAMES, _TinyNet

pytestmark = pytest.mark.ml

ROOT = Path(__file__).resolve().parents[2]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_manifest(root: Path, models: dict[str, Any]) -> None:
    (root / "MANIFEST.json").write_text(json.dumps({"schema": "redsim.ml.assets/1", "models": models}, indent=1))


def build_image_assets(root: Path, *, model_id: str = "vehicles_cnn", seed: int = 0, per_class: int = 20,
                       sha_override: str | None = None, weights_rel: str = "models/img/model.pt",
                       full_pickle: bool = False) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    net = _TinyNet(seed).eval()
    weights = root / weights_rel
    weights.parent.mkdir(parents=True, exist_ok=True)
    torch.save(net if full_pickle else net.state_dict(), weights)
    rng = np.random.default_rng(seed)
    n = per_class * len(CLASS_NAMES)
    x = rng.integers(0, 256, size=(n, 3, 8, 8), dtype=np.uint8)
    y = np.repeat(np.arange(len(CLASS_NAMES)), per_class)
    split = root / "datasets/img/eval.npz"
    split.parent.mkdir(parents=True, exist_ok=True)
    np.savez(split, x=x, y=y, indices=np.arange(n) + 5000, class_names=np.asarray(CLASS_NAMES))
    entry = {
        "name": "Synthetic tiny CNN", "modality": "image", "format": "torch_state_dict",
        "architecture_id": "tinynet", "architecture_kwargs": {"seed": 0},
        "weights": weights_rel, "sha256": sha_override or _sha(weights),
        "input_shape": [3, 8, 8], "n_classes": 3, "class_names": list(CLASS_NAMES),
        "eval_split": "datasets/img/eval.npz", "eval_split_sha256": _sha(split),
        "dataset_id": "synthetic/tiny", "dataset_revision": "deadbeef", "dataset_split": "eval",
        "license": "test fixture", "source_url": "https://example.invalid/synthetic-tiny",
        "clean_accuracy": {"value": 0.5, "n": n, "split": "eval"},
    }
    _write_manifest(root, {model_id: entry})
    return entry


def build_tabular_assets(root: Path, *, model_id: str = "url_trees", with_sha: bool = True, bad_sha: bool = False,
                         with_surrogate: bool = False, string_classes: bool = False) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    names = tabular.contract_feature_names()
    rng = np.random.default_rng(0)
    class_names = ["benign", "defacement", "phishing", "malware"]
    x = rng.random((120, len(names)), dtype=np.float32) * np.linspace(1, 100, len(names)).astype(np.float32)
    y = np.repeat(np.arange(4), 30)
    labels: Any = np.asarray(class_names)[y] if string_classes else y
    rf = RandomForestClassifier(n_estimators=8, random_state=0).fit(x, labels)
    weights = root / "models/url/model.joblib"
    weights.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(rf, weights)
    split = root / "datasets/url/eval.npz"
    split.parent.mkdir(parents=True, exist_ok=True)
    np.savez(split, x=x, y=y, indices=np.arange(120))
    features = [{"name": nme, "dtype": "float", "min": float(x[:, i].min()), "max": float(x[:, i].max()),
                 "perturbable": nme not in tabular.FROZEN_URL_FEATURES} for i, nme in enumerate(names)]
    entry: dict[str, Any] = {
        "name": "Synthetic URL trees", "modality": "tabular", "format": "sklearn_joblib",
        "weights": "models/url/model.joblib", "class_names": class_names, "features": features,
        "eval_split": "datasets/url/eval.npz", "eval_split_sha256": _sha(split),
        "dataset_id": "kaggle:sid321axn/malicious-urls-dataset", "dataset_revision": "csv-sha", "dataset_split": "eval",
        "license": "CC0: Public Domain",
    }
    if with_sha:
        entry["sha256"] = ("00" * 32) if bad_sha else _sha(weights)
    if with_surrogate:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")            # convergence on random features is irrelevant here
            lr = LogisticRegression(max_iter=200).fit(x, rf.predict(x))
        sur = root / "models/url/surrogate.joblib"
        joblib.dump(lr, sur)
        entry["surrogate"] = {"kind": "logistic_regression", "path": "models/url/surrogate.joblib",
                              "sha256": _sha(sur), "agreement_clean": {"n": 120, "n_correct": 108}}
    _write_manifest(root, {model_id: entry})
    return entry


@pytest.fixture
def tinynet_arch(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setitem(artifact.ARCHITECTURES, "tinynet", lambda **kw: _TinyNet(**kw))
    return "tinynet"


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)
    monkeypatch.setattr(socket, "getaddrinfo", _refuse)


# ----------------------------------------------------------------------------------------
# registry and stubs
# ----------------------------------------------------------------------------------------

def test_registry_lists_bundled_targets_and_stub() -> None:
    ids = TARGETS.ids()
    assert {"vehicles_cnn", "url_trees", "cifar10_smallcnn", "endpoint_stub"} <= set(ids)
    for t in TARGETS:
        assert isinstance(t, Target), t.id
    infos = list_targets()
    assert all(isinstance(i, TargetInfo) for i in infos)
    by_id = {i.id: i for i in infos}
    assert by_id["cifar10_smallcnn"].metadata["fixture_only"] is True
    assert by_id["vehicles_cnn"].metadata["fixture_only"] is False and by_id["vehicles_cnn"].domain == "image"
    assert by_id["url_trees"].domain == "tabular" and by_id["endpoint_stub"].domain == "llm"
    assert get_target("endpoint_stub") is unavailable.ENDPOINT_STUB
    assert targets_pkg.TARGETS is TARGETS


def test_importing_targets_pulls_no_ml_library_into_the_process() -> None:
    code = ("import sys; import redsim.ml.targets; "
            "print(sorted(m for m in ('torch','art','onnx','onnxruntime','sklearn','shap') if m in sys.modules))")
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT, env=env, check=True)
    assert out.stdout.strip() == "[]", out.stdout + out.stderr


def test_llm_stub_is_honest_and_leaks_no_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHIA_API_KEY", "pk_super_secret_value")
    monkeypatch.setenv("PYTHIA_BASE_URL", "https://pythia.example")
    monkeypatch.delenv("REDSIM_ML_LLM_MODEL", raising=False)
    monkeypatch.setenv("REDSIM_LLM_MODEL", "pythia/auto")      # the pre-M0 name: no longer honoured anywhere
    stub = get_target("endpoint_stub")
    info = stub.info()
    assert info.status == "not_implemented" and info.domain == "llm" and info.reason
    assert "501" in info.reason and "AuthProfile" in info.reason
    conn = info.metadata["connection"]
    assert conn["chat_path"] == "/v1/chat/completions" and conn["env"]["api_key"] == "PYTHIA_API_KEY"
    assert conn["env"]["model"] == unavailable.MODEL_ENV == "REDSIM_ML_LLM_MODEL"   # the frozen M0 name only
    assert conn["set"]["api_key"] is True and conn["set"]["model"] is False and conn["configured"] is False
    assert "pk_super_secret_value" not in json.dumps(info.model_dump())
    assert "pk_super_secret_value" not in json.dumps(stub.manifest())
    monkeypatch.setenv("REDSIM_ML_LLM_MODEL", "pythia/auto")
    configured = stub.info().metadata["connection"]
    assert configured["set"]["model"] is True and configured["configured"] is True
    assert "pythia/auto" not in json.dumps(stub.info().model_dump())   # names of variables, never their values
    for call in (stub.load, lambda: stub.sample(4, 0), lambda: stub.predict_proba(np.zeros((1, 3))),
                 stub.art_classifier, stub.torch_model):
        with pytest.raises(TargetUnavailable):
            call()


# ----------------------------------------------------------------------------------------
# bundled image target
# ----------------------------------------------------------------------------------------

def test_missing_assets_are_reported_not_faked(tmp_path: Path) -> None:
    for t in (bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path),
              tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path)):
        info = t.info()
        assert info.status == "not_implemented" and info.reason is not None
        assert str(tmp_path / "MANIFEST.json") in info.reason and "build-assets" in info.reason
        assert info.metadata["availability"] == "assets_missing"
        with pytest.raises(TargetUnavailable, match="missing"):
            t.load()
        with pytest.raises(TargetUnavailable):
            t.sample(10, 0)
    (tmp_path / "MANIFEST.json").write_text("{not json")
    broken = bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path)
    assert broken.info().metadata["availability"] == "manifest_invalid"
    with pytest.raises(UnsupportedArtifact):
        broken.load()


def test_registered_targets_default_to_env_assets_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(bundled.ASSETS_DIR_ENV, str(tmp_path / "built"))
    assert get_target("vehicles_cnn").root == tmp_path / "built"
    monkeypatch.delenv(bundled.ASSETS_DIR_ENV)
    assert get_target("vehicles_cnn").root == Path(bundled.DEFAULT_ASSETS_DIR)


def test_bundled_image_target_loads_samples_and_predicts(tmp_path: Path, tinynet_arch: str) -> None:
    entry = build_image_assets(tmp_path)
    t = bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path)
    assert isinstance(t, Target)
    info = t.info()
    assert info.status == "available" and info.metadata["dataset_id"] == "synthetic/tiny"
    assert info.metadata["clean_accuracy"] == entry["clean_accuracy"] and info.metadata["gradients"] is True
    t.load()
    t.load()
    s = t.sample(30, seed=0)
    assert s.x.dtype == np.float32 and s.x.shape == (30, 3, 8, 8) and s.x.min() >= 0.0 and s.x.max() <= 1.0
    assert np.bincount(s.y, minlength=3).tolist() == [10, 10, 10]
    assert s.indices.min() >= 5000                                     # source indices, not positions
    assert np.array_equal(s.indices, t.sample(30, seed=0).indices)
    assert not np.array_equal(s.indices, t.sample(30, seed=1).indices)
    assert s.class_names == list(CLASS_NAMES)
    proba = t.predict_proba(s.x)
    with torch.no_grad():
        ref = torch.softmax(t.torch_model()(torch.from_numpy(s.x)), dim=1).numpy()
    assert proba.shape == (30, 3) and np.allclose(proba.sum(axis=1), 1.0, atol=1e-5) and np.allclose(proba, ref, atol=1e-5)
    clf = t.art_classifier()
    assert clf.nb_classes == 3 and clf.input_shape == (3, 8, 8) and tuple(clf.clip_values) == (0.0, 1.0)
    assert clf.predict(s.x[:4]).shape == (4, 3)
    assert isinstance(t.torch_model(), nn.Module) and not t.torch_model().training
    m = t.manifest()
    assert m["weights_sha256_verified"] == entry["sha256"] and m["gradients"] is True
    assert m["eval_per_class"] == {c: 20 for c in CLASS_NAMES} and m["dataset_revision"] == "deadbeef"
    assert "torch" in m["library_versions"]
    mm = MLModelManifest.model_validate(m)                     # the schema block is a valid spec 5.5 manifest
    assert mm.name == entry["name"] and mm.modality == "image" and mm.format == "torch_state_dict"
    assert mm.sha256 == entry["sha256"] and mm.size_bytes == (tmp_path / entry["weights"]).stat().st_size
    assert mm.architecture_id == "tinynet" and mm.input_shape == [3, 8, 8] and mm.n_classes == 3
    assert mm.class_names == list(CLASS_NAMES) and mm.features is None and mm.surrogate is None
    assert mm.dataset_id == "synthetic/tiny" and mm.dataset_revision == "deadbeef" and mm.dataset_split == "eval"
    assert mm.clean_accuracy == CleanAccuracy(value=0.5, n=60, split="eval")
    assert mm.status == "available" and mm.refusal_reason is None and mm.gradients is True and mm.bundled is True
    assert mm.license == "test fixture" and mm.source_url == entry["source_url"]
    assert mm.manifest_sha256 and m["manifest_sha256"] == mm.manifest_sha256
    assert m["weights"] == entry["weights"] and m["eval_split"] == entry["eval_split"]   # the raw entry stays


def test_bundled_manifest_refuses_entries_that_break_the_model_manifest(tmp_path: Path, tinynet_arch: str) -> None:
    entry = build_image_assets(tmp_path)
    no_dataset = {k: v for k, v in entry.items() if k != "dataset_id"}
    _write_manifest(tmp_path, {"vehicles_cnn": no_dataset})
    with pytest.raises(UnsupportedArtifact, match=r"(?s)valid model manifest.*dataset_id"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()
    _write_manifest(tmp_path, {"vehicles_cnn": {**entry, "clean_accuracy": {"value": 0.5}}})   # no denominator
    with pytest.raises(UnsupportedArtifact, match="valid model manifest"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()
    _write_manifest(tmp_path, {"vehicles_cnn": {**entry, "clean_accuracy": 0.5}})
    with pytest.raises(UnsupportedArtifact, match="clean_accuracy"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()


def test_manifest_count_blocks_keep_their_denominators() -> None:
    assert bundled.accuracy_point({"n": 120, "n_correct": 108}) == {"n": 120, "n_correct": 108, "accuracy": 0.9}
    assert bundled.accuracy_point({"n": 120, "n_correct": 108, "accuracy": 0.9}) == {"n": 120, "n_correct": 108,
                                                                                    "accuracy": 0.9}
    assert bundled.accuracy_point({"value": 0.9, "n": 120}) == {"n": 120, "n_correct": 108, "accuracy": 0.9}
    assert bundled.accuracy_point({"n": 0, "n_correct": 0}) == {"n": 0, "n_correct": 0, "accuracy": None}
    assert bundled.accuracy_point({"value": 0.9}) is None and bundled.accuracy_point(0.9) is None
    assert bundled.clean_accuracy_entry(None, "eval") is None
    assert bundled.clean_accuracy_entry({"value": 0.5, "n": 10}, "eval") == {"value": 0.5, "n": 10, "split": "eval"}
    assert bundled.clean_accuracy_entry({"value": 0.5, "n": 10, "split": "test"}, "eval")["split"] == "test"
    with pytest.raises(UnsupportedArtifact, match="clean_accuracy"):
        bundled.clean_accuracy_entry(0.5, "eval")
    assert bundled.surrogate_info_entry(None) is None
    decl = {"kind": "lr", "path": "models/s.joblib", "sha256": "ab" * 32, "agreement_clean": {"value": 0.5, "n": 4}}
    assert bundled.surrogate_info_entry(decl) == {"kind": "lr", "sha256": "ab" * 32,
                                                  "agreement_clean": {"n": 4, "n_correct": 2, "accuracy": 0.5}}
    with pytest.raises(UnsupportedArtifact, match="surrogate"):
        bundled.surrogate_info_entry("models/s.joblib")


def test_bundled_image_hash_mismatch_refused(tmp_path: Path, tinynet_arch: str) -> None:
    build_image_assets(tmp_path, sha_override="ab" * 32)
    t = bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path)
    with pytest.raises(UnsupportedArtifact, match="hash_mismatch"):
        t.load()


def test_bundled_image_refuses_pickled_module_and_missing_digest(tmp_path: Path, tinynet_arch: str) -> None:
    build_image_assets(tmp_path, full_pickle=True)      # sha256 matches the pickled file, format does not
    with pytest.raises(UnsupportedArtifact, match="pickle_refused"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()
    entry = build_image_assets(tmp_path)
    del entry["sha256"]
    _write_manifest(tmp_path, {"vehicles_cnn": entry})
    with pytest.raises(UnsupportedArtifact, match="no sha256"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()


def test_bundled_image_refuses_path_escape_and_unknown_architecture(tmp_path: Path, tinynet_arch: str) -> None:
    entry = build_image_assets(tmp_path)
    escaped = {**entry, "weights": "../outside.pt"}
    _write_manifest(tmp_path, {"vehicles_cnn": escaped})
    with pytest.raises(UnsupportedArtifact, match="escapes"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()
    _write_manifest(tmp_path, {"vehicles_cnn": {**entry, "architecture_id": "not_allowlisted"}})
    with pytest.raises(UnsupportedArtifact, match="architecture_not_allowlisted"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()
    _write_manifest(tmp_path, {"vehicles_cnn": {**entry, "input_shape": [3, 32, 32]}})
    with pytest.raises(UnsupportedArtifact, match="shape_mismatch"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()
    _write_manifest(tmp_path, [{"id": "vehicles_cnn", **entry}])       # list form of the manifest
    bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()


def test_smallcnn_allowlist_entry_reports_missing_module_clearly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "redsim.ml.targets.architectures", None)   # simulate the module being absent
    with pytest.raises(UnsupportedArtifact, match="not available"):
        artifact.resolve_architecture("smallcnn", {"n_classes": 3})


# ----------------------------------------------------------------------------------------
# bundled tabular (URL maliciousness) target
# ----------------------------------------------------------------------------------------

def test_bundled_tabular_target_loads_predicts_without_network(tmp_path: Path, no_network: None) -> None:
    entry = build_tabular_assets(tmp_path, with_surrogate=True)
    t = tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path)
    assert isinstance(t, Target)
    info = t.info()
    assert info.status == "available" and info.domain == "tabular" and info.metadata["gradients"] is True
    assert "realizability not established" in info.metadata["realizability"]
    t.load()
    assert t.feature_names == tabular.contract_feature_names() and len(t.feature_names) == 16
    s = t.sample(40, seed=0)
    assert s.x.shape == (40, 16) and s.x.dtype == np.float32 and np.bincount(s.y, minlength=4).tolist() == [10] * 4
    assert s.class_names == entry["class_names"]
    proba = t.predict_proba(s.x)
    assert proba.shape == (40, 4) and np.allclose(proba.sum(axis=1), 1.0, atol=1e-5)
    clf = t.art_classifier()
    assert type(clf).__name__.startswith("Scikitlearn") and clf.predict(s.x[:3]).shape == (3, 4)
    mins, maxs = clf.clip_values
    assert mins.shape == (16,) and np.all(maxs >= mins)
    assert t.torch_model() is None
    mask = t.perturbable_mask()
    assert mask.shape == (16,) and mask.sum() == 12
    assert not any(mask[t.feature_names.index(f)] for f in tabular.FROZEN_URL_FEATURES)
    sur = t.surrogate_art_classifier()
    assert sur is not None and hasattr(sur, "loss_gradient") and sur.predict(s.x[:2]).shape == (2, 4)
    m = t.manifest()
    assert m["weights_sha256_verified"] == entry["sha256"] and m["torch_model"] is None
    assert m["eval_per_class"] == {c: 30 for c in entry["class_names"]} and "scikit-learn" in m["library_versions"]
    assert m["realizability"] == tabular.REALIZABILITY_NOTE
    assert m["feature_names"] == t.feature_names and m["perturbable"] == mask.tolist()
    mm = MLModelManifest.model_validate(m)                     # the schema block is a valid spec 5.5 manifest
    assert mm.modality == "tabular" and mm.format == "sklearn_joblib" and mm.sha256 == entry["sha256"]
    assert mm.size_bytes == (tmp_path / entry["weights"]).stat().st_size and mm.architecture_id is None
    assert mm.input_shape == [16] and mm.n_classes == 4 and mm.class_names == entry["class_names"]
    assert mm.features is not None and [f.name for f in mm.features] == t.feature_names
    assert [f.perturbable for f in mm.features] == mask.tolist() and all(f.dtype == "float" for f in mm.features)
    assert all(f.min is not None and f.max is not None and f.max >= f.min for f in mm.features)
    assert mm.surrogate == SurrogateInfo(kind="logistic_regression", sha256=entry["surrogate"]["sha256"],
                                         agreement_clean=AccuracyPoint(n=120, n_correct=108, accuracy=0.9))
    assert m["surrogate"] == mm.surrogate.model_dump(mode="json")   # the surrogate path stays out of the record
    assert mm.dataset_id == entry["dataset_id"] and mm.dataset_revision == "csv-sha" and mm.dataset_split == "eval"
    assert mm.clean_accuracy is None and mm.license == "CC0: Public Domain" and mm.source_url is None
    assert mm.status == "available" and mm.gradients is True and mm.bundled is True and mm.manifest_sha256


def test_bundled_tabular_aligns_string_classes(tmp_path: Path) -> None:
    build_tabular_assets(tmp_path, string_classes=True)
    t = tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path)
    s = t.sample(20, 0)
    proba = t.predict_proba(s.x)
    hard = t.sklearn_model().predict(s.x)
    names = np.asarray(s.class_names)
    assert np.array_equal(names[proba.argmax(1)], hard)      # columns follow the manifest class order
    mm = MLModelManifest.model_validate(t.manifest())
    assert mm.surrogate is None and mm.gradients is False     # no surrogate declared: no gradients claimed


def test_bundled_tabular_without_feature_specs_keeps_the_contract_names(tmp_path: Path) -> None:
    entry = build_tabular_assets(tmp_path)
    _write_manifest(tmp_path, {"url_trees": {k: v for k, v in entry.items() if k != "features"}})
    t = tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path)
    m = t.manifest()
    mm = MLModelManifest.model_validate(m)
    assert mm.features is None and mm.input_shape == [16]      # no FeatureSpec rows are invented
    assert m["feature_names"] == tabular.contract_feature_names()
    assert t.perturbable_mask().sum() == 12 and t.feature_ranges() is None


def test_bundled_tabular_never_opens_pickle_without_matching_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[Path] = []
    real_load = joblib.load

    def spy(path: Any, *a: Any, **kw: Any) -> Any:
        opened.append(Path(path))
        return real_load(path, *a, **kw)

    monkeypatch.setattr(joblib, "load", spy)
    build_tabular_assets(tmp_path, with_sha=False)
    with pytest.raises(UnsupportedArtifact, match="no sha256"):
        tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path).load()
    build_tabular_assets(tmp_path, bad_sha=True)
    with pytest.raises(UnsupportedArtifact, match="hash_mismatch"):
        tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path).load()
    assert opened == []                                           # the pickle was never deserialised
    build_tabular_assets(tmp_path)
    tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path).load()
    assert len(opened) == 1


def test_bundled_tabular_refuses_feature_disagreement(tmp_path: Path) -> None:
    entry = build_tabular_assets(tmp_path)
    reordered = list(reversed(entry["features"]))
    _write_manifest(tmp_path, {"url_trees": {**entry, "features": reordered}})
    with pytest.raises(UnsupportedArtifact, match="feature order"):
        tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path).load()
    _write_manifest(tmp_path, {"url_trees": {**entry, "format": "onnx"}})
    with pytest.raises(UnsupportedArtifact, match="expected one of"):
        tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path).load()
    _write_manifest(tmp_path, {"url_trees": {**entry, "format": "xgboost_json"}})   # a joblib file is not one
    with pytest.raises(UnsupportedArtifact, match=r"\.json or \.ubj"):
        tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path).load()
    undigested = {"kind": "logistic_regression", "path": "models/url/surrogate.joblib"}   # no sha256
    _write_manifest(tmp_path, {"url_trees": {**entry, "surrogate": undigested}})
    with pytest.raises(UnsupportedArtifact, match=r"(?s)valid model manifest.*surrogate\.sha256"):
        tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path).load()


# ----------------------------------------------------------------------------------------
# evaluation-slice binding and verification at load (G-ASSET6 / G-ASSET7), legacy ids, unload
# ----------------------------------------------------------------------------------------

def test_tampered_or_missing_eval_split_raises_dataset_unavailable(tmp_path: Path, tinynet_arch: str) -> None:
    entry = build_image_assets(tmp_path)
    split = tmp_path / entry["eval_split"]
    payload = bytearray(split.read_bytes())
    payload[-1] ^= 0xFF
    split.write_bytes(bytes(payload))
    with pytest.raises(errors.DatasetUnavailable, match="hash_mismatch") as info:
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()
    assert info.value.code == "dataset_unavailable" and isinstance(info.value, TargetUnavailable)
    split.unlink()
    with pytest.raises(errors.DatasetUnavailable, match="not found"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()
    unbound = {k: v for k, v in entry.items() if k not in ("eval_split", "eval_split_sha256")}
    _write_manifest(tmp_path, {"vehicles_cnn": unbound})
    with pytest.raises(errors.DatasetUnavailable, match="bound to no evaluation slice"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()

    tab = build_tabular_assets(tmp_path)
    tsplit = tmp_path / tab["eval_split"]
    payload = bytearray(tsplit.read_bytes())
    payload[-1] ^= 0xFF
    tsplit.write_bytes(bytes(payload))
    with pytest.raises(errors.DatasetUnavailable, match="hash_mismatch"):
        tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path).load()
    tsplit.unlink()
    with pytest.raises(errors.DatasetUnavailable, match="not found"):
        tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path).load()


def test_weights_digest_mismatch_is_a_typed_refusal(tmp_path: Path, tinynet_arch: str) -> None:
    build_image_assets(tmp_path, sha_override="ab" * 32)
    with pytest.raises(ArtifactDigestMismatch) as info:
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()
    assert info.value.code == "artifact_digest_mismatch" and isinstance(info.value, UnsupportedArtifact)


def test_eval_split_binds_through_the_dataset_entry(tmp_path: Path, tinynet_arch: str) -> None:
    """The builder shape: the slice lives at datasets[dataset_id].splits[split].file, not on the model entry."""
    entry = build_image_assets(tmp_path)
    split_rel, split_sha = entry.pop("eval_split"), entry.pop("eval_split_sha256")
    entry.pop("class_names")                                       # class names come from the dataset entry
    entry["dataset_revision"] = None
    doc = {
        "schema": "redsim.ml.assets/1",
        "datasets": {entry["dataset_id"]: {
            "id": entry["dataset_id"], "revision": "rev-from-dataset", "class_names": list(CLASS_NAMES),
            "splits": {"eval": {"name": "eval", "n": 60,
                                "file": {"path": split_rel, "sha256": split_sha, "size_bytes": 1}}}}},
        "models": {"vehicles_cnn": {**entry, "file": {"path": entry["weights"], "sha256": entry["sha256"],
                                                      "size_bytes": 1},
                                    "architecture": {"architecture_id": "tinynet", "seed": 0}}},
    }
    (tmp_path / "MANIFEST.json").write_text(json.dumps(doc))
    t = bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path)
    t.load()
    m = t.manifest()
    assert m["eval_split_file"] == split_rel and m["eval_split_sha256_verified"] == split_sha
    assert m["class_names"] == list(CLASS_NAMES) and m["dataset_revision"] == "rev-from-dataset"
    assert m["manifest_verified"] is False                          # not a full builder manifest: per-file checks ran
    ref = bundled.resolve_eval_split(doc, doc["models"]["vehicles_cnn"], "vehicles_cnn")
    assert ref.path == split_rel and ref.split == "eval" and ref.class_names == list(CLASS_NAMES)
    assert bundled.weights_ref(doc["models"]["vehicles_cnn"]) == (entry["weights"], entry["sha256"])
    assert bundled.architecture_kwargs(doc["models"]["vehicles_cnn"]) == {"architecture_id": "tinynet", "seed": 0}
    # A model entry whose sha256 disagrees with its own file block is refused before anything is read.
    doc["models"]["vehicles_cnn"]["file"]["sha256"] = "ab" * 32
    (tmp_path / "MANIFEST.json").write_text(json.dumps(doc))
    with pytest.raises(UnsupportedArtifact, match="file block"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()
    # A dataset entry without the named split falls back to nothing: the run is refused, never guessed.
    del doc["models"]["vehicles_cnn"]["file"]
    doc["datasets"][entry["dataset_id"]]["splits"] = {}
    (tmp_path / "MANIFEST.json").write_text(json.dumps(doc))
    with pytest.raises(errors.DatasetUnavailable, match="no bundled split"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path).load()


def test_legacy_tabular_id_resolves_to_url_trees(tmp_path: Path) -> None:
    entry = build_tabular_assets(tmp_path)
    _write_manifest(tmp_path, {"url_classifier": entry})           # what earlier builds wrote
    t = tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path)
    assert t.info().status == "available"
    t.load()
    assert t.manifest()["id"] == "url_trees" and t.manifest()["weights_sha256_verified"] == entry["sha256"]
    assert bundled.manifest_entry({"models": [{"id": "url_classifier", **entry}]}, "url_trees") is not None
    assert bundled.manifest_entry({"models": {"url_classifier": entry}}, "vehicles_cnn") is None


def test_unload_re_reads_the_asset_tree(tmp_path: Path, tinynet_arch: str) -> None:
    build_image_assets(tmp_path, per_class=10)
    t = bundled.BundledImageTarget("vehicles_cnn", assets_dir=tmp_path)
    assert t.manifest()["eval_n"] == 30
    build_image_assets(tmp_path, per_class=20)
    assert t.manifest()["eval_n"] == 30                             # cached
    t.unload()
    assert t.manifest()["eval_n"] == 60                             # re-read
    build_tabular_assets(tmp_path)
    tab = tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path)
    tab.load()
    tab.unload()
    assert tab._x is None
    tab.load()
    assert tab.manifest()["eval_n"] == 120


def test_bundled_targets_expose_surrogate_file_refs(tmp_path: Path) -> None:
    entry = build_tabular_assets(tmp_path, with_surrogate=True)
    assert bundled.surrogate_ref(entry["surrogate"]) == (entry["surrogate"]["path"], entry["surrogate"]["sha256"])
    builder_shape = {"kind": "lr", "sha256": entry["surrogate"]["sha256"],
                     "file": {"path": entry["surrogate"]["path"], "sha256": entry["surrogate"]["sha256"],
                              "size_bytes": 1}}
    assert bundled.surrogate_ref(builder_shape) == bundled.surrogate_ref(entry["surrogate"])
    with pytest.raises(UnsupportedArtifact, match="file block"):
        bundled.surrogate_ref({**builder_shape, "sha256": "cd" * 32})
    entry["surrogate"] = builder_shape
    _write_manifest(tmp_path, {"url_trees": entry})
    t = tabular.BundledTabularTarget("url_trees", assets_dir=tmp_path)
    assert t.surrogate_art_classifier() is not None
