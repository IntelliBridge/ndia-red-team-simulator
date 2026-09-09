"""Build tiny assets with the real builder, load them through ``TARGETS``, predict (G-ASSET1/3/6/7).

The proof that the loaders read exactly what ``redsim ml build-assets`` writes: ``build_cnn_asset`` on a
synthetic 8x8 image set and ``build_url_asset`` on the committed URL sample go into ``tmp_path`` as a
full ``AssetManifest``; ``REDSIM_ML_ASSETS_DIR`` points the registered ``vehicles_cnn`` and ``url_trees``
targets at it. No network, no Kaggle, no download; nothing here is a demo result.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("sklearn")
pytest.importorskip("art")

import numpy as np

from redsim.ml import errors
from redsim.ml.assets import datasets as ds
from redsim.ml.assets.build import build_cnn_asset, build_url_asset
from redsim.ml.assets.manifest import (
    MANIFEST_NAME,
    AssetManifest,
    DatasetEntry,
    load_manifest,
    write_manifest,
)
from redsim.ml.errors import ArtifactDigestMismatch, UnsupportedArtifact
from redsim.ml.schema import MLModelManifest
from redsim.ml.targets import bundled, tabular
from redsim.ml.targets.base import Target
from redsim.ml.targets.registry import TARGETS, get_target

pytestmark = pytest.mark.ml

SAMPLE = Path(__file__).parent / "fixtures" / "malicious_urls_sample.csv"
CLASS_NAMES = ["class_0", "class_1", "class_2"]


def _quiet(_: str) -> None:
    return None


def _synthetic_images(n: int = 48, image_size: int = 8, seed: int = 0) -> ds.ImageDataset:
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 256, size=(n, 3, image_size, image_size), dtype=np.uint8)
    y = (np.arange(n) % len(CLASS_NAMES)).astype(np.int64)
    entry = DatasetEntry(id="local:synthetic-images", source="local", revision="synthetic-v1", license="n/a",
                         class_names=list(CLASS_NAMES), fixture_only=True, notes=["unit-test double"])
    train = ds.ImageSplit(name="train", x=x, y=y, indices=np.arange(n, dtype=np.int64), class_names=list(CLASS_NAMES))
    n_eval = n // 2
    evaluation = ds.ImageSplit(name="test", x=x[:n_eval], y=y[:n_eval], indices=np.arange(n_eval, dtype=np.int64),
                               class_names=list(CLASS_NAMES))
    return ds.ImageDataset(dataset=entry, train=train, eval=evaluation)


@pytest.fixture
def built_tree(tmp_path: Path, no_kaggle: Path) -> Path:
    """A complete asset tree written by the real builder: one image model, one tabular model."""
    root = tmp_path / "assets"
    img_ds, img_model = build_cnn_asset(_synthetic_images(), model_id="vehicles_cnn", root=root, epochs=1, seed=0,
                                        log=_quiet)
    url_ds, url_model = build_url_asset(ds.sample_url_table(SAMPLE), model_id="url_trees", root=root, seed=0,
                                        log=_quiet)
    manifest = AssetManifest.new()
    manifest.datasets[img_ds.id] = img_ds
    manifest.datasets[url_ds.id] = url_ds
    manifest.models[img_model.id] = img_model
    manifest.models[url_model.id] = url_model
    write_manifest(manifest, root / MANIFEST_NAME)
    return root


@pytest.fixture
def registered(built_tree: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> Path:
    """Point the registered targets at the built tree and leave them unloaded afterwards."""
    monkeypatch.setenv(bundled.ASSETS_DIR_ENV, str(built_tree))
    for target_id in ("vehicles_cnn", "url_trees"):
        target = get_target(target_id)
        target.unload()
        request.addfinalizer(target.unload)
    return built_tree


def test_registered_targets_load_the_built_assets_and_predict(registered: Path) -> None:
    raw = json.loads((registered / MANIFEST_NAME).read_text())
    assert set(raw["models"]) == {"vehicles_cnn", "url_trees"}

    img = TARGETS.get("vehicles_cnn")
    assert isinstance(img, Target) and img.root == registered
    info = img.info()
    assert info.status == "available" and info.metadata["architecture_id"] == "small_cnn"
    assert info.metadata["file"]["path"] == "bundled/vehicles_cnn/weights.pt"
    img.load()
    s = img.sample(12, seed=0)
    assert s.x.shape == (12, 3, 8, 8) and s.x.dtype == np.float32 and 0.0 <= s.x.min() and s.x.max() <= 1.0
    assert np.bincount(s.y, minlength=3).tolist() == [4, 4, 4] and s.class_names == CLASS_NAMES
    proba = img.predict_proba(s.x)
    assert proba.shape == (12, 3) and np.allclose(proba.sum(axis=1), 1.0, atol=1e-5)
    clf = img.art_classifier()
    assert type(clf).__name__ == "PyTorchClassifier" and clf.input_shape == (3, 8, 8) and clf.nb_classes == 3
    m = img.manifest()
    entry = raw["models"]["vehicles_cnn"]
    assert m["weights_sha256_verified"] == entry["sha256"] == entry["file"]["sha256"]
    assert m["manifest_verified"] is True, "the asset-manifest verification ran at load"
    assert m["eval_split_file"] == raw["datasets"]["local:synthetic-images"]["splits"]["test"]["file"]["path"]
    assert m["architecture"] == entry["architecture"] and m["architecture_id"] == "small_cnn"
    assert m["eval_n"] == 24 and m["eval_per_class"] == {c: 8 for c in CLASS_NAMES}
    mm = MLModelManifest.model_validate(m)
    assert mm.clean_accuracy is not None and mm.clean_accuracy.n == 24 and mm.clean_accuracy.split == "test"
    assert mm.clean_accuracy.value == entry["metrics"]["clean_accuracy"]
    assert mm.dataset_id == "local:synthetic-images" and mm.dataset_revision == "synthetic-v1"
    assert mm.gradients is True and mm.bundled is True and mm.manifest_sha256 == entry["manifest_sha256"]
    # The model reproduces the accuracy the build recorded on the very slice it is bound to.
    x_all, y_all = np.load(registered / m["eval_split_file"], allow_pickle=False)["x"], None
    with np.load(registered / m["eval_split_file"], allow_pickle=False) as npz:
        y_all = npz["y"]
    acc = float((img.predict_proba(x_all).argmax(1) == y_all).mean())
    assert acc == pytest.approx(entry["metrics"]["clean_accuracy"])

    tab = TARGETS.get("url_trees")
    assert isinstance(tab, Target) and tab.root == registered
    tinfo = tab.info()
    assert tinfo.status == "available" and tinfo.metadata["gradients"] is True    # via the declared surrogate
    assert tinfo.metadata["format"] == "sklearn_joblib" and tinfo.metadata["fixture_only"] is True
    tab.load()
    assert tab.feature_names == list(tabular.contract_feature_names()) and len(tab.feature_names) == 16
    ts = tab.sample(8, seed=0)
    assert ts.x.shape == (8, 16) and ts.x.dtype == np.float32 and np.bincount(ts.y, minlength=4).tolist() == [2] * 4
    tproba = tab.predict_proba(ts.x)
    assert tproba.shape == (8, 4) and np.allclose(tproba.sum(axis=1), 1.0, atol=1e-5)
    tclf = tab.art_classifier()
    assert type(tclf).__name__.startswith("Scikitlearn") and tclf.predict(ts.x[:2]).shape == (2, 4)
    sur = tab.surrogate_art_classifier()
    assert sur is not None and hasattr(sur, "loss_gradient") and sur.predict(ts.x[:2]).shape == (2, 4)
    # The build's surrogate is a Pipeline(StandardScaler, LogisticRegression): ART sees the bare logistic
    # regression with the scaler folded into preprocessing, so predictions match the pipeline exactly and
    # PGD by transfer has a loss gradient to follow (spec 12.2).
    assert np.allclose(sur.predict(ts.x), tab._surrogate.predict_proba(ts.x), atol=1e-5)
    grad = sur.loss_gradient(ts.x[:3], np.eye(4, dtype=np.float32)[ts.y[:3]])
    assert grad.shape == (3, 16) and np.isfinite(grad).all() and np.abs(grad).sum() > 0
    assert tab.torch_model() is None and tab.sklearn_model() is tab.sklearn_model()
    tm = tab.manifest()
    tentry = raw["models"]["url_trees"]
    assert tm["weights_sha256_verified"] == tentry["file"]["sha256"] and tm["manifest_verified"] is True
    assert tm["eval_split_file"].endswith("/eval.npz") and tm["n_features"] == 16
    assert tm["eval_n"] == 12 and tm["eval_per_class"] == {c: 3 for c in tentry["class_names"]}
    tmm = MLModelManifest.model_validate(tm)
    assert tmm.format == "sklearn_joblib" and tmm.gradients is True and tmm.surrogate is not None
    assert tmm.surrogate.sha256 == tentry["surrogate"]["file"]["sha256"]
    assert tmm.surrogate.agreement_clean is not None and tmm.surrogate.agreement_clean.n == 12
    assert tmm.features is not None and [f.name for f in tmm.features] == tab.feature_names
    assert tab.perturbable_mask().sum() == 12 and tab.feature_ranges() is not None
    assert tmm.clean_accuracy is not None and tmm.clean_accuracy.value == tentry["metrics"]["clean_accuracy"]
    assert tmm.dataset_id == "local:tests/ml/fixtures/malicious_urls_sample.csv"
    # Predictions on the bundled slice reproduce the recorded clean accuracy (the slice is precomputed features).
    with np.load(registered / tm["eval_split_file"], allow_pickle=False) as npz:
        tx, ty = npz["x"], npz["y"]
    assert float((tab.predict_proba(tx).argmax(1) == ty).mean()) == pytest.approx(tentry["metrics"]["clean_accuracy"])


def test_prefer_xgboost_build_is_loadable_end_to_end(tmp_path: Path, no_kaggle: Path) -> None:
    root = tmp_path / "assets"
    url_ds, url_model = build_url_asset(ds.sample_url_table(SAMPLE), model_id="url_trees", root=root, seed=0,
                                        prefer_xgboost=True, log=_quiet)
    manifest = AssetManifest.new()
    manifest.datasets[url_ds.id] = url_ds
    manifest.models[url_model.id] = url_model
    write_manifest(manifest, root / MANIFEST_NAME)
    t = tabular.BundledTabularTarget("url_trees", assets_dir=root)
    t.load()
    s = t.sample(8, 0)
    assert t.predict_proba(s.x).shape == (8, 4)
    if importlib.util.find_spec("xgboost") is None:
        assert url_model.format == "sklearn_joblib" and url_model.training["xgboost_requested"] is True
        assert type(t.art_classifier()).__name__.startswith("Scikitlearn")
    else:  # pragma: no cover - depends on the environment
        assert url_model.format == "xgboost_json" and url_model.file.path.endswith(".json")
        assert type(t.art_classifier()).__name__ == "XGBoostClassifier"
        assert t.sklearn_model().num_features() == 16
    assert MLModelManifest.model_validate(t.manifest()).format == url_model.format


def _flip_last_byte(path: Path) -> None:
    payload = bytearray(path.read_bytes())
    payload[-1] ^= 0xFF
    path.write_bytes(bytes(payload))


def test_tampered_or_missing_eval_split_is_dataset_unavailable(built_tree: Path) -> None:
    loaded = load_manifest(built_tree / MANIFEST_NAME)
    img_split = built_tree / loaded.datasets["local:synthetic-images"].splits["test"].file.path  # type: ignore[union-attr]
    _flip_last_byte(img_split)
    with pytest.raises(errors.DatasetUnavailable, match="sha256 mismatch") as info:
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=built_tree).load()
    assert info.value.code == "dataset_unavailable"
    img_split.unlink()
    with pytest.raises(errors.DatasetUnavailable, match="missing file"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=built_tree).load()

    url_entry = loaded.datasets["local:tests/ml/fixtures/malicious_urls_sample.csv"]
    url_split = built_tree / url_entry.splits["eval"].file.path  # type: ignore[union-attr]
    _flip_last_byte(url_split)
    with pytest.raises(errors.DatasetUnavailable, match="sha256 mismatch"):
        tabular.BundledTabularTarget("url_trees", assets_dir=built_tree).load()
    url_split.unlink()
    with pytest.raises(errors.DatasetUnavailable, match="missing file"):
        tabular.BundledTabularTarget("url_trees", assets_dir=built_tree).load()
    # The human-readable listing is part of the bundled split too: tampering it is caught the same way.
    url_split.write_bytes(b"")
    doc = json.loads((built_tree / MANIFEST_NAME).read_text())
    split = doc["datasets"][url_entry.id]["splits"]["eval"]
    (built_tree / split["file"]["path"]).write_bytes(b"")
    _flip_last_byte(built_tree / split["rows_csv"]["path"])
    with pytest.raises(errors.DatasetUnavailable):
        tabular.BundledTabularTarget("url_trees", assets_dir=built_tree).load()


def test_tampered_weights_or_edited_entry_are_typed_refusals(built_tree: Path) -> None:
    doc = json.loads((built_tree / MANIFEST_NAME).read_text())
    _flip_last_byte(built_tree / doc["models"]["vehicles_cnn"]["file"]["path"])
    with pytest.raises(ArtifactDigestMismatch, match="hash_mismatch"):
        bundled.BundledImageTarget("vehicles_cnn", assets_dir=built_tree).load()
    surrogate = built_tree / doc["models"]["url_trees"]["surrogate"]["file"]["path"]
    original = surrogate.read_bytes()
    _flip_last_byte(surrogate)
    with pytest.raises(ArtifactDigestMismatch, match="surrogate"):
        tabular.BundledTabularTarget("url_trees", assets_dir=built_tree).load()
    surrogate.write_bytes(original)
    # An edited entry no longer matches its manifest_sha256: refused before any file is opened.
    fresh = json.loads((built_tree / MANIFEST_NAME).read_text())
    fresh["models"]["url_trees"]["class_names"] = list(reversed(fresh["models"]["url_trees"]["class_names"]))
    (built_tree / MANIFEST_NAME).write_text(json.dumps(fresh))
    with pytest.raises(UnsupportedArtifact, match="manifest_sha256 mismatch"):
        tabular.BundledTabularTarget("url_trees", assets_dir=built_tree).load()


def test_legacy_url_classifier_entry_in_a_builder_manifest_still_loads(built_tree: Path) -> None:
    doc = json.loads((built_tree / MANIFEST_NAME).read_text())
    doc["models"]["url_classifier"] = doc["models"].pop("url_trees")     # what earlier builds wrote
    (built_tree / MANIFEST_NAME).write_text(json.dumps(doc))
    t = tabular.BundledTabularTarget("url_trees", assets_dir=built_tree)
    assert t.info().status == "available"
    t.load()
    assert t.manifest()["manifest_verified"] is True and t.manifest()["id"] == "url_trees"


def test_upload_binding_resolves_the_same_slice_the_bundled_model_uses(built_tree: Path) -> None:
    """The API/worker binding for uploads (services.ml_models) and the bundled loader read one shape."""
    from redsim.services.ml_models import resolve_dataset_binding

    binding = resolve_dataset_binding("local:synthetic-images", root=built_tree)
    t = bundled.BundledImageTarget("vehicles_cnn", assets_dir=built_tree)
    t.load()
    assert binding.file_path == t.manifest()["eval_split_file"] and binding.split == "test"
    assert binding.class_names == CLASS_NAMES and binding.revision == "synthetic-v1" and binding.legacy is False
    url_binding = resolve_dataset_binding("local:tests/ml/fixtures/malicious_urls_sample.csv", root=built_tree)
    assert url_binding.file_path.endswith("/eval.npz") and url_binding.modality == "tabular"
