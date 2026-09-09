"""The bundled URL classifier trains on the committed sample without Kaggle or the network (spec 11.3.3, M4).

ml tier: needs scikit-learn and numpy. No test here contacts Kaggle.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

pytestmark = pytest.mark.ml
np = pytest.importorskip("numpy")
pytest.importorskip("sklearn")

from redsim.ml.assets import datasets as ds
from redsim.ml.assets.build import build_url_asset
from redsim.ml.assets.manifest import (
    MANIFEST_NAME,
    AssetManifest,
    load_manifest,
    manifest_digest,
    verify_files,
    verify_manifest,
    write_manifest,
)
from redsim.ml.assets.train_url_classifier import (
    SURROGATE_KIND,
    load_url_classifier,
    save_url_classifier,
    train_url_classifier,
)
from redsim.ml.datasets.url_features import EXTRACTOR_VERSION, FEATURE_NAMES, featurize_array
from redsim.ml.schema import FeatureSpec, MLModelManifest

SAMPLE = Path(__file__).parent / "fixtures" / "malicious_urls_sample.csv"


def _quiet(_: str) -> None:
    return None


def _table() -> ds.UrlTable:
    return ds.sample_url_table(SAMPLE)


def test_trains_on_committed_sample():
    table = _table()
    assert table.dataset.fixture_only is True
    assert table.dataset.class_names == ["benign", "defacement", "phishing", "malware"]
    assert table.dataset.n_rows == len(table.urls) == len(table.row_indices) == 60
    assert table.dataset.sampled_from is not None and table.dataset.sampled_from["source_file_sha256"]
    result = train_url_classifier(table.urls, table.labels, seed=0, log=_quiet)
    assert result.library == "scikit-learn" and result.format == "sklearn_joblib", "sklearn is the default (spec 9.2)"
    assert result.training["xgboost_requested"] is False
    assert result.x_eval is not None and result.x_eval.shape == (len(result.eval_idx), len(FEATURE_NAMES))
    assert np.array_equal(result.x_eval, featurize_array([result.urls[i] for i in result.eval_idx]))
    assert result.n_duplicates_removed == 0
    assert len(result.train_idx) + len(result.eval_idx) == len(table.urls)
    assert not set(result.train_idx.tolist()) & set(result.eval_idx.tolist())
    assert result.metrics["n"] == len(result.eval_idx) == 12  # 4 classes x 3 held out at 20 %
    assert 0.0 <= result.metrics["clean_accuracy"] <= 1.0
    assert sum(c["n"] for c in result.metrics["per_class"].values()) == result.metrics["n"]
    assert [f.name for f in result.features] == list(FEATURE_NAMES)
    assert all(isinstance(f, FeatureSpec) for f in result.features)
    assert all(f.min is not None and f.max is not None and f.min <= f.max for f in result.features)
    assert 0 <= result.surrogate_agree_count <= len(result.eval_idx)
    assert result.surrogate_agreement == result.surrogate_agree_count / len(result.eval_idx)
    assert result.training["extractor_version"] == EXTRACTOR_VERSION
    assert result.training["surrogate"]["kind"] == SURROGATE_KIND


def test_prefer_xgboost_is_honoured_only_when_importable():
    import importlib.util

    table = _table()
    result = train_url_classifier(table.urls, table.labels, seed=0, prefer_xgboost=True, log=_quiet)
    assert result.training["xgboost_requested"] is True
    if importlib.util.find_spec("xgboost") is None:
        assert result.library == "scikit-learn" and result.format == "sklearn_joblib"
    else:  # pragma: no cover - depends on the environment
        assert result.library == "xgboost" and result.format == "xgboost_json"


def test_same_seed_same_split_and_predictions():
    table = _table()
    a = train_url_classifier(table.urls, table.labels, seed=3, log=_quiet)
    b = train_url_classifier(table.urls, table.labels, seed=3, log=_quiet)
    assert np.array_equal(a.eval_idx, b.eval_idx)
    x = featurize_array(a.urls)
    assert np.array_equal(a.model.predict(x), b.model.predict(x))
    c = train_url_classifier(table.urls, table.labels, seed=4, log=_quiet)
    assert not np.array_equal(a.eval_idx, c.eval_idx)


def test_save_and_reload(tmp_path: Path):
    table = _table()
    result = train_url_classifier(table.urls, table.labels, seed=0, log=_quiet)
    model_file, surrogate_file = save_url_classifier(result, tmp_path / "bundled" / "url", assets_root=tmp_path)
    for entry in (model_file, surrogate_file):
        path = tmp_path / entry.path
        assert path.exists() and path.stat().st_size == entry.size_bytes
    x = featurize_array(result.urls)
    reloaded = load_url_classifier(tmp_path / model_file.path, result.format)
    assert np.array_equal(reloaded.predict(x), result.model.predict(x))
    proba = reloaded.predict_proba(x)
    assert proba.shape == (len(result.urls), 4)
    assert np.allclose(proba.sum(axis=1), 1.0)
    import joblib

    surrogate = joblib.load(tmp_path / surrogate_file.path)
    assert surrogate.predict(x).shape == (len(result.urls),)


def test_build_url_asset_writes_manifest_entries(tmp_path: Path):
    entry, model = build_url_asset(_table(), model_id="url_trees", root=tmp_path, seed=0, log=_quiet)
    manifest = AssetManifest.new()
    manifest.datasets[entry.id] = entry
    manifest.models[model.id] = model
    write_manifest(manifest, tmp_path / MANIFEST_NAME)
    loaded = load_manifest(tmp_path / MANIFEST_NAME)
    assert verify_files(loaded, tmp_path) == []

    record = loaded.models["url_trees"]
    assert record.modality == "tabular" and record.epochs is None
    assert record.features is not None and len(record.features) == 16
    assert record.extractor_version == EXTRACTOR_VERSION
    assert record.surrogate is not None and record.surrogate.kind == SURROGATE_KIND
    assert record.surrogate.sha256 == record.surrogate.file.sha256
    agreement = record.surrogate.agreement_clean
    assert agreement.n == 12 and 0 <= agreement.n_correct <= 12 and agreement.accuracy == agreement.n_correct / 12
    assert record.fixture_only is True, "the committed sample must never build a demo target"
    assert "scikit-learn" in record.library_versions
    assert verify_manifest(loaded, tmp_path) == []

    # The written entry is a schema.MLModelManifest row with FeatureSpec features and a SurrogateInfo.
    raw_entry = json.loads((tmp_path / MANIFEST_NAME).read_text())["models"]["url_trees"]
    projected = MLModelManifest.model_validate(raw_entry)
    assert projected.modality == "tabular" and projected.format == "sklearn_joblib"
    assert projected.architecture_id == "sklearn_hist_gradient_boosting"
    assert raw_entry["file"]["path"] == "bundled/url_trees/model.joblib"
    assert raw_entry["surrogate"]["file"]["path"] == "bundled/url_trees/surrogate.joblib"
    assert projected.input_shape == [16] and projected.n_classes == 4
    assert projected.class_names == ["benign", "defacement", "phishing", "malware"]
    assert projected.features is not None and [f.name for f in projected.features] == list(FEATURE_NAMES)
    assert {f.name for f in projected.features if not f.perturbable} == {"has_ip_host", "is_shortener", "has_https",
                                                                          "suspicious_tld"}
    assert all(f.min is not None and f.max is not None for f in projected.features)
    assert projected.surrogate is not None and projected.surrogate.kind == SURROGATE_KIND
    assert projected.surrogate.sha256 == record.surrogate.file.sha256
    assert projected.surrogate.agreement_clean is not None and projected.surrogate.agreement_clean.n == 12
    assert projected.dataset_id == entry.id and projected.dataset_revision == entry.revision
    assert projected.dataset_split == "eval" == projected.clean_accuracy.split  # type: ignore[union-attr]
    assert projected.clean_accuracy.value == record.metrics["clean_accuracy"]  # type: ignore[union-attr]
    assert projected.clean_accuracy.n == 12  # type: ignore[union-attr]
    assert projected.status == "available" and projected.refusal_reason is None
    assert projected.gradients is False, "tree ensembles expose no loss gradient; PGD uses the surrogate"
    assert projected.bundled is True and projected.license == "CC0: Public Domain"
    assert projected.source_url is None, "the committed sample has no distribution page"
    assert projected.sha256 == record.file.sha256 and projected.size_bytes == record.file.size_bytes
    assert projected.manifest_sha256 == manifest_digest(projected) == record.manifest_sha256

    ds_record = loaded.datasets[entry.id]
    assert ds_record.revision == entry.source_files[0].sha256
    assert ds_record.splits["train"].n == 48 and ds_record.splits["eval"].n == 12
    assert ds_record.splits["eval"].per_class == {c: 3 for c in ds_record.class_names}
    assert ds_record.preprocessing["features"] == list(FEATURE_NAMES)
    eval_split = ds_record.splits["eval"]
    assert eval_split.file is not None and eval_split.file.path.endswith("/eval.npz")
    assert eval_split.rows_csv is not None and eval_split.rows_csv.path.endswith("/eval.csv")
    # The featurized slice is what the target loads (no featurization at load); the CSV lists the same rows.
    with np.load(tmp_path / eval_split.file.path, allow_pickle=False) as npz:
        assert npz["x"].shape == (12, 16) and npz["x"].dtype == np.float32
        assert np.array_equal(npz["indices"], result_eval_idx(entry, model, tmp_path))
        assert list(npz["feature_names"]) == list(FEATURE_NAMES) and str(npz["extractor_version"]) == EXTRACTOR_VERSION
        assert list(npz["class_names"]) == ["benign", "defacement", "phishing", "malware"]
        x_npz, y_npz = npz["x"], npz["y"]
    lines = (tmp_path / eval_split.rows_csv.path).read_text(encoding="utf-8").splitlines()
    assert lines[0] == "index,url,type" and len(lines) == 13
    rows = [line.split(",", 2) for line in lines[1:]]
    assert np.array_equal(featurize_array([r[1] for r in rows]).astype(np.float32), x_npz)
    assert [ds_record.class_names[int(k)] for k in y_npz] == [r[2] for r in rows]
    assert "eval.npz" in ds_record.preprocessing["eval_slice"]


def result_eval_idx(entry, model, root: Path) -> np.ndarray:
    """The eval row indices as written to the CSV beside the npz (the two must agree)."""
    csv_path = root / entry.splits["eval"].rows_csv.path
    return np.asarray([int(line.split(",", 1)[0]) for line in csv_path.read_text().splitlines()[1:]], dtype=np.int64)


def test_unknown_label_is_rejected():
    urls = [f"http://host{i}.example.test/" for i in range(16)]
    labels = ["benign", "defacement", "phishing", "spam"] * 4
    with pytest.raises(ValueError, match="unknown class label"):
        train_url_classifier(urls, labels, log=_quiet)


def test_training_and_prediction_make_no_network_call(monkeypatch: pytest.MonkeyPatch):
    def _boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted in the URL pipeline")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    table = _table()
    result = train_url_classifier(table.urls, table.labels, seed=0, log=_quiet)
    proba = result.model.predict_proba(featurize_array(table.urls))
    assert proba.shape == (len(table.urls), 4)
