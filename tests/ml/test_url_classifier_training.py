"""The bundled URL classifier trains on the committed sample without Kaggle or the network (spec 11.3.3, M4).

ml tier: needs scikit-learn and numpy. No test here contacts Kaggle.
"""

from __future__ import annotations

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
    verify_files,
    write_manifest,
)
from redsim.ml.assets.train_url_classifier import (
    SURROGATE_KIND,
    load_url_classifier,
    save_url_classifier,
    train_url_classifier,
)
from redsim.ml.datasets.url_features import EXTRACTOR_VERSION, FEATURE_NAMES, featurize_array

SAMPLE = Path(__file__).parent / "fixtures" / "malicious_urls_sample.csv"


def _quiet(_: str) -> None:
    return None


def _table() -> ds.UrlTable:
    return ds.sample_url_table(SAMPLE)


def test_trains_on_committed_sample():
    table = _table()
    assert table.dataset.fixture_only is True
    assert table.dataset.class_names == ["benign", "defacement", "phishing", "malware"]
    result = train_url_classifier(table.urls, table.labels, seed=0, log=_quiet)
    assert result.library in {"scikit-learn", "xgboost"}
    assert result.format in {"sklearn_joblib", "xgboost_json"}
    assert result.n_duplicates_removed == 0
    assert len(result.train_idx) + len(result.eval_idx) == len(table.urls)
    assert not set(result.train_idx.tolist()) & set(result.eval_idx.tolist())
    assert result.metrics["n"] == len(result.eval_idx) == 12  # 4 classes x 3 held out at 20 %
    assert 0.0 <= result.metrics["clean_accuracy"] <= 1.0
    assert sum(c["n"] for c in result.metrics["per_class"].values()) == result.metrics["n"]
    assert [f.name for f in result.features] == list(FEATURE_NAMES)
    assert all(f.min is not None and f.max is not None and f.min <= f.max for f in result.features)
    assert 0.0 <= result.surrogate_agreement <= 1.0
    assert result.training["extractor_version"] == EXTRACTOR_VERSION
    assert result.training["surrogate"]["kind"] == SURROGATE_KIND


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
    entry, model = build_url_asset(_table(), model_id="url_classifier", root=tmp_path, seed=0, log=_quiet)
    manifest = AssetManifest.new()
    manifest.datasets[entry.id] = entry
    manifest.models[model.id] = model
    write_manifest(manifest, tmp_path / MANIFEST_NAME)
    loaded = load_manifest(tmp_path / MANIFEST_NAME)
    assert verify_files(loaded, tmp_path) == []

    record = loaded.models["url_classifier"]
    assert record.modality == "tabular" and record.epochs is None
    assert record.features is not None and len(record.features) == 16
    assert record.extractor_version == EXTRACTOR_VERSION
    assert record.surrogate is not None and 0.0 <= record.surrogate.agreement_eval <= 1.0
    assert record.surrogate.n_eval == 12
    assert record.fixture_only is True, "the committed sample must never build a demo target"
    assert "scikit-learn" in record.library_versions

    ds_record = loaded.datasets[entry.id]
    assert ds_record.revision == entry.source_files[0].sha256
    assert ds_record.splits["train"].n == 48 and ds_record.splits["eval"].n == 12
    assert ds_record.splits["eval"].per_class == {c: 3 for c in ds_record.class_names}
    assert ds_record.preprocessing["features"] == list(FEATURE_NAMES)
    eval_csv = tmp_path / ds_record.splits["eval"].file.path  # type: ignore[union-attr]
    lines = eval_csv.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "index,url,type" and len(lines) == 13


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
