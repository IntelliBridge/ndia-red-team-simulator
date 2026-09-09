"""``redsim ml build-assets`` options, the featurized eval slice and the ``--fixture`` build (G-ASSET1/3/5/13).

Everything runs on synthetic data in ``tmp_path``; the only model trained is the URL classifier on the
committed sample. Nothing here downloads, and no resnet18 is trained.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

pytest.importorskip("numpy")
pytest.importorskip("sklearn")
pytest.importorskip("torch")

import numpy as np

from redsim.ml.assets import ARCH_CHOICES, canonical_model_id
from redsim.ml.assets import datasets as ds
from redsim.ml.assets.build import (
    DEFAULT_FIXTURE_PATH,
    BuildOptions,
    build_assets,
    build_cifar10_fixture,
    build_url_asset,
    summarize,
    write_url_eval_slice,
)
from redsim.ml.assets.manifest import (
    MANIFEST_NAME,
    AssetManifest,
    DatasetEntry,
    FileEntry,
    SplitEntry,
    load_manifest,
    sha256_file,
    write_manifest,
)
from redsim.ml.datasets import DatasetUnavailable, cifar10
from redsim.ml.datasets.url_features import FEATURE_NAMES, featurize_array

pytestmark = pytest.mark.ml

SAMPLE = Path(__file__).parent / "fixtures" / "malicious_urls_sample.csv"


def _quiet(_: str) -> None:
    return None


# ---------------------------------------------------------------------------
# BuildOptions
# ---------------------------------------------------------------------------

def test_build_options_defaults_and_canonicalisation(tmp_path: Path):
    opts = BuildOptions(out=tmp_path)
    assert opts.prefer_xgboost is False, "sklearn_joblib is the default bundled tabular format"
    assert opts.arch == "small_cnn" and opts.build_models is True and opts.fixture is False
    assert opts.selected == {"image", "cifar10", "tabular"} and opts.cache_dir == tmp_path / "cache"
    assert opts.fixture_out == DEFAULT_FIXTURE_PATH and opts.fixture_sidecar is None
    assert BuildOptions(only=("url_classifier",)).only == ("url_trees",)
    assert BuildOptions(only=("url_classifier",)).selected == {"tabular"}
    assert BuildOptions(arch="smallcnn").arch == "small_cnn"
    assert BuildOptions(arch="resnet18").arch == "resnet18" and ARCH_CHOICES == ("small_cnn", "resnet18")
    assert BuildOptions(build_models=False, fixture=True).selected == set()
    assert canonical_model_id("url_classifier") == "url_trees" and canonical_model_id("vehicles_cnn") == "vehicles_cnn"
    with pytest.raises(ValueError, match="arch must be one of"):
        BuildOptions(arch="vgg_from_the_internet")
    with pytest.raises(ValueError, match="unknown model id"):
        BuildOptions(only=("nope",))
    with pytest.raises(ValueError, match="dataset must be one of"):
        BuildOptions(dataset="bogus")


# ---------------------------------------------------------------------------
# The featurized tabular eval slice
# ---------------------------------------------------------------------------

def test_write_url_eval_slice_writes_npz_and_csv_that_agree(tmp_path: Path):
    urls = [f"http://host{i}.example.test/p/{i}?q={i}" for i in range(10)]
    labels = np.asarray([0, 1, 2, 3] * 2 + [0, 1], dtype=np.int64)
    class_names = ["benign", "defacement", "phishing", "malware"]
    eval_idx = np.asarray([1, 4, 7, 9], dtype=np.int64)
    entry = DatasetEntry(id="local:t", source="local", revision="r1", class_names=class_names)
    npz_entry, csv_entry = write_url_eval_slice(urls, labels, eval_idx, class_names, tmp_path, entry)
    assert npz_entry.path.endswith("/eval.npz") and csv_entry.path.endswith("/eval.csv")
    assert sha256_file(tmp_path / npz_entry.path) == npz_entry.sha256
    assert sha256_file(tmp_path / csv_entry.path) == csv_entry.sha256
    with np.load(tmp_path / npz_entry.path, allow_pickle=False) as npz:
        assert npz["x"].dtype == np.float32 and npz["x"].shape == (4, len(FEATURE_NAMES))
        assert np.array_equal(npz["x"], featurize_array([urls[i] for i in eval_idx]).astype(np.float32))
        assert np.array_equal(npz["y"], labels[eval_idx]) and np.array_equal(npz["indices"], eval_idx)
        assert list(npz["feature_names"]) == list(FEATURE_NAMES) and list(npz["class_names"]) == class_names
    lines = (tmp_path / csv_entry.path).read_text().splitlines()
    assert lines[0] == "index,url,type" and [int(line.split(",")[0]) for line in lines[1:]] == eval_idx.tolist()
    assert [line.rsplit(",", 1)[1] for line in lines[1:]] == [class_names[int(labels[i])] for i in eval_idx]
    # A precomputed x_eval is written as is, and its shape is checked.
    x_eval = featurize_array([urls[i] for i in eval_idx])
    write_url_eval_slice(urls, labels, eval_idx, class_names, tmp_path, entry, x_eval=x_eval)
    with pytest.raises(ValueError, match="shape"):
        write_url_eval_slice(urls, labels, eval_idx, class_names, tmp_path, entry, x_eval=x_eval[:2])


# ---------------------------------------------------------------------------
# --fixture
# ---------------------------------------------------------------------------

def _bundled_cifar10_tree(root: Path, *, n_per_class: int = 20, seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    """An assets root holding a bundled CIFAR-10-shaped test split, as build-assets --dataset cifar10 leaves it."""
    x, y = cifar10.synthetic_test_split(seed=seed, n=n_per_class * 10)
    rel = "datasets/hf--uoft-cs--cifar10/rev0/test.npz"
    path = root / rel
    path.parent.mkdir(parents=True)
    np.savez_compressed(path, x=x, y=y, indices=np.arange(len(y)), class_names=np.asarray(cifar10.CLASS_NAMES))
    manifest = AssetManifest.new()
    manifest.datasets[cifar10.DATASET_ID] = DatasetEntry(
        id=cifar10.DATASET_ID, source="huggingface", revision="rev0abcdef", class_names=list(cifar10.CLASS_NAMES),
        fixture_only=True, splits={"test": SplitEntry(name="test", n=len(y), file=FileEntry(
            path=rel, sha256=sha256_file(path), size_bytes=path.stat().st_size))})
    write_manifest(manifest, root / MANIFEST_NAME)
    return x, y


def test_fixture_from_the_bundled_test_split(tmp_path: Path):
    root = tmp_path / "assets"
    x, y = _bundled_cifar10_tree(root)
    out = tmp_path / "fixtures" / cifar10.FIXTURE_NAME
    result = build_cifar10_fixture(out=out, assets_root=root, cache_dir=tmp_path / "cache", per_class=5, seed=0,
                                   log=_quiet)
    assert result.path == out and result.sidecar == out.parent / "MANIFEST.json"
    assert result.synthetic is False and result.source_kind == "bundled_split_npz"
    entry = result.entry
    assert entry["source_dataset_id"] == "hf:uoft-cs/cifar10" and entry["source_revision"] == "rev0abcdef"
    assert entry["source"]["path"] == "datasets/hf--uoft-cs--cifar10/rev0/test.npz" and "assets_root" not in entry["source"]
    assert entry["n_rows"] == 50 and entry["per_class"] == {c: 5 for c in cifar10.CLASS_NAMES}
    assert entry["n_source_rows"] == 200 and entry["shape"] == [50, 3, 32, 32] and entry["dtype"] == "uint8"
    idx = np.asarray(entry["source_row_indices"], dtype=np.int64)
    assert len(idx) == 50 and len(set(idx.tolist())) == 50 and np.array_equal(idx, np.sort(idx))
    assert entry["source_row_indices_sha256"] == ds.indices_sha256(idx)
    assert np.array_equal(idx, cifar10.fixture_indices(y, per_class=5, seed=0))
    assert entry["sampling"]["seed"] == 0 and entry["sampling"]["per_class"] == 5
    assert entry["sha256"] == sha256_file(out)
    fx, fy, fidx = cifar10.load_fixture_npz(out)
    assert np.array_equal(fx, x[idx]) and np.array_equal(fy, y[idx]) and np.array_equal(fidx, idx)
    assert cifar10.fixture_provenance(out) == {"dataset_id": "hf:uoft-cs/cifar10", "dataset_revision": "rev0abcdef"}
    sidecar = json.loads(result.sidecar.read_text())
    assert sidecar["files"][cifar10.FIXTURE_NAME] == entry and sidecar["schema_version"] == 1
    assert any("never a demo target" in note for note in entry["notes"])

    # A second fixture entry merges into an existing sidecar instead of replacing it.
    (out.parent / "other.csv").write_text("url,type\n")
    sidecar["files"]["other.csv"] = {"synthetic": True}
    result.sidecar.write_text(json.dumps(sidecar))
    build_cifar10_fixture(out=out, assets_root=root, cache_dir=None, per_class=5, seed=0, log=_quiet)
    merged = json.loads(result.sidecar.read_text())["files"]
    assert set(merged) == {cifar10.FIXTURE_NAME, "other.csv"}

    # A tampered bundled split is refused, never sampled from.
    split = root / "datasets/hf--uoft-cs--cifar10/rev0/test.npz"
    payload = bytearray(split.read_bytes())
    payload[-1] ^= 0xFF
    split.write_bytes(bytes(payload))
    with pytest.raises(DatasetUnavailable, match="tampered"):
        build_cifar10_fixture(out=out, assets_root=root, cache_dir=None, per_class=5, log=_quiet)


def _png(arr_hwc: np.ndarray) -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.fromarray(arr_hwc, "RGB").save(buf, format="PNG")
    return buf.getvalue()


def test_fixture_from_the_cached_hub_parquet(tmp_path: Path):
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    pytest.importorskip("PIL")
    cache = tmp_path / "cache"
    parquet = cache / "hf--uoft-cs--cifar10" / "deadbeef" / cifar10.TEST_PARQUET
    parquet.parent.mkdir(parents=True)
    rng = np.random.default_rng(0)
    imgs = rng.integers(0, 256, size=(40, 32, 32, 3), dtype=np.uint8)
    labels = [i % 10 for i in range(40)]
    table = pa.table({
        "img": pa.array([{"bytes": _png(im), "path": f"{i}.png"} for i, im in enumerate(imgs)],
                        type=pa.struct([("bytes", pa.binary()), ("path", pa.string())])),
        "label": pa.array(labels, type=pa.int64()),
    })
    pq.write_table(table, parquet)
    out = tmp_path / "fx" / cifar10.FIXTURE_NAME
    result = build_cifar10_fixture(out=out, assets_root=tmp_path / "no-assets", cache_dir=cache, per_class=2, log=_quiet)
    assert result.source_kind == "hub_parquet_cache" and result.synthetic is False
    assert result.entry["source_revision"] == "deadbeef" and result.entry["source"]["sha256"] == sha256_file(parquet)
    fx, fy, fidx = cifar10.load_fixture_npz(out)
    assert fx.shape == (20, 3, 32, 32) and np.bincount(fy, minlength=10).tolist() == [2] * 10
    assert np.array_equal(fx, imgs.transpose(0, 3, 1, 2)[fidx])


def test_fixture_without_a_local_split_refuses_unless_synthetic_is_allowed(tmp_path: Path):
    out = tmp_path / "fx" / cifar10.FIXTURE_NAME
    with pytest.raises(DatasetUnavailable, match="no local copy"):
        build_cifar10_fixture(out=out, assets_root=tmp_path / "none", cache_dir=tmp_path / "empty", log=_quiet)
    assert not out.exists()
    warnings: list[str] = []
    result = build_cifar10_fixture(out=out, assets_root=None, cache_dir=None, per_class=3, allow_synthetic=True,
                                   log=_quiet, warn=warnings.append)
    assert result.synthetic is True and result.source_kind == "synthetic"
    assert result.entry["source_dataset_id"] == cifar10.SYNTHETIC_DATASET_ID
    assert result.entry["source_revision"] == "synthetic-seed-0" and result.entry["n_rows"] == 30
    assert any("SYNTHETIC" in w for w in warnings) and any("Not CIFAR-10 data" in n for n in result.entry["notes"])
    assert cifar10.fixture_provenance(out)["dataset_id"] == cifar10.SYNTHETIC_DATASET_ID

    # A committed real draw is never overwritten by a synthetic one.
    sidecar = json.loads(result.sidecar.read_text())
    sidecar["files"][cifar10.FIXTURE_NAME]["synthetic"] = False
    result.sidecar.write_text(json.dumps(sidecar))
    with pytest.raises(DatasetUnavailable, match="refusing to overwrite"):
        build_cifar10_fixture(out=out, assets_root=None, cache_dir=None, allow_synthetic=True, log=_quiet)


# ---------------------------------------------------------------------------
# build_assets: legacy id replacement, fixture-only runs, summary
# ---------------------------------------------------------------------------

def test_build_assets_replaces_the_legacy_tabular_entry_and_writes_the_fixture(tmp_path: Path, no_kaggle: Path,
                                                                               monkeypatch):
    monkeypatch.setattr("redsim.ml.assets.build.inject_truststore", lambda: False)
    root = tmp_path / "assets"
    _bundled_cifar10_tree(root)
    # An earlier build left the tabular model under its old id.
    legacy_ds, legacy_model = build_url_asset(ds.sample_url_table(SAMPLE), model_id="url_classifier", root=root,
                                              seed=0, log=_quiet)
    manifest = load_manifest(root / MANIFEST_NAME)
    manifest.datasets[legacy_ds.id] = legacy_ds
    manifest.models["url_classifier"] = legacy_model
    write_manifest(manifest, root / MANIFEST_NAME)

    logs: list[str] = []
    fixture_out = tmp_path / "fixtures" / cifar10.FIXTURE_NAME
    result = build_assets(BuildOptions(dataset="tabular", out=root, fixture=True, fixture_out=fixture_out),
                          log=logs.append, warn=logs.append)
    assert set(result.models) == {"url_trees"}, "the legacy entry is replaced by the id the registry serves"
    assert any("legacy manifest entry 'url_classifier'" in line for line in logs)
    assert result.models["url_trees"].format == "sklearn_joblib" and result.models["url_trees"].fixture_only is True
    assert cifar10.DATASET_ID in result.datasets, "entries this run did not build are kept"
    assert fixture_out.exists() and (fixture_out.parent / "MANIFEST.json").exists()
    assert json.loads((fixture_out.parent / "MANIFEST.json").read_text())["files"][cifar10.FIXTURE_NAME]["n_rows"] == 200
    text = summarize(result)
    assert "url_trees: sklearn_joblib (sklearn_hist_gradient_boosting)" in text and "[fixture only]" in text

    # --fixture alone: no model built, manifest untouched, fixture rewritten from local files only.
    before = (root / MANIFEST_NAME).read_bytes()
    logs.clear()
    build_assets(BuildOptions(out=root, build_models=False, fixture=True, fixture_out=fixture_out), log=logs.append)
    assert (root / MANIFEST_NAME).read_bytes() == before
    assert any("no model selected" in line for line in logs) and any("bundled test split" in line for line in logs)


# ---------------------------------------------------------------------------
# Dataset caveats in the build and in a campaign on the built target (G-CAVEAT, G-EXP2)
# ---------------------------------------------------------------------------

def test_url_build_writes_the_lexical_feature_caveats(tmp_path: Path, no_kaggle: Path):
    from redsim.ml.assets.build import (
        FIXTURE_ONLY_CAVEAT,
        KAGGLE_URL_CAVEATS,
        URL_PIPELINE_CAVEATS,
        dataset_caveats,
    )
    from redsim.ml.schema import contains_banned_score_word

    entry, model = build_url_asset(ds.sample_url_table(SAMPLE), model_id="url_trees", root=tmp_path / "assets", seed=0,
                                   log=_quiet)
    assert entry.caveats == [*URL_PIPELINE_CAVEATS, FIXTURE_ONLY_CAVEAT]
    assert entry.caveats[0].startswith("URL strings are inert data") and "never fetches, resolves" in entry.caveats[0]
    assert entry.caveats[1].startswith("Realizability gap") and "lexical URL features" in entry.caveats[1]
    assert "no tabular row is presented as demonstrated URL evasion" in entry.caveats[1]
    assert entry.subject_centered is None and model.subject_centered is None       # no tabular meaning
    assert model.dataset_caveats == entry.caveats
    for text in (*URL_PIPELINE_CAVEATS, *KAGGLE_URL_CAVEATS):
        assert not contains_banned_score_word(text) and "readiness" not in text.lower(), text
    # The Kaggle file adds its own rows (label noise, age, imbalance, access) after the pipeline caveats.
    kaggle = DatasetEntry(id=f"kaggle:{ds.MALICIOUS_URLS_SLUG}", source="kaggle", revision="d" * 64,
                          class_names=list(ds.URL_CLASS_NAMES))
    full = dataset_caveats(kaggle, pipeline=URL_PIPELINE_CAVEATS)
    assert full == [*URL_PIPELINE_CAVEATS, *KAGGLE_URL_CAVEATS] and FIXTURE_ONLY_CAVEAT not in full
    # Written to disk, read back, and the model entry still verifies (the copy is outside the digest).
    manifest = AssetManifest.new()
    manifest.datasets[entry.id] = entry
    manifest.models[model.id] = model
    write_manifest(manifest, tmp_path / "assets" / MANIFEST_NAME)
    loaded = load_manifest(tmp_path / "assets" / MANIFEST_NAME)
    assert loaded.models["url_trees"].dataset_caveats == entry.caveats
    assert loaded.datasets[entry.id].caveats == entry.caveats
    from redsim.ml.assets.manifest import verify_manifest

    assert verify_manifest(loaded, tmp_path / "assets") == []
    assert "3 dataset caveat(s)" in summarize(loaded)


def test_build_assets_run_records_the_caveats_in_the_written_manifest(tmp_path: Path, no_kaggle: Path, monkeypatch):
    from redsim.ml.assets.build import FIXTURE_ONLY_CAVEAT, URL_PIPELINE_CAVEATS

    monkeypatch.setattr("redsim.ml.assets.build.inject_truststore", lambda: False)
    root = tmp_path / "assets"
    result = build_assets(BuildOptions(dataset="tabular", out=root), log=_quiet, warn=_quiet)
    raw = json.loads((root / MANIFEST_NAME).read_text())
    sample_id = "local:tests/ml/fixtures/malicious_urls_sample.csv"
    assert raw["datasets"][sample_id]["caveats"] == [*URL_PIPELINE_CAVEATS, FIXTURE_ONLY_CAVEAT]
    assert raw["datasets"][sample_id]["subject_centered"] is None
    assert raw["models"]["url_trees"]["dataset_caveats"] == raw["datasets"][sample_id]["caveats"]
    assert result.models["url_trees"].dataset_caveats == list(raw["models"]["url_trees"]["dataset_caveats"])


def _synthetic_images(n: int = 48, image_size: int = 8, seed: int = 0) -> ds.ImageDataset:
    class_names = ["class_0", "class_1", "class_2"]
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 256, size=(n, 3, image_size, image_size), dtype=np.uint8)
    y = (np.arange(n) % len(class_names)).astype(np.int64)
    entry = DatasetEntry(id="local:synthetic-images", source="local", revision="synthetic-v1", license="n/a",
                         class_names=class_names, fixture_only=True, notes=["unit-test double"])
    train = ds.ImageSplit(name="train", x=x, y=y, indices=np.arange(n, dtype=np.int64), class_names=class_names)
    n_eval = n // 2
    evaluation = ds.ImageSplit(name="test", x=x[:n_eval], y=y[:n_eval], indices=np.arange(n_eval, dtype=np.int64),
                               class_names=class_names)
    return ds.ImageDataset(dataset=entry, train=train, eval=evaluation)


def test_campaign_on_a_built_target_carries_the_dataset_caveats(tmp_path: Path, no_kaggle: Path, monkeypatch):
    """The round trip that closes G-CAVEAT / G-EXP2: build tiny assets with the real builder, load them through the
    registered targets and run a campaign; the limitations carry each build-time caveat as
    "Dataset caveat (<dataset id>): <text>" and the provenance manifest carries the subject_centered flag."""
    import sys

    pytest.importorskip("art")
    from redsim.ml.artifacts import FilesystemSink
    from redsim.ml.assets.build import FIXTURE_ONLY_CAVEAT, URL_PIPELINE_CAVEATS, build_cnn_asset
    from redsim.ml.campaign import D3_BOUNDS_LIMITATION, run_campaign
    from redsim.ml.schema import CampaignConfig
    from redsim.ml.targets import bundled
    from redsim.ml.targets.registry import get_target

    root = tmp_path / "assets"
    img_ds, img_model = build_cnn_asset(_synthetic_images(), model_id="vehicles_cnn", root=root, epochs=1, seed=0,
                                        subject_centered=False, log=_quiet)
    url_ds, url_model = build_url_asset(ds.sample_url_table(SAMPLE), model_id="url_trees", root=root, seed=0,
                                        log=_quiet)
    manifest = AssetManifest.new()
    manifest.datasets[img_ds.id] = img_ds
    manifest.datasets[url_ds.id] = url_ds
    manifest.models[img_model.id] = img_model
    manifest.models[url_model.id] = url_model
    write_manifest(manifest, root / MANIFEST_NAME)

    monkeypatch.setenv(bundled.ASSETS_DIR_ENV, str(root))
    monkeypatch.setitem(sys.modules, "redsim.ml.recommend.rules", None)      # the rule layer is not under test
    for target_id in ("vehicles_cnn", "url_trees"):
        get_target(target_id).unload()
    try:
        image_cfg = CampaignConfig(target_id="vehicles_cnn", modality="image", attack_ids=["fgsm"], eps_grid=[0.03],
                                   reference_eps=0.03, n_samples=12, seed=0, explain_k=0,
                                   dataset_id="local:synthetic-images")
        rec = run_campaign(image_cfg, FilesystemSink(tmp_path / "run-image"), explain=False)
        assert rec.status == "succeeded" and rec.target.id == "vehicles_cnn"
        assert f"Dataset caveat (local:synthetic-images): {FIXTURE_ONLY_CAVEAT}" in rec.limitations
        assert D3_BOUNDS_LIMITATION in rec.limitations
        assert rec.provenance.model_manifest["subject_centered"] is False
        assert rec.provenance.model_manifest["dataset_caveats"] == [FIXTURE_ONLY_CAVEAT]
        assert rec.provenance.dataset == "local:synthetic-images" and rec.provenance.dataset_revision == "synthetic-v1"

        tabular_cfg = CampaignConfig(target_id="url_trees", modality="tabular", attack_ids=["pgd"],
                                     attack_params={"pgd": {"max_iter": 2}}, eps_grid=[0.03], reference_eps=0.03,
                                     n_samples=12, seed=0, explain_k=0, dataset_split="eval",
                                     dataset_id="local:tests/ml/fixtures/malicious_urls_sample.csv")
        trec = run_campaign(tabular_cfg, FilesystemSink(tmp_path / "run-tabular"), explain=False)
        assert trec.status == "succeeded" and trec.target.domain == "tabular"
        prefix = "Dataset caveat (local:tests/ml/fixtures/malicious_urls_sample.csv): "
        for text in (*URL_PIPELINE_CAVEATS, FIXTURE_ONLY_CAVEAT):
            assert f"{prefix}{text}" in trec.limitations
        assert trec.provenance.model_manifest["subject_centered"] is None
        assert trec.provenance.model_manifest["dataset_caveats"] == [*URL_PIPELINE_CAVEATS, FIXTURE_ONLY_CAVEAT]
        assert not any(lim.startswith("Dataset caveat (local:synthetic-images)") for lim in trec.limitations)
    finally:
        for target_id in ("vehicles_cnn", "url_trees"):
            get_target(target_id).unload()
