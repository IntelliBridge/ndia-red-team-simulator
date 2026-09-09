"""``MANIFEST.json`` round-trips, its model entries are ``schema.MLModelManifest`` rows, and a one-epoch
``SmallCNN`` build yields hash-verifiable weights.

ml tier: needs torch. Everything runs on 64 synthetic images in ``tmp_path``;
no dataset download and no network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import get_args

import pytest

pytestmark = pytest.mark.ml
torch = pytest.importorskip("torch")
np = pytest.importorskip("numpy")

from redsim.ml.assets import datasets as ds
from redsim.ml.assets.build import build_cnn_asset, summarize
from redsim.ml.assets.manifest import (
    MANIFEST_NAME,
    AssetManifest,
    DatasetEntry,
    DatasetSource,
    FileEntry,
    ModelEntry,
    load_manifest,
    manifest_digest,
    model_manifest,
    sha256_bytes,
    sha256_file,
    stamp_manifest_sha256,
    verify_entries,
    verify_files,
    verify_manifest,
    verify_model_assets,
    write_manifest,
)
from redsim.ml.assets.train_cnn import load_small_cnn, predict_logits
from redsim.ml.schema import CleanAccuracy, MLModelManifest
from redsim.ml.targets import architectures
from redsim.ml.targets.architectures import (
    ARCHITECTURE_ALIASES,
    ARCHITECTURES,
    CatalogModule,
    ResNet18,
    SmallCNN,
    UnknownArchitecture,
    architecture_ids,
    build_architecture,
    canonical_architecture_id,
)


def _quiet(_: str) -> None:
    return None


def _entry(fake: FileEntry, **over) -> ModelEntry:
    base: dict = {
        "id": "x", "name": "Example CNN", "modality": "image", "format": "torch_state_dict", "sha256": fake.sha256,
        "size_bytes": fake.size_bytes, "architecture_id": "small_cnn", "input_shape": [3, 8, 8], "n_classes": 2,
        "class_names": ["a", "b"], "file": fake, "dataset_id": "hf:example/ds", "dataset_revision": "abc123",
        "dataset_split": "test", "train_split": "train", "seed": 0, "epochs": 3, "gradients": True,
        "clean_accuracy": CleanAccuracy(value=0.5, n=2, split="test"), "metrics": {"clean_accuracy": 0.5, "n": 2},
    }
    base.update(over)
    return ModelEntry(**base)


def _synthetic_images(n: int = 64, image_size: int = 16, n_classes: int = 4, seed: int = 0) -> ds.ImageDataset:
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 256, size=(n, 3, image_size, image_size), dtype=np.uint8)
    y = (np.arange(n) % n_classes).astype(np.int64)
    names = [f"class_{i}" for i in range(n_classes)]
    entry = DatasetEntry(id="local:synthetic-images", source="local", revision="synthetic-v1", license="n/a",
                         class_names=names, fixture_only=True, notes=["unit-test double"])
    train = ds.ImageSplit(name="train", x=x, y=y, indices=np.arange(n, dtype=np.int64), class_names=names)
    n_eval = n // 2
    evaluation = ds.ImageSplit(name="test", x=x[:n_eval], y=y[:n_eval], indices=np.arange(n_eval, dtype=np.int64),
                               class_names=names)
    return ds.ImageDataset(dataset=entry, train=train, eval=evaluation)


# ---------------------------------------------------------------------------
# SmallCNN contract
# ---------------------------------------------------------------------------

def test_small_cnn_default_signature_and_shapes():
    model = SmallCNN()
    assert (model.in_channels, model.n_classes, model.image_size) == (3, 10, 32)
    assert model.architecture_id == "small_cnn" and ARCHITECTURES["small_cnn"] is SmallCNN
    model.eval()
    with torch.no_grad():
        assert model(torch.rand(2, 3, 32, 32)).shape == (2, 10)
    big = SmallCNN(in_channels=3, n_classes=7, image_size=128).eval()
    with torch.no_grad():
        assert big(torch.rand(1, 3, 128, 128)).shape == (1, 7)
    assert big.input_shape == (3, 128, 128)
    assert big.architecture_config() == {"architecture_id": "small_cnn", "in_channels": 3, "n_classes": 7,
                                         "image_size": 128}
    assert "input_mean" in big.state_dict() and "input_std" in big.state_dict()


def test_small_cnn_is_deterministic_under_manual_seed():
    torch.manual_seed(1234)
    a = SmallCNN(3, 4, 16)
    torch.manual_seed(1234)
    b = SmallCNN(3, 4, 16)
    for key, value in a.state_dict().items():
        assert torch.equal(value, b.state_dict()[key]), key
    x = torch.rand(5, 3, 16, 16)
    a.eval()
    b.eval()
    with torch.no_grad():
        assert torch.equal(a(x), b(x))


def test_architecture_catalog_refuses_unknown_ids_and_bad_args():
    assert isinstance(build_architecture("small_cnn", n_classes=3), SmallCNN)
    with pytest.raises(UnknownArchitecture):
        build_architecture("resnet_from_upload")
    # The alias resolves; the builder's architecture block (with its architecture_id key) is accepted as kwargs.
    assert ARCHITECTURE_ALIASES == {"smallcnn": "small_cnn"} and canonical_architecture_id("smallcnn") == "small_cnn"
    assert architecture_ids() == ["resnet18", "small_cnn"]
    assert architecture_ids(include_aliases=True) == ["resnet18", "small_cnn", "smallcnn"]
    assert isinstance(build_architecture("smallcnn", n_classes=3), SmallCNN)
    block = SmallCNN(3, 4, 16).architecture_config()
    rebuilt = build_architecture(block["architecture_id"], **block)
    assert isinstance(rebuilt, SmallCNN) and rebuilt.architecture_config() == block
    with pytest.raises(UnknownArchitecture, match="declares"):
        build_architecture("resnet18", **block)
    with pytest.raises(ValueError):
        SmallCNN(n_classes=1)
    with pytest.raises(ValueError):
        SmallCNN(image_size=4)
    with pytest.raises(ValueError):
        SmallCNN().set_input_normalization(torch.zeros(3), torch.zeros(3))


def test_resnet18_is_a_catalog_architecture_with_offline_init(tmp_path: Path, monkeypatch):
    """resnet18 adapts torchvision's backbone to the class count; ImageNet weights only from the local cache."""
    pytest.importorskip("torchvision")
    assert ARCHITECTURES["resnet18"] is ResNet18 and issubclass(ResNet18, CatalogModule)
    monkeypatch.setattr(architectures, "imagenet_resnet18_checkpoint", lambda: None)
    model = build_architecture("resnet18", n_classes=3, image_size=8)
    assert isinstance(model, ResNet18) and model.input_shape == (3, 8, 8)
    assert model.architecture_config() == {"architecture_id": "resnet18", "in_channels": 3, "n_classes": 3,
                                           "image_size": 8}
    assert "pretrained" not in model.architecture_config(), "init is a build record, not a constructor argument"
    loaded, note = model.init_imagenet_backbone()
    assert loaded is False and note.startswith("random init") and model.backbone_init == "random"
    model.eval()
    with torch.no_grad():
        assert model(torch.rand(2, 3, 8, 8)).shape == (2, 3)          # 8x8 inputs run through the adaptive pool
    assert "input_mean" in model.state_dict() and model.state_dict()["backbone.fc.weight"].shape == (3, 512)
    with pytest.raises(ValueError):
        ResNet18(n_classes=1)

    # A cached checkpoint (here: a locally written random resnet18 state_dict, never a download) is loaded
    # into the backbone only; the head keeps the task's class count.
    from torchvision.models import resnet18

    fake = tmp_path / architectures.RESNET18_IMAGENET_FILENAME
    torch.save(resnet18(weights=None, num_classes=1000).state_dict(), fake)
    monkeypatch.setattr(architectures, "imagenet_resnet18_checkpoint", lambda: fake)
    pretrained = ResNet18(n_classes=3, image_size=8)
    loaded, note = pretrained.init_imagenet_backbone()
    assert loaded is True and "imagenet1k_v1" in note and str(fake) in note
    assert pretrained.backbone.fc.out_features == 3
    two_channel = ResNet18(in_channels=2, n_classes=3, image_size=8)
    assert two_channel.init_imagenet_backbone()[0] is False           # ImageNet weights need 3 channels

    # The build helper records which initialisation was used, without training anything here.
    from redsim.ml.assets.train_cnn import build_image_model

    monkeypatch.setattr(architectures, "imagenet_resnet18_checkpoint", lambda: None)
    built, init = build_image_model("resnet18", in_channels=3, n_classes=3, image_size=8, log=_quiet)
    assert isinstance(built, ResNet18) and init["imagenet_backbone_loaded"] is False
    assert init["backbone_init"].startswith("random init")
    small, init_small = build_image_model("smallcnn", in_channels=3, n_classes=3, image_size=8, log=_quiet)
    assert isinstance(small, SmallCNN) and init_small == {"backbone_init": "random (seeded)"}


# ---------------------------------------------------------------------------
# Manifest schema
# ---------------------------------------------------------------------------

def test_manifest_round_trip_and_sorted_keys(tmp_path: Path):
    manifest = AssetManifest.new()
    fake = FileEntry(path="bundled/x/weights.pt", sha256=sha256_bytes(b"weights"), size_bytes=7)
    manifest.datasets["hf:example/ds"] = DatasetEntry(id="hf:example/ds", source="huggingface", revision="abc123",
                                                       license="mit", class_names=["a", "b"])
    manifest.models["x"] = stamp_manifest_sha256(_entry(fake))
    path = tmp_path / MANIFEST_NAME
    write_manifest(manifest, path)
    loaded = load_manifest(path)
    assert loaded == manifest
    raw = json.loads(path.read_text())
    assert list(raw) == sorted(raw)
    assert raw["schema_version"] == 1 and raw["builder"] == "redsim ml build-assets"
    assert "torch" in raw["library_versions"]
    # unknown keys are ignored on read, not rejected
    raw["future_field"] = {"x": 1}
    path.write_text(json.dumps(raw))
    assert load_manifest(path) == manifest


def test_file_entry_requires_a_real_sha256():
    with pytest.raises(ValueError):
        FileEntry(path="x", sha256="nothex", size_bytes=1)


def test_model_entry_is_an_ml_model_manifest():
    fake = FileEntry(path="bundled/x/weights.pt", sha256=sha256_bytes(b"weights"), size_bytes=7)
    entry = stamp_manifest_sha256(_entry(fake))
    assert isinstance(entry, MLModelManifest)
    # The on-disk shape (a JSON dump) validates as the frozen schema; build-only keys are ignored.
    raw = json.loads(json.dumps(entry.model_dump(mode="json")))
    projected = MLModelManifest.model_validate(raw)
    assert projected == model_manifest(entry)
    assert projected.status == "available" and projected.bundled is True and projected.refusal_reason is None
    assert projected.sha256 == fake.sha256 and projected.size_bytes == 7
    assert not hasattr(projected, "file") and not hasattr(projected, "train_split")
    # manifest_sha256 is the digest of the projection and can be recomputed from the projection alone.
    assert entry.manifest_sha256 == manifest_digest(entry) == manifest_digest(projected)
    assert manifest_digest(_entry(fake, class_names=["b", "a"])) != entry.manifest_sha256
    assert manifest_digest(_entry(fake, notes=["build-only"])) == entry.manifest_sha256

    manifest = AssetManifest.new()
    manifest.models["x"] = entry
    assert verify_entries(manifest) == []
    manifest.models["x"] = _entry(fake)                     # not stamped
    assert any("manifest_sha256 mismatch" in p for p in verify_entries(manifest))


def test_dataset_source_admits_the_phase_b_origins():
    """``uci`` (the SMS Spam Collection) and ``github`` (the nltk_data WordNet zip) joined the literal in Phase B."""
    assert get_args(DatasetSource) == ("huggingface", "kaggle", "uci", "github", "local")
    for source, ident in (("uci", "uci:sms-spam-collection"), ("github", "nltk_data:wordnet"), ("local", "local:x")):
        assert DatasetEntry(id=ident, source=source).source == source
    with pytest.raises(ValueError):
        DatasetEntry(id="x", source="bittorrent")
    # The B0 fetchers asked for these members tolerantly; they now record the real origin, and the fallback
    # note that explained the ``local`` stand-in is gone.
    assert ds.dataset_source("uci") == "uci" and ds.dataset_source("github") == "github"
    assert ds.dataset_source("bittorrent") == "local"
    assert ds._source_fallback_note("uci") == [] and ds._source_fallback_note("github") == []


P0_PROJECTION_KEYS = {
    "architecture_id", "bundled", "class_names", "clean_accuracy", "dataset_id", "dataset_revision", "dataset_split",
    "features", "format", "gradients", "input_shape", "license", "modality", "n_classes", "name", "refusal_reason",
    "sha256", "size_bytes", "source_url", "status", "surrogate",
}


def test_legacy_entry_keeps_its_digest_without_the_phase_b_blocks():
    """MODALITIES-05: a manifest written before ``text`` / ``detection`` / ``endpoint`` / ``derived_from`` existed
    reads back with the same ``manifest_sha256``, so every asset tree built by P0 still verifies."""
    fake = FileEntry(path="bundled/x/weights.pt", sha256=sha256_bytes(b"weights"), size_bytes=7)
    entry = stamp_manifest_sha256(_entry(fake))
    raw = json.loads(json.dumps(entry.model_dump(mode="json")))
    for block in ("text", "detection", "endpoint", "derived_from"):
        assert block not in raw, f"an absent {block} block is dropped from the written entry, not written as null"
    # The P0-era row: no block keys and no Phase B build-record field at all.
    legacy = {k: v for k, v in raw.items() if k != "train_slice_split"}
    loaded = ModelEntry.model_validate(legacy)
    assert loaded.manifest_sha256 == entry.manifest_sha256 == manifest_digest(loaded)
    assert loaded.text is None and loaded.detection is None and loaded.endpoint is None and loaded.derived_from is None
    assert loaded.train_slice_split is None
    manifest = AssetManifest.new()
    manifest.models["x"] = loaded
    assert verify_entries(manifest) == []
    # The digest is a function of the P0 projection keys alone ...
    projection = model_manifest(loaded).model_dump(mode="json", exclude={"manifest_sha256"})
    assert set(projection) == P0_PROJECTION_KEYS
    # ... so the Phase B build-record field never moves it ...
    assert manifest_digest(loaded.model_copy(update={"train_slice_split": "train_slice"})) == loaded.manifest_sha256
    # ... while a block that is present is part of what the model declares and enters the digest, round-tripping.
    declared = stamp_manifest_sha256(_entry(fake, detection={"input_size": [8, 8], "classes": ["a", "b"]}))
    assert declared.manifest_sha256 != entry.manifest_sha256
    reread = ModelEntry.model_validate(json.loads(json.dumps(declared.model_dump(mode="json"))))
    assert reread.detection is not None and reread.detection.classes == ["a", "b"]
    assert reread.detection.box_format == "xyxy" and reread.manifest_sha256 == manifest_digest(reread)
    manifest.models["declared"] = reread
    assert verify_entries(manifest) == []


def test_model_entry_refuses_inconsistent_records():
    fake = FileEntry(path="bundled/x/weights.pt", sha256=sha256_bytes(b"weights"), size_bytes=7)
    with pytest.raises(ValueError, match="sha256 and size_bytes"):
        _entry(fake, sha256=sha256_bytes(b"other"))
    with pytest.raises(ValueError, match="clean accuracy"):
        _entry(fake, clean_accuracy=None)
    with pytest.raises(ValueError, match="clean_accuracy.split"):
        _entry(fake, dataset_split="eval")
    # The frozen schema's own checks still run on the subclass.
    with pytest.raises(ValueError, match="class_names length"):
        _entry(fake, n_classes=3)
    with pytest.raises(ValueError, match="refusal_reason"):
        _entry(fake, status="refused")
    with pytest.raises(ValueError, match="architecture_id"):
        _entry(fake, architecture_id=None)


# ---------------------------------------------------------------------------
# One-epoch build on synthetic images
# ---------------------------------------------------------------------------

def test_one_epoch_build_yields_manifest_and_hash_verifiable_weights(tmp_path: Path):
    data = _synthetic_images()
    root = tmp_path / "assets"
    entry, model = build_cnn_asset(data, model_id="synthetic_cnn", root=root, epochs=1, seed=0,
                                   fixture_only=True, notes=["capped"], log=_quiet)
    manifest = AssetManifest.new()
    manifest.datasets[entry.id] = entry
    manifest.models[model.id] = model
    write_manifest(manifest, root / MANIFEST_NAME)

    loaded = load_manifest(root / MANIFEST_NAME)
    record = loaded.models["synthetic_cnn"]
    weights = root / record.file.path
    assert weights.exists()
    assert sha256_file(weights) == record.file.sha256
    assert weights.stat().st_size == record.file.size_bytes
    assert verify_files(loaded, root) == []
    assert verify_manifest(loaded, root) == []

    # The written entry is a schema.MLModelManifest row.
    raw_entry = json.loads((root / MANIFEST_NAME).read_text())["models"]["synthetic_cnn"]
    projected = MLModelManifest.model_validate(raw_entry)
    assert projected.name == "synthetic_cnn" and projected.modality == "image"
    assert projected.format == "torch_state_dict" and projected.architecture_id == "small_cnn"
    assert projected.input_shape == [3, 16, 16] and projected.n_classes == 4
    assert projected.class_names == [f"class_{i}" for i in range(4)]
    assert projected.features is None and projected.surrogate is None
    assert projected.dataset_id == "local:synthetic-images" and projected.dataset_revision == "synthetic-v1"
    assert projected.dataset_split == "test"
    assert projected.clean_accuracy is not None
    assert projected.clean_accuracy.value == record.metrics["clean_accuracy"]
    assert projected.clean_accuracy.n == 32 and projected.clean_accuracy.split == "test"
    assert projected.status == "available" and projected.refusal_reason is None
    assert projected.gradients is True and projected.bundled is True
    assert projected.license == "n/a" and projected.source_url is None
    assert projected.sha256 == record.file.sha256 == sha256_file(weights)
    assert projected.size_bytes == weights.stat().st_size
    assert projected.manifest_sha256 == manifest_digest(projected) == record.manifest_sha256

    assert record.architecture == {"architecture_id": "small_cnn", "in_channels": 3, "n_classes": 4, "image_size": 16}
    assert record.epochs == 1 and record.seed == 0 and record.fixture_only is True
    assert record.metrics["n"] == 32
    assert 0.0 <= record.metrics["clean_accuracy"] <= 1.0
    assert sum(c["n"] for c in record.metrics["per_class"].values()) == 32
    assert sum(c["n_correct"] for c in record.metrics["per_class"].values()) == record.metrics["n_correct"]
    assert len(record.metrics["history"]) == 1
    assert len(record.training["input_mean"]) == 3 and record.training["n_train"] == 64
    assert "torch" in record.library_versions

    ds_record = loaded.datasets["local:synthetic-images"]
    assert ds_record.splits["train"].n == 64 and ds_record.splits["test"].n == 32
    assert ds_record.splits["test"].per_class == {f"class_{i}": 8 for i in range(4)}
    assert ds_record.splits["test"].file is not None
    assert "capped" in ds_record.notes
    slice_npz = np.load(root / ds_record.splits["test"].file.path, allow_pickle=False)
    assert slice_npz["x"].shape == (32, 3, 16, 16) and slice_npz["x"].dtype == np.uint8
    assert list(slice_npz["class_names"]) == [f"class_{i}" for i in range(4)]

    # ATTACKS_HARDEN-11: the bundled training slice, drawn from the training split, is a split of the dataset
    # named by the model entry (outside the digest), digest-checked with every other bundled file, and reads
    # back as an ImageSplit for the training defenses. 64 rows are fewer than the 1536 requested, so all of them.
    assert record.train_slice_split == "train_slice"
    train_slice = ds_record.splits["train_slice"]
    assert train_slice.n == 64 and train_slice.seed == 0 and train_slice.file is not None
    assert train_slice.file.path == "bundled/synthetic_cnn/train_slice.npz"
    assert train_slice.per_class == {f"class_{i}": 16 for i in range(4)}
    assert train_slice.indices_sha256 == ds.indices_sha256(np.arange(64))
    reloaded_slice = ds.load_train_slice(root / train_slice.file.path, expected_sha256=train_slice.file.sha256)
    assert reloaded_slice.name == "train_slice" and reloaded_slice.x.shape == (64, 3, 16, 16)
    assert np.array_equal(reloaded_slice.y, data.train.y) and reloaded_slice.class_names == data.train.class_names
    sidecar = ds.read_train_slice_sidecar(root / "bundled" / "synthetic_cnn" / ds.TRAIN_SLICE_SIDECAR_NAME)
    assert sidecar.model_id == "synthetic_cnn" and sidecar.dataset_id == ds_record.id and sidecar.source_split == "train"
    assert sidecar.split_entry == train_slice and sidecar.n_requested == ds.DEFAULT_TRAIN_SLICE_N and sidecar.seed == 0
    assert record.manifest_sha256 == manifest_digest(record.model_copy(update={"train_slice_split": None}))
    assert not verify_model_assets(loaded, root, "synthetic_cnn")
    assert "train slice train_slice" in summarize(loaded)

    # The weights reload into a fresh SmallCNN (tensors only) and reproduce the recorded accuracy.
    kwargs = {k: v for k, v in record.architecture.items() if k != "architecture_id"}
    reloaded = load_small_cnn(weights, **kwargs)
    preds = predict_logits(reloaded, data.eval.x).argmax(axis=1)
    assert float((preds == data.eval.y).mean()) == pytest.approx(record.metrics["clean_accuracy"])

    text = summarize(loaded)
    assert "synthetic_cnn" in text and "[fixture only]" in text

    # A single flipped byte is caught by the hash check.
    payload = bytearray(weights.read_bytes())
    payload[-1] ^= 0xFF
    weights.write_bytes(bytes(payload))
    problems = verify_files(loaded, root)
    assert len(problems) == 1 and "sha256 mismatch" in problems[0] and record.file.path in problems[0]
    assert verify_manifest(loaded, root) == problems
    # ... and so is a tampered training slice, reported on the dataset side of the model's verification.
    slice_path = root / train_slice.file.path
    slice_bytes = bytearray(slice_path.read_bytes())
    slice_bytes[-1] ^= 0xFF
    slice_path.write_bytes(bytes(slice_bytes))
    model_problems = verify_model_assets(loaded, root, "synthetic_cnn")
    assert any("train_slice" in p and "sha256 mismatch" in p for p in model_problems.dataset)
    with pytest.raises(ds.DatasetUnavailable, match="does not match"):
        ds.load_train_slice(slice_path, expected_sha256=train_slice.file.sha256)
    weights.unlink()
    assert any("missing file" in p for p in verify_files(loaded, root))

    # An edited entry (class names swapped) no longer matches its manifest_sha256.
    edited = json.loads((root / MANIFEST_NAME).read_text())
    edited["models"]["synthetic_cnn"]["class_names"] = ["class_1", "class_0", "class_2", "class_3"]
    (root / MANIFEST_NAME).write_text(json.dumps(edited))
    assert any("manifest_sha256 mismatch" in p for p in verify_entries(load_manifest(root / MANIFEST_NAME)))


def test_build_without_a_train_slice_records_none(tmp_path: Path):
    data = _synthetic_images(n=16, image_size=8, n_classes=2)
    root = tmp_path / "assets"
    entry, model = build_cnn_asset(data, model_id="synthetic_cnn", root=root, epochs=1, seed=0, fixture_only=True,
                                   train_slice=ds.TrainSliceOptions(enabled=False), log=_quiet)
    assert model.train_slice_split is None and "train_slice" not in entry.splits
    assert not (root / "bundled" / "synthetic_cnn" / ds.TRAIN_SLICE_NAME).exists()
    assert not (root / "bundled" / "synthetic_cnn" / ds.TRAIN_SLICE_SIDECAR_NAME).exists()
    # An explicit size caps the draw, stratified over the classes and seeded.
    entry2, model2 = build_cnn_asset(data, model_id="synthetic_cnn", root=tmp_path / "assets2", epochs=1, seed=0,
                                     fixture_only=True, train_slice=ds.TrainSliceOptions(n=6, seed=3), log=_quiet)
    assert model2.train_slice_split == "train_slice"
    drawn = entry2.splits["train_slice"]
    assert drawn.n == 6 and drawn.seed == 3 and drawn.per_class == {"class_0": 3, "class_1": 3}
    with pytest.raises(ValueError, match="train slice n"):
        ds.TrainSliceOptions(n=0)


def test_split_entry_carries_the_rows_csv_beside_the_slice_and_scoped_verification(tmp_path: Path):
    from redsim.ml.assets.manifest import SplitEntry, model_entry, verify_model_assets

    root = tmp_path / "assets"
    root.mkdir()
    npz, csv_file = root / "datasets/d/eval.npz", root / "datasets/d/eval.csv"
    npz.parent.mkdir(parents=True)
    npz.write_bytes(b"npz-bytes")
    csv_file.write_bytes(b"index,url,type\n")
    weights = root / "bundled/x/weights.pt"
    weights.parent.mkdir(parents=True)
    weights.write_bytes(b"weights")
    fake = FileEntry(path="bundled/x/weights.pt", sha256=sha256_file(weights), size_bytes=7)
    manifest = AssetManifest.new()
    manifest.datasets["hf:example/ds"] = DatasetEntry(
        id="hf:example/ds", source="huggingface", revision="abc123", class_names=["a", "b"],
        splits={"test": SplitEntry(name="test", n=2, file=FileEntry(path="datasets/d/eval.npz",
                                                                     sha256=sha256_file(npz), size_bytes=9),
                                   rows_csv=FileEntry(path="datasets/d/eval.csv", sha256=sha256_file(csv_file),
                                                      size_bytes=15))})
    manifest.models["x"] = stamp_manifest_sha256(_entry(fake))
    write_manifest(manifest, root / MANIFEST_NAME)
    loaded = load_manifest(root / MANIFEST_NAME)
    assert loaded.datasets["hf:example/ds"].splits["test"].rows_csv is not None
    assert verify_manifest(loaded, root) == []
    assert not verify_model_assets(loaded, root, "x")
    assert model_entry(loaded, "x") is loaded.models["x"] and model_entry(loaded, "nope") is None

    csv_file.write_bytes(b"tampered")
    problems = verify_files(loaded, root)
    assert len(problems) == 1 and "split test rows" in problems[0]
    scoped = verify_model_assets(loaded, root, "x")
    assert scoped.model == [] and len(scoped.dataset) == 1 and "rows" in scoped.dataset[0]
    npz.unlink()
    scoped = verify_model_assets(loaded, root, "x")
    assert any("missing file datasets/d/eval.npz" in p for p in scoped.dataset) and scoped.model == []
    weights.write_bytes(b"other")
    scoped = verify_model_assets(loaded, root, "x")
    assert len(scoped.model) == 1 and "sha256 mismatch" in scoped.model[0]

    # A model bound to a split the dataset does not bundle, or to an unknown dataset, is a dataset problem.
    loaded.models["y"] = stamp_manifest_sha256(_entry(fake, id="y", dataset_split="eval",
                                                      clean_accuracy=CleanAccuracy(value=0.5, n=2, split="eval")))
    assert any("no bundled split 'eval'" in p for p in verify_model_assets(loaded, root, "y").dataset)
    loaded.models["z"] = stamp_manifest_sha256(_entry(fake, id="z", dataset_id="hf:other/ds"))
    assert any("not in the manifest's datasets" in p for p in verify_model_assets(loaded, root, "z").dataset)
    loaded.models["w"] = stamp_manifest_sha256(_entry(fake, id="w", dataset_revision="different"))
    assert any("dataset_revision" in p for p in verify_model_assets(loaded, root, "w").dataset)
    assert verify_model_assets(loaded, root, "absent").model == ["model absent: no entry in the manifest"]

    # The legacy tabular id resolves to the current one when only the legacy entry exists.
    loaded.models["url_classifier"] = loaded.models.pop("x")
    assert model_entry(loaded, "url_trees") is loaded.models["url_classifier"]


def test_same_seed_reproduces_identical_weights(tmp_path: Path):
    data = _synthetic_images()
    _, first = build_cnn_asset(data, model_id="cnn", root=tmp_path / "a", epochs=1, seed=7, log=_quiet)
    _, second = build_cnn_asset(data, model_id="cnn", root=tmp_path / "b", epochs=1, seed=7, log=_quiet)
    assert first.file.sha256 == second.file.sha256 == first.sha256
    assert first.metrics["clean_accuracy"] == second.metrics["clean_accuracy"]
    assert first.manifest_sha256 == second.manifest_sha256
    _, other = build_cnn_asset(data, model_id="cnn", root=tmp_path / "c", epochs=1, seed=8, log=_quiet)
    assert other.file.sha256 != first.file.sha256
    assert other.manifest_sha256 != first.manifest_sha256


# ---------------------------------------------------------------------------
# Dataset caveats and subject_centered (G-CAVEAT, G-EXP2; spec 11.3, 13.4, 14.5)
# ---------------------------------------------------------------------------

def test_caveat_fields_default_on_a_legacy_manifest_and_stay_outside_the_digest(tmp_path: Path):
    """A manifest written before the fields existed reads back with [] / None and still verifies; adding the
    fields to an entry leaves manifest_sha256 unchanged (they are build record, not projection)."""
    from redsim.ml.assets.manifest import with_dataset_caveats

    root = tmp_path / "assets"
    weights = root / "bundled/x/weights.pt"
    weights.parent.mkdir(parents=True)
    weights.write_bytes(b"weights")
    fake = FileEntry(path="bundled/x/weights.pt", sha256=sha256_file(weights), size_bytes=7)
    manifest = AssetManifest.new()
    manifest.datasets["hf:example/ds"] = DatasetEntry(id="hf:example/ds", source="huggingface", revision="abc123",
                                                       class_names=["a", "b"])
    manifest.models["x"] = stamp_manifest_sha256(_entry(fake))
    write_manifest(manifest, root / MANIFEST_NAME)
    raw = json.loads((root / MANIFEST_NAME).read_text())
    # Simulate the legacy shape: strip the new keys entirely.
    for key in ("caveats", "subject_centered"):
        raw["datasets"]["hf:example/ds"].pop(key, None)
    for key in ("dataset_caveats", "subject_centered"):
        raw["models"]["x"].pop(key, None)
    (root / MANIFEST_NAME).write_text(json.dumps(raw))
    legacy = load_manifest(root / MANIFEST_NAME)
    assert legacy.datasets["hf:example/ds"].caveats == [] and legacy.datasets["hf:example/ds"].subject_centered is None
    assert legacy.models["x"].dataset_caveats == [] and legacy.models["x"].subject_centered is None
    assert verify_manifest(legacy, root) == [] and verify_entries(legacy) == []

    # Adding the fields changes neither the projection nor the digest.
    ds_entry = legacy.datasets["hf:example/ds"].model_copy(update={
        "caveats": ["Subjects are web-thumbnail framed."], "subject_centered": False})
    with_caveats = with_dataset_caveats(legacy.models["x"], ds_entry)
    assert with_caveats.dataset_caveats == ["Subjects are web-thumbnail framed."] and with_caveats.subject_centered is False
    assert manifest_digest(with_caveats) == legacy.models["x"].manifest_sha256 == with_caveats.manifest_sha256
    assert model_manifest(with_caveats) == model_manifest(legacy.models["x"])
    projected = MLModelManifest.model_validate(with_caveats.model_dump(mode="json"))
    assert not hasattr(projected, "dataset_caveats") and not hasattr(projected, "subject_centered")
    legacy.datasets["hf:example/ds"] = ds_entry
    legacy.models["x"] = with_caveats
    assert verify_manifest(legacy, root) == []
    write_manifest(legacy, root / MANIFEST_NAME)
    reloaded = load_manifest(root / MANIFEST_NAME)
    assert reloaded == legacy
    on_disk = json.loads((root / MANIFEST_NAME).read_text())
    assert on_disk["datasets"]["hf:example/ds"]["caveats"] == ["Subjects are web-thumbnail framed."]
    assert on_disk["datasets"]["hf:example/ds"]["subject_centered"] is False
    assert on_disk["models"]["x"]["dataset_caveats"] == ["Subjects are web-thumbnail framed."]
    assert on_disk["models"]["x"]["subject_centered"] is False

    # The copy is bound to the model's dataset: a mismatched dataset entry is refused, never silently attached.
    other = DatasetEntry(id="hf:other/ds", source="huggingface", caveats=["x"])
    with pytest.raises(ValueError, match="bound to dataset"):
        with_dataset_caveats(with_caveats, other)


def test_cnn_build_records_the_vehicle_caveats_and_subject_centered_false(tmp_path: Path):
    """A build on the vehicles dataset id writes the spec 11.3.1 caveats (D3 framing first) and subject_centered=false;
    a CIFAR-10-id build writes the fixture-only statement and subject_centered=true; an unlisted local dataset gets only
    the fixture-only statement when it is fixture-only and no subject_centered claim."""
    from redsim.ml.assets.build import (
        CIFAR10_CAVEATS,
        FIXTURE_ONLY_CAVEAT,
        VEHICLES_CAVEATS,
        VEHICLES_DATASET_ID,
        dataset_caveats,
        subject_centered_for,
    )
    from redsim.ml.datasets import cifar10
    from redsim.ml.schema import contains_banned_score_word

    data = _synthetic_images(n=16, image_size=8)
    # Synthetic pixels under the vehicles id: a build-path test of what the manifest says, not vehicle data.
    vehicles = data.dataset.model_copy(update={"id": VEHICLES_DATASET_ID, "fixture_only": False, "notes": []})
    vdata = ds.ImageDataset(dataset=vehicles, train=data.train, eval=data.eval)
    entry, model = build_cnn_asset(vdata, model_id="vehicles_cnn", root=tmp_path / "v", epochs=1, seed=0, log=_quiet)
    assert entry.caveats == list(VEHICLES_CAVEATS) and entry.subject_centered is False
    assert model.dataset_caveats == entry.caveats and model.subject_centered is False
    assert entry.caveats[0].startswith("leibnitz-lab/military_vehicles is an open, unclassified, publicly available")
    assert "never trains, optimises or deploys a targeting or weapons model" in entry.caveats[0]
    assert any("Ground-level photographs, not aerial or overhead imagery" in c for c in entry.caveats)
    assert any("not reliably centred" in c and "heuristic" in c for c in entry.caveats)
    for text in (*VEHICLES_CAVEATS, *CIFAR10_CAVEATS, FIXTURE_ONLY_CAVEAT):
        assert not contains_banned_score_word(text), text
        assert "readiness" not in text.lower() and "certif" not in text.lower(), text
    # The digest is the projection's: the same weights with no caveats stamp the same manifest_sha256.
    assert manifest_digest(model.model_copy(update={"dataset_caveats": [], "subject_centered": None})) == model.manifest_sha256
    # The manifest round-trips the fields and verifies.
    manifest = AssetManifest.new()
    manifest.datasets[entry.id] = entry
    manifest.models[model.id] = model
    write_manifest(manifest, tmp_path / "v" / MANIFEST_NAME)
    loaded = load_manifest(tmp_path / "v" / MANIFEST_NAME)
    assert verify_manifest(loaded, tmp_path / "v") == []
    assert loaded.models["vehicles_cnn"].dataset_caveats == list(VEHICLES_CAVEATS)
    assert loaded.datasets[VEHICLES_DATASET_ID].subject_centered is False
    # Explicit arguments extend the table and override the flag; duplicates collapse.
    entry2, model2 = build_cnn_asset(vdata, model_id="vehicles_cnn", root=tmp_path / "v2", epochs=1, seed=0,
                                     caveats=["Smoke build.", VEHICLES_CAVEATS[1]], subject_centered=True, log=_quiet)
    assert entry2.caveats == [*VEHICLES_CAVEATS, "Smoke build."] and entry2.subject_centered is True
    assert model2.subject_centered is True

    cifar = data.dataset.model_copy(update={"id": cifar10.DATASET_ID, "fixture_only": True})
    centry, cmodel = build_cnn_asset(ds.ImageDataset(dataset=cifar, train=data.train, eval=data.eval),
                                     model_id="cifar10_smallcnn", root=tmp_path / "c", epochs=1, seed=0, log=_quiet)
    assert centry.caveats == [*CIFAR10_CAVEATS, FIXTURE_ONLY_CAVEAT] and centry.subject_centered is True
    assert cmodel.dataset_caveats == centry.caveats and cmodel.subject_centered is True
    assert "never a demo target" in centry.caveats[0]

    lentry, lmodel = build_cnn_asset(data, model_id="synthetic_cnn", root=tmp_path / "l", epochs=1, seed=0, log=_quiet)
    assert lentry.caveats == [FIXTURE_ONLY_CAVEAT] and lentry.subject_centered is None and lmodel.subject_centered is None
    plain = DatasetEntry(id="local:unlisted", source="local")
    assert dataset_caveats(plain) == [] and subject_centered_for(plain) is None
    assert subject_centered_for(DatasetEntry(id="local:unlisted", source="local", subject_centered=False)) is False
