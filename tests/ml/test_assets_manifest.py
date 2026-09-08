"""``MANIFEST.json`` round-trips and a one-epoch ``SmallCNN`` build yields hash-verifiable weights.

ml tier: needs torch. Everything runs on 64 synthetic images in ``tmp_path``;
no dataset download and no network.
"""

from __future__ import annotations

import json
from pathlib import Path

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
    FileEntry,
    ModelEntry,
    load_manifest,
    sha256_bytes,
    sha256_file,
    verify_files,
    write_manifest,
)
from redsim.ml.assets.train_cnn import load_small_cnn, predict_logits
from redsim.ml.targets.architectures import (
    ARCHITECTURES,
    SmallCNN,
    UnknownArchitecture,
    build_architecture,
)


def _quiet(_: str) -> None:
    return None


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
    with pytest.raises(ValueError):
        SmallCNN(n_classes=1)
    with pytest.raises(ValueError):
        SmallCNN(image_size=4)
    with pytest.raises(ValueError):
        SmallCNN().set_input_normalization(torch.zeros(3), torch.zeros(3))


# ---------------------------------------------------------------------------
# Manifest schema
# ---------------------------------------------------------------------------

def test_manifest_round_trip_and_sorted_keys(tmp_path: Path):
    manifest = AssetManifest.new()
    fake = FileEntry(path="bundled/x/weights.pt", sha256=sha256_bytes(b"weights"), size_bytes=7)
    manifest.datasets["hf:example/ds"] = DatasetEntry(id="hf:example/ds", source="huggingface", revision="abc123",
                                                       license="mit", class_names=["a", "b"])
    manifest.models["x"] = ModelEntry(id="x", modality="image", format="torch_state_dict", architecture_id="small_cnn",
                                      file=fake, dataset_id="hf:example/ds", dataset_revision="abc123",
                                      train_split="train", eval_split="test", class_names=["a", "b"], seed=0,
                                      epochs=3, metrics={"clean_accuracy": 0.5, "n": 2})
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
    weights.unlink()
    assert any("missing file" in p for p in verify_files(loaded, root))


def test_same_seed_reproduces_identical_weights(tmp_path: Path):
    data = _synthetic_images()
    _, first = build_cnn_asset(data, model_id="cnn", root=tmp_path / "a", epochs=1, seed=7, log=_quiet)
    _, second = build_cnn_asset(data, model_id="cnn", root=tmp_path / "b", epochs=1, seed=7, log=_quiet)
    assert first.file.sha256 == second.file.sha256
    assert first.metrics["clean_accuracy"] == second.metrics["clean_accuracy"]
    _, other = build_cnn_asset(data, model_id="cnn", root=tmp_path / "c", epochs=1, seed=8, log=_quiet)
    assert other.file.sha256 != first.file.sha256
