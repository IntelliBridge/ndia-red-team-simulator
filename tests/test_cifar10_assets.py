"""Production CIFAR-10 asset tests with temporary synthetic bundles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest
import torch

import redsim.setup_assets as asset_setup
import redsim.targets.registry as target_registry
from redsim.registry import Registry
from redsim.setup_assets import setup_assets
from redsim.targets.base import Target
from redsim.targets.cifar10_assets import (
    MANIFEST_FILENAME,
    TEST_CACHE_FILENAME,
    WEIGHTS_FILENAME,
    TorchCifar10Backend,
    build_small_cnn,
    sha256_file,
)


class SyntheticDataset:
    def __init__(self, samples_per_class: int) -> None:
        rng = np.random.default_rng(22)
        self.x = rng.random((10 * samples_per_class, 3, 32, 32), dtype=np.float32)
        self.y = np.repeat(np.arange(10, dtype=np.int64), samples_per_class)

    def __len__(self) -> int:
        return len(self.y)

    def __getitem__(self, index: int) -> tuple[torch.Tensor, int]:
        return torch.from_numpy(self.x[index]), int(self.y[index])


def write_asset_bundle(assets_dir: Path) -> dict[str, Any]:
    assets_dir.mkdir(parents=True, exist_ok=True)
    weights_path = assets_dir / WEIGHTS_FILENAME
    cache_path = assets_dir / TEST_CACHE_FILENAME
    model = build_small_cnn()
    torch.save(model.state_dict(), weights_path)
    dataset = SyntheticDataset(samples_per_class=2)
    np.savez_compressed(cache_path, x=dataset.x, y=dataset.y)
    manifest = {
        "dataset": "CIFAR-10",
        "dataset_split": "test",
        "model_architecture": "SmallCNN(2 conv blocks, 2 fully connected layers)",
        "training_seed": 7,
        "training_epochs": 1,
        "torch_version": torch.__version__,
        "clean_test_accuracy": 0.1,
        "weights_sha256": sha256_file(weights_path),
        "test_cache_sha256": sha256_file(cache_path),
    }
    (assets_dir / MANIFEST_FILENAME).write_text(json.dumps(manifest))
    return manifest


def test_backend_loads_verified_bundle_and_predicts(tmp_path: Path) -> None:
    expected_manifest = write_asset_bundle(tmp_path)
    backend = TorchCifar10Backend(tmp_path)

    backend.load()
    x, y = backend.test_data()
    probabilities = backend.predict_proba(x[:3])

    assert x.shape == (20, 3, 32, 32)
    assert y.shape == (20,)
    assert probabilities.shape == (3, 10)
    assert np.allclose(probabilities.sum(axis=1), 1.0)
    assert backend.torch_model().training is False
    assert backend.manifest() == expected_manifest


def test_backend_reports_incomplete_asset_bundle(tmp_path: Path) -> None:
    backend = TorchCifar10Backend(tmp_path)

    assert backend.assets_available() is False
    with pytest.raises(FileNotFoundError, match="run `python -m redsim.setup_assets`"):
        backend.load()


@pytest.mark.parametrize("filename", [WEIGHTS_FILENAME, TEST_CACHE_FILENAME])
def test_backend_rejects_tampered_assets(tmp_path: Path, filename: str) -> None:
    write_asset_bundle(tmp_path)
    with (tmp_path / filename).open("ab") as handle:
        handle.write(b"tampered")

    with pytest.raises(ValueError, match="SHA-256"):
        TorchCifar10Backend(tmp_path).load()


def test_setup_assets_writes_hashes_and_measured_accuracy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    train = SyntheticDataset(samples_per_class=2)
    test = SyntheticDataset(samples_per_class=1)
    model = build_small_cnn()
    monkeypatch.setattr(
        asset_setup,
        "load_cifar10",
        lambda data_dir: (train, test, "synthetic:test-double"),
    )
    monkeypatch.setattr(
        asset_setup,
        "train_model",
        lambda *args, **kwargs: (model, 0.67),
    )
    assets_dir = tmp_path / "assets"

    manifest = setup_assets(
        assets_dir=assets_dir,
        data_dir=tmp_path / "data",
        epochs=3,
        batch_size=5,
        seed=17,
    )

    stored = json.loads((assets_dir / MANIFEST_FILENAME).read_text())
    assert manifest == stored
    assert stored["clean_test_accuracy"] == 0.67
    assert stored["dataset_source"] == "synthetic:test-double"
    assert stored["training_seed"] == 17
    assert stored["training_epochs"] == 3
    assert stored["n_train"] == 20
    assert stored["n_test"] == 10
    assert stored["weights_sha256"] == sha256_file(assets_dir / WEIGHTS_FILENAME)
    assert stored["test_cache_sha256"] == sha256_file(assets_dir / TEST_CACHE_FILENAME)


def test_live_target_registration_requires_and_validates_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    isolated = Registry[Target]("target", protocol=Target)
    monkeypatch.setattr(target_registry, "TARGETS", isolated)

    with pytest.raises(FileNotFoundError, match="assets are incomplete"):
        target_registry.register_cifar10_assets(tmp_path)

    write_asset_bundle(tmp_path)
    target = target_registry.register_cifar10_assets(tmp_path)

    assert isolated.ids() == ["cifar10"]
    assert target.info().status == "available"
    assert target_registry.register_cifar10_assets(tmp_path) is target