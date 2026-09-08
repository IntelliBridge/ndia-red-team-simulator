"""Asset-backed CIFAR-10 model implementation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

WEIGHTS_FILENAME = "cifar10_smallcnn.pt"
TEST_CACHE_FILENAME = "cifar10_test.npz"
MANIFEST_FILENAME = "MANIFEST.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_small_cnn() -> Any:
    """Construct the fixed milestone architecture without importing Torch at module load."""

    import torch.nn as nn

    return nn.Sequential(
        nn.Conv2d(3, 32, kernel_size=3, padding=1),
        nn.ReLU(),
        nn.MaxPool2d(2),
        nn.Conv2d(32, 64, kernel_size=3, padding=1),
        nn.ReLU(),
        nn.MaxPool2d(2),
        nn.Flatten(),
        nn.Linear(64 * 8 * 8, 128),
        nn.ReLU(),
        nn.Linear(128, 10),
    )


class TorchCifar10Backend:
    """Load generated weights and a normalized test cache from ``assets/``."""

    def __init__(self, assets_dir: str | Path) -> None:
        self.assets_dir = Path(assets_dir)
        self._model: Any = None
        self._classifier: Any = None
        self._x_test: np.ndarray | None = None
        self._y_test: np.ndarray | None = None
        self._manifest: dict[str, Any] | None = None

    @property
    def required_paths(self) -> tuple[Path, Path, Path]:
        return (
            self.assets_dir / WEIGHTS_FILENAME,
            self.assets_dir / TEST_CACHE_FILENAME,
            self.assets_dir / MANIFEST_FILENAME,
        )

    def assets_available(self) -> bool:
        return all(path.is_file() for path in self.required_paths)

    def load(self) -> None:
        if self._model is not None:
            return
        if not self.assets_available():
            missing = [path.name for path in self.required_paths if not path.is_file()]
            raise FileNotFoundError(
                f"CIFAR-10 assets are incomplete in {self.assets_dir}: missing {', '.join(missing)}; "
                "run `python -m redsim.setup_assets`"
            )

        import torch

        manifest = json.loads((self.assets_dir / MANIFEST_FILENAME).read_text())
        self._validate_manifest(manifest)
        cache = np.load(self.assets_dir / TEST_CACHE_FILENAME, allow_pickle=False)
        x_test = np.asarray(cache["x"], dtype=np.float32)
        y_test = np.asarray(cache["y"], dtype=np.int64)
        model = build_small_cnn()
        state = torch.load(
            self.assets_dir / WEIGHTS_FILENAME,
            map_location="cpu",
            weights_only=True,
        )
        model.load_state_dict(state)
        model.eval()

        self._manifest = manifest
        self._x_test = x_test
        self._y_test = y_test
        self._model = model

    def test_data(self) -> tuple[np.ndarray, np.ndarray]:
        self._require_loaded()
        assert self._x_test is not None and self._y_test is not None
        return self._x_test, self._y_test

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        self._require_loaded()
        import torch

        assert self._model is not None
        with torch.no_grad():
            logits = self._model(torch.from_numpy(np.asarray(x, dtype=np.float32)))
            return torch.softmax(logits, dim=1).cpu().numpy()

    def art_classifier(self) -> Any:
        self._require_loaded()
        if self._classifier is None:
            import torch.nn as nn
            from art.estimators.classification import PyTorchClassifier

            assert self._model is not None
            self._classifier = PyTorchClassifier(
                model=self._model,
                loss=nn.CrossEntropyLoss(),
                input_shape=(3, 32, 32),
                nb_classes=10,
                clip_values=(0.0, 1.0),
                device_type="cpu",
            )
        return self._classifier

    def torch_model(self) -> Any:
        self._require_loaded()
        return self._model

    def manifest(self) -> dict[str, Any]:
        if self._manifest is None:
            path = self.assets_dir / MANIFEST_FILENAME
            if not path.is_file():
                return {}
            return json.loads(path.read_text())
        return dict(self._manifest)

    def _require_loaded(self) -> None:
        if self._model is None:
            raise RuntimeError("CIFAR-10 assets must be loaded first")

    def _validate_manifest(self, manifest: dict[str, Any]) -> None:
        required = {
            "dataset",
            "dataset_split",
            "model_architecture",
            "training_seed",
            "training_epochs",
            "torch_version",
            "clean_test_accuracy",
            "weights_sha256",
            "test_cache_sha256",
        }
        missing = sorted(required - manifest.keys())
        if missing:
            raise ValueError(f"CIFAR-10 manifest is missing: {', '.join(missing)}")

        weights_hash = sha256_file(self.assets_dir / WEIGHTS_FILENAME)
        if weights_hash != manifest["weights_sha256"]:
            raise ValueError("CIFAR-10 weights do not match the manifest SHA-256")
        cache_hash = sha256_file(self.assets_dir / TEST_CACHE_FILENAME)
        if cache_hash != manifest["test_cache_sha256"]:
            raise ValueError("CIFAR-10 test cache does not match the manifest SHA-256")