"""Bundled CIFAR-10 target interface.

Dataset and model loading are delegated to a backend so the target's sampling
and contract behavior can be tested without downloading assets or importing
Torch.  The production asset backend is added separately by ``setup_assets``.
"""

from __future__ import annotations

from typing import Any, Protocol

import numpy as np

from redsim.schema import TargetInfo
from redsim.targets.base import Sample

CIFAR10_CLASS_NAMES: tuple[str, ...] = (
    "airplane",
    "automobile",
    "bird",
    "cat",
    "deer",
    "dog",
    "frog",
    "horse",
    "ship",
    "truck",
)


class Cifar10Backend(Protocol):
    """Model/data operations supplied by a production or synthetic backend."""

    def load(self) -> None: ...

    def test_data(self) -> tuple[np.ndarray, np.ndarray]: ...

    def predict_proba(self, x: np.ndarray) -> np.ndarray: ...

    def art_classifier(self) -> Any: ...

    def torch_model(self) -> Any: ...

    def manifest(self) -> dict[str, Any]: ...


class Cifar10Target:
    """Live image target over a bundled model and the CIFAR-10 test split."""

    id = "cifar10"

    def __init__(self, backend: Cifar10Backend) -> None:
        self._backend = backend
        self._loaded = False

    def info(self) -> TargetInfo:
        metadata = {
            "dataset": "CIFAR-10",
            "dataset_split": "test",
            "n_classes": len(CIFAR10_CLASS_NAMES),
            "class_names": list(CIFAR10_CLASS_NAMES),
        }
        metadata.update(self._backend.manifest())
        return TargetInfo(
            id=self.id,
            name="Bundled CIFAR-10 classifier",
            domain="image",
            status="available",
            metadata=metadata,
        )

    def load(self) -> None:
        if self._loaded:
            return
        self._backend.load()
        self._validate_test_data()
        self._loaded = True

    def sample(self, n: int, seed: int) -> Sample:
        self._require_loaded()
        x, y = self._backend.test_data()
        if n <= 0:
            raise ValueError("sample size must be positive")
        if n > len(y):
            raise ValueError(f"sample size {n} exceeds test split size {len(y)}")

        labels = np.unique(y)
        expected = np.arange(len(CIFAR10_CLASS_NAMES))
        if not np.array_equal(labels, expected):
            raise ValueError("CIFAR-10 test split must contain labels 0 through 9")

        rng = np.random.default_rng(seed)
        per_class, remainder = divmod(n, len(labels))
        remainder_labels = set(rng.permutation(labels)[:remainder].tolist())
        selected: list[np.ndarray] = []

        for label in labels:
            candidates = np.flatnonzero(y == label)
            count = per_class + int(label in remainder_labels)
            if count > len(candidates):
                raise ValueError(
                    f"class {int(label)} has only {len(candidates)} samples; {count} requested"
                )
            selected.append(rng.choice(candidates, size=count, replace=False))

        indices = np.concatenate(selected)
        indices = indices[rng.permutation(len(indices))]
        return Sample(
            x=np.asarray(x[indices], dtype=np.float32),
            y=np.asarray(y[indices], dtype=np.int64),
            indices=indices,
            class_names=list(CIFAR10_CLASS_NAMES),
        )

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        self._require_loaded()
        probabilities = np.asarray(self._backend.predict_proba(x))
        expected_shape = (len(x), len(CIFAR10_CLASS_NAMES))
        if probabilities.shape != expected_shape:
            raise ValueError(
                f"backend probabilities have shape {probabilities.shape}; expected {expected_shape}"
            )
        if not np.all(np.isfinite(probabilities)):
            raise ValueError("backend probabilities must be finite")
        if np.any(probabilities < 0) or np.any(probabilities > 1):
            raise ValueError("backend probabilities must be in [0, 1]")
        if not np.allclose(probabilities.sum(axis=1), 1.0, atol=1e-5):
            raise ValueError("backend probability rows must sum to 1")
        return probabilities

    def art_classifier(self) -> Any:
        self._require_loaded()
        return self._backend.art_classifier()

    def torch_model(self) -> Any:
        self._require_loaded()
        return self._backend.torch_model()

    def manifest(self) -> dict[str, Any]:
        self._require_loaded()
        return dict(self._backend.manifest())

    def _require_loaded(self) -> None:
        if not self._loaded:
            raise RuntimeError("CIFAR-10 target must be loaded before evaluation")

    def _validate_test_data(self) -> None:
        x, y = self._backend.test_data()
        if x.ndim != 4 or x.shape[1:] != (3, 32, 32):
            raise ValueError("CIFAR-10 inputs must have shape (n, 3, 32, 32)")
        if y.ndim != 1 or len(y) != len(x):
            raise ValueError("CIFAR-10 labels must have shape (n,) matching the inputs")
        if x.dtype != np.float32:
            raise ValueError("CIFAR-10 inputs must be float32")
        if np.any(x < 0) or np.any(x > 1):
            raise ValueError("CIFAR-10 inputs must be normalized to [0, 1]")