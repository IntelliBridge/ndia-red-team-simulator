"""CIFAR-10 target tests using only deterministic in-memory test doubles."""

from typing import Any

import numpy as np
import pytest

from redsim.targets.base import Target
from redsim.targets.image_cifar10 import CIFAR10_CLASS_NAMES, Cifar10Target


class SyntheticCifar10Backend:
    def __init__(self, samples_per_class: int = 12) -> None:
        rng = np.random.default_rng(41)
        self.x = rng.random(
            (len(CIFAR10_CLASS_NAMES) * samples_per_class, 3, 32, 32),
            dtype=np.float32,
        )
        self.y = np.repeat(
            np.arange(len(CIFAR10_CLASS_NAMES), dtype=np.int64),
            samples_per_class,
        )
        self.load_calls = 0
        self.classifier = object()
        self.model = object()

    def load(self) -> None:
        self.load_calls += 1

    def test_data(self) -> tuple[np.ndarray, np.ndarray]:
        return self.x, self.y

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        return np.full(
            (len(x), len(CIFAR10_CLASS_NAMES)),
            1 / len(CIFAR10_CLASS_NAMES),
            dtype=np.float32,
        )

    def art_classifier(self) -> Any:
        return self.classifier

    def torch_model(self) -> Any:
        return self.model

    def manifest(self) -> dict[str, Any]:
        return {
            "model": "SyntheticCifar10Backend",
            "weights_sha256": "a" * 64,
            "clean_test_accuracy": 0.7,
        }


def test_target_satisfies_runtime_protocol() -> None:
    assert isinstance(Cifar10Target(SyntheticCifar10Backend()), Target)


def test_info_describes_available_bundled_public_target() -> None:
    target = Cifar10Target(SyntheticCifar10Backend())

    info = target.info()

    assert info.id == "cifar10"
    assert info.domain == "image"
    assert info.status == "available"
    assert info.reason is None
    assert info.metadata["dataset"] == "CIFAR-10"
    assert info.metadata["dataset_split"] == "test"
    assert info.metadata["class_names"] == list(CIFAR10_CLASS_NAMES)
    assert info.metadata["clean_test_accuracy"] == 0.7


def test_load_is_idempotent() -> None:
    backend = SyntheticCifar10Backend()
    target = Cifar10Target(backend)

    target.load()
    target.load()

    assert backend.load_calls == 1


def test_evaluation_operations_require_load() -> None:
    target = Cifar10Target(SyntheticCifar10Backend())

    with pytest.raises(RuntimeError, match="must be loaded"):
        target.sample(20, seed=0)
    with pytest.raises(RuntimeError, match="must be loaded"):
        target.predict_proba(np.zeros((1, 3, 32, 32), dtype=np.float32))
    with pytest.raises(RuntimeError, match="must be loaded"):
        target.manifest()


def test_sampling_is_seeded_and_stratified() -> None:
    target = Cifar10Target(SyntheticCifar10Backend())
    target.load()

    first = target.sample(25, seed=7)
    repeated = target.sample(25, seed=7)
    different = target.sample(25, seed=8)

    assert np.array_equal(first.indices, repeated.indices)
    assert not np.array_equal(first.indices, different.indices)
    counts = np.bincount(first.y, minlength=len(CIFAR10_CLASS_NAMES))
    assert counts.sum() == 25
    assert counts.max() - counts.min() <= 1
    assert first.x.dtype == np.float32
    assert first.y.dtype == np.int64
    assert first.class_names == list(CIFAR10_CLASS_NAMES)


@pytest.mark.parametrize("n", [0, -1, 121])
def test_sampling_rejects_invalid_sizes(n: int) -> None:
    target = Cifar10Target(SyntheticCifar10Backend())
    target.load()

    with pytest.raises(ValueError, match="sample size"):
        target.sample(n, seed=0)


def test_prediction_and_model_adapters_delegate_to_backend() -> None:
    backend = SyntheticCifar10Backend()
    target = Cifar10Target(backend)
    target.load()
    batch = target.sample(4, seed=3).x

    probabilities = target.predict_proba(batch)

    assert probabilities.shape == (4, len(CIFAR10_CLASS_NAMES))
    assert np.allclose(probabilities.sum(axis=1), 1)
    assert target.art_classifier() is backend.classifier
    assert target.torch_model() is backend.model
    assert target.manifest()["weights_sha256"] == "a" * 64


@pytest.mark.parametrize(
    "probabilities",
    [
        np.ones((2, 9), dtype=np.float32),
        np.full((2, 10), np.nan, dtype=np.float32),
        np.full((2, 10), -0.1, dtype=np.float32),
        np.full((2, 10), 0.2, dtype=np.float32),
    ],
)
def test_invalid_backend_probabilities_are_rejected(probabilities: np.ndarray) -> None:
    class InvalidPredictionBackend(SyntheticCifar10Backend):
        def predict_proba(self, x: np.ndarray) -> np.ndarray:
            return probabilities

    target = Cifar10Target(InvalidPredictionBackend())
    target.load()

    with pytest.raises(ValueError, match="probabilit"):
        target.predict_proba(target.sample(2, seed=0).x)


def test_load_rejects_malformed_test_data() -> None:
    backend = SyntheticCifar10Backend()
    backend.x = backend.x.astype(np.float64)

    with pytest.raises(ValueError, match="float32"):
        Cifar10Target(backend).load()