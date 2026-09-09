"""``uoft-cs/cifar10`` loader (spec section 11.3.5). CI / fixture dataset only.

CIFAR-10 never appears in the demo catalog and is never presented as results.
The hub parquet (``plain_text/test-00000-of-00001.parquet``, columns ``img``
struct{bytes, path} and ``label``) is fetched once by ``redsim ml build-assets``
and decoded here; CI reads the committed 500-image fixture ``.npz`` instead.

The fixture (``tests/ml/fixtures/cifar10_test_500.npz``) is written by
``redsim ml build-assets --fixture`` (``redsim.ml.assets.build.build_cifar10_fixture``)
from a local copy of the test split: ``fixture_indices`` picks 50 rows per class
with seed 0, ``save_fixture_npz`` writes them, and the sidecar
``tests/ml/fixtures/MANIFEST.json`` records the source dataset id, revision,
the chosen source indices and the file digest. When no local copy of the test
split exists the build can fall back to ``synthetic_test_split`` -- a seeded
stand-in with CIFAR-10's shape and class list that is labelled synthetic in the
sidecar and is never described as CIFAR-10 data.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import httpx
import numpy as np

from redsim.ml.datasets import DatasetUnavailable
from redsim.ml.datasets.image_hub import download_file, image_bytes_to_array, resolve_revision
from redsim.ml.datasets.sampling import stratified_indices

REPO_ID = "uoft-cs/cifar10"
DATASET_ID = f"hf:{REPO_ID}"          # the id ``redsim ml build-assets`` records for the hub dataset
TEST_PARQUET = "plain_text/test-00000-of-00001.parquet"
TRAIN_PARQUET = "plain_text/train-00000-of-00001.parquet"
CLASS_NAMES: tuple[str, ...] = ("airplane", "automobile", "bird", "cat", "deer", "dog", "frog", "horse",
                                "ship", "truck")
LICENSE = ("unknown on the HF card; no formal license statement exists, universally redistributed for "
           "research. Test fixture only, never presented as results.")
IMAGE_SIZE = 32
FIXTURE_PER_CLASS = 50
FIXTURE_SEED = 0
FIXTURE_NAME = "cifar10_test_500.npz"
SYNTHETIC_DATASET_ID = "local:synthetic-cifar10-shaped"
SYNTHETIC_TEST_N = 1000               # 100 per class: enough for the 50-per-class fixture draw


def class_names() -> list[str]:
    return list(CLASS_NAMES)


def load_parquet(path: Path, *, image_col: str = "img", label_col: str = "label",
                 limit: int | None = None) -> tuple[np.ndarray, np.ndarray]:
    """Decode a HF image-classification parquet into uint8 NCHW ``x`` and int64 ``y``."""
    import pyarrow.parquet as pq

    try:
        table = pq.read_table(path, columns=[image_col, label_col])
    except Exception as exc:  # pyarrow raises several types
        raise DatasetUnavailable(f"cannot read parquet {path}: {exc}") from exc
    if limit is not None:
        table = table.slice(0, limit)
    images: list[Any] = table.column(image_col).to_pylist()
    labels = np.asarray(table.column(label_col).to_pylist(), dtype=np.int64)
    xs: list[np.ndarray] = []
    for cell in images:
        data = cell.get("bytes") if isinstance(cell, dict) else cell
        if not isinstance(data, (bytes, bytearray)):
            raise DatasetUnavailable("image column does not carry encoded bytes")
        xs.append(image_bytes_to_array(bytes(data), None))
    x = np.stack(xs) if xs else np.empty((0, 3, IMAGE_SIZE, IMAGE_SIZE), dtype=np.uint8)
    return x, labels


def fetch_test_split(revision: str = "main", *, client: httpx.Client | None = None) -> tuple[Path, str]:
    """Download the test parquet at the resolved revision. Build time only; never called by tests."""
    sha = resolve_revision(REPO_ID, revision, client=client)
    return download_file(REPO_ID, TEST_PARQUET, sha, client=client), sha


def fixture_indices(y: np.ndarray, *, per_class: int = FIXTURE_PER_CLASS, seed: int = FIXTURE_SEED) -> np.ndarray:
    """Seeded stratified selection of ``per_class`` rows per class (500 total for the committed fixture)."""
    return np.sort(stratified_indices(y, per_class * len(CLASS_NAMES), seed))


def synthetic_test_split(*, seed: int = FIXTURE_SEED, n: int = SYNTHETIC_TEST_N) -> tuple[np.ndarray, np.ndarray]:
    """A seeded stand-in with CIFAR-10's shape: uint8 (n, 3, 32, 32) noise and balanced labels.

    Used only when ``build-assets --fixture`` finds no local copy of the real test split. It is a
    test double, not CIFAR-10: whatever is built from it is labelled ``synthetic`` in the sidecar.
    """
    if n < len(CLASS_NAMES):
        raise ValueError(f"n must be >= {len(CLASS_NAMES)}")
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 256, size=(n, 3, IMAGE_SIZE, IMAGE_SIZE), dtype=np.uint8)
    y = (np.arange(n) % len(CLASS_NAMES)).astype(np.int64)
    return x, y


def save_fixture_npz(path: Path, x: np.ndarray, y: np.ndarray, indices: np.ndarray, *,
                     dataset_revision: str, dataset_id: str = REPO_ID) -> str:
    """Write the fixture slice (uint8 NCHW) and return its sha256 for the sidecar manifest."""
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(path, x=np.asarray(x, dtype=np.uint8), y=np.asarray(y, dtype=np.int64),
                        indices=np.asarray(indices, dtype=np.int64),
                        class_names=np.asarray(CLASS_NAMES), dataset_id=np.asarray(dataset_id),
                        dataset_revision=np.asarray(dataset_revision))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_fixture_npz(path: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Read a fixture slice written by ``save_fixture_npz``: ``(x uint8 NCHW, y, source indices)``."""
    try:
        with np.load(path, allow_pickle=False) as npz:
            x = np.asarray(npz["x"])
            y = np.asarray(npz["y"], dtype=np.int64)
            indices = np.asarray(npz["indices"], dtype=np.int64) if "indices" in npz else np.arange(len(y))
    except (OSError, KeyError, ValueError) as exc:
        raise DatasetUnavailable(f"cannot read fixture {path}: {exc}") from exc
    if x.ndim != 4 or x.shape[1] != 3:
        raise DatasetUnavailable(f"fixture {path} is not NCHW RGB: shape {x.shape}")
    return x, y, indices


def fixture_provenance(path: Path) -> dict[str, str]:
    """The ``dataset_id`` / ``dataset_revision`` strings stored inside a fixture ``.npz`` (empty when absent)."""
    out: dict[str, str] = {}
    try:
        with np.load(path, allow_pickle=False) as npz:
            for key in ("dataset_id", "dataset_revision"):
                if key in npz:
                    out[key] = str(np.asarray(npz[key]).item())
    except (OSError, KeyError, ValueError) as exc:
        raise DatasetUnavailable(f"cannot read fixture {path}: {exc}") from exc
    return out


__all__ = [
    "CLASS_NAMES", "DATASET_ID", "FIXTURE_NAME", "FIXTURE_PER_CLASS", "FIXTURE_SEED", "IMAGE_SIZE", "LICENSE",
    "REPO_ID", "SYNTHETIC_DATASET_ID", "SYNTHETIC_TEST_N", "TEST_PARQUET", "TRAIN_PARQUET", "class_names",
    "fetch_test_split", "fixture_indices", "fixture_provenance", "load_fixture_npz", "load_parquet",
    "save_fixture_npz", "synthetic_test_split",
]
