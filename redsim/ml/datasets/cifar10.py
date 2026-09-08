"""``uoft-cs/cifar10`` loader (spec section 11.3.5). CI / fixture dataset only.

CIFAR-10 never appears in the demo catalog and is never presented as results.
The hub parquet (``plain_text/test-00000-of-00001.parquet``, columns ``img``
struct{bytes, path} and ``label``) is fetched once by ``redsim ml build-assets``
and decoded here; CI reads the committed 500-image fixture ``.npz`` instead.
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
TEST_PARQUET = "plain_text/test-00000-of-00001.parquet"
TRAIN_PARQUET = "plain_text/train-00000-of-00001.parquet"
CLASS_NAMES: tuple[str, ...] = ("airplane", "automobile", "bird", "cat", "deer", "dog", "frog", "horse",
                                "ship", "truck")
LICENSE = ("unknown on the HF card; no formal license statement exists, universally redistributed for "
           "research. Test fixture only, never presented as results.")
IMAGE_SIZE = 32
FIXTURE_PER_CLASS = 50
FIXTURE_SEED = 0


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


def save_fixture_npz(path: Path, x: np.ndarray, y: np.ndarray, indices: np.ndarray, *,
                     dataset_revision: str) -> str:
    """Write the fixture slice (uint8 NCHW) and return its sha256 for the sidecar manifest."""
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(path, x=np.asarray(x, dtype=np.uint8), y=np.asarray(y, dtype=np.int64),
                        indices=np.asarray(indices, dtype=np.int64),
                        class_names=np.asarray(CLASS_NAMES), dataset_id=np.asarray(REPO_ID),
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


__all__ = [
    "CLASS_NAMES", "FIXTURE_PER_CLASS", "FIXTURE_SEED", "IMAGE_SIZE", "LICENSE", "REPO_ID", "TEST_PARQUET",
    "TRAIN_PARQUET", "class_names", "fetch_test_split", "fixture_indices", "load_fixture_npz", "load_parquet",
    "save_fixture_npz",
]
