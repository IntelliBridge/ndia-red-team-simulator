"""The committed CIFAR-10 fixture matches its sidecar and is served by no target (spec 11.3.5, G-ASSET5).

``tests/ml/fixtures/cifar10_test_500.npz`` was written by ``redsim ml build-assets --fixture`` from a
local copy of the ``uoft-cs/cifar10`` test split; ``tests/ml/fixtures/MANIFEST.json`` records the source
dataset id, revision, the chosen source rows and the file digest. Nothing here touches the network.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("numpy")

import numpy as np

from redsim.ml.assets import datasets as ds
from redsim.ml.datasets import cifar10

FIXTURES = Path(__file__).parent / "fixtures"
NPZ = FIXTURES / cifar10.FIXTURE_NAME
SIDECAR = FIXTURES / "MANIFEST.json"


@pytest.fixture(scope="module")
def entry() -> dict:
    sidecar = json.loads(SIDECAR.read_text(encoding="utf-8"))
    assert sidecar["schema_version"] == 1
    return sidecar["files"][cifar10.FIXTURE_NAME]


def test_fixture_file_matches_its_sidecar_digest(entry: dict) -> None:
    assert NPZ.is_file() and NPZ.stat().st_size < 3 * 1024 * 1024, "the committed slice stays small"
    assert hashlib.sha256(NPZ.read_bytes()).hexdigest() == entry["sha256"]


def test_fixture_is_the_pinned_seed_0_draw_of_the_real_test_split(entry: dict) -> None:
    assert entry["synthetic"] is False, "the committed fixture is a real draw, not the synthetic stand-in"
    assert entry["source_dataset_id"] == cifar10.DATASET_ID == "hf:uoft-cs/cifar10"
    assert entry["source_split"] == "test" and len(entry["source_revision"]) == 40   # a hub commit sha
    assert entry["source"]["kind"] in {"bundled_split_npz", "hub_parquet_cache"} and entry["source"]["sha256"]
    assert entry["n_source_rows"] == 10000 and entry["n_rows"] == 500
    assert entry["sampling"]["seed"] == cifar10.FIXTURE_SEED == 0
    assert entry["sampling"]["per_class"] == cifar10.FIXTURE_PER_CLASS == 50
    assert entry["per_class"] == {name: 50 for name in cifar10.CLASS_NAMES}
    assert entry["class_names"] == list(cifar10.CLASS_NAMES)
    idx = np.asarray(entry["source_row_indices"], dtype=np.int64)
    assert idx.shape == (500,) and len(set(idx.tolist())) == 500 and np.array_equal(idx, np.sort(idx))
    assert 0 <= idx.min() and idx.max() < 10000
    assert entry["source_row_indices_sha256"] == ds.indices_sha256(idx)


def test_fixture_contents_match_the_sidecar(entry: dict) -> None:
    x, y, indices = cifar10.load_fixture_npz(NPZ)
    assert x.shape == tuple(entry["shape"]) == (500, 3, 32, 32) and x.dtype == np.uint8
    assert np.bincount(y, minlength=10).tolist() == [50] * 10
    assert np.array_equal(indices, np.asarray(entry["source_row_indices"], dtype=np.int64))
    assert cifar10.fixture_provenance(NPZ) == {"dataset_id": entry["source_dataset_id"],
                                               "dataset_revision": entry["source_revision"]}
    with np.load(NPZ, allow_pickle=False) as npz:
        assert sorted(npz.files) == sorted(entry["npz_keys"])
        assert list(npz["class_names"]) == list(cifar10.CLASS_NAMES)
    # Real images, not noise: neighbouring pixels are correlated far more than in a uniform draw.
    flat = x.astype(np.float64)
    neighbour_diff = np.abs(flat[:, :, :, 1:] - flat[:, :, :, :-1]).mean()
    assert neighbour_diff < 40.0, f"mean neighbour difference {neighbour_diff:.1f} looks like noise"


def test_fixture_is_never_served_as_a_result() -> None:
    """No registered target reads the committed fixture, and the CIFAR-10 target is fixture_only."""
    from redsim.ml.targets.registry import TARGETS, list_targets

    infos = {i.id: i for i in list_targets()}
    assert infos["cifar10_smallcnn"].metadata["fixture_only"] is True
    for target in TARGETS:
        assets_dir = target.info().metadata.get("assets_dir")
        assert assets_dir is None or Path(assets_dir).resolve() != FIXTURES.resolve()
    assert any("never a demo target" in note for note in
               json.loads(SIDECAR.read_text())["files"][cifar10.FIXTURE_NAME]["notes"])
