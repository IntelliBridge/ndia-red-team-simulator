"""Datasets: stratified seeded sampling, CIFAR-10 parquet/npz decoding, hub helpers (no network)."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

pytest.importorskip("httpx")
pytest.importorskip("numpy")
pytest.importorskip("PIL")
pytest.importorskip("pyarrow")
pytest.importorskip("pyarrow.parquet")

import httpx
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
from PIL import Image

from redsim.ml import errors
from redsim.ml.datasets import (
    DEFAULT_WORK_DIR,
    DatasetUnavailable,
    cifar10,
    image_hub,
    work_dir,
)
from redsim.ml.datasets.sampling import (
    as_model_input,
    per_class_counts,
    stratified_indices,
    stratified_sample,
)
from redsim.ml.errors import TargetUnavailable
from redsim.ml.targets.base import Sample

pytestmark = pytest.mark.ml


# ----------------------------------------------------------------------------------------
# sampling
# ----------------------------------------------------------------------------------------

def _labels(*counts: int) -> np.ndarray:
    return np.concatenate([np.full(c, i, dtype=np.int64) for i, c in enumerate(counts)])


def test_stratified_indices_balanced_and_seeded() -> None:
    y = _labels(50, 50, 50)
    idx = stratified_indices(y, 30, seed=0)
    assert idx.shape == (30,)
    assert len(set(idx.tolist())) == 30
    assert np.bincount(y[idx], minlength=3).tolist() == [10, 10, 10]
    assert np.array_equal(idx, stratified_indices(y, 30, seed=0))
    assert not np.array_equal(idx, stratified_indices(y, 30, seed=1))


def test_stratified_indices_redistributes_when_a_class_is_exhausted() -> None:
    y = _labels(5, 50, 50)
    idx = stratified_indices(y, 30, seed=3)
    counts = np.bincount(y[idx], minlength=3)
    assert idx.shape == (30,)
    assert counts[0] == 5                       # the small class is fully used
    assert sorted(counts[1:].tolist()) == [12, 13]   # the shortfall flows to the others
    assert len(set(idx.tolist())) == 30


def test_stratified_indices_caps_at_split_size_and_rejects_bad_n() -> None:
    y = _labels(4, 6)
    idx = stratified_indices(y, 100, seed=0)
    assert sorted(idx.tolist()) == list(range(10))
    with pytest.raises(ValueError):
        stratified_indices(y, 0, seed=0)
    with pytest.raises(ValueError):
        stratified_indices(np.empty(0, dtype=np.int64), 5, seed=0)


def test_stratified_sample_scales_uint8_and_maps_source_indices() -> None:
    y = _labels(20, 20)
    x = np.random.default_rng(0).integers(0, 256, size=(40, 3, 4, 4), dtype=np.uint8)
    source = np.arange(1000, 1040)
    s = stratified_sample(x, y, 10, seed=0, class_names=["a", "b"], source_indices=source)
    assert isinstance(s, Sample)
    assert s.x.dtype == np.float32 and s.x.min() >= 0.0 and s.x.max() <= 1.0
    assert s.x.shape == (10, 3, 4, 4) and s.y.shape == (10,)
    assert np.bincount(s.y, minlength=2).tolist() == [5, 5]
    assert s.indices.min() >= 1000 and s.class_names == ["a", "b"]
    assert np.array_equal(s.x, x[s.indices - 1000].astype(np.float32) / 255.0)
    assert per_class_counts(s.y, ["a", "b"]) == {"a": 5, "b": 5}
    assert as_model_input(np.ones((2, 3), dtype=np.float64)).dtype == np.float32
    with pytest.raises(ValueError):
        stratified_sample(x, y[:-1], 10, 0, ["a", "b"])


# ----------------------------------------------------------------------------------------
# cifar10
# ----------------------------------------------------------------------------------------

def _png(arr_hwc: np.ndarray) -> bytes:
    buf = io.BytesIO()
    Image.fromarray(arr_hwc, "RGB").save(buf, format="PNG")
    return buf.getvalue()


def test_cifar10_parquet_decodes_hf_layout(tmp_path: Path) -> None:
    rng = np.random.default_rng(0)
    imgs = rng.integers(0, 256, size=(4, 32, 32, 3), dtype=np.uint8)
    labels = [3, 0, 9, 3]
    table = pa.table({
        "img": pa.array([{"bytes": _png(im), "path": f"{i}.png"} for i, im in enumerate(imgs)],
                        type=pa.struct([("bytes", pa.binary()), ("path", pa.string())])),
        "label": pa.array(labels, type=pa.int64()),
    })
    path = tmp_path / "test.parquet"
    pq.write_table(table, path)
    x, y = cifar10.load_parquet(path)
    assert x.shape == (4, 3, 32, 32) and x.dtype == np.uint8
    assert y.tolist() == labels
    assert np.array_equal(x, imgs.transpose(0, 3, 1, 2))   # PNG is lossless
    assert len(cifar10.class_names()) == 10
    with pytest.raises(DatasetUnavailable):
        cifar10.load_parquet(tmp_path / "missing.parquet")


def test_cifar10_fixture_npz_round_trip_and_fixture_indices(tmp_path: Path) -> None:
    y = np.repeat(np.arange(10), 20)
    idx = cifar10.fixture_indices(y, per_class=5, seed=0)
    assert idx.shape == (50,) and np.bincount(y[idx], minlength=10).tolist() == [5] * 10
    assert np.array_equal(idx, np.sort(idx))
    x = np.zeros((50, 3, 32, 32), dtype=np.uint8)
    path = tmp_path / "cifar10_test_50.npz"
    digest = cifar10.save_fixture_npz(path, x, y[idx], idx, dataset_revision="abc123")
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    x2, y2, idx2 = cifar10.load_fixture_npz(path)
    assert x2.shape == (50, 3, 32, 32) and np.array_equal(y2, y[idx]) and np.array_equal(idx2, idx)
    bad = tmp_path / "bad.npz"
    np.savez(bad, x=np.zeros((3, 4)), y=np.zeros(3))
    with pytest.raises(DatasetUnavailable):
        cifar10.load_fixture_npz(bad)


def test_dataset_unavailable_is_the_spec_failure_class_and_still_a_target_unavailable() -> None:
    exc = DatasetUnavailable("slice missing")
    assert isinstance(exc, errors.DatasetUnavailable) and isinstance(exc, TargetUnavailable)
    assert exc.code == "dataset_unavailable" and isinstance(exc, errors.MLError)


def test_cifar10_synthetic_stand_in_is_seeded_and_labelled(tmp_path: Path) -> None:
    x, y = cifar10.synthetic_test_split(seed=0, n=100)
    assert x.shape == (100, 3, 32, 32) and x.dtype == np.uint8
    assert np.bincount(y, minlength=10).tolist() == [10] * 10
    x2, _ = cifar10.synthetic_test_split(seed=0, n=100)
    assert np.array_equal(x, x2) and not np.array_equal(x, cifar10.synthetic_test_split(seed=1, n=100)[0])
    with pytest.raises(ValueError):
        cifar10.synthetic_test_split(n=3)
    assert cifar10.SYNTHETIC_DATASET_ID.startswith("local:synthetic") and cifar10.DATASET_ID == "hf:uoft-cs/cifar10"
    idx = cifar10.fixture_indices(y, per_class=2, seed=0)
    path = tmp_path / cifar10.FIXTURE_NAME
    cifar10.save_fixture_npz(path, x[idx], y[idx], idx, dataset_revision="synthetic-seed-0",
                             dataset_id=cifar10.SYNTHETIC_DATASET_ID)
    assert cifar10.fixture_provenance(path) == {"dataset_id": cifar10.SYNTHETIC_DATASET_ID,
                                                "dataset_revision": "synthetic-seed-0"}
    with pytest.raises(DatasetUnavailable):
        cifar10.fixture_provenance(tmp_path / "absent.npz")


# ----------------------------------------------------------------------------------------
# image_hub (httpx.MockTransport, never the network)
# ----------------------------------------------------------------------------------------

REPO = "leibnitz-lab/military_vehicles"
SHA = "0123456789abcdef0123456789abcdef01234567"
FILES = {
    "test_coarse/Tank/0001.jpg": b"tank-bytes",
    "test_coarse/BMD/0002.jpg": b"bmd-bytes",
    "test_coarse/README.md": b"not an image",
    "train_coarse/Tank/0003.jpg": b"train-bytes",
}


class _Hub:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request.url.path)
        path = request.url.path
        if path in (f"/api/datasets/{REPO}/revision/main", f"/api/datasets/{REPO}/revision/{SHA}"):
            return httpx.Response(200, json={"sha": SHA, "siblings": [{"rfilename": f} for f in FILES]})
        prefix = f"/datasets/{REPO}/resolve/{SHA}/"
        if path.startswith(prefix):
            rel = path[len(prefix):]
            if rel in FILES:
                return httpx.Response(200, content=FILES[rel])
        return httpx.Response(404, json={"error": "not found"})


def test_work_dir_env_and_cache_layout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("REDSIM_ML_WORK_DIR", raising=False)
    assert work_dir() == Path(DEFAULT_WORK_DIR)
    monkeypatch.setenv("REDSIM_ML_WORK_DIR", str(tmp_path / "w"))
    assert work_dir() == tmp_path / "w"
    assert image_hub.dataset_cache_dir(REPO, SHA) == tmp_path / "w" / "datasets" / "leibnitz-lab--military_vehicles" / SHA
    monkeypatch.setenv("HF_ENDPOINT", "https://mirror.example/")
    assert image_hub.hub_endpoint() == "https://mirror.example"
    assert image_hub.resolve_url(REPO, "a b/c.jpg", SHA) == f"https://mirror.example/datasets/{REPO}/resolve/{SHA}/a%20b/c.jpg"


def test_resolve_revision_and_repo_files_with_mock_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HF_ENDPOINT", raising=False)
    hub = _Hub()
    with image_hub.make_client(transport=httpx.MockTransport(hub)) as client:
        assert image_hub.resolve_revision(REPO, "main", client=client) == SHA
        files = image_hub.repo_files(REPO, "main", client=client)
    assert files == sorted(FILES)
    assert image_hub.imagefolder_files(files, "test_coarse") == [
        ("test_coarse/BMD/0002.jpg", "BMD"), ("test_coarse/Tank/0001.jpg", "Tank")]
    failing = httpx.MockTransport(lambda r: httpx.Response(500))
    with image_hub.make_client(transport=failing) as client, pytest.raises(DatasetUnavailable):
        image_hub.resolve_revision(REPO, "main", client=client)


def test_download_file_verifies_digest_caches_and_refuses_escapes(monkeypatch: pytest.MonkeyPatch,
                                                                  tmp_path: Path) -> None:
    monkeypatch.delenv("HF_ENDPOINT", raising=False)
    monkeypatch.setenv("REDSIM_ML_WORK_DIR", str(tmp_path))
    hub = _Hub()
    rel = "test_coarse/Tank/0001.jpg"
    good = hashlib.sha256(FILES[rel]).hexdigest()
    with image_hub.make_client(transport=httpx.MockTransport(hub)) as client:
        dest = image_hub.download_file(REPO, rel, SHA, client=client, expected_sha256=good)
        assert dest == image_hub.dataset_cache_dir(REPO, SHA) / rel
        assert dest.read_bytes() == FILES[rel]
        assert not dest.with_name(dest.name + ".part").exists()
        n_calls = len(hub.calls)
        assert image_hub.download_file(REPO, rel, SHA, client=client, expected_sha256=good) == dest
        assert len(hub.calls) == n_calls                      # cache hit, no request
        with pytest.raises(DatasetUnavailable):
            image_hub.download_file(REPO, "test_coarse/BMD/0002.jpg", SHA, client=client,
                                    expected_sha256="00" * 32)
        assert not (image_hub.dataset_cache_dir(REPO, SHA) / "test_coarse/BMD/0002.jpg").exists()
        with pytest.raises(DatasetUnavailable):
            image_hub.download_file(REPO, "missing.jpg", SHA, client=client)
        with pytest.raises(DatasetUnavailable):
            image_hub.download_file(REPO, "../../escape.jpg", SHA, client=client)
    assert isinstance(DatasetUnavailable("x"), TargetUnavailable)


def test_fetch_imagefolder_split_downloads_only_that_split(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("HF_ENDPOINT", raising=False)
    monkeypatch.setenv("REDSIM_ML_WORK_DIR", str(tmp_path))
    hub = _Hub()
    with image_hub.make_client(transport=httpx.MockTransport(hub)) as client:
        items = image_hub.fetch_imagefolder_split(REPO, SHA, "test_coarse", client=client)
    assert [(p.name, c) for p, c in items] == [("0002.jpg", "BMD"), ("0001.jpg", "Tank")]
    assert all(p.exists() for p, _ in items)
    assert not any("train_coarse" in c for c in hub.calls if c.startswith(f"/datasets/{REPO}/resolve"))


def test_preprocess_image_resizes_shorter_side_and_center_crops(tmp_path: Path) -> None:
    wide = Image.fromarray(np.full((20, 40, 3), 200, dtype=np.uint8), "RGB")
    out = image_hub.preprocess_image(wide, 16)
    assert out.shape == (3, 16, 16) and out.dtype == np.uint8 and int(out[0, 0, 0]) == 200
    native = image_hub.preprocess_image(wide, None)
    assert native.shape == (3, 20, 40)
    a, b = tmp_path / "Tank" / "a.png", tmp_path / "BMD" / "b.png"
    a.parent.mkdir()
    b.parent.mkdir()
    Image.fromarray(np.zeros((12, 12, 3), dtype=np.uint8), "RGB").save(a)
    Image.fromarray(np.full((12, 30, 3), 255, dtype=np.uint8), "RGB").save(b)
    x, y = image_hub.imagefolder_to_arrays([(a, "Tank"), (b, "BMD")], ["BMD", "Tank"], 8)
    assert x.shape == (2, 3, 8, 8) and y.tolist() == [1, 0]
    assert int(x[1].min()) == 255
    with pytest.raises(DatasetUnavailable):
        image_hub.imagefolder_to_arrays([(a, "Unknown")], ["BMD", "Tank"], 8)
    assert json.dumps(cifar10.LICENSE)   # the fixture license note is plain text
