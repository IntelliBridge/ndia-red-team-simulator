"""Datasets: stratified seeded sampling, CIFAR-10 parquet/npz decoding, hub helpers (no network).

Phase B (wave B0 ``datasets`` track): the UCI SMS Spam Collection fetcher, loader and committed sample; the
WordNet fetch and the tiny synonyms fixture; YOLO label parsing and the person-free detection subset selection;
the bundled training slice; and the public data repository index snapshot. Every network path runs against
``httpx.MockTransport``; the live ``INDEX.csv`` check is ``slow`` and gated by ``REDSIM_PUBLIC_DATA_CHECK=1``.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import zipfile
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
from redsim.ml.assets import datasets as ds
from redsim.ml.assets import fixture_sample as fs
from redsim.ml.assets.manifest import FileEntry, sha256_file
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


# ----------------------------------------------------------------------------------------
# Phase B: shared helpers
# ----------------------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"
SIDECAR = FIXTURES / "MANIFEST.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def test_dataset_source_falls_back_to_local_until_the_literal_gains_the_member() -> None:
    assert ds.dataset_source("kaggle") == "kaggle" and ds.dataset_source("huggingface") == "huggingface"
    # ``uci`` / ``github`` are requested additively in manifest.DatasetSource; either answer is a valid literal member.
    from typing import get_args

    from redsim.ml.assets.manifest import DatasetSource
    for preferred in ("uci", "github"):
        got = ds.dataset_source(preferred)
        assert got in get_args(DatasetSource)
        assert got == preferred or got == "local"
        note = ds._source_fallback_note(preferred)
        assert (note == []) == (got == preferred)


def test_safe_zip_member_refuses_escapes() -> None:
    assert ds._safe_zip_member("wordnet/LICENSE") == "wordnet/LICENSE"
    for bad in ("../x", "/abs", "a/../../b", ""):
        with pytest.raises(ds.DatasetUnavailable):
            ds._safe_zip_member(bad)


# ----------------------------------------------------------------------------------------
# Phase B: UCI SMS Spam Collection (MODALITIES-11 / -12)
# ----------------------------------------------------------------------------------------

def _sms_corpus(n_ham: int = 40, n_spam: int = 12) -> str:
    lines = []
    for k in range(max(n_ham, n_spam)):
        if k < n_ham:
            lines.append(f"ham\tSee you at {k} tonight, bring the notes")
        if k < n_spam:
            lines.append(f"spam\tWIN a prize now, text {80000 + k} to claim offer {k}")
    lines.insert(3, "")                       # a blank line shifts the line indices
    lines.insert(5, "junk line without a tab")
    return "\n".join(lines) + "\n"


def test_read_sms_rows_keeps_line_indices_and_skips_malformed_lines(tmp_path: Path) -> None:
    path = tmp_path / ds.SMS_SPAM_FILE
    path.write_text(_sms_corpus(), encoding="utf-8")
    indices, texts, labels = ds.read_sms_rows(path)
    assert len(texts) == len(labels) == len(indices) == 52
    raw = path.read_text(encoding="utf-8").split("\n")
    for i, text, label in zip(indices, texts, labels, strict=True):
        assert raw[i] == f"{label}\t{text}"
    assert 3 not in indices and 5 not in indices
    assert set(labels) == {"ham", "spam"}


def test_sms_spam_table_pins_the_digest_and_records_the_licence(tmp_path: Path) -> None:
    path = tmp_path / ds.SMS_SPAM_FILE
    path.write_text(_sms_corpus(), encoding="utf-8")
    with pytest.raises(ds.DatasetUnavailable, match="pinned"):
        ds.sms_spam_table(path)                                   # not the UCI bytes
    table = ds.sms_spam_table(path, pinned_sha256=None, archive_sha256=None)
    entry = table.dataset
    assert entry.id == ds.SMS_SPAM_DATASET_ID and entry.revision == sha256_file(path) == entry.source_file_sha256
    assert entry.license == "CC BY 4.0" and ds.SMS_SPAM_LICENSE_URL in (entry.license_note or "")
    assert entry.class_names == ["ham", "spam"] and entry.n_rows == 52 and entry.fixture_only is False
    assert entry.caveats == list(ds.SMS_SPAM_CAVEATS) and any("Attribution" in n for n in entry.notes)
    assert [f.path for f in entry.source_files] == [ds.SMS_SPAM_FILE]
    with_archive = ds.sms_spam_table(path, pinned_sha256=None)
    assert [f.path for f in with_archive.dataset.source_files] == [ds.SMS_SPAM_ARCHIVE_NAME, ds.SMS_SPAM_FILE]
    assert with_archive.dataset.archive_sha256 == ds.SMS_SPAM_ARCHIVE_SHA256
    assert table.per_class() == {"ham": 40, "spam": 12}
    # the pinned constants are what the UCI page and zip carried on 2026-09-09
    assert SHA256_RE.match(ds.SMS_SPAM_ARCHIVE_SHA256) and SHA256_RE.match(ds.SMS_SPAM_FILE_SHA256)
    assert ds.SMS_SPAM_LICENSE_TEXT.startswith("This dataset is licensed under a Creative Commons Attribution 4.0")


def test_sms_eval_split_is_seeded_stratified_and_disjoint(tmp_path: Path) -> None:
    path = tmp_path / ds.SMS_SPAM_FILE
    path.write_text(_sms_corpus(100, 30), encoding="utf-8")
    table = ds.sms_spam_table(path, pinned_sha256=None)
    train, ev = ds.sms_eval_split(table.labels)
    assert len(train) + len(ev) == table.n and not set(train.tolist()) & set(ev.tolist())
    assert sum(1 for i in ev if table.labels[i] == "ham") == 20 and sum(1 for i in ev if table.labels[i] == "spam") == 6
    assert np.array_equal(ev, ds.sms_eval_split(table.labels)[1])
    assert not np.array_equal(ev, ds.sms_eval_split(table.labels, seed=1)[1])

    out = tmp_path / "eval.tsv"
    written = ds.write_sms_tsv(out, table, ev)
    assert written.sha256 == sha256_file(out) and written.path == "eval.tsv"
    indices, texts, labels = ds.read_sms_tsv(out)
    assert indices == [table.row_indices[int(i)] for i in ev]
    assert texts == [table.texts[int(i)] for i in ev] and labels == [table.labels[int(i)] for i in ev]
    assert out.read_text(encoding="utf-8").splitlines()[0] == "index\tlabel\ttext"
    table.texts[int(ev[0])] = "has\ta tab"
    with pytest.raises(ValueError, match="tab"):
        ds.write_sms_tsv(tmp_path / "bad.tsv", table, ev)
    (tmp_path / "wrong.tsv").write_text("a\tb\n", encoding="utf-8")
    with pytest.raises(ds.DatasetUnavailable):
        ds.read_sms_tsv(tmp_path / "wrong.tsv")


def _sms_zip(corpus: str, readme: str = "SMS Spam Collection v.1 readme") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(ds.SMS_SPAM_FILE, corpus)
        zf.writestr(ds.SMS_SPAM_README, readme)
    return buf.getvalue()


def test_fetch_sms_spam_verifies_both_digests_and_caches(tmp_path: Path) -> None:
    corpus = _sms_corpus()
    blob = _sms_zip(corpus)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=blob)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    archive_sha = hashlib.sha256(blob).hexdigest()
    file_sha = hashlib.sha256(corpus.encode("utf-8")).hexdigest()
    with pytest.raises(ds.DatasetUnavailable, match="sha256 mismatch"):
        ds.fetch_sms_spam(client, tmp_path, expected_archive_sha256="00" * 32, expected_file_sha256=file_sha, log=lambda _: None)
    assert not (ds.sms_cache_dir(tmp_path) / ds.SMS_SPAM_ARCHIVE_NAME).exists()
    with pytest.raises(ds.DatasetUnavailable, match="pinned"):
        ds.fetch_sms_spam(client, tmp_path, expected_archive_sha256=archive_sha, expected_file_sha256="11" * 32,
                          log=lambda _: None)
    path = ds.fetch_sms_spam(client, tmp_path, expected_archive_sha256=archive_sha, expected_file_sha256=file_sha,
                             log=lambda _: None)
    assert path == ds.sms_cache_dir(tmp_path) / ds.SMS_SPAM_FILE and path.read_text(encoding="utf-8") == corpus
    record = json.loads((path.parent / ds.SMS_DOWNLOAD_RECORD).read_text(encoding="utf-8"))
    assert record["archive"]["sha256"] == archive_sha and record["file"]["sha256"] == file_sha
    assert record["license"] == "CC BY 4.0" and record["license_url"] == ds.SMS_SPAM_LICENSE_URL
    assert record["readme"]["sha256"] == hashlib.sha256(b"SMS Spam Collection v.1 readme").hexdigest()
    n = len(calls)
    assert ds.fetch_sms_spam(client, tmp_path, expected_archive_sha256=archive_sha, expected_file_sha256=file_sha,
                             log=lambda _: None) == path
    assert len(calls) == n                                        # cached, no request
    failing = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    with pytest.raises(ds.DatasetUnavailable, match="HTTP 503"):
        ds.fetch_sms_spam(failing, tmp_path / "other", expected_archive_sha256=None, expected_file_sha256=None,
                          log=lambda _: None)


def test_sms_fixture_sample_draw_is_seeded_screened_and_cited(tmp_path: Path) -> None:
    corpus = _sms_corpus(60, 40) + "spam\tXXX hot pics\nham\t" + "x" * 300 + "\nham\tSee you at 0 tonight, bring the notes\n"
    source = tmp_path / ds.SMS_SPAM_FILE
    source.write_text(corpus, encoding="utf-8")
    dest = tmp_path / "fixtures" / ds.SMS_SAMPLE_NAME
    entry = fs.write_sms_fixture_sample(source, dest, n_per_class=10, seed=3, pinned_sha256=None, archive_sha256=None)
    indices, texts, labels = ds.read_sms_tsv(dest)
    assert labels == ["ham"] * 10 + ["spam"] * 10 and len(set(texts)) == 20
    assert all(fs.eligible_sms(t) for t in texts) and not any("XXX" in t for t in texts)
    raw = corpus.split("\n")
    for i, text, label in zip(indices, texts, labels, strict=True):
        assert raw[i] == f"{label}\t{text}"
    assert entry["source_row_indices"] == indices and entry["n_rows"] == 20 and entry["synthetic"] is False
    assert entry["source_file_sha256"] == sha256_file(source) and entry["sha256"] == sha256_file(dest)
    assert entry["per_class"] == {"ham": 10, "spam": 10} and entry["sampling"]["seed"] == 3
    assert entry["license"] == "CC BY 4.0" and entry["source_dataset_id"] == ds.SMS_SPAM_DATASET_ID
    sidecar = json.loads((dest.parent / "MANIFEST.json").read_text(encoding="utf-8"))
    assert sidecar["files"][ds.SMS_SAMPLE_NAME] == entry
    again = fs.write_sms_fixture_sample(source, tmp_path / "again.tsv", n_per_class=10, seed=3, pinned_sha256=None,
                                        archive_sha256=None)
    assert again["source_row_indices"] == entry["source_row_indices"]
    table = ds.sms_sample_table(dest)
    assert table.dataset.fixture_only is True and table.dataset.sampled_from is not None
    assert table.dataset.sampled_from["source_file_sha256"] == entry["source_file_sha256"]
    assert table.row_indices == indices and table.n == 20
    with pytest.raises(ValueError, match="only"):
        fs.draw_text_sample(texts, labels, n_per_class=11, seed=0, class_names=ds.SMS_CLASS_NAMES)


def test_committed_sms_sample_matches_its_sidecar_and_loads_offline() -> None:
    sample = FIXTURES / ds.SMS_SAMPLE_NAME
    sidecar = json.loads(SIDECAR.read_text(encoding="utf-8"))["files"][ds.SMS_SAMPLE_NAME]
    assert sidecar["synthetic"] is False and sidecar["source_dataset_id"] == ds.SMS_SPAM_DATASET_ID
    assert sidecar["source_file"] == ds.SMS_SPAM_FILE
    assert sidecar["source_file_sha256"] == ds.SMS_SPAM_FILE_SHA256      # drawn from the pinned UCI file
    assert sidecar["source_archive_sha256"] == ds.SMS_SPAM_ARCHIVE_SHA256
    assert sidecar["n_source_rows"] == ds.SMS_SPAM_N_ROWS and sidecar["license"] == ds.SMS_SPAM_LICENSE
    assert sidecar["sha256"] == sha256_file(sample) and sidecar["size_bytes"] == sample.stat().st_size
    indices, texts, labels = ds.read_sms_tsv(sample)
    assert len(texts) == sidecar["n_rows"] >= 200 and indices == sidecar["source_row_indices"]
    assert len(set(indices)) == len(indices) and all(0 <= i < ds.SMS_SPAM_N_ROWS for i in indices)
    assert sidecar["source_row_indices_sha256"] == ds.indices_sha256(np.asarray(indices))
    n = sidecar["sampling"]["n_per_class"]
    assert labels == ["ham"] * n + ["spam"] * n and sidecar["per_class"] == {"ham": n, "spam": n}
    assert all(fs.eligible_sms(t) for t in texts) and len(set(texts)) == len(texts)
    table = ds.sms_sample_table(sample)
    assert table.dataset.fixture_only is True and table.dataset.license == "CC BY 4.0"
    assert table.dataset.sampled_from is not None
    assert table.dataset.sampled_from["source_file_sha256"] == ds.SMS_SPAM_FILE_SHA256
    assert ds.committed_sms_sample_path() == sample


# ----------------------------------------------------------------------------------------
# Phase B: WordNet 3.0 (cached, never republished) and the synonyms fixture
# ----------------------------------------------------------------------------------------

def _mini_wordnet() -> dict[str, str]:
    """A two-synset WordNet-format excerpt: ``quick`` (adj) and ``prize`` (noun)."""
    data_adj_lines = [
        "  1 This software and database is being provided to you, the LICENSEE ...\n",
    ]
    header = "".join(data_adj_lines)
    off1 = len(header.encode())
    syn1 = f"{off1:08d} 00 s 03 quick 0 speedy 0 fast(p) 0 000 | moving rapidly\n"
    off2 = off1 + len(syn1.encode())
    syn2 = f"{off2:08d} 00 a 02 quick 0 immediate 0 000 | performed with little delay\n"
    data_adj = header + syn1 + syn2
    index_adj = "  1 licence header\n" f"quick a 2 1 & 2 1 {off1:08d} {off2:08d}\n" f"slow a 1 0 1 0 {off1:08d}\n"
    n_header = header
    noff = len(n_header.encode())
    nsyn = f"{noff:08d} 06 n 03 prize 0 award 0 booty 1 001 @ 00000000 n 0000 | something given\n"
    data_noun = n_header + nsyn
    index_noun = "  1 licence header\n" f"prize n 1 1 @ 1 0 {noff:08d}\n"
    return {"data.adj": data_adj, "index.adj": index_adj, "data.noun": data_noun, "index.noun": index_noun}


def test_wordnet_reader_on_a_synthetic_database(tmp_path: Path) -> None:
    wn = tmp_path / "wordnet"
    wn.mkdir()
    for name, text in _mini_wordnet().items():
        (wn / name).write_text(text, encoding="utf-8")
    assert fs.wordnet_synonyms(wn, "quick", "a") == ["speedy", "fast", "immediate"]
    assert fs.wordnet_synonyms(wn, "Quick", "a") == ["speedy", "fast", "immediate"]
    assert fs.wordnet_synonyms(wn, "prize", "n") == ["award", "booty"]
    assert fs.wordnet_synonyms(wn, "absent", "n") == []
    with pytest.raises(ValueError):
        fs.wordnet_synonyms(wn, "quick", "x")
    dest = tmp_path / "synonyms_tiny.json"
    entry = fs.write_synonyms_tiny(wn, dest, words=(("quick", "a"), ("prize", "n"), ("absent", "n")), max_synonyms=2)
    data = json.loads(dest.read_text(encoding="utf-8"))
    assert data["entries"] == {"quick": {"pos": "a", "synonyms": ["speedy", "fast"]},
                               "prize": {"pos": "n", "synonyms": ["award", "booty"]}}
    assert data["skipped"] == ["absent"] and data["n_entries"] == 2
    assert data["source"]["zip_sha256"] == ds.WORDNET_ZIP_SHA256 and data["copyright"] == ds.WORDNET_COPYRIGHT
    assert entry["sha256"] == sha256_file(dest) and entry["source_dataset_id"] == ds.WORDNET_DATASET_ID
    assert json.loads((tmp_path / "MANIFEST.json").read_text())["files"]["synonyms_tiny.json"] == entry


def test_committed_synonyms_fixture_is_well_formed_and_cited() -> None:
    path = FIXTURES / "synonyms_tiny.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1 and data["n_entries"] == len(data["entries"]) >= 24
    for lemma, entry in data["entries"].items():
        assert entry["pos"] in fs.WORDNET_POS_FILES and entry["synonyms"]
        assert lemma not in entry["synonyms"] and len(entry["synonyms"]) <= data["max_synonyms_per_entry"]
    src = data["source"]
    assert src["dataset_id"] == ds.WORDNET_DATASET_ID and src["revision"] == ds.WORDNET_REVISION
    assert src["zip_sha256"] == ds.WORDNET_ZIP_SHA256 and src["license_sha256"] == ds.WORDNET_LICENSE_SHA256
    assert "Princeton" in data["license_note"] and data["copyright"] == ds.WORDNET_COPYRIGHT
    sidecar = json.loads(SIDECAR.read_text(encoding="utf-8"))["files"]["synonyms_tiny.json"]
    assert sidecar["sha256"] == sha256_file(path) and sidecar["source_file_sha256"] == ds.WORDNET_ZIP_SHA256
    assert sidecar["n_entries"] == data["n_entries"]


def _wordnet_zip(*, with_license: bool = True, escape: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("wordnet/", "")
        for name, text in _mini_wordnet().items():
            zf.writestr(f"wordnet/{name}", text)
        if with_license:
            zf.writestr(ds.WORDNET_LICENSE_MEMBER, "WordNet Release 3.0 ... " + ds.WORDNET_COPYRIGHT)
        zf.writestr(ds.WORDNET_README_MEMBER, "This is the README file for WordNet 3.0")
        if escape:
            zf.writestr("wordnet/../evil", "x")
    return buf.getvalue()


def test_fetch_wordnet_unpacks_an_nltk_data_tree_and_records_digests(tmp_path: Path) -> None:
    blob = _wordnet_zip()
    calls: list[str] = []
    client = httpx.Client(transport=httpx.MockTransport(lambda r: (calls.append(str(r.url)), httpx.Response(200, content=blob))[1]))
    digest = hashlib.sha256(blob).hexdigest()
    with pytest.raises(ds.DatasetUnavailable, match="sha256 mismatch"):
        ds.fetch_wordnet(client, tmp_path, expected_sha256="00" * 32, log=lambda _: None)
    dl = ds.fetch_wordnet(client, tmp_path, revision="abc123", expected_sha256=digest, log=lambda _: None)
    assert dl.url == ds.wordnet_url("abc123") and calls[-1] == dl.url
    assert dl.nltk_data_dir == ds.wordnet_nltk_data_dir(tmp_path)
    lic = dl.nltk_data_dir / "corpora" / "wordnet" / "LICENSE"
    assert lic.is_file() and dl.license.sha256 == sha256_file(lic) and dl.zip.sha256 == digest
    assert (dl.nltk_data_dir / "corpora" / "wordnet" / "index.adj").is_file()
    assert fs.wordnet_synonyms(dl.nltk_data_dir / "corpora" / "wordnet", "prize", "n") == ["award", "booty"]
    record = json.loads((ds.wordnet_cache_dir(tmp_path) / ds.WORDNET_DOWNLOAD_RECORD).read_text())
    assert record["republished"] is False and record["license"] == ds.WORDNET_LICENSE and record["revision"] == "abc123"
    n = len(calls)
    cached = ds.fetch_wordnet(client, tmp_path, expected_sha256=digest, log=lambda _: None)
    assert cached.zip.sha256 == digest and len(calls) == n
    entry = ds.wordnet_dataset_entry(dl)
    assert entry.id == ds.WORDNET_DATASET_ID and entry.license == ds.WORDNET_LICENSE and entry.revision == "abc123"
    assert [f.sha256 for f in entry.source_files] == [digest, dl.license.sha256] and entry.splits == {}
    # an unlicensed or escaping archive is refused
    for blob2, msg in ((_wordnet_zip(with_license=False), "unlicensed"), (_wordnet_zip(escape=True), "refusing")):
        c2 = httpx.Client(transport=httpx.MockTransport(lambda r, b=blob2: httpx.Response(200, content=b)))
        with pytest.raises(ds.DatasetUnavailable, match=msg):
            ds.fetch_wordnet(c2, tmp_path / msg, expected_sha256=None, log=lambda _: None)


# ----------------------------------------------------------------------------------------
# Phase B: detection subset (MODALITIES-27) -- YOLO labels, person-free selection, manifest
# ----------------------------------------------------------------------------------------

def test_kaggle_file_url_percent_encodes_the_path_as_one_segment() -> None:
    url = ds.kaggle_file_url(ds.MILITARY_ASSETS_SLUG, "military_object_dataset/test/labels/000001.txt")
    assert url.endswith("/military_object_dataset%2Ftest%2Flabels%2F000001.txt")
    assert url.startswith(ds.KAGGLE_DOWNLOAD.format(slug=ds.MILITARY_ASSETS_SLUG) + "/")
    assert ds.MILITARY_ASSETS_CLASS_NAMES.index("military_tank") == 2 and ds.military_assets_class_id("weapon") == 1
    with pytest.raises(ValueError):
        ds.military_assets_class_id("dragon")
    assert not set(ds.MILITARY_ASSETS_SUBSET_CLASSES) & set(ds.MILITARY_ASSETS_EXCLUDED_CLASSES)
    assert {"camouflage_soldier", "soldier", "civilian", "weapon"} <= set(ds.MILITARY_ASSETS_EXCLUDED_CLASSES)


def test_parse_yolo_labels_and_xyxy() -> None:
    boxes = ds.parse_yolo_labels("2 0.5 0.5 0.2 0.4\n\n10 0.25 0.75 0.1 0.1\n")
    assert [b.class_id for b in boxes] == [2, 10]
    assert ds.yolo_to_xyxy(boxes[0], 100, 50) == (40.0, 15.0, 60.0, 35.0)
    assert ds.yolo_to_xyxy(ds.YoloBox(2, 0.0, 0.0, 0.5, 0.5), 100, 100) == (0.0, 0.0, 25.0, 25.0)
    for bad in ("2 0.5 0.5 0.2", "x 0.5 0.5 0.2 0.4", "12 0.5 0.5 0.2 0.4", "2 1.5 0.5 0.2 0.4"):
        with pytest.raises(ds.DatasetUnavailable):
            ds.parse_yolo_labels(bad)
    assert ds.primary_class([]) is None
    assert ds.primary_class([ds.YoloBox(10, .5, .5, .1, .1), ds.YoloBox(2, .5, .5, .1, .1), ds.YoloBox(2, .1, .1, .1, .1)]) == 2
    assert ds.primary_class([ds.YoloBox(10, .5, .5, .1, .1), ds.YoloBox(2, .5, .5, .1, .1)]) == 2   # tie -> smallest id


def _label_set() -> dict[str, list[ds.YoloBox]]:
    b = ds.YoloBox
    labels: dict[str, list[ds.YoloBox]] = {}
    for k in range(30):
        labels[f"val/tank{k:03d}"] = [b(2, .5, .5, .3, .3)]
        labels[f"val/air{k:03d}"] = [b(10, .5, .5, .3, .3), b(10, .2, .2, .1, .1)]
        labels[f"test/truck{k:03d}"] = [b(3, .5, .5, .3, .3), b(4, .1, .1, .1, .1)]   # truck primary, vehicle second
    labels["val/soldier_and_tank"] = [b(2, .5, .5, .3, .3), b(6, .1, .1, .1, .1)]       # person box: dropped
    labels["val/weapon"] = [b(1, .5, .5, .3, .3)]
    labels["val/warship"] = [b(11, .5, .5, .3, .3)]                                      # not a keep class: dropped
    labels["val/empty"] = []
    return labels


def test_select_detection_subset_excludes_person_weapon_and_unmodelled_images() -> None:
    labels = _label_set()
    keep = [ds.military_assets_class_id(c) for c in ds.MILITARY_ASSETS_SUBSET_CLASSES]
    excl = [ds.military_assets_class_id(c) for c in ds.MILITARY_ASSETS_EXCLUDED_CLASSES]
    chosen = ds.select_detection_subset(labels, keep_classes=keep, exclude_classes=excl, n=30, seed=0)
    assert len(chosen) == 30 and chosen == sorted(chosen)
    assert not any(k in chosen for k in ("val/soldier_and_tank", "val/weapon", "val/warship", "val/empty"))
    prim = [ds.MILITARY_ASSETS_CLASS_NAMES[ds.primary_class(labels[k])] for k in chosen]   # type: ignore[index]
    assert prim.count("military_tank") == 10 and prim.count("military_aircraft") == 10 and prim.count("military_truck") == 10
    assert chosen == ds.select_detection_subset(labels, keep_classes=keep, exclude_classes=excl, n=30, seed=0)
    assert chosen != ds.select_detection_subset(labels, keep_classes=keep, exclude_classes=excl, n=30, seed=1)
    assert ds.select_detection_subset({"a": []}, keep_classes=keep, exclude_classes=excl, n=5, seed=0) == []
    with pytest.raises(ValueError):
        ds.select_detection_subset(labels, keep_classes=[2, 6], exclude_classes=[6], n=5, seed=0)

    files = {}
    for k in chosen:
        files[k] = FileEntry(path=f"images/{k}.jpg", sha256="ab" * 32, size_bytes=10)
        files[k + ".txt"] = FileEntry(path=f"labels/{k}.txt", sha256="cd" * 32, size_bytes=2)
    man = ds.detection_subset_manifest(chosen, labels, files, n_requested=30, seed=0, n_candidates=90,
                                       splits_scanned=("val", "test"), image_sizes={chosen[0]: (640, 480)})
    assert man["n_images"] == 30 and man["n_boxes"] == 10 + 20 + 20
    assert man["per_class_images"] == {"military_tank": 10, "military_truck": 10, "military_vehicle": 0, "military_aircraft": 10}
    assert man["per_class_boxes"]["military_vehicle"] == 10 and man["excluded_classes"] == list(ds.MILITARY_ASSETS_EXCLUDED_CLASSES)
    assert man["license"] == "CC BY 4.0" and "RAWx18" in man["attribution"] and man["images"][0]["width"] == 640
    assert man["selection"]["n_candidates"] == 90 and man["keep_class_ids"] == keep
    entry = ds.military_assets_dataset_entry(man, index_sha256="ef" * 32)
    assert entry.id == ds.MILITARY_ASSETS_DATASET_ID and entry.revision == "ef" * 32 and entry.source == "kaggle"
    assert entry.class_names == list(ds.MILITARY_ASSETS_SUBSET_CLASSES) and entry.n_rows == 30
    assert entry.preprocessing["excluded_classes"] == list(ds.MILITARY_ASSETS_EXCLUDED_CLASSES)


def test_fetch_kaggle_file_uses_bearer_to_kaggle_and_anonymous_to_storage(tmp_path: Path) -> None:
    auth = ds.KaggleAuth(kind="bearer", source="test", secret="fake-token-for-tests")
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.headers.get("authorization")))
        if request.url.host == "www.kaggle.com":
            assert str(request.url).endswith("%2Flabels%2F000001.txt")     # one percent-encoded segment
            return httpx.Response(302, headers={"location": "https://storage.example/blob/000001.txt"})
        return httpx.Response(200, content=b"2 0.5 0.5 0.2 0.2\n")

    dest = tmp_path / "labels" / "000001.txt"
    out = ds.fetch_kaggle_file(auth, ds.MILITARY_ASSETS_SLUG, "military_object_dataset/test/labels/000001.txt", dest,
                               transport=httpx.MockTransport(handler))
    assert out == dest and dest.read_bytes() == b"2 0.5 0.5 0.2 0.2\n"
    assert seen[0] == ("www.kaggle.com", "Bearer fake-token-for-tests") and seen[1] == ("storage.example", None)
    n = len(seen)
    ds.fetch_kaggle_file(auth, ds.MILITARY_ASSETS_SLUG, "military_object_dataset/test/labels/000001.txt", dest,
                         transport=httpx.MockTransport(handler))
    assert len(seen) == n                                             # cached


# ----------------------------------------------------------------------------------------
# Phase B: bundled training slice (ATTACKS_HARDEN-11)
# ----------------------------------------------------------------------------------------

def _image_split(n_per_class: int = 30, n_classes: int = 3, size: int = 6, seed: int = 0) -> ds.ImageSplit:
    rng = np.random.default_rng(seed)
    n = n_per_class * n_classes
    y = np.repeat(np.arange(n_classes), n_per_class)
    x = rng.integers(0, 256, size=(n, 3, size, size), dtype=np.uint8)
    return ds.ImageSplit(name="train_coarse", x=x, y=y, indices=np.arange(n, dtype=np.int64),
                         class_names=[f"c{i}" for i in range(n_classes)])


def test_write_train_slice_is_seeded_stratified_disjoint_and_digested(tmp_path: Path) -> None:
    split = _image_split()
    root = tmp_path / "assets"
    dest = root / "bundled" / "vehicles_cnn" / ds.TRAIN_SLICE_NAME
    eval_like = np.arange(0, 90, 3)                                   # pretend these rows are held out
    sub, entry = ds.write_train_slice(split, dest, root, n=30, seed=0, exclude_indices=eval_like)
    assert sub.n == entry.n == 30 and entry.per_class == {"c0": 10, "c1": 10, "c2": 10}
    assert not set(sub.indices.tolist()) & set(eval_like.tolist())
    assert entry.seed == 0 and entry.indices_sha256 == ds.indices_sha256(sub.indices)
    assert entry.file is not None and entry.file.path == "bundled/vehicles_cnn/train_slice.npz"
    assert entry.file.sha256 == sha256_file(dest) and entry.name == "train_coarse_slice"
    again, again_entry = ds.write_train_slice(split, tmp_path / "b" / "t.npz", tmp_path, n=30, seed=0,
                                              exclude_indices=eval_like)
    assert np.array_equal(again.indices, sub.indices) and again_entry.indices_sha256 == entry.indices_sha256
    other, _ = ds.write_train_slice(split, tmp_path / "c" / "t.npz", tmp_path, n=30, seed=1, exclude_indices=eval_like)
    assert not np.array_equal(other.indices, sub.indices)
    back = ds.load_train_slice(dest, expected_sha256=entry.file.sha256)
    assert np.array_equal(back.x, sub.x) and np.array_equal(back.y, sub.y) and np.array_equal(back.indices, sub.indices)
    assert back.class_names == split.class_names and back.name == "train_coarse_slice"
    assert np.array_equal(back.x, split.x[sub.indices])              # source indices point at the source rows
    with pytest.raises(ds.DatasetUnavailable, match="sha256"):
        ds.load_train_slice(dest, expected_sha256="00" * 32)
    with pytest.raises(ds.DatasetUnavailable, match="missing"):
        ds.load_train_slice(tmp_path / "absent.npz")
    np.savez(tmp_path / "bad.npz", x=np.zeros((2, 3)), y=np.zeros(2))
    with pytest.raises(ds.DatasetUnavailable):
        ds.load_train_slice(tmp_path / "bad.npz")
    assert ds.train_slice_indices(split.y, 5, 0, exclude=np.arange(90)).size == 0
    assert ds.TrainSliceOptions().n == ds.DEFAULT_TRAIN_SLICE_N
    with pytest.raises(ValueError):
        ds.TrainSliceOptions(n=0)


def test_cached_imagefolder_split_follows_the_hub_sorted_order(tmp_path: Path) -> None:
    root = tmp_path / "hf--x--y" / "sha"
    paths = ["train_coarse/Tank/b.png", "train_coarse/BMD/a.png", "train_coarse/Tank/a.png", "train_coarse/README.md",
             "train_coarse/Tank/deep/z.png"]
    for rel in paths:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if rel.endswith(".png"):
            Image.fromarray(np.full((10, 14, 3), 7, dtype=np.uint8), "RGB").save(p)
        else:
            p.write_text("x")
    split = ds.cached_imagefolder_split(root, "train_coarse", image_size=4)
    assert split.class_names == ["BMD", "Tank"] and split.y.tolist() == [0, 1, 1]      # BMD/a, Tank/a, Tank/b
    assert split.x.shape == (3, 3, 4, 4) and split.indices.tolist() == [0, 1, 2] and int(split.x[0, 0, 0, 0]) == 7
    part = ds.cached_imagefolder_split(root, "train_coarse", class_names=["BMD", "Tank"], image_size=4, positions=[2])
    assert part.indices.tolist() == [2] and part.y.tolist() == [1]
    with pytest.raises(ds.DatasetUnavailable):
        ds.cached_imagefolder_split(root, "train_coarse", class_names=["Tank"], image_size=4)
    with pytest.raises(ds.DatasetUnavailable):
        ds.cached_imagefolder_split(root, "missing", image_size=4)


# ----------------------------------------------------------------------------------------
# Phase B: the public data repository index (TESTS_DOCS-35, LLM-27) -- snapshot, no network
# ----------------------------------------------------------------------------------------

def test_public_index_snapshot_has_a_row_for_every_dataset_the_code_names() -> None:
    published, pending, fixture = set(ds.PUBLIC_DATA_FILES), set(ds.PUBLIC_DATA_PENDING), set(ds.FIXTURE_ONLY_DATASET_IDS)
    assert not (published & pending) and not (published & fixture) and not (pending & fixture)
    assert published | pending | fixture == ds.CODE_NAMED_DATASET_IDS      # every id has exactly one status
    for reason in ds.PUBLIC_DATA_PENDING.values():
        assert reason.strip() and "MODALITIES" in reason or "INTEROP" in reason
    rows = ds.read_public_index()
    assert rows and ds.missing_public_index_rows(rows) == {}
    for dataset_id, files in ds.PUBLIC_DATA_FILES.items():
        found = ds.public_index_rows_for(dataset_id, rows)
        assert set(found) == set(files), dataset_id
        for row in found.values():
            assert row["license"].strip() and row["source"].strip() and row["note"].strip()
            if row["sha256"] not in ("n/a (metadata file)",) and not row["sha256"].startswith("see "):
                assert SHA256_RE.match(row["sha256"]), row
    # the fixture-only CIFAR-10 slice is never published (spec 11.1)
    assert not any("cifar" in row["file"].lower() for row in rows)
    assert cifar10.DATASET_ID not in ds.PUBLIC_DATA_FILES


def test_public_index_pinned_digests_match_the_loader_constants() -> None:
    by_file = {row["file"]: row for row in ds.read_public_index()}
    for file, digest in ds.PUBLIC_DATA_PINNED_SHA256.items():
        assert by_file[file]["sha256"] == digest, file
    sms = by_file["data/sms_spam_collection.tsv"]
    assert int(sms["bytes"]) == ds.SMS_SPAM_FILE_SIZE and "CC BY 4.0" in sms["license"]
    garak = by_file["external/garak-probe-corpora.md"]
    assert ds.GARAK_VERSION in garak["source"] and "never re-packaged" in garak["note"]
    wordnet = by_file["external/wordnet-3.0.md"]
    assert "not republished" in wordnet["note"].lower() or "never republished" in wordnet["note"].lower()
    if ds.MILITARY_ASSETS_DATASET_ID in ds.PUBLIC_DATA_FILES:
        subset = by_file["data/military_assets_subset/"]
        assert "CC BY 4.0" in subset["license"] and ds.MILITARY_ASSETS_SLUG in subset["source"]
        assert "person and weapon classes excluded" in subset["note"]
    else:
        assert "data/military_assets_subset/" not in by_file          # pending, so no row is claimed
    for directory, digest in ds.PUBLIC_DATA_DIRECTORY_MANIFEST_SHA256.items():
        assert digest in by_file[directory]["sha256"], directory
    assert re.fullmatch(r"[0-9a-f]{64}", ds.MILITARY_ASSETS_ARCHIVE_SHA256)


def test_fixture_manifest_names_public_index_sha256() -> None:
    """The committed SMS sample was drawn from the same bytes the public repository publishes."""
    by_file = {row["file"]: row for row in ds.read_public_index()}
    sidecar = json.loads(SIDECAR.read_text(encoding="utf-8"))["files"][ds.SMS_SAMPLE_NAME]
    assert sidecar["source_file_sha256"] == by_file["data/sms_spam_collection.tsv"]["sha256"]
    assert sidecar["source_dataset_id"] in ds.PUBLIC_DATA_FILES


@pytest.mark.slow
def test_live_public_index_covers_the_snapshot() -> None:
    if os.environ.get("REDSIM_PUBLIC_DATA_CHECK") != "1":
        pytest.skip("set REDSIM_PUBLIC_DATA_CHECK=1 to compare against the live INDEX.csv")
    try:
        import truststore
        verify: object = truststore.SSLContext(__import__("ssl").PROTOCOL_TLS_CLIENT)
    except ImportError:  # pragma: no cover
        verify = True
    with httpx.Client(timeout=60, follow_redirects=True, verify=verify) as client:   # type: ignore[arg-type]
        live = ds.fetch_public_index(client)
    live_files = {row["file"]: row for row in live}
    for row in ds.read_public_index():
        assert row["file"] in live_files, row["file"]
        assert live_files[row["file"]]["sha256"] == row["sha256"], row["file"]
