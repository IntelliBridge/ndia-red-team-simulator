"""The committed URL sample is a seeded, stratified, cited draw from the Kaggle file (spec 11.3.3, 22.2).

Unit tier plus numpy. Nothing here contacts Kaggle: the draw is exercised on a
synthetic source table and the committed sample is checked against its sidecar.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")

from redsim.ml.assets import datasets as ds
from redsim.ml.assets import fixture_sample as fs

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "malicious_urls_sample.csv"
SIDECAR = FIXTURES / "MANIFEST.json"


def _source_rows(n_per_class: int = 40) -> tuple[list[str], list[str]]:
    urls: list[str] = []
    labels: list[str] = []
    for k in range(n_per_class):
        for name in ds.URL_CLASS_NAMES:
            urls.append(f"http://{name}{k}.test/p/{k}")
            labels.append(name)
    urls += ["http://benign0.test/p/0", "http://has space.test/", "http://ünïcode.test/", "http://long.test/" + "a" * 300]
    labels += ["benign", "malware", "malware", "malware"]
    return urls, labels


def test_draw_sample_is_seeded_stratified_distinct_and_eligible():
    urls, labels = _source_rows()
    chosen = fs.draw_sample(urls, labels, n_per_class=5, seed=1)
    assert len(chosen) == 20
    assert [labels[i] for i in chosen] == [name for name in ds.URL_CLASS_NAMES for _ in range(5)]
    picked = [urls[i] for i in chosen]
    assert len(set(picked)) == 20 and all(fs.eligible(u) for u in picked)
    assert len(urls) - 1 not in chosen, "the duplicate URL string is skipped"
    assert fs.draw_sample(urls, labels, n_per_class=5, seed=1) == chosen
    assert fs.draw_sample(urls, labels, n_per_class=5, seed=2) != chosen
    with pytest.raises(ValueError, match="only"):
        fs.draw_sample(urls, labels, n_per_class=41, seed=0)


def test_write_fixture_sample_round_trips_and_cites_source_rows(tmp_path: Path):
    urls, labels = _source_rows()
    source = tmp_path / "malicious_phish.csv"
    with open(source, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "type"])
        writer.writerow(["", ""])                  # a blank row shifts the data-row indices
        writer.writerows(zip(urls, labels, strict=True))
    dest = tmp_path / "fixtures" / "sample.csv"
    entry = fs.write_fixture_sample(source, dest, n_per_class=3, seed=7, archive_sha256="ab" * 32)

    with open(dest, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["type"] for r in rows] == [name for name in ds.URL_CLASS_NAMES for _ in range(3)]
    with open(source, newline="", encoding="utf-8") as fh:
        source_rows = list(csv.DictReader(fh))
    for row, index in zip(rows, entry["source_row_indices"], strict=True):
        assert source_rows[index]["url"] == row["url"] and source_rows[index]["type"] == row["type"]
    assert entry["synthetic"] is False and entry["n_rows"] == 12 and entry["n_source_rows"] == len(urls)
    assert entry["per_class"] == {name: 3 for name in sorted(ds.URL_CLASS_NAMES)}
    assert entry["sha256"] == hashlib.sha256(dest.read_bytes()).hexdigest()
    assert entry["source_file_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert entry["source_archive_sha256"] == "ab" * 32 and entry["sampling"]["seed"] == 7
    assert entry["source_row_indices_sha256"] == ds.indices_sha256(np.asarray(entry["source_row_indices"]))

    sidecar = json.loads((dest.parent / "MANIFEST.json").read_text(encoding="utf-8"))
    assert sidecar["files"]["sample.csv"] == entry
    # A second run merges into the existing sidecar rather than replacing it.
    sidecar["files"]["other.csv"] = {"sha256": "x"}
    (dest.parent / "MANIFEST.json").write_text(json.dumps(sidecar))
    fs.write_fixture_sample(source, dest, n_per_class=3, seed=7)
    merged = json.loads((dest.parent / "MANIFEST.json").read_text(encoding="utf-8"))
    assert set(merged["files"]) == {"sample.csv", "other.csv"}

    table = ds.sample_url_table(dest)
    assert table.dataset.fixture_only is True and table.dataset.n_rows == 12
    assert table.dataset.sampled_from is not None
    assert table.dataset.sampled_from["source_file_sha256"] == entry["source_file_sha256"]
    assert table.dataset.sampled_from["sampling"]["seed"] == 7
    assert table.row_indices == list(range(12))


def test_main_reads_the_download_record_for_the_archive_digest(tmp_path: Path, capsys):
    urls, labels = _source_rows()
    cache = tmp_path / "kaggle--sid321axn--malicious-urls-dataset"
    cache.mkdir()
    source = cache / "malicious_phish.csv"
    with open(source, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "type"])
        writer.writerows(zip(urls, labels, strict=True))
    (cache / ds.KAGGLE_DOWNLOAD_RECORD).write_text(json.dumps({"archive": {"sha256": "cd" * 32}}))
    dest = tmp_path / "out" / "malicious_urls_sample.csv"
    assert fs.main(["--source", str(source), "--dest", str(dest), "--per-class", "2", "--seed", "3"]) == 0
    entry = json.loads((dest.parent / "MANIFEST.json").read_text())["files"]["malicious_urls_sample.csv"]
    assert entry["source_archive_sha256"] == "cd" * 32 and entry["n_rows"] == 8
    assert "8 rows" in capsys.readouterr().out


def test_committed_sample_matches_its_sidecar():
    sidecar = json.loads(SIDECAR.read_text(encoding="utf-8"))["files"]["malicious_urls_sample.csv"]
    with open(SAMPLE, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert sidecar["synthetic"] is False
    assert sidecar["source_dataset_id"] == f"kaggle:{ds.MALICIOUS_URLS_SLUG}"
    assert sidecar["source_file"] == ds.MALICIOUS_URLS_FILE
    assert re.fullmatch(r"[0-9a-f]{64}", sidecar["source_file_sha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", sidecar["source_archive_sha256"])
    indices = sidecar["source_row_indices"]
    assert len(indices) == len(rows) == sidecar["n_rows"] and len(set(indices)) == len(indices)
    assert all(0 <= i < sidecar["n_source_rows"] for i in indices)
    assert sidecar["source_row_indices_sha256"] == ds.indices_sha256(np.asarray(indices))
    assert sidecar["sampling"]["n_per_class"] * len(ds.URL_CLASS_NAMES) == sidecar["n_rows"]
    assert sidecar["sampling"]["module"] == "redsim.ml.assets.fixture_sample"
    assert [r["type"] for r in rows] == [name for name in ds.URL_CLASS_NAMES
                                         for _ in range(sidecar["sampling"]["n_per_class"])]
    assert all(fs.eligible(r["url"]) for r in rows)
    assert sidecar["sha256"] == hashlib.sha256(SAMPLE.read_bytes()).hexdigest()
