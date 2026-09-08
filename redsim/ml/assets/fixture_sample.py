"""Draw the committed CI sample of the Kaggle malicious-URLs file (spec 11.3.3, 20.3, 22.2).

``tests/ml/fixtures/malicious_urls_sample.csv`` is a seeded, stratified draw
from ``malicious_phish.csv``. Its sidecar entry in
``tests/ml/fixtures/MANIFEST.json`` names the source file digest, the archive
digest, the 0-based source row indices and the sampling rule, so the draw can
be checked and repeated. CI never contacts Kaggle: this module runs once, by
hand, after ``redsim ml build-assets --dataset tabular`` has cached the file.
URL strings are data and are never fetched.

    python -m redsim.ml.assets.fixture_sample \\
        --source assets/cache/kaggle--sid321axn--malicious-urls-dataset/malicious_phish.csv
"""

from __future__ import annotations

import argparse
import csv
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from redsim.ml.assets import datasets as ds
from redsim.ml.assets.manifest import sha256_file

DEFAULT_DEST = Path(__file__).resolve().parents[3] / "tests" / "ml" / "fixtures" / "malicious_urls_sample.csv"
MAX_URL_LENGTH = 200
ELIGIBILITY_RULE = (f"printable ASCII, no whitespace, at most {MAX_URL_LENGTH} characters, exact-duplicate URL "
                    "strings dropped keeping the first occurrence")
SAMPLING_METHOD = ("seeded stratified draw: numpy default_rng(seed).choice without replacement over the eligible "
                   "rows of each class, equal count per class, rows ordered by class then by source row")


def eligible(url: str) -> bool:
    """A row that keeps the fixture plain: ASCII, printable, no whitespace, bounded length."""
    return (url.isascii() and url.isprintable() and not any(ch.isspace() for ch in url)
            and len(url) <= MAX_URL_LENGTH)


def draw_sample(urls: Sequence[str], labels: Sequence[str], *, n_per_class: int, seed: int,
                class_names: Sequence[str] = ds.URL_CLASS_NAMES) -> list[int]:
    """Positions of the draw into ``urls``: ``n_per_class`` eligible, distinct URLs per class."""
    if n_per_class < 1:
        raise ValueError("n_per_class must be >= 1")
    rng = np.random.default_rng(seed)
    seen: set[str] = set()
    pools: dict[str, list[int]] = {name: [] for name in class_names}
    for pos, (url, label) in enumerate(zip(urls, labels, strict=True)):
        if label not in pools or url in seen or not eligible(url):
            continue
        seen.add(url)
        pools[label].append(pos)
    chosen: list[int] = []
    for name in class_names:
        pool = pools[name]
        if len(pool) < n_per_class:
            raise ValueError(f"class {name!r} has only {len(pool)} eligible rows, need {n_per_class}")
        picks = rng.choice(len(pool), size=n_per_class, replace=False)
        chosen.extend(sorted(pool[int(i)] for i in picks))
    return chosen


def write_fixture_sample(source_csv: Path, dest_csv: Path, sidecar_path: Path | None = None, *,
                         n_per_class: int = 15, seed: int = 0, archive_sha256: str | None = None,
                         notes: Sequence[str] = ()) -> dict[str, Any]:
    """Write the sample CSV and its sidecar entry (merged into the sidecar file); return the entry.

    ``notes`` are appended to the entry's notes, for instance why a seed was
    chosen; the draw itself is fully described by the recorded seed and rule.
    """
    source_csv = Path(source_csv)
    dest_csv = Path(dest_csv)
    sidecar_path = Path(sidecar_path) if sidecar_path is not None else dest_csv.parent / ds.FIXTURE_SIDECAR_NAME
    indices, urls, labels = ds.read_url_rows(source_csv)
    chosen = draw_sample(urls, labels, n_per_class=n_per_class, seed=seed)
    rows = [(urls[i], labels[i]) for i in chosen]
    source_rows = [int(indices[i]) for i in chosen]

    dest_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(dest_csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(["url", "type"])
        writer.writerows(rows)

    entry: dict[str, Any] = {
        "role": "CI tabular fixture for the URL pipeline (spec 11.2, 11.3.3, 22.2)",
        "synthetic": False,
        "source_dataset_id": f"kaggle:{ds.MALICIOUS_URLS_SLUG}",
        "source_file": ds.MALICIOUS_URLS_FILE,
        "source_file_sha256": sha256_file(source_csv),
        "source_archive_sha256": archive_sha256,
        "n_source_rows": len(urls),
        "source_row_indices": source_rows,
        "source_row_indices_sha256": ds.indices_sha256(np.asarray(source_rows, dtype=np.int64)),
        "sampling": {"method": SAMPLING_METHOD, "eligibility": ELIGIBILITY_RULE, "seed": seed,
                     "n_per_class": n_per_class, "drawn_at": datetime.now(UTC).isoformat(),
                     "module": "redsim.ml.assets.fixture_sample"},
        "columns": ["url", "type"],
        "n_rows": len(rows),
        "per_class": {name: sum(1 for _, label in rows if label == name) for name in sorted(ds.URL_CLASS_NAMES)},
        "sha256": sha256_file(dest_csv),
        "notes": [
            ("Real rows of the CC0 Kaggle file. URL strings are data and are never fetched, resolved or rendered "
             "(spec 11.3.3); some named hosts were malicious when the dataset was compiled."),
            ("n_source_rows counts the data rows read (blank url or type skipped); source_row_indices are 0-based "
             "positions among the file's data rows, header excluded, in the order of the sample's rows."),
            ("Never presented as results: no demo target, no Finding, no evidence (spec 11.1). A build without "
             "Kaggle credentials trains on it and marks the dataset and model fixture_only."),
            *notes,
        ],
    }
    sidecar: dict[str, Any] = {"schema_version": 1, "files": {}}
    if sidecar_path.is_file():
        loaded = json.loads(sidecar_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            sidecar = loaded
            sidecar.setdefault("files", {})
    sidecar["files"][dest_csv.name] = entry
    sidecar_path.write_text(json.dumps(sidecar, indent=2) + "\n", encoding="utf-8")
    return entry


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m redsim.ml.assets.fixture_sample",
        description="Draw the committed CI sample from the cached Kaggle malicious_phish.csv and record its provenance.",
    )
    parser.add_argument("--source", required=True, help="Path of the cached malicious_phish.csv")
    parser.add_argument("--dest", default=str(DEFAULT_DEST), help=f"Sample CSV to write (default: {DEFAULT_DEST})")
    parser.add_argument("--sidecar", default=None, help="Sidecar MANIFEST.json (default: beside --dest)")
    parser.add_argument("--per-class", dest="per_class", type=int, default=15, help="Rows per class (default: 15)")
    parser.add_argument("--seed", type=int, default=0, help="Draw seed (default: 0)")
    parser.add_argument("--note", action="append", default=[], help="Extra sidecar note (repeatable)")
    args = parser.parse_args(argv)

    source = Path(args.source)
    archive_sha256: str | None = None
    record = source.parent / ds.KAGGLE_DOWNLOAD_RECORD
    if record.is_file():
        data = json.loads(record.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("archive"), dict):
            archive_sha256 = data["archive"].get("sha256")
    entry = write_fixture_sample(source, Path(args.dest), Path(args.sidecar) if args.sidecar else None,
                                 n_per_class=args.per_class, seed=args.seed, archive_sha256=archive_sha256,
                                 notes=args.note)
    print(f"wrote {args.dest}: {entry['n_rows']} rows, sha256 {entry['sha256'][:12]}..., drawn from "
          f"{entry['source_file']} sha256 {entry['source_file_sha256'][:12]}... ({entry['n_source_rows']} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
