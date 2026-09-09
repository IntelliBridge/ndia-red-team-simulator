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

Phase B adds two more committed fixtures, drawn the same way (seeded, cited,
sidecar entry merged into the same ``MANIFEST.json``):

* ``--kind sms``: ``tests/ml/fixtures/sms_spam_sample.tsv``, a stratified draw from the
  cached UCI ``SMSSpamCollection`` (MODALITIES-11);
* ``--kind synonyms``: ``tests/ml/fixtures/synonyms_tiny.json``, a few dozen WordNet 3.0
  synonym sets read from the cached ``nltk_data/corpora/wordnet`` tree with the small
  reader below (no nltk dependency), for the word-substitution attack's CI path.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from redsim.ml.assets import datasets as ds
from redsim.ml.assets.manifest import sha256_file

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "ml" / "fixtures"
DEFAULT_DEST = FIXTURES_DIR / "malicious_urls_sample.csv"
DEFAULT_SMS_DEST = FIXTURES_DIR / ds.SMS_SAMPLE_NAME
DEFAULT_SYNONYMS_DEST = FIXTURES_DIR / "synonyms_tiny.json"
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
    _merge_sidecar(sidecar_path, dest_csv.name, entry)
    return entry


# ---------------------------------------------------------------------------
# SMS Spam Collection sample (MODALITIES-11): tests/ml/fixtures/sms_spam_sample.tsv
# ---------------------------------------------------------------------------

MAX_SMS_LENGTH = 200
# A committed fixture is read by every contributor and CI log; rows whose text carries this wording are skipped.
# Substring match, lower-cased; the screen is recorded in the sidecar so the draw stays reproducible.
SMS_SCREEN_WORDS: tuple[str, ...] = ("xxx", "sex", "porn", "nude", "horny", "fuck", "dick", "pussy", "slut",
                                     "bitch", "shit", "cunt", "cock")
SMS_ELIGIBILITY_RULE = (f"printable, no tab or newline, 1 to {MAX_SMS_LENGTH} characters, exact-duplicate texts dropped "
                        f"keeping the first occurrence, texts containing any of {list(SMS_SCREEN_WORDS)} (lower-cased "
                        "substring) skipped")
SMS_SAMPLING_METHOD = ("seeded stratified draw: numpy default_rng(seed).choice without replacement over the eligible "
                       "rows of each class, equal count per class, rows ordered by class then by source row")


def eligible_sms(text: str) -> bool:
    """A message that keeps the fixture plain: printable, single-line, bounded, none of the screened wording."""
    if not text or len(text) > MAX_SMS_LENGTH or not text.isprintable() or "\t" in text:
        return False
    lowered = text.lower()
    return not any(word in lowered for word in SMS_SCREEN_WORDS)


def draw_text_sample(texts: Sequence[str], labels: Sequence[str], *, n_per_class: int, seed: int,
                     class_names: Sequence[str], eligible: Callable[[str], bool] = eligible_sms) -> list[int]:
    """Positions of the draw into ``texts``: ``n_per_class`` eligible, distinct texts per class (same rule as URLs)."""
    if n_per_class < 1:
        raise ValueError("n_per_class must be >= 1")
    rng = np.random.default_rng(seed)
    seen: set[str] = set()
    pools: dict[str, list[int]] = {name: [] for name in class_names}
    for pos, (text, label) in enumerate(zip(texts, labels, strict=True)):
        if label not in pools or text in seen or not eligible(text):
            continue
        seen.add(text)
        pools[label].append(pos)
    chosen: list[int] = []
    for name in class_names:
        pool = pools[name]
        if len(pool) < n_per_class:
            raise ValueError(f"class {name!r} has only {len(pool)} eligible rows, need {n_per_class}")
        picks = rng.choice(len(pool), size=n_per_class, replace=False)
        chosen.extend(sorted(pool[int(i)] for i in picks))
    return chosen


def _merge_sidecar(sidecar_path: Path, name: str, entry: dict[str, Any]) -> None:
    sidecar: dict[str, Any] = {"schema_version": 1, "files": {}}
    if sidecar_path.is_file():
        loaded = json.loads(sidecar_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            sidecar = loaded
            sidecar.setdefault("files", {})
    sidecar["files"][name] = entry
    sidecar_path.write_text(json.dumps(sidecar, indent=2) + "\n", encoding="utf-8")


def write_sms_fixture_sample(source_tsv: Path, dest_tsv: Path, sidecar_path: Path | None = None, *,
                             n_per_class: int = 150, seed: int = 0, pinned_sha256: str | None = ds.SMS_SPAM_FILE_SHA256,
                             archive_sha256: str | None = ds.SMS_SPAM_ARCHIVE_SHA256,
                             notes: Sequence[str] = ()) -> dict[str, Any]:
    """Write the SMS sample TSV (``index label text``) and merge its sidecar entry; return the entry.

    ``pinned_sha256`` guards that the source is the UCI corpus (``None`` for a
    synthetic source in tests). The entry names the source digest, the archive
    digest, the source line indices and the sampling rule.
    """
    source_tsv = Path(source_tsv)
    dest_tsv = Path(dest_tsv)
    sidecar_path = Path(sidecar_path) if sidecar_path is not None else dest_tsv.parent / ds.FIXTURE_SIDECAR_NAME
    table = ds.sms_spam_table(source_tsv, pinned_sha256=pinned_sha256, archive_sha256=archive_sha256)
    chosen = draw_text_sample(table.texts, table.labels, n_per_class=n_per_class, seed=seed,
                              class_names=ds.SMS_CLASS_NAMES)
    written = ds.write_sms_tsv(dest_tsv, table, chosen)
    source_rows = [table.row_indices[i] for i in chosen]
    entry: dict[str, Any] = {
        "role": "CI text fixture for the SMS spam pipeline (MODALITIES-11, spec 11.1, 22.2)",
        "synthetic": False,
        "source_dataset_id": ds.SMS_SPAM_DATASET_ID,
        "source_file": ds.SMS_SPAM_FILE,
        "source_file_sha256": table.dataset.source_file_sha256,
        "source_archive_sha256": archive_sha256,
        "source_url": ds.SMS_SPAM_ARCHIVE_URL,
        "n_source_rows": table.n,
        "source_row_indices": source_rows,
        "source_row_indices_sha256": ds.indices_sha256(np.asarray(source_rows, dtype=np.int64)),
        "sampling": {"method": SMS_SAMPLING_METHOD, "eligibility": SMS_ELIGIBILITY_RULE, "seed": seed,
                     "n_per_class": n_per_class, "drawn_at": datetime.now(UTC).isoformat(),
                     "module": "redsim.ml.assets.fixture_sample"},
        "columns": list(ds.SMS_TSV_COLUMNS),
        "n_rows": len(chosen),
        "per_class": {name: sum(1 for i in chosen if table.labels[i] == name) for name in ds.SMS_CLASS_NAMES},
        "sha256": written.sha256,
        "size_bytes": written.size_bytes,
        "license": ds.SMS_SPAM_LICENSE,
        "license_url": ds.SMS_SPAM_LICENSE_URL,
        "attribution": ds.SMS_SPAM_ATTRIBUTION,
        "notes": [
            ("Real rows of the CC BY 4.0 UCI SMS Spam Collection, verbatim. Message texts are data (never dialled or "
             "sent); phone numbers and short codes in them are 2003-2011 UK and Singapore numbers as published."),
            ("n_source_rows counts the corpus lines read; source_row_indices are 0-based line positions in "
             "SMSSpamCollection in the order of the sample's rows, and the index column repeats them."),
            "Never presented as results: no demo target, no Finding, no evidence (spec 11.1).",
            *notes,
        ],
    }
    _merge_sidecar(sidecar_path, dest_tsv.name, entry)
    return entry


# ---------------------------------------------------------------------------
# WordNet 3.0 synonyms (tiny CI fixture): tests/ml/fixtures/synonyms_tiny.json
# ---------------------------------------------------------------------------

WORDNET_POS_FILES: dict[str, str] = {"n": "noun", "v": "verb", "a": "adj", "r": "adv"}
_ADJ_MARKER = re.compile(r"\((a|p|ip)\)$")

# (lemma, pos) pairs drawn from SMS-flavoured vocabulary; only entries with at least one synonym are written.
DEFAULT_SYNONYM_WORDS: tuple[tuple[str, str], ...] = (
    ("free", "a"), ("win", "v"), ("call", "v"), ("prize", "n"), ("urgent", "a"), ("claim", "v"), ("reward", "n"),
    ("cash", "n"), ("mobile", "a"), ("phone", "n"), ("message", "n"), ("friend", "n"), ("home", "n"),
    ("night", "n"), ("tomorrow", "n"), ("love", "v"), ("money", "n"), ("good", "a"), ("great", "a"),
    ("happy", "a"), ("new", "a"), ("big", "a"), ("small", "a"), ("fast", "a"), ("late", "a"), ("early", "a"),
    ("buy", "v"), ("send", "v"), ("receive", "v"), ("stop", "v"), ("reply", "v"), ("offer", "n"),
    ("chance", "n"), ("winner", "n"), ("holiday", "n"), ("ticket", "n"), ("meeting", "n"), ("work", "n"),
    ("car", "n"), ("quick", "a"), ("cheap", "a"), ("important", "a"), ("special", "a"), ("guaranteed", "a"),
    ("customer", "n"), ("service", "n"), ("contact", "v"), ("collect", "v"), ("award", "n"), ("bonus", "n"),
)


def wordnet_synonyms(wordnet_dir: Path, lemma: str, pos: str = "n") -> list[str]:
    """Synonyms of ``lemma`` (all its synsets of ``pos``) from a WordNet 3.0 database directory.

    A small reader of the ``index.<pos>`` / ``data.<pos>`` files (``wninput(5WN)``):
    the index line names the synset byte offsets, each data line lists its
    words. Multi-word lemmas come back with spaces; adjective markers such as
    ``(p)`` are stripped; the lemma itself is excluded; order is the file order.
    """
    if pos not in WORDNET_POS_FILES:
        raise ValueError(f"pos must be one of {sorted(WORDNET_POS_FILES)}, got {pos!r}")
    wordnet_dir = Path(wordnet_dir)
    index_path = wordnet_dir / f"index.{WORDNET_POS_FILES[pos]}"
    data_path = wordnet_dir / f"data.{WORDNET_POS_FILES[pos]}"
    key = lemma.strip().lower().replace(" ", "_")
    offsets: list[int] = []
    with open(index_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("  ") or not line.strip():
                continue                                    # licence header lines start with two spaces
            parts = line.split()
            if parts[0] != key:
                continue
            p_cnt = int(parts[3])
            offsets = [int(o) for o in parts[6 + p_cnt:]]
            break
    if not offsets:
        return []
    out: list[str] = []
    with open(data_path, "rb") as fh:
        for offset in offsets:
            fh.seek(offset)
            fields = fh.readline().decode("utf-8", "replace").split("|", 1)[0].split()
            if len(fields) < 4 or int(fields[0]) != offset:
                raise ValueError(f"{data_path.name}: no synset at offset {offset}")
            w_cnt = int(fields[3], 16)
            for i in range(w_cnt):
                word = _ADJ_MARKER.sub("", fields[4 + 2 * i]).replace("_", " ")
                if word.lower() != key.replace("_", " ") and word not in out:
                    out.append(word)
    return out


def write_synonyms_tiny(wordnet_dir: Path, dest: Path, sidecar_path: Path | None = None, *,
                        words: Sequence[tuple[str, str]] = DEFAULT_SYNONYM_WORDS, max_synonyms: int = 8,
                        source: dict[str, Any] | None = None) -> dict[str, Any]:
    """Write ``synonyms_tiny.json`` (``entries[lemma] = {pos, synonyms}``) and merge its sidecar entry.

    ``source`` is the WordNet provenance block (``download.json`` of ``fetch_wordnet``); the module constants
    are used when it is not given. Entries without a synonym are skipped and listed under ``skipped``.
    """
    wordnet_dir = Path(wordnet_dir)
    dest = Path(dest)
    sidecar_path = Path(sidecar_path) if sidecar_path is not None else dest.parent / ds.FIXTURE_SIDECAR_NAME
    entries: dict[str, dict[str, Any]] = {}
    skipped: list[str] = []
    for lemma, pos in words:
        syns = wordnet_synonyms(wordnet_dir, lemma, pos)[:max_synonyms]
        if syns:
            entries[lemma] = {"pos": pos, "synonyms": syns}
        else:
            skipped.append(lemma)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "role": "CI synonym fixture for the word-substitution attack (MODALITIES-15); WordNet 3.0 excerpt, never a target",
        "source": source or {
            "dataset_id": ds.WORDNET_DATASET_ID, "version": ds.WORDNET_VERSION, "repo": ds.WORDNET_REPO,
            "revision": ds.WORDNET_REVISION, "url": ds.wordnet_url(), "zip_sha256": ds.WORDNET_ZIP_SHA256,
            "license": ds.WORDNET_LICENSE, "license_sha256": ds.WORDNET_LICENSE_SHA256, "homepage": ds.WORDNET_HOMEPAGE,
        },
        "copyright": ds.WORDNET_COPYRIGHT,
        "license_note": ds.WORDNET_LICENSE_NOTE,
        "reader": "redsim.ml.assets.fixture_sample.wordnet_synonyms (index.<pos> / data.<pos>, wninput(5WN))",
        "max_synonyms_per_entry": max_synonyms,
        "n_entries": len(entries),
        "skipped": skipped,
        "entries": entries,
    }
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    entry: dict[str, Any] = {
        "role": payload["role"],
        "synthetic": False,
        "source_dataset_id": ds.WORDNET_DATASET_ID,
        "source_revision": payload["source"].get("revision"),
        "source_file": ds.WORDNET_ZIP_PATH,
        "source_file_sha256": payload["source"].get("zip_sha256"),
        "license": ds.WORDNET_LICENSE,
        "license_file_sha256": payload["source"].get("license_sha256"),
        "n_entries": len(entries),
        "sha256": sha256_file(dest),
        "size_bytes": dest.stat().st_size,
        "drawn_at": datetime.now(UTC).isoformat(),
        "module": "redsim.ml.assets.fixture_sample",
        "notes": ["An excerpt of WordNet 3.0 synsets for a fixed word list; the full database stays in the gitignored "
                  "assets cache and is never republished. The Princeton licence and copyright notice travel with the "
                  "excerpt (license_note inside the file)."],
    }
    _merge_sidecar(sidecar_path, dest.name, entry)
    return entry


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m redsim.ml.assets.fixture_sample",
        description="Draw the committed CI sample from the cached Kaggle malicious_phish.csv and record its provenance.",
    )
    parser.add_argument("--kind", choices=("urls", "sms", "synonyms"), default="urls",
                        help="Which fixture to draw (default: urls)")
    parser.add_argument("--source", required=True,
                        help="Path of the cached malicious_phish.csv / SMSSpamCollection / nltk_data corpora/wordnet dir")
    parser.add_argument("--dest", default=None, help="Fixture file to write (default: the committed path for --kind)")
    parser.add_argument("--sidecar", default=None, help="Sidecar MANIFEST.json (default: beside --dest)")
    parser.add_argument("--per-class", dest="per_class", type=int, default=None,
                        help="Rows per class (default: 15 for urls, 150 for sms)")
    parser.add_argument("--seed", type=int, default=0, help="Draw seed (default: 0)")
    parser.add_argument("--note", action="append", default=[], help="Extra sidecar note (repeatable)")
    args = parser.parse_args(argv)

    source = Path(args.source)
    sidecar = Path(args.sidecar) if args.sidecar else None
    if args.kind == "sms":
        dest = Path(args.dest) if args.dest else DEFAULT_SMS_DEST
        entry = write_sms_fixture_sample(source, dest, sidecar, n_per_class=args.per_class or 150, seed=args.seed,
                                         notes=args.note)
        print(f"wrote {dest}: {entry['n_rows']} rows, sha256 {entry['sha256'][:12]}..., drawn from "
              f"{entry['source_file']} sha256 {entry['source_file_sha256'][:12]}... ({entry['n_source_rows']} rows)")
        return 0
    if args.kind == "synonyms":
        dest = Path(args.dest) if args.dest else DEFAULT_SYNONYMS_DEST
        record_path = source.parent.parent.parent / ds.WORDNET_DOWNLOAD_RECORD    # <cache>/wordnet/download.json
        provenance: dict[str, Any] | None = None
        if record_path.is_file():
            data = json.loads(record_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                provenance = {"dataset_id": ds.WORDNET_DATASET_ID, "version": ds.WORDNET_VERSION, "repo": ds.WORDNET_REPO,
                              "revision": data.get("revision"), "url": data.get("url"),
                              "zip_sha256": (data.get("zip") or {}).get("sha256"), "license": ds.WORDNET_LICENSE,
                              "license_sha256": (data.get("license_file") or {}).get("sha256"),
                              "homepage": ds.WORDNET_HOMEPAGE}
        entry = write_synonyms_tiny(source, dest, sidecar, source=provenance)
        print(f"wrote {dest}: {entry['n_entries']} entries, sha256 {entry['sha256'][:12]}...")
        return 0
    if args.dest:
        args_dest = Path(args.dest)
    else:
        args_dest = DEFAULT_DEST
    archive_sha256: str | None = None
    record = source.parent / ds.KAGGLE_DOWNLOAD_RECORD
    if record.is_file():
        data = json.loads(record.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("archive"), dict):
            archive_sha256 = data["archive"].get("sha256")
    entry = write_fixture_sample(source, args_dest, sidecar, n_per_class=args.per_class or 15, seed=args.seed,
                                 archive_sha256=archive_sha256, notes=args.note)
    print(f"wrote {args_dest}: {entry['n_rows']} rows, sha256 {entry['sha256'][:12]}..., drawn from "
          f"{entry['source_file']} sha256 {entry['source_file_sha256'][:12]}... ({entry['n_source_rows']} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
