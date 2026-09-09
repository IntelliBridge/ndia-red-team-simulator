"""UCI SMS Spam Collection access and the text tokenizer contract (spec 11, MODALITIES-11, -13).

The corpus (Almeida and Hidalgo, 2011; CC BY 4.0 as declared on the UCI page) is
fetched once at build time by ``redsim.ml.assets.datasets`` into the local cache;
this module only reads what is already on disk: the source ``SMSSpamCollection``
TSV (``<label>\\t<message>`` per line, labels ``ham`` / ``spam``), the committed
CI fixture ``tests/ml/fixtures/sms_spam_sample.tsv`` (same layout) and the
bundled evaluation slice ``eval.jsonl`` the build writes beside the model
(``{"index", "text", "label"}`` per line, digest recorded in the asset manifest).
Nothing here fetches, and no message text is ever logged.

The tokenizer contract lives here because three consumers must agree on it: the
bundled ``TfidfVectorizer`` (``TOKEN_PATTERN``), the SHAP text masker
(``MASKER_SPLIT_PATTERN``) and the word-substitution attack. ``re.findall(r"\\w+", s)``
yields exactly the non-empty segments of ``re.split(r"\\W+", s)``, which is what
``shap.maskers.Text(r"\\W+")`` tokenises on, so one word of the attack is one
token of the explainer and one term of the model (``tokenize`` is asserted equal
to the masker's tokens in ``tests/ml/test_text_modality.py``). Message texts are
dataset content: they live in artifacts, never on an Observation or in a summary.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from redsim.ml.datasets import DatasetUnavailable
from redsim.ml.datasets.sampling import per_class_counts

DATASET_ID = "uci:sms-spam-collection"
DATASET_NAME = "UCI SMS Spam Collection"
DATASET_URL = "https://archive.ics.uci.edu/dataset/228/sms+spam+collection"
DATASET_ARCHIVE_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
SOURCE_FILE_NAME = "SMSSpamCollection"
LICENSE = "CC BY 4.0"
LICENSE_NOTE = ("CC BY 4.0 as declared on the UCI repository page for dataset 228 (verified 2026-09-09); the "
                "declaration covers the compiled corpus. Original sources: Grumbletext, the NUS SMS Corpus, "
                "Caroline Tagg's PhD thesis and SMS Spam Corpus v.0.1 (Almeida, Hidalgo and Yamakami 2011).")
CLASS_NAMES: list[str] = ["ham", "spam"]

# The tokenizer contract (see the module docstring). ``TOKEN_PATTERN`` is scikit-learn's ``token_pattern``
# (findall semantics); ``MASKER_SPLIT_PATTERN`` is the split regex handed to ``shap.maskers.Text``.
TOKEN_PATTERN = r"(?u)\w+"
MASKER_SPLIT_PATTERN = r"\W+"
LOWERCASE = True
NGRAM_RANGE: tuple[int, int] = (1, 2)

FIXTURE_NAME = "sms_spam_sample.tsv"            # committed by the wave B0 datasets track
EVAL_JSONL_NAME = "eval.jsonl"

# Spec 11.3 caveats for the corpus (MODALITIES-11, -23). Copied onto the dataset and model entries at build time
# and appended to every text campaign's limitations by the runner.
SMS_CAVEATS: tuple[str, ...] = (
    (f"{DATASET_NAME} is an open, unclassified, publicly available corpus whose licence ({LICENSE}) is stated on "
     "its distribution page (D3, spec 11.1); it is a proxy for no operational channel or deployment condition."),
    "2011-era English SMS: the spam it contains is not current smishing and results describe this snapshot only.",
    ("Class imbalance: about 87% of messages are ham, so spam per-class counts are small at the default n_samples; "
     "per-class n is always shown and macro-F1 is recorded beside accuracy."),
    ("Messages contain phone numbers and short codes as published in the corpus for over a decade; message text is "
     "dataset content that lives in artifacts only, never on an Observation, in a finding title or in a summary."),
)

_WORD_RE = re.compile(TOKEN_PATTERN)


# --------------------------------------------------------------------------------------- tokenizer contract

def tokenize(text: str) -> list[str]:
    """The ``\\w+`` tokens of ``text`` (case preserved), identical to the SHAP masker's non-empty tokens."""
    return _WORD_RE.findall(text)


def word_spans(text: str) -> list[tuple[int, int]]:
    """``(start, end)`` of every ``\\w+`` token, in order; the substitution attack edits by span."""
    return [m.span() for m in _WORD_RE.finditer(text)]


def n_words(text: str) -> int:
    return len(word_spans(text))


def changed_positions(text: str, other: str) -> list[int] | None:
    """Word positions where ``other`` differs from ``text``; ``None`` when the token counts differ (not 1:1)."""
    a, b = tokenize(text), tokenize(other)
    if len(a) != len(b):
        return None
    return [i for i, (u, v) in enumerate(zip(a, b, strict=True)) if u != v]


def edit_fraction(text: str, other: str) -> float | None:
    """Share of words changed between ``text`` and ``other`` (``None`` when not 1:1 or when ``text`` has no words)."""
    changed = changed_positions(text, other)
    total = n_words(text)
    if changed is None or total == 0:
        return None
    return len(changed) / total


# --------------------------------------------------------------------------------------- source TSV

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def encode_labels(labels: Sequence[str], class_names: Sequence[str] = CLASS_NAMES) -> np.ndarray:
    index = {name: i for i, name in enumerate(class_names)}
    try:
        return np.asarray([index[label] for label in labels], dtype=np.int64)
    except KeyError as exc:
        raise DatasetUnavailable(f"unknown class label {exc.args[0]!r}; expected one of {list(class_names)}") from None


def read_sms_tsv(path: Path) -> tuple[list[str], list[str]]:
    """``(labels, texts)`` from a ``<label>\\t<message>`` file (the UCI layout and the committed fixture).

    Blank lines are skipped and a first line reading ``label\\ttext`` is treated as a header. Any other
    malformed line or unknown label is refused with ``DatasetUnavailable``; nothing is guessed.
    """
    path = Path(path)
    if not path.is_file():
        raise DatasetUnavailable(f"SMS corpus file not found: {path}")
    labels: list[str] = []
    texts: list[str] = []
    with path.open("r", encoding="utf-8", errors="strict", newline="") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            if "\t" not in line:
                raise DatasetUnavailable(f"{path.name}:{lineno}: expected '<label>\\t<message>'")
            label, text = line.split("\t", 1)
            label = label.strip().lower()
            if lineno == 1 and label == "label" and text.strip().lower() in {"text", "message"}:
                continue
            if label not in CLASS_NAMES:
                raise DatasetUnavailable(f"{path.name}:{lineno}: unknown label {label!r}; expected {CLASS_NAMES}")
            labels.append(label)
            texts.append(text.strip())
    if not texts:
        raise DatasetUnavailable(f"{path.name} holds no rows")
    return labels, texts


@dataclass
class SmsSpamTable:
    """Rows read from one source file, with the digest that becomes ``dataset_revision``."""

    texts: list[str]
    labels: np.ndarray                      # int64 indices into ``class_names``
    label_names: list[str]
    class_names: list[str] = field(default_factory=lambda: list(CLASS_NAMES))
    source_path: Path | None = None
    source_sha256: str | None = None
    fixture_only: bool = False

    @property
    def n_rows(self) -> int:
        return len(self.texts)

    def per_class(self) -> dict[str, int]:
        return per_class_counts(self.labels, self.class_names)


def load_sms_spam(path: Path, *, expected_sha256: str | None = None, fixture_only: bool = False) -> SmsSpamTable:
    """Read a source TSV (the cached UCI file or the committed fixture) after an optional digest check."""
    path = Path(path)
    if not path.is_file():
        raise DatasetUnavailable(f"SMS corpus file not found: {path}")
    digest = sha256_file(path)
    if expected_sha256 and digest != expected_sha256.strip().lower():
        raise DatasetUnavailable(f"hash_mismatch: {path.name} has sha256 {digest}, expected {expected_sha256}")
    label_names, texts = read_sms_tsv(path)
    return SmsSpamTable(texts=texts, labels=encode_labels(label_names), label_names=label_names,
                        source_path=path, source_sha256=digest, fixture_only=fixture_only)


def fixture_path() -> Path | None:
    """The committed CI fixture ``tests/ml/fixtures/sms_spam_sample.tsv`` when this is a source checkout."""
    candidate = Path(__file__).resolve().parents[3] / "tests" / "ml" / "fixtures" / FIXTURE_NAME
    return candidate if candidate.is_file() else None


# --------------------------------------------------------------------------------------- bundled eval slice

def write_eval_jsonl(path: Path, *, texts: Sequence[str], labels: np.ndarray, indices: np.ndarray,
                     class_names: Sequence[str] = CLASS_NAMES) -> str:
    """Write the evaluation slice (one ``{"index", "text", "label"}`` object per line); return its sha256."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    y = np.asarray(labels, dtype=np.int64).reshape(-1)
    idx = np.asarray(indices, dtype=np.int64).reshape(-1)
    if not (len(texts) == y.shape[0] == idx.shape[0]):
        raise ValueError("texts, labels and indices disagree on the number of rows")
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for text, label, source_index in zip(texts, y.tolist(), idx.tolist(), strict=True):
            fh.write(json.dumps({"index": int(source_index), "text": str(text), "label": class_names[int(label)]},
                                ensure_ascii=False) + "\n")
    return sha256_file(path)


def read_eval_jsonl(path: Path, *, expected_sha256: str | None = None,
                    class_names: Sequence[str] = CLASS_NAMES) -> tuple[list[str], np.ndarray, np.ndarray]:
    """``(texts, y, indices)`` from a bundled ``eval.jsonl``; missing, tampered or malformed -> ``DatasetUnavailable``."""
    path = Path(path)
    if not path.is_file():
        raise DatasetUnavailable(f"evaluation split not found: {path}")
    if expected_sha256 and sha256_file(path) != expected_sha256.strip().lower():
        raise DatasetUnavailable(f"hash_mismatch: evaluation split {path.name} differs from the manifest digest")
    texts: list[str] = []
    labels: list[str] = []
    indices: list[int] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict) or not isinstance(row.get("text"), str):
                    raise DatasetUnavailable(f"{path.name}:{lineno}: expected an object with a string 'text'")
                texts.append(row["text"])
                labels.append(str(row.get("label")))
                indices.append(int(row.get("index", lineno - 1)))
    except (OSError, ValueError) as exc:
        raise DatasetUnavailable(f"evaluation split {path} is unreadable: {exc}") from exc
    if not texts:
        raise DatasetUnavailable(f"evaluation split {path} holds no rows")
    return texts, encode_labels(labels, class_names), np.asarray(indices, dtype=np.int64)


__all__ = [
    "CLASS_NAMES", "DATASET_ARCHIVE_URL", "DATASET_ID", "DATASET_NAME", "DATASET_URL", "EVAL_JSONL_NAME",
    "FIXTURE_NAME", "LICENSE", "LICENSE_NOTE", "LOWERCASE", "MASKER_SPLIT_PATTERN", "NGRAM_RANGE", "SMS_CAVEATS",
    "SOURCE_FILE_NAME", "TOKEN_PATTERN", "SmsSpamTable", "changed_positions", "edit_fraction", "encode_labels",
    "fixture_path", "load_sms_spam", "n_words", "read_eval_jsonl", "read_sms_tsv", "sha256_file", "tokenize",
    "word_spans", "write_eval_jsonl",
]
