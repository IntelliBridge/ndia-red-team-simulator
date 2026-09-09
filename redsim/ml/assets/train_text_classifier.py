"""The bundled text classifier ``sms_tfidf_lr`` (spec 9.2 bundled sklearn row, MODALITIES-13).

``Pipeline(TfidfVectorizer(word 1-2 grams, lowercase, token_pattern = sms_spam.TOKEN_PATTERN),
LogisticRegression)`` trained on CPU in seconds on the UCI SMS Spam Collection's
training split and saved as a joblib file. joblib is a pickle: the loader
(``redsim.ml.targets.text``) opens it only after its sha256 equals the manifest
digest, exactly as the tabular target does. ``build_text_asset(root, ...)`` is the
entry point ``redsim ml build-assets --dataset text`` (wave B2/B4 CLI wiring) calls;
it takes a source TSV or an in-memory table so tests drive it offline.

Everything measured is written into ``MANIFEST.json`` (clean accuracy on the eval
split with ``n``, per-class ``n`` / ``n_correct``, macro-F1 because the class
prior is about 87% ham) and nowhere else. The tokenizer spec the SHAP masker and
the word-substitution attack must match is written twice: as the ``text`` block
(``schema.MLModelManifest.text``, added by wave B0) and inside the build record
(``architecture.text``) so a tree built before B0's field exists still carries it.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from redsim.ml.assets import MODEL_NAMES
from redsim.ml.assets.datasets import stratified_split
from redsim.ml.assets.manifest import (
    DatasetEntry,
    FileEntry,
    ModelEntry,
    SplitEntry,
    file_entry,
    library_versions,
    sha256_file,
    stamp_manifest_sha256,
    with_dataset_caveats,
)
from redsim.ml.datasets import sms_spam
from redsim.ml.datasets.sms_spam import CLASS_NAMES, SmsSpamTable, tokenize
from redsim.ml.schema import CleanAccuracy

Log = Callable[[str], None]

TEXT_MODEL_ID = "sms_tfidf_lr"
TEXT_ARCHITECTURE_ID = "sklearn_tfidf_logreg"
TEXT_MODEL_NAME = "SMS spam classifier (TF-IDF word 1-2 grams + logistic regression)"
TEXT_DATASET_CHOICE = "text"                # the ``--dataset`` value the CLI maps to TEXT_MODEL_ID
# Realizability differs from the tabular path: an adversarial text is a constructible input. What is not verified
# is meaning and grammar (spec 12.9 analogue for text, MODALITIES-23).
TEXT_REALIZABILITY_NOTE = ("adversarial texts are realisable inputs (a substituted message can be sent as is); "
                           "semantic preservation and grammaticality are not verified")
TEXT_PIPELINE_CAVEATS: tuple[str, ...] = (
    (f"Tokenizer contract: words are the {sms_spam.TOKEN_PATTERN!r} tokens (lowercased, 1-2 grams); the SHAP masker "
     f"splits on {sms_spam.MASKER_SPLIT_PATTERN!r} and the word-substitution attack edits one such token for one, so "
     "attack, model and explainer agree on what a word is."),
    (f"Realizability: {TEXT_REALIZABILITY_NOTE}; substitutions are lexicon-bound and may be ungrammatical or change "
     "meaning (no sentence-encoder similarity constraint)."),
)


@dataclass
class TextClassifierResult:
    pipeline: Any
    class_names: list[str]
    metrics: dict[str, Any]                 # n, n_correct, clean_accuracy, macro_f1, per_class
    training: dict[str, Any]
    text_spec: dict[str, Any]               # the TextModelSpec block (tokenizer regex, lowercase, ngrams, vocab, max words)
    train_idx: np.ndarray
    eval_idx: np.ndarray
    texts: list[str]                        # de-duplicated rows, indexed by train_idx / eval_idx
    labels: np.ndarray
    n_duplicates_removed: int
    params: dict[str, Any] = field(default_factory=dict)


def classification_metrics(y_true: np.ndarray, y_pred: np.ndarray, class_names: Sequence[str]) -> dict[str, Any]:
    """n, n_correct, clean accuracy, per-class n / n_correct, macro F1 (numpy only, no torch import)."""
    yt = np.asarray(y_true).astype(np.int64).ravel()
    yp = np.asarray(y_pred).astype(np.int64).ravel()
    if yt.shape != yp.shape:
        raise ValueError("y_true and y_pred differ in length")
    n = int(yt.shape[0])
    per_class: dict[str, dict[str, int]] = {}
    f1s: list[float] = []
    for i, name in enumerate(class_names):
        mask = yt == i
        tp = int(((yp == i) & mask).sum())
        fp = int(((yp == i) & ~mask).sum())
        fn = int((mask & (yp != i)).sum())
        per_class[str(name)] = {"n": int(mask.sum()), "n_correct": tp}
        denom = 2 * tp + fp + fn
        if mask.any() or fp:
            f1s.append((2 * tp / denom) if denom else 0.0)
    n_correct = int((yt == yp).sum())
    return {"n": n, "n_correct": n_correct, "clean_accuracy": (n_correct / n) if n else 0.0,
            "macro_f1": float(np.mean(f1s)) if f1s else 0.0, "per_class": per_class}


def dedupe_texts(texts: Sequence[str], labels: Sequence[int] | np.ndarray) -> tuple[list[str], np.ndarray, int]:
    """Exact-string de-duplication, first occurrence kept (the UCI corpus repeats a few hundred messages)."""
    seen: set[str] = set()
    kept_texts: list[str] = []
    kept_labels: list[int] = []
    for text, label in zip(texts, np.asarray(labels).tolist(), strict=True):
        if text in seen:
            continue
        seen.add(text)
        kept_texts.append(text)
        kept_labels.append(int(label))
    return kept_texts, np.asarray(kept_labels, dtype=np.int64), len(texts) - len(kept_texts)


def make_pipeline(seed: int) -> tuple[Any, dict[str, Any]]:
    """The bundled pipeline and its recorded constructor parameters."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    params: dict[str, Any] = {
        "tfidf": {"token_pattern": sms_spam.TOKEN_PATTERN, "lowercase": sms_spam.LOWERCASE,
                  "ngram_range": list(sms_spam.NGRAM_RANGE), "sublinear_tf": True, "min_df": 1},
        "logreg": {"C": 10.0, "max_iter": 2000, "random_state": seed},
    }
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(token_pattern=sms_spam.TOKEN_PATTERN, lowercase=sms_spam.LOWERCASE,
                                  ngram_range=sms_spam.NGRAM_RANGE, sublinear_tf=True, min_df=1)),
        ("logreg", LogisticRegression(C=10.0, max_iter=2000, random_state=seed)),
    ])
    return pipeline, params


def text_model_spec(pipeline: Any, train_texts: Sequence[str]) -> dict[str, Any]:
    """The ``TextModelSpec`` block (MODALITIES-05): what the tokenizer is, so the masker and attack can match it.

    ``token_pattern`` is the ``schema.TextModelSpec`` name of the vectoriser's token regex, so the manifest's
    ``ModelEntry.text`` records it (a producer that emitted only ``tokenizer_regex`` left it ``None``);
    ``tokenizer_regex`` carries the same value under the name the attack and the SHAP text masker read, and
    ``masker_split_regex`` is the split regex handed to ``shap.maskers.Text``.
    """
    vectorizer = pipeline.named_steps["tfidf"]
    return {
        "token_pattern": sms_spam.TOKEN_PATTERN,
        "tokenizer_regex": sms_spam.TOKEN_PATTERN,
        "masker_split_regex": sms_spam.MASKER_SPLIT_PATTERN,
        "lowercase": bool(vectorizer.lowercase),
        "ngram_range": [int(v) for v in vectorizer.ngram_range],
        "vocabulary_size": int(len(vectorizer.vocabulary_)),
        "max_words": int(max((len(tokenize(t)) for t in train_texts), default=0)),
    }


def train_text_classifier(texts: Sequence[str], labels: Sequence[int] | np.ndarray, *, seed: int = 0,
                          holdout: float = 0.2, class_names: Sequence[str] = CLASS_NAMES,
                          log: Log = print) -> TextClassifierResult:
    """De-duplicate, split (seeded, stratified), fit the pipeline, measure it on the held-out split."""
    names = list(class_names)
    texts_d, y, n_dupes = dedupe_texts(texts, labels)
    if len(texts_d) < 2 * len(names):
        raise ValueError(f"need at least {2 * len(names)} distinct messages, got {len(texts_d)}")
    if y.min() < 0 or y.max() >= len(names):
        raise ValueError("labels fall outside the declared class list")
    train_idx, eval_idx = stratified_split(y, holdout, seed)
    if len(eval_idx) == 0:
        raise ValueError("eval split is empty; provide more rows per class")
    if len(np.unique(y[train_idx])) < 2:
        raise ValueError("the training split holds a single class; a classifier cannot be fitted")
    log(f"text classifier: {len(texts_d)} distinct messages ({n_dupes} duplicates removed), "
        f"train {len(train_idx)} / eval {len(eval_idx)}")

    pipeline, params = make_pipeline(seed)
    train_texts = [texts_d[int(i)] for i in train_idx]
    eval_texts = [texts_d[int(i)] for i in eval_idx]
    t0 = time.perf_counter()
    pipeline.fit(train_texts, y[train_idx])
    fit_s = time.perf_counter() - t0
    pred_eval = np.asarray(pipeline.predict(eval_texts), dtype=np.int64)
    metrics = classification_metrics(y[eval_idx], pred_eval, names)
    log(f"text classifier: clean accuracy {metrics['clean_accuracy']:.4f}, macro-F1 {metrics['macro_f1']:.4f} "
        f"on n={metrics['n']}")
    spec = text_model_spec(pipeline, train_texts)
    training = {
        "library": "scikit-learn", "params": params, "seed": seed, "holdout": holdout, "split_seed": seed,
        "n_train": int(len(train_idx)), "n_eval": int(len(eval_idx)), "n_duplicates_removed": n_dupes,
        "fit_wall_time_s": round(fit_s, 3), "device": "cpu", "dedupe": "exact message string, first occurrence kept",
        "text": dict(spec),
    }
    return TextClassifierResult(pipeline=pipeline, class_names=names, metrics=metrics, training=training,
                                text_spec=spec, train_idx=train_idx, eval_idx=eval_idx, texts=texts_d, labels=y,
                                n_duplicates_removed=n_dupes, params=params)


def save_text_classifier(result: TextClassifierResult, out_dir: Path, *, assets_root: Path) -> FileEntry:
    """Write ``model.joblib`` under ``out_dir``; return its manifest file entry (path relative to the root)."""
    import joblib

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / "model.joblib"
    joblib.dump(result.pipeline, model_path)
    rel = model_path.resolve().relative_to(Path(assets_root).resolve()).as_posix()
    return FileEntry(path=rel, sha256=sha256_file(model_path), size_bytes=model_path.stat().st_size)


def load_text_classifier(path: Path) -> Any:
    """Build-side reload (tests and the build's own checks). The worker loads through ``targets.text``."""
    import joblib

    # Build-side only: the file was written by this process moments earlier (see save_text_classifier).
    return joblib.load(Path(path))


# --------------------------------------------------------------------------------------- manifest entries

def sms_dataset_entry(table: SmsSpamTable) -> DatasetEntry:
    """The ``datasets[...]`` entry for the corpus rows in ``table`` (revision = the source file's sha256)."""
    # ``source`` stays ``"local"``: the manifest's DatasetSource literal knows huggingface / kaggle / local, and the
    # UCI file is read from the local cache the B0 fetcher filled. The distribution URL is recorded beside it.
    return DatasetEntry(
        id=sms_spam.DATASET_ID, source="local", revision=table.source_sha256, url=sms_spam.DATASET_URL,
        license=sms_spam.LICENSE, license_note=sms_spam.LICENSE_NOTE, class_names=list(table.class_names),
        source_files=([FileEntry(path=table.source_path.name, sha256=table.source_sha256,
                                 size_bytes=table.source_path.stat().st_size)]
                      if table.source_path is not None and table.source_sha256 else []),
        source_file_sha256=table.source_sha256, n_rows=table.n_rows, fixture_only=table.fixture_only,
        preprocessing={"tokenizer": sms_spam.TOKEN_PATTERN, "masker_split": sms_spam.MASKER_SPLIT_PATTERN,
                       "lowercase": sms_spam.LOWERCASE, "ngram_range": list(sms_spam.NGRAM_RANGE),
                       "eval_slice": "eval.jsonl holds the held-out messages (index, text, label)"},
        caveats=list(sms_spam.SMS_CAVEATS),
    )


def _dataset_dir(root: Path, entry: DatasetEntry) -> Path:
    safe_id = entry.id.replace(":", "--").replace("/", "--")
    return Path(root) / "datasets" / safe_id / (entry.revision or "unpinned")


def _per_class(labels: np.ndarray, idx: np.ndarray, class_names: Sequence[str]) -> dict[str, int]:
    counts = np.bincount(np.asarray(labels)[idx], minlength=len(class_names))
    return {name: int(counts[i]) for i, name in enumerate(class_names)}


def _indices_sha256(indices: np.ndarray) -> str:
    import hashlib

    return hashlib.sha256(np.asarray(indices, dtype=np.int64).tobytes()).hexdigest()


def write_text_eval_slice(texts: Sequence[str], labels: np.ndarray, eval_idx: np.ndarray,
                          class_names: Sequence[str], root: Path, entry: DatasetEntry) -> FileEntry:
    """Bundle the held-out messages as ``eval.jsonl`` (index, text, label); the loader consumes this file."""
    out_dir = _dataset_dir(root, entry)
    idx = np.asarray(eval_idx, dtype=np.int64)
    path = out_dir / sms_spam.EVAL_JSONL_NAME
    sms_spam.write_eval_jsonl(path, texts=[texts[int(i)] for i in idx], labels=np.asarray(labels)[idx], indices=idx,
                              class_names=class_names)
    return file_entry(Path(root), path)


def _merged_caveats(entry: DatasetEntry, extra: Sequence[str]) -> list[str]:
    """Dataset caveats -> pipeline caveats -> the build table's row (when ``build.py`` knows the id) -> extra."""
    from redsim.ml.assets import build as _build

    table_fn = getattr(_build, "dataset_caveats", None)
    if callable(table_fn):
        merged = table_fn(entry, pipeline=TEXT_PIPELINE_CAVEATS, extra=extra)
        return [str(c) for c in merged]
    out: list[str] = []
    for c in [*entry.caveats, *TEXT_PIPELINE_CAVEATS, *extra]:
        if c not in out:
            out.append(c)
    return out


def build_text_asset(root: Path, *, table: SmsSpamTable | None = None, source: Path | None = None,
                     model_id: str = TEXT_MODEL_ID, seed: int = 0, holdout: float = 0.2,
                     caveats: Sequence[str] = (), name: str | None = None, fixture_only: bool | None = None,
                     log: Log = print) -> tuple[DatasetEntry, ModelEntry]:
    """Train ``sms_tfidf_lr`` on the corpus rows and write model, eval slice and manifest entries under ``root``.

    Rows come from ``table`` (in memory) or ``source`` (a ``<label>\\t<message>`` TSV: the cached UCI file the
    B0 fetcher wrote, or the committed fixture). The dataset entry carries the corpus caveats and the tokenizer
    contract; the model entry carries a copy (spec 11.3, 14.5) and the ``text`` spec block. No network here.
    """
    root = Path(root).resolve()
    if table is None:
        if source is None:
            raise ValueError("build_text_asset needs a table or a source TSV path")
        table = sms_spam.load_sms_spam(Path(source), fixture_only=bool(fixture_only))
    elif fixture_only is not None:
        table.fixture_only = bool(fixture_only)
    class_names = list(table.class_names)
    result = train_text_classifier(table.texts, table.labels, seed=seed, holdout=holdout, class_names=class_names,
                                   log=log)
    model_file = save_text_classifier(result, root / "bundled" / model_id, assets_root=root)

    entry = sms_dataset_entry(table)
    entry.n_duplicates_removed = result.n_duplicates_removed
    entry.caveats = _merged_caveats(entry, caveats)
    entry.subject_centered = None
    eval_file = write_text_eval_slice(result.texts, result.labels, result.eval_idx, class_names, root, entry)
    entry.splits["train"] = SplitEntry(name="train", n=len(result.train_idx),
                                       per_class=_per_class(result.labels, result.train_idx, class_names),
                                       seed=seed, indices_sha256=_indices_sha256(result.train_idx))
    entry.splits["eval"] = SplitEntry(name="eval", n=len(result.eval_idx),
                                      per_class=_per_class(result.labels, result.eval_idx, class_names),
                                      seed=seed, indices_sha256=_indices_sha256(result.eval_idx), file=eval_file)

    fields: dict[str, Any] = {
        "id": model_id, "name": name or MODEL_NAMES.get(model_id, TEXT_MODEL_NAME), "modality": "text",
        "format": "sklearn_joblib", "sha256": model_file.sha256, "size_bytes": model_file.size_bytes,
        "file": model_file, "architecture_id": TEXT_ARCHITECTURE_ID,
        # ``architecture.text`` duplicates the spec block so a manifest read by a tree without
        # ``MLModelManifest.text`` (pre-B0) still tells the loader what the tokenizer is.
        "architecture": {"library": "scikit-learn", "params": result.params, "text": dict(result.text_spec)},
        "input_shape": [], "n_classes": len(class_names), "class_names": class_names,
        "dataset_id": entry.id, "dataset_revision": entry.revision, "dataset_split": "eval", "train_split": "train",
        "clean_accuracy": CleanAccuracy(value=float(result.metrics["clean_accuracy"]), n=int(result.metrics["n"]),
                                        split="eval"),
        "gradients": False,    # a TF-IDF pipeline exposes no loss gradient to ART; text attacks are adapter-native
        "license": entry.license, "source_url": entry.url, "seed": seed, "epochs": None,
        "training": result.training, "metrics": result.metrics,
        "library_versions": library_versions(("scikit-learn", "numpy", "shap")),
        "fixture_only": entry.fixture_only,
        "notes": [("Input contract: one message string per row; the pipeline lowercases and tokenises with "
                   f"{sms_spam.TOKEN_PATTERN!r} (word 1-2 grams)."),
                  "Clean accuracy and macro-F1 are measured on the full held-out evaluation split at build time.",
                  "No ART estimator: the word-substitution attack queries predict_proba directly (black-box)."],
        "text": dict(result.text_spec),   # MLModelManifest.text (B0); ignored by a manifest schema without it
    }
    model = ModelEntry(**fields)
    model = stamp_manifest_sha256(with_dataset_caveats(model, entry))
    log(f"{model_id}: clean accuracy {result.metrics['clean_accuracy']:.4f} on n={result.metrics['n']}, "
        f"macro-F1 {result.metrics['macro_f1']:.4f}, model sha256 {model.sha256[:12]}..., "
        f"{len(entry.caveats)} dataset caveat(s)")
    return entry, model


__all__ = [
    "TEXT_ARCHITECTURE_ID", "TEXT_DATASET_CHOICE", "TEXT_MODEL_ID", "TEXT_MODEL_NAME", "TEXT_PIPELINE_CAVEATS",
    "TEXT_REALIZABILITY_NOTE", "TextClassifierResult", "build_text_asset", "classification_metrics", "dedupe_texts",
    "load_text_classifier", "make_pipeline", "save_text_classifier", "sms_dataset_entry", "text_model_spec",
    "train_text_classifier", "write_text_eval_slice",
]
