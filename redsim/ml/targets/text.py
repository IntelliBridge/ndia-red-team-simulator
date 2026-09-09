"""Bundled text target ``sms_tfidf_lr`` over ``assets/MANIFEST.json`` (spec 9.2, 12.1; MODALITIES-14).

A scikit-learn ``Pipeline(TfidfVectorizer, LogisticRegression)`` trained by
``redsim.ml.assets.train_text_classifier.build_text_asset`` and stored as the
only pickle the ML vertical opens, the ``sklearn_joblib`` bundled format: the
joblib file is deserialised only after the asset-manifest verification hashed it
(``verify_bundled_entry``) or its sha256 matched the entry digest, exactly as
``redsim.ml.targets.tabular`` does. The evaluation slice is the bundled
``eval.jsonl`` (``index, text, label`` per line) bound through
``datasets[dataset_id].splits["eval"].file`` and digest-checked the same way.

What differs from the numeric targets:

* ``sample()`` returns ``Sample.x`` as an object array of message strings (the
  campaign runner for text never coerces it to float32) with seeded, stratified
  indices into the bundled slice;
* ``predict_proba()`` takes strings; ``art_classifier()`` raises
  ``AttackNotApplicable`` because ART has no estimator for a text pipeline and
  the text attacks query ``predict_proba`` directly (black-box, adapter-native);
  ``torch_model()`` is ``None``;
* ``manifest()`` carries the ``schema.MLModelManifest`` fields plus the tokenizer
  spec (``text``: regex, lowercase flag, n-gram range, vocabulary size, max
  words) read from the entry's ``text`` block or, for a manifest written before
  that field existed, from ``architecture.text``;
* ``synonym_lexicon()`` resolves the word-substitution lexicon from the asset tree
  (``<assets>/lexicons/synonyms.json`` or ``<assets>/lexicons/nltk_data``,
  the WordNet copy wave B0 fetches), ``None`` when neither is present.

Registration at import touches no file and happens only when the ``Domain``
literal knows ``"text"`` (wave B0's schema addition): on a tree without it the
target's ``info()`` could not be represented and registering it would break the
catalog, so the instance is exposed as ``SMS_TFIDF_LR`` and left unregistered.
Import-light: scikit-learn and joblib are imported inside methods only, so the
API process may import this module (spec 9.1 rule 2).
"""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Any, get_args

import numpy as np

from redsim.ml.datasets import DatasetUnavailable
from redsim.ml.datasets.sampling import per_class_counts, stratified_indices
from redsim.ml.datasets.sms_spam import (
    LOWERCASE,
    MASKER_SPLIT_PATTERN,
    NGRAM_RANGE,
    TOKEN_PATTERN,
    read_eval_jsonl,
)
from redsim.ml.errors import AttackNotApplicable, TargetUnavailable, UnsupportedArtifact
from redsim.ml.schema import Domain, TargetInfo
from redsim.ml.targets.artifact import library_versions, model_manifest, verify_sha256
from redsim.ml.targets.base import Sample
from redsim.ml.targets.bundled import (
    BUILD_HINT,
    MANIFEST_NAME,
    EvalSplitRef,
    assets_dir,
    clean_accuracy_entry,
    manifest_entry,
    read_manifest,
    register_once,
    resolve_asset_path,
    resolve_eval_split,
    verify_bundled_entry,
    weights_ref,
)

TEXT_MODEL_ID = "sms_tfidf_lr"
TEXT_FORMATS: tuple[str, ...] = ("sklearn_joblib",)
LEXICONS_DIR = "lexicons"                       # <assets>/lexicons/{synonyms.json | nltk_data/}
NO_ART_ESTIMATOR_REASON = ("no ART estimator for text: the bundled pipeline exposes predict_proba over strings only; "
                           "text attacks are adapter-native (word_substitution queries predict_proba directly)")
TEXT_REALIZABILITY_NOTE = ("adversarial texts are realisable inputs (a substituted message can be sent as is); "
                           "semantic preservation and grammaticality are not verified")
TEXT_EXPLAINER_NOTE = "PartitionExplainer over shap.maskers.Text on predict_proba (token attributions)"
TEXT_INFO_KEYS: tuple[str, ...] = (
    "dataset_id", "dataset_revision", "dataset_split", "license", "source_url", "clean_accuracy", "sha256",
    "class_names", "format", "description", "file", "architecture_id", "manifest_sha256", "fixture_only", "text",
)


def text_domain_supported() -> bool:
    """Whether this tree's ``schema.Domain`` literal knows ``"text"`` (wave B0 adds it)."""
    return "text" in get_args(Domain)


def default_text_spec() -> dict[str, Any]:
    """The tokenizer contract of ``redsim.ml.datasets.sms_spam`` when a manifest entry declares none."""
    return {"tokenizer_regex": TOKEN_PATTERN, "masker_split_regex": MASKER_SPLIT_PATTERN, "lowercase": LOWERCASE,
            "ngram_range": list(NGRAM_RANGE), "vocabulary_size": None, "max_words": None}


def text_spec_from_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """``entry["text"]`` (the B0 manifest block), else ``entry["architecture"]["text"]``, else the defaults."""
    block = entry.get("text")
    if not isinstance(block, dict):
        arch = entry.get("architecture")
        block = arch.get("text") if isinstance(arch, dict) else None
    spec = default_text_spec()
    if isinstance(block, dict):
        spec.update({str(k): v for k, v in block.items()})
    return spec


class BundledTextTarget:
    """The bundled SMS spam classifier: TF-IDF word 1-2 grams and logistic regression over message strings."""

    def __init__(self, target_id: str = TEXT_MODEL_ID, *, name: str | None = None,
                 assets_dir: str | Path | None = None, description: str = "") -> None:
        self.id = target_id
        self._name = name or target_id
        self._assets_dir = assets_dir
        self._description = description
        self.unload()

    def unload(self) -> None:
        """Drop everything ``load()`` cached so the next call re-reads the asset tree."""
        self._entry: dict[str, Any] | None = None
        self._split: EvalSplitRef | None = None
        self._pipeline: Any = None
        self._texts: list[str] = []
        self._y: np.ndarray | None = None
        self._indices: np.ndarray | None = None
        self._class_names: list[str] = []
        self._column_order: np.ndarray | None = None
        self._sha256: str | None = None
        self._verified_by_manifest = False
        self._manifest: dict[str, Any] | None = None
        self._text_spec: dict[str, Any] = default_text_spec()
        self._lexicon: Any = None
        self._lexicon_resolved = False

    @property
    def root(self) -> Path:
        return assets_dir(self._assets_dir)

    def _read_entry(self) -> dict[str, Any] | None:
        return manifest_entry(read_manifest(self.root), self.id)

    def _require_entry(self, manifest: dict[str, Any] | None) -> dict[str, Any]:
        entry = manifest_entry(manifest, self.id)
        if entry is None:
            raise TargetUnavailable(f"bundled assets for {self.id!r} are missing: no entry in "
                                    f"{self.root / MANIFEST_NAME}; {BUILD_HINT}")
        return entry

    # -- protocol -------------------------------------------------------------------------

    def info(self) -> TargetInfo:
        base_meta: dict[str, Any] = {"source": "bundled", "assets_dir": str(self.root),
                                     "realizability": TEXT_REALIZABILITY_NOTE, "gradients": False}
        try:
            entry = self._read_entry()
        except UnsupportedArtifact as exc:
            return TargetInfo(id=self.id, name=self._name, domain="text", status="not_implemented",
                              reason=f"asset manifest unreadable: {exc}",
                              metadata={**base_meta, "availability": "manifest_invalid"})
        if entry is None:
            return TargetInfo(id=self.id, name=self._name, domain="text", status="not_implemented",
                              reason=f"bundled assets not found at {self.root / MANIFEST_NAME}; {BUILD_HINT}",
                              metadata={**base_meta, "availability": "assets_missing"})
        meta = {**base_meta, "availability": "available", **{k: entry[k] for k in TEXT_INFO_KEYS if k in entry},
                "text": text_spec_from_entry(entry)}
        if entry.get("fixture_only"):
            meta["fixture_only"] = True
        return TargetInfo(id=self.id, name=str(entry.get("name") or self._name), domain="text",
                          status="available", metadata=meta)

    def _load_pickle_after_digest(self, rel: str | None, expected: Any, *, verified: bool) -> tuple[Any, str, Path]:
        """``(pipeline, verified sha256, path)`` for the bundled joblib file, opened only after its digest matched."""
        if not isinstance(rel, str) or not rel:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} has no path for its model")
        path = resolve_asset_path(self.root, rel)
        if not path.is_file():
            raise TargetUnavailable(f"model for {self.id!r} not found at {path}; {BUILD_HINT}")
        if not isinstance(expected, str) or not expected:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} carries no sha256 for its model; a bundled joblib "
                                      "file is opened only after its digest is verified")
        digest = expected.lower() if verified else verify_sha256(path, expected.lower())
        import joblib

        # Deliberate pickle load (spec section 9.2, bundled sklearn row): the file is an in-repo asset written by
        # `redsim ml build-assets`, never an upload, and it is opened only after its sha256 matched the manifest
        # digest just above (verify_bundled_entry hashed it, or verify_sha256 did). Uploaded pickles are refused
        # in artifact.py before any deserialisation, and text uploads stay 501 (MODALITIES-24).
        try:
            obj = joblib.load(path)
        except Exception as exc:
            raise UnsupportedArtifact(f"model for {self.id!r} failed to deserialise: {exc}") from exc
        return obj, digest, path

    def load(self) -> None:
        if self._y is not None:
            return
        manifest = read_manifest(self.root)
        entry = self._require_entry(manifest)
        assert manifest is not None
        fmt = str(entry.get("format", "sklearn_joblib"))
        if fmt not in TEXT_FORMATS:
            raise UnsupportedArtifact(f"bundled text target {self.id!r} declares format {fmt!r}; expected one of "
                                      f"{TEXT_FORMATS} (text uploads are not accepted, MODALITIES-24)")
        names = [str(n) for n in (entry.get("class_names") or [])]
        if not names:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} declares no class_names")
        # Manifest verification first (spec 9.5): digests of this model's file and its evaluation slice.
        verified = verify_bundled_entry(manifest, self.root, self.id)
        rel, expected = weights_ref(entry)
        pipeline, self._sha256, model_path = self._load_pickle_after_digest(rel, expected, verified=verified)
        if not hasattr(pipeline, "predict_proba"):
            raise UnsupportedArtifact(f"bundled model for {self.id!r} has no predict_proba")

        split = resolve_eval_split(manifest, entry, self.id)
        texts, y, idx = read_eval_jsonl(resolve_asset_path(self.root, split.path),
                                        expected_sha256=None if verified else split.sha256, class_names=names)
        if y.shape[0] == 0 or len(texts) != y.shape[0]:
            raise DatasetUnavailable("text evaluation split must be a non-empty list of (text, label) rows")
        if y.min() < 0 or y.max() >= len(names):
            raise DatasetUnavailable("evaluation labels fall outside the declared class list")
        self._column_order = self._column_order_for(pipeline, names)
        try:
            probe = np.asarray(pipeline.predict_proba([texts[0]]))
        except Exception as exc:  # noqa: BLE001 - a pipeline that cannot score a string is refused, not guessed at
            raise UnsupportedArtifact(f"bundled model for {self.id!r} failed to score a message: {exc}") from exc
        if probe.ndim != 2 or probe.shape[1] != len(names):
            raise UnsupportedArtifact(f"shape_mismatch: model emits {probe.shape[1:]} classes, manifest declares "
                                      f"{len(names)}")
        spec = text_spec_from_entry(entry)
        revision = entry.get("dataset_revision") or split.revision
        self._manifest = model_manifest(
            f"manifest entry {self.id!r}",
            name=str(entry.get("name") or self._name), modality="text", format=fmt, sha256=self._sha256,
            size_bytes=model_path.stat().st_size, architecture_id=entry.get("architecture_id"),
            input_shape=[], n_classes=len(names), class_names=names,
            dataset_id=entry.get("dataset_id"), dataset_revision=revision, dataset_split=entry.get("dataset_split"),
            clean_accuracy=clean_accuracy_entry(entry.get("clean_accuracy"), entry.get("dataset_split")),
            status="available", gradients=False, bundled=True, license=entry.get("license"),
            source_url=entry.get("source_url"),
            text=spec,   # MLModelManifest.text (B0); dropped by a schema without the field
        )
        self._entry, self._split, self._class_names = entry, split, names
        self._pipeline, self._text_spec = pipeline, spec
        self._verified_by_manifest = verified
        self._texts, self._y, self._indices = list(texts), y, idx

    @staticmethod
    def _column_order_for(model: Any, class_names: list[str]) -> np.ndarray | None:
        """Map ``model.classes_`` onto the manifest class order (ints 0..K-1 or the names themselves)."""
        classes = getattr(model, "classes_", None)
        if classes is None:
            return None
        classes = list(np.asarray(classes).tolist())
        if classes == list(range(len(class_names))):
            return None
        if all(isinstance(c, str) for c in classes) and sorted(classes) == sorted(class_names):
            return np.asarray([classes.index(name) for name in class_names], dtype=np.int64)
        raise UnsupportedArtifact(f"model classes_ {classes} cannot be aligned with class_names {class_names}")

    def sample(self, n: int, seed: int) -> Sample:
        """Seeded, stratified slice of message strings (``x`` is an object array of ``str``)."""
        self.load()
        assert self._y is not None
        idx = stratified_indices(self._y, n, seed)
        source = self._indices[idx] if self._indices is not None else idx
        return Sample(x=np.asarray([self._texts[int(i)] for i in idx], dtype=object), y=self._y[idx].astype(np.int64),
                      indices=np.asarray(source, dtype=np.int64), class_names=list(self._class_names))

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        """Class probabilities for a sequence of message strings, in manifest class order (float32)."""
        self.load()
        texts = [str(t) for t in (x.tolist() if isinstance(x, np.ndarray) else list(x))]
        if not texts:
            return np.empty((0, len(self._class_names)), dtype=np.float32)
        proba = np.asarray(self._pipeline.predict_proba(texts), dtype=np.float32)
        if self._column_order is not None:
            proba = proba[:, self._column_order]
        return proba

    def art_classifier(self) -> Any:
        """Refused: ART has no estimator for a text pipeline (spec 12.1 text row; the attacks are adapter-native)."""
        self.load()
        raise AttackNotApplicable(NO_ART_ESTIMATOR_REASON)

    def torch_model(self) -> Any:
        """``None``: a TF-IDF pipeline has no differentiable module. SHAP uses the Partition explainer on strings."""
        self.load()
        return None

    def sklearn_model(self) -> Any:
        """The real pipeline (for the explainer's ``predict_proba`` and build-side checks)."""
        self.load()
        return self._pipeline

    def text_spec(self) -> dict[str, Any]:
        """The tokenizer contract the masker and the attack must match."""
        self.load()
        return dict(self._text_spec)

    def synonym_lexicon(self) -> Any:
        """The word-substitution lexicon bundled under ``<assets>/lexicons``, or ``None`` when none is present.

        Looks for ``synonyms.json`` (a ``{word: [synonyms]}`` table) and then ``nltk_data`` (WordNet as fetched by
        ``redsim ml build-assets``). Resolved once per load; the lexicon class lives with the attack.
        """
        if self._lexicon_resolved:
            return self._lexicon
        self._lexicon_resolved = True
        from redsim.ml.attacks.word_substitution import SynonymLexicon

        base = self.root / LEXICONS_DIR
        json_path = base / "synonyms.json"
        nltk_dir = base / "nltk_data"
        if json_path.is_file():
            self._lexicon = SynonymLexicon.from_json(json_path)
        elif nltk_dir.is_dir():
            self._lexicon = SynonymLexicon.from_nltk_data(nltk_dir)
        return self._lexicon

    def manifest(self) -> dict[str, Any]:
        """Raw asset entry + load-time provenance, with the validated ``MLModelManifest`` fields on top."""
        self.load()
        assert self._entry is not None and self._manifest is not None and self._y is not None
        assert self._split is not None
        lexicon = self.synonym_lexicon()
        return {
            **self._entry,
            "id": self.id, "source": "bundled", "fixture_only": bool(self._entry.get("fixture_only", False)),
            "weights_sha256_verified": self._sha256,
            "eval_split_file": self._split.path, "eval_split_sha256_verified": self._split.sha256,
            "manifest_verified": self._verified_by_manifest,
            "torch_model": None, "art_estimator": None,
            "explainer": TEXT_EXPLAINER_NOTE, "realizability": TEXT_REALIZABILITY_NOTE,
            "eval_n": int(self._y.shape[0]), "eval_per_class": per_class_counts(self._y, self._class_names),
            "lexicon": None if lexicon is None else {"source": lexicon.source, "sha256": lexicon.sha256,
                                                     "license": lexicon.license},
            "library_versions": {**library_versions("scikit-learn", "shap", "numpy"),
                                 "python": platform.python_version()},
            "assets_dir": str(self.root),
            **self._manifest,
            "text": dict(self._text_spec),
        }


SMS_TFIDF_LR = BundledTextTarget(
    TEXT_MODEL_ID, name="Bundled SMS spam classifier (TF-IDF word 1-2 grams + logistic regression)",
    description="Demo text target (UCI SMS Spam Collection, CC BY 4.0; spec 11 text row, MODALITIES-13/-14).")
if text_domain_supported():
    register_once(SMS_TFIDF_LR)

__all__ = [
    "LEXICONS_DIR", "NO_ART_ESTIMATOR_REASON", "SMS_TFIDF_LR", "TEXT_EXPLAINER_NOTE", "TEXT_FORMATS", "TEXT_INFO_KEYS",
    "TEXT_MODEL_ID", "TEXT_REALIZABILITY_NOTE", "BundledTextTarget", "default_text_spec", "text_domain_supported",
    "text_spec_from_entry",
]
