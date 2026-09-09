"""Bundled URL-maliciousness tabular target (spec sections 9.2, 11.3.3, 12.9).

A tree ensemble trained by ``redsim ml build-assets`` on the lexical URL
features of ``redsim/ml/datasets/url_features.py`` (imported lazily). Two
formats are accepted:

* ``sklearn_joblib`` (the build default): the joblib file is the only pickle
  the ML vertical ever opens, and it is opened only after its sha256 matches
  the asset manifest (spec section 9.2, bundled sklearn row).
* ``xgboost_json`` (``build-assets --xgboost``): ``xgboost.Booster.load_model``
  on the JSON / UBJSON file (no pickle), wrapped for ART's ``XGBoostClassifier``;
  the booster's feature count must equal the dataset manifest's. Refused with a
  clear reason when xgboost is not installed in this build.

Manifest entry shape (``redsim.ml.assets.build.build_url_asset``; see ``bundled.py`` for the tree):

    "url_trees": {
      "name": "...", "modality": "tabular", "format": "sklearn_joblib",
      "sha256": "...", "file": {"path": "bundled/url_trees/model.joblib", "sha256": "...", "size_bytes": 1},
      "class_names": ["benign", "defacement", "phishing", "malware"],
      "features": [{"name": "url_length", "dtype": "int", "min": 0, "max": 2175, "perturbable": true}, ...],
      "surrogate": {"kind": "sklearn_logistic_regression_standardized", "sha256": "...",
                    "file": {"path": "bundled/url_trees/surrogate.joblib", "sha256": "...", "size_bytes": 1},
                    "agreement_clean": {"n": 0, "n_correct": 0, "accuracy": 0.0}},
      "dataset_id": "kaggle:sid321axn/malicious-urls-dataset", "dataset_revision": "<csv sha256>",
      "dataset_split": "eval", "license": "CC0: Public Domain", "clean_accuracy": {...}
    }

with the evaluation slice at ``datasets[dataset_id].splits["eval"].file``: an ``.npz`` of
precomputed features ``x`` (n, n_features) float32, labels ``y``, ``indices`` and ``feature_names``
(``eval.npz``, written beside the human-readable ``eval.csv``). Nothing featurizes at load. The
earlier flat shape (``weights`` / ``eval_split`` / ``surrogate.path``) and the legacy id
``url_classifier`` are still read. URL strings are data: nothing here fetches, resolves or renders
one, and the target never needs the strings at runtime.

``manifest()`` returns the ``schema.MLModelManifest`` fields (``features`` as ``FeatureSpec`` rows,
``surrogate`` as ``SurrogateInfo``, validated at load) merged over the raw asset entry and the
load-time provenance (``feature_names``, ``perturbable``, ``weights_sha256_verified``, ``eval_per_class``).
"""

from __future__ import annotations

import importlib
import platform
from pathlib import Path
from typing import Any

import numpy as np

from redsim.ml.datasets import DatasetUnavailable
from redsim.ml.datasets.sampling import per_class_counts, stratified_sample
from redsim.ml.errors import TargetUnavailable, UnsupportedArtifact
from redsim.ml.schema import TargetInfo
from redsim.ml.targets.artifact import library_versions, model_manifest, sha256_file, verify_sha256
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
    surrogate_info_entry,
    surrogate_ref,
    verify_bundled_entry,
    weights_ref,
)

TABULAR_FORMATS: tuple[str, ...] = ("sklearn_joblib", "xgboost_json")

# Contract with redsim/ml/datasets/url_features.py (assets branch). Used only when that module is absent.
URL_FEATURE_NAMES: tuple[str, ...] = (
    "url_length", "digit_ratio", "letter_ratio", "count_dot", "count_hyphen", "count_at", "count_query",
    "count_percent", "count_equals", "subdomain_count", "path_depth", "has_ip_host", "is_shortener",
    "has_https", "suspicious_tld", "shannon_entropy",
)
FROZEN_URL_FEATURES: frozenset[str] = frozenset({"has_ip_host", "is_shortener", "has_https", "suspicious_tld"})
REALIZABILITY_NOTE = ("feature-space perturbation; realizability not established (a perturbed feature vector is a "
                      "realizable attack only if it maps back to a constructible URL, which Phase A does not "
                      "construct or check)")


def contract_feature_names() -> list[str]:
    """Feature names from ``url_features`` when present, else the in-tree contract copy."""
    try:
        url_features = importlib.import_module("redsim.ml.datasets.url_features")
    except ImportError:
        return list(URL_FEATURE_NAMES)
    names = getattr(url_features, "feature_names", None) or getattr(url_features, "FEATURE_NAMES", None)
    if callable(names):
        names = names()
    if isinstance(names, (list, tuple)) and all(isinstance(n, str) for n in names):
        return list(names)
    return list(URL_FEATURE_NAMES)


class BoosterModel:
    """``predict_proba`` over an ``xgboost.Booster`` loaded from JSON / UBJSON (never a pickle).

    The booster is the real model (``booster`` is what ART and ``TreeExplainer`` see); this wrapper only
    gives it the scikit-learn surface the target uses. ``classes_`` is ``None``: a booster's columns are
    the label indices 0..K-1 in order.
    """

    classes_ = None

    def __init__(self, booster: Any, n_classes: int) -> None:
        self.booster = booster
        self.n_classes = int(n_classes)

    @property
    def n_features_in_(self) -> int:
        return int(self.booster.num_features())

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        import xgboost as xgb

        raw = np.asarray(self.booster.predict(xgb.DMatrix(np.asarray(x, dtype=np.float32))), dtype=np.float32)
        if raw.ndim == 1:                         # binary objective: P(class 1)
            raw = np.stack([1.0 - raw, raw], axis=1)
        if raw.ndim != 2 or raw.shape[1] != self.n_classes:
            raise UnsupportedArtifact(f"shape_mismatch: booster emits {raw.shape[1:]} outputs for {self.n_classes} classes")
        return raw

    def predict(self, x: np.ndarray) -> np.ndarray:
        return self.predict_proba(x).argmax(axis=1)


def load_tabular_split(path: Path, *, expected_sha256: str | None = None
                       ) -> tuple[np.ndarray, np.ndarray, np.ndarray | None, list[str] | None]:
    """``(x float32, y, indices | None, feature_names | None)`` from a featurized ``.npz`` slice.

    A missing, tampered (digest) or unreadable slice raises ``DatasetUnavailable`` (spec 9.5).
    """
    if not path.is_file():
        raise DatasetUnavailable(f"evaluation split not found: {path}; {BUILD_HINT}")
    if expected_sha256 and sha256_file(path) != expected_sha256.lower():
        raise DatasetUnavailable(f"hash_mismatch: evaluation split {path.name} differs from the manifest digest")
    if path.suffix.lower() != ".npz":
        raise DatasetUnavailable(f"tabular evaluation split must be a featurized .npz, got {path.name}; a build "
                                 "before eval.npz existed must be re-run (redsim ml build-assets --dataset tabular)")
    try:
        with np.load(path, allow_pickle=False) as npz:
            x = np.asarray(npz["x"], dtype=np.float32)
            y = np.asarray(npz["y"]).reshape(-1).astype(np.int64)
            idx = np.asarray(npz["indices"]).astype(np.int64) if "indices" in npz else None
            names = [str(s) for s in np.asarray(npz["feature_names"]).tolist()] if "feature_names" in npz else None
    except (OSError, KeyError, ValueError) as exc:
        raise DatasetUnavailable(f"evaluation split {path} is unreadable: {exc}") from exc
    return x, y, idx, names


TABULAR_INFO_KEYS: tuple[str, ...] = (
    "dataset_id", "dataset_revision", "dataset_split", "license", "source_url", "clean_accuracy", "sha256",
    "class_names", "format", "features", "surrogate", "description", "file", "architecture_id",
    "manifest_sha256", "fixture_only", "extractor_version",
)


class BundledTabularTarget:
    """URL maliciousness classifier: tree ensemble over lexical URL features."""

    def __init__(self, target_id: str, *, name: str | None = None, assets_dir: str | Path | None = None,
                 description: str = "") -> None:
        self.id = target_id
        self._name = name or target_id
        self._assets_dir = assets_dir
        self._description = description
        self.unload()

    def unload(self) -> None:
        """Drop everything ``load()`` cached so the next call re-reads the asset tree."""
        self._entry: dict[str, Any] | None = None
        self._split: EvalSplitRef | None = None
        self._format: str | None = None
        self._model: Any = None            # predict_proba surface (sklearn estimator or BoosterModel)
        self._estimator: Any = None        # the real model for ART / TreeExplainer (sklearn estimator or Booster)
        self._surrogate: Any = None
        self._surrogate_clf: Any = None
        self._x: np.ndarray | None = None
        self._y: np.ndarray | None = None
        self._indices: np.ndarray | None = None
        self._class_names: list[str] = []
        self._feature_names: list[str] = []
        self._features: list[dict[str, Any]] = []
        self._column_order: np.ndarray | None = None
        self._sha256: str | None = None
        self._verified_by_manifest = False
        self._clf: Any = None
        self._manifest: dict[str, Any] | None = None

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
                                     "realizability": REALIZABILITY_NOTE}
        try:
            entry = self._read_entry()
        except UnsupportedArtifact as exc:
            return TargetInfo(id=self.id, name=self._name, domain="tabular", status="not_implemented",
                              reason=f"asset manifest unreadable: {exc}",
                              metadata={**base_meta, "availability": "manifest_invalid"})
        if entry is None:
            return TargetInfo(id=self.id, name=self._name, domain="tabular", status="not_implemented",
                              reason=f"bundled assets not found at {self.root / MANIFEST_NAME}; {BUILD_HINT}",
                              metadata={**base_meta, "availability": "assets_missing"})
        meta = {**base_meta, "availability": "available",
                **{k: entry[k] for k in TABULAR_INFO_KEYS if k in entry},
                "gradients": bool(entry.get("surrogate"))}  # only via the declared surrogate, never natively
        return TargetInfo(id=self.id, name=str(entry.get("name") or self._name), domain="tabular",
                          status="available", metadata=meta)

    def _locate(self, rel: str | None, expected: Any, what: str) -> tuple[Path, str]:
        if not isinstance(rel, str) or not rel:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} has no path for its {what}")
        path = resolve_asset_path(self.root, rel)
        if not path.is_file():
            raise TargetUnavailable(f"{what} for {self.id!r} not found at {path}; {BUILD_HINT}")
        if not isinstance(expected, str) or not expected:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} carries no sha256 for its {what}; a bundled "
                                      f"{what} is opened only after its digest is verified")
        return path, expected.lower()

    def _load_pickle_after_digest(self, rel: str | None, expected: Any, what: str, *,
                                  verified: bool = False) -> tuple[Any, str, Path]:
        """``(object, verified sha256, path)`` for a bundled joblib file, opened only after its digest matched.

        ``verified`` says the asset-manifest verification already hashed this file during this load.
        """
        path, expected_sha = self._locate(rel, expected, what)
        digest = expected_sha if verified else verify_sha256(path, expected_sha)
        import joblib

        # Deliberate pickle load (spec section 9.2, bundled sklearn row): the file is an in-repo asset written by
        # `redsim ml build-assets`, never an upload, and it is opened only after its sha256 matched the manifest
        # digest just above. Uploaded pickles are refused in artifact.py before any deserialisation.
        try:
            obj = joblib.load(path)
        except Exception as exc:
            raise UnsupportedArtifact(f"{what} for {self.id!r} failed to deserialise: {exc}") from exc
        return obj, digest, path

    def _load_xgboost_json(self, rel: str | None, expected: Any, n_classes: int, *,
                           verified: bool = False) -> tuple[BoosterModel, str, Path]:
        """``xgboost.Booster.load_model`` on a JSON / UBJSON file (no pickle), after its digest matched."""
        path, expected_sha = self._locate(rel, expected, "model")
        digest = expected_sha if verified else verify_sha256(path, expected_sha)
        if path.suffix.lower() not in {".json", ".ubj"}:
            raise UnsupportedArtifact(f"xgboost_json model for {self.id!r} must be a .json or .ubj file written by "
                                      f"Booster.save_model, got {path.name}")
        try:
            import xgboost as xgb
        except ImportError as exc:
            raise UnsupportedArtifact(f"bundled model for {self.id!r} is xgboost_json but xgboost is not installed "
                                      "in this build; rebuild with `redsim ml build-assets --dataset tabular` "
                                      "(scikit-learn ensemble) or install xgboost on the worker") from exc
        booster = xgb.Booster()
        try:
            booster.load_model(str(path))
        except Exception as exc:  # noqa: BLE001 - xgboost raises XGBoostError and ValueError
            raise UnsupportedArtifact(f"xgboost_json model for {self.id!r} failed to load: "
                                      f"{str(exc).splitlines()[0][:200]}") from exc
        return BoosterModel(booster, n_classes), digest, path

    def load(self) -> None:
        if self._x is not None:
            return
        manifest = read_manifest(self.root)
        entry = self._require_entry(manifest)
        assert manifest is not None
        fmt = str(entry.get("format", "sklearn_joblib"))
        if fmt not in TABULAR_FORMATS:
            raise UnsupportedArtifact(f"bundled tabular target {self.id!r} declares format {fmt!r}; expected one of "
                                      f"{TABULAR_FORMATS}")
        names = [str(n) for n in (entry.get("class_names") or [])]
        if not names:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} declares no class_names")
        # Manifest verification first (spec 9.5): digests of this model's files and its evaluation slice.
        verified = verify_bundled_entry(manifest, self.root, self.id)
        rel, expected = weights_ref(entry)
        if fmt == "xgboost_json":
            model, self._sha256, weights = self._load_xgboost_json(rel, expected, len(names), verified=verified)
            estimator: Any = model.booster
        else:
            model, self._sha256, weights = self._load_pickle_after_digest(rel, expected, "model", verified=verified)
            estimator = model
        if not hasattr(model, "predict_proba"):
            raise UnsupportedArtifact(f"bundled model for {self.id!r} has no predict_proba")

        split = resolve_eval_split(manifest, entry, self.id)
        x, y, idx, split_feature_names = load_tabular_split(resolve_asset_path(self.root, split.path),
                                                            expected_sha256=None if verified else split.sha256)
        if x.ndim != 2 or x.shape[0] != y.shape[0] or x.shape[0] == 0:
            raise DatasetUnavailable(f"tabular evaluation split must be a non-empty (n, n_features) table, got {x.shape}")
        if y.min() < 0 or y.max() >= len(names):
            raise DatasetUnavailable("evaluation labels fall outside the declared class list")

        features = [dict(f) for f in entry.get("features") or [] if isinstance(f, dict)]
        feature_names = [str(f["name"]) for f in features if "name" in f] or contract_feature_names()
        contract = contract_feature_names()
        if features and feature_names != contract:
            raise UnsupportedArtifact("feature order in the manifest disagrees with url_features: "
                                      f"{feature_names} vs {contract}")
        if split_feature_names is not None and split_feature_names != feature_names:
            raise DatasetUnavailable("feature order in the evaluation slice disagrees with the manifest: "
                                     f"{split_feature_names} vs {feature_names}")
        if x.shape[1] != len(feature_names):
            raise DatasetUnavailable(f"shape_mismatch: split has {x.shape[1]} features, contract declares "
                                     f"{len(feature_names)}")
        n_in = getattr(model, "n_features_in_", None)
        if n_in is not None and int(n_in) != x.shape[1]:
            raise UnsupportedArtifact(f"shape_mismatch: model expects {n_in} features, split has {x.shape[1]}")

        self._column_order = self._column_order_for(model, names)
        probe = model.predict_proba(x[:1])
        if np.asarray(probe).shape[1] != len(names):
            raise UnsupportedArtifact(f"shape_mismatch: model emits {np.asarray(probe).shape[1]} classes, manifest "
                                      f"declares {len(names)}")
        surrogate = entry.get("surrogate")
        revision = entry.get("dataset_revision") or split.revision
        self._manifest = model_manifest(
            f"manifest entry {self.id!r}",
            name=str(entry.get("name") or self._name), modality="tabular", format=fmt,
            sha256=self._sha256, size_bytes=weights.stat().st_size, architecture_id=entry.get("architecture_id"),
            input_shape=[int(x.shape[1])], n_classes=len(names), class_names=names,
            features=features or None, surrogate=surrogate_info_entry(surrogate),
            dataset_id=entry.get("dataset_id"), dataset_revision=revision,
            dataset_split=entry.get("dataset_split"),
            clean_accuracy=clean_accuracy_entry(entry.get("clean_accuracy"), entry.get("dataset_split")),
            status="available", gradients=bool(surrogate),  # only via the declared surrogate, never natively
            bundled=True, license=entry.get("license"), source_url=entry.get("source_url"),
        )
        self._entry, self._split, self._format, self._class_names = entry, split, fmt, names
        self._model, self._estimator = model, estimator
        self._features, self._feature_names = features, feature_names
        self._verified_by_manifest = verified
        self._x, self._y, self._indices = x, y, idx

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
        self.load()
        assert self._x is not None and self._y is not None
        return stratified_sample(self._x, self._y, n, seed, self._class_names, source_indices=self._indices)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        self.load()
        proba = np.asarray(self._model.predict_proba(np.asarray(x, dtype=np.float32)), dtype=np.float32)
        if self._column_order is not None:
            proba = proba[:, self._column_order]
        return proba

    def feature_ranges(self) -> tuple[np.ndarray, np.ndarray] | None:
        """Per-feature (min, max) from the manifest's training-split ranges, when declared."""
        self.load()
        if not self._features or not all("min" in f and "max" in f for f in self._features):
            return None
        mins = np.asarray([float(f["min"]) for f in self._features], dtype=np.float32)
        maxs = np.asarray([float(f["max"]) for f in self._features], dtype=np.float32)
        return mins, maxs

    def art_clip_values(self) -> tuple[np.ndarray, np.ndarray] | None:
        """``feature_ranges`` as ART ``clip_values``: a feature constant on the training split (min == max, for
        instance a binary flag that never fired) gets a zero-width range ART refuses, so its upper bound is
        nudged by 1e-6. The manifest keeps the measured ranges; only the estimator's clip box is widened, and
        such a feature stays frozen by the perturbable mask when it is a declared flag."""
        ranges = self.feature_ranges()
        if ranges is None:
            return None
        mins, maxs = ranges
        return mins, np.where(maxs > mins, maxs, mins + np.float32(1e-6)).astype(np.float32)

    def perturbable_mask(self) -> np.ndarray:
        """Declared continuous features attacks may touch; binary flags and the label are frozen (12.9)."""
        self.load()
        if self._features:
            return np.asarray([bool(f.get("perturbable", False)) for f in self._features])
        return np.asarray([name not in FROZEN_URL_FEATURES for name in self._feature_names])

    def art_classifier(self) -> Any:
        self.load()
        if self._clf is None:
            ranges = self.art_clip_values()
            if self._format == "xgboost_json":
                from art.estimators.classification import XGBoostClassifier

                assert self._x is not None
                self._clf = XGBoostClassifier(model=self._estimator, clip_values=ranges,
                                              nb_features=int(self._x.shape[1]), nb_classes=len(self._class_names))
            else:
                from art.estimators.classification import SklearnClassifier

                self._clf = SklearnClassifier(model=self._estimator, clip_values=ranges)
        return self._clf

    @staticmethod
    def _differentiable_surrogate(obj: Any) -> tuple[Any, tuple[np.ndarray, np.ndarray] | None]:
        """``(estimator, preprocessing)`` ART can differentiate through.

        The build's surrogate is a ``Pipeline(StandardScaler, LogisticRegression)``; ART wraps a Pipeline as
        a generic classifier with no ``loss_gradient``, so the scaler is folded into ART's
        ``preprocessing=(mean, std)`` and the bare logistic regression becomes the estimator. Any other
        shape is passed through unchanged (ART decides what it can differentiate).
        """
        steps = getattr(obj, "steps", None)
        if not isinstance(steps, list) or not steps:
            return obj, None
        *pre, (_, last) = steps
        mean = np.zeros(1, dtype=np.float32)
        std = np.ones(1, dtype=np.float32)
        for _, step in pre:
            if type(step).__name__ != "StandardScaler":
                return obj, None                 # not a plain standardisation: leave the pipeline as is
            if getattr(step, "mean_", None) is not None:
                mean = np.asarray(step.mean_, dtype=np.float32)
            if getattr(step, "scale_", None) is not None:
                std = np.asarray(step.scale_, dtype=np.float32)
        return last, (mean, std)

    def surrogate_art_classifier(self) -> Any:
        """ART estimator over the build-time PGD surrogate, or ``None`` when the manifest declares none.

        The estimator exposes ``loss_gradient`` for the standardised logistic-regression surrogate the build
        writes (its ``StandardScaler`` is folded into ART preprocessing); predictions equal the pipeline's.
        """
        self.load()
        assert self._entry is not None
        decl = self._entry.get("surrogate")
        if not isinstance(decl, dict):
            return None
        rel, sha = surrogate_ref(decl)
        if rel is None:
            return None
        if self._surrogate_clf is None:
            from art.estimators.classification import SklearnClassifier

            self._surrogate, _, _ = self._load_pickle_after_digest(rel, sha, "surrogate",
                                                                   verified=self._verified_by_manifest)
            estimator, preprocessing = self._differentiable_surrogate(self._surrogate)
            kwargs: dict[str, Any] = {"model": estimator, "clip_values": self.art_clip_values()}
            if preprocessing is not None:
                kwargs["preprocessing"] = preprocessing
            self._surrogate_clf = SklearnClassifier(**kwargs)
        return self._surrogate_clf

    def torch_model(self) -> Any:
        """``None``: a tree ensemble has no differentiable module. SHAP uses ``TreeExplainer`` on the real model."""
        self.load()
        return None

    def sklearn_model(self) -> Any:
        """The real estimator (sklearn ensemble, or the xgboost Booster) for ART and ``TreeExplainer``."""
        self.load()
        return self._estimator

    @property
    def feature_names(self) -> list[str]:
        self.load()
        return list(self._feature_names)

    def manifest(self) -> dict[str, Any]:
        """Raw asset entry + load-time provenance, with the validated ``MLModelManifest`` fields on top."""
        self.load()
        assert self._entry is not None and self._manifest is not None and self._y is not None and self._x is not None
        assert self._split is not None
        return {
            **self._entry,
            "id": self.id, "source": "bundled", "weights_sha256_verified": self._sha256,
            "eval_split_file": self._split.path, "eval_split_sha256_verified": self._split.sha256,
            "manifest_verified": self._verified_by_manifest,
            "feature_names": self._feature_names, "perturbable": self.perturbable_mask().tolist(),
            "n_features": int(self._x.shape[1]), "torch_model": None,
            "explainer": "TreeExplainer on the real model", "realizability": REALIZABILITY_NOTE,
            "eval_n": int(self._y.shape[0]), "eval_per_class": per_class_counts(self._y, self._class_names),
            "library_versions": {**library_versions("scikit-learn", "xgboost", "adversarial-robustness-toolbox",
                                                    "numpy"),
                                 "python": platform.python_version()},
            "assets_dir": str(self.root),
            **self._manifest,
        }


URL_TREES = register_once(BundledTabularTarget(
    "url_trees", name="Bundled URL maliciousness classifier (tree ensemble on lexical URL features)",
    description="Demo tabular target (spec section 11.3.3, Kaggle sid321axn/malicious-urls-dataset, CC0)."))

__all__ = ["FROZEN_URL_FEATURES", "REALIZABILITY_NOTE", "TABULAR_FORMATS", "TABULAR_INFO_KEYS", "URL_FEATURE_NAMES",
           "URL_TREES", "BoosterModel", "BundledTabularTarget", "contract_feature_names", "load_tabular_split"]
