"""Bundled URL-maliciousness tabular target (spec sections 9.2, 11.3.3, 12.9).

A scikit-learn tree ensemble trained by ``redsim ml build-assets`` on the lexical
URL features of ``redsim/ml/datasets/url_features.py`` (owned by the assets
branch and imported lazily). The joblib file is the only pickle the ML vertical
ever opens, and it is opened only after its sha256 matches the asset manifest
(spec section 9.2, bundled sklearn row).

Manifest entry shape (see ``bundled.py`` for the file layout):

    "url_trees": {
      "name": "...", "modality": "tabular", "format": "sklearn_joblib",
      "weights": "models/url_trees/model.joblib", "sha256": "...",
      "eval_split": "datasets/malicious_urls/eval.npz", "eval_split_sha256": "...",
      "class_names": ["benign", "defacement", "phishing", "malware"],
      "features": [{"name": "url_length", "dtype": "int", "min": 0, "max": 2175, "perturbable": true}, ...],
      "surrogate": {"kind": "logistic_regression", "path": "models/url_trees/surrogate.joblib",
                    "sha256": "...", "agreement_clean": {"value": 0.0, "n": 0}},
      "dataset_id": "kaggle:sid321axn/malicious-urls-dataset", "dataset_revision": "<csv sha256>",
      "dataset_split": "eval", "license": "CC0: Public Domain", "clean_accuracy": {...}
    }

The evaluation split ``.npz`` holds precomputed features ``x`` (n, n_features) float32, labels ``y``
and optional ``indices``. URL strings are data: nothing here fetches, resolves or renders one, and
the target never needs the strings at runtime because the features are precomputed at build time.
"""

from __future__ import annotations

import importlib
import platform
from pathlib import Path
from typing import Any

import numpy as np

from redsim.ml.datasets.sampling import per_class_counts, stratified_sample
from redsim.ml.errors import TargetUnavailable, UnsupportedArtifact
from redsim.ml.schema import TargetInfo
from redsim.ml.targets.artifact import library_versions, sha256_file, verify_sha256
from redsim.ml.targets.base import Sample
from redsim.ml.targets.bundled import (
    BUILD_HINT,
    MANIFEST_NAME,
    assets_dir,
    manifest_entry,
    read_manifest,
    register_once,
    resolve_asset_path,
)

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


class BundledTabularTarget:
    """URL maliciousness classifier: sklearn tree ensemble over lexical URL features."""

    def __init__(self, target_id: str, *, name: str | None = None, assets_dir: str | Path | None = None,
                 description: str = "") -> None:
        self.id = target_id
        self._name = name or target_id
        self._assets_dir = assets_dir
        self._description = description
        self._entry: dict[str, Any] | None = None
        self._model: Any = None
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
        self._clf: Any = None

    @property
    def root(self) -> Path:
        return assets_dir(self._assets_dir)

    def _read_entry(self) -> dict[str, Any] | None:
        return manifest_entry(read_manifest(self.root), self.id)

    def _require_entry(self) -> dict[str, Any]:
        entry = self._read_entry()
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
        keys = ("dataset_id", "dataset_revision", "dataset_split", "license", "source_url", "clean_accuracy",
                "sha256", "class_names", "format", "features", "surrogate", "description")
        meta = {**base_meta, "availability": "available",
                "gradients": bool(entry.get("surrogate")),  # only via the declared surrogate, never natively
                **{k: entry[k] for k in keys if k in entry}}
        return TargetInfo(id=self.id, name=str(entry.get("name") or self._name), domain="tabular",
                          status="available", metadata=meta)

    def _load_pickle_after_digest(self, rel: str, expected: Any, what: str) -> tuple[Any, str]:
        path = resolve_asset_path(self.root, rel)
        if not path.is_file():
            raise TargetUnavailable(f"{what} for {self.id!r} not found at {path}; {BUILD_HINT}")
        if not isinstance(expected, str) or not expected:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} carries no sha256 for its {what}; a bundled "
                                      "joblib file is opened only after its digest is verified")
        digest = verify_sha256(path, expected)
        import joblib

        # Deliberate pickle load (spec section 9.2, bundled sklearn row): the file is an in-repo asset written by
        # `redsim ml build-assets`, never an upload, and it is opened only after its sha256 matched the manifest
        # digest just above. Uploaded pickles are refused in artifact.py before any deserialisation.
        try:
            obj = joblib.load(path)
        except Exception as exc:
            raise UnsupportedArtifact(f"{what} for {self.id!r} failed to deserialise: {exc}") from exc
        return obj, digest

    def load(self) -> None:
        if self._x is not None:
            return
        entry = self._require_entry()
        fmt = entry.get("format", "sklearn_joblib")
        if fmt != "sklearn_joblib":
            raise UnsupportedArtifact(f"bundled tabular target {self.id!r} declares format {fmt!r}; expected sklearn_joblib")
        rel = entry.get("weights")
        if not isinstance(rel, str):
            raise UnsupportedArtifact(f"manifest entry {self.id!r} has no 'weights' path")
        model, self._sha256 = self._load_pickle_after_digest(rel, entry.get("sha256"), "model")
        if not hasattr(model, "predict_proba"):
            raise UnsupportedArtifact(f"bundled model for {self.id!r} has no predict_proba")

        split_rel = entry.get("eval_split")
        if not isinstance(split_rel, str):
            raise UnsupportedArtifact(f"manifest entry {self.id!r} has no 'eval_split' path")
        split = resolve_asset_path(self.root, split_rel)
        if not split.is_file():
            raise TargetUnavailable(f"evaluation split for {self.id!r} not found at {split}; {BUILD_HINT}")
        expected_split = entry.get("eval_split_sha256")
        if expected_split and sha256_file(split) != str(expected_split).lower():
            raise UnsupportedArtifact(f"hash_mismatch: evaluation split {split.name} differs from the manifest digest")
        try:
            with np.load(split, allow_pickle=False) as npz:
                x = np.asarray(npz["x"], dtype=np.float32)
                y = np.asarray(npz["y"]).reshape(-1).astype(np.int64)
                idx = np.asarray(npz["indices"]).astype(np.int64) if "indices" in npz else None
        except (OSError, KeyError, ValueError) as exc:
            raise UnsupportedArtifact(f"evaluation split {split} is unreadable: {exc}") from exc
        if x.ndim != 2 or x.shape[0] != y.shape[0] or x.shape[0] == 0:
            raise UnsupportedArtifact(f"tabular evaluation split must be a non-empty (n, n_features) table, got {x.shape}")

        names = [str(n) for n in (entry.get("class_names") or [])]
        if not names:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} declares no class_names")
        if y.min() < 0 or y.max() >= len(names):
            raise UnsupportedArtifact("evaluation labels fall outside the declared class list")

        features = [dict(f) for f in entry.get("features") or [] if isinstance(f, dict)]
        feature_names = [str(f["name"]) for f in features if "name" in f] or contract_feature_names()
        contract = contract_feature_names()
        if features and feature_names != contract:
            raise UnsupportedArtifact("feature order in the manifest disagrees with url_features: "
                                      f"{feature_names} vs {contract}")
        if x.shape[1] != len(feature_names):
            raise UnsupportedArtifact(f"shape_mismatch: split has {x.shape[1]} features, contract declares "
                                      f"{len(feature_names)}")
        n_in = getattr(model, "n_features_in_", None)
        if n_in is not None and int(n_in) != x.shape[1]:
            raise UnsupportedArtifact(f"shape_mismatch: model expects {n_in} features, split has {x.shape[1]}")

        self._column_order = self._column_order_for(model, names)
        probe = model.predict_proba(x[:1])
        if np.asarray(probe).shape[1] != len(names):
            raise UnsupportedArtifact(f"shape_mismatch: model emits {np.asarray(probe).shape[1]} classes, manifest "
                                      f"declares {len(names)}")
        self._entry, self._model, self._class_names = entry, model, names
        self._features, self._feature_names = features, feature_names
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

    def perturbable_mask(self) -> np.ndarray:
        """Declared continuous features attacks may touch; binary flags and the label are frozen (12.9)."""
        self.load()
        if self._features:
            return np.asarray([bool(f.get("perturbable", False)) for f in self._features])
        return np.asarray([name not in FROZEN_URL_FEATURES for name in self._feature_names])

    def art_classifier(self) -> Any:
        self.load()
        if self._clf is None:
            from art.estimators.classification import SklearnClassifier

            ranges = self.feature_ranges()
            self._clf = SklearnClassifier(model=self._model, clip_values=ranges)
        return self._clf

    def surrogate_art_classifier(self) -> Any:
        """ART estimator over the build-time PGD surrogate, or ``None`` when the manifest declares none."""
        self.load()
        assert self._entry is not None
        decl = self._entry.get("surrogate")
        if not isinstance(decl, dict) or not decl.get("path"):
            return None
        if self._surrogate_clf is None:
            from art.estimators.classification import SklearnClassifier

            self._surrogate, _ = self._load_pickle_after_digest(str(decl["path"]), decl.get("sha256"), "surrogate")
            self._surrogate_clf = SklearnClassifier(model=self._surrogate, clip_values=self.feature_ranges())
        return self._surrogate_clf

    def torch_model(self) -> Any:
        """``None``: a tree ensemble has no differentiable module. SHAP uses ``TreeExplainer`` on the real model."""
        self.load()
        return None

    def sklearn_model(self) -> Any:
        self.load()
        return self._model

    @property
    def feature_names(self) -> list[str]:
        self.load()
        return list(self._feature_names)

    def manifest(self) -> dict[str, Any]:
        self.load()
        assert self._entry is not None and self._y is not None and self._x is not None
        return {
            **self._entry,
            "id": self.id, "source": "bundled", "weights_sha256_verified": self._sha256,
            "class_names": self._class_names, "feature_names": self._feature_names,
            "perturbable": self.perturbable_mask().tolist(), "n_features": int(self._x.shape[1]),
            "gradients": bool(self._entry.get("surrogate")), "torch_model": None,
            "explainer": "TreeExplainer on the real model", "realizability": REALIZABILITY_NOTE,
            "eval_n": int(self._y.shape[0]), "eval_per_class": per_class_counts(self._y, self._class_names),
            "library_versions": {**library_versions("scikit-learn", "adversarial-robustness-toolbox", "numpy"),
                                 "python": platform.python_version()},
            "assets_dir": str(self.root),
        }


URL_TREES = register_once(BundledTabularTarget(
    "url_trees", name="Bundled URL maliciousness classifier (tree ensemble on lexical URL features)",
    description="Demo tabular target (spec section 11.3.3, Kaggle sid321axn/malicious-urls-dataset, CC0)."))

__all__ = ["FROZEN_URL_FEATURES", "REALIZABILITY_NOTE", "URL_FEATURE_NAMES", "URL_TREES", "BundledTabularTarget",
           "contract_feature_names"]
