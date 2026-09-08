"""The bundled URL maliciousness classifier (spec 11.3.3, milestone M4).

A tree ensemble on the lexical features of ``redsim.ml.datasets.url_features``:
XGBoost when it is importable, otherwise scikit-learn's
``HistGradientBoostingClassifier``. The choice is recorded in the manifest
(spec 20.2). Beside it the build fits the differentiable PGD surrogate of spec
12.2 (a standardised logistic regression trained on the ensemble's predicted
labels) and records its agreement with the ensemble on the clean eval split.
"""

from __future__ import annotations

import importlib.util
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from redsim.ml.assets.datasets import URL_CLASS_NAMES, dedupe_urls, stratified_split
from redsim.ml.assets.manifest import FileEntry, sha256_file
from redsim.ml.assets.train_cnn import classification_metrics
from redsim.ml.datasets.url_features import EXTRACTOR_VERSION, FEATURE_NAMES, FEATURE_SPECS, featurize_array
from redsim.ml.schema import FeatureSpec

Log = Callable[[str], None]

SURROGATE_KIND = "sklearn_logistic_regression_standardized"


@dataclass
class UrlClassifierResult:
    model: Any
    format: str                      # "xgboost_json" | "sklearn_joblib"
    library: str                     # "xgboost" | "scikit-learn"
    surrogate: Any
    surrogate_agreement: float          # agree_count / n_eval
    surrogate_agree_count: int       # eval rows where the surrogate's label equals the ensemble's
    class_names: list[str]
    features: list[FeatureSpec]
    metrics: dict[str, Any]
    training: dict[str, Any]
    train_idx: np.ndarray
    eval_idx: np.ndarray
    urls: list[str]                  # de-duplicated rows, indexed by train_idx / eval_idx
    labels: np.ndarray
    n_duplicates_removed: int


def xgboost_available() -> bool:
    return importlib.util.find_spec("xgboost") is not None


def encode_labels(labels: Sequence[str], class_names: Sequence[str]) -> np.ndarray:
    index = {name: i for i, name in enumerate(class_names)}
    try:
        return np.asarray([index[label] for label in labels], dtype=np.int64)
    except KeyError as exc:
        raise ValueError(f"unknown class label {exc.args[0]!r}; expected one of {list(class_names)}") from None


def feature_entries(x_train: np.ndarray) -> list[FeatureSpec]:
    """``schema.FeatureSpec`` rows with the training-split min / max, in ``FEATURE_NAMES`` order."""
    out: list[FeatureSpec] = []
    for i, spec in enumerate(FEATURE_SPECS):
        col = x_train[:, i] if len(x_train) else np.zeros(1, dtype=np.float32)
        out.append(FeatureSpec(name=spec.name, dtype=spec.dtype, perturbable=spec.perturbable,
                               min=float(col.min()), max=float(col.max())))
    return out


def _make_model(seed: int, prefer_xgboost: bool, n_classes: int) -> tuple[Any, str, str, dict[str, Any]]:
    if prefer_xgboost and xgboost_available():
        import xgboost as xgb

        params: dict[str, Any] = {"n_estimators": 300, "max_depth": 8, "learning_rate": 0.1, "subsample": 0.9,
                                  "colsample_bytree": 0.9, "random_state": seed, "n_jobs": 4,
                                  "objective": "multi:softprob", "num_class": n_classes, "tree_method": "hist"}
        return xgb.XGBClassifier(**params), "xgboost_json", "xgboost", params
    from sklearn.ensemble import HistGradientBoostingClassifier

    params = {"max_iter": 300, "learning_rate": 0.1, "max_leaf_nodes": 31, "l2_regularization": 0.0,
              "early_stopping": False, "random_state": seed}
    return HistGradientBoostingClassifier(**params), "sklearn_joblib", "scikit-learn", params


def _make_surrogate(seed: int) -> Any:
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    return Pipeline([("scale", StandardScaler()),
                     ("logreg", LogisticRegression(max_iter=5000, C=1.0, random_state=seed))])


def train_url_classifier(urls: Sequence[str], labels: Sequence[str], *, seed: int = 0, holdout: float = 0.2,
                         prefer_xgboost: bool = True, class_names: Sequence[str] = URL_CLASS_NAMES,
                         log: Log = print) -> UrlClassifierResult:
    """De-duplicate, split, featurize, fit the ensemble and its surrogate, measure both."""
    names = list(class_names)
    urls_d, labels_d, n_dupes = dedupe_urls(urls, labels)
    if len(urls_d) < 2 * len(names):
        raise ValueError(f"need at least {2 * len(names)} distinct URLs, got {len(urls_d)}")
    y = encode_labels(labels_d, names)
    train_idx, eval_idx = stratified_split(y, holdout, seed)
    if len(eval_idx) == 0:
        raise ValueError("eval split is empty; provide more rows per class")
    log(f"url classifier: {len(urls_d)} distinct URLs ({n_dupes} duplicates removed), "
        f"train {len(train_idx)} / eval {len(eval_idx)}")

    x = featurize_array(urls_d)
    x_train, y_train = x[train_idx], y[train_idx]
    x_eval, y_eval = x[eval_idx], y[eval_idx]

    model, fmt, library, params = _make_model(seed, prefer_xgboost, len(names))
    t0 = time.perf_counter()
    model.fit(x_train, y_train)
    fit_s = time.perf_counter() - t0
    pred_eval = np.asarray(model.predict(x_eval), dtype=np.int64)
    metrics = classification_metrics(y_eval, pred_eval, names)
    log(f"url classifier ({library}): clean accuracy {metrics['clean_accuracy']:.4f} on n={metrics['n']}")

    surrogate = _make_surrogate(seed)
    pred_train = np.asarray(model.predict(x_train), dtype=np.int64)
    if len(np.unique(pred_train)) < 2:
        # Degenerate ensemble output (tiny fixtures): fit on true labels so the surrogate is still defined.
        pred_train = y_train
    surrogate.fit(x_train, pred_train)
    agree = np.asarray(surrogate.predict(x_eval), dtype=np.int64) == pred_eval
    agree_count = int(agree.sum())
    agreement = agree_count / len(pred_eval)
    log(f"surrogate ({SURROGATE_KIND}): agreement with the ensemble on the eval split {agreement:.4f}")

    training = {
        "library": library, "params": params, "seed": seed, "holdout": holdout, "split_seed": seed,
        "n_train": len(train_idx), "n_eval": len(eval_idx), "n_duplicates_removed": n_dupes,
        "fit_wall_time_s": round(fit_s, 3), "feature_names": list(FEATURE_NAMES),
        "extractor_version": EXTRACTOR_VERSION, "device": "cpu",
        "surrogate": {"kind": SURROGATE_KIND, "fit_on": "ensemble predicted labels (training split)"},
    }
    return UrlClassifierResult(
        model=model, format=fmt, library=library, surrogate=surrogate, surrogate_agreement=agreement,
        surrogate_agree_count=agree_count,
        class_names=names, features=feature_entries(x_train), metrics=metrics, training=training,
        train_idx=train_idx, eval_idx=eval_idx, urls=urls_d, labels=y, n_duplicates_removed=n_dupes,
    )


def save_url_classifier(result: UrlClassifierResult, out_dir: Path, *, assets_root: Path) -> tuple[FileEntry, FileEntry]:
    """Write the ensemble and the surrogate under ``out_dir``; return their manifest file entries."""
    import joblib

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if result.format == "xgboost_json":
        model_path = out_dir / "model.json"
        result.model.save_model(str(model_path))
    else:
        model_path = out_dir / "model.joblib"
        joblib.dump(result.model, model_path)
    surrogate_path = out_dir / "surrogate.joblib"
    joblib.dump(result.surrogate, surrogate_path)

    def _entry(path: Path) -> FileEntry:
        rel = path.resolve().relative_to(Path(assets_root).resolve()).as_posix()
        return FileEntry(path=rel, sha256=sha256_file(path), size_bytes=path.stat().st_size)

    return _entry(model_path), _entry(surrogate_path)


def load_url_classifier(path: Path, fmt: str) -> Any:
    if fmt == "xgboost_json":
        import xgboost as xgb

        model = xgb.XGBClassifier()
        model.load_model(str(path))
        return model
    import joblib

    return joblib.load(Path(path))
