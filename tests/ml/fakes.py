"""Shared test doubles (spec 11.1, 22): fixtures that exercise the ``Target`` protocol offline.

``TinyTarget`` satisfies the Target protocol with a random-weight 1-conv model on
8x8x3 inputs and 3 classes, so attack / explain / run tests never need the CIFAR-10
assets or the network.

``TinyTabularTarget`` is the tabular counterpart: a seeded scikit-learn tree
ensemble on a 12-feature, 3-class synthetic table with a declared linear PGD
surrogate (spec 9.2, 12.9), an ART estimator without loss gradients for the real
model and one with gradients for the surrogate, ``torch_model()`` raising
``NotImplementedError`` (a tree ensemble has no differentiable module) and a
manifest that carries digests, feature declarations and the surrogate's measured
clean agreement. Both doubles live only under ``tests/``: no API path serves them
and nothing they produce is evidence.
"""

from __future__ import annotations

import hashlib
from typing import Any

import numpy as np
import torch
from torch import nn

from redsim.ml.datasets.sampling import stratified_sample
from redsim.ml.schema import TargetInfo
from redsim.ml.targets.base import Sample

CLASS_NAMES = ["circle", "square", "triangle"]


class _TinyNet(nn.Module):
    def __init__(self, seed: int = 0) -> None:
        super().__init__()
        torch.manual_seed(seed)
        self.conv = nn.Conv2d(3, 4, kernel_size=3, padding=1)
        self.fc = nn.Linear(4 * 8 * 8, len(CLASS_NAMES))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.fc(torch.relu(self.conv(x)).flatten(1))


class TinyTarget:
    id = "tiny"

    def __init__(self, seed: int = 0) -> None:
        self._net = _TinyNet(seed).eval()
        self._clf: Any = None

    def info(self) -> TargetInfo:
        return TargetInfo(id=self.id, name="Tiny random CNN (test double)", domain="image",
                          status="available", metadata={"dataset": "synthetic", "n_classes": 3})

    def load(self) -> None:
        return None

    def sample(self, n: int, seed: int) -> Sample:
        rng = np.random.default_rng(seed)
        x = rng.random((n, 3, 8, 8), dtype=np.float32)
        y = rng.integers(0, len(CLASS_NAMES), size=n)
        return Sample(x=x, y=y, indices=np.arange(n), class_names=list(CLASS_NAMES))

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        with torch.no_grad():
            logits = self._net(torch.from_numpy(np.asarray(x, dtype=np.float32)))
            return torch.softmax(logits, dim=1).numpy()

    def art_classifier(self) -> Any:
        if self._clf is None:
            from art.estimators.classification import PyTorchClassifier
            self._clf = PyTorchClassifier(
                model=self._net, loss=nn.CrossEntropyLoss(), input_shape=(3, 8, 8),
                nb_classes=len(CLASS_NAMES), clip_values=(0.0, 1.0), device_type="cpu",
            )
        return self._clf

    def torch_model(self) -> Any:
        return self._net

    def manifest(self) -> dict[str, Any]:
        blob = b"".join(p.detach().numpy().tobytes() for p in self._net.parameters())
        return {"dataset": "synthetic", "split": "none", "model": "TinyNet",
                "weights_sha256": hashlib.sha256(blob).hexdigest()}


# --- tabular double ------------------------------------------------------------------------------

TABULAR_FEATURE_NAMES: list[str] = [f"feature_{i:02d}" for i in range(12)]
# The last two columns are declared frozen (spec 12.9: perturbable features are declared, not inferred).
TABULAR_FROZEN: frozenset[str] = frozenset({"feature_10", "feature_11"})
TABULAR_CLASS_NAMES: list[str] = ["low", "medium", "high"]
TABULAR_DATASET = "synthetic_tabular"
TABULAR_REALIZABILITY_NOTE = ("feature-space perturbation; realizability not established (synthetic table, test "
                              "double: no constructible input exists behind a feature vector)")
_N_TRAIN = 240
_N_EVAL = 180


def _labels(x: np.ndarray) -> np.ndarray:
    """Three bands of a linear score over the first eight columns; columns 8 to 11 carry no signal."""
    s = x[:, :4].sum(axis=1) - x[:, 4:8].sum(axis=1)
    return np.where(s < -0.5, 0, np.where(s < 0.5, 1, 2)).astype(np.int64)


def _sha256_arrays(*arrays: Any) -> str:
    h = hashlib.sha256()
    for a in arrays:
        arr = np.ascontiguousarray(np.asarray(a))
        h.update(str(arr.dtype).encode())
        h.update(str(arr.shape).encode())
        h.update(arr.tobytes())
    return h.hexdigest()


def _forest_digest(forest: Any) -> str:
    parts: list[Any] = []
    for est in forest.estimators_:
        t = est.tree_
        parts.extend((t.feature, t.threshold, t.value))
    return _sha256_arrays(*parts)


class TinyTabularTarget:
    """Seeded RandomForest on a 12-feature, 3-class synthetic table with a declared linear surrogate.

    ``surrogate=False`` builds the same target without a surrogate declaration, so a white-box attack
    finds no differentiable estimator (``surrogate_art_classifier()`` is ``None``) and must be recorded
    ``not_run`` (spec 9.5).
    """

    id = "tiny_tabular"

    def __init__(self, seed: int = 0, *, surrogate: bool = True) -> None:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression

        self._seed = int(seed)
        rng = np.random.default_rng(seed)
        x_train = rng.random((_N_TRAIN, len(TABULAR_FEATURE_NAMES)), dtype=np.float32)
        y_train = _labels(x_train)
        self._x_eval = rng.random((_N_EVAL, len(TABULAR_FEATURE_NAMES)), dtype=np.float32)
        self._y_eval = _labels(self._x_eval)
        if len(np.unique(y_train)) != len(TABULAR_CLASS_NAMES):  # pragma: no cover - fixed by construction
            raise RuntimeError("synthetic training table must contain every class")
        self._forest = RandomForestClassifier(n_estimators=10, max_depth=5, random_state=self._seed).fit(x_train, y_train)
        self._with_surrogate = bool(surrogate)
        self._surrogate: Any = None
        self._agreement: dict[str, Any] | None = None
        if self._with_surrogate:
            # A surrogate mimics the target: fitted to the forest's own predictions, agreement measured
            # on the held-out evaluation pool (never invented).
            self._surrogate = LogisticRegression(max_iter=500).fit(x_train, self._forest.predict(x_train))
            agree = int((self._surrogate.predict(self._x_eval) == self._forest.predict(self._x_eval)).sum())
            self._agreement = {"n": int(_N_EVAL), "n_correct": agree, "accuracy": agree / _N_EVAL}
        self._clf: Any = None
        self._surrogate_clf: Any = None

    # -- protocol ---------------------------------------------------------------------------------

    def info(self) -> TargetInfo:
        return TargetInfo(id=self.id, name="Tiny synthetic tree ensemble (test double)", domain="tabular",
                          status="available",
                          metadata={"dataset": TABULAR_DATASET, "n_classes": len(TABULAR_CLASS_NAMES),
                                    "gradients": self._with_surrogate, "realizability": TABULAR_REALIZABILITY_NOTE})

    def load(self) -> None:
        return None

    def sample(self, n: int, seed: int) -> Sample:
        return stratified_sample(self._x_eval, self._y_eval, n, seed, list(TABULAR_CLASS_NAMES))

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        return np.asarray(self._forest.predict_proba(np.asarray(x, dtype=np.float32)), dtype=np.float32)

    def feature_ranges(self) -> tuple[np.ndarray, np.ndarray]:
        k = len(TABULAR_FEATURE_NAMES)
        return np.zeros(k, dtype=np.float32), np.ones(k, dtype=np.float32)

    def perturbable_mask(self) -> np.ndarray:
        return np.asarray([name not in TABULAR_FROZEN for name in TABULAR_FEATURE_NAMES])

    def art_classifier(self) -> Any:
        """ART wrapper over the real forest: predicts, but exposes no loss gradient."""
        if self._clf is None:
            from art.estimators.classification import SklearnClassifier
            self._clf = SklearnClassifier(model=self._forest, clip_values=self.feature_ranges())
        return self._clf

    def surrogate_art_classifier(self) -> Any:
        """ART estimator over the declared linear surrogate (has ``loss_gradient``), or ``None``."""
        if not self._with_surrogate:
            return None
        if self._surrogate_clf is None:
            from art.estimators.classification import SklearnClassifier
            self._surrogate_clf = SklearnClassifier(model=self._surrogate, clip_values=self.feature_ranges())
        return self._surrogate_clf

    def torch_model(self) -> Any:
        raise NotImplementedError("a tree ensemble has no torch module; SHAP uses TreeExplainer on the real model")

    def sklearn_model(self) -> Any:
        return self._forest

    @property
    def feature_names(self) -> list[str]:
        return list(TABULAR_FEATURE_NAMES)

    def manifest(self) -> dict[str, Any]:
        digest = _forest_digest(self._forest)
        mins, maxs = self.feature_ranges()
        out: dict[str, Any] = {
            "dataset": TABULAR_DATASET, "dataset_id": TABULAR_DATASET, "split": "eval",
            "model": "RandomForestClassifier", "format": "sklearn_joblib",
            "weights_sha256": digest, "sha256": digest, "seed": self._seed,
            "n_features": len(TABULAR_FEATURE_NAMES), "feature_names": list(TABULAR_FEATURE_NAMES),
            "features": [{"name": name, "dtype": "float", "min": float(mins[i]), "max": float(maxs[i]),
                          "perturbable": name not in TABULAR_FROZEN}
                         for i, name in enumerate(TABULAR_FEATURE_NAMES)],
            "perturbable": self.perturbable_mask().tolist(),
            "class_names": list(TABULAR_CLASS_NAMES), "torch_model": None,
            "explainer": "TreeExplainer on the real model", "realizability": TABULAR_REALIZABILITY_NOTE,
            "caveats": ["synthetic table generated by a seeded rule; a test double, never evidence about any dataset"],
            "eval_n": int(_N_EVAL),
        }
        if self._with_surrogate and self._surrogate is not None:
            out["surrogate"] = {
                "kind": "logistic_regression",
                "sha256": _sha256_arrays(self._surrogate.coef_, self._surrogate.intercept_),
                "agreement_clean": dict(self._agreement or {}),
            }
        return out


__all__ = ["CLASS_NAMES", "TABULAR_CLASS_NAMES", "TABULAR_DATASET", "TABULAR_FEATURE_NAMES", "TABULAR_FROZEN",
           "TABULAR_REALIZABILITY_NOTE", "TinyTabularTarget", "TinyTarget"]
