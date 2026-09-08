"""Target protocol (design spec section 2.1).

A target is a model plus the public dataset slice it is evaluated on. The
image target is live; tabular and LLM targets are registered stubs whose
``info().status`` is ``not_implemented`` so the UI can show them honestly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import numpy as np

from aegis.ml.schema import TargetInfo


@dataclass
class Sample:
    """Evaluation slice. ``x`` is float32 in [0, 1], NCHW for images."""

    x: np.ndarray
    y: np.ndarray            # int labels, shape (n,)
    indices: np.ndarray      # index into the source split, for reproducibility
    class_names: list[str]


@runtime_checkable
class Target(Protocol):
    id: str

    def info(self) -> TargetInfo: ...

    def load(self) -> None:
        """Load weights/data. Idempotent. Raises NotImplementedError for stubs."""
        ...

    def sample(self, n: int, seed: int) -> Sample:
        """Stratified, seeded slice of the evaluation split."""
        ...

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        """Class probabilities, shape (n, n_classes)."""
        ...

    def art_classifier(self) -> Any:
        """An ART estimator wrapping the model (``PyTorchClassifier`` for images)."""
        ...

    def torch_model(self) -> Any:
        """The underlying ``torch.nn.Module`` in eval mode (for SHAP)."""
        ...

    def manifest(self) -> dict[str, Any]:
        """Dataset / weights provenance: names, versions, sha256, training config."""
        ...
