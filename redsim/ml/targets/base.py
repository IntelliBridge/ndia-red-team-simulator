"""Target protocol (design spec section 2.1).

A target is a model plus the public dataset slice it is evaluated on. The
bundled image and tabular targets are live when their assets are present; the
LLM endpoint target is a registered stub whose ``info().status`` is
``not_implemented`` so the UI can show it honestly.

``Sample`` is defined in ``redsim.ml.datasets.sampling`` (the module that
builds it) and re-exported here unchanged, so ``from redsim.ml.targets.base
import Sample`` keeps working while the datasets package stays free of any
import of the targets package (see ``tests/ml/test_import_order.py``).
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import numpy as np

from redsim.ml.datasets.sampling import Sample
from redsim.ml.schema import TargetInfo

__all__ = ["Sample", "Target"]


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
