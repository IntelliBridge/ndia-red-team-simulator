"""Fail-closed base class for target domains not implemented in this milestone."""

from __future__ import annotations

from typing import Any, NoReturn

import numpy as np

from redsim.schema import Domain, TargetInfo
from redsim.targets.base import Sample


class UnavailableTarget:
    """Expose honest catalog metadata while refusing every evaluation operation."""

    id: str
    name: str
    domain: Domain
    reason: str
    metadata: dict[str, Any] = {}

    def info(self) -> TargetInfo:
        return TargetInfo(
            id=self.id,
            name=self.name,
            domain=self.domain,
            status="not_implemented",
            reason=self.reason,
            metadata=dict(self.metadata),
        )

    def _unavailable(self) -> NoReturn:
        raise NotImplementedError(f"target {self.id!r} is not implemented: {self.reason}")

    def load(self) -> None:
        self._unavailable()

    def sample(self, n: int, seed: int) -> Sample:
        self._unavailable()

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        self._unavailable()

    def art_classifier(self) -> Any:
        self._unavailable()

    def torch_model(self) -> Any:
        self._unavailable()

    def manifest(self) -> dict[str, Any]:
        self._unavailable()