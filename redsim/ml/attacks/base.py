"""Attack adapter protocol (design spec section 2.3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import numpy as np

from redsim.ml.schema import AttackInfo
from redsim.ml.targets.base import Target


@dataclass
class AttackOutput:
    x_adv: np.ndarray
    linf_norm_mean: float
    l2_norm_mean: float
    wall_time_s: float
    params: dict[str, float | int | bool]
    library_versions: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@runtime_checkable
class AttackAdapter(Protocol):
    id: str

    def info(self) -> AttackInfo: ...

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        """Fill defaults, coerce types, and reject out-of-range values (ValueError)."""
        ...

    def run(self, target: Target, x: np.ndarray, y: np.ndarray,
            params: dict[str, float | int | bool], seed: int) -> AttackOutput:
        ...
