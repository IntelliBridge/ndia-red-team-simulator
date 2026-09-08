"""Explanation stability -- ``expl_shift`` (spec section 13.5).

``expl_shift = clamp(1 - cos(flatten(phi_clean), flatten(phi_adv)), 0, 1)`` for
attributions of the *same* class on the clean and adversarial input. A pair
whose either norm is below ``NORM_FLOOR`` is undefined: ``expl_shift`` returns
``nan`` and ``aggregate`` counts it as excluded rather than as 0 or 1.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from typing import TypeGuard

import numpy as np

NORM_FLOOR = 1e-12


def channel_sum(attr: np.ndarray) -> np.ndarray:
    """Collapse an image attribution to H x W by summing over channels.

    Accepts ``(C, H, W)`` or ``(H, W, C)`` when the channel axis is the small
    one (<= 4). 2-D input is returned unchanged. Tabular vectors pass through.
    """
    a = np.asarray(attr, dtype=np.float64)
    if a.ndim == 3:
        if a.shape[0] <= 4 and a.shape[0] <= a.shape[-1]:
            return a.sum(axis=0)
        if a.shape[-1] <= 4:
            return a.sum(axis=-1)
        return a.sum(axis=0)
    return a


def expl_shift(attr_clean: np.ndarray, attr_adv: np.ndarray) -> float:
    """``clamp(1 - cosine_similarity, 0, 1)`` over the flattened attributions.

    Returns ``nan`` when either vector's L2 norm is below ``NORM_FLOOR`` (the
    pair is undefined and must be excluded, not counted).
    """
    a = np.asarray(attr_clean, dtype=np.float64).ravel()
    b = np.asarray(attr_adv, dtype=np.float64).ravel()
    if a.shape != b.shape:
        raise ValueError(f"attribution shapes differ: {a.shape} vs {b.shape}")
    na = float(np.linalg.norm(a))
    nb = float(np.linalg.norm(b))
    if na < NORM_FLOOR or nb < NORM_FLOOR:
        return float("nan")
    cos = float(np.dot(a, b) / (na * nb))
    cos = max(-1.0, min(1.0, cos))
    return float(min(1.0, max(0.0, 1.0 - cos)))


def is_defined(value: float | None) -> TypeGuard[float]:
    return value is not None and not math.isnan(value)


def aggregate(values: Iterable[float | None]) -> tuple[float | None, int, int]:
    """``(mean over defined values, n_defined, n_excluded)``. The mean is ``None`` when nothing is defined."""
    items = list(values)  # materialise once: a generator must not be consumed twice
    defined = [float(v) for v in items if is_defined(v)]
    n_excluded = len(items) - len(defined)
    if not defined:
        return None, 0, n_excluded
    return float(np.mean(defined)), len(defined), n_excluded
