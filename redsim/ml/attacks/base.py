"""Attack adapter protocol (design spec section 2.3, product spec 12.1).

The protocol is the contract the campaign runner calls: ``info()``, ``resolve_params()``
and ``run(target, x, y, params, seed)``. Adapters may additionally carry optional class
attributes the runner and the registry read with ``getattr`` defaults, so they are not
protocol members:

- ``domains``: ``frozenset`` of ``Domain`` values the adapter applies to.
- ``takes_eps``: ``False`` for minimal-norm attacks whose grid is an evaluation grid (spec
  12.3): the attack runs once, unconstrained but with bounded iterations, and the campaign
  thresholds the achieved per-sample norm against every grid eps.
- ``capabilities``: tags from ``registry.KNOWN_ATTACK_CAPABILITIES``.
- ``norms``: ``frozenset`` of campaign norms (``"linf"``, ``"l2"``, ``"edit"``,
  ``"patch_area"``) the adapter may be evaluated under. Absent, the registry derives
  ``{"linf", "l2"}`` from a ``norm_l2`` parameter and ``{"linf"}`` otherwise
  (``registry.attack_norms`` / ``attack_supports_norm``).
- ``domain_defaults``: ``{domain: {param: value}}`` per-modality cost defaults applied to
  keys the caller omitted (``registry.apply_domain_defaults``); explicit values always win.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import numpy as np

from redsim.ml.schema import AttackInfo
from redsim.ml.targets.base import Target


@dataclass
class AttackOutput:
    """One adapter run on one slice.

    ``x_adv`` is in the target's raw input units (pixels in [0, 1], or raw feature values for
    tabular targets with integer features already rounded) so the campaign measures the real
    model on exactly these rows. ``linf_norm_mean`` / ``l2_norm_mean`` are in the units the
    attack optimised: raw for images, min-max-scaled for tabular targets (``notes`` says so).
    """

    x_adv: np.ndarray
    linf_norm_mean: float
    l2_norm_mean: float
    wall_time_s: float
    params: dict[str, float | int | bool]
    library_versions: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    # Black-box attacks only (spec 12.5 ``queries(a)``): mean model ``predict`` rows per sample
    # whose prediction the attack flipped from the model's clean prediction, i.e. the query
    # cost of one successful decision-boundary crossing. ``None`` when no sample flipped
    # (denominator 0, the spent total is still in ``notes``) and for gradient / control
    # adapters. The per-attacked-sample rate (total / n) is recorded in ``notes`` as well.
    queries_mean: float | None = None


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
