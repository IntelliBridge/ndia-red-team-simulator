"""Explain-stage output contract (master plan section 5)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from redsim.ml.schema import Observation


@dataclass
class ExplainOutput:
    """What an explainer hands back to the campaign.

    ``observations`` are per-sample evidence rows (spec 13.3 step 5);
    ``expl_shift_mean`` is the campaign-level explanation shift at the
    reference budget over the explained set (13.5), ``None`` when no pair was
    defined; ``meta`` carries explainer provenance (name, shap version,
    nsamples, background size, wall time, nondeterminism notes), the
    denominators of every aggregate, per-sample values that the ``Observation``
    schema has no field for, and the run-relative paths of campaign-level
    artifacts. Nothing in ``meta`` is a claim; it is provenance and derived
    summaries.
    """

    observations: list[Observation]
    expl_shift_mean: float | None
    meta: dict[str, Any] = field(default_factory=dict)
