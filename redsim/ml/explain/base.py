"""Explain-stage output contract (master plan section 5, spec 13.3 and 13.5)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from redsim.ml.schema import STANDING_LIMITATIONS, Observation

# The frozen wording of the SHAP limitation (first entry of ``schema.STANDING_LIMITATIONS``). Explainers
# state it in ``meta["limitations"]`` so a campaign that lists explainer limitations carries one sentence.
SHAP_LIMITATION: str = STANDING_LIMITATIONS[0]

# The reference-row fields of ``Measurement`` that the explain stage supplies (spec 13.5).
MEASUREMENT_FIELDS: tuple[str, ...] = (
    "expl_shift_mean", "expl_shift_n", "expl_shift_n_excluded", "expl_shift_noise_floor", "expl_shift_noise_floor_n",
)


@dataclass
class ExplainOutput:
    """What an explainer hands back to the campaign.

    ``observations`` are per-sample evidence rows (spec 13.3 step 5). Each carries
    its own ``expl_shift`` and, for tabular targets, the feature identifiers ranked
    by |SHAP| (``top_features_clean`` / ``top_features_adv``, empty for images).

    The five scalar fields are the reference-row fields of ``Measurement`` (spec
    13.5). The campaign writes them onto the evasion measurement at the reference
    budget through ``measurement_fields()``. ``expl_shift_mean`` is the mean over
    the explained pairs whose shift is defined, ``expl_shift_n`` that count and
    ``expl_shift_n_excluded`` the pairs left out because an attribution norm was
    below the floor. ``expl_shift_noise_floor`` is the same statistic between the
    clean attributions and those of the benign-noise control at the same eps, and
    it is ``None`` (with ``expl_shift_noise_floor_n`` ``None``) when no control was
    explained.

    ``meta`` carries explainer provenance (name, shap version, nsamples, background
    size, wall time, nondeterminism notes), derived summaries with their
    denominators and the run-relative paths of campaign-level artifacts. Nothing
    in ``meta`` is a claim.
    """

    observations: list[Observation]
    expl_shift_mean: float | None
    expl_shift_n: int = 0
    expl_shift_n_excluded: int = 0
    expl_shift_noise_floor: float | None = None
    expl_shift_noise_floor_n: int | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def measurement_fields(self) -> dict[str, Any]:
        """The reference-row ``Measurement`` fields as an update mapping for ``Measurement.model_copy``."""
        return {name: getattr(self, name) for name in MEASUREMENT_FIELDS}
