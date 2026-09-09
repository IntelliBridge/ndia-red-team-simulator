"""Record models of the LLM track under the name the register uses (LLM-13, -24).

The models live in :mod:`redsim.ml.llm.scorecard` (the scorecard) and
:mod:`redsim.ml.llm.probe_child` (the child spec and result); this module
re-exports them so ``redsim.ml.llm.schema.LLMProbeScorecard`` resolves, and
carries ``LLM_STANDING_LIMITATIONS``: the dataset-independent sentences every
probe scorecard states. The parameterised list (guardrail mode, prompt cap,
seed, garak version, excluded and not-run probes) is
:func:`redsim.ml.llm.scorecard.llm_standing_limitations`.

Nothing here touches the frozen ``redsim.ml.schema``.
"""

from __future__ import annotations

from redsim.ml.llm.catalog import HARMBENCH_EXCLUSION
from redsim.ml.llm.probe_child import (
    ChildDetectorCounts,
    ChildProbeResult,
    ChildResult,
    LLMProbeChildSpec,
)
from redsim.ml.llm.scorecard import (
    D9_SENTENCE,
    DETECTOR_LIMITATION,
    GUARDRAIL_TEXT,
    HIT_MEANING,
    NARRATIVE_LIMITATION,
    NO_CLAIM_LIMITATION,
    SCORECARD_VERSION,
    DetectorResult,
    GuardrailMode,
    LLMProbeScorecard,
    ProbeFamilyResult,
    ProbeResult,
    UsageSummary,
    assert_no_mri,
    build_scorecard,
    llm_standing_limitations,
)

#: The parameter-free standing limitations (D9 first). See ``llm_standing_limitations`` for the full list.
LLM_STANDING_LIMITATIONS: tuple[str, ...] = (
    D9_SENTENCE,
    HIT_MEANING,
    DETECTOR_LIMITATION,
    HARMBENCH_EXCLUSION,
    NARRATIVE_LIMITATION,
    NO_CLAIM_LIMITATION,
)

__all__ = [
    "D9_SENTENCE",
    "GUARDRAIL_TEXT",
    "LLM_STANDING_LIMITATIONS",
    "SCORECARD_VERSION",
    "ChildDetectorCounts",
    "ChildProbeResult",
    "ChildResult",
    "DetectorResult",
    "GuardrailMode",
    "LLMProbeChildSpec",
    "LLMProbeScorecard",
    "ProbeFamilyResult",
    "ProbeResult",
    "UsageSummary",
    "assert_no_mri",
    "build_scorecard",
    "llm_standing_limitations",
]
