"""Evidence model for a redsim run (design spec section 3).

The record keeps four things in separate fields, never blended in prose:
measurements (what was counted), observations (per-sample evidence),
interpretation (inferred statements) and candidate recommendations. The
Literal types make the labels part of the contract: a recommendation cannot
be anything but ``candidate`` / ``not evaluated``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

Domain = Literal["image", "tabular", "llm"]
TargetStatus = Literal["available", "not_implemented"]
AttackFamily = Literal["evasion", "control"]
RunStatus = Literal["queued", "running", "succeeded", "failed", "not_implemented"]
MeasurementFamily = Literal["clean", "evasion", "control"]

# Pipeline stages, in order. ``runs.py`` writes ``stage`` as it progresses so
# the UI timeline can render progress without a queue.
STAGES: tuple[str, ...] = ("load_target", "sample", "clean_eval", "attack", "control", "explain",
                           "interpret", "recommend", "report")


class TargetInfo(BaseModel):
    id: str
    name: str
    domain: Domain
    status: TargetStatus
    reason: str | None = None            # why unavailable (stubs)
    metadata: dict[str, Any] = Field(default_factory=dict)   # dataset, clean accuracy, manifest


class ParamSpec(BaseModel):
    name: str
    type: Literal["float", "int", "bool"]
    default: float | int | bool
    min: float | None = None
    max: float | None = None
    description: str = ""


class AttackInfo(BaseModel):
    id: str
    name: str
    domain: Domain
    family: AttackFamily
    description: str = ""
    params_schema: list[ParamSpec] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class RunConfig(BaseModel):
    target_id: str
    attack_id: str
    params: dict[str, float | int | bool] = Field(default_factory=dict)
    n_samples: int = Field(200, ge=10, le=1000)
    seed: int = 0
    include_control: bool = True
    explain_k: int = Field(8, ge=0, le=32)
    llm_narrative: bool = False          # opt-in; needs REDSIM_LLM_MODEL


class Provenance(BaseModel):
    redsim_version: str
    python: str
    torch: str
    art: str
    shap: str
    numpy: str
    model_sha256: str | None = None
    dataset: str | None = None
    dataset_split: str | None = None
    model_manifest: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime
    finished_at: datetime | None = None
    hostname: str
    device: str = "cpu"
    nondeterminism: list[str] = Field(default_factory=list)


class Measurement(BaseModel):
    """One row per test family. ``id`` is cited by interpretation and recommendations."""

    id: str                              # e.g. "m.clean", "m.evasion.fgsm", "m.control.noise"
    family: MeasurementFamily
    attack_id: str | None = None
    params: dict[str, float | int | bool] = Field(default_factory=dict)
    n: int
    n_correct: int
    accuracy: float
    n_flipped_from_clean: int | None = None
    linf_norm_mean: float | None = None
    l2_norm_mean: float | None = None
    per_class: dict[str, dict[str, int]] = Field(default_factory=dict)   # class -> {"n":…, "n_correct":…}
    wall_time_s: float = 0.0
    notes: list[str] = Field(default_factory=list)


class Observation(BaseModel):
    """Per-sample evidence: images + attribution maps + a heuristic metric."""

    id: str                              # e.g. "o.003"
    sample_index: int
    true_label: str
    pred_clean: str
    pred_adv: str
    flipped: bool
    confidence_clean: float
    confidence_adv: float
    artifacts: dict[str, str]            # name -> run-relative path
    artifact_sha256: dict[str, str] = Field(default_factory=dict)
    center_mass_ratio_clean: float | None = None
    center_mass_ratio_adv: float | None = None
    metric_kind: Literal["heuristic"] = "heuristic"
    metric_note: str = ("center_mass_ratio = share of |SHAP| inside the central 50% of the image; "
                        "a proxy for attention on the subject, not a segmentation.")


class Interpretation(BaseModel):
    id: str
    statement: str
    basis: list[str]                     # measurement / observation ids
    kind: Literal["inferred"] = "inferred"


class CandidateRecommendation(BaseModel):
    id: str
    title: str
    rationale: str
    triggered_by: list[str]              # measurement / observation ids
    status: Literal["candidate"] = "candidate"
    validation: Literal["not evaluated"] = "not evaluated"
    references: list[str] = Field(default_factory=list)
    narrative: str | None = None         # optional LLM prose; labelled in UI
    narrative_source: Literal["rules", "llm"] = "rules"


class RunRecord(BaseModel):
    run_id: str
    status: RunStatus
    stage: str | None = None
    stages_done: list[str] = Field(default_factory=list)
    error: str | None = None
    created_at: datetime
    config: RunConfig
    target: TargetInfo
    attack: AttackInfo | None = None
    provenance: Provenance | None = None
    measurements: list[Measurement] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    interpretation: list[Interpretation] = Field(default_factory=list)
    recommendations: list[CandidateRecommendation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    reviewer_notes: str | None = None

    @model_validator(mode="after")
    def _limitations_required_when_done(self) -> RunRecord:
        if self.status == "succeeded" and not self.limitations:
            raise ValueError("a succeeded run must state its limitations")
        return self


class RunSummary(BaseModel):
    run_id: str
    status: RunStatus
    stage: str | None
    target_id: str
    attack_id: str
    created_at: datetime


# Limitations every succeeded run carries, regardless of outcome.
STANDING_LIMITATIONS: tuple[str, ...] = (
    "CIFAR-10 is a benign public benchmark; it is not a proxy for any operational domain or sensor.",
    "SHAP attributions describe the model's sensitivity, not the cause of a failure; they are not causal proof.",
    "Results come from a single seed and a single perturbation budget unless a sweep was run.",
    "The evaluation slice is small; per-class numbers in particular have wide uncertainty.",
    "White-box gradient attacks assume full model access; black-box and physical-world attacks were not evaluated.",
    "Recommendations are candidates. None has been validated against this model; that requires a separate evaluation.",
    "Passing or failing this suite does not establish safety, robustness in general, or deployment readiness.",
)
