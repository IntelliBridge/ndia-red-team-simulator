"""Evidence model for an adversarial-ML evaluation run.

The record keeps four things in separate fields, never blended in prose:
measurements (what was counted), observations (per-sample evidence),
interpretation (inferred statements) and candidate recommendations. The
Literal types make the labels part of the contract: a recommendation cannot
be anything but ``candidate`` / ``not evaluated``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

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
    atlas_technique_id: str | None = None      # e.g. AML.T0043
    atlas_technique_name: str | None = None    # e.g. Craft Adversarial Data


class RunConfig(BaseModel):
    target_id: str
    attack_id: str | None = None                       # single-attack form (kept for compatibility)
    attack_ids: list[str] = Field(default_factory=list)  # campaign form: attack set
    eps_grid: list[float] = Field(default_factory=lambda: [0.01, 0.03, 0.1])
    reference_eps: float = 0.03
    scoring_weights: dict[str, float] | None = None    # None = spec defaults 0.35/0.25/0.20/0.10/0.10
    defense: dict[str, Any] | None = None              # {id, params} for verify-after-harden re-runs
    params: dict[str, float | int | bool] = Field(default_factory=dict)
    n_samples: int = Field(200, ge=10, le=1000)
    seed: int = 0
    include_control: bool = True
    explain_k: int = Field(8, ge=0, le=32)
    llm_narrative: bool = False          # opt-in; needs REDSIM_LLM_MODEL


class Provenance(BaseModel):
    aegis_version: str
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
    severity: Literal["critical", "high", "medium", "low"] | None = None   # derived per spec section 15, never hand-set


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


class Scoring(BaseModel):
    """Model Robustness Index for ONE campaign (one model x one modality x declared attack set x
    eps grid x reference budget). Never aggregated across modalities or compared across campaigns
    with different settings (D9). Always shown with subscores, denominators and the eps curve."""

    mri: int = Field(ge=0, le=100)
    grade: Literal["A", "B", "C", "D", "F"]
    reading: str                              # attack-scoped wording only; never a readiness claim
    subscores: dict[str, float]               # S_acc, S_asr, S_eps, S_conf, S_expl in [0, 100]
    weights: dict[str, float]                 # 0.35/0.25/0.20/0.10/0.10, never renormalized (master plan section 5)
    reference_eps: float
    eps_grid: list[float]
    attack_ids: list[str]
    modality: Domain
    inputs: dict[str, Any] = Field(default_factory=dict)   # acc_clean, per-attack acc_adv/asr/pert/conf_gap/expl_shift
    basis_measurements: list[str] = Field(default_factory=list)
    delta_from: str | None = None             # run_id of the pre-hardening campaign when this is a verify re-run
    delta_mri: int | None = None
    delta_subscores: dict[str, float] | None = None
    not_a_readiness_statement: Literal[True] = True


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
    scoring: Scoring | None = None
    atlas_coverage: list[str] = Field(default_factory=list)   # MITRE ATLAS technique ids exercised (Phase B2 fills)
    limitations: list[str] = Field(default_factory=list)
    reviewer_notes: str | None = None

    @field_validator("limitations")
    @classmethod
    def _limitations_required_when_done(cls, v: list[str], info: Any) -> list[str]:
        status = info.data.get("status")
        if status == "succeeded" and not v:
            raise ValueError("a succeeded run must state its limitations")
        return v


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
