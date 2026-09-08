"""Evidence model for an adversarial-ML campaign.

The record keeps four things in separate fields, never blended in prose:
measurements (what was counted), observations (per-sample evidence),
interpretation (inferred statements) and candidate recommendations. The
Literal types make the labels part of the contract: a recommendation cannot
be anything but ``candidate``, and its validation can only be
``not evaluated`` or ``measured``.

This module is the frozen M0 contract (spec sections 5.3 to 5.7, 12.5, 13.3,
14, 15, 16.4). Later milestones add behaviour, not fields. A field change
after the freeze follows the protocol in ``docs/plans/01-p0-contracts-api-skeleton.md``
section 8.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime
from itertools import pairwise
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

Domain = Literal["image", "tabular", "llm"]
Modality = Literal["image", "tabular"]
TargetStatus = Literal["available", "not_implemented"]
AttackFamily = Literal["evasion", "control"]
# ``not_implemented`` is an admission-time 501 and is never persisted. The
# other values are the ``Job`` vocabulary (spec section 6.2).
RunStatus = Literal["queued", "running", "succeeded", "failed", "cancelled", "not_implemented"]
MeasurementFamily = Literal["clean", "evasion", "control"]
Norm = Literal["linf", "l2"]
CampaignKind = Literal["attack", "verify", "ingest"]
Completeness = Literal["complete", "partial"]
Grade = Literal["A", "B", "C", "D", "F"]
ModelFormat = Literal[
    "onnx", "torch_state_dict", "safetensors_state_dict", "sklearn_joblib", "xgboost_json", "endpoint",
]
ModelStatus = Literal["registered", "validating", "available", "refused"]
RefusalReason = Literal[
    "pickle_refused", "unsupported_format", "architecture_missing", "load_failed",
    "shape_mismatch", "size_limit", "timeout",
]
VerifyOutcome = Literal["verified", "still_vulnerable", "inconclusive"]
ReviewState = Literal["unreviewed", "dismissed"]

# Pipeline stages, in order. The worker writes ``stage`` as it progresses so
# the UI timeline can render progress. ``attack`` is written per attack as
# ``attack:<attack_id>``. ``score`` runs at the end of the explain stage.
STAGES: tuple[str, ...] = (
    "load_target", "sample", "clean_eval", "attack", "control", "explain", "score",
    "interpret", "recommend", "report",
)

# Words that never appear in grade text, badge text or generated narrative
# (spec 15.8 iii). Matched as whole words, case-insensitive.
BANNED_SCORE_WORDS: tuple[str, ...] = (
    "hardened", "harden before fielding", "deployment-ready", "not deployment-ready",
    "certified", "safe", "fielding",
)
_BANNED_RE = re.compile(
    r"\b(" + "|".join(re.escape(w) for w in BANNED_SCORE_WORDS) + r")\b", re.IGNORECASE,
)

# Printed under every grade, in the UI and in reports (spec 15.5).
GRADE_STATEMENT = (
    "A grade describes measured behaviour under the declared attack set, ε grid and slice. "
    "It is not a readiness, safety, or certification statement, and it does not describe "
    "robustness to attacks that were not run."
)


def grade_for_mri(mri: int) -> Grade:
    """Grade band for an MRI value (spec 15.5). Pure, no rounding."""
    if mri >= 90:
        return "A"
    if mri >= 75:
        return "B"
    if mri >= 60:
        return "C"
    if mri >= 40:
        return "D"
    return "F"


def contains_banned_score_word(text: str) -> bool:
    return bool(_BANNED_RE.search(text))


# ---------------------------------------------------------------------------
# Catalog entries
# ---------------------------------------------------------------------------


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
    """Registry entry for one attack adapter, also the shape ``GET /v1/attacks`` lists."""

    id: str
    name: str
    domain: Domain
    family: AttackFamily
    description: str = ""
    params_schema: list[ParamSpec] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    phase: Literal["A", "B"] = "A"
    access: Literal["white-box", "black-box"] = "white-box"
    requires_gradients: bool = True
    status: Literal["available", "not_implemented"] = "available"
    reason: str | None = None


# ---------------------------------------------------------------------------
# Campaign configuration (spec 5.6, 12.3, 15.3)
# ---------------------------------------------------------------------------


class MRIWeights(BaseModel):
    """The MRI weight vector. Sums to 1 and is never renormalised."""

    acc: float = 0.35
    asr: float = 0.25
    eps: float = 0.20
    conf: float = 0.10
    expl: float = 0.10

    @model_validator(mode="after")
    def _sum_to_one(self) -> MRIWeights:
        total = self.acc + self.asr + self.eps + self.conf + self.expl
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"MRI weights must sum to 1.0, got {total}")
        return self

    def as_dict(self) -> dict[str, float]:
        return {"acc": self.acc, "asr": self.asr, "eps": self.eps, "conf": self.conf, "expl": self.expl}


class SeverityThresholds(BaseModel):
    asr_high: float = Field(0.5, gt=0.0, le=1.0)
    asr_mid: float = Field(0.2, gt=0.0, le=1.0)


class ConfidenceThresholds(BaseModel):
    """Clean-correct sample counts that set ``Finding.confidence`` (spec 15.5)."""

    n_high: int = Field(100, ge=1)
    n_medium: int = Field(30, ge=1)


class InterpretationThresholds(BaseModel):
    """Defaults for the interpretation rules I1 to I6 (spec 14.6)."""

    evasion_drop: float = 0.20          # I1: acc(evasion at eps_ref) < acc(clean) - evasion_drop
    control_tolerance: float = 0.05     # I1: |acc(control at eps_ref) - acc(clean)| <= control_tolerance
    control_drop: float = 0.10          # I2: acc(control at eps_ref) < acc(clean) - control_drop
    iterative_margin: float = 0.10      # I3: acc(pgd) < acc(fgsm) - iterative_margin at the same eps
    center_mass_drop: float = 0.15      # I4: mean center-mass ratio drop on flipped observations
    expl_shift_high: float = 0.5        # I5: mean explanation shift at eps_ref
    conf_gap_high: float = 0.5          # I6: mean confidence gap at eps_ref


class ScoringConfig(BaseModel):
    """The ``ml.scoring`` block, copied onto the campaign at admission and frozen."""

    version: str = "mri-1"
    weights: MRIWeights = Field(default_factory=MRIWeights)
    severity: SeverityThresholds = Field(default_factory=SeverityThresholds)
    confidence: ConfidenceThresholds = Field(default_factory=ConfidenceThresholds)
    interpretation: InterpretationThresholds = Field(default_factory=InterpretationThresholds)


class DefenseConfig(BaseModel):
    """An ART preprocessing defense applied to an evaluation copy in a verify run."""

    id: str                               # id from GET /v1/defenses, e.g. "feature_squeezing"
    art_class: str | None = None          # e.g. "art.defences.preprocessor.FeatureSqueezing"
    params: dict[str, Any] = Field(default_factory=dict)


class CampaignConfig(BaseModel):
    """One campaign: one model, one modality, a declared attack set, an ε grid, a reference budget.

    Immutable after admission. The ``settings_hash`` of spec 5.6 is computed
    over this object excluding ``defense``, ``llm_narrative`` and
    ``target_snapshot``.
    """

    target_id: str
    modality: Modality
    attack_ids: list[str] = Field(min_length=1)
    attack_params: dict[str, dict[str, float | int | bool]] = Field(default_factory=dict)
    norm: Norm = "linf"
    eps_grid: list[float] = Field(min_length=1)          # sorted ascending, each in (0, 1]
    reference_eps: float                                 # must be a member of eps_grid
    finding_asr_threshold: float = Field(0.2, gt=0.0, le=1.0)
    n_samples: int = Field(200, ge=10, le=1000)
    seed: int = 0
    include_control: bool = True
    explain_k: int = Field(8, ge=0, le=32)
    dataset_id: str
    dataset_revision: str | None = None
    dataset_split: str = "test"
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    defense: DefenseConfig | None = None                 # verify campaigns only
    llm_narrative: bool = False                          # opt-in; needs REDSIM_ML_LLM_MODEL
    auto_recommend: bool = True
    target_snapshot: dict[str, Any] = Field(default_factory=dict)   # frozen target row + manifest
    attacks: list[AttackInfo] = Field(default_factory=list)         # registry snapshots

    @field_validator("eps_grid")
    @classmethod
    def _grid_sorted_in_range(cls, v: list[float]) -> list[float]:
        if any(not (0.0 < e <= 1.0) for e in v):
            raise ValueError("eps_grid members must lie in (0, 1]")
        if any(b <= a for a, b in pairwise(v)):
            raise ValueError("eps_grid must be strictly ascending")
        return v

    @model_validator(mode="after")
    def _reference_in_grid(self) -> CampaignConfig:
        if self.reference_eps not in self.eps_grid:
            raise ValueError("reference_eps must be a member of eps_grid")
        unknown = set(self.attack_params) - set(self.attack_ids)
        if unknown:
            raise ValueError(f"attack_params names attacks outside attack_ids: {sorted(unknown)}")
        return self


# ---------------------------------------------------------------------------
# Provenance (spec 14.4)
# ---------------------------------------------------------------------------


class Provenance(BaseModel):
    redsim_version: str
    python: str
    torch: str
    art: str
    shap: str
    numpy: str
    onnxruntime: str | None = None
    sklearn: str | None = None
    xgboost: str | None = None
    model_sha256: str | None = None
    dataset: str | None = None
    dataset_revision: str | None = None
    dataset_split: str | None = None
    sample_indices_sha256: str | None = None
    settings_hash: str | None = None
    baseline_run_id: str | None = None   # verify runs
    parent_run_id: str | None = None     # reruns
    defense: dict[str, Any] | None = None            # verify runs: ART class and resolved params
    llm: dict[str, Any] | None = None                # PythiaSettings.redacted() + hashes, never the key
    thread_env: dict[str, str] = Field(default_factory=dict)
    model_manifest: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime
    finished_at: datetime | None = None
    hostname: str
    device: str = "cpu"
    nondeterminism: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# The four kinds of statement (spec 14.1)
# ---------------------------------------------------------------------------


class Measurement(BaseModel):
    """One row per test family at one setting. ``id`` is cited by interpretation and recommendations.

    Ids: ``m.clean``, ``m.evasion.<attack_id>.eps<ε>``, ``m.control.noise.eps<ε>``.
    ``params`` carries ``eps``, ``norm`` and every resolved attack parameter.
    """

    id: str
    family: MeasurementFamily
    attack_id: str | None = None
    params: dict[str, float | int | bool | str] = Field(default_factory=dict)
    n: int
    n_correct: int
    accuracy: float
    n_flipped_from_clean: int | None = None
    n_clean_correct: int | None = None               # ASR denominator (= m.clean.n_correct)
    attack_success_rate: float | None = None         # n_flipped_from_clean / n_clean_correct
    linf_norm_mean: float | None = None
    l2_norm_mean: float | None = None
    pert_first_success_mean: float | None = None     # reference_eps row only
    pert_first_success_n: int | None = None
    conf_gap_mean: float | None = None
    conf_gap_n: int | None = None
    expl_shift_mean: float | None = None             # reference_eps row only
    expl_shift_n: int | None = None
    expl_shift_n_excluded: int | None = None
    expl_shift_noise_floor: float | None = None
    expl_shift_noise_floor_n: int | None = None
    queries_mean: float | None = None                # black-box attacks only
    per_class: dict[str, dict[str, int]] = Field(default_factory=dict)   # class -> {"n":…, "n_correct":…}
    wall_time_s: float = 0.0
    notes: list[str] = Field(default_factory=list)


class Observation(BaseModel):
    """Per-sample evidence: inputs, attribution maps and a heuristic metric."""

    id: str                              # e.g. "o.003"
    sample_index: int
    true_label: str
    pred_clean: str
    pred_adv: str
    flipped: bool
    confidence_clean: float
    confidence_adv: float
    artifacts: dict[str, str]            # name -> Artifact.id
    artifact_sha256: dict[str, str] = Field(default_factory=dict)
    center_mass_ratio_clean: float | None = None
    center_mass_ratio_adv: float | None = None
    expl_shift: float | None = None
    top_features_clean: list[str] = Field(default_factory=list)   # tabular, ranked by |SHAP|
    top_features_adv: list[str] = Field(default_factory=list)
    metric_kind: Literal["heuristic"] = "heuristic"
    metric_note: str = ("center_mass_ratio = share of |SHAP| inside the central 50% of the image; "
                        "a proxy for attention on the subject, not a segmentation.")


class Interpretation(BaseModel):
    id: str
    statement: str
    basis: list[str] = Field(min_length=1)    # measurement / observation ids
    kind: Literal["inferred"] = "inferred"


class AccuracyPoint(BaseModel):
    """A fraction with its denominator. ``accuracy`` is ``None`` when ``n`` is 0."""

    n: int
    n_correct: int
    accuracy: float | None = None


class Subscores(BaseModel):
    """The five MRI dimensions on a 0 to 100 scale. Also used for per-dimension deltas."""

    S_acc: float | None = None
    S_asr: float | None = None
    S_eps: float | None = None
    S_conf: float | None = None
    S_expl: float | None = None

    def missing(self) -> list[str]:
        return [name for name, value in self.model_dump().items() if value is None]


class CleanAccuracyDelta(BaseModel):
    before: AccuracyPoint
    after: AccuracyPoint
    delta: float | None = None


class FamilyDelta(BaseModel):
    measurement_id: str
    before: AccuracyPoint
    after: AccuracyPoint
    delta: float | None = None


class MRIDelta(BaseModel):
    """ΔMRI between a verify run and its baseline (spec 15.6). Verify runs only."""

    baseline_run_id: str
    mri_before: int
    mri_after: int
    delta: int
    delta_subscores: Subscores = Field(default_factory=Subscores)
    delta_acc_clean: CleanAccuracyDelta
    delta_families: list[FamilyDelta] = Field(default_factory=list)


class MeasuredDelta(BaseModel):
    """The measured ΔMRI attached to the one recommendation whose defense a verify run applied."""

    verify_run_id: str
    baseline_run_id: str
    defense: DefenseConfig
    delta_mri: int
    delta_subscores: Subscores = Field(default_factory=Subscores)
    delta_acc_clean: CleanAccuracyDelta
    settings_hash: str
    measured_at: datetime


class CandidateRecommendation(BaseModel):
    id: str
    title: str
    rationale: str
    triggered_by: list[str] = Field(min_length=1)   # measurement / observation ids
    status: Literal["candidate"] = "candidate"
    validation: Literal["not evaluated", "measured"] = "not evaluated"
    measured: MeasuredDelta | None = None
    references: list[str] = Field(default_factory=list)
    narrative: str | None = None         # optional LLM prose; labelled in UI
    narrative_source: Literal["rules", "llm"] = "rules"

    @model_validator(mode="after")
    def _measured_pairs_with_validation(self) -> CandidateRecommendation:
        if self.validation == "measured" and self.measured is None:
            raise ValueError("validation 'measured' requires a measured block")
        if self.validation == "not evaluated" and self.measured is not None:
            raise ValueError("a measured block requires validation 'measured'")
        return self


# ---------------------------------------------------------------------------
# Score record (spec 5.6, 15)
# ---------------------------------------------------------------------------


class MRIInputRow(BaseModel):
    """One (attack, ε) row of scoring inputs with its denominators."""

    attack_id: str
    eps: float
    acc_clean: float | None = None
    acc_adv: float | None = None
    asr: float | None = None
    pert: float | None = None
    conf_gap: float | None = None
    expl_shift: float | None = None
    queries: float | None = None
    n: int
    n_correct_clean: int | None = None
    n_attacked: int | None = None
    n_explained: int | None = None


class ScoredValue(BaseModel):
    value: float | None = None
    n: int | None = None
    reason: str | None = None            # why unavailable, when value is None


class PerAttackSubscores(BaseModel):
    S_acc: ScoredValue = Field(default_factory=ScoredValue)
    S_asr: ScoredValue = Field(default_factory=ScoredValue)
    S_eps: ScoredValue = Field(default_factory=ScoredValue)
    S_conf: ScoredValue = Field(default_factory=ScoredValue)
    S_expl: ScoredValue = Field(default_factory=ScoredValue)


class MRIRecord(BaseModel):
    """The per-campaign score record. Never rendered without ``inputs``, ``subscores`` and the ε curve."""

    scoring_version: str
    weights: MRIWeights
    eps_grid: list[float]
    reference_eps: float
    norm: Norm
    attack_ids: list[str]
    finding_asr_threshold: float
    settings_hash: str
    inputs: list[MRIInputRow] = Field(default_factory=list)
    per_attack: dict[str, PerAttackSubscores] = Field(default_factory=dict)
    subscores: Subscores = Field(default_factory=Subscores)
    mri: int | None = Field(None, ge=0, le=100)
    grade: Grade | None = None
    completeness: Completeness
    missing: list[str] = Field(default_factory=list)   # "<dimension> unavailable (<reason>)"
    reading: str | None = None                          # attack-scoped grade text
    delta: MRIDelta | None = None                       # verify runs only
    computed_at: datetime

    @model_validator(mode="after")
    def _mri_needs_all_five(self) -> MRIRecord:
        absent = self.subscores.missing()
        if self.mri is not None:
            if absent:
                raise ValueError(f"mri set while subscores are missing: {absent}")
            if self.completeness != "complete":
                raise ValueError("mri set on a partial score record")
            if self.grade != grade_for_mri(self.mri):
                raise ValueError(f"grade {self.grade!r} does not match mri {self.mri}")
        else:
            if self.grade is not None:
                raise ValueError("grade without mri")
            if self.completeness == "complete":
                raise ValueError("a complete score record must carry an mri")
            if not self.missing:
                raise ValueError("a partial score record must name what is missing")
        if self.reading and contains_banned_score_word(self.reading):
            raise ValueError("reading contains a banned readiness word")
        return self


# ---------------------------------------------------------------------------
# Model manifest (spec 5.5), stored in targets.detail
# ---------------------------------------------------------------------------


class FeatureSpec(BaseModel):
    name: str
    dtype: str
    min: float | None = None
    max: float | None = None
    perturbable: bool = False


class SurrogateInfo(BaseModel):
    kind: str
    sha256: str
    agreement_clean: AccuracyPoint | None = None


class CleanAccuracy(BaseModel):
    value: float
    n: int
    split: str


class MLModelManifest(BaseModel):
    name: str
    modality: Modality
    format: ModelFormat
    sha256: str
    size_bytes: int = Field(ge=0)
    architecture_id: str | None = None
    input_shape: list[int] = Field(default_factory=list)
    n_classes: int = Field(ge=1)
    class_names: list[str] = Field(default_factory=list)
    features: list[FeatureSpec] | None = None
    surrogate: SurrogateInfo | None = None
    dataset_id: str
    dataset_revision: str | None = None
    dataset_split: str = "test"
    clean_accuracy: CleanAccuracy | None = None
    status: ModelStatus = "registered"
    refusal_reason: RefusalReason | None = None
    gradients: bool | None = None
    bundled: bool = False
    license: str | None = None
    source_url: str | None = None
    manifest_sha256: str | None = None

    @model_validator(mode="after")
    def _consistency(self) -> MLModelManifest:
        if self.class_names and len(self.class_names) != self.n_classes:
            raise ValueError("class_names length must equal n_classes")
        if self.format in ("torch_state_dict", "safetensors_state_dict") and not self.architecture_id:
            raise ValueError("state_dict formats require architecture_id")
        if self.status == "refused" and self.refusal_reason is None:
            raise ValueError("a refused model must carry refusal_reason")
        if self.status != "refused" and self.refusal_reason is not None:
            raise ValueError("refusal_reason is only set on a refused model")
        return self


# ---------------------------------------------------------------------------
# Finding detail (spec 5.7), stored in findings.schema_blob["ml"]
# ---------------------------------------------------------------------------


class FindingReview(BaseModel):
    state: ReviewState = "unreviewed"
    reviewer: str | None = None
    reason: str | None = None
    at: datetime | None = None
    notes: str | None = None


class FindingVerify(BaseModel):
    run_id: str
    defense: DefenseConfig
    outcome: VerifyOutcome
    delta: MRIDelta | None = None


class AtlasTechnique(BaseModel):
    """MITRE ATLAS tag. Phase B2 only, never back-filled by guesswork."""

    id: str
    name: str
    atlas_version: str


class MLFindingDetail(BaseModel):
    attack_id: str
    attack_name: str
    family: Literal["evasion"] = "evasion"
    norm: Norm
    eps_grid: list[float]
    reference_eps: float
    first_success_eps: float | None = None
    asr_at_reference: float | None = None
    asr_by_eps: dict[str, float] = Field(default_factory=dict)
    threshold: float
    measurements: list[Measurement] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    interpretation: list[Interpretation] = Field(default_factory=list)
    recommendations: list[CandidateRecommendation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    artifacts: dict[str, str] = Field(default_factory=dict)   # name -> Artifact.id
    review: FindingReview = Field(default_factory=FindingReview)
    verify: FindingVerify | None = None
    atlas_technique: AtlasTechnique | None = None


# ---------------------------------------------------------------------------
# Robustness curve (spec 12.3), the ml.curve artifact and the /campaign field
# ---------------------------------------------------------------------------


class CurvePoint(BaseModel):
    eps: float
    n: int
    n_correct: int
    accuracy: float | None = None
    n_clean_correct: int | None = None
    n_flipped_from_clean: int | None = None
    asr: float | None = None


class RobustnessCurve(BaseModel):
    attack_id: str
    norm: Norm
    eps_grid: list[float]
    reference_eps: float
    clean: AccuracyPoint
    points: list[CurvePoint] = Field(default_factory=list)
    control: list[CurvePoint] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# The run record (the ml.run_record artifact) and the /campaign response
# ---------------------------------------------------------------------------


class RunRecord(BaseModel):
    run_id: str
    status: RunStatus
    stage: str | None = None
    stages_done: list[str] = Field(default_factory=list)
    error: str | None = None
    created_at: datetime
    config: CampaignConfig
    target: TargetInfo
    attacks: list[AttackInfo] = Field(default_factory=list)
    provenance: Provenance | None = None
    measurements: list[Measurement] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    interpretation: list[Interpretation] = Field(default_factory=list)
    recommendations: list[CandidateRecommendation] = Field(default_factory=list)
    score: MRIRecord | None = None
    limitations: list[str] = Field(default_factory=list)
    reviewer_notes: str | None = None

    @model_validator(mode="after")
    def _limitations_required_when_done(self) -> RunRecord:
        # A model validator, not a field validator: Pydantic skips field
        # validators for defaulted fields, and an empty list is the default.
        if self.status == "succeeded" and not self.limitations:
            raise ValueError("a succeeded run must state its limitations")
        return self

    @model_validator(mode="after")
    def _no_dangling_citations(self) -> RunRecord:
        known = {m.id for m in self.measurements} | {o.id for o in self.observations}
        known |= {i.id for i in self.interpretation}
        for interp in self.interpretation:
            dangling = [b for b in interp.basis if b not in known]
            if dangling:
                raise ValueError(f"interpretation {interp.id} cites unknown ids: {dangling}")
        for rec in self.recommendations:
            dangling = [t for t in rec.triggered_by if t not in known]
            if dangling:
                raise ValueError(f"recommendation {rec.id} cites unknown ids: {dangling}")
        return self


class ScoreStatus(BaseModel):
    """Why ``score`` is ``None`` on a campaign response."""

    state: Literal["pending", "unavailable"]
    reason: str | None = None


class CampaignRecord(RunRecord):
    """The ``GET /v1/runs/{id}/campaign`` response: the run record plus its queryable projections."""

    kind: CampaignKind = "attack"
    completed_at: datetime | None = None
    settings_hash: str | None = None
    baseline_run_id: str | None = None
    parent_run_id: str | None = None
    curve: list[RobustnessCurve] = Field(default_factory=list)
    completeness: Completeness = "partial"
    missing: list[str] = Field(default_factory=list)
    score_status: ScoreStatus | None = None

    @model_validator(mode="after")
    def _score_or_status(self) -> CampaignRecord:
        if self.score is None and self.score_status is None:
            raise ValueError("a campaign without a score must carry score_status")
        if self.score is not None and self.score_status is not None:
            raise ValueError("score and score_status are mutually exclusive")
        return self


class RunSummary(BaseModel):
    run_id: str
    status: RunStatus
    stage: str | None
    target_id: str
    attack_ids: list[str]
    created_at: datetime


# ---------------------------------------------------------------------------
# Limitations (spec 14.5)
# ---------------------------------------------------------------------------

# The dataset sentence is a template filled from the dataset manifest (D3).
DATASET_LIMITATION_TEMPLATE = (
    "{dataset_name} is an open, unclassified public benchmark; it is not a proxy for any "
    "operational domain, sensor, or deployment condition."
)
SINGLE_BUDGET_LIMITATION = (
    "Results come from a single seed and a single perturbation budget unless a sweep was run."
)
SWEEP_LIMITATION_TEMPLATE = "Results come from a single seed; the ε grid was {eps_grid}."

# Limitations every succeeded run carries, regardless of outcome and dataset.
STANDING_LIMITATIONS: tuple[str, ...] = (
    "SHAP attributions describe the model's sensitivity, not the cause of a failure; they are not causal proof.",
    "The evaluation slice is small; per-class numbers in particular have wide uncertainty.",
    "White-box gradient attacks assume full model access; black-box and physical-world attacks were not evaluated.",
    "Recommendations are candidates. None has been validated against this model; that requires a separate evaluation.",
    "Passing or failing this suite does not establish safety, robustness in general, or deployment readiness.",
)


def standing_limitations(dataset_name: str, eps_grid: Sequence[float] | None = None) -> list[str]:
    """The standing limitations for one campaign: dataset sentence, budget sentence, then the rest."""
    budget = (
        SWEEP_LIMITATION_TEMPLATE.format(eps_grid=list(eps_grid))
        if eps_grid and len(eps_grid) > 1
        else SINGLE_BUDGET_LIMITATION
    )
    return [DATASET_LIMITATION_TEMPLATE.format(dataset_name=dataset_name), budget, *STANDING_LIMITATIONS]
