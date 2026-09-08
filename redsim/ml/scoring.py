"""Model Robustness Index (spec section 15 and master plan section 5).

    MRI = round(0.35*S_acc + 0.25*S_asr + 0.20*S_eps + 0.10*S_conf + 0.10*S_expl)

Pure functions only. ``score_run`` reads a ``CampaignConfig`` and the campaign's
``Measurement`` rows and returns ``(MRIRecord, None)`` when all five subscores
exist. When a dimension is unavailable it returns a PARTIAL ``MRIRecord``
(``mri`` and ``grade`` ``None``, ``completeness = "partial"``, ``missing`` naming
every unavailable dimension and its reason, the available subscores kept with
their denominators) together with the reason text; weights are NEVER
renormalised over the available dimensions (spec 15.4). When nothing can be
scored at all (no clean row, a partial run missing evasion rows) it returns
``(None, reason)``.

One campaign = one model x one modality x one declared attack set x one eps
grid x one reference budget; nothing here aggregates across those boundaries
(D9 i). ``severity_for`` derives the Finding-level severity from the first
success budget and the ASR against ``SeverityThresholds`` (spec 15.5); nothing
sets severity by hand and no ``Measurement`` carries one. ``delta`` builds the
``MRIDelta`` of a verify run and refuses incompatible campaigns (spec 15.6).
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise
from typing import Any, Literal

from redsim.ml.eval import eps_of, eps_tag
from redsim.ml.schema import (
    GRADE_STATEMENT,
    AccuracyPoint,
    CampaignConfig,
    CleanAccuracyDelta,
    ConfidenceThresholds,
    CurvePoint,
    FamilyDelta,
    Grade,
    Measurement,
    MRIDelta,
    MRIInputRow,
    MRIRecord,
    MRIWeights,
    PerAttackSubscores,
    RobustnessCurve,
    ScoredValue,
    SeverityThresholds,
    Subscores,
    contains_banned_score_word,
    grade_for_mri,
)

Severity = Literal["critical", "high", "medium", "low"]
Confidence = Literal["high", "medium", "low"]

SUBSCORE_KEYS: tuple[str, ...] = ("S_acc", "S_asr", "S_eps", "S_conf", "S_expl")
# Subscore key -> the MRIWeights field that weights it.
WEIGHT_FIELD: dict[str, str] = {"S_acc": "acc", "S_asr": "asr", "S_eps": "eps", "S_conf": "conf", "S_expl": "expl"}
# The scoring algorithm this module implements; ``ScoringConfig.version`` must name it.
SCORING_VERSION = "mri-1"
# Spec 12.6 denominator guard: below this many clean-correct samples no Finding is created.
MIN_CLEAN_CORRECT_FOR_FINDING = 10

# Attack-scoped grade readings (spec 15.5, D9 iii). Checked against the banned list on use.
GRADE_READINGS: dict[str, str] = {
    "A": ("Under the in-scope attacks at the declared eps grid, accuracy and attributions were "
          "essentially unchanged on this slice."),
    "B": "Minor degradation under the strongest in-scope attack at the reference budget.",
    "C": "Substantial degradation under the in-scope iterative attack at the reference budget.",
    "D": "The cheapest in-scope attack succeeded at the reference budget on a large share of the slice.",
    "F": "Predictions flipped at the smallest eps in the declared grid on most of the slice.",
}
# Printed under every grade (spec 15.5); the schema owns the wording.
GRADE_SENTENCE = GRADE_STATEMENT
ONE_POINT_GRID_LIMITATION = ("The eps grid has a single point, so S_eps degenerates to the robust-accuracy "
                             "ratio at that point rather than an area under a curve.")


def contains_banned_wording(text: str) -> bool:
    """Whole-word match against ``schema.BANNED_SCORE_WORDS``."""
    return contains_banned_score_word(text or "")


def weights_by_subscore(weights: MRIWeights) -> dict[str, float]:
    """``{"S_acc": 0.35, ...}`` from the ``MRIWeights`` vector, exactly as configured (never renormalised)."""
    return {key: float(getattr(weights, field)) for key, field in WEIGHT_FIELD.items()}


# --- settings hash (spec 5.6, 15.6) -----------------------------------------------------------

_SETTINGS_HASH_EXCLUDE = frozenset({"defense", "llm_narrative", "target_snapshot"})


def canonical_settings_json(config: CampaignConfig) -> str:
    """Canonical JSON of the campaign config excluding ``defense``, ``llm_narrative`` and
    ``target_snapshot`` (the fields a verify run is allowed to change)."""
    payload = config.model_dump(mode="json", exclude=set(_SETTINGS_HASH_EXCLUDE))
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def settings_hash(config: CampaignConfig, model_sha256: str | None = None) -> str:
    """sha256 over the canonical config JSON concatenated with the model sha256 (spec 5.6). Two
    campaigns are comparable iff this value is equal. Without ``model_sha256`` the hash covers the
    settings only; the campaign always passes the model digest."""
    h = hashlib.sha256(canonical_settings_json(config).encode("utf-8"))
    if model_sha256:
        h.update(str(model_sha256).encode("utf-8"))
    return h.hexdigest()


_compute_settings_hash = settings_hash


# --- small numeric helpers ------------------------------------------------------------------------

def _clamp01(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


def _same_eps(a: float, b: float) -> bool:
    return math.isclose(float(a), float(b), rel_tol=0.0, abs_tol=1e-12)


def eps_bands(eps_grid: Sequence[float], reference_eps: float) -> tuple[float, float, float]:
    """``(eps_small, eps_mid, eps_large)`` per spec 15.5: min, reference when strictly between,
    else the median grid point, max."""
    grid = sorted(float(e) for e in eps_grid)
    if not grid:
        raise ValueError("eps_grid is empty")
    small, large = grid[0], grid[-1]
    if small < float(reference_eps) < large:
        mid = float(reference_eps)
    else:
        mid = grid[len(grid) // 2]
    return small, mid, large


def trapezoid_auc_normalized(xs: Sequence[float], ys: Sequence[float]) -> float:
    """Trapezoid rule over the declared grid only, divided by ``(x_max - x_min)``. A one-point grid
    degenerates to the value at that point (spec 15.2)."""
    pairs = sorted(zip((float(x) for x in xs), (float(y) for y in ys), strict=True))
    if not pairs:
        raise ValueError("empty curve")
    if len(pairs) == 1:
        return pairs[0][1]
    area = 0.0
    for (x0, y0), (x1, y1) in pairwise(pairs):
        area += (x1 - x0) * (y0 + y1) / 2.0
    width = pairs[-1][0] - pairs[0][0]
    if width <= 0:
        return pairs[0][1]
    return area / width


# --- reading the measurement table --------------------------------------------------------------

def clean_row(measurements: Sequence[Measurement]) -> Measurement | None:
    return next((m for m in measurements if m.family == "clean"), None)


def evasion_rows(measurements: Sequence[Measurement], attack_id: str) -> dict[float, Measurement]:
    """``eps -> row`` for one attack's evasion rows (eps read from ``params["eps"]``)."""
    out: dict[float, Measurement] = {}
    for m in measurements:
        if m.family == "evasion" and m.attack_id == attack_id and (e := eps_of(m)) is not None:
            out[e] = m
    return out


def _lookup[T](rows: Mapping[float, T], eps: float) -> T | None:
    for k, v in rows.items():
        if _same_eps(k, eps):
            return v
    return None


def _row_at(rows: Mapping[float, Measurement], eps: float) -> Measurement:
    m = _lookup(rows, eps)
    if m is None:
        raise ValueError(f"no measurement row at eps {eps:g}")
    return m


def _scored(fraction: float, n: int | None) -> ScoredValue:
    """A subscore on the 0 to 100 scale with the denominator it was computed over."""
    return ScoredValue(value=round(100.0 * fraction, 1), n=n)


def asr_by_eps(measurements: Sequence[Measurement], attack_id: str) -> dict[float, float | None]:
    """``eps -> attack_success_rate`` for one attack (``None`` where the denominator was 0)."""
    return {e: m.attack_success_rate for e, m in sorted(evasion_rows(measurements, attack_id).items())}


def _asr_value(v: Any) -> float | None:
    if isinstance(v, Mapping):
        v = v.get("asr")
    if isinstance(v, Measurement):
        v = v.attack_success_rate
    return None if v is None else float(v)


def first_success(asr_table: Mapping[float, Any], threshold: float) -> tuple[float | None, float | None]:
    """Smallest grid eps whose ASR crosses ``threshold`` and the ASR there, or ``(None, None)`` when the
    attack never crosses it or the ASR is undefined everywhere. ``asr_table`` maps eps to the ASR
    (a float, a ``Measurement`` or a ``{"asr": ...}`` mapping)."""
    for e in sorted(float(k) for k in asr_table):
        asr = _asr_value(_lookup(asr_table, e))
        if asr is not None and asr >= float(threshold):
            return e, asr
    return None, None


# --- Finding-level derivations (spec 12.6, 15.5) --------------------------------------------------

def severity_for(first_success_eps: float | None, asr_at_first_success: float | None,
                 eps_grid: Sequence[float], reference_eps: float,
                 thresholds: SeverityThresholds | None = None) -> Severity | None:
    """Derived Finding severity (spec 15.5). ``None`` when the attack never crossed the threshold.

    With the grid sorted ascending, ``eps_small = min``, ``eps_large = max`` and ``eps_mid`` is the
    reference eps when strictly between them, else the median grid point:

    - critical: first success at ``eps <= eps_small`` with ``asr >= asr_high``.
    - high: ``eps <= eps_small`` with ``asr >= asr_mid``, or at ``eps_mid`` with ``asr >= asr_high``.
    - medium: first success at ``eps_mid`` and not high, or at ``eps_small`` with ``asr < asr_mid``
      (only reachable when ``finding_asr_threshold`` is configured below ``asr_mid``).
    - low: first success only above ``eps_mid``.
    """
    if first_success_eps is None or asr_at_first_success is None:
        return None
    t = thresholds or SeverityThresholds()
    small, mid, _large = eps_bands(eps_grid, reference_eps)
    eps = float(first_success_eps)
    asr = float(asr_at_first_success)
    tol = 1e-12
    if eps <= small + tol:
        if asr >= t.asr_high:
            return "critical"
        if asr >= t.asr_mid:
            return "high"
        return "medium"
    if eps <= mid + tol:
        return "high" if asr >= t.asr_high else "medium"
    return "low"


def confidence_for(n_clean_correct: int, thresholds: ConfidenceThresholds | None = None) -> Confidence:
    """``Finding.confidence`` from the clean-correct sample count (spec 15.5): sample-size based."""
    t = thresholds or ConfidenceThresholds()
    if n_clean_correct >= t.n_high:
        return "high"
    if n_clean_correct >= t.n_medium:
        return "medium"
    return "low"


@dataclass(frozen=True)
class FindingInputs:
    """Everything ``MLFindingDetail`` and ``Finding.severity`` need for one attack, derived from the
    measurement table and the campaign config. No Finding is created here."""

    attack_id: str
    threshold: float
    n_clean_correct: int
    asr_by_eps: dict[str, float]            # "0.01" -> asr, defined rows only (MLFindingDetail shape)
    asr_at_reference: float | None
    first_success_eps: float | None
    asr_at_first_success: float | None
    severity: Severity | None
    confidence: Confidence
    crosses_threshold: bool                 # the attack "succeeded" at some grid eps (spec 12.6)
    denominator_ok: bool                    # n_clean_correct >= MIN_CLEAN_CORRECT_FOR_FINDING (spec 12.6)


def finding_inputs(config: CampaignConfig, measurements: Sequence[Measurement], attack_id: str) -> FindingInputs:
    clean = clean_row(measurements)
    n_cc = int(clean.n_correct) if clean is not None else 0
    table = asr_by_eps(measurements, attack_id)
    fs_eps, fs_asr = first_success(table, config.finding_asr_threshold)
    ref_asr = _asr_value(_lookup(table, float(config.reference_eps)))
    return FindingInputs(
        attack_id=attack_id, threshold=float(config.finding_asr_threshold), n_clean_correct=n_cc,
        asr_by_eps={f"{e:g}": float(v) for e, v in table.items() if v is not None},
        asr_at_reference=ref_asr, first_success_eps=fs_eps, asr_at_first_success=fs_asr,
        severity=severity_for(fs_eps, fs_asr, config.eps_grid, config.reference_eps, config.scoring.severity),
        confidence=confidence_for(n_cc, config.scoring.confidence),
        crosses_threshold=fs_eps is not None,
        denominator_ok=n_cc >= MIN_CLEAN_CORRECT_FOR_FINDING,
    )


# --- the MRI ---------------------------------------------------------------------------------------

def reading_for(grade: Grade, config: CampaignConfig) -> str:
    """The attack-scoped reading for a grade: the spec 15.5 sentence plus the scope it describes."""
    grid = [float(e) for e in config.eps_grid]
    text = (f"{GRADE_READINGS[grade]} Scope: attacks {', '.join(config.attack_ids)}; norm {config.norm}; "
            f"eps grid {grid}; reference eps {float(config.reference_eps):g}.")
    if contains_banned_wording(text):
        raise ValueError("grade reading contains a banned readiness word")
    return text


def input_rows(config: CampaignConfig, measurements: Sequence[Measurement]) -> list[MRIInputRow]:
    """One ``MRIInputRow`` per (attack, eps) with its denominators. Raises ``ValueError`` when the
    clean row or any (attack, eps) row is absent (a partial run is not scored)."""
    clean = clean_row(measurements)
    if clean is None:
        raise ValueError("no clean row (m.clean) among the measurements")
    rows: list[MRIInputRow] = []
    for a in dict.fromkeys(config.attack_ids):
        by_eps = evasion_rows(measurements, a)
        for e in config.eps_grid:
            m = _lookup(by_eps, float(e))
            if m is None:
                raise ValueError(f"partial run: attack {a!r} has no row at eps {float(e):g}")
            rows.append(MRIInputRow(
                attack_id=a, eps=float(e), acc_clean=float(clean.accuracy), acc_adv=float(m.accuracy),
                asr=m.attack_success_rate, pert=m.pert_first_success_mean, conf_gap=m.conf_gap_mean,
                expl_shift=m.expl_shift_mean, queries=m.queries_mean, n=m.n,
                n_correct_clean=clean.n_correct, n_attacked=m.n, n_explained=m.expl_shift_n,
            ))
    return rows


def score_run(*, config: CampaignConfig, measurements: Sequence[Measurement],
              settings_hash: str | None = None,
              computed_at: datetime | None = None) -> tuple[MRIRecord | None, str | None]:
    """Score one campaign from its measurement table.

    Returns ``(MRIRecord, None)`` when all five subscores exist for every declared attack. When a
    dimension is unavailable it returns ``(partial MRIRecord, reason)``: ``mri`` and ``grade`` are
    ``None``, ``completeness`` is ``"partial"``, ``missing`` names each unavailable dimension with
    its reason, and the available subscores stay with their denominators. Weights are never
    renormalised. Returns ``(None, reason)`` when nothing can be scored: no clean row, or a partial
    run with a declared attack missing rows on the grid. Raises ``ValueError`` for configuration
    errors (a scoring version this module does not implement)."""
    if config.scoring.version != SCORING_VERSION:
        raise ValueError(f"scoring version {config.scoring.version!r} is not implemented here "
                         f"(this module implements {SCORING_VERSION!r})")
    grid = [float(e) for e in config.eps_grid]
    ref = float(config.reference_eps)
    attack_ids = list(dict.fromkeys(config.attack_ids))
    weights = weights_by_subscore(config.scoring.weights)
    shash = settings_hash if settings_hash is not None else _compute_settings_hash(config)

    clean = clean_row(measurements)
    if clean is None:
        return None, "MRI not computed: no clean row (m.clean) among the measurements; nothing to score against."
    n = int(clean.n)
    n_cc = int(clean.n_correct)
    acc_clean = float(clean.accuracy)

    rows_by_attack: dict[str, dict[float, Measurement]] = {}
    for a in attack_ids:
        rows = evasion_rows(measurements, a)
        gaps = [e for e in grid if _lookup(rows, e) is None]
        if len(gaps) == len(grid):
            return None, (f"MRI not computed: partial run; attack {a!r} has no evasion rows. "
                          "No subscore is reported for a partial run.")
        if gaps:
            return None, (f"MRI not computed: partial run; attack {a!r} has no row at eps "
                          f"{', '.join(f'{e:g}' for e in gaps)}. No subscore is reported for a partial run.")
        rows_by_attack[a] = rows

    inputs = input_rows(config, measurements)

    per_attack: dict[str, PerAttackSubscores] = {}
    raw: dict[str, dict[str, float | None]] = {}          # unrounded fractions in [0, 1]
    unavailable: dict[str, list[str]] = {k: [] for k in SUBSCORE_KEYS}
    for a in attack_ids:
        rows = rows_by_attack[a]
        ref_row = _row_at(rows, ref)
        frac: dict[str, float | None] = {}
        sub: dict[str, ScoredValue] = {}
        if acc_clean <= 0.0 or n_cc <= 0:
            why = f"acc_clean == 0 (m.clean.n_correct = {n_cc}/{n}; denominator 0)"
            for key, denominator in (("S_acc", n), ("S_eps", n), ("S_asr", n_cc)):
                frac[key] = None
                sub[key] = ScoredValue(value=None, n=denominator, reason=why)
        else:
            ratios = [_clamp01(float(_row_at(rows, e).accuracy) / acc_clean) for e in grid]
            s_acc = min(ratios)
            s_eps = _clamp01(trapezoid_auc_normalized(grid, ratios))
            frac["S_acc"], sub["S_acc"] = s_acc, _scored(s_acc, n)
            frac["S_eps"], sub["S_eps"] = s_eps, _scored(s_eps, n)
            asr = ref_row.attack_success_rate
            if asr is None:
                frac["S_asr"] = None
                sub["S_asr"] = ScoredValue(value=None, n=ref_row.n_clean_correct,
                                           reason=f"asr undefined at eps {ref:g} (n_clean_correct == 0)")
            else:
                s_asr = 1.0 - _clamp01(asr)
                frac["S_asr"], sub["S_asr"] = s_asr, _scored(s_asr, ref_row.n_clean_correct)
        gap = ref_row.conf_gap_mean
        if gap is None:
            frac["S_conf"] = None
            sub["S_conf"] = ScoredValue(value=None, n=ref_row.conf_gap_n,
                                        reason=f"conf_gap_mean missing at eps {ref:g}")
        else:
            s_conf = 1.0 - _clamp01(gap)
            frac["S_conf"], sub["S_conf"] = s_conf, _scored(s_conf, ref_row.conf_gap_n)
        shift = ref_row.expl_shift_mean
        if shift is None:
            frac["S_expl"] = None
            sub["S_expl"] = ScoredValue(value=None, n=ref_row.expl_shift_n,
                                        reason=(f"explanation stability unavailable (no expl_shift_mean at eps "
                                                f"{ref:g}: explain stage not run, unsupported or failed)"))
        else:
            s_expl = 1.0 - _clamp01(shift)
            frac["S_expl"], sub["S_expl"] = s_expl, _scored(s_expl, ref_row.expl_shift_n)
        per_attack[a] = PerAttackSubscores(**sub)
        raw[a] = frac
        for k in SUBSCORE_KEYS:
            if frac[k] is None:
                unavailable[k].append(f"{a}: {sub[k].reason}")

    values: dict[str, float | None] = {}
    missing: list[str] = []
    for k in SUBSCORE_KEYS:
        if unavailable[k]:
            values[k] = None
            missing.append(f"{k} unavailable ({'; '.join(unavailable[k])})")
        else:
            present = [f for a in attack_ids if (f := raw[a][k]) is not None]
            values[k] = round(100.0 * sum(present) / len(present), 1)

    base: dict[str, Any] = {
        "scoring_version": config.scoring.version, "weights": config.scoring.weights, "eps_grid": grid,
        "reference_eps": ref, "norm": config.norm, "attack_ids": attack_ids,
        "finding_asr_threshold": float(config.finding_asr_threshold), "settings_hash": shash,
        "inputs": inputs, "per_attack": per_attack, "subscores": Subscores(**values),
        "computed_at": computed_at or datetime.now(UTC),
    }
    if missing:
        avail = ", ".join(f"{k}={values[k]:.1f}" for k in SUBSCORE_KEYS if values[k] is not None) or "none"
        reason = ("MRI not computed: " + "; ".join(missing) +
                  f". Available subscores (weights not renormalised): {avail}.")
        record = MRIRecord(**base, mri=None, grade=None, completeness="partial", missing=missing, reading=None)
        return record, reason

    complete = {k: v for k, v in values.items() if v is not None}
    weighted = sum(weights[k] * complete[k] for k in SUBSCORE_KEYS)
    mri = max(0, min(100, round(weighted)))     # Python round-half-to-even on the weighted sum
    grade = grade_for_mri(mri)
    record = MRIRecord(**base, mri=mri, grade=grade, completeness="complete", missing=[],
                       reading=reading_for(grade, config))
    return record, None


# --- delta MRI on verify (spec 15.6) ----------------------------------------------------------------

def _clean_point(record: MRIRecord, measurements: Sequence[Measurement] | None) -> AccuracyPoint:
    if measurements is not None:
        m = clean_row(measurements)
        if m is not None:
            return AccuracyPoint(n=m.n, n_correct=m.n_correct, accuracy=m.accuracy)
    if not record.inputs:
        raise ValueError("score record has no inputs; cannot recover the clean accuracy")
    row = record.inputs[0]
    if row.n_correct_clean is None or row.acc_clean is None:
        raise ValueError("score record inputs lack the clean denominators")
    return AccuracyPoint(n=row.n, n_correct=row.n_correct_clean, accuracy=row.acc_clean)


def _adv_point(row: MRIInputRow, measurements: Sequence[Measurement] | None) -> AccuracyPoint:
    mid = f"m.evasion.{row.attack_id}.{eps_tag(row.eps)}"
    if measurements is not None:
        m = next((x for x in measurements if x.id == mid), None)
        if m is not None:
            return AccuracyPoint(n=m.n, n_correct=m.n_correct, accuracy=m.accuracy)
    if row.acc_adv is None:
        raise ValueError(f"score record input {mid} lacks acc_adv")
    return AccuracyPoint(n=row.n, n_correct=round(row.acc_adv * row.n), accuracy=row.acc_adv)


def delta(before: MRIRecord, after: MRIRecord, *, baseline_run_id: str,
          measurements_before: Sequence[Measurement] | None = None,
          measurements_after: Sequence[Measurement] | None = None) -> MRIDelta:
    """The measured ΔMRI of a verify run against its baseline (spec 15.6).

    Both records must be complete and share ``settings_hash``, scoring version, eps grid, reference
    budget, norm, attack set and weight vector; otherwise ``ValueError`` (surfaced by the API as 409
    incompatible_campaigns). The clean-accuracy change always travels with the delta. Family deltas
    are exact when the measurement lists are given and are otherwise reconstructed from the
    ``inputs`` rows (``n_correct = round(acc_adv * n)``)."""
    if before.mri is None or after.mri is None:
        raise ValueError("delta needs two complete score records (mri computed on both)")
    problems: list[str] = []
    if before.settings_hash != after.settings_hash:
        problems.append("settings_hash differs")
    if before.scoring_version != after.scoring_version:
        problems.append(f"scoring version {before.scoring_version!r} != {after.scoring_version!r}")
    if [round(e, 12) for e in sorted(before.eps_grid)] != [round(e, 12) for e in sorted(after.eps_grid)]:
        problems.append(f"eps grid {before.eps_grid} != {after.eps_grid}")
    if not _same_eps(before.reference_eps, after.reference_eps):
        problems.append(f"reference eps {before.reference_eps} != {after.reference_eps}")
    if before.norm != after.norm:
        problems.append(f"norm {before.norm!r} != {after.norm!r}")
    if sorted(before.attack_ids) != sorted(after.attack_ids):
        problems.append(f"attack set {before.attack_ids} != {after.attack_ids}")
    if before.weights.as_dict() != after.weights.as_dict():
        problems.append("weight vectors differ")
    if problems:
        raise ValueError("incompatible campaigns: " + "; ".join(problems))

    sub_delta = Subscores(**{
        k: round(float(getattr(after.subscores, k)) - float(getattr(before.subscores, k)), 1) for k in SUBSCORE_KEYS})
    clean_b = _clean_point(before, measurements_before)
    clean_a = _clean_point(after, measurements_after)
    clean_delta = (None if clean_a.accuracy is None or clean_b.accuracy is None
                   else float(clean_a.accuracy) - float(clean_b.accuracy))
    families: list[FamilyDelta] = []
    for rb in before.inputs:
        ra = next((r for r in after.inputs if r.attack_id == rb.attack_id and _same_eps(r.eps, rb.eps)), None)
        if ra is None:
            continue
        pb = _adv_point(rb, measurements_before)
        pa = _adv_point(ra, measurements_after)
        d = None if pa.accuracy is None or pb.accuracy is None else float(pa.accuracy) - float(pb.accuracy)
        families.append(FamilyDelta(measurement_id=f"m.evasion.{rb.attack_id}.{eps_tag(rb.eps)}",
                                    before=pb, after=pa, delta=d))
    return MRIDelta(
        baseline_run_id=baseline_run_id, mri_before=int(before.mri), mri_after=int(after.mri),
        delta=int(after.mri) - int(before.mri), delta_subscores=sub_delta,
        delta_acc_clean=CleanAccuracyDelta(before=clean_b, after=clean_a, delta=clean_delta),
        delta_families=families,
    )


# --- robustness curve (spec 12.3): the ml.curve artifact and the /campaign ``curve`` field ------------------

def control_rows(measurements: Sequence[Measurement]) -> dict[float, Measurement]:
    """``eps -> row`` for the benign-noise control rows (eps read from ``params["eps"]``)."""
    out: dict[float, Measurement] = {}
    for m in measurements:
        if m.family == "control" and (e := eps_of(m)) is not None:
            out[e] = m
    return out


def _curve_point(eps: float, m: Measurement) -> CurvePoint:
    return CurvePoint(eps=float(eps), n=m.n, n_correct=m.n_correct, accuracy=m.accuracy if m.n > 0 else None,
                      n_clean_correct=m.n_clean_correct, n_flipped_from_clean=m.n_flipped_from_clean,
                      asr=m.attack_success_rate)


def robustness_curve(config: CampaignConfig, measurements: Sequence[Measurement], attack_id: str) -> RobustnessCurve:
    """One attack's accuracy / ASR curve over the declared grid, with the control at the same eps.

    Read from the measurement table so the curve and the rows can never disagree: a grid eps without a
    row is simply absent from ``points`` (a partial run draws a partial curve). ``ValueError`` without a
    clean row, since the curve has nothing to anchor to."""
    clean = clean_row(measurements)
    if clean is None:
        raise ValueError("no clean row (m.clean) among the measurements; the curve has no anchor")
    grid = [float(e) for e in config.eps_grid]
    rows = evasion_rows(measurements, attack_id)
    ctrl = control_rows(measurements)
    points = [_curve_point(e, m) for e in grid if (m := _lookup(rows, e)) is not None]
    control = [_curve_point(e, m) for e in grid if (m := _lookup(ctrl, e)) is not None]
    return RobustnessCurve(
        attack_id=attack_id, norm=config.norm, eps_grid=grid, reference_eps=float(config.reference_eps),
        clean=AccuracyPoint(n=clean.n, n_correct=clean.n_correct, accuracy=clean.accuracy if clean.n > 0 else None),
        points=points, control=control,
    )


def robustness_curves(config: CampaignConfig, measurements: Sequence[Measurement]) -> list[RobustnessCurve]:
    """A ``RobustnessCurve`` per declared attack, in ``config.attack_ids`` order."""
    return [robustness_curve(config, measurements, a) for a in dict.fromkeys(config.attack_ids)]


__all__ = [
    "GRADE_READINGS",
    "GRADE_SENTENCE",
    "MIN_CLEAN_CORRECT_FOR_FINDING",
    "ONE_POINT_GRID_LIMITATION",
    "SCORING_VERSION",
    "SUBSCORE_KEYS",
    "Confidence",
    "FindingInputs",
    "Severity",
    "asr_by_eps",
    "canonical_settings_json",
    "clean_row",
    "confidence_for",
    "contains_banned_wording",
    "control_rows",
    "delta",
    "eps_bands",
    "evasion_rows",
    "finding_inputs",
    "first_success",
    "input_rows",
    "reading_for",
    "robustness_curve",
    "robustness_curves",
    "score_run",
    "settings_hash",
    "severity_for",
    "trapezoid_auc_normalized",
    "weights_by_subscore",
]
