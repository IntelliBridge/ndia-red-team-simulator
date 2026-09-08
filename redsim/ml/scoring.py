"""Model Robustness Index (spec section 15 and master plan section 5).

    MRI = round(0.35*S_acc + 0.25*S_asr + 0.20*S_eps + 0.10*S_conf + 0.10*S_expl)

Pure functions only. ``score_run`` returns ``(Scoring, None)`` when all five subscores
exist and ``(None, reason)`` otherwise; weights are NEVER renormalised over the
available dimensions (spec 15.4). One campaign = one model x one modality x one
declared attack set x one eps grid x one reference budget; nothing here aggregates
across those boundaries (D9 i). ``severity_for`` derives Finding severity from the
first-success budget and the ASR (spec 15.5); nothing sets severity by hand.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from itertools import pairwise
from typing import Any, Literal

from redsim.ml.schema import Domain, Scoring

Severity = Literal["critical", "high", "medium", "low"]

SUBSCORE_KEYS: tuple[str, ...] = ("S_acc", "S_asr", "S_eps", "S_conf", "S_expl")
DEFAULT_WEIGHTS: dict[str, float] = {"S_acc": 0.35, "S_asr": 0.25, "S_eps": 0.20, "S_conf": 0.10, "S_expl": 0.10}
_WEIGHT_ALIASES = {"acc": "S_acc", "asr": "S_asr", "eps": "S_eps", "conf": "S_conf", "expl": "S_expl"}

FINDING_ASR_THRESHOLD = 0.2
SEVERITY_ASR_HIGH = 0.5
SEVERITY_ASR_MID = 0.2
SCORING_VERSION = "mri-1.0"

GRADE_READINGS: dict[str, str] = {
    "A": ("Under the in-scope attacks at the declared eps grid, accuracy and attributions were "
          "essentially unchanged on this slice."),
    "B": "Minor degradation under the strongest in-scope attack at the reference budget.",
    "C": "Substantial degradation under the in-scope iterative attack at the reference budget.",
    "D": "The cheapest in-scope attack succeeded at the reference budget on a large share of the slice.",
    "F": "Predictions flipped at the smallest eps in the declared grid on most of the slice.",
}
GRADE_SENTENCE = ("A grade describes measured behaviour under the declared attack set, eps grid and slice. "
                  "It is not a readiness, safety, or certification statement, and it does not describe "
                  "robustness to attacks that were not run.")
GRADE_BANDS: tuple[tuple[int, str], ...] = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F"))

# Words that must not appear as grade text, badge text or narrative (spec 15.8 iii). Checked
# against readings by tests and exposed so the narrative layer can reuse the same list.
BANNED_GRADE_WORDS: tuple[str, ...] = ("hardened", "harden before fielding", "deployment-ready",
                                       "not deployment-ready", "certified", "safe", "fielding")
_BANNED_RE = re.compile(r"hardened|fielding|deployment-ready|certif|\bsafe\b", re.IGNORECASE)


def contains_banned_wording(text: str) -> bool:
    return bool(_BANNED_RE.search(text or ""))


def _clamp01(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


def normalize_weights(weights: Mapping[str, float] | None) -> dict[str, float]:
    """Accept ``S_acc``-style or ``acc``-style keys. All five must be present and sum to 1.0."""
    if weights is None:
        return dict(DEFAULT_WEIGHTS)
    out: dict[str, float] = {}
    for k, v in weights.items():
        key = _WEIGHT_ALIASES.get(str(k), str(k))
        if key not in SUBSCORE_KEYS:
            raise ValueError(f"unknown weight key {k!r}; expected one of {SUBSCORE_KEYS}")
        out[key] = float(v)
    missing = [k for k in SUBSCORE_KEYS if k not in out]
    if missing:
        raise ValueError(f"weights missing {missing}; all five dimensions must carry a weight")
    if any(v < 0 for v in out.values()):
        raise ValueError("weights must be non-negative")
    if not math.isclose(sum(out.values()), 1.0, abs_tol=1e-9):
        raise ValueError(f"weights must sum to 1.0, got {sum(out.values())!r}")
    return {k: out[k] for k in SUBSCORE_KEYS}


def grade_for(mri: int) -> str:
    if not 0 <= mri <= 100:
        raise ValueError(f"MRI out of range: {mri}")
    for floor, grade in GRADE_BANDS:
        if mri >= floor:
            return grade
    return "F"  # pragma: no cover - unreachable, floor 0 always matches


def eps_bands(eps_grid: list[float], reference_eps: float) -> tuple[float, float, float]:
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


def trapezoid_auc_normalized(xs: list[float], ys: list[float]) -> float:
    """Trapezoid rule over the declared grid only, divided by ``(x_max - x_min)``. A one-point grid
    degenerates to the value at that point (spec 15.2)."""
    pairs = sorted(zip((float(x) for x in xs), (float(y) for y in ys)))
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


def _eps_key(eps: float) -> str:
    return f"{float(eps):g}"


def _lookup(rows: Mapping[float, Mapping[str, Any]], eps: float) -> Mapping[str, Any] | None:
    for k, v in rows.items():
        if math.isclose(float(k), float(eps), rel_tol=0.0, abs_tol=1e-12):
            return v
    return None


def score_run(*, modality: Domain, acc_clean: float,
              per_attack: Mapping[str, Mapping[float, Mapping[str, Any]]],
              eps_grid: list[float], reference_eps: float,
              weights: Mapping[str, float] | None = None,
              basis_measurements: list[str]) -> tuple[Scoring | None, str | None]:
    """Compute the MRI for one campaign.

    ``per_attack`` maps ``attack_id -> eps -> {acc_adv, asr, conf_gap, expl_shift | None, pert | None}``.
    Returns ``(Scoring, None)`` when every one of the five subscores is available for every
    attack, else ``(None, reason)``; the reason names the missing dimension and lists the
    subscores that were available so the limitation text can show them. Weights are never
    renormalised. Raises ``ValueError`` for configuration errors (bad weights, reference eps not
    in the grid, empty attack set, mixed norms are the caller's problem)."""
    w = normalize_weights(weights)
    grid = sorted(float(e) for e in eps_grid)
    if not grid:
        raise ValueError("eps_grid must not be empty")
    if not any(math.isclose(float(reference_eps), e, abs_tol=1e-12) for e in grid):
        raise ValueError(f"reference_eps {reference_eps} is not a member of eps_grid {grid}")
    attack_ids = sorted(per_attack)
    if not attack_ids:
        raise ValueError("per_attack is empty: a campaign scores at least one attack")

    inputs: dict[str, Any] = {
        "acc_clean": float(acc_clean),
        "per_attack": {a: {_eps_key(e): dict(v) for e, v in per_attack[a].items()} for a in attack_ids},
        "per_attack_subscores": {},
        "scoring_version": SCORING_VERSION,
        "notes": [],
    }
    if len(grid) == 1:
        inputs["notes"].append("one-point eps grid: S_eps degenerates to the robust-accuracy ratio at that point")

    if acc_clean <= 0.0:
        return None, ("MRI not computed: S_acc, S_asr, S_eps unavailable (acc_clean == 0; denominator 0). "
                      "No subscore could be computed.")

    per_attack_sub: dict[str, dict[str, float | None]] = {}
    missing: list[str] = []
    for a in attack_ids:
        rows = per_attack[a]
        for e in grid:
            if _lookup(rows, e) is None:
                return None, (f"MRI not computed: partial run; attack {a!r} has no row at eps {e:g}. "
                              "No subscore is reported for a partial run.")
        ratios = [_clamp01(float(_lookup(rows, e)["acc_adv"]) / acc_clean) for e in grid]  # type: ignore[index]
        ref = _lookup(rows, reference_eps)
        assert ref is not None
        sub: dict[str, float | None] = {
            "S_acc": min(ratios),
            "S_eps": _clamp01(trapezoid_auc_normalized(grid, ratios)),
        }
        asr = ref.get("asr")
        sub["S_asr"] = None if asr is None else 1.0 - _clamp01(float(asr))
        if asr is None:
            missing.append(f"S_asr for {a!r} (asr undefined at eps {reference_eps:g}: n_clean_correct == 0)")
        cg = ref.get("conf_gap")
        sub["S_conf"] = None if cg is None else 1.0 - _clamp01(float(cg))
        if cg is None:
            missing.append(f"S_conf for {a!r} (conf_gap missing at eps {reference_eps:g})")
        es = ref.get("expl_shift")
        sub["S_expl"] = None if es is None else 1.0 - _clamp01(float(es))
        if es is None:
            missing.append(f"S_expl for {a!r} (explanation stability unavailable at eps {reference_eps:g})")
        per_attack_sub[a] = sub

    subscores: dict[str, float] = {}
    available: dict[str, float] = {}
    for key in SUBSCORE_KEYS:
        present = [float(v) for a in attack_ids if (v := per_attack_sub[a][key]) is not None]
        if len(present) == len(attack_ids):
            available[key] = round(100.0 * sum(present) / len(present), 1)
    inputs["per_attack_subscores"] = {
        a: {k: (None if v is None else round(100.0 * v, 1)) for k, v in per_attack_sub[a].items()}
        for a in attack_ids}

    if missing:
        avail_txt = ", ".join(f"{k}={available[k]:.1f}" for k in SUBSCORE_KEYS if k in available) or "none"
        return None, ("MRI not computed: " + "; ".join(missing) +
                      f". Available subscores (weights not renormalised): {avail_txt}.")

    subscores = {k: available[k] for k in SUBSCORE_KEYS}
    weighted = sum(w[k] * subscores[k] for k in SUBSCORE_KEYS)
    mri = round(weighted)  # Python round-half-to-even on the weighted sum (returns int)
    mri = max(0, min(100, mri))
    grade = grade_for(mri)
    reading = GRADE_READINGS[grade]
    assert not contains_banned_wording(reading)
    scoring = Scoring(
        mri=mri, grade=grade, reading=reading, subscores=subscores, weights=w,
        reference_eps=float(reference_eps), eps_grid=grid, attack_ids=attack_ids, modality=modality,
        inputs=inputs, basis_measurements=list(basis_measurements),
    )
    return scoring, None


def first_success(rows: Mapping[float, Mapping[str, Any]],
                  threshold: float = FINDING_ASR_THRESHOLD) -> tuple[float | None, float | None]:
    """Smallest grid eps whose ASR crosses ``threshold`` and the ASR there, or ``(None, None)`` when the
    attack never crosses it or the ASR is undefined everywhere."""
    for e in sorted(float(k) for k in rows):
        asr = _lookup(rows, e).get("asr")  # type: ignore[union-attr]
        if asr is not None and float(asr) >= threshold:
            return e, float(asr)
    return None, None


def severity_for(attack_id: str, first_success_eps: float | None, asr_at_first_success: float | None,
                 eps_small: float, eps_mid: float, eps_large: float) -> Severity | None:
    """Derived Finding severity (spec 15.5). ``None`` when the attack never succeeded."""
    if first_success_eps is None or asr_at_first_success is None:
        return None
    eps = float(first_success_eps)
    asr = float(asr_at_first_success)
    tol = 1e-12
    if eps <= eps_small + tol:
        if asr >= SEVERITY_ASR_HIGH:
            return "critical"
        if asr >= SEVERITY_ASR_MID:
            return "high"
        return "medium"  # only reachable when finding_asr_threshold is configured below 0.2
    if eps <= eps_mid + tol:
        return "high" if asr >= SEVERITY_ASR_HIGH else "medium"
    return "low"


def delta(before: Scoring, after: Scoring, *, before_run_id: str | None = None) -> Scoring:
    """ΔMRI on verify (spec 15.6): ``after`` annotated with ``delta_mri`` / ``delta_subscores``.

    Both campaigns must share modality, attack set, eps grid, reference budget and weights;
    otherwise the comparison is refused with ``ValueError`` (surfaced as 409 incompatible_campaigns).
    ``settings_hash`` and ``sample_indices_sha256`` equality are checked by the caller, which
    holds the provenance."""
    problems: list[str] = []
    if before.modality != after.modality:
        problems.append(f"modality {before.modality!r} != {after.modality!r}")
    if sorted(before.attack_ids) != sorted(after.attack_ids):
        problems.append(f"attack set {before.attack_ids} != {after.attack_ids}")
    if [round(e, 12) for e in sorted(before.eps_grid)] != [round(e, 12) for e in sorted(after.eps_grid)]:
        problems.append(f"eps grid {before.eps_grid} != {after.eps_grid}")
    if not math.isclose(before.reference_eps, after.reference_eps, abs_tol=1e-12):
        problems.append(f"reference eps {before.reference_eps} != {after.reference_eps}")
    if normalize_weights(before.weights) != normalize_weights(after.weights):
        problems.append("weight vectors differ")
    if problems:
        raise ValueError("incompatible campaigns: " + "; ".join(problems))
    sub_delta = {k: round(after.subscores[k] - before.subscores[k], 1) for k in SUBSCORE_KEYS}
    return after.model_copy(update={
        "delta_from": before_run_id,
        "delta_mri": int(after.mri - before.mri),
        "delta_subscores": sub_delta,
    })
