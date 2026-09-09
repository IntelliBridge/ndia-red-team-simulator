"""Deterministic rule layer (spec sections 14.6 and 16.2).

``interpret`` turns measurement / observation rows into ``Interpretation``
sentences (``kind="inferred"``) whose ``basis`` cites the ids they rest on.
``recommend`` turns the same evidence into ``CandidateRecommendation`` rows
(``status="candidate"``, ``validation="not evaluated"``, ``measured=None``)
that cite the ids that triggered them and name the defense they map to as a
``defense:<id>`` reference. ``<id>`` is a ``DefenseConfig.id`` the verify loop
accepts (``feature_squeezing``, ``spatial_smoothing``, ``jpeg_compression``) or
the Phase B apply step ``adversarial_training``. ``defense_configs`` turns
those references back into ``DefenseConfig`` rows.

Both entry points take ``(measurements, observations, score: MRIRecord | None)``
plus an optional fourth ``settings: ScoringConfig`` whose ``interpretation``
block supplies the thresholds (the keywords ``thresholds`` and
``finding_asr_threshold`` override it). ``recommend`` also accepts the campaign
runner's order ``(measurements, observations, interpretation, score)``: a list
in the ``score`` slot is the interpretation list. Every cited id is the id of a
measurement, observation or interpretation the caller passed in, so a
``RunRecord`` built from the output never carries a dangling citation.
``THRESHOLDS`` holds the default thresholds.

No rule asserts a cause in the training data or architecture. No rule states a
numeric gain: direction only, until a verify run measures a delta MRI.
Thresholds are printed next to each statement. Rule ids are stable (``r.R3``
means the same rule in every run).

The benign-control comparison in I1 / R1 (and its complement in I2 / R1b) is
``redsim.ml.scoring.control_preserves_accuracy``, the spec 12.4 binomial
predicate, not a fixed tolerance: a control is "flat" when its accuracy is
within two percentage points of the clean accuracy or not significantly below
it (one-sided exact binomial test at ``THRESHOLDS["control_alpha"]``). I8 is
the spec 12.4 noise-sensitivity statement: the control alone crossing
``finding_asr_threshold`` at some grid eps.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from redsim.ml.schema import (
    CandidateRecommendation,
    DefenseConfig,
    Interpretation,
    InterpretationThresholds,
    Measurement,
    MRIRecord,
    Observation,
    ScoringConfig,
)
from redsim.ml.scoring import (
    CONTROL_ACCURACY_FLOOR,
    DEFAULT_CONTROL_ALPHA,
    control_degradation_pvalue,
    control_preserves_accuracy,
)

logger = logging.getLogger(__name__)

DEFAULT_FINDING_ASR_THRESHOLD = 0.2   # CampaignConfig.finding_asr_threshold default
_DEFAULT_IT = InterpretationThresholds()

# Defaults. ``effective_thresholds`` overlays the campaign's InterpretationThresholds and ASR threshold.
THRESHOLDS: dict[str, float] = {
    "attack_drop": _DEFAULT_IT.evasion_drop,          # I1: attack accuracy drop vs clean at eps_ref
    "control_alpha": DEFAULT_CONTROL_ALPHA,           # I1 / R1: significance level of the binomial control predicate
    "control_flat": _DEFAULT_IT.control_tolerance,    # mirrored from the frozen schema; retired from I1 / R1 (spec 12.4)
    "control_drop": _DEFAULT_IT.control_drop,         # I2 / R1b: control reduced accuracy by at least this
    "iterative_gap": _DEFAULT_IT.iterative_margin,    # I3 / R2: pgd worse than fgsm by at least this at the same eps
    "cmr_drop": _DEFAULT_IT.center_mass_drop,         # I4 / R3: centre-mass drop on flipped samples (heuristic)
    "expl_shift": _DEFAULT_IT.expl_shift_high,        # I5 / R3
    "conf_gap": _DEFAULT_IT.conf_gap_high,            # I6 / R4
    "asr": DEFAULT_FINDING_ASR_THRESHOLD,             # R1 / R1b / R5: finding_asr_threshold
    "any_drop": 0.05,                                 # R6
    "top3_changed_fraction": 0.5,                     # R3t
}

# Defense ids a candidate may map to. The first three are DefenseConfig ids the verify loop applies
# (redsim.ml.defenses); adversarial_training is the Phase B apply step.
DEFENSE_IDS: tuple[str, ...] = ("feature_squeezing", "spatial_smoothing", "jpeg_compression", "adversarial_training")

# defense id -> (ART class path, motivating reference, phase / runnable note)
_DEFENSES: dict[str, tuple[str, str, str]] = {
    "adversarial_training": ("art.defences.trainer.AdversarialTrainerMadryPGD",
                             "Madry et al. 2018, Towards Deep Learning Models Resistant to Adversarial Attacks",
                             "Phase B apply step, not runnable by the Phase A verify loop"),
    "feature_squeezing": ("art.defences.preprocessor.FeatureSqueezing",
                          "Xu, Evans, Qi 2018, Feature Squeezing", "Phase A verify loop"),
    "spatial_smoothing": ("art.defences.preprocessor.SpatialSmoothing",
                          "Xu, Evans, Qi 2018, Feature Squeezing", "Phase A verify loop"),
    "jpeg_compression": ("art.defences.preprocessor.JpegCompression",
                         "Dziugaite, Ghahramani, Roy 2016, A study of the effect of JPG compression on adversarial images",
                         "Phase A verify loop (image)"),
}
_DIRECTION_ONLY = ("Intended direction only: expected gain is not measured until a verify run reports a "
                   "measured delta MRI on this model at these settings.")


def effective_thresholds(thresholds: InterpretationThresholds | None,
                         finding_asr_threshold: float | None) -> dict[str, float]:
    """``THRESHOLDS`` with the campaign's ``InterpretationThresholds`` and ASR threshold applied."""
    it = thresholds or _DEFAULT_IT
    out = dict(THRESHOLDS)
    out.update({"attack_drop": it.evasion_drop, "control_flat": it.control_tolerance, "control_drop": it.control_drop,
                "iterative_gap": it.iterative_margin, "cmr_drop": it.center_mass_drop,
                "expl_shift": it.expl_shift_high, "conf_gap": it.conf_gap_high})
    if finding_asr_threshold is not None:
        out["asr"] = float(finding_asr_threshold)
    return out


def _resolve_thresholds(settings: ScoringConfig | None,
                        thresholds: InterpretationThresholds | None) -> InterpretationThresholds | None:
    """The explicit ``thresholds`` keyword wins, else the ``interpretation`` block of ``settings``."""
    if thresholds is not None:
        return thresholds
    return settings.interpretation if settings is not None else None


def _positional_contract(score: Any, settings: Any, interpretation: Any,
                         ) -> tuple[MRIRecord | None, ScoringConfig | None, list[Interpretation] | None]:
    """Normalise ``recommend``'s positional arguments.

    The plan's order is ``(measurements, observations, score[, settings])``. The campaign runner calls
    ``recommend(measurements, observations, interpretation, score)``, so a list in the ``score`` slot is
    the interpretation list and the ``settings`` slot then carries the score record (or ``None``).
    """
    if isinstance(score, (list, tuple)):
        interp = list(interpretation) if interpretation is not None else list(score)
        if settings is None or isinstance(settings, MRIRecord):
            return settings, None, interp
        if isinstance(settings, ScoringConfig):
            return None, settings, interp
        raise TypeError(f"recommend(): unexpected positional argument of type {type(settings).__name__}")
    if score is not None and not isinstance(score, MRIRecord):
        raise TypeError(f"recommend(): score must be an MRIRecord or None, got {type(score).__name__}")
    if settings is not None and not isinstance(settings, ScoringConfig):
        raise TypeError(f"recommend(): settings must be a ScoringConfig or None, got {type(settings).__name__}")
    return score, settings, None if interpretation is None else list(interpretation)


# --------------------------------------------------------------------------- evidence context

def _eps(m: Measurement | None) -> float | None:
    if m is None:
        return None
    e = m.params.get("eps")
    if isinstance(e, bool) or not isinstance(e, (int, float)):
        return None
    return float(e)


def _same(a: float | None, b: float | None, tol: float = 1e-9) -> bool:
    return a is not None and b is not None and math.isclose(a, b, rel_tol=1e-6, abs_tol=tol)


def _attack_is(attack_id: str | None, name: str) -> bool:
    if not attack_id:
        return False
    a = attack_id.lower()
    return a == name or a.startswith((name + "_", name + "-"))


def _num(v: Any) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and not math.isnan(float(v)) else None


@dataclass
class _Ctx:
    clean: Measurement | None
    evasion: list[Measurement]
    controls: list[Measurement]
    ref_eps: float | None
    eps_grid: list[float]
    score: MRIRecord | None
    explain_meta: dict[str, Any]
    t: dict[str, float]
    ids: set[str] = field(default_factory=set)

    @property
    def acc_clean(self) -> float | None:
        return None if self.clean is None else float(self.clean.accuracy)

    def rows(self, attack_id: str) -> dict[float, Measurement]:
        return {e: m for m in self.evasion if m.attack_id == attack_id and (e := _eps(m)) is not None}

    def attack_ids(self) -> list[str]:
        seen: list[str] = []
        for m in self.evasion:
            if m.attack_id and m.attack_id not in seen:
                seen.append(m.attack_id)
        return seen

    def at(self, attack_id: str, eps: float | None) -> Measurement | None:
        for e, m in self.rows(attack_id).items():
            if _same(e, eps):
                return m
        return None

    def control_at(self, eps: float | None) -> Measurement | None:
        for m in self.controls:
            if _same(_eps(m), eps):
                return m
        return None

    def asr(self, m: Measurement | None) -> float | None:
        """The row's recorded ASR, else ``n_flipped_from_clean`` over the clean-correct denominator."""
        if m is None:
            return None
        if m.attack_success_rate is not None:
            return float(m.attack_success_rate)
        denom = m.n_clean_correct if m.n_clean_correct is not None else (
            self.clean.n_correct if self.clean is not None else None)
        if m.n_flipped_from_clean is None or not denom or denom <= 0:
            return None
        return float(m.n_flipped_from_clean) / float(denom)

    def eps_small(self) -> float | None:
        return min(self.eps_grid) if self.eps_grid else None

    def exposure(self, attack_id: str) -> tuple[float, float]:
        """Spec 15.5 ordering key for one attack: (first-success eps, -ASR there). Smaller is more exposed."""
        for eps, m in sorted(self.rows(attack_id).items()):
            a = self.asr(m)
            if a is not None and a >= self.t["asr"]:
                return (eps, -a)
        return (math.inf, 0.0)


def _context(measurements: list[Measurement], score: MRIRecord | None, explain_meta: dict[str, Any] | None,
             reference_eps: float | None, thresholds: InterpretationThresholds | None,
             finding_asr_threshold: float | None) -> _Ctx:
    clean = next((m for m in measurements if m.family == "clean"), None)
    evasion = [m for m in measurements if m.family == "evasion"]
    controls = [m for m in measurements if m.family == "control"]
    grid = sorted({e for m in evasion if (e := _eps(m)) is not None})
    if not grid and score is not None:
        grid = sorted(float(e) for e in score.eps_grid)
    ref = reference_eps
    if ref is None and score is not None:
        ref = float(score.reference_eps)
    if ref is None:
        ctrl_eps = sorted({e for m in controls if (e := _eps(m)) is not None})
        if len(ctrl_eps) == 1:
            ref = ctrl_eps[0]
        elif grid:
            ref = grid[len(grid) // 2]
    asr_t = finding_asr_threshold
    if asr_t is None and score is not None:
        asr_t = float(score.finding_asr_threshold)
    return _Ctx(clean=clean, evasion=evasion, controls=controls, ref_eps=ref, eps_grid=grid, score=score,
                explain_meta=dict(explain_meta or {}), t=effective_thresholds(thresholds, asr_t),
                ids={m.id for m in measurements})


def _score_input(score: MRIRecord | None, attack_id: str | None, eps: float | None, key: str) -> float | None:
    """``MRIRecord.inputs`` row for ``(attack, eps)``: ``expl_shift`` or ``conf_gap``."""
    if score is None or attack_id is None:
        return None
    for row in score.inputs:
        if row.attack_id == attack_id and _same(row.eps, eps):
            return _num(getattr(row, key, None))
    return None


def _metric(ctx: _Ctx, m: Measurement | None, key: str) -> float | None:
    """``expl_shift`` / ``conf_gap`` for a row: its own ``<key>_mean`` field, else the score inputs, else explain meta."""
    if m is None:
        return None
    own = _num(getattr(m, f"{key}_mean", None))
    if own is not None:
        return own
    v = _score_input(ctx.score, m.attack_id, _eps(m), key)
    if v is not None:
        return v
    if key == "expl_shift":
        meta = ctx.explain_meta
        per_attack = meta.get("per_attack")
        if isinstance(per_attack, dict) and isinstance(per_attack.get(m.attack_id), dict):
            v = _num(per_attack[m.attack_id].get("expl_shift_mean"))
            if v is not None:
                return v
        v = _num(meta.get("expl_shift_mean"))
        single = (len(ctx.attack_ids()) <= 1 or meta.get("attack_id") == m.attack_id
                  or meta.get("flat_from_attack") == m.attack_id)
        if v is not None and single and _same(_eps(m), ctx.ref_eps):
            return v
    return None


def _cmr_drop(observations: list[Observation]) -> tuple[float | None, float | None, list[str]]:
    pairs = [(o.id, float(o.center_mass_ratio_clean), float(o.center_mass_ratio_adv)) for o in observations
             if o.flipped and o.center_mass_ratio_clean is not None and o.center_mass_ratio_adv is not None]
    if not pairs:
        return None, None, []
    mc = sum(c for _, c, _ in pairs) / len(pairs)
    ma = sum(a for _, _, a in pairs) / len(pairs)
    return mc, ma, [oid for oid, _, _ in pairs]


def _top3_changed(observations: list[Observation]) -> tuple[float | None, int, list[str]]:
    """Tabular: fraction of flipped observations whose top-3 feature set changed, its n, and the changed ids."""
    rows = [(o.id, set(o.top_features_clean[:3]) != set(o.top_features_adv[:3])) for o in observations
            if o.flipped and o.top_features_clean and o.top_features_adv]
    if not rows:
        return None, 0, []
    changed = [oid for oid, flag in rows if flag]
    return len(changed) / len(rows), len(rows), changed


def _interp_ids(interpretation: Iterable[Interpretation] | None, code: str, must_cite: Iterable[str]) -> list[str]:
    """Ids of the ``<code>:`` interpretations whose basis meets ``must_cite`` (the rows the rule itself cites)."""
    wanted = set(must_cite)
    if not wanted:
        return []
    return [i.id for i in (interpretation or []) if i.statement.startswith(code + ":") and wanted & set(i.basis)]


def _eps_txt(e: float | None) -> str:
    return "reference" if e is None else f"{e:g}"


def _eps_sort_key(m: Measurement) -> float:
    e = _eps(m)
    return math.inf if e is None else e


def _control_flat(clean: Measurement, ctrl: Measurement, t: dict[str, float]) -> bool:
    """Spec 12.4 predicate: the control did not degrade accuracy (binomial, not a fixed tolerance)."""
    return control_preserves_accuracy(clean, ctrl, alpha=t["control_alpha"])


def _control_verdict(clean: Measurement, ctrl: Measurement, t: dict[str, float]) -> str:
    """The counts and the test printed next to every I1 / I2 / R1 / R1b statement (spec 14.6: thresholds
    travel with the sentence)."""
    p = control_degradation_pvalue(clean, ctrl)
    p_txt = "undefined (denominator 0)" if p is None else f"{p:.3f}"
    return (f"control {ctrl.n_correct}/{ctrl.n} vs clean {clean.n_correct}/{clean.n}; one-sided exact binomial "
            f"p = {p_txt} at alpha = {t['control_alpha']:g}, floor {CONTROL_ACCURACY_FLOOR:g}")


def _control_crosses_asr(ctx: _Ctx, ctrl: Measurement, acc_clean: float) -> tuple[bool, str]:
    """Spec 12.4 noise sensitivity: the control alone crosses ``finding_asr_threshold`` at this eps, read as the
    control row's ASR when recorded (flipped / clean-correct), else as its accuracy drop against the clean row."""
    asr = ctx.asr(ctrl)
    if asr is not None:
        return asr >= ctx.t["asr"], f"control ASR {asr:.3f} >= {ctx.t['asr']:g}"
    drop = acc_clean - float(ctrl.accuracy)
    return drop > ctx.t["asr"] + 1e-9, f"accuracy drop {drop:.3f} > {ctx.t['asr']:g}"


# --------------------------------------------------------------------------- interpretation

def interpret(measurements: list[Measurement], observations: list[Observation], score: MRIRecord | None,
              settings: ScoringConfig | None = None, *,
              explain_meta: dict[str, Any] | None = None, reference_eps: float | None = None,
              scoring_reason: str | None = None, thresholds: InterpretationThresholds | None = None,
              finding_asr_threshold: float | None = None) -> list[Interpretation]:
    """Spec 14.6 rules I1-I6 plus I7 (MRI not computed). Every statement cites ids that exist in the inputs."""
    if score is not None and not isinstance(score, MRIRecord):
        raise TypeError(f"interpret(): score must be an MRIRecord or None, got {type(score).__name__}")
    if settings is not None and not isinstance(settings, ScoringConfig):
        raise TypeError(f"interpret(): settings must be a ScoringConfig or None, got {type(settings).__name__}")
    ctx = _context(measurements, score, explain_meta, reference_eps, _resolve_thresholds(settings, thresholds),
                   finding_asr_threshold)
    known = ctx.ids | {o.id for o in observations}
    out: list[Interpretation] = []
    t = ctx.t

    def add(code: str, statement: str, basis: list[str]) -> None:
        cited = [b for b in dict.fromkeys(basis) if b in known]
        if not cited:
            return
        out.append(Interpretation(id=f"i.{len(out) + 1}", statement=f"{code}: {statement}", basis=cited))

    if ctx.clean is None:
        return out
    acc_clean = float(ctx.acc_clean or 0.0)
    ctrl = ctx.control_at(ctx.ref_eps)
    ref_txt = _eps_txt(ctx.ref_eps)

    # I1 -- gradient-aligned failure: attack degrades, noise does not (spec 12.4 binomial predicate).
    ctrl_flat = ctrl is not None and _control_flat(ctx.clean, ctrl, t)
    if ctrl is not None and ctrl_flat:
        for a in ctx.attack_ids():
            m = ctx.at(a, ctx.ref_eps)
            if m is not None and float(m.accuracy) < acc_clean - t["attack_drop"]:
                add("I1", f"Random noise at eps={ref_txt} did not reduce accuracy ({_control_verdict(ctx.clean, ctrl, t)}) "
                          f"while {a} did ({m.n_correct}/{m.n}, drop > {t['attack_drop']:g}). The degradation is "
                          "aligned with the loss gradient rather than with general noise sensitivity.",
                    [ctx.clean.id, m.id, ctrl.id])

    # I2 -- benign noise also degrades: significantly below clean AND by at least control_drop.
    if ctrl is not None and not ctrl_flat and float(ctrl.accuracy) < acc_clean - t["control_drop"]:
        add("I2", f"Benign noise at eps={ref_txt} also reduced accuracy ({_control_verdict(ctx.clean, ctrl, t)}; "
                  f"drop > {t['control_drop']:g}). Part of the attack effect is general input sensitivity, not only "
                  "adversarial structure.",
            [ctrl.id, ctx.clean.id])

    # I8 -- noise-sensitive at some grid eps (spec 12.4): the control alone crosses finding_asr_threshold.
    for m_ctrl in sorted(ctx.controls, key=_eps_sort_key):
        crossed, reason = _control_crosses_asr(ctx, m_ctrl, acc_clean)
        if crossed:
            add("I8", f"The model is noise-sensitive at eps={_eps_txt(_eps(m_ctrl))}: the benign control alone "
                      f"reduced accuracy from {ctx.clean.n_correct}/{ctx.clean.n} to {m_ctrl.n_correct}/{m_ctrl.n} "
                      f"({reason}, the finding_asr_threshold). Evasion results at this eps are not attributable to "
                      "adversarial alignment.",
                [m_ctrl.id, ctx.clean.id])

    # I3 -- iterative vs single-step gap at the same eps.
    fgsm_ids = [a for a in ctx.attack_ids() if _attack_is(a, "fgsm")]
    pgd_ids = [a for a in ctx.attack_ids() if _attack_is(a, "pgd")]
    for f_id in fgsm_ids:
        for p_id in pgd_ids:
            for eps, f_row in sorted(ctx.rows(f_id).items()):
                p_row = ctx.at(p_id, eps)
                if p_row is not None and float(p_row.accuracy) < float(f_row.accuracy) - t["iterative_gap"]:
                    add("I3", f"The iterative attack ({p_id}: {p_row.n_correct}/{p_row.n}) degraded the model more than "
                              f"the single-step attack ({f_id}: {f_row.n_correct}/{f_row.n}) at eps={eps:g} "
                              f"(gap > {t['iterative_gap']:g}). Single-step results understate the exposure.",
                        [p_row.id, f_row.id])

    # I4 -- centre-mass shift on flipped observations (heuristic).
    mc, ma, obs_ids = _cmr_drop(observations)
    if mc is not None and ma is not None and ma <= mc - t["cmr_drop"]:
        add("I4", f"On the flipped samples (n = {len(obs_ids)}), attribution moved away from the central region of the "
                  f"image under attack (heuristic centre-mass proxy: mean {mc:.3f} -> {ma:.3f}, drop >= {t['cmr_drop']:g}). "
                  "This is a heuristic, not a segmentation, and not a claim about the training data.",
            obs_ids)

    # I5 / I6 -- explanation shift and confident wrong predictions at the reference budget.
    for a in ctx.attack_ids():
        m = ctx.at(a, ctx.ref_eps)
        if m is None:
            continue
        shift = _metric(ctx, m, "expl_shift")
        if shift is not None and shift >= t["expl_shift"]:
            n_txt = f" over n = {m.expl_shift_n}" if m.expl_shift_mean is not None and m.expl_shift_n is not None else ""
            add("I5", f"Attributions changed substantially between clean and adversarial inputs under {a} at eps={ref_txt} "
                      f"(mean explanation shift {shift:.3f}{n_txt} >= {t['expl_shift']:g}). The model's stated reasons "
                      "are not stable under this perturbation.", [m.id])
        gap = _metric(ctx, m, "conf_gap")
        if gap is not None and gap >= t["conf_gap"]:
            n_txt = f" over n = {m.conf_gap_n}" if m.conf_gap_mean is not None and m.conf_gap_n is not None else ""
            add("I6", f"Wrong predictions under {a} at eps={ref_txt} were made with high confidence (mean confidence gap "
                      f"{gap:.3f}{n_txt} >= {t['conf_gap']:g}). Confidence is not a usable signal of attack at this eps.",
                [m.id])

    # I7 -- MRI absent (no score record, or a partial one).
    if score is None or score.mri is None:
        ref_rows = [m.id for a in ctx.attack_ids() if (m := ctx.at(a, ctx.ref_eps)) is not None]
        why = scoring_reason
        if not why and score is not None and score.missing:
            why = ", ".join(score.missing)
        if not why:
            why = ctx.explain_meta.get("unavailable_reason")
        if not why:
            has_expl = any(_metric(ctx, ctx.at(a, ctx.ref_eps), "expl_shift") is not None for a in ctx.attack_ids())
            why = ("explanation stability (S_expl) has no input: explanations were unavailable or explain_k = 0"
                   if not has_expl and not observations else "one or more of the five subscores is unavailable")
        add("I7", f"MRI not computed: {why}. Weights are never renormalised over the available dimensions, so no "
                  "partial index is shown. The measurements above stand on their own.", [ctx.clean.id, *ref_rows])
    return out


# --------------------------------------------------------------------------- recommendations

def _registered_defense_ids() -> set[str]:
    try:
        from redsim.ml.defenses import list_defenses  # lazy: owned by another module
        ids = {str(d.get("id")) for d in list_defenses() if isinstance(d, dict) and d.get("id")}
        if ids:
            return ids | set(_DEFENSES)
    except Exception as exc:  # noqa: BLE001 -- module may not exist yet; the built-in ids are the fallback
        logger.debug("redsim.ml.defenses unavailable (%s), using built-in defense ids", type(exc).__name__)
    return set(_DEFENSES)


def _refs(defense_ids: Iterable[str], *extra: str, bypass: bool = False) -> list[str]:
    known = _registered_defense_ids()
    refs: list[str] = []
    for d in defense_ids:
        refs.append(f"defense:{d}" if d in known else f"defense:{d} (not registered in redsim.ml.defenses)")
        if d in _DEFENSES:
            cls, paper, phase = _DEFENSES[d]
            refs.append(f"{cls} ({phase})")
            refs.append(paper)
    refs.extend(extra)
    if bypass:
        refs.append("Athalye, Carlini, Wagner 2018, Obfuscated Gradients Give a False Sense of Security")
    return list(dict.fromkeys(refs))


def defense_configs(rec: CandidateRecommendation) -> list[DefenseConfig]:
    """The ``defense:<id>`` references of a candidate as ``DefenseConfig`` rows (params left to the verify request).

    ``adversarial_training`` is returned too when cited. It is a Phase B apply step, so the verify loop must check
    the id against ``redsim.ml.defenses`` before applying it.
    """
    out: list[DefenseConfig] = []
    for ref in rec.references:
        if not ref.startswith("defense:"):
            continue
        did = ref[len("defense:"):].split(" ", 1)[0]
        cls = _DEFENSES[did][0] if did in _DEFENSES else None
        out.append(DefenseConfig(id=did, art_class=cls))
    return out


def _rank_key(rec: CandidateRecommendation, by_id: dict[str, Measurement], ctx: _Ctx) -> tuple[float, float, float, str]:
    """Most exposed cited attack first (spec 15.5 ordering), then largest degradation at eps_ref, then rule id."""
    cited = [by_id[i] for i in rec.triggered_by if i in by_id and by_id[i].family == "evasion"]
    attacks = {m.attack_id for m in cited if m.attack_id}
    exposure = min((ctx.exposure(a) for a in attacks), default=(math.inf, 0.0))
    ref_cited = [m for m in cited if _same(_eps(m), ctx.ref_eps)] or cited
    acc_clean = float(ctx.acc_clean or 0.0)
    drop = max((acc_clean - float(m.accuracy) for m in ref_cited), default=0.0)
    return (exposure[0], exposure[1], -drop, rec.id)


def recommend(measurements: list[Measurement], observations: list[Observation], score: MRIRecord | None,
              settings: ScoringConfig | None = None, *,
              interpretation: list[Interpretation] | None = None, explain_meta: dict[str, Any] | None = None,
              reference_eps: float | None = None, modality: str | None = None, seed: int | None = None,
              thresholds: InterpretationThresholds | None = None,
              finding_asr_threshold: float | None = None) -> list[CandidateRecommendation]:
    """Spec 16.2 rules R1-R7, ranked by the exposure of the cited attack, then degradation at eps_ref, then rule id.

    ``interpretation`` (the rows ``interpret`` produced for the same evidence) lets a candidate also cite the
    interpretation that motivates it. Every ``triggered_by`` id exists among the inputs. The campaign runner's
    positional order ``(measurements, observations, interpretation, score)`` is accepted as well.
    """
    score, settings, interpretation = _positional_contract(score, settings, interpretation)
    if not measurements:
        return []
    ctx = _context(measurements, score, explain_meta, reference_eps, _resolve_thresholds(settings, thresholds),
                   finding_asr_threshold)
    known = ctx.ids | {o.id for o in observations} | {i.id for i in (interpretation or [])}
    t = ctx.t
    recs: list[CandidateRecommendation] = []
    if modality is None:
        if ctx.explain_meta.get("modality"):
            modality = str(ctx.explain_meta["modality"])
        elif any(o.top_features_clean for o in observations):
            modality = "tabular"
        elif any(o.center_mass_ratio_clean is not None for o in observations):
            modality = "image"
    clean = ctx.clean
    acc_clean = float(ctx.acc_clean or 0.0)
    ref_txt = _eps_txt(ctx.ref_eps)
    ctrl = ctx.control_at(ctx.ref_eps)
    n_cc = clean.n_correct if clean is not None else 0
    fgsm_ids = [a for a in ctx.attack_ids() if _attack_is(a, "fgsm")]
    pgd_ids = [a for a in ctx.attack_ids() if _attack_is(a, "pgd")]

    def add(rule: str, title: str, rationale: str, triggered: list[str], references: list[str]) -> None:
        cited = [i for i in dict.fromkeys(triggered) if i in known]
        if not cited:
            return
        recs.append(CandidateRecommendation(
            id=f"r.{rule}", title=title, rationale=f"{rationale} {_DIRECTION_ONLY}", triggered_by=cited,
            validation="not evaluated", measured=None, references=references))

    # R1 / R1b -- single-step success at the smallest eps, split by the noise control.
    if clean is not None:
        for f_id in fgsm_ids:
            m_small = ctx.at(f_id, ctx.eps_small())
            asr_small = ctx.asr(m_small)
            if m_small is None or asr_small is None or asr_small < t["asr"] or ctrl is None:
                continue
            f_ref = ctx.at(f_id, ctx.ref_eps)
            if _control_flat(clean, ctrl, t):
                add("R1", "Adversarial training (PGD-based) and gradient-masking review",
                    f"Single-step {f_id} succeeded at the smallest eps={_eps_txt(ctx.eps_small())} "
                    f"({m_small.n_flipped_from_clean}/{n_cc} flipped, ASR {asr_small:.3f} >= {t['asr']:g}) while random "
                    f"noise at eps={ref_txt} did not reduce accuracy ({_control_verdict(clean, ctrl, t)}), so the "
                    "failure is gradient-aligned. Adversarial training targets this directly. Review the model for "
                    "gradient masking before trusting any defense that only hides gradients.",
                    [m_small.id, ctrl.id, clean.id,
                     *(_interp_ids(interpretation, "I1", [f_ref.id]) if f_ref is not None else [])],
                    _refs(["adversarial_training"], "Known limit: robustness is specific to the training threat model and eps"))
            elif float(ctrl.accuracy) < acc_clean - t["control_drop"]:
                add("R1b", "Noise-robust training and input-quality controls",
                    f"Both {f_id} at eps={_eps_txt(ctx.eps_small())} ({m_small.n_flipped_from_clean}/{n_cc} flipped, "
                    f"ASR {asr_small:.3f}) and benign noise at eps={ref_txt} ({_control_verdict(clean, ctrl, t)}; "
                    f"drop > {t['control_drop']:g}) degraded accuracy, so part of the "
                    "exposure is general input sensitivity. Augmentation with the same noise family and input-quality "
                    "checks are candidates alongside adversarial training.",
                    [m_small.id, ctrl.id, clean.id, *_interp_ids(interpretation, "I2", [ctrl.id])],
                    ["no ART implementation (training-side)",
                     "Known limit: does not address gradient-aligned perturbations on its own"])

    # R2 -- iterative attacks understate exposure.
    r2_rows: list[str] = []
    r2_txt: list[str] = []
    for f_id in fgsm_ids:
        for p_id in pgd_ids:
            for eps, f_row in sorted(ctx.rows(f_id).items()):
                p_row = ctx.at(p_id, eps)
                if p_row is not None and float(p_row.accuracy) < float(f_row.accuracy) - t["iterative_gap"]:
                    r2_rows += [p_row.id, f_row.id]
                    r2_txt.append(f"eps={eps:g}: {p_id} {p_row.n_correct}/{p_row.n} vs {f_id} {f_row.n_correct}/{f_row.n}")
    if r2_rows:
        add("R2", "Evaluate with iterative attacks at multiple eps and iteration counts before relying on results",
            f"PGD degraded the model more than FGSM ({', '.join(r2_txt)}, gap > {t['iterative_gap']:g}), so single-step "
            "results understate exposure. Any future evaluation of this model should include iterative attacks across "
            "the grid.", [*r2_rows, *_interp_ids(interpretation, "I3", r2_rows)],
            ["no ART implementation (evaluation practice)"])

    # R3 -- peripheral / unstable features (heuristic).
    mc, ma, obs_ids = _cmr_drop(observations)
    r3_trig: list[str] = []
    r3_txt: list[str] = []
    r3_rows: list[str] = []
    if mc is not None and ma is not None and ma <= mc - t["cmr_drop"]:
        r3_trig += obs_ids
        r3_txt.append(f"attribution moved away from the central region on the {len(obs_ids)} flipped samples explained "
                      f"(heuristic centre-mass proxy, mean {mc:.3f} -> {ma:.3f}, drop >= {t['cmr_drop']:g})")
    for a in ctx.attack_ids():
        m = ctx.at(a, ctx.ref_eps)
        shift = _metric(ctx, m, "expl_shift")
        if m is not None and shift is not None and shift >= t["expl_shift"]:
            r3_rows.append(m.id)
            r3_txt.append(f"attributions under {a} at eps={ref_txt} shifted by {shift:.3f} on average (>= {t['expl_shift']:g})")
    r3_trig += r3_rows
    if r3_trig:
        defenses = ["feature_squeezing", "spatial_smoothing"] if modality != "tabular" else ["feature_squeezing"]
        add("R3", "Investigate reliance on peripheral or irrelevant features (input preprocessing, feature squeezing, "
                  "spatial smoothing, cropping/augmentation, retraining with masking)",
            "Heuristic: " + ", and ".join(r3_txt) + ". This is consistent with reliance on features a small perturbation "
            "can change. It is a heuristic reading of attribution maps, not a causal finding.",
            [*r3_trig, *_interp_ids(interpretation, "I4", obs_ids), *_interp_ids(interpretation, "I5", r3_rows)],
            _refs(defenses, bypass=True))

    # R3t -- tabular: driving features changed under attack (from the observations' feature rankings).
    frac, n_flip, changed_ids = _top3_changed(observations)
    if frac is None:
        frac = _num(ctx.explain_meta.get("top3_changed_fraction_flipped"))
        n_flip = int(ctx.explain_meta.get("top3_changed_n_flipped") or 0)
    if modality == "tabular" and frac is not None and frac >= t["top3_changed_fraction"]:
        trig = changed_ids or [o.id for o in observations if o.flipped] or [o.id for o in observations]
        k_changed = len(changed_ids) if changed_ids else round(float(frac) * n_flip)
        add("R3t", "Feature range validation and clipping at inference, monotonic constraints where the domain allows",
            f"Heuristic: on {k_changed} of {n_flip} flipped rows the top-3 features driving the prediction changed under "
            f"attack (fraction {float(frac):.2f} >= {t['top3_changed_fraction']:g}). Validating and clipping feature "
            "ranges at inference bounds what an L-inf perturbation can reach.",
            trig, _refs(["feature_squeezing"], "estimator clip_values (ART, Phase A verify)",
                        "Known limit: bounds only what lies outside the valid range"))

    # R4 -- confidently wrong.
    for a in ctx.attack_ids():
        m = ctx.at(a, ctx.ref_eps)
        gap = _metric(ctx, m, "conf_gap")
        if m is not None and gap is not None and gap >= t["conf_gap"]:
            add("R4", "Confidence calibration and an out-of-distribution reject option",
                f"Wrong predictions under {a} at eps={ref_txt} carried a mean confidence gap of {gap:.3f} "
                f"(>= {t['conf_gap']:g}), so the model is confidently wrong. Calibrated confidences and a reject option "
                "make attacks detectable at the decision point.",
                [m.id, *_interp_ids(interpretation, "I6", [m.id])],
                [("no ART implementation (calibration is training-side. ART postprocessors obfuscate "
                  "confidences and are not calibration)")])
            break

    # R5 -- black-box attack succeeded.
    bb_rows = [m for a in ctx.attack_ids() if (_attack_is(a, "hopskipjump") or _attack_is(a, "boundary"))
               for m in ctx.rows(a).values() if (ctx.asr(m) or 0.0) >= t["asr"]]
    if bb_rows:
        m = bb_rows[0]
        q = _num(m.queries_mean)
        add("R5", "Rate limiting and query-pattern monitoring at the inference API",
            f"The decision-based attack {m.attack_id} succeeded on {m.n_flipped_from_clean}/{n_cc} "
            f"(ASR {ctx.asr(m):.3f} >= {t['asr']:g})" + (f" within {q:g} queries on average" if q is not None else "") +
            ". Limiting and monitoring query volume per client raises the attacker's cost.",
            [r.id for r in bb_rows], ["no ART implementation (operational control)",
                                      "Known limit: does not stop transfer attacks"])

    # R6 -- any degradation: cheap preprocessing experiment.
    r6_rows = [m for m in ctx.evasion if clean is not None and float(m.accuracy) < acc_clean - t["any_drop"]]
    if r6_rows and clean is not None:
        worst = min(r6_rows, key=lambda m: float(m.accuracy))
        defenses = (["jpeg_compression", "spatial_smoothing", "feature_squeezing"] if modality != "tabular"
                    else ["feature_squeezing"])
        add("R6", "Input preprocessing defenses as a cheap first experiment (JPEG compression, spatial smoothing, "
                  "feature squeezing)",
            f"Accuracy fell from {clean.n_correct}/{clean.n} ({acc_clean:.3f}) to {worst.n_correct}/{worst.n} "
            f"({float(worst.accuracy):.3f}) under {worst.attack_id} at eps={_eps_txt(_eps(worst))} (drop > "
            f"{t['any_drop']:g}, {len(r6_rows)} evasion rows affected). Preprocessing defenses are cheap to test with "
            "the verify loop. Caveat: defenses that work by masking gradients are often bypassed by adaptive attacks "
            "(Athalye, Carlini, Wagner 2018), so a measured delta MRI here is an upper bound on their benefit.",
            [m.id for m in r6_rows] + [clean.id], _refs(defenses, bypass=True))

    # R7 -- always.
    anchor = clean.id if clean is not None else measurements[0].id
    n_txt = f"{clean.n} samples" if clean is not None else f"{measurements[0].n} samples"
    seed_txt = f" with seed {seed}" if seed is not None else ""
    add("R7", "Rerun with a larger slice and a different seed before drawing conclusions",
        f"This run evaluated {n_txt}{seed_txt}" + (f" over the eps grid {ctx.eps_grid}" if ctx.eps_grid else "") +
        ". Per-class counts in particular have wide uncertainty. A rerun with more samples, more seeds and more eps "
        "points is the cheapest check on every number above.",
        [anchor], ["no ART implementation (evaluation practice)"])

    by_id = {m.id: m for m in measurements}
    recs.sort(key=lambda r: _rank_key(r, by_id, ctx))
    return recs
