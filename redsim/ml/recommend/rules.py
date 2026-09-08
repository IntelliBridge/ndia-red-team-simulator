"""Deterministic rule layer (spec sections 14.6 and 16.2).

``interpret`` turns measurement / observation rows into ``Interpretation``
sentences (``kind="inferred"``) whose ``basis`` cites the ids they rest on;
``recommend`` turns the same evidence into ``CandidateRecommendation`` rows
(``status="candidate"``, ``validation="not evaluated"``) that cite the ids
that triggered them and map to a defense id from ``redsim.ml.defenses`` (the
string ids are the fallback when that module is not importable yet).

No rule asserts a cause in the training data or architecture; no rule states a
numeric gain -- direction only. Thresholds are printed next to each statement.
Rule ids are stable (``r.R3`` means the same rule in every run).
"""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from redsim.ml.schema import CandidateRecommendation, Interpretation, Measurement, Observation, Scoring

logger = logging.getLogger(__name__)

THRESHOLDS: dict[str, float] = {
    "attack_drop": 0.20,      # I1: attack accuracy drop vs clean
    "control_flat": 0.05,     # I1 / R1: |control - clean| within this = noise did not reduce accuracy
    "control_drop": 0.10,     # I2 / R1b: control reduced accuracy by at least this
    "iterative_gap": 0.10,    # I3 / R2: pgd worse than fgsm by at least this at the same eps
    "cmr_drop": 0.15,         # I4 / R3: centre-mass drop on flipped samples (heuristic)
    "expl_shift": 0.5,        # I5 / R3
    "conf_gap": 0.5,          # I6 / R4
    "asr": 0.2,               # R1 / R1b / R5: finding_asr_threshold
    "any_drop": 0.05,         # R6
    "top3_changed_fraction": 0.5,   # R3t
}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}

# defense id -> (ART class path, motivating reference, phase / runnable note)
_DEFENSES: dict[str, tuple[str, str, str]] = {
    "adversarial_training": ("art.defences.trainer.AdversarialTrainerMadryPGD",
                             "Madry et al. 2018, Towards Deep Learning Models Resistant to Adversarial Attacks",
                             "Phase B apply step; not runnable by the Phase A verify loop"),
    "feature_squeezing": ("art.defences.preprocessor.FeatureSqueezing",
                          "Xu, Evans, Qi 2018, Feature Squeezing", "Phase A verify loop"),
    "spatial_smoothing": ("art.defences.preprocessor.SpatialSmoothing",
                          "Xu, Evans, Qi 2018, Feature Squeezing", "Phase A verify loop"),
    "jpeg_compression": ("art.defences.preprocessor.JpegCompression",
                         "Dziugaite, Ghahramani, Roy 2016, A study of the effect of JPG compression on adversarial images",
                         "Phase A verify loop (image)"),
}
_BYPASS = ("Known bypass: defenses that work by masking gradients are often bypassed by adaptive attacks "
           "(Athalye, Carlini, Wagner 2018); a measured delta MRI is an upper bound on their benefit.")
_DIRECTION_ONLY = ("Intended direction only: expected gain is not measured until a verify run reports a "
                   "measured delta MRI on this model at these settings.")


# --------------------------------------------------------------------------- evidence context

def _eps(m: Measurement) -> float | None:
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


@dataclass
class _Ctx:
    clean: Measurement | None
    evasion: list[Measurement]
    controls: list[Measurement]
    ref_eps: float | None
    eps_grid: list[float]
    scoring: Scoring | None
    explain_meta: dict[str, Any]
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
        if m is None or m.n_flipped_from_clean is None or self.clean is None or self.clean.n_correct <= 0:
            return None
        return float(m.n_flipped_from_clean) / float(self.clean.n_correct)

    def eps_small(self) -> float | None:
        return min(self.eps_grid) if self.eps_grid else None


def _context(measurements: list[Measurement], scoring: Scoring | None, explain_meta: dict[str, Any] | None,
             reference_eps: float | None) -> _Ctx:
    clean = next((m for m in measurements if m.family == "clean"), None)
    evasion = [m for m in measurements if m.family == "evasion"]
    controls = [m for m in measurements if m.family == "control"]
    grid = sorted({e for m in evasion if (e := _eps(m)) is not None})
    ref = reference_eps
    if ref is None and scoring is not None:
        ref = float(scoring.reference_eps)
    if ref is None:
        ctrl_eps = sorted({e for m in controls if (e := _eps(m)) is not None})
        if len(ctrl_eps) == 1:
            ref = ctrl_eps[0]
        elif grid:
            ref = grid[len(grid) // 2]
    return _Ctx(clean=clean, evasion=evasion, controls=controls, ref_eps=ref, eps_grid=grid, scoring=scoring,
                explain_meta=dict(explain_meta or {}), ids={m.id for m in measurements})


def _from_inputs(inputs: dict[str, Any], attack_id: str, eps: float | None, key: str) -> float | None:
    """Tolerant lookup of ``per_attack[attack][eps][key]`` (eps keys may be floats or strings)."""
    per_attack = inputs.get("per_attack", inputs)
    if not isinstance(per_attack, dict):
        return None
    rows = per_attack.get(attack_id)
    if not isinstance(rows, dict):
        return None
    if key in rows and isinstance(rows[key], (int, float)) and not isinstance(rows[key], bool):
        return float(rows[key])  # flat per-attack form
    for k, v in rows.items():
        try:
            k_eps = float(k)
        except (TypeError, ValueError):
            continue
        if _same(k_eps, eps) and isinstance(v, dict):
            val = v.get(key)
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                return float(val)
    return None


def _from_notes(m: Measurement | None, key: str) -> float | None:
    """``<key> = <number>`` (spaces optional) in a measurement's notes, e.g. campaign's
    ``"conf_gap_mean = 0.6200 over n=100 (...)"`` or ``"expl_shift_mean = 0.5500 over 4 explained samples"``."""
    if m is None:
        return None
    pattern = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(key) + r"\s*=\s*(-?\d+(?:\.\d+)?)")
    for note in m.notes:
        found = pattern.search(note)
        if found:
            try:
                return float(found.group(1))
            except ValueError:
                return None
    return None


def _metric(ctx: _Ctx, attack_id: str, eps: float | None, key: str) -> float | None:
    """``expl_shift`` / ``conf_gap`` at ``(attack, eps)`` from scoring inputs, then explain meta, then row notes."""
    if ctx.scoring is not None:
        v = _from_inputs(ctx.scoring.inputs, attack_id, eps, key)
        if v is not None:
            return v
    if key == "expl_shift":
        meta = ctx.explain_meta
        per_attack = meta.get("per_attack")
        if isinstance(per_attack, dict) and isinstance(per_attack.get(attack_id), dict):
            v = per_attack[attack_id].get("expl_shift_mean")
            if isinstance(v, (int, float)):
                return float(v)
        v = meta.get("expl_shift_mean")
        single_attack = len(ctx.attack_ids()) <= 1 or meta.get("attack_id") == attack_id
        if isinstance(v, (int, float)) and single_attack and _same(eps, ctx.ref_eps):
            return float(v)
    return _from_notes(ctx.at(attack_id, eps), key + "_mean") or _from_notes(ctx.at(attack_id, eps), key)


def _cmr_drop(observations: list[Observation]) -> tuple[float | None, float | None, list[str]]:
    pairs = [(o.id, float(o.center_mass_ratio_clean), float(o.center_mass_ratio_adv)) for o in observations
             if o.flipped and o.center_mass_ratio_clean is not None and o.center_mass_ratio_adv is not None]
    if not pairs:
        return None, None, []
    mc = sum(c for _, c, _ in pairs) / len(pairs)
    ma = sum(a for _, _, a in pairs) / len(pairs)
    return mc, ma, [oid for oid, _, _ in pairs]


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.3f}"


def _eps_txt(e: float | None) -> str:
    return "reference" if e is None else f"{e:g}"


# --------------------------------------------------------------------------- interpretation

def interpret(measurements: list[Measurement], observations: list[Observation], scoring: Scoring | None, *,
              explain_meta: dict[str, Any] | None = None, reference_eps: float | None = None,
              scoring_reason: str | None = None) -> list[Interpretation]:
    """Spec 14.6 rules I1-I6 plus I7 (MRI not computed). Every statement cites existing ids."""
    ctx = _context(measurements, scoring, explain_meta, reference_eps)
    out: list[Interpretation] = []
    t = THRESHOLDS

    def add(code: str, statement: str, basis: list[str]) -> None:
        basis = [b for b in dict.fromkeys(basis) if b]
        if not basis:
            return
        out.append(Interpretation(id=f"i.{len(out) + 1}", statement=f"{code}: {statement}", basis=basis))

    if ctx.clean is None:
        return out
    acc_clean = float(ctx.acc_clean or 0.0)
    ctrl = ctx.control_at(ctx.ref_eps)
    ref_txt = _eps_txt(ctx.ref_eps)

    # I1 -- gradient-aligned failure: attack degrades, noise does not.
    if ctrl is not None and abs(float(ctrl.accuracy) - acc_clean) <= t["control_flat"]:
        for a in ctx.attack_ids():
            m = ctx.at(a, ctx.ref_eps)
            if m is not None and float(m.accuracy) < acc_clean - t["attack_drop"]:
                add("I1", f"Random noise at eps={ref_txt} did not reduce accuracy ({ctrl.n_correct}/{ctrl.n} vs clean "
                          f"{ctx.clean.n_correct}/{ctx.clean.n}, |delta| <= {t['control_flat']:g}) while {a} did "
                          f"({m.n_correct}/{m.n}, drop > {t['attack_drop']:g}); the degradation is aligned with the loss "
                          "gradient rather than with general noise sensitivity.",
                    [ctx.clean.id, m.id, ctrl.id])

    # I2 -- benign noise also degrades.
    if ctrl is not None and float(ctrl.accuracy) < acc_clean - t["control_drop"]:
        add("I2", f"Benign noise at eps={ref_txt} also reduced accuracy ({ctrl.n_correct}/{ctrl.n} vs clean "
                  f"{ctx.clean.n_correct}/{ctx.clean.n}, drop > {t['control_drop']:g}); part of the attack effect is "
                  "general input sensitivity, not only adversarial structure.",
            [ctrl.id, ctx.clean.id])

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
                              f"(gap > {t['iterative_gap']:g}); single-step results understate the exposure.",
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
        shift = _metric(ctx, a, ctx.ref_eps, "expl_shift")
        if shift is not None and shift >= t["expl_shift"]:
            add("I5", f"Attributions changed substantially between clean and adversarial inputs under {a} at eps={ref_txt} "
                      f"(mean explanation shift {shift:.3f} >= {t['expl_shift']:g}); the model's stated reasons are not "
                      "stable under this perturbation.", [m.id])
        gap = _metric(ctx, a, ctx.ref_eps, "conf_gap")
        if gap is not None and gap >= t["conf_gap"]:
            add("I6", f"Wrong predictions under {a} at eps={ref_txt} were made with high confidence (mean confidence gap "
                      f"{gap:.3f} >= {t['conf_gap']:g}); confidence is not a usable signal of attack at this eps.", [m.id])

    # I7 -- MRI absent.
    if scoring is None:
        ref_rows = [m.id for a in ctx.attack_ids() if (m := ctx.at(a, ctx.ref_eps)) is not None]
        has_expl = any(_metric(ctx, a, ctx.ref_eps, "expl_shift") is not None for a in ctx.attack_ids())
        why = scoring_reason or ctx.explain_meta.get("unavailable_reason")
        if not why:
            why = ("explanation stability (S_expl) has no input: explanations were unavailable or explain_k = 0"
                   if not has_expl and not observations else "one or more of the five subscores is unavailable")
        add("I7", f"MRI not computed: {why}. Weights are never renormalised over the available dimensions, so no "
                  "partial index is shown; the measurements above stand on their own.", [ctx.clean.id, *ref_rows])
    return out


# --------------------------------------------------------------------------- recommendations

def _defense_ids() -> set[str]:
    try:
        from redsim.ml.defenses import list_defenses  # lazy: owned by another module
        ids = {str(d.get("id")) for d in list_defenses() if isinstance(d, dict) and d.get("id")}
        if ids:
            return ids | set(_DEFENSES)
    except Exception as exc:  # noqa: BLE001 -- module may not exist yet; string ids are the fallback
        logger.debug("redsim.ml.defenses unavailable (%s); using built-in defense ids", type(exc).__name__)
    return set(_DEFENSES)


def _refs(defense_ids: Iterable[str], *extra: str, bypass: bool = False) -> list[str]:
    known = _defense_ids()
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


def _rank_key(rec: CandidateRecommendation, by_id: dict[str, Measurement], acc_clean: float,
              ref_eps: float | None) -> tuple[int, float, str]:
    cited = [by_id[i] for i in rec.triggered_by if i in by_id and by_id[i].family == "evasion"]
    sev = min((_SEVERITY_RANK.get(m.severity, 4) for m in cited), default=4)
    ref_cited = [m for m in cited if _same(_eps(m), ref_eps)] or cited
    drop = max((acc_clean - float(m.accuracy) for m in ref_cited), default=0.0)
    return (sev, -drop, rec.id)


def recommend(measurements: list[Measurement], observations: list[Observation],
              interpretation: list[Interpretation], scoring: Scoring | None, *,
              explain_meta: dict[str, Any] | None = None, reference_eps: float | None = None,
              modality: str | None = None, seed: int | None = None) -> list[CandidateRecommendation]:
    """Spec 16.2 rules R1-R7, ranked by triggering severity, then degradation at eps_ref, then rule id."""
    if not measurements:
        return []
    ctx = _context(measurements, scoring, explain_meta, reference_eps)
    t = THRESHOLDS
    recs: list[CandidateRecommendation] = []
    if modality is None:
        if scoring is not None:
            modality = scoring.modality
        elif ctx.explain_meta.get("modality"):
            modality = str(ctx.explain_meta["modality"])
        elif any(o.center_mass_ratio_clean is not None for o in observations):
            modality = "image"
    clean = ctx.clean
    acc_clean = float(ctx.acc_clean or 0.0)
    ref_txt = _eps_txt(ctx.ref_eps)
    ctrl = ctx.control_at(ctx.ref_eps)
    n_cc = clean.n_correct if clean is not None else 0

    def add(rule: str, title: str, rationale: str, triggered: list[str], references: list[str]) -> None:
        triggered = [i for i in dict.fromkeys(triggered) if i]
        if not triggered:
            return
        recs.append(CandidateRecommendation(
            id=f"r.{rule}", title=title, rationale=f"{rationale} {_DIRECTION_ONLY}",
            triggered_by=triggered, references=references))

    # R1 / R1b -- single-step success at the smallest eps, split by the noise control.
    if clean is not None:
        for f_id in [a for a in ctx.attack_ids() if _attack_is(a, "fgsm")]:
            m_small = ctx.at(f_id, ctx.eps_small())
            asr_small = ctx.asr(m_small)
            if m_small is None or asr_small is None or asr_small < t["asr"] or ctrl is None:
                continue
            if abs(float(ctrl.accuracy) - acc_clean) <= t["control_flat"]:
                add("R1", "Adversarial training (PGD-based) and gradient-masking review",
                    f"Single-step {f_id} succeeded at the smallest eps={_eps_txt(ctx.eps_small())} "
                    f"({m_small.n_flipped_from_clean}/{n_cc} flipped, ASR {asr_small:.3f} >= {t['asr']:g}) while random "
                    f"noise at eps={ref_txt} did not reduce accuracy ({ctrl.n_correct}/{ctrl.n} vs clean "
                    f"{clean.n_correct}/{clean.n}, |delta| <= {t['control_flat']:g}), so the failure is gradient-aligned; "
                    "adversarial training targets this directly. Review the model for gradient masking before trusting "
                    "any defense that only hides gradients.",
                    [m_small.id, ctrl.id, clean.id],
                    _refs(["adversarial_training"], "Known limit: robustness is specific to the training threat model and eps"))
            elif float(ctrl.accuracy) < acc_clean - t["control_drop"]:
                add("R1b", "Noise-robust training and input-quality controls",
                    f"Both {f_id} at eps={_eps_txt(ctx.eps_small())} ({m_small.n_flipped_from_clean}/{n_cc} flipped, "
                    f"ASR {asr_small:.3f}) and benign noise at eps={ref_txt} ({ctrl.n_correct}/{ctrl.n} vs clean "
                    f"{clean.n_correct}/{clean.n}, drop > {t['control_drop']:g}) degraded accuracy; part of the exposure "
                    "is general input sensitivity. Augmentation with the same noise family and input-quality checks are "
                    "candidates alongside adversarial training.",
                    [m_small.id, ctrl.id, clean.id],
                    ["no ART implementation (training-side)",
                     "Known limit: does not address gradient-aligned perturbations on its own"])

    # R2 -- iterative attacks understate exposure.
    r2_rows: list[str] = []
    r2_txt: list[str] = []
    for f_id in [a for a in ctx.attack_ids() if _attack_is(a, "fgsm")]:
        for p_id in [a for a in ctx.attack_ids() if _attack_is(a, "pgd")]:
            for eps, f_row in sorted(ctx.rows(f_id).items()):
                p_row = ctx.at(p_id, eps)
                if p_row is not None and float(p_row.accuracy) < float(f_row.accuracy) - t["iterative_gap"]:
                    r2_rows += [p_row.id, f_row.id]
                    r2_txt.append(f"eps={eps:g}: {p_id} {p_row.n_correct}/{p_row.n} vs {f_id} {f_row.n_correct}/{f_row.n}")
    if r2_rows:
        add("R2", "Evaluate with iterative attacks at multiple eps and iteration counts before relying on results",
            f"PGD degraded the model more than FGSM ({'; '.join(r2_txt)}; gap > {t['iterative_gap']:g}); single-step "
            "results understate exposure. Any future evaluation of this model should include iterative attacks across "
            "the grid.", r2_rows, ["no ART implementation (evaluation practice)"])

    # R3 -- peripheral / unstable features (heuristic).
    mc, ma, obs_ids = _cmr_drop(observations)
    r3_trig: list[str] = []
    r3_txt: list[str] = []
    if mc is not None and ma is not None and ma <= mc - t["cmr_drop"]:
        r3_trig += obs_ids
        r3_txt.append(f"attribution moved away from the central region on the {len(obs_ids)} flipped samples explained "
                      f"(heuristic centre-mass proxy, mean {mc:.3f} -> {ma:.3f}, drop >= {t['cmr_drop']:g})")
    for a in ctx.attack_ids():
        m = ctx.at(a, ctx.ref_eps)
        shift = _metric(ctx, a, ctx.ref_eps, "expl_shift") if m is not None else None
        if m is not None and shift is not None and shift >= t["expl_shift"]:
            r3_trig.append(m.id)
            r3_txt.append(f"attributions under {a} at eps={ref_txt} shifted by {shift:.3f} on average (>= {t['expl_shift']:g})")
    if r3_trig:
        defenses = ["feature_squeezing", "spatial_smoothing"] if modality != "tabular" else ["feature_squeezing"]
        add("R3", "Investigate reliance on peripheral or irrelevant features (input preprocessing, feature squeezing, "
                  "spatial smoothing, cropping/augmentation, retraining with masking)",
            "Heuristic: " + "; ".join(r3_txt) + ". This is consistent with reliance on features a small perturbation can "
            "change; it is a heuristic reading of attribution maps, not a causal finding.",
            r3_trig, _refs(defenses, bypass=True))

    # R3t -- tabular: driving features changed under attack.
    frac = ctx.explain_meta.get("top3_changed_fraction_flipped")
    n_flip = ctx.explain_meta.get("top3_changed_n_flipped", 0)
    if modality == "tabular" and isinstance(frac, (int, float)) and frac >= t["top3_changed_fraction"]:
        flipped_obs = [o.id for o in observations if o.flipped] or [o.id for o in observations]
        k_changed = round(float(frac) * int(n_flip)) if n_flip else 0
        add("R3t", "Feature range validation and clipping at inference; monotonic constraints where the domain allows",
            f"Heuristic: on {k_changed} of {n_flip} flipped rows the top-3 features driving the prediction changed under "
            f"attack (fraction {float(frac):.2f} >= {t['top3_changed_fraction']:g}). Validating and clipping feature "
            "ranges at inference bounds what an L-inf perturbation can reach.",
            flipped_obs, _refs(["feature_squeezing"], "estimator clip_values (ART, Phase A verify)",
                               "Known limit: bounds only what lies outside the valid range"))

    # R4 -- confidently wrong.
    for a in ctx.attack_ids():
        m = ctx.at(a, ctx.ref_eps)
        gap = _metric(ctx, a, ctx.ref_eps, "conf_gap") if m is not None else None
        if m is not None and gap is not None and gap >= t["conf_gap"]:
            add("R4", "Confidence calibration and an out-of-distribution reject option",
                f"Wrong predictions under {a} at eps={ref_txt} carried a mean confidence gap of {gap:.3f} "
                f"(>= {t['conf_gap']:g}); the model is confidently wrong. Calibrated confidences and a reject option "
                "make attacks detectable at the decision point.",
                [m.id], [("no ART implementation (calibration is training-side; ART postprocessors obfuscate "
                          "confidences and are not calibration)")])
            break

    # R5 -- black-box attack succeeded.
    bb_rows = [m for a in ctx.attack_ids() if (_attack_is(a, "hopskipjump") or _attack_is(a, "boundary"))
               for m in ctx.rows(a).values() if (ctx.asr(m) or 0.0) >= t["asr"]]
    if bb_rows:
        m = bb_rows[0]
        q = _from_notes(m, "queries_mean")
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
            f"{t['any_drop']:g}; {len(r6_rows)} evasion rows affected). Preprocessing defenses are cheap to test with "
            "the verify loop. Caveat: defenses that work by masking gradients are often bypassed by adaptive attacks "
            "(Athalye, Carlini, Wagner 2018); a measured delta MRI here is an upper bound on their benefit.",
            [m.id for m in r6_rows] + [clean.id], _refs(defenses, bypass=True))

    # R7 -- always.
    anchor = clean.id if clean is not None else measurements[0].id
    n_txt = f"{clean.n} samples" if clean is not None else f"{measurements[0].n} samples"
    seed_txt = f" with seed {seed}" if seed is not None else ""
    add("R7", "Rerun with a larger slice and a different seed before drawing conclusions",
        f"This run evaluated {n_txt}{seed_txt}" + (f" over the eps grid {ctx.eps_grid}" if ctx.eps_grid else "") +
        ". Per-class counts in particular have wide uncertainty; a rerun with more samples, more seeds and more eps "
        "points is the cheapest check on every number above.",
        [anchor], ["no ART implementation (evaluation practice)"])

    by_id = {m.id: m for m in measurements}
    recs.sort(key=lambda r: _rank_key(r, by_id, acc_clean, ctx.ref_eps))
    return recs
