"""Deterministic SHAP text summary (spec section 13.7).

The only explanation-derived content the LLM writer may see: plain-text
measurements with denominators, the score record (or the reason the MRI was
not computed), the explanation aggregates with their ``n``, and the top
attribution observations by feature identifier or class label. No image, no
array, no URL string. The text is scrubbed with ``guardrails.filter_output``.

The aggregates are read from the frozen evidence fields: the reference-row
``Measurement`` fields (``expl_shift_mean`` and its denominators, the noise
floor) and the per-sample ``Observation`` fields (``expl_shift``,
``top_features_*``). ``explain_meta`` only adds explainer provenance and the
modality-specific extras (centre-mass means, top-5 ranking changes).
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Any

from redsim.llm.guardrails import filter_output
from redsim.ml.schema import GRADE_STATEMENT, Measurement, MRIRecord, Observation

FIXED_SENTENCE = "SHAP attributions describe the model's sensitivity, not the cause of a failure."
MAX_OBSERVATIONS_LISTED = 8
NORM_LABELS = {"linf": "L-inf", "l2": "L2"}


def _fmt(v: float | None, nd: int = 3) -> str:
    return "n/a" if v is None else f"{v:.{nd}f}"


def _eps(m: Measurement) -> float | None:
    e = m.params.get("eps")
    return float(e) if isinstance(e, (int, float)) and not isinstance(e, bool) else None


def _asr_text(m: Measurement, clean: Measurement | None) -> str | None:
    if m.n_flipped_from_clean is None:
        return None
    denom = m.n_clean_correct if m.n_clean_correct is not None else (clean.n_correct if clean is not None else None)
    if denom is None:
        return f"flipped_from_clean={m.n_flipped_from_clean} (ASR not computed: denominator unknown)"
    if denom <= 0:
        return f"flipped_from_clean={m.n_flipped_from_clean}/0 (ASR not computed: denominator 0)"
    asr = m.attack_success_rate if m.attack_success_rate is not None else m.n_flipped_from_clean / denom
    return f"flipped_from_clean={m.n_flipped_from_clean}/{denom} (ASR {_fmt(asr)})"


def _measurement_lines(measurements: list[Measurement]) -> list[str]:
    clean = next((m for m in measurements if m.family == "clean"), None)
    lines = ["Measurements (counts and rates, every rate shown with its denominator):"]
    if clean is not None:
        lines.append(f"slice: n = {clean.n}, clean accuracy {clean.n_correct}/{clean.n} ({_fmt(clean.accuracy)})")
    for m in measurements:
        parts = [f"- {m.id}: family={m.family}"]
        if m.attack_id:
            parts.append(f"attack={m.attack_id}")
        eps = _eps(m)
        if eps is not None:
            parts.append(f"eps={eps:g}")
        parts.append(f"accuracy={m.n_correct}/{m.n} ({_fmt(m.accuracy)})")
        asr = _asr_text(m, clean)
        if asr:
            parts.append(asr)
        if m.linf_norm_mean is not None:
            parts.append(f"linf_mean={_fmt(m.linf_norm_mean, 4)}")
        if m.l2_norm_mean is not None:
            parts.append(f"l2_mean={_fmt(m.l2_norm_mean, 4)}")
        if m.pert_first_success_mean is not None:
            parts.append(f"pert_first_success_mean={_fmt(m.pert_first_success_mean, 4)} over n={m.pert_first_success_n}")
        if m.conf_gap_mean is not None:
            parts.append(f"conf_gap_mean={_fmt(m.conf_gap_mean)} over n={m.conf_gap_n}")
        if m.expl_shift_mean is not None:
            excluded = f" ({m.expl_shift_n_excluded} excluded)" if m.expl_shift_n_excluded else ""
            parts.append(f"expl_shift_mean={_fmt(m.expl_shift_mean)} over n={m.expl_shift_n}{excluded}")
        if m.expl_shift_noise_floor is not None:
            parts.append(f"expl_shift_noise_floor={_fmt(m.expl_shift_noise_floor)} over n={m.expl_shift_noise_floor_n}")
        if m.queries_mean is not None:
            parts.append(f"queries_mean={m.queries_mean:g}")
        if m.notes:
            parts.append("notes: " + " | ".join(m.notes))
        lines.append(" ".join(parts))
    return lines


def _score_lines(score: MRIRecord | None, reason: str | None) -> list[str]:
    never = "Weights are never renormalised over the available dimensions."
    if score is None:
        why = reason or "one or more of the five subscores is unavailable"
        return [f"Scoring: MRI not computed: {why}. {never}"]
    subs = score.subscores.model_dump()
    available = ", ".join(f"{k}={v:.1f}" for k, v in subs.items() if v is not None) or "none"
    weights = ", ".join(f"{k}={v:g}" for k, v in score.weights.as_dict().items())
    header = (f"Scoring (one campaign: attacks={', '.join(score.attack_ids)}, norm={score.norm}, "
              f"eps_grid={score.eps_grid}, reference_eps={score.reference_eps:g}, version={score.scoring_version}):")
    if score.mri is None:
        why = ", ".join(score.missing) or reason or "one or more of the five subscores is unavailable"
        return [header, f"MRI not computed: {why}. Available subscores: {available}. Weights: {weights}. {never}"]
    lines = [header, f"MRI = {score.mri} (grade {score.grade}). Subscores: {available}. Weights: {weights}."]
    if score.reading:
        lines.append(f"Reading: {score.reading}")
    if score.delta is not None:
        d = score.delta
        lines.append(f"Measured delta MRI vs baseline run {d.baseline_run_id}: {d.delta:+d} "
                     f"({d.mri_before} -> {d.mri_after}).")
    lines.append(GRADE_STATEMENT)
    return lines


def _mean(vals: Iterable[float | None]) -> float | None:
    xs = [float(v) for v in vals if v is not None]
    return sum(xs) / len(xs) if xs else None


def _observation_lines(observations: list[Observation]) -> list[str]:
    if not observations:
        return ["Observations: none (explanations unavailable or explain_k = 0)."]
    flipped = [o for o in observations if o.flipped]
    lines = [(f"Observations: {len(observations)} explained samples ({len(flipped)} flipped, "
              f"{len(observations) - len(flipped)} not flipped).")]
    cm_flipped = [o for o in flipped if o.center_mass_ratio_clean is not None and o.center_mass_ratio_adv is not None]
    if cm_flipped:
        lines.append(f"Centre-mass heuristic on flipped samples (n = {len(cm_flipped)}): mean clean "
                     f"{_fmt(_mean(o.center_mass_ratio_clean for o in cm_flipped))} -> adversarial "
                     f"{_fmt(_mean(o.center_mass_ratio_adv for o in cm_flipped))} "
                     "(heuristic proxy for attention on the subject, not a segmentation).")
    ranked = sorted(observations, key=lambda o: (not o.flipped, o.id))[:MAX_OBSERVATIONS_LISTED]
    lines.append("Top attribution observations (labels and feature identifiers only):")
    for o in ranked:
        parts = [(f"- {o.id}: true={o.true_label} clean={o.pred_clean} ({o.confidence_clean:.2f}) "
                  f"adv={o.pred_adv} ({o.confidence_adv:.2f}) flipped={'yes' if o.flipped else 'no'}")]
        if o.center_mass_ratio_clean is not None or o.center_mass_ratio_adv is not None:
            parts.append(f"center_mass clean={_fmt(o.center_mass_ratio_clean)} adv={_fmt(o.center_mass_ratio_adv)} "
                         "[heuristic]")
        if o.expl_shift is not None:
            parts.append(f"expl_shift={o.expl_shift:.3f}")
        if o.top_features_clean:
            parts.append("top features clean: " + ", ".join(str(f) for f in o.top_features_clean[:5]))
        if o.top_features_adv:
            parts.append("adversarial: " + ", ".join(str(f) for f in o.top_features_adv[:5]))
        lines.append(" | ".join(parts))
    return lines


def _explain_lines(measurements: list[Measurement], explain_meta: dict[str, Any] | None,
                   reference_eps: float | None, norm: str) -> list[str]:
    meta = explain_meta if isinstance(explain_meta, dict) else {}
    ref_rows = [m for m in measurements if m.family == "evasion" and m.expl_shift_mean is not None]
    if not ref_rows and not meta:
        return ["Explanation aggregates: unavailable (explain stage absent or unsupported). S_expl has no input."]
    lines = ["Explanation aggregates (derived values with denominators):"]
    for m in ref_rows:
        eps = _eps(m)
        eps_txt = f"{eps:g}" if eps is not None else (f"{reference_eps:g}" if reference_eps is not None else "reference")
        floor_txt = (f"{_fmt(m.expl_shift_noise_floor)} over n = {m.expl_shift_noise_floor_n}"
                     if m.expl_shift_noise_floor is not None else "not computed (no control explained)")
        excluded = f" ({m.expl_shift_n_excluded} pairs excluded as undefined)" if m.expl_shift_n_excluded else ""
        lines.append(f"For {m.attack_id} at eps = {eps_txt} ({norm}), the mean expl_shift between clean and "
                     f"adversarial attributions was {_fmt(m.expl_shift_mean)} over n = {m.expl_shift_n}{excluded}. "
                     f"The benign-noise control at the same eps gave {floor_txt}.")
    if not ref_rows and isinstance(meta.get("expl_shift_mean"), (int, float)):
        # Explainer meta only (no reference row carries the aggregate): still shown with its denominators.
        floor = meta.get("expl_shift_noise_floor")
        floor_txt = (f"{_fmt(floor)} over n = {meta.get('expl_shift_noise_floor_n')}" if floor is not None
                     else "not computed (no control explained)")
        eps_txt = f"{reference_eps:g}" if reference_eps is not None else str(meta.get("eps", "reference"))
        lines.append(f"For {meta.get('flat_from_attack') or 'the attack set'} at eps = {eps_txt} ({norm}), the mean "
                     f"expl_shift was {_fmt(meta['expl_shift_mean'])} over n = {meta.get('expl_shift_n', 0)}. "
                     f"The benign-noise control at the same eps gave {floor_txt}.")
    if meta.get("modality") == "tabular":
        t5c = ", ".join(str(f) for f in meta.get("top5_clean", [])) or "n/a"
        t5a = ", ".join(str(f) for f in meta.get("top5_adv", [])) or "n/a"
        lines.append(f"The top features by mean |SHAP| were {t5c} on clean rows and {t5a} on adversarial rows "
                     f"(n = {meta.get('n_explained', 'n/a')}). {meta.get('n_rank_changes', 'n/a')} of the top 5 "
                     "changed rank.")
        frac = meta.get("top3_changed_fraction_flipped")
        if isinstance(frac, (int, float)) and not isinstance(frac, bool) and not math.isnan(float(frac)):
            lines.append(f"The top-3 features under attack differed from the clean top-3 on "
                         f"{meta.get('top3_changed_n_flipped', 0)} flipped rows (fraction {float(frac):.2f}).")
    else:
        cmm = meta.get("center_mass_ratio_mean")
        cm = cmm.get("flipped", {}) if isinstance(cmm, dict) else {}
        if isinstance(cm, dict) and cm:
            lines.append(f"The centre-mass heuristic (share of |SHAP| in the central 50% of the image) moved from "
                         f"{_fmt(cm.get('clean'))} to {_fmt(cm.get('adv'))} on flipped samples (n = {cm.get('n', 0)}). "
                         "This metric is a heuristic proxy for attention on the subject, not a segmentation.")
    if meta.get("explainer"):
        lines.append(f"Explainer: {meta.get('explainer')} (shap {meta.get('shap_version', 'n/a')}, "
                     f"nsamples={meta.get('nsamples')}, background_size={meta.get('background_size')}).")
        if meta.get("explainer") == "PartitionExplainer":
            lines.append("PartitionExplainer masking attributions are not the same quantity as gradient attributions "
                         "and are not compared across paths.")
    cache = meta.get("cache")
    if isinstance(cache, dict) and isinstance(cache.get("hits"), int) and cache["hits"] > 0:
        lines.append(f"Explanation cache: {cache['hits']} of {cache.get('n', 'n/a')} per-sample attributions were "
                     "reused from a previous run with matching input digests.")
    return lines


def _norm_label(score: MRIRecord | None, measurements: list[Measurement], norm: str | None) -> str:
    if norm:
        return norm
    if score is not None:
        return NORM_LABELS.get(score.norm, score.norm)
    for m in measurements:
        v = m.params.get("norm")
        if isinstance(v, str) and v:
            return NORM_LABELS.get(v.lower(), v)
    return "L-inf"


def text_summary(measurements: list[Measurement], observations: list[Observation], score: MRIRecord | None, *,
                 explain_meta: dict[str, Any] | None = None, scoring_reason: str | None = None,
                 limitations: list[str] | None = None, norm: str | None = None) -> str:
    """Plain-text summary for humans and for the LLM writer, scrubbed of credential-shaped tokens."""
    ref_eps = score.reference_eps if score is not None else None
    lines: list[str] = []
    lines += _measurement_lines(measurements)
    lines.append("")
    lines += _score_lines(score, scoring_reason)
    lines.append("")
    lines += _explain_lines(measurements, explain_meta, ref_eps, _norm_label(score, measurements, norm))
    lines.append("")
    lines += _observation_lines(observations)
    if limitations:
        lines.append("")
        lines.append("Limitations:")
        lines += [f"- {lim}" for lim in limitations]
    lines.append("")
    lines.append(FIXED_SENTENCE)
    return filter_output("\n".join(lines)).text
