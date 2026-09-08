"""Deterministic SHAP text summary (spec section 13.7).

The only explanation-derived content the LLM writer may see: plain-text
measurements with denominators, the scorecard numbers (or the reason the MRI
was not computed), the explanation aggregates with their ``n``, and the top
attribution observations by feature identifier or class label. No image, no
array, no URL string. The text is scrubbed with ``guardrails.filter_output``.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from redsim.llm.guardrails import filter_output
from redsim.ml.schema import Measurement, Observation, Scoring

FIXED_SENTENCE = "SHAP attributions describe the model's sensitivity, not the cause of a failure."
MAX_OBSERVATIONS_LISTED = 8


def _fmt(v: float | None, nd: int = 3) -> str:
    return "n/a" if v is None else f"{v:.{nd}f}"


def _eps(m: Measurement) -> float | None:
    e = m.params.get("eps")
    return float(e) if isinstance(e, (int, float)) and not isinstance(e, bool) else None


def _measurement_lines(measurements: list[Measurement]) -> list[str]:
    clean = next((m for m in measurements if m.family == "clean"), None)
    lines = ["Measurements (counts and rates; every rate is shown with its denominator):"]
    if clean is not None:
        lines.append(f"slice: n = {clean.n}; clean accuracy {clean.n_correct}/{clean.n} ({_fmt(clean.accuracy)})")
    for m in measurements:
        parts = [f"- {m.id}: family={m.family}"]
        if m.attack_id:
            parts.append(f"attack={m.attack_id}")
        eps = _eps(m)
        if eps is not None:
            parts.append(f"eps={eps:g}")
        parts.append(f"accuracy={m.n_correct}/{m.n} ({_fmt(m.accuracy)})")
        if m.n_flipped_from_clean is not None and clean is not None:
            if clean.n_correct > 0:
                asr = m.n_flipped_from_clean / clean.n_correct
                parts.append(f"flipped_from_clean={m.n_flipped_from_clean}/{clean.n_correct} (ASR {_fmt(asr)})")
            else:
                parts.append(f"flipped_from_clean={m.n_flipped_from_clean}/0 (ASR not computed: denominator 0)")
        if m.linf_norm_mean is not None:
            parts.append(f"linf_mean={_fmt(m.linf_norm_mean, 4)}")
        if m.severity:
            parts.append(f"severity={m.severity}")
        if m.notes:
            parts.append("notes: " + "; ".join(m.notes))
        lines.append(" ".join(parts))
    return lines


def _scoring_lines(scoring: Scoring | None, reason: str | None) -> list[str]:
    if scoring is None:
        why = reason or "one or more of the five subscores is unavailable"
        return ["Scoring: MRI not computed: " + why + ". Weights are never renormalised over available dimensions."]
    subs = ", ".join(f"{k}={v:.1f}" for k, v in scoring.subscores.items())
    weights = ", ".join(f"{k}={v:g}" for k, v in scoring.weights.items())
    lines = [
        (f"Scoring (one campaign: modality={scoring.modality}, attacks={', '.join(scoring.attack_ids)}, "
         f"eps_grid={scoring.eps_grid}, reference_eps={scoring.reference_eps:g}):"),
        f"MRI = {scoring.mri} (grade {scoring.grade}); subscores {subs}; weights {weights}.",
        f"Reading: {scoring.reading}",
    ]
    if scoring.delta_mri is not None:
        lines.append(f"Measured delta MRI vs {scoring.delta_from or 'baseline'}: {scoring.delta_mri:+d}.")
    lines.append("A grade describes measured behaviour under the declared attack set, eps grid and slice. "
                 "It is not a readiness, safety, or certification statement.")
    return lines


def _mean(vals: Iterable[float | None]) -> float | None:
    xs = [float(v) for v in vals if v is not None]
    return sum(xs) / len(xs) if xs else None


def _observation_lines(observations: list[Observation], explain_meta: dict[str, Any] | None) -> list[str]:
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
    per_sample = (explain_meta or {}).get("per_sample", {}) if isinstance(explain_meta, dict) else {}
    ranked = sorted(observations, key=lambda o: (not o.flipped, o.id))[:MAX_OBSERVATIONS_LISTED]
    lines.append("Top attribution observations (labels and feature identifiers only):")
    for o in ranked:
        parts = [(f"- {o.id}: true={o.true_label} clean={o.pred_clean} ({o.confidence_clean:.2f}) "
                  f"adv={o.pred_adv} ({o.confidence_adv:.2f}) flipped={'yes' if o.flipped else 'no'}")]
        if o.center_mass_ratio_clean is not None or o.center_mass_ratio_adv is not None:
            parts.append(f"center_mass clean={_fmt(o.center_mass_ratio_clean)} adv={_fmt(o.center_mass_ratio_adv)} "
                         "[heuristic]")
        ps = per_sample.get(o.id, {}) if isinstance(per_sample, dict) else {}
        if isinstance(ps, dict):
            if ps.get("expl_shift") is not None:
                parts.append(f"expl_shift={float(ps['expl_shift']):.3f}")
            if ps.get("top_features_clean"):
                parts.append("top features clean: " + ", ".join(str(f) for f in ps["top_features_clean"][:5]))
            if ps.get("top_features_adv"):
                parts.append("adversarial: " + ", ".join(str(f) for f in ps["top_features_adv"][:5]))
        lines.append("; ".join(parts))
    return lines


def _explain_lines(explain_meta: dict[str, Any] | None, attack: str | None, reference_eps: float | None,
                   norm: str) -> list[str]:
    if not isinstance(explain_meta, dict) or not explain_meta:
        return ["Explanation aggregates: unavailable (explain stage absent or unsupported); S_expl has no input."]
    n = explain_meta.get("expl_shift_n", 0)
    shift = explain_meta.get("expl_shift_mean")
    floor = explain_meta.get("expl_shift_noise_floor")
    n_ctrl = explain_meta.get("expl_shift_noise_floor_n", 0)
    n_f = explain_meta.get("n_flipped_explained", 0)
    n_u = explain_meta.get("n_unflipped_explained", 0)
    a = attack or "the attack set"
    eps_txt = f"{reference_eps:g}" if reference_eps is not None else str(explain_meta.get("eps", "reference"))
    floor_txt = (f"{_fmt(floor)} over n = {n_ctrl}" if floor is not None else "not computed (no control explained)")
    lines = ["Explanation aggregates (derived values with denominators):"]
    if explain_meta.get("modality") == "tabular":
        t5c = ", ".join(explain_meta.get("top5_clean", [])) or "n/a"
        t5a = ", ".join(explain_meta.get("top5_adv", [])) or "n/a"
        lines.append(f"For {a} at eps = {eps_txt} (per-feature scaled), the top features by mean |SHAP| were {t5c} "
                     f"on clean rows and {t5a} on adversarial rows (n = {explain_meta.get('n_explained', n)}); "
                     f"{explain_meta.get('n_rank_changes', 'n/a')} of the top 5 changed rank. Mean expl_shift was "
                     f"{_fmt(shift)} (n = {n}); the control at the same eps gave {floor_txt}.")
        frac = explain_meta.get("top3_changed_fraction_flipped")
        if frac is not None:
            lines.append(f"The top-3 features under attack differed from the clean top-3 on "
                         f"{explain_meta.get('top3_changed_n_flipped', 0)} flipped rows (fraction {frac:.2f}).")
    else:
        cm = explain_meta.get("center_mass_ratio_mean", {}).get("flipped", {}) if isinstance(
            explain_meta.get("center_mass_ratio_mean"), dict) else {}
        lines.append(f"For {a} at eps = {eps_txt} ({norm}), attribution similarity between clean and adversarial inputs "
                     f"fell to a mean expl_shift of {_fmt(shift)} over n = {n} explained samples ({n_f} flipped, "
                     f"{n_u} not); the benign-noise control at the same eps gave {floor_txt}.")
        if cm:
            lines.append(f"The centre-mass heuristic (share of |SHAP| in the central 50% of the image) moved from "
                         f"{_fmt(cm.get('clean'))} to {_fmt(cm.get('adv'))} on flipped samples (n = {cm.get('n', 0)}); "
                         "this metric is a heuristic proxy for attention on the subject, not a segmentation.")
    lines.append(f"Explainer: {explain_meta.get('explainer', 'n/a')} (shap {explain_meta.get('shap_version', 'n/a')}, "
                 f"nsamples={explain_meta.get('nsamples')}, background_size={explain_meta.get('background_size')}).")
    return lines


def text_summary(measurements: list[Measurement], observations: list[Observation], scoring: Scoring | None, *,
                 explain_meta: dict[str, Any] | None = None, scoring_reason: str | None = None,
                 limitations: list[str] | None = None, norm: str = "L-inf") -> str:
    """Plain-text summary for humans and for the LLM writer, scrubbed of credential-shaped tokens."""
    ref_rows = [m for m in measurements if m.family == "evasion"]
    attack = ", ".join(sorted({m.attack_id for m in ref_rows if m.attack_id})) or None
    ref_eps = scoring.reference_eps if scoring is not None else None
    lines: list[str] = []
    lines += _measurement_lines(measurements)
    lines.append("")
    lines += _scoring_lines(scoring, scoring_reason)
    lines.append("")
    lines += _explain_lines(explain_meta, attack, ref_eps, norm)
    lines.append("")
    lines += _observation_lines(observations, explain_meta)
    if limitations:
        lines.append("")
        lines.append("Limitations:")
        lines += [f"- {lim}" for lim in limitations]
    lines.append("")
    lines.append(FIXED_SENTENCE)
    return filter_output("\n".join(lines)).text
