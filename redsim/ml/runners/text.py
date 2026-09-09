"""The text modality runner (MODALITIES-09, -18, -20, -23): ``run_text(config, target, *, frame)``.

``redsim.ml.campaign.run_campaign`` dispatches a ``text`` campaign here through
``redsim.ml.runners.base.MODALITY_RUNNERS``. The runner performs the ``sample``,
``clean_eval``, ``attack:<attack_id>`` and ``control`` stages on the frame's evidence
lists, in that order, and returns a :class:`~redsim.ml.runners.base.ModalityResult`
whose explain closure runs ``redsim.ml.explain.shap_text`` at the reference budget.
The frame owns everything else (curves, flip matrix, score, rules, report). What text
changes against the classification runner:

* the slice is an object array of message strings and is never coerced to float;
* the budget is the edit share (``Norm`` ``"edit"``, grid ``{0.1, 0.2, 0.3}``,
  reference ``0.2``): every evasion and control row states the realised
  ``edit_fraction_mean`` (the ``Measurement.edit_fraction_mean`` field wave B0 adds,
  and the row notes on either side of that rebase); ``linf_norm_mean`` /
  ``l2_norm_mean`` stay ``None`` with a note; ``pert_first_success_mean`` is the mean
  realised edit fraction at the first flipping budget; the per-message edit
  fractions and word counts are merged into ``flip_matrix.json``;
* the control is ``word_substitution.CONTROL`` (random word swaps from the slice's own
  vocabulary at the same budget, no model query), recorded under the shared control
  row id ``m.control.noise.eps<eps>`` with ``attack_id`` ``noise_control`` so the
  spec 12.4 predicate and rules I1 / I2 apply unchanged;
* the adversarial slices are JSON lines of message strings (``adv_slice/*.jsonl``)
  under the ``REDSIM_ML_MAX_ADV_ARTIFACT_MB`` cap;
* the trailing limitations are the text caveats of MODALITIES-23, the edit-grid
  scoring statement with the lexicon digest, and a correction of the standing
  white-box sentence (no gradient attack applies to a text pipeline; the black-box
  word-substitution attack was evaluated).

Nothing is faked: an adapter that raises ``AttackNotApplicable`` (no lexicon) is
recorded ``not_run`` through the frame and leaves the in-scope set before scoring;
an explainer failure is recorded per attack; every row carries ``n`` and its
denominators. The MRI of a text campaign is its own number (``modality`` and
``norm`` are in the settings hash and ``scoring.delta`` refuses a mismatch); it is
never aggregated with image or tabular campaigns.
"""

from __future__ import annotations

import io
import json
import logging
import math
import time
from collections.abc import Sequence
from typing import Any

import numpy as np

from redsim.ml.attacks import NONDETERMINISM_PREFIX
from redsim.ml.attacks import word_substitution as ws
from redsim.ml.datasets.sms_spam import edit_fraction, n_words
from redsim.ml.errors import AttackNotApplicable, TargetUnavailable
from redsim.ml.eval import eps_tag, measure, pert_first_success
from redsim.ml.runners.base import (
    CONTROL_ATTACK_ID,
    CampaignFrame,
    ModalityResult,
    as_float,
    as_int,
    call_supported,
    control_verdict,
    dataset_caveats,
    explain_fields,
    max_adv_artifact_bytes,
    split_notes,
    uniq,
)
from redsim.ml.schema import CampaignConfig, Interpretation, Measurement
from redsim.ml.scoring import MIN_CLEAN_CORRECT_FOR_FINDING, finding_inputs
from redsim.ml.targets.base import Sample, Target

logger = logging.getLogger(__name__)

MODALITY = "text"
NORM = "edit"
BUDGET_LABEL = "edit budget (share of words)"
EXPLAIN_MODULE = "redsim.ml.explain.shap_text"
NORMS_NOT_APPLICABLE_NOTE = ("linf_norm_mean / l2_norm_mean are not defined for text and are None; the budget is the "
                             "edit fraction (share of words substituted)")
EDIT_FIELD_ABSENT_NOTE = ("Measurement.edit_fraction_mean is not a field of this tree's schema (wave B0 adds it); the "
                          "value is stated in the note above")
# Correction of the standing white-box sentence (``schema.STANDING_LIMITATIONS[2]``), which the frame prints for
# every campaign and adjusts only for HopSkipJump. For a text pipeline the honest statement is this one.
WHITE_BOX_WITH_TEXT_BLACK_BOX = (
    "Correction to the standing white-box sentence for this text campaign: no white-box gradient attack applies to "
    "the text pipeline (it exposes no gradients); the black-box word_substitution attack was evaluated with "
    "predict_proba query access only; physical-world attacks were not evaluated.")
# MODALITIES-23: appended to every text campaign after the standing, D3 and dataset-caveat sentences.
TEXT_LIMITATIONS: tuple[str, ...] = (
    ("Word substitutions are lexicon-bound (WordNet-derived or committed synonym table) and semantic preservation is "
     "not verified: no sentence-encoder similarity constraint, no part-of-speech check, so adversarial messages may "
     "be ungrammatical or change meaning."),
    ("Adversarial texts are realisable inputs, unlike tabular feature vectors: a substituted message can be sent as "
     "is. Realisability says nothing about whether a human would send it."),
    ("Explanations are Partition-explainer token attributions at the reference budget only; they describe "
     "sensitivity to word removal and are not causal proof."),
    ("The class prior of the corpus is uneven (about 87% ham on the SMS Spam Collection), so per-class n is shown on "
     "every row and per-class figures carry wide uncertainty at the default slice size."),
)
TEXT_SCORING_LIMITATION_TEMPLATE = (
    "The edit-budget grid is a share of words substituted; S_eps integrates accuracy over that grid and the MRI is "
    "comparable only with text campaigns at an identical grid, reference budget and lexicon ({lexicon}).")

__all__ = [
    "BUDGET_LABEL", "EXPLAIN_MODULE", "MODALITY", "NORM", "TEXT_LIMITATIONS", "TEXT_SCORING_LIMITATION_TEMPLATE",
    "WHITE_BOX_WITH_TEXT_BLACK_BOX", "edit_fractions", "run_text",
]

# (eps, x_adv, params, notes, wall_time_s, queries_mean) per grid eps
AttackOutputs = list[tuple[float, np.ndarray, dict[str, Any], list[str], float, float | None]]


def _texts(x: Any) -> list[str]:
    items = x.tolist() if isinstance(x, np.ndarray) else list(x)
    bad = sorted({type(t).__name__ for t in items if not isinstance(t, str)})
    if bad:
        raise TargetUnavailable(f"a text target must sample message strings; got {bad}")
    return [str(t) for t in items]


def _set_if_field(model: Any, name: str, value: Any) -> bool:
    """Assign a wave B0 field when this tree's schema has it; the caller states the value in a note as well."""
    if name in type(model).model_fields:
        setattr(model, name, value)
        return True
    return False


def _jsonl_bytes(texts: Sequence[str], indices: np.ndarray, y: np.ndarray, class_names: Sequence[str]) -> bytes:
    buf = io.StringIO()
    for text, idx, label in zip(texts, np.asarray(indices).tolist(), np.asarray(y).tolist(), strict=True):
        buf.write(json.dumps({"index": int(idx), "text": text, "label": class_names[int(label)]}, ensure_ascii=False))
        buf.write("\n")
    return buf.getvalue().encode("utf-8")


def edit_fractions(texts: Sequence[str], adv: Sequence[str]) -> np.ndarray:
    """Per-message realised edit fraction (``nan`` when a pair is not one-word-for-one-word or has no words)."""
    out = np.full(len(texts), np.nan, dtype=np.float64)
    for i, (a, b) in enumerate(zip(texts, adv, strict=True)):
        f = edit_fraction(a, b)
        if f is not None:
            out[i] = f
    return out


def _edit_note(fractions: np.ndarray, eps: float) -> tuple[float | None, str]:
    defined = fractions[~np.isnan(fractions)]
    frac_mean = float(defined.mean()) if defined.size else None
    n_undefined = int(np.isnan(fractions).sum())
    note = (f"edit_fraction_mean = {frac_mean:.4f} realised share of words substituted over {int(defined.size)} "
            "messages" if frac_mean is not None
            else "edit_fraction_mean not computed (no message has a defined edit fraction)")
    if n_undefined:
        note += f"; {n_undefined} message(s) excluded (token count changed or no words)"
    note += f"; budget eps={eps:g} = ceil(eps * n_words) words per message (at least 1)"
    return frac_mean, note


def _lexicon_description(manifest: dict[str, Any], row_notes: Sequence[str]) -> str:
    block = manifest.get("lexicon")
    if isinstance(block, dict) and block.get("sha256"):
        return f"lexicon source={block.get('source')}, sha256={block.get('sha256')}"
    found = uniq([n for n in row_notes if n.startswith("lexicon:")])
    return "; ".join(found) if found else "lexicon not recorded"


def run_text(config: CampaignConfig, target: Target, *, frame: CampaignFrame) -> ModalityResult:
    """Sample, clean_eval, attack:<id> and control stages for a text target, plus the explain closure.

    ``config`` is ``frame.config``. Raises ``ValueError`` before any stage when the campaign norm is not
    ``"edit"`` (a text budget is a share of words, never an L-p radius).
    """
    if config.norm != NORM:
        raise ValueError(f"a text campaign's norm is {NORM!r} (share of words substituted), got {config.norm!r}")
    sink = frame.sink
    info = frame.info
    manifest = frame.manifest
    adapters = frame.adapters
    params_by_attack = frame.params_by_attack
    grid = frame.grid
    ref = frame.ref
    measurements = frame.measurements
    observations = frame.observations
    interpretation = frame.interpretation
    limitations = frame.limitations
    nondeterminism = frame.nondeterminism
    versions = frame.versions
    stage_done = frame.stage_done
    for adapter in adapters:
        norms = getattr(adapter, "norms", None)
        if norms is not None and NORM not in norms:
            raise AttackNotApplicable(f"attack {adapter.id!r} supports the norms {sorted(norms)}; a text campaign "
                                      f"runs under {NORM!r}")

    # --- sample ------------------------------------------------------------------------------
    sample: Sample = target.sample(config.n_samples, config.seed)
    texts = _texts(sample.x)
    x = np.asarray(texts, dtype=object)
    y = np.asarray(sample.y).astype(int)
    n = int(y.shape[0])
    if len(texts) != n:
        raise TargetUnavailable("the text slice's x and y disagree on the number of rows")
    class_names = list(sample.class_names)
    dataset_name = frame.dataset_name
    words_per_text = [n_words(t) for t in texts]
    slice_note = (f"slice: dataset={dataset_name}, split={config.dataset_split}, n_samples={n}, seed={config.seed}, "
                  f"selection=target.sample(n, seed); words per message: min {min(words_per_text, default=0)}, "
                  f"mean {float(np.mean(words_per_text)) if words_per_text else 0.0:.1f}, "
                  f"max {max(words_per_text, default=0)}")
    limitations.extend(f"Dataset caveat ({dataset_name}): {c}" for c in dataset_caveats(manifest, info.metadata))
    stage_done("sample")

    # --- clean_eval --------------------------------------------------------------------------
    t0 = time.perf_counter()
    proba_clean = np.asarray(target.predict_proba(x), dtype=np.float64)
    y_clean = proba_clean.argmax(axis=1)
    m_clean = measure("m.clean", "clean", y, y_clean, class_names, wall_time_s=time.perf_counter() - t0,
                      notes=[slice_note])
    measurements.append(m_clean)
    acc_clean = m_clean.accuracy
    n_clean_correct = m_clean.n_correct
    stage_done("clean_eval")

    # --- attack ------------------------------------------------------------------------------
    x_adv_ref: dict[str, np.ndarray] = {}
    proba_adv_ref: dict[str, np.ndarray] = {}
    flip_matrix: dict[str, dict[str, list[bool]]] = {}
    edit_matrix: dict[str, dict[str, list[float | None]]] = {}
    max_adv_bytes = max_adv_artifact_bytes()
    lexicon_notes: list[str] = []

    for adapter in adapters:
        aid = adapter.id
        rows_by_eps: dict[float, Measurement] = {}
        outputs: AttackOutputs = []
        try:
            for e in grid:
                p = adapter.resolve_params({**params_by_attack[aid], "eps": e})
                out = adapter.run(target, x, y, p, config.seed)
                versions.update(out.library_versions)
                outputs.append((e, np.asarray(out.x_adv, dtype=object), dict(out.params), list(out.notes),
                                float(out.wall_time_s), out.queries_mean))
        except AttackNotApplicable as exc:
            frame.record_not_run(aid, str(exc) or type(exc).__name__)
            continue
        flip_matrix[aid] = {}
        edit_matrix[aid] = {}
        flips_by_eps: dict[float, np.ndarray] = {}
        fractions_by_eps: dict[float, np.ndarray] = {}
        for e, x_adv, p, notes, wall, queries in outputs:
            row_notes, nd = split_notes(notes, NONDETERMINISM_PREFIX)
            nondeterminism.extend(nd)
            lexicon_notes.extend(nt for nt in row_notes if nt.startswith("lexicon:"))
            adv_texts = _texts(x_adv)
            if len(adv_texts) != n:
                raise AttackNotApplicable(f"attack {aid!r} returned {len(adv_texts)} rows for {n} messages")
            proba_adv = np.asarray(target.predict_proba(x_adv), dtype=np.float64)
            y_adv = proba_adv.argmax(axis=1)
            fractions = edit_fractions(texts, adv_texts)
            frac_mean, edit_note = _edit_note(fractions, e)
            row_notes.extend([edit_note, NORMS_NOT_APPLICABLE_NOTE])
            m = measure(f"m.evasion.{aid}.{eps_tag(e)}", "evasion", y, y_adv, class_names, attack_id=aid,
                        params={**p, "eps": e, "norm": config.norm}, y_pred_clean=y_clean, proba=proba_adv,
                        queries_mean=queries, wall_time_s=wall, notes=row_notes)
            if frac_mean is not None and not _set_if_field(m, "edit_fraction_mean", frac_mean):
                m.notes.append(EDIT_FIELD_ABSENT_NOTE)
            flipped = (y_clean == y) & (y_adv != y)
            flips_by_eps[e] = flipped
            fractions_by_eps[e] = np.where(np.isnan(fractions), 0.0, fractions)
            flip_matrix[aid][eps_tag(e)] = [bool(v) for v in flipped]
            edit_matrix[aid][eps_tag(e)] = [None if math.isnan(f) else float(f) for f in fractions.tolist()]
            rows_by_eps[e] = m
            measurements.append(m)
            if math.isclose(e, ref, abs_tol=1e-12):
                x_adv_ref[aid] = x_adv
                proba_adv_ref[aid] = proba_adv
            blob = _jsonl_bytes(adv_texts, np.asarray(sample.indices), y, class_names)
            if len(blob) <= max_adv_bytes:
                sink.put(f"adv_slice/{aid}_{eps_tag(e)}.jsonl", blob, "application/json")
            else:
                m.notes.append("full adversarial slice not retained (over REDSIM_ML_MAX_ADV_ARTIFACT_MB)")

        # pert at first success (spec 15.1) lives on the reference row only: the realised edit fraction of the
        # smallest budget at which each message flipped, averaged over the messages that flipped anywhere.
        pert_mean, pert_n = pert_first_success(flips_by_eps, fractions_by_eps)
        ref_row = rows_by_eps[next(e for e in rows_by_eps if math.isclose(e, ref, abs_tol=1e-12))]
        ref_row.pert_first_success_mean = pert_mean
        ref_row.pert_first_success_n = pert_n
        ref_row.notes.append(
            f"pert_first_success_mean = {pert_mean:.6g} (realised edit fraction at the first flipping budget) over "
            f"{pert_n} flipped samples" if pert_mean is not None
            else "pert_first_success_mean not computed (no sample flipped at any grid budget)")
        fi = finding_inputs(config, measurements, aid)
        for e, m in rows_by_eps.items():
            if not fi.denominator_ok:
                m.notes.append(f"denominator too small for a finding (n_clean_correct={n_clean_correct} < "
                               f"{MIN_CLEAN_CORRECT_FOR_FINDING}); no Finding is created from this row")
            elif m.attack_success_rate is not None and m.attack_success_rate >= config.finding_asr_threshold:
                m.notes.append(f"attack_success_rate {m.attack_success_rate:.4f} crosses finding_asr_threshold "
                               f"{config.finding_asr_threshold:g} (first success at eps={fi.first_success_eps:g})")
        stage_done(f"attack:{aid}")

    in_scope = frame.close_attack_set()

    # --- control -----------------------------------------------------------------------------
    x_ctrl_ref: np.ndarray | None = None
    if config.include_control:
        control = ws.CONTROL
        for e in grid:
            p = control.resolve_params({"eps": e})
            out = control.run(target, x, y, p, config.seed)
            ctrl_texts = _texts(out.x_adv)
            if math.isclose(e, ref, abs_tol=1e-12):
                x_ctrl_ref = np.asarray(ctrl_texts, dtype=object)
            row_notes, nd = split_notes(out.notes, NONDETERMINISM_PREFIX)
            nondeterminism.extend(nd)
            proba_ctrl = np.asarray(target.predict_proba(out.x_adv), dtype=np.float64)
            y_ctrl = proba_ctrl.argmax(axis=1)
            frac_mean, edit_note = _edit_note(edit_fractions(texts, ctrl_texts), e)
            row_notes.append(f"control adapter {control.id} (random word swaps) recorded under the shared control "
                             f"row id, attack_id={CONTROL_ATTACK_ID}")
            row_notes.extend([edit_note, NORMS_NOT_APPLICABLE_NOTE])
            m = measure(f"m.control.noise.{eps_tag(e)}", "control", y, y_ctrl, class_names,
                        attack_id=CONTROL_ATTACK_ID, params={**p, "norm": config.norm}, y_pred_clean=y_clean,
                        proba=proba_ctrl, wall_time_s=out.wall_time_s,
                        notes=row_notes + ["control rows never create a Finding and never enter the MRI"])
            if frac_mean is not None:
                _set_if_field(m, "edit_fraction_mean", frac_mean)
            preserved, how = control_verdict(m_clean, m)
            if preserved:
                m.notes.append(f"control preserves accuracy at eps={e:g}: {m.n_correct}/{n} against clean "
                               f"{m_clean.n_correct}/{n} ({how})")
            else:
                m.notes.append(f"random word swaps alone reduced accuracy from {m_clean.n_correct}/{n} to "
                               f"{m.n_correct}/{n} at eps={e:g}; the control did not preserve accuracy ({how})")
                interpretation.append(Interpretation(
                    id=f"i.control.noise_sensitive.{eps_tag(e)}",
                    statement=(f"The model is sensitive to random word swaps at eps={e:g}: the benign control alone "
                               f"reduced accuracy from {m_clean.n_correct}/{n} to {m.n_correct}/{n}, a drop of "
                               f"{acc_clean - m.accuracy:.4f} that the control predicate does not accept ({how}); "
                               "evasion results at this budget are not attributable to synonym-directed "
                               "substitution alone."),
                    basis=["m.clean", m.id]))
                limitations.append(f"The model is sensitive to random word swaps at eps={e:g}: the benign control "
                                   f"alone reduced accuracy from {m_clean.n_correct}/{n} to {m.n_correct}/{n}, so "
                                   "evasion results at this budget are not attributable to synonym-directed "
                                   "substitution alone.")
            measurements.append(m)
        stage_done("control")
    else:
        limitations.append("The benign word-swap control was disabled for this run (include_control=false); "
                           "synonym-directed failure cannot be separated from general sensitivity to word changes.")

    model_sha256 = manifest.get("model_sha256") or manifest.get("weights_sha256") or manifest.get("sha256")
    dataset_revision = frame.dataset_revision

    # --- explain (run by the frame after the curve and flip-matrix artifacts) ----------------------
    def explain() -> None:
        seen_obs: set[str] = set()
        explainer_stated_limitations = False
        for adapter in in_scope:
            aid = adapter.id
            ref_row_id = f"m.evasion.{aid}.{eps_tag(ref)}"
            try:
                import importlib

                mod = importlib.import_module(EXPLAIN_MODULE)
                out = call_supported(mod.explain, target, sample, x_adv_ref[aid], proba_clean, proba_adv_ref[aid],
                                     sink, k=config.explain_k, seed=config.seed, x_ctrl=x_ctrl_ref, eps=ref,
                                     attack_id=aid, model_sha256=None if model_sha256 is None else str(model_sha256),
                                     dataset_revision=None if dataset_revision is None else str(dataset_revision))
            except Exception as exc:  # noqa: BLE001 - explain must never fail the campaign (spec 14.7)
                why_unavailable = (f"module {EXPLAIN_MODULE!r} not importable" if isinstance(exc, ImportError)
                                   else f"{type(exc).__name__}: {exc}")
                interpretation.append(Interpretation(
                    id=f"i.explain.unavailable.{aid}",
                    statement=(f"Explanations are unavailable for attack {aid!r} at eps={ref:g} ({why_unavailable}); "
                               "no attribution evidence was recorded and S_expl has no input, so the MRI is not "
                               "computed."),
                    basis=[ref_row_id]))
                limitations.append(f"Explain stage unavailable for {aid!r}: {why_unavailable}.")
                continue
            for obs in list(getattr(out, "observations", []) or []):
                if obs.id in seen_obs:
                    obs = obs.model_copy(update={"id": f"{obs.id}.{aid}"})
                seen_obs.add(obs.id)
                observations.append(obs)
            fields = explain_fields(out)
            shift = as_float(fields.get("expl_shift_mean"))
            meta = dict(getattr(out, "meta", {}) or {})
            nd_meta = meta.get("nondeterminism")
            if isinstance(nd_meta, str):
                nondeterminism.append(nd_meta)
            elif isinstance(nd_meta, (list, tuple)):
                nondeterminism.extend(str(s) for s in nd_meta)
            lim_meta = meta.get("limitations")
            if isinstance(lim_meta, (list, tuple)) and lim_meta:
                limitations.extend(str(s) for s in lim_meta)
                explainer_stated_limitations = True
            frame.explain_meta[aid] = meta
            ref_row = next(m for m in measurements if m.id == ref_row_id)
            ref_row.expl_shift_n = as_int(fields.get("expl_shift_n"))
            ref_row.expl_shift_n_excluded = as_int(fields.get("expl_shift_n_excluded"))
            ref_row.expl_shift_noise_floor = as_float(fields.get("expl_shift_noise_floor"))
            ref_row.expl_shift_noise_floor_n = as_int(fields.get("expl_shift_noise_floor_n"))
            if shift is None:
                limitations.append(f"Explainer for {aid!r} returned no explanation-shift aggregate; S_expl has no "
                                   "input and the MRI is not computed.")
            else:
                ref_row.expl_shift_mean = shift
                if ref_row.expl_shift_n is None:
                    ref_row.expl_shift_n = len([o for o in observations if o.id in seen_obs])
                ref_row.notes.append(f"expl_shift_mean = {shift:.4f} over {ref_row.expl_shift_n} explained messages "
                                     "(explain stage, reference budget only, positional token attributions)")
        if not explainer_stated_limitations and frame.explain_meta:
            limitations.append(f"Up to {config.explain_k} flipped and {config.explain_k} unflipped messages were "
                               f"explained out of n={n}, at the reference budget eps={ref:g} only.")

    trailing = [WHITE_BOX_WITH_TEXT_BLACK_BOX, *TEXT_LIMITATIONS]
    if in_scope:
        trailing.append(TEXT_SCORING_LIMITATION_TEMPLATE.format(lexicon=_lexicon_description(manifest, lexicon_notes)))
    return ModalityResult(
        n=n, indices=np.asarray(sample.indices), flip_matrix=flip_matrix, explain=explain, curves=True, mri=True,
        trailing_limitations=trailing,
        flip_matrix_extra={"budget": BUDGET_LABEL, "edit_fraction": edit_matrix, "n_words": words_per_text},
    )
