"""The classification runner: image and tabular campaigns (spec 12.2 to 12.9, 13, 15.1).

This is the pre-refactor body of ``run_campaign`` from ``sample`` to ``control`` plus its explain stage,
moved behind the :class:`~redsim.ml.runners.base.ModalityRunner` contract with its behaviour unchanged
(``tests/ml/test_campaign_golden.py`` proves the record, the artifacts and the stage order are identical
to the frozen pre-refactor function). The sample is coerced to a float32 tensor with integer labels and
every row measures argmax classification through ``redsim.ml.eval.measure``.

Per attack and grid eps: the adapter runs (a minimal-norm adapter with ``takes_eps=False`` runs once and
is thresholded against the grid, examples over budget reverting to the clean input, spec 15.1), the rows
carry ``n`` and the ASR denominator, the adversarial slice is written as ``adv_slice/<attack>_<eps>.npz``
under the artifact cap, ``pert_first_success`` lands on the reference row only, and the finding
threshold crossing is noted from ``scoring.finding_inputs``.

Per-sample export slices (Phase B, INTEROP-04): every slice this runner writes is a self-describing
``.npz`` — ``clean_slice.npz`` after ``clean_eval`` (``x``, ``indices``, ``y``, ``y_pred_clean``,
``conf_clean``), ``adv_slice/<attack>_<eps>.npz`` per attack row and ``control_slice/<eps>.npz`` per
control row (``x_adv``, ``indices``, ``y``, ``y_pred_clean``, ``y_pred_adv``, ``conf_clean``, ``conf_adv``),
each carrying the descriptor keys ``family`` / ``attack`` / ``eps`` the Croissant export labels it by
(``redsim.ml.interop.parquet.SLICE_META_KEYS``). Confidences are the probability of the predicted class.
Every slice is written under the same ``REDSIM_ML_MAX_ADV_ARTIFACT_MB`` cap; one not retained is noted on
its measurement row, never faked at export time. A white-box adapter that raises
``AttackNotApplicable`` on a target without loss gradients is retried on the declared surrogate (spec
12.9) or recorded ``not_run`` through the frame. The control runs the uniform-noise adapter at every
grid eps and the spec 12.4 predicate decides whether it preserved accuracy. The explain closure runs
the domain's SHAP module at the reference budget and fills the ``expl_shift_*`` fields on the reference
row; an unavailable or failing explainer is recorded, never faked (spec 14.7).
"""

from __future__ import annotations

import importlib
import io
import logging
import math
import time
from typing import Any

import numpy as np

from redsim.ml.attacks import NONDETERMINISM_PREFIX
from redsim.ml.errors import AttackNotApplicable, ExplainUnavailable
from redsim.ml.eval import eps_tag, measure, per_sample_norm, pert_first_success
from redsim.ml.runners.base import (
    CONTROL_ATTACK_ID,
    EXPLAIN_MODULES,
    REALIZABILITY_CAVEAT,
    SUBJECT_CENTERED_CAVEAT,
    SURROGATE_NOTE_PREFIX,
    SURROGATE_TRANSFER_LIMITATION_TEMPLATE,
    TABULAR_LIMITATION,
    CampaignFrame,
    ModalityResult,
    SurrogateTargetView,
    as_float,
    as_int,
    call_supported,
    control_verdict,
    dataset_caveats,
    explain_fields,
    max_adv_artifact_bytes,
    split_notes,
    surrogate_description,
    surrogate_for_white_box,
)
from redsim.ml.schema import CampaignConfig, Interpretation, Measurement
from redsim.ml.scoring import MIN_CLEAN_CORRECT_FOR_FINDING, finding_inputs
from redsim.ml.targets.base import Sample, Target

logger = logging.getLogger(__name__)

__all__ = ["SLICE_FAMILY_ADVERSARIAL", "SLICE_FAMILY_CLEAN", "SLICE_FAMILY_CONTROL", "run_classification",
           "slice_bytes"]

# (eps, x_adv, params, notes, wall_time_s, queries_mean) per grid eps
AttackOutputs = list[tuple[float, np.ndarray, dict[str, Any], list[str], float, float | None]]

#: Slice families (mirrors ``redsim.ml.interop.parquet.FAMILY_*``; the runner never imports the export).
SLICE_FAMILY_CLEAN = "clean"
SLICE_FAMILY_ADVERSARIAL = "adversarial"
SLICE_FAMILY_CONTROL = "control"
SLICE_NOT_RETAINED_NOTE = "{what} slice not retained (over REDSIM_ML_MAX_ADV_ARTIFACT_MB)"


def slice_bytes(*, family: str, attack: str, eps: float | None, **arrays: np.ndarray) -> bytes:
    """A self-describing per-sample slice (INTEROP-04).

    ``arrays`` are the per-sample columns (``x`` or ``x_adv``, ``indices``, ``y``, ``y_pred_clean``,
    ``y_pred_adv``, ``conf_clean``, ``conf_adv``); ``family`` / ``attack`` travel as zero-dimensional
    unicode arrays and ``eps`` as a float scalar (omitted for the clean slice), so the export labels the
    slice from its own bytes whatever the blob backend did with the name (``allow_pickle=False`` loads
    every key). Compressed, no pickle.
    """
    payload: dict[str, Any] = dict(arrays)
    payload["family"] = np.asarray(family)
    payload["attack"] = np.asarray(attack)
    if eps is not None:
        payload["eps"] = np.asarray(float(eps), dtype=np.float64)
    buf = io.BytesIO()
    np.savez_compressed(buf, **payload)
    return buf.getvalue()


def run_classification(config: CampaignConfig, target: Target, *, frame: CampaignFrame) -> ModalityResult:
    """Sample, clean_eval, attack:<id> and control stages for an image or tabular target, plus the explain
    closure. See the module docstring; ``config`` is ``frame.config``."""
    sink = frame.sink
    info = frame.info
    domain = frame.domain
    manifest = frame.manifest
    adapters = frame.adapters
    params_by_attack = frame.params_by_attack
    grid = frame.grid
    ref = frame.ref
    l2 = frame.l2
    measurements = frame.measurements
    observations = frame.observations
    interpretation = frame.interpretation
    limitations = frame.limitations
    nondeterminism = frame.nondeterminism
    versions = frame.versions
    stage_done = frame.stage_done

    # --- sample ------------------------------------------------------------------------------
    sample: Sample = target.sample(config.n_samples, config.seed)
    x = np.asarray(sample.x, dtype=np.float32)
    y = np.asarray(sample.y).astype(int)
    n = int(y.shape[0])
    class_names = list(sample.class_names)
    dataset_name = frame.dataset_name
    slice_note = (f"slice: dataset={dataset_name}, split={config.dataset_split}, n_samples={n}, "
                  f"seed={config.seed}, selection=target.sample(n, seed)")
    # Dataset caveats recorded at build time travel with every campaign on that dataset (spec 11.3, 14.5).
    limitations.extend(f"Dataset caveat ({dataset_name}): {c}" for c in dataset_caveats(manifest, info.metadata))
    subject_centered = frame.subject_centered
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
    # Per-sample export slices (INTEROP-04): the clean slice carries the clean predictions and their
    # confidence (probability of the predicted class); adversarial and control slices below reuse them.
    conf_clean = proba_clean.max(axis=1)
    sample_indices = np.asarray(sample.indices)
    max_adv_bytes = max_adv_artifact_bytes()
    blob = slice_bytes(family=SLICE_FAMILY_CLEAN, attack="", eps=None, x=x, indices=sample_indices, y=y,
                       y_pred_clean=y_clean, conf_clean=conf_clean)
    if len(blob) <= max_adv_bytes:
        sink.put("clean_slice.npz", blob, "application/octet-stream")
    else:
        m_clean.notes.append(SLICE_NOT_RETAINED_NOTE.format(what="clean"))
    stage_done("clean_eval")

    # --- attack ------------------------------------------------------------------------------
    x_adv_ref: dict[str, np.ndarray] = {}
    proba_adv_ref: dict[str, np.ndarray] = {}
    flip_matrix: dict[str, dict[str, list[bool]]] = {}
    tabular = domain == "tabular"
    via_surrogate: list[str] = []             # white-box attacks that ran on the declared surrogate (12.9)
    surrogate_desc = surrogate_description(manifest)

    def attack_outputs(adapter: Any, attack_target: Any) -> AttackOutputs:
        """Run one adapter on ``attack_target`` for every grid eps: ``(eps, x_adv, params, notes, wall, queries)``
        per row. A minimal-norm attack runs once and is thresholded against the grid (spec 15.1); examples over
        budget revert to the clean input for that eps row. Raises ``AttackNotApplicable`` untouched."""
        aid = adapter.id
        rows: AttackOutputs = []
        if getattr(adapter, "takes_eps", True):
            for e in grid:
                p = adapter.resolve_params({**params_by_attack[aid], "eps": e})
                out = adapter.run(attack_target, x, y, p, config.seed)
                versions.update(out.library_versions)
                rows.append((e, np.asarray(out.x_adv, dtype=np.float32), dict(out.params), list(out.notes),
                             float(out.wall_time_s), out.queries_mean))
            return rows
        p = adapter.resolve_params(params_by_attack[aid])
        out = adapter.run(attack_target, x, y, p, config.seed)
        versions.update(out.library_versions)
        norms = per_sample_norm(x, out.x_adv, l2=l2)
        x_adv_full = np.asarray(out.x_adv, dtype=np.float32)
        for e in grid:
            within = norms <= e + 1e-9
            x_adv_e = np.where(within.reshape((-1,) + (1,) * (x.ndim - 1)), x_adv_full, x)
            notes = list(out.notes) + [
                (f"thresholded at eps={e:g}: {int(within.sum())}/{n} adversarial examples within budget; "
                 "the rest revert to the clean input for this row"),
                "wall_time_s is the single attack run shared by every eps row"]
            rows.append((e, x_adv_e.astype(np.float32), {**p, "eps": e}, notes, float(out.wall_time_s),
                         out.queries_mean))
        return rows

    for adapter in adapters:
        aid = adapter.id
        rows_by_eps: dict[float, Measurement] = {}
        view_used = False
        try:
            outputs = attack_outputs(adapter, target)
        except AttackNotApplicable as exc:
            # Surrogate transfer (12.9) as a fallback for adapters that do not resolve the declared surrogate
            # themselves: a white-box adapter on a target without loss gradients is retried on a view whose
            # estimator is the surrogate; predictions below still come from the real target. Never silent.
            reason = str(exc) or type(exc).__name__
            surrogate_clf = surrogate_for_white_box(target) if adapter.info().requires_gradients else None
            if surrogate_clf is None:
                frame.record_not_run(aid, reason)
                continue
            try:
                outputs = attack_outputs(adapter, SurrogateTargetView(target, surrogate_clf))
            except AttackNotApplicable as exc2:
                frame.record_not_run(aid, f"{reason}; retried on the declared surrogate: {exc2}")
                continue
            view_used = True
        adapter_noted_surrogate = any(n_.startswith(SURROGATE_NOTE_PREFIX) for row in outputs for n_ in row[3])
        if view_used or adapter_noted_surrogate:
            via_surrogate.append(aid)
        flip_matrix[aid] = {}

        flips_by_eps: dict[float, np.ndarray] = {}
        norms_by_eps: dict[float, np.ndarray] = {}
        for e, x_adv, p, notes, wall, queries in outputs:
            row_notes, nd = split_notes(notes, NONDETERMINISM_PREFIX)
            nondeterminism.extend(nd)
            proba_adv = np.asarray(target.predict_proba(x_adv), dtype=np.float64)
            y_adv = proba_adv.argmax(axis=1)
            if tabular:
                row_notes.append(REALIZABILITY_CAVEAT)
            if view_used and not adapter_noted_surrogate:
                row_notes.append(f"{SURROGATE_NOTE_PREFIX}{surrogate_desc}; the campaign handed the adapter the "
                                 "declared surrogate estimator; scored on the real model")
            m = measure(f"m.evasion.{aid}.{eps_tag(e)}", "evasion", y, y_adv, class_names, attack_id=aid,
                        params={**p, "eps": e, "norm": config.norm}, x_ref=x, x_adv=x_adv, y_pred_clean=y_clean,
                        proba=proba_adv, queries_mean=queries, wall_time_s=wall, notes=row_notes)
            flipped = (y_clean == y) & (y_adv != y)
            flips_by_eps[e] = flipped
            norms_by_eps[e] = per_sample_norm(x, x_adv, l2=l2)
            flip_matrix[aid][eps_tag(e)] = [bool(v) for v in flipped]
            rows_by_eps[e] = m
            measurements.append(m)
            if math.isclose(e, ref, abs_tol=1e-12):
                x_adv_ref[aid] = x_adv
                proba_adv_ref[aid] = proba_adv
            blob = slice_bytes(family=SLICE_FAMILY_ADVERSARIAL, attack=aid, eps=e, x_adv=x_adv,
                               indices=sample_indices, y=y, y_pred_clean=y_clean, y_pred_adv=y_adv,
                               conf_clean=conf_clean, conf_adv=proba_adv.max(axis=1))
            if len(blob) <= max_adv_bytes:
                sink.put(f"adv_slice/{aid}_{eps_tag(e)}.npz", blob, "application/octet-stream")
            else:
                m.notes.append(SLICE_NOT_RETAINED_NOTE.format(what="full adversarial"))

        # pert at first success (spec 15.1) lives on the reference row only.
        pert_mean, pert_n = pert_first_success(flips_by_eps, norms_by_eps)
        ref_row = rows_by_eps[next(e for e in rows_by_eps if math.isclose(e, ref, abs_tol=1e-12))]
        ref_row.pert_first_success_mean = pert_mean
        ref_row.pert_first_success_n = pert_n
        ref_row.notes.append(
            f"pert_first_success_mean = {pert_mean:.6g} ({config.norm}) over {pert_n} flipped samples"
            if pert_mean is not None else "pert_first_success_mean not computed (no sample flipped at any grid eps)")

        # Finding-level facts are derived by scoring.finding_inputs (spec 12.6, 15.5); the rows only
        # record the threshold crossing and the denominator guard, never a severity.
        fi = finding_inputs(config, measurements, aid)
        for e, m in rows_by_eps.items():
            if not fi.denominator_ok:
                m.notes.append(f"denominator too small for a finding (n_clean_correct={n_clean_correct} < "
                               f"{MIN_CLEAN_CORRECT_FOR_FINDING}); no Finding is created from this row")
            elif m.attack_success_rate is not None and m.attack_success_rate >= config.finding_asr_threshold:
                m.notes.append(f"attack_success_rate {m.attack_success_rate:.4f} crosses finding_asr_threshold "
                               f"{config.finding_asr_threshold:g} (first success at eps={fi.first_success_eps:g})")
        stage_done(f"attack:{aid}")

    # The in-scope attack set is what ran (spec 15.4); the frame's scoring config and curves read it.
    in_scope = frame.close_attack_set()

    # --- control -----------------------------------------------------------------------------
    x_ctrl_ref: np.ndarray | None = None   # control slice at the reference eps: the explainer's noise floor (13.5)
    if config.include_control:
        control = frame.attack_registry.get(CONTROL_ATTACK_ID)
        for e in grid:
            p = control.resolve_params({"eps": e, "norm_l2": l2})
            out = control.run(target, x, y, p, config.seed)
            if math.isclose(e, ref, abs_tol=1e-12):
                x_ctrl_ref = np.asarray(out.x_adv, dtype=np.float32)
            row_notes, nd = split_notes(out.notes, NONDETERMINISM_PREFIX)
            nondeterminism.extend(nd)
            proba_ctrl = np.asarray(target.predict_proba(out.x_adv), dtype=np.float64)
            y_ctrl = proba_ctrl.argmax(axis=1)
            m = measure(f"m.control.noise.{eps_tag(e)}", "control", y, y_ctrl, class_names,
                        attack_id=CONTROL_ATTACK_ID, params={**p, "norm": config.norm}, x_ref=x, x_adv=out.x_adv,
                        y_pred_clean=y_clean, proba=proba_ctrl, wall_time_s=out.wall_time_s,
                        notes=row_notes + ["control rows never create a Finding and never enter the MRI"])
            # Spec 12.4: "control preserves accuracy" is |acc_control - acc_clean| <= max(0.02, one binomial SE).
            # A degradation beyond that is an inferred statement with its basis ids, not a caption on the row.
            preserved, how = control_verdict(m_clean, m)
            if preserved:
                m.notes.append(f"control preserves accuracy at eps={e:g}: {m.n_correct}/{n} against clean "
                               f"{m_clean.n_correct}/{n} ({how})")
            else:
                m.notes.append(f"benign noise alone reduced accuracy from {m_clean.n_correct}/{n} to {m.n_correct}/{n} "
                               f"at eps={e:g}; the control did not preserve accuracy ({how})")
                interpretation.append(Interpretation(
                    id=f"i.control.noise_sensitive.{eps_tag(e)}",
                    statement=(f"The model is noise-sensitive at eps={e:g}: the benign control alone reduced accuracy "
                               f"from {m_clean.n_correct}/{n} to {m.n_correct}/{n}, a drop of "
                               f"{acc_clean - m.accuracy:.4f} that the control predicate does not accept ({how}); "
                               "evasion results at this eps are not attributable to adversarial alignment alone."),
                    basis=["m.clean", m.id]))
                limitations.append(f"The model is noise-sensitive at eps={e:g}: the benign control alone reduced "
                                   f"accuracy from {m_clean.n_correct}/{n} to {m.n_correct}/{n}, so evasion results "
                                   "at this eps are not attributable to adversarial alignment alone.")
            measurements.append(m)
            blob = slice_bytes(family=SLICE_FAMILY_CONTROL, attack=CONTROL_ATTACK_ID, eps=e,
                               x_adv=np.asarray(out.x_adv, dtype=np.float32), indices=sample_indices, y=y,
                               y_pred_clean=y_clean, y_pred_adv=y_ctrl, conf_clean=conf_clean,
                               conf_adv=proba_ctrl.max(axis=1))
            if len(blob) <= max_adv_bytes:
                sink.put(f"control_slice/{eps_tag(e)}.npz", blob, "application/octet-stream")
            else:
                m.notes.append(SLICE_NOT_RETAINED_NOTE.format(what="control"))
        stage_done("control")
    else:
        limitations.append("The benign noise control was disabled for this run (include_control=false); "
                           "gradient-aligned failure cannot be separated from general noise sensitivity.")

    # --- explain (run by the frame after the curve and flip-matrix artifacts) ----------------------
    def explain() -> None:
        module_name = EXPLAIN_MODULES.get(domain)
        seen_obs: set[str] = set()
        explainer_stated_limitations = False
        weak_subject = domain == "image" and subject_centered is False
        for adapter in in_scope:
            aid = adapter.id
            ref_row_id = f"m.evasion.{aid}.{eps_tag(ref)}"
            try:
                if module_name is None:
                    raise ExplainUnavailable(f"no explainer is implemented for the {domain!r} domain")
                mod = importlib.import_module(module_name)
                kwargs: dict[str, Any] = {"k": config.explain_k, "seed": config.seed}
                if domain == "tabular":
                    feats = manifest.get("features")
                    kwargs["feature_names"] = ([f.get("name") if isinstance(f, dict) else str(f) for f in feats]
                                               if isinstance(feats, list) else None)
                # Base contract: (target, sample, x_adv, proba_clean, proba_adv, sink, *, k, seed[, feature_names]).
                # Optional extras the explainer may accept: the control slice for the noise floor and the eps.
                out = call_supported(mod.explain, target, sample, x_adv_ref[aid], proba_clean, proba_adv_ref[aid],
                                     sink, **kwargs, x_ctrl=x_ctrl_ref, eps=ref)
            except Exception as exc:  # noqa: BLE001 - explain must never fail the campaign (spec 14.7)
                why_unavailable = (f"module {module_name!r} not importable" if isinstance(exc, ImportError)
                                   else f"{type(exc).__name__}: {exc}")
                interpretation.append(Interpretation(
                    id=f"i.explain.unavailable.{aid}",
                    statement=(f"Explanations are unavailable for attack {aid!r} at eps={ref:g} "
                               f"({why_unavailable}); no attribution evidence was recorded and S_expl has no "
                               "input, so the MRI is not computed."),
                    basis=[ref_row_id]))
                limitations.append(f"Explain stage unavailable for {aid!r}: {why_unavailable}.")
                continue
            for obs in list(getattr(out, "observations", []) or []):
                if obs.id in seen_obs:
                    obs = obs.model_copy(update={"id": f"{obs.id}.{aid}"})
                if weak_subject and SUBJECT_CENTERED_CAVEAT not in obs.metric_note:
                    # Spec 13.4: the centre-mass caveat travels on the observation itself, not only in prose.
                    obs = obs.model_copy(update={"metric_note": f"{obs.metric_note} {SUBJECT_CENTERED_CAVEAT}"})
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
            # The explain stage fills the attribution-shift fields on the reference row (spec 13.5).
            ref_row.expl_shift_n = as_int(fields.get("expl_shift_n"))
            ref_row.expl_shift_n_excluded = as_int(fields.get("expl_shift_n_excluded"))
            ref_row.expl_shift_noise_floor = as_float(fields.get("expl_shift_noise_floor"))
            ref_row.expl_shift_noise_floor_n = as_int(fields.get("expl_shift_noise_floor_n"))
            if shift is None:
                limitations.append(f"Explainer for {aid!r} returned no explanation-shift aggregate; S_expl has "
                                   "no input and the MRI is not computed.")
            else:
                ref_row.expl_shift_mean = shift
                if ref_row.expl_shift_n is None:
                    ref_row.expl_shift_n = len([o for o in observations if o.id in seen_obs])
                ref_row.notes.append(f"expl_shift_mean = {shift:.4f} over {ref_row.expl_shift_n} explained "
                                     "samples (explain stage, reference budget only)")
        if not explainer_stated_limitations and frame.explain_meta:
            # Only when at least one explainer ran; an all-unavailable stage already says so per attack.
            limitations.append(f"Up to {config.explain_k} flipped and {config.explain_k} unflipped samples were "
                               f"explained out of n={n}, at the reference budget eps={ref:g} only.")
        if weak_subject and observations:
            limitations.append(SUBJECT_CENTERED_CAVEAT)

    trailing: list[str] = []
    if tabular:
        trailing.append(TABULAR_LIMITATION)
    if via_surrogate:
        trailing.append(SURROGATE_TRANSFER_LIMITATION_TEMPLATE.format(attacks=", ".join(via_surrogate),
                                                                      surrogate=surrogate_desc))
    return ModalityResult(n=n, indices=np.asarray(sample.indices), flip_matrix=flip_matrix, explain=explain,
                          curves=True, mri=True, trailing_limitations=trailing)
