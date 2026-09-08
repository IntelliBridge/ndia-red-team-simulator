"""Run one adversarial-ML campaign end to end and assemble its record.

Pure Python: no Celery, database or HTTP. The worker task calls ``run_campaign``
inside the sandboxed child and persists the returned record; tests call it on the
``TinyTarget`` double with a ``FilesystemSink``.

Stage order follows ``redsim.ml.schema.STAGES``: load_target -> sample -> clean_eval
-> attack (written per attack as ``attack:<attack_id>``, every eps in the grid) ->
control (benign noise at every eps, the reference eps included) -> explain (at the
reference budget; optional and tolerant of a missing or failing explainer) -> score
-> interpret -> recommend -> report. The explain and recommend modules are imported
lazily; when one is absent or fails the record says so in an ``Interpretation`` and a
limitation rather than pretending (spec 14.7).

Invariants enforced here (spec 14, 15): measurements, observations, interpretation
and candidate recommendations stay in separate lists; every Measurement carries
``n`` and its denominators; a control accompanies the attacks at the same eps; the
MRI is computed only when all five subscores exist and the score record is
otherwise partial with the reason in ``missing`` and ``limitations``; every
citation resolves to a recorded id; candidates carry no measured delta.

The returned ``CampaignRecord`` is a ``RunRecord`` plus the queryable projections
(``curve``, ``settings_hash``, ``completeness``, ``missing``, ``score_status``).
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import inspect
import io
import json
import math
import os
import platform
import socket
import sys
import time
import uuid
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any

import numpy as np

from redsim.ml.artifacts import ArtifactSink
from redsim.ml.attacks import (
    ATTACKS,
    CPU_FLOAT32_NOTE,
    NONDETERMINISM_PREFIX,
    library_versions,
)
from redsim.ml.errors import AttackNotApplicable, ExplainUnavailable, MLError, TargetUnavailable
from redsim.ml.eval import eps_tag, measure, per_sample_norm, pert_first_success
from redsim.ml.schema import (
    AttackInfo,
    CampaignConfig,
    CampaignRecord,
    CandidateRecommendation,
    Interpretation,
    Measurement,
    MRIRecord,
    Observation,
    Provenance,
    RobustnessCurve,
    ScoreStatus,
    standing_limitations,
)
from redsim.ml.scoring import (
    MIN_CLEAN_CORRECT_FOR_FINDING,
    ONE_POINT_GRID_LIMITATION,
    finding_inputs,
    robustness_curves,
    score_run,
    settings_hash,
)
from redsim.ml.targets.base import Sample, Target
from redsim.ml.targets.registry import TARGETS

CONTROL_ATTACK_ID = "noise_control"
DEFAULT_MAX_ADV_ARTIFACT_MB = 64.0                   # spec 12.8

REALIZABILITY_CAVEAT = "feature-space perturbation; realizability not established"
DEFENSE_LIMITATION = (
    "The white-box attacks in this run used ART's straight-through gradient estimate through the "
    "preprocessing defense. Adaptive attacks that account for the defense may succeed where these did "
    "not, so the measured delta MRI is an upper bound on the defense's benefit against these attacks, "
    "not a general robustness gain.")
TABULAR_LIMITATION = (
    "Tabular evasion rows are feature-space perturbations; a perturbed feature vector is evidence about "
    "the decision surface and is a realizable attack only if it maps back to a constructible input, which "
    "this run neither constructs nor checks. L-inf budgets on mixed-type features are a further caveat.")
MRI_SCOPE_LIMITATION = (
    "The MRI summarises this campaign only (one model, one modality, the declared attack set, eps grid "
    "and reference budget); it is not comparable across campaigns with different settings and is never "
    "aggregated across modalities.")
WHITE_BOX_STANDING = "White-box gradient attacks assume full model access; black-box and physical-world attacks were not evaluated."
WHITE_BOX_WITH_BLACK_BOX = (
    "White-box gradient attacks assume full model access; the black-box attack hopskipjump was evaluated "
    "with label-only query access; physical-world attacks were not evaluated.")
_EXPLAIN_MODULES = {"image": "redsim.ml.explain.shap_image", "tabular": "redsim.ml.explain.shap_tabular"}
_THREAD_ENV_VARS = ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "REDSIM_ML_SANDBOX_THREADS")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _dist_version(dist: str, module: str) -> str:
    try:
        return version(dist)
    except PackageNotFoundError:
        pass
    try:
        return str(getattr(importlib.import_module(module), "__version__", "unknown"))
    except Exception:  # noqa: BLE001 - optional dependency
        return "not installed"


def _redsim_version() -> str:
    try:
        from redsim import __version__
        return str(__version__)
    except Exception:  # noqa: BLE001
        return _dist_version("redsim-platform", "redsim")


def _manifest_get(manifest: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in manifest and manifest[k] is not None:
            return manifest[k]
    return None


def _max_adv_artifact_bytes() -> int:
    raw = os.environ.get("REDSIM_ML_MAX_ADV_ARTIFACT_MB", "").strip()
    try:
        mb = float(raw) if raw else DEFAULT_MAX_ADV_ARTIFACT_MB
    except ValueError:
        mb = DEFAULT_MAX_ADV_ARTIFACT_MB
    return int(mb * 1024 * 1024)


def _npz_bytes(x_adv: np.ndarray, indices: np.ndarray, y: np.ndarray) -> bytes:
    buf = io.BytesIO()
    np.savez_compressed(buf, x_adv=x_adv, indices=indices, y=y)
    return buf.getvalue()


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, indent=2, sort_keys=True, default=str).encode("utf-8")


def _split_notes(notes: list[str]) -> tuple[list[str], list[str]]:
    """Separate ``nondeterminism: ...`` notes (-> Provenance) from row notes (-> Measurement)."""
    row, nd = [], []
    for n in notes:
        if n.startswith(NONDETERMINISM_PREFIX):
            nd.append(n[len(NONDETERMINISM_PREFIX):])
        else:
            row.append(n)
    return row, nd


def _uniq(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def _call_supported(fn: Any, *args: Any, **optional: Any) -> Any:
    """Call ``fn`` with the positional contract plus only those optional keywords its signature
    accepts. The explain / recommend modules may extend the base contract with extra keywords
    (``x_ctrl``, ``reference_eps``, ...); a callee that lacks them still gets a valid call."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return fn(*args)
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return fn(*args, **optional)
    return fn(*args, **{k: v for k, v in optional.items() if k in params})


def _sha256_indices(indices: Any) -> str:
    arr = np.asarray(indices).astype(np.int64)
    return hashlib.sha256(arr.tobytes()).hexdigest()


def _thread_env() -> dict[str, str]:
    """``OMP_NUM_THREADS``, ``MKL_NUM_THREADS`` and the torch thread count, as observed (spec 14.4)."""
    env = {k: os.environ[k] for k in _THREAD_ENV_VARS if os.environ.get(k)}
    with contextlib.suppress(Exception):  # torch is optional for tabular targets
        import torch
        env["torch_threads"] = str(torch.get_num_threads())
    return env


def _as_int(v: Any) -> int | None:
    if isinstance(v, bool) or not isinstance(v, (int, float, np.integer, np.floating)):
        return None
    return int(v)


def _as_float(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float, np.integer, np.floating)):
        return None
    return float(v)


def _defense_provenance(target: Target, config: CampaignConfig) -> dict[str, Any] | None:
    """``Provenance.defense`` for a verify run: the applied defense as the wrapper describes it (ART class,
    resolved params, what it does not defend), else the requested ``DefenseConfig`` when the wrapper does
    not describe itself. ``None`` for an attack run."""
    if config.defense is None:
        return None
    describe = getattr(target, "describe", None)
    if callable(describe):
        described = describe()
        if isinstance(described, dict):
            return dict(described)
    return config.defense.model_dump(mode="json")


# The reference-row Measurement fields the explain stage supplies (spec 13.5; ``explain.base.MEASUREMENT_FIELDS``).
_EXPLAIN_FIELDS = ("expl_shift_mean", "expl_shift_n", "expl_shift_n_excluded", "expl_shift_noise_floor",
                   "expl_shift_noise_floor_n")


def _explain_fields(out: Any) -> dict[str, Any]:
    """The reference-row fields from an explainer's output: ``ExplainOutput.measurement_fields()`` when the
    output provides it, else the same-named attributes, else the legacy ``meta`` keys."""
    fields_fn = getattr(out, "measurement_fields", None)
    if callable(fields_fn):
        got = fields_fn()
        if isinstance(got, dict):
            return dict(got)
    meta = dict(getattr(out, "meta", {}) or {})
    return {name: getattr(out, name, meta.get(name)) for name in _EXPLAIN_FIELDS}


# --- configuration -> runnable pieces -------------------------------------------------------------------

def _resolve_target(config: CampaignConfig) -> Target:
    target = TARGETS.maybe_get(config.target_id)
    if target is None:
        raise TargetUnavailable(f"unknown target {config.target_id!r}")
    info = target.info()
    if info.status != "available":
        raise TargetUnavailable(info.reason or f"target {config.target_id!r} is {info.status}")
    if info.domain != config.modality:
        raise ValueError(f"config.modality {config.modality!r} does not match the target domain {info.domain!r}")
    target.load()
    if config.defense is not None:
        try:
            defenses = importlib.import_module("redsim.ml.defenses")
        except ImportError as exc:
            raise MLError("a defense was requested but redsim.ml.defenses is not available; "
                          "refusing to run an undefended campaign in its place") from exc
        target = defenses.apply_defense(target, config.defense.id, dict(config.defense.params))
    return target


def _resolve_attacks(config: CampaignConfig, domain: str) -> list[Any]:
    ids = _uniq([i for i in config.attack_ids if i])
    if not ids:
        raise ValueError("CampaignConfig.attack_ids is empty")
    adapters = []
    for aid in ids:
        adapter = ATTACKS.maybe_get(aid)
        if adapter is None:
            raise AttackNotApplicable(f"unknown attack {aid!r}; registered: {ATTACKS.ids()}")
        info = adapter.info()
        if info.family != "evasion":
            raise AttackNotApplicable(
                f"{aid!r} is a {info.family} adapter; the benign control runs automatically and is not "
                "part of the attack set")
        if info.status != "available":
            raise AttackNotApplicable(info.reason or f"attack {aid!r} is {info.status}")
        domains = getattr(adapter, "domains", frozenset({info.domain}))
        if domain not in domains:
            raise AttackNotApplicable(f"attack {aid!r} applies to {sorted(domains)}, not {domain!r}")
        if config.norm == "l2" and not any(s.name == "norm_l2" for s in info.params_schema):
            raise AttackNotApplicable(f"attack {aid!r} supports the L-inf norm only; the campaign norm is 'l2'")
        adapters.append(adapter)
    return adapters


def _attack_params(config: CampaignConfig, adapters: list[Any]) -> dict[str, dict[str, Any]]:
    """``config.attack_params`` per adapter. ``eps`` comes from the grid and ``norm_l2`` from
    ``config.norm``, so a caller that sets either per attack has a configuration error."""
    out: dict[str, dict[str, Any]] = {}
    l2 = config.norm == "l2"
    for a in adapters:
        given = dict(config.attack_params.get(a.id, {}))
        clash = sorted(k for k in ("eps", "norm_l2") if k in given)
        if clash:
            raise ValueError(f"attack_params[{a.id!r}] must not set {clash}: eps comes from eps_grid and the "
                             "norm from config.norm")
        if any(s.name == "norm_l2" for s in a.info().params_schema):
            given["norm_l2"] = l2
        out[a.id] = given
    return out


# --- the run --------------------------------------------------------------------------------------------

def run_campaign(config: CampaignConfig, sink: ArtifactSink, *, explain: bool = True,
                 narrative_settings: Any | None = None, baseline_run_id: str | None = None,
                 parent_run_id: str | None = None) -> CampaignRecord:
    """Run the campaign described by ``config`` and return its record (status ``succeeded``).

    Raises ``TargetUnavailable`` / ``AttackNotApplicable`` / ``ValueError`` for configuration
    problems before any stage runs. Explain and recommend failures never fail the run: they are
    recorded as unavailable (spec 14.7, 16.1). ``baseline_run_id`` (verify runs) and
    ``parent_run_id`` (reruns) are copied onto the provenance and the record when given."""
    started_at = _utcnow()
    run_id = uuid.uuid4().hex
    stages_done: list[str] = []
    limitations: list[str] = []
    nondeterminism: list[str] = [CPU_FLOAT32_NOTE]
    versions: dict[str, str] = library_versions()
    measurements: list[Measurement] = []
    observations: list[Observation] = []
    interpretation: list[Interpretation] = []
    recommendations: list[CandidateRecommendation] = []

    # --- load_target -------------------------------------------------------------------------
    target = _resolve_target(config)
    info = target.info()
    domain = info.domain
    manifest = dict(target.manifest() or {})
    model_sha256 = _manifest_get(manifest, "model_sha256", "weights_sha256", "sha256")
    adapters = _resolve_attacks(config, domain)
    params_by_attack = _attack_params(config, adapters)
    grid = [float(e) for e in config.eps_grid]
    ref = float(config.reference_eps)
    l2 = config.norm == "l2"
    for a in adapters:  # validate bounds before running anything (spec 12.1)
        for e in grid:
            if getattr(a, "takes_eps", True):
                a.resolve_params({**params_by_attack[a.id], "eps": e})
            else:
                a.resolve_params(params_by_attack[a.id])
    shash = settings_hash(config, None if model_sha256 is None else str(model_sha256))
    stages_done.append("load_target")

    # --- sample ------------------------------------------------------------------------------
    sample: Sample = target.sample(config.n_samples, config.seed)
    x = np.asarray(sample.x, dtype=np.float32)
    y = np.asarray(sample.y).astype(int)
    n = int(y.shape[0])
    class_names = list(sample.class_names)
    dataset_name = (_manifest_get(manifest, "dataset", "dataset_id", "dataset_name")
                    or info.metadata.get("dataset") or config.dataset_id)
    dataset_revision = config.dataset_revision or _manifest_get(manifest, "dataset_revision", "revision")
    slice_note = (f"slice: dataset={dataset_name}, split={config.dataset_split}, n_samples={n}, "
                  f"seed={config.seed}, selection=target.sample(n, seed)")
    stages_done.append("sample")

    # --- clean_eval --------------------------------------------------------------------------
    t0 = time.perf_counter()
    proba_clean = np.asarray(target.predict_proba(x), dtype=np.float64)
    y_clean = proba_clean.argmax(axis=1)
    m_clean = measure("m.clean", "clean", y, y_clean, class_names, wall_time_s=time.perf_counter() - t0,
                      notes=[slice_note])
    measurements.append(m_clean)
    acc_clean = m_clean.accuracy
    n_clean_correct = m_clean.n_correct
    stages_done.append("clean_eval")

    # --- attack ------------------------------------------------------------------------------
    x_adv_ref: dict[str, np.ndarray] = {}
    proba_adv_ref: dict[str, np.ndarray] = {}
    flip_matrix: dict[str, dict[str, list[bool]]] = {}
    max_adv_bytes = _max_adv_artifact_bytes()
    tabular = domain == "tabular"

    for adapter in adapters:
        aid = adapter.id
        flip_matrix[aid] = {}
        rows_by_eps: dict[float, Measurement] = {}
        takes_eps = getattr(adapter, "takes_eps", True)
        outputs: list[tuple[float, np.ndarray, dict[str, Any], list[str], float, float | None]] = []

        if takes_eps:
            for e in grid:
                p = adapter.resolve_params({**params_by_attack[aid], "eps": e})
                out = adapter.run(target, x, y, p, config.seed)
                versions.update(out.library_versions)
                outputs.append((e, np.asarray(out.x_adv, dtype=np.float32), dict(out.params), list(out.notes),
                                float(out.wall_time_s), out.queries_mean))
        else:
            # Minimal-norm attack: one run, then success at eps by thresholding the achieved norm
            # (spec 15.1). Examples over budget revert to the clean input for that eps row.
            p = adapter.resolve_params(params_by_attack[aid])
            out = adapter.run(target, x, y, p, config.seed)
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
                outputs.append((e, x_adv_e.astype(np.float32), {**p, "eps": e}, notes, float(out.wall_time_s),
                                out.queries_mean))

        flips_by_eps: dict[float, np.ndarray] = {}
        norms_by_eps: dict[float, np.ndarray] = {}
        for e, x_adv, p, notes, wall, queries in outputs:
            row_notes, nd = _split_notes(notes)
            nondeterminism.extend(nd)
            proba_adv = np.asarray(target.predict_proba(x_adv), dtype=np.float64)
            y_adv = proba_adv.argmax(axis=1)
            if tabular:
                row_notes.append(REALIZABILITY_CAVEAT)
                surrogate = manifest.get("surrogate")
                if surrogate and aid != "hopskipjump":
                    row_notes.append(f"white-box via surrogate transfer: {surrogate}")
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
            blob = _npz_bytes(x_adv, np.asarray(sample.indices), y)
            if len(blob) <= max_adv_bytes:
                sink.put(f"adv_slice/{aid}_{eps_tag(e)}.npz", blob, "application/octet-stream")
            else:
                m.notes.append("full adversarial slice not retained (over REDSIM_ML_MAX_ADV_ARTIFACT_MB)")

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
        stages_done.append(f"attack:{aid}")

    # --- control -----------------------------------------------------------------------------
    x_ctrl_ref: np.ndarray | None = None   # control slice at the reference eps: the explainer's noise floor (13.5)
    control_drop = float(config.scoring.interpretation.control_drop)
    if config.include_control:
        control = ATTACKS.get(CONTROL_ATTACK_ID)
        for e in grid:
            p = control.resolve_params({"eps": e, "norm_l2": l2})
            out = control.run(target, x, y, p, config.seed)
            if math.isclose(e, ref, abs_tol=1e-12):
                x_ctrl_ref = np.asarray(out.x_adv, dtype=np.float32)
            row_notes, nd = _split_notes(out.notes)
            nondeterminism.extend(nd)
            proba_ctrl = np.asarray(target.predict_proba(out.x_adv), dtype=np.float64)
            y_ctrl = proba_ctrl.argmax(axis=1)
            m = measure(f"m.control.noise.{eps_tag(e)}", "control", y, y_ctrl, class_names,
                        attack_id=CONTROL_ATTACK_ID, params={**p, "norm": config.norm}, x_ref=x, x_adv=out.x_adv,
                        y_pred_clean=y_clean, proba=proba_ctrl, wall_time_s=out.wall_time_s,
                        notes=row_notes + ["control rows never create a Finding and never enter the MRI"])
            if acc_clean - m.accuracy > control_drop:
                m.notes.append(f"benign noise alone reduced accuracy from {m_clean.n_correct}/{n} to "
                               f"{m.n_correct}/{n} at eps={e:g}, more than the configured control_drop "
                               f"{control_drop:g}")
                limitations.append(f"The model is noise-sensitive at eps={e:g}: the benign control alone reduced "
                                   f"accuracy by more than {control_drop:g}, so evasion results at this eps are not "
                                   "attributable to adversarial alignment alone.")
            measurements.append(m)
        stages_done.append("control")
    else:
        limitations.append("The benign noise control was disabled for this run (include_control=false); "
                           "gradient-aligned failure cannot be separated from general noise sensitivity.")

    # One RobustnessCurve per attack (spec 12.3), read back from the measurement table so the curve and
    # the rows can never disagree; the control points are the same for every attack.
    curves: list[RobustnessCurve] = robustness_curves(config, measurements)
    for curve in curves:
        sink.put(f"curve/{curve.attack_id}.json", curve.model_dump_json(indent=2).encode("utf-8"),
                 "application/json")
    sink.put("flip_matrix.json", _json_bytes({"attack_ids": [a.id for a in adapters], "eps_grid": grid, "n": n,
                                              "norm": config.norm,
                                              "indices": [int(i) for i in np.asarray(sample.indices)],
                                              "flipped": flip_matrix}), "application/json")

    # --- explain -----------------------------------------------------------------------------
    explain_meta: dict[str, dict[str, Any]] = {}   # attack_id -> explainer meta (noise floor, counts, settings)
    explain_attempted = explain and config.explain_k > 0
    if not explain_attempted:
        why = "explain disabled" if not explain else "explain_k = 0"
        limitations.append(f"Explanations were not computed ({why}); S_expl has no input and the MRI is not "
                           "computed (spec 15.4). No observation was recorded.")
    else:
        module_name = _EXPLAIN_MODULES.get(domain)
        seen_obs: set[str] = set()
        explainer_stated_limitations = False
        for adapter in adapters:
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
                out = _call_supported(mod.explain, target, sample, x_adv_ref[aid], proba_clean, proba_adv_ref[aid],
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
                seen_obs.add(obs.id)
                observations.append(obs)
            fields = _explain_fields(out)
            shift = _as_float(fields.get("expl_shift_mean"))
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
            explain_meta[aid] = meta
            ref_row = next(m for m in measurements if m.id == ref_row_id)
            # The explain stage fills the attribution-shift fields on the reference row (spec 13.5).
            ref_row.expl_shift_n = _as_int(fields.get("expl_shift_n"))
            ref_row.expl_shift_n_excluded = _as_int(fields.get("expl_shift_n_excluded"))
            ref_row.expl_shift_noise_floor = _as_float(fields.get("expl_shift_noise_floor"))
            ref_row.expl_shift_noise_floor_n = _as_int(fields.get("expl_shift_noise_floor_n"))
            if shift is None:
                limitations.append(f"Explainer for {aid!r} returned no explanation-shift aggregate; S_expl has "
                                   "no input and the MRI is not computed.")
            else:
                ref_row.expl_shift_mean = shift
                if ref_row.expl_shift_n is None:
                    ref_row.expl_shift_n = len([o for o in observations if o.id in seen_obs])
                ref_row.notes.append(f"expl_shift_mean = {shift:.4f} over {ref_row.expl_shift_n} explained "
                                     "samples (explain stage, reference budget only)")
        if not explainer_stated_limitations:
            limitations.append(f"Up to {config.explain_k} flipped and {config.explain_k} unflipped samples were "
                               f"explained out of n={n}, at the reference budget eps={ref:g} only.")
        stages_done.append("explain")

    # --- score -------------------------------------------------------------------------------
    score, score_reason = score_run(config=config, measurements=measurements, settings_hash=shash,
                                    computed_at=_utcnow())
    if score_reason:
        limitations.append(score_reason)
    if len(grid) == 1:
        limitations.append(ONE_POINT_GRID_LIMITATION)
    stages_done.append("score")

    # --- interpret / recommend ---------------------------------------------------------------
    standing = _standing(dataset_name, grid, [a.id for a in adapters])
    try:
        rules = importlib.import_module("redsim.ml.recommend.rules")
    except ImportError:
        rules = None
    meta_flat = _flatten_explain_meta(explain_meta, domain, score_reason)
    if rules is None:
        interpretation.append(Interpretation(
            id="i.rules.unavailable",
            statement=("Interpretation and recommendation rules are unavailable (module redsim.ml.recommend.rules "
                       "not present); no rule-based statement and no candidate recommendation was produced."),
            basis=["m.clean"]))
        limitations.append("Rule layer unavailable: no interpretation rules ran and no candidate recommendations "
                           "were produced.")
        stages_done.extend(["interpret", "recommend"])
    else:
        # Base contracts: interpret(measurements, observations, score) and
        # recommend(measurements, observations, score, *, interpretation=...). The extra keywords
        # (thresholds, reference eps, explain meta, ...) are passed only when the rules module declares
        # them. A failing rule layer is recorded, never faked.
        try:
            produced = list(_call_supported(
                rules.interpret, measurements, observations, score,
                explain_meta=meta_flat, reference_eps=ref, scoring_reason=score_reason,
                thresholds=config.scoring.interpretation,
                finding_asr_threshold=config.finding_asr_threshold) or [])
        except Exception as exc:  # noqa: BLE001 - the rule layer must never fail the campaign (14.7)
            produced = []
            interpretation.append(Interpretation(
                id="i.rules.unavailable",
                statement=(f"Interpretation rules failed ({type(exc).__name__}: {exc}); no rule-based statement "
                           "was produced."),
                basis=["m.clean"]))
            limitations.append(f"Rule layer failed during interpretation ({type(exc).__name__}); no candidate "
                               "recommendations were produced.")
            rules = None
        interpretation.extend(_drop_dangling(produced, measurements, observations, interpretation, limitations,
                                             "interpretation"))
        stages_done.append("interpret")
        if rules is not None and config.auto_recommend:
            try:
                produced_recs = list(_call_supported(
                    rules.recommend, measurements, observations, score,
                    interpretation=interpretation, explain_meta=meta_flat, reference_eps=ref, modality=domain,
                    seed=config.seed, thresholds=config.scoring.interpretation,
                    finding_asr_threshold=config.finding_asr_threshold) or [])
            except Exception as exc:  # noqa: BLE001
                produced_recs = []
                limitations.append(f"Rule layer failed during recommendation ({type(exc).__name__}: {exc}); no "
                                   "candidate recommendations were produced.")
            recommendations = _drop_dangling(produced_recs, measurements, observations, interpretation,
                                             limitations, "recommendation")
            stages_done.append("recommend")
        elif rules is not None:
            limitations.append("auto_recommend=false: no candidate recommendations were generated in this run; "
                               "the harden step can create them later under the same run.")

    llm_provenance: dict[str, Any] | None = None
    if recommendations:
        settings = narrative_settings
        if settings is None and config.llm_narrative:
            try:
                from redsim.llm.pythia import PythiaSettings
                settings = PythiaSettings.from_env()
            except Exception:  # noqa: BLE001
                settings = None
            if settings is None:
                limitations.append("An LLM narrative was requested but Pythia is not configured "
                                   "(PYTHIA_BASE_URL / PYTHIA_API_KEY / REDSIM_ML_LLM_MODEL); recommendations "
                                   "carry rule text only (narrative_source='rules').")
        if settings is not None:
            try:
                summary_mod = importlib.import_module("redsim.ml.explain.summary")
                narrative_mod = importlib.import_module("redsim.ml.recommend.narrative")
                summary_text = _call_supported(
                    summary_mod.text_summary, measurements, observations, score,
                    explain_meta=meta_flat, scoring_reason=score_reason, limitations=standing + limitations,
                    norm=config.norm)
                recommendations = list(narrative_mod.add_narrative(recommendations, summary_text, settings))
            except Exception as exc:  # noqa: BLE001 - narrative failure leaves rule output standing (16.1)
                limitations.append(f"LLM narrative not generated ({type(exc).__name__}: {exc}); recommendations "
                                   "carry rule text only (narrative_source='rules').")
            if any(r.narrative_source == "llm" for r in recommendations):
                nondeterminism.append("LLM narrative is nondeterministic (temperature=0.2); prompt and response "
                                      "hashes recorded")
                redacted = getattr(settings, "redacted", None)
                llm_provenance = (dict(redacted()) if callable(redacted)
                                  else {"settings": type(settings).__name__, "redacted": "unavailable"})
        elif not config.llm_narrative:
            limitations.append("No LLM narrative was requested; recommendations carry rule text only.")

    # --- report ------------------------------------------------------------------------------
    finished_at = _utcnow()
    limitations = standing + limitations
    if tabular:
        limitations.append(TABULAR_LIMITATION)
    if config.defense is not None:
        limitations.append(DEFENSE_LIMITATION)
    if score is not None and score.mri is not None:
        limitations.append(MRI_SCOPE_LIMITATION)
    provenance = Provenance(
        redsim_version=_redsim_version(), python=platform.python_version(),
        torch=versions.get("torch", "not installed"), art=versions.get("art", "not installed"),
        shap=_dist_version("shap", "shap"), numpy=versions.get("numpy", np.__version__),
        onnxruntime=versions.get("onnxruntime"), sklearn=versions.get("scikit-learn"),
        xgboost=versions.get("xgboost"),
        model_sha256=None if model_sha256 is None else str(model_sha256),
        dataset=str(dataset_name),
        dataset_revision=None if dataset_revision is None else str(dataset_revision),
        dataset_split=config.dataset_split,
        sample_indices_sha256=_sha256_indices(sample.indices), settings_hash=shash,
        baseline_run_id=baseline_run_id, parent_run_id=parent_run_id,
        defense=_defense_provenance(target, config),
        llm=llm_provenance, thread_env=_thread_env(),
        model_manifest={**manifest, "seed": config.seed, "n_samples": n, "library_versions": versions,
                        "python_executable": sys.executable},
        started_at=started_at, finished_at=finished_at,
        hostname=socket.gethostname(), device=str(manifest.get("device") or "cpu"),
        nondeterminism=_uniq(nondeterminism),
    )
    stages_done.append("report")

    record = CampaignRecord(
        run_id=run_id, status="succeeded", stage="report", stages_done=stages_done, created_at=started_at,
        config=config, target=info, attacks=[a.info() for a in adapters], provenance=provenance,
        measurements=measurements, observations=observations, interpretation=interpretation,
        recommendations=recommendations, score=score, limitations=_uniq(limitations),
        kind="verify" if config.defense is not None else "attack", completed_at=finished_at,
        settings_hash=shash, baseline_run_id=baseline_run_id, parent_run_id=parent_run_id, curve=curves,
        completeness=score.completeness if score is not None else "partial",
        missing=list(score.missing) if score is not None else [score_reason or "score unavailable"],
        score_status=None if score is not None else ScoreStatus(state="unavailable", reason=score_reason),
    )
    sink.put("run_record.json", record.model_dump_json(indent=2).encode("utf-8"), "application/json")
    if score is not None:
        sink.put("score.json", score.model_dump_json(indent=2).encode("utf-8"), "application/json")
    return record


# --- helpers ----------------------------------------------------------------------------------------

def _drop_dangling(items: list[Any], measurements: list[Measurement], observations: list[Observation],
                   interpretation: list[Interpretation], limitations: list[str], what: str) -> list[Any]:
    """Keep only the statements whose citations resolve to recorded ids (spec 14.1). A dropped statement
    is named in ``limitations``: it is a rule-layer defect, not evidence."""
    known = {m.id for m in measurements} | {o.id for o in observations} | {i.id for i in interpretation}
    kept: list[Any] = []
    for item in items:
        cites = list(getattr(item, "basis", None) or getattr(item, "triggered_by", None) or [])
        dangling = [c for c in cites if c not in known]
        if dangling:
            limitations.append(f"Dropped {what} {item.id!r}: it cites ids that were not recorded in this run "
                               f"({', '.join(dangling)}).")
            continue
        kept.append(item)
        known.add(item.id)
    return kept


def _flatten_explain_meta(per_attack_meta: dict[str, dict[str, Any]], domain: str,
                          scoring_reason: str | None) -> dict[str, Any]:
    """One flat dict for the rules / summary layer: ``modality``, the per-attack metas under
    ``per_attack``, and the scalar fields of the attack with the largest ``expl_shift_mean``
    (labelled ``flat_from_attack``) so a single-attack consumer reads the worst case, never an
    invented average. ``unavailable_reason`` carries the MRI-not-computed reason when there is one."""
    flat: dict[str, Any] = {"modality": domain, "per_attack": dict(per_attack_meta)}
    if scoring_reason:
        flat["unavailable_reason"] = scoring_reason
    with_shift = [(aid, m) for aid, m in per_attack_meta.items()
                  if isinstance(m, dict) and isinstance(m.get("expl_shift_mean"), (int, float))]
    if with_shift:
        aid, meta = max(with_shift, key=lambda kv: float(kv[1]["expl_shift_mean"]))
        flat.update({k: v for k, v in meta.items() if k not in ("per_attack", "modality")})
        flat["flat_from_attack"] = aid
    return flat


def _standing(dataset_name: Any, grid: list[float], attack_ids: list[str]) -> list[str]:
    """``schema.standing_limitations`` for this campaign, with the white-box sentence adjusted when
    the black-box HopSkipJump attack ran (the standing text would otherwise be false)."""
    out = standing_limitations(str(dataset_name), grid)
    if "hopskipjump" in attack_ids:
        out = [WHITE_BOX_WITH_BLACK_BOX if s == WHITE_BOX_STANDING else s for s in out]
    return out


__all__ = ["AttackInfo", "CampaignRecord", "MRIRecord", "run_campaign"]
