"""Run one adversarial-ML campaign end to end and assemble its ``RunRecord``.

Pure Python: no Celery, database or HTTP. The worker task calls ``run_campaign``
inside the sandboxed child and persists the returned record; tests call it on the
``TinyTarget`` double with a ``FilesystemSink``.

Stage order follows ``redsim.ml.schema.STAGES``: load_target -> sample -> clean_eval
-> attack (every attack x every eps in the grid) -> control (benign noise at every
eps) -> explain (at the reference budget; optional and tolerant of a missing or
failing explainer) -> interpret -> recommend -> report. The explain and recommend
modules are imported lazily; when one is absent the record says so in an
``Interpretation`` and a limitation rather than pretending (spec 14.7).

Invariants enforced here (spec 14, 15): measurements, observations, interpretation
and candidate recommendations stay in separate lists; every Measurement carries
``n`` and its denominators; a control accompanies the attacks at the same eps;
severity is derived by ``scoring.severity_for``; the MRI is computed only when all
five subscores exist and is otherwise ``None`` with the reason in ``limitations``.
"""

from __future__ import annotations

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
from redsim.ml.eval import conf_gap, eps_tag, measure
from redsim.ml.schema import (
    STAGES,
    STANDING_LIMITATIONS,
    AttackInfo,
    CandidateRecommendation,
    Interpretation,
    Measurement,
    Observation,
    Provenance,
    RunConfig,
    RunRecord,
    Scoring,
)
from redsim.ml.scoring import (
    FINDING_ASR_THRESHOLD,
    eps_bands,
    first_success,
    score_run,
    severity_for,
)
from redsim.ml.targets.base import Sample, Target
from redsim.ml.targets.registry import TARGETS

CONTROL_ATTACK_ID = "noise_control"
NOISE_SENSITIVITY_THRESHOLD = FINDING_ASR_THRESHOLD   # spec 12.4: control alone degrades by more than this
MIN_CLEAN_CORRECT_FOR_FINDING = 10                   # spec 12.6 denominator guard
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
_EXPLAIN_MODULES = {"image": "redsim.ml.explain.shap_image", "tabular": "redsim.ml.explain.shap_tabular"}


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


def _resolve_target(config: RunConfig) -> Target:
    target = TARGETS.maybe_get(config.target_id)
    if target is None:
        raise TargetUnavailable(f"unknown target {config.target_id!r}")
    info = target.info()
    if info.status != "available":
        raise TargetUnavailable(info.reason or f"target {config.target_id!r} is {info.status}")
    target.load()
    if config.defense:
        defense_id = config.defense.get("id") if isinstance(config.defense, dict) else None
        if not defense_id:
            raise ValueError("config.defense must be {id, params}")
        try:
            defenses = importlib.import_module("redsim.ml.defenses")
        except ImportError as exc:
            raise MLError("a defense was requested but redsim.ml.defenses is not available; "
                          "refusing to run an undefended campaign in its place") from exc
        target = defenses.apply_defense(target, defense_id, dict(config.defense.get("params") or {}))
    return target


def _resolve_attacks(config: RunConfig, domain: str) -> list[Any]:
    ids = list(config.attack_ids) or ([config.attack_id] if config.attack_id else [])
    ids = _uniq([i for i in ids if i])
    if not ids:
        raise ValueError("RunConfig needs attack_ids (or attack_id)")
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
        domains = getattr(adapter, "domains", frozenset({info.domain}))
        if domain not in domains:
            raise AttackNotApplicable(f"attack {aid!r} applies to {sorted(domains)}, not {domain!r}")
        adapters.append(adapter)
    return adapters


def _attack_params(config: RunConfig, adapters: list[Any]) -> dict[str, dict[str, Any]]:
    """Split the shared ``config.params`` per adapter by its ParamSpec names. A key no adapter
    accepts is a configuration error (typo protection)."""
    schemas = {a.id: {s.name for s in a.info().params_schema} for a in adapters}
    control_schema = {s.name for s in ATTACKS.get(CONTROL_ATTACK_ID).info().params_schema}
    accepted = set().union(*schemas.values()) | control_schema | {"eps_step"}
    unknown = sorted(k for k in config.params if k not in accepted)
    if unknown:
        raise ValueError(f"config.params has key(s) no attack in the set accepts: {unknown}")
    out: dict[str, dict[str, Any]] = {}
    for a in adapters:
        out[a.id] = {k: v for k, v in config.params.items() if k in schemas[a.id] and k != "eps"}
    return out


def _grid(config: RunConfig) -> list[float]:
    grid = sorted({float(e) for e in config.eps_grid})
    if not grid:
        raise ValueError("eps_grid must not be empty")
    if any(e <= 0 for e in grid):
        raise ValueError("eps_grid members must be positive")
    if not any(math.isclose(float(config.reference_eps), e, abs_tol=1e-12) for e in grid):
        raise ValueError(f"reference_eps {config.reference_eps} must be a member of eps_grid {grid}")
    return grid


def _per_sample_norm(x: np.ndarray, x_adv: np.ndarray, l2: bool) -> np.ndarray:
    d = (np.asarray(x_adv, dtype=np.float64) - np.asarray(x, dtype=np.float64)).reshape(x.shape[0], -1)
    return np.sqrt((d * d).sum(axis=1)) if l2 else np.abs(d).max(axis=1)


def run_campaign(config: RunConfig, sink: ArtifactSink, *, explain: bool = True,
                 narrative_settings: Any | None = None) -> RunRecord:
    """Run the campaign described by ``config`` and return its ``RunRecord`` (status ``succeeded``).

    Raises ``TargetUnavailable`` / ``AttackNotApplicable`` / ``ValueError`` for configuration
    problems before any stage runs. Explain and recommend failures never fail the run: they are
    recorded as unavailable (spec 14.7, 16.1)."""
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
    adapters = _resolve_attacks(config, domain)
    params_by_attack = _attack_params(config, adapters)
    grid = _grid(config)
    ref = float(config.reference_eps)
    eps_small, eps_mid, eps_large = eps_bands(grid, ref)
    for a in adapters:  # validate bounds before running anything (spec 12.1)
        for e in grid:
            if getattr(a, "takes_eps", True):
                a.resolve_params({**params_by_attack[a.id], "eps": e})
            else:
                a.resolve_params(params_by_attack[a.id])
    stages_done.append("load_target")

    # --- sample ------------------------------------------------------------------------------
    sample: Sample = target.sample(config.n_samples, config.seed)
    x = np.asarray(sample.x, dtype=np.float32)
    y = np.asarray(sample.y).astype(int)
    n = int(y.shape[0])
    class_names = list(sample.class_names)
    dataset_name = _manifest_get(manifest, "dataset", "dataset_id", "dataset_name") or info.metadata.get("dataset")
    dataset_split = _manifest_get(manifest, "split", "dataset_split")
    slice_note = (f"slice: dataset={dataset_name}, split={dataset_split}, n_samples={n}, seed={config.seed}, "
                  f"selection=target.sample(n, seed)")
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
    per_attack: dict[str, dict[float, dict[str, Any]]] = {}
    x_adv_ref: dict[str, np.ndarray] = {}
    proba_adv_ref: dict[str, np.ndarray] = {}
    flip_matrix: dict[str, dict[str, list[bool]]] = {}
    curve_points: dict[str, list[dict[str, Any]]] = {}
    atlas: list[str] = []
    max_adv_bytes = _max_adv_artifact_bytes()
    tabular = domain == "tabular"

    for adapter in adapters:
        aid = adapter.id
        ainfo: AttackInfo = adapter.info()
        if ainfo.atlas_technique_id:
            atlas.append(ainfo.atlas_technique_id)
        per_attack[aid] = {}
        flip_matrix[aid] = {}
        curve_points[aid] = []
        rows_by_eps: list[tuple[float, Measurement]] = []
        takes_eps = getattr(adapter, "takes_eps", True)
        outputs: list[tuple[float, np.ndarray, dict[str, Any], list[str], float]] = []

        if takes_eps:
            for e in grid:
                p = adapter.resolve_params({**params_by_attack[aid], "eps": e})
                out = adapter.run(target, x, y, p, config.seed)
                versions.update(out.library_versions)
                outputs.append((e, np.asarray(out.x_adv, dtype=np.float32), dict(out.params), list(out.notes),
                                float(out.wall_time_s)))
        else:
            # Minimal-norm attack: one run, then success at eps by thresholding the achieved norm
            # (spec 15.1). Examples over budget revert to the clean input for that eps row.
            p = adapter.resolve_params(params_by_attack[aid])
            out = adapter.run(target, x, y, p, config.seed)
            versions.update(out.library_versions)
            l2 = bool(p.get("norm_l2", False))
            norms = _per_sample_norm(x, out.x_adv, l2)
            x_adv_full = np.asarray(out.x_adv, dtype=np.float32)
            for e in grid:
                within = norms <= e + 1e-9
                x_adv_e = np.where(within.reshape((-1,) + (1,) * (x.ndim - 1)), x_adv_full, x)
                notes = list(out.notes) + [
                    (f"thresholded at eps={e:g}: {int(within.sum())}/{n} adversarial examples within budget; "
                     "the rest revert to the clean input for this row"),
                    "wall_time_s is the single attack run shared by every eps row"]
                outputs.append((e, x_adv_e.astype(np.float32), {**p, "eps": e}, notes, float(out.wall_time_s)))

        for e, x_adv, p, notes, wall in outputs:
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
                        params={**p, "eps": e}, x_ref=x, x_adv=x_adv, y_pred_clean=y_clean,
                        wall_time_s=wall, notes=row_notes)
            flipped = (y_clean == y) & (y_adv != y)
            asr = (int(flipped.sum()) / n_clean_correct) if n_clean_correct > 0 else None
            l2_norm = bool(p.get("norm_l2", False))
            pert = m.l2_norm_mean if l2_norm else m.linf_norm_mean
            cg = conf_gap(proba_adv, y)
            m.notes.append(f"conf_gap_mean = {cg:.4f} over n={n} (mean of max(0, max_j!=y p_j - p_y) on x_adv)")
            per_attack[aid][e] = {"acc_adv": m.accuracy, "asr": asr, "conf_gap": cg, "expl_shift": None,
                                  "pert": pert, "n": n, "n_correct": m.n_correct,
                                  "n_flipped_from_clean": int(flipped.sum()), "n_clean_correct": n_clean_correct}
            flip_matrix[aid][eps_tag(e)] = [bool(v) for v in flipped]
            curve_points[aid].append({"eps": e, "n": n, "n_correct": m.n_correct, "accuracy": m.accuracy,
                                      "n_clean_correct": n_clean_correct,
                                      "n_flipped_from_clean": int(flipped.sum()), "asr": asr,
                                      "linf_norm_mean": m.linf_norm_mean, "l2_norm_mean": m.l2_norm_mean})
            rows_by_eps.append((e, m))
            measurements.append(m)
            if math.isclose(e, ref, abs_tol=1e-12):
                x_adv_ref[aid] = x_adv
                proba_adv_ref[aid] = proba_adv
            blob = _npz_bytes(x_adv, np.asarray(sample.indices), y)
            if len(blob) <= max_adv_bytes:
                sink.put(f"adv_slice/{aid}_{eps_tag(e)}.npz", blob, "application/octet-stream")
            else:
                m.notes.append("full adversarial slice not retained (over REDSIM_ML_MAX_ADV_ARTIFACT_MB)")

        # pert at first success (spec 12.5): per sample, the norm at the smallest eps where it flips.
        first_norms: list[float] = []
        norm_l2_attack = bool(outputs[0][2].get("norm_l2", False)) if outputs else False
        per_eps_norms = {e: _per_sample_norm(x, x_adv, norm_l2_attack) for e, x_adv, *_ in outputs}
        for i in range(n):
            for e in grid:
                if flip_matrix[aid][eps_tag(e)][i]:
                    first_norms.append(float(per_eps_norms[e][i]))
                    break
        pert_first = (sum(first_norms) / len(first_norms)) if first_norms else None

        # Derived severity (spec 15.5) with the denominator guard (spec 12.6).
        fs_eps, fs_asr = first_success(per_attack[aid], FINDING_ASR_THRESHOLD)
        severity = severity_for(aid, fs_eps, fs_asr, eps_small, eps_mid, eps_large)
        for e, m in rows_by_eps:
            if math.isclose(e, ref, abs_tol=1e-12):
                m.notes.append(
                    f"pert_first_success_mean = {pert_first:.6g} over {len(first_norms)} flipped samples"
                    if pert_first is not None else "pert_first_success_mean not computed (no sample flipped)")
            if n_clean_correct < MIN_CLEAN_CORRECT_FOR_FINDING:
                m.notes.append(f"denominator too small for a finding (n_clean_correct={n_clean_correct} < "
                               f"{MIN_CLEAN_CORRECT_FOR_FINDING}); severity not derived")
                continue
            row_asr = per_attack[aid][e]["asr"]
            if severity is not None and row_asr is not None and row_asr >= FINDING_ASR_THRESHOLD:
                m.severity = severity
                m.notes.append(f"severity {severity!r} derived per spec 15.5 from first success at eps={fs_eps:g} "
                               f"with ASR {fs_asr:.3f} (eps_small={eps_small:g}, eps_mid={eps_mid:g}, "
                               f"eps_large={eps_large:g}); threshold {FINDING_ASR_THRESHOLD}")

        sink.put(f"curve/{aid}.json", _json_bytes({
            "attack_id": aid, "norm": "L2" if norm_l2_attack else "Linf", "eps_grid": grid, "reference_eps": ref,
            "clean": {"n": n, "n_correct": n_clean_correct, "accuracy": acc_clean},
            "points": curve_points[aid], "control": [],
            "pert_first_success_mean": pert_first, "pert_first_success_n": len(first_norms),
        }), "application/json")
    stages_done.append("attack")

    # --- control -----------------------------------------------------------------------------
    control_rows: dict[float, Measurement] = {}
    x_ctrl_ref: np.ndarray | None = None   # control slice at the reference eps: the explainer's noise floor (13.5)
    if config.include_control:
        control = ATTACKS.get(CONTROL_ATTACK_ID)
        norm_l2 = bool(config.params.get("norm_l2", False))
        for e in grid:
            p = control.resolve_params({"eps": e, "norm_l2": norm_l2})
            out = control.run(target, x, y, p, config.seed)
            if math.isclose(e, ref, abs_tol=1e-12):
                x_ctrl_ref = np.asarray(out.x_adv, dtype=np.float32)
            row_notes, nd = _split_notes(out.notes)
            nondeterminism.extend(nd)
            proba_ctrl = np.asarray(target.predict_proba(out.x_adv), dtype=np.float64)
            y_ctrl = proba_ctrl.argmax(axis=1)
            m = measure(f"m.control.noise.{eps_tag(e)}", "control", y, y_ctrl, class_names,
                        attack_id=CONTROL_ATTACK_ID, params=dict(p), x_ref=x, x_adv=out.x_adv,
                        y_pred_clean=y_clean, wall_time_s=out.wall_time_s,
                        notes=row_notes + ["control rows never create a Finding and never enter the MRI"])
            measurements.append(m)
            control_rows[e] = m
            if acc_clean - m.accuracy > NOISE_SENSITIVITY_THRESHOLD:
                interpretation.append(Interpretation(
                    id=f"i.control.{eps_tag(e)}",
                    statement=(f"The model is noise-sensitive at eps={e:g}: benign uniform noise alone reduced "
                               f"accuracy from {m_clean.n_correct}/{n} to {m.n_correct}/{n} (more than "
                               f"{NOISE_SENSITIVITY_THRESHOLD:g}); evasion results at this eps are not "
                               "attributable to adversarial alignment."),
                    basis=["m.clean", m.id]))
        # Append control points to each curve artifact for display beside the attack curve.
        for aid in per_attack:
            sink.put(f"curve/{aid}.json", _json_bytes({
                "attack_id": aid, "eps_grid": grid, "reference_eps": ref,
                "clean": {"n": n, "n_correct": n_clean_correct, "accuracy": acc_clean},
                "points": curve_points[aid],
                "control": [{"eps": e, "n": control_rows[e].n, "n_correct": control_rows[e].n_correct,
                             "accuracy": control_rows[e].accuracy} for e in grid],
            }), "application/json")
        stages_done.append("control")
    else:
        limitations.append("The benign noise control was disabled for this run (include_control=false); "
                           "gradient-aligned failure cannot be separated from general noise sensitivity.")
    sink.put("flip_matrix.json", _json_bytes({"attack_ids": sorted(per_attack), "eps_grid": grid, "n": n,
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
            shift = getattr(out, "expl_shift_mean", None)
            per_attack[aid][ref]["expl_shift"] = None if shift is None else float(shift)
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
            if shift is None:
                limitations.append(f"Explainer for {aid!r} returned no explanation-shift aggregate; S_expl has "
                                   "no input and the MRI is not computed.")
            else:
                ref_row = next(m for m in measurements if m.id == ref_row_id)
                ref_row.notes.append(f"expl_shift_mean = {float(shift):.4f} over "
                                     f"{meta.get('expl_shift_n', 'k')} explained samples (explain stage)")
        if not explainer_stated_limitations:
            limitations.append(f"Up to {config.explain_k} flipped and {config.explain_k} unflipped samples were "
                               f"explained out of n={n}, at the reference budget eps={ref:g} only.")
        stages_done.append("explain")

    # --- score -------------------------------------------------------------------------------
    basis = ["m.clean"] + [m.id for m in measurements if m.family == "evasion"]
    scoring, reason = score_run(modality=domain, acc_clean=acc_clean,
                                per_attack={a: {e: dict(v) for e, v in rows.items()} for a, rows in per_attack.items()},
                                eps_grid=grid, reference_eps=ref, weights=config.scoring_weights,
                                basis_measurements=basis)
    if scoring is None:
        limitations.append(reason or "MRI not computed.")

    # --- interpret / recommend ---------------------------------------------------------------
    standing = _standing_limitations(dataset_name, grid, [a.id for a in adapters])
    try:
        rules = importlib.import_module("redsim.ml.recommend.rules")
    except ImportError:
        rules = None
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
        # Base contracts: interpret(measurements, observations, scoring) and
        # recommend(measurements, observations, interpretation, scoring). The extra keywords are passed
        # only when the rules module declares them.
        meta_flat = _flatten_explain_meta(explain_meta, domain, reason)
        interpretation.extend(list(_call_supported(
            rules.interpret, measurements, observations, scoring,
            explain_meta=meta_flat, reference_eps=ref, scoring_reason=reason) or []))
        stages_done.append("interpret")
        recommendations = list(_call_supported(
            rules.recommend, measurements, observations, interpretation, scoring,
            explain_meta=meta_flat, reference_eps=ref, modality=domain, seed=config.seed) or [])
        stages_done.append("recommend")
        settings = narrative_settings
        if settings is None and config.llm_narrative:
            try:
                from redsim.llm.pythia import PythiaSettings
                settings = PythiaSettings.from_env()
            except Exception:  # noqa: BLE001
                settings = None
            if settings is None:
                limitations.append("An LLM narrative was requested but Pythia is not configured "
                                   "(PYTHIA_BASE_URL / PYTHIA_API_KEY / REDSIM_LLM_MODEL); recommendations "
                                   "carry rule text only (narrative_source='rules').")
        if settings is not None and recommendations:
            try:
                summary_mod = importlib.import_module("redsim.ml.explain.summary")
                narrative_mod = importlib.import_module("redsim.ml.recommend.narrative")
                summary_text = _call_supported(
                    summary_mod.text_summary, measurements, observations, scoring,
                    explain_meta=meta_flat, scoring_reason=reason, limitations=standing + limitations)
                recommendations = list(narrative_mod.add_narrative(recommendations, summary_text, settings))
            except Exception as exc:  # noqa: BLE001 - narrative failure leaves rule output standing (16.1)
                limitations.append(f"LLM narrative not generated ({type(exc).__name__}: {exc}); recommendations "
                                   "carry rule text only (narrative_source='rules').")
            if any(r.narrative_source == "llm" for r in recommendations):
                nondeterminism.append("LLM narrative is nondeterministic (temperature=0.2); prompt and response "
                                      "hashes recorded")
        elif settings is None and not config.llm_narrative:
            limitations.append("No LLM narrative was requested; recommendations carry rule text only.")

    # --- report ------------------------------------------------------------------------------
    finished_at = _utcnow()
    limitations = standing + limitations
    if tabular:
        limitations.append(TABULAR_LIMITATION)
    if config.defense:
        limitations.append(DEFENSE_LIMITATION)
    if scoring is not None:
        limitations.append("The MRI summarises this campaign only (one model, one modality, the declared attack "
                           "set, eps grid and reference budget); it is not comparable across campaigns with "
                           "different settings and is never aggregated across modalities.")
    provenance = Provenance(
        redsim_version=_redsim_version(), python=platform.python_version(),
        torch=versions.get("torch", "not installed"), art=versions.get("art", "not installed"),
        shap=_dist_version("shap", "shap"), numpy=versions.get("numpy", np.__version__),
        model_sha256=_manifest_get(manifest, "model_sha256", "weights_sha256", "sha256"),
        dataset=None if dataset_name is None else str(dataset_name),
        dataset_split=None if dataset_split is None else str(dataset_split),
        model_manifest=manifest, started_at=started_at, finished_at=finished_at,
        hostname=socket.gethostname(), device=str(manifest.get("device") or "cpu"),
        nondeterminism=_uniq(nondeterminism),
    )
    provenance.model_manifest = {**manifest, "seed": config.seed, "n_samples": n,
                                 "sample_indices_sha256": _sha256_indices(sample.indices),
                                 "library_versions": versions, "python_executable": sys.executable}
    stages_done.append("report")
    ordered_stages = [s for s in STAGES if s in stages_done]

    record = RunRecord(
        run_id=run_id, status="succeeded", stage="report", stages_done=ordered_stages, created_at=started_at,
        config=config, target=info, attack=adapters[0].info() if len(adapters) == 1 else None,
        provenance=provenance, measurements=measurements, observations=observations,
        interpretation=interpretation, recommendations=recommendations, scoring=scoring,
        atlas_coverage=sorted(set(atlas)), limitations=_uniq(limitations),
    )
    sink.put("run_record.json", record.model_dump_json(indent=2).encode("utf-8"), "application/json")
    return record


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


def _sha256_indices(indices: Any) -> str:
    import hashlib
    arr = np.asarray(indices).astype(np.int64)
    return hashlib.sha256(arr.tobytes()).hexdigest()


def _standing_limitations(dataset_name: Any, grid: list[float], attack_ids: list[str]) -> list[str]:
    """``STANDING_LIMITATIONS`` with the two conditional substitutions of spec 14.5 and the
    black-box adjustment when HopSkipJump ran."""
    out: list[str] = []
    grid_txt = "[" + ", ".join(f"{e:g}" for e in grid) + "]"
    for sentence in STANDING_LIMITATIONS:
        if sentence.startswith("CIFAR-10 is a benign public benchmark") and dataset_name:
            out.append(f"{dataset_name} is an open, unclassified public benchmark; it is not a proxy for any "
                       "operational domain, sensor, or deployment condition.")
        elif sentence.startswith("Results come from a single seed") and len(grid) > 1:
            out.append(f"Results come from a single seed; the eps grid was {grid_txt}.")
        elif sentence.startswith("White-box gradient attacks assume full model access") and "hopskipjump" in attack_ids:
            out.append("White-box gradient attacks assume full model access; the black-box attack hopskipjump "
                       "was evaluated with label-only query access; physical-world attacks were not evaluated.")
        else:
            out.append(sentence)
    return out


__all__ = ["Scoring", "run_campaign"]
