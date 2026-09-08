"""SHAP explanations for tabular targets (spec sections 13.2-13.6, tabular rows).

``shap.TreeExplainer`` (``tree_path_dependent``, exact and deterministic) on
the real tree model, otherwise ``shap.KernelExplainer`` over ``predict_proba``
with a small seeded background. Attributions of the clean-predicted class
are compared clean vs adversarial (``expl_shift``, recorded per sample on the
``Observation``). The per-sample top features are the ``Observation``'s
``top_features_clean`` / ``top_features_adv`` (feature identifiers ranked by
|SHAP|) and are also written as JSON. Campaign-level bar and beeswarm plots
share the feature order (fixed by the clean ranking) and the x-axis range. The
returned ``ExplainOutput`` carries the reference-row ``Measurement`` fields
(``expl_shift_mean`` with its ``n`` and exclusions, the benign-noise floor with
its ``n``) for the campaign to write onto the evasion measurement (spec 13.5).

Only numeric feature vectors and the manifest's feature identifiers are ever
written. No raw URL string, and no other source row text, enters an artifact,
an observation, or the summary (spec 11.3.3 / 13.7). A feature identifier that
is itself URL-shaped is refused.
"""

from __future__ import annotations

import io
import json
import logging
import math
import re
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import numpy as np

from redsim.ml.artifacts import ArtifactSink
from redsim.ml.errors import ExplainUnavailable
from redsim.ml.explain.base import SHAP_LIMITATION, ExplainOutput
from redsim.ml.explain.stability import aggregate, expl_shift, is_defined
from redsim.ml.schema import Observation
from redsim.ml.targets.base import Sample, Target

if TYPE_CHECKING:
    from matplotlib.figure import Figure

logger = logging.getLogger(__name__)

TOP_K = 5
TABULAR_METRIC_NOTE = ("tabular target: no centre-mass analogue (ratios are None). The per-sample evidence is the "
                       "ranking of feature identifiers by |SHAP| for the clean-predicted class, clean vs adversarial "
                       "(top_features_clean / top_features_adv), and the per-sample expl_shift.")
_URL_SHAPED = re.compile(r"(?i)(?:[a-z][a-z0-9+.-]*://|^www\.)")


# --------------------------------------------------------------------------- model resolution

def _resolve_model(target: Target) -> Any | None:
    """Find the underlying estimator: ``target.sklearn_model()``, ``target.model``, or the ART wrapper's ``.model``."""
    getter = getattr(target, "sklearn_model", None)
    if callable(getter):
        try:
            m = getter()
            if m is not None:
                return m
        except Exception as exc:  # noqa: BLE001 -- fall through to the other accessors
            logger.debug("sklearn_model() failed: %s", type(exc).__name__)
    m = getattr(target, "model", None)
    if m is not None and not callable(m):
        return m
    try:
        clf = target.art_classifier()
    except Exception:  # noqa: BLE001
        return None
    for attr in ("model", "_model"):
        inner = getattr(clf, attr, None)
        if inner is not None:
            return inner
    return None


def _select_vec(sv: Any, j: int, cls: int, n_classes: int) -> np.ndarray:
    """Per-sample feature attribution vector for ``cls`` from shap's list / class-last / single-output forms."""
    if isinstance(sv, (list, tuple)):
        if len(sv) == 1:
            v = np.asarray(sv[0][j], dtype=np.float64)
            return v if cls == 1 or n_classes != 2 else -v
        return np.asarray(sv[cls][j], dtype=np.float64)
    arr = np.asarray(sv, dtype=np.float64)
    if arr.ndim == 3:
        return np.asarray(arr[j, :, cls])
    v = np.asarray(arr[j])  # single-output (binary log-odds toward class 1)
    return v if cls == 1 or n_classes != 2 else -v


def _attributions(shap: Any, model: Any, predict_proba: Callable[[np.ndarray], np.ndarray],
                  background: np.ndarray, batches: list[np.ndarray], nsamples: int,
                  seed: int) -> tuple[str, list[Any], list[str]]:
    errors: list[str] = []
    if model is not None:
        try:
            explainer = shap.TreeExplainer(model, feature_perturbation="tree_path_dependent")
            outs = [explainer.shap_values(xb) for xb in batches]
            return "TreeExplainer", outs, errors
        except Exception as exc:  # noqa: BLE001 -- shap raises bare exceptions for unsupported models
            errors.append(f"TreeExplainer: {type(exc).__name__}: {str(exc)[:160]}")
    try:
        state = np.random.get_state()
        np.random.seed(seed)
        try:
            explainer = shap.KernelExplainer(predict_proba, background)
            outs = [explainer.shap_values(xb, nsamples=nsamples, silent=True) for xb in batches]
        finally:
            np.random.set_state(state)
        return "KernelExplainer", outs, errors
    except Exception as exc:  # noqa: BLE001
        errors.append(f"KernelExplainer: {type(exc).__name__}: {str(exc)[:160]}")
    raise ExplainUnavailable("SHAP could not explain this tabular model: " + " | ".join(errors))


# --------------------------------------------------------------------------- plots (Figure + Agg, no pyplot state)

def _new_fig(width: float, height: float) -> Figure:
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    fig = Figure(figsize=(width, height), dpi=100)
    FigureCanvasAgg(fig)
    return fig


def _png(fig: Figure) -> bytes:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=100, bbox_inches="tight")
    return buf.getvalue()


def render_bar(values: np.ndarray, names: list[str], xmax: float, title: str) -> bytes:
    """Mean |SHAP| per feature, rows in the given (fixed) order, shared x range."""
    mean_abs = np.abs(values).mean(axis=0)
    fig = _new_fig(5.0, 0.28 * len(names) + 1.2)
    ax = fig.add_subplot(111)
    y = np.arange(len(names))
    ax.barh(y, mean_abs, color="#1f77b4")
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=7)
    ax.invert_yaxis()
    ax.set_xlim(0.0, max(float(xmax), 1e-12))
    ax.set_xlabel("mean |SHAP| (clean-predicted class)", fontsize=8)
    ax.set_title(title, fontsize=9)
    return _png(fig)


def render_beeswarm(values: np.ndarray, features: np.ndarray, names: list[str], xmax: float, title: str,
                    seed: int) -> bytes:
    """Beeswarm-style strip plot: one row per feature, x = SHAP value, colour = scaled feature value."""
    rng = np.random.default_rng(seed)
    fig = _new_fig(5.0, 0.28 * len(names) + 1.2)
    ax = fig.add_subplot(111)
    fmin = features.min(axis=0)
    frange = np.where((features.max(axis=0) - fmin) > 1e-12, features.max(axis=0) - fmin, 1.0)
    scaled = (features - fmin) / frange
    for row in range(len(names)):
        jitter = rng.uniform(-0.3, 0.3, size=values.shape[0])
        ax.scatter(values[:, row], np.full(values.shape[0], row) + jitter, c=scaled[:, row], cmap="coolwarm",
                   vmin=0.0, vmax=1.0, s=14, alpha=0.85, linewidths=0)
    ax.axvline(0.0, color="#888", linewidth=0.8)
    ax.set_yticks(np.arange(len(names)))
    ax.set_yticklabels(names, fontsize=7)
    ax.invert_yaxis()
    v = max(float(xmax), 1e-12)
    ax.set_xlim(-v, v)
    ax.set_xlabel("SHAP value (clean-predicted class), colour = scaled feature value", fontsize=8)
    ax.set_title(title, fontsize=9)
    return _png(fig)


def render_pair(v_clean: np.ndarray, v_adv: np.ndarray, names: list[str], title: str) -> bytes:
    """Per-sample grouped bars: SHAP clean vs adversarial per feature, same class."""
    fig = _new_fig(5.0, 0.3 * len(names) + 1.2)
    ax = fig.add_subplot(111)
    y = np.arange(len(names))
    ax.barh(y - 0.2, v_clean, height=0.4, color="#1f77b4", label="clean")
    ax.barh(y + 0.2, v_adv, height=0.4, color="#d62728", label="adversarial")
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=7)
    ax.invert_yaxis()
    ax.axvline(0.0, color="#888", linewidth=0.8)
    ax.legend(fontsize=7, loc="lower right")
    ax.set_title(title, fontsize=9)
    return _png(fig)


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (np.floating, float)):
        f = float(obj)
        return None if math.isnan(f) else f
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.bool_):
        return bool(obj)
    if isinstance(obj, np.ndarray):
        return _jsonable(obj.tolist())
    return obj


def _check_identifiers(names: list[str]) -> None:
    """Feature identifiers are manifest names, never source row text. URL-shaped strings are refused (not echoed)."""
    bad = [i for i, nm in enumerate(names) if _URL_SHAPED.search(nm)]
    if bad:
        raise ExplainUnavailable(f"{len(bad)} feature identifier(s) at positions {bad[:5]} look like URL strings. The "
                                 "tabular explainer records manifest feature identifiers only")


def _feature_names(target: Target, feature_names: list[str] | None, n_features: int) -> tuple[list[str], str]:
    """Resolve feature identifiers: explicit list, else the target manifest, else generic ``feature_<i>``."""
    names: list[str] | None = None
    source = "generic (no feature identifiers supplied)"
    if feature_names is not None:
        names, source = [str(f) for f in feature_names], "argument"
    else:
        try:
            manifest = target.manifest() or {}
        except Exception:  # noqa: BLE001 -- a manifest failure must not block the explanation
            manifest = {}
        for key in ("feature_names", "features"):
            feats = manifest.get(key)
            if isinstance(feats, list) and len(feats) == n_features:
                names = [str(f.get("name", i)) if isinstance(f, dict) else str(f) for i, f in enumerate(feats)]
                source = f"manifest.{key}"
                break
    if names is None:
        names = [f"feature_{i:02d}" for i in range(n_features)]
    _check_identifiers(names)
    return names, source


def _ranking(v: np.ndarray, names: list[str], top: int) -> list[str]:
    order = np.argsort(-np.abs(v), kind="stable")
    return [names[int(i)] for i in order[:top]]


# --------------------------------------------------------------------------- entry point

def explain(target: Target, sample: Sample, x_adv: np.ndarray, proba_clean: np.ndarray,
            proba_adv: np.ndarray, sink: ArtifactSink, *, k: int, seed: int, feature_names: list[str] | None,
            x_ctrl: np.ndarray | None = None, nsamples: int = 200, background_size: int = 100) -> ExplainOutput:
    """Explain the first ``k`` flipped and first ``k`` unflipped rows at the reference budget.

    ``feature_names`` are the manifest's feature identifiers. When ``None`` the target manifest's
    ``feature_names`` / ``features`` entry is used, else generic ``feature_<i>`` identifiers, and
    ``meta["feature_names_source"]`` says which.
    """
    if k <= 0:
        raise ExplainUnavailable("explain_k = 0: no samples were requested for explanation, so S_expl has no input")

    import shap  # heavy import stays local

    t0 = time.perf_counter()
    x = np.ascontiguousarray(np.asarray(sample.x, dtype=np.float32))
    xa = np.ascontiguousarray(np.asarray(x_adv, dtype=np.float32))
    if x.ndim != 2:
        raise ExplainUnavailable(f"tabular explainer expects a 2-D feature matrix, got shape {x.shape}")
    if x.shape != xa.shape:
        raise ExplainUnavailable(f"clean/adversarial shapes differ: {x.shape} vs {xa.shape}")
    names, names_source = _feature_names(target, feature_names, x.shape[1])
    if len(names) != x.shape[1]:
        raise ExplainUnavailable(f"{len(names)} feature names for {x.shape[1]} feature columns")
    n, n_features = x.shape
    pc = np.asarray(proba_clean)
    pa = np.asarray(proba_adv)
    n_classes = int(pc.shape[1])
    pred_clean = pc.argmax(axis=1)
    pred_adv = pa.argmax(axis=1)
    flipped = pred_clean != pred_adv
    class_names = list(sample.class_names)

    flipped_idx = np.flatnonzero(flipped)[:k]
    unflipped_idx = np.flatnonzero(~flipped)[:k]
    explained = np.sort(np.concatenate([flipped_idx, unflipped_idx])).astype(int)
    if explained.size == 0:
        raise ExplainUnavailable("empty evaluation slice: nothing to explain")

    rng = np.random.default_rng(seed)
    pool = np.setdiff1d(np.arange(n), explained)
    if pool.size == 0:
        pool = np.arange(n)
    bg_idx = np.sort(rng.choice(pool, size=min(background_size, pool.size), replace=False))

    batches = [x[explained], xa[explained]]
    xc = None
    if x_ctrl is not None:
        xc = np.ascontiguousarray(np.asarray(x_ctrl, dtype=np.float32))
        if xc.shape != x.shape:
            raise ExplainUnavailable(f"control input shape {xc.shape} differs from clean {x.shape}")
        batches.append(xc[explained])

    model = _resolve_model(target)
    explainer_name, outs, tried = _attributions(shap, model, target.predict_proba, x[bg_idx], batches, nsamples, seed)
    sv_clean, sv_adv = outs[0], outs[1]
    sv_ctrl = outs[2] if xc is not None else None
    deterministic = explainer_name == "TreeExplainer"
    effective_nsamples: int | None = None if deterministic else nsamples
    effective_bg = 0 if deterministic else int(bg_idx.size)

    m = explained.size
    v_clean_all = np.zeros((m, n_features))
    v_adv_all = np.zeros((m, n_features))
    observations: list[Observation] = []
    shifts: list[float] = []
    noise_shifts: list[float] = []
    per_sample: dict[str, dict[str, Any]] = {}
    top3_changed_flags: list[bool] = []

    for j, i in enumerate(explained.tolist()):
        c = int(pred_clean[i])
        a = int(pred_adv[i])
        is_flipped = bool(flipped[i])
        v_clean = _select_vec(sv_clean, j, c, n_classes)
        v_adv = _select_vec(sv_adv, j, c, n_classes)
        v_ctrl = _select_vec(sv_ctrl, j, c, n_classes) if sv_ctrl is not None else None
        v_clean_all[j] = v_clean
        v_adv_all[j] = v_adv
        shift = expl_shift(v_clean, v_adv)
        shifts.append(shift)
        noise = expl_shift(v_clean, v_ctrl) if v_ctrl is not None else float("nan")
        if v_ctrl is not None:
            noise_shifts.append(noise)

        top_clean = _ranking(v_clean, names, TOP_K)
        top_adv = _ranking(v_adv, names, TOP_K)
        top3_changed = set(top_clean[:3]) != set(top_adv[:3])
        if is_flipped:
            top3_changed_flags.append(top3_changed)

        name_c = class_names[c] if c < len(class_names) else str(c)
        name_a = class_names[a] if a < len(class_names) else str(a)
        yi = int(sample.y[i])
        name_t = class_names[yi] if yi < len(class_names) else str(yi)
        prefix = f"obs_{i:03d}"
        obs_id = f"o.{i:03d}"

        feature_rows = [{
            "name": names[f], "value_clean": float(x[i, f]), "value_adv": float(xa[i, f]),
            "delta": float(xa[i, f] - x[i, f]), "shap_clean": float(v_clean[f]), "shap_adv": float(v_adv[f]),
        } for f in range(n_features)]
        top_json = {
            "observation_id": obs_id, "sample_index": i, "source_index": int(sample.indices[i]),
            "explainer": explainer_name, "shap_version": shap.__version__, "class_explained": name_c,
            "class_explained_index": c, "adv_pred_class": name_a, "flipped": is_flipped,
            "top_features_clean": top_clean, "top_features_adv": top_adv, "top3_changed": top3_changed,
            "expl_shift": None if not is_defined(shift) else shift,
            "expl_shift_noise": None if not is_defined(noise) else noise,
            "nsamples": effective_nsamples, "background_size": effective_bg, "seed": seed,
            "features": feature_rows,
            "note": "feature identifiers and numeric values only, no source row text",
        }
        artifacts: dict[str, str] = {}
        artifacts["top_features.json"] = sink.put(f"{prefix}/top_features.json",
                                                  json.dumps(_jsonable(top_json), indent=1).encode(),
                                                  "application/json")
        order = np.argsort(-np.abs(v_clean), kind="stable")
        artifacts["shap_pair.png"] = sink.put(
            f"{prefix}/shap_pair.png",
            render_pair(v_clean[order], v_adv[order], [names[int(o)] for o in order],
                        f"{obs_id} SHAP clean vs adversarial | class={name_c}"), "image/png")
        npz_buf = io.BytesIO()
        arrays: dict[str, Any] = {"clean": v_clean.astype(np.float32), "adv": v_adv.astype(np.float32),
                                         "indices": np.asarray([i, int(sample.indices[i])], dtype=np.int64)}
        if v_ctrl is not None:
            arrays["control"] = v_ctrl.astype(np.float32)
        np.savez_compressed(npz_buf, **arrays)
        artifacts["shap_values.npz"] = sink.put(f"{prefix}/shap_values.npz", npz_buf.getvalue(),
                                                "application/octet-stream")
        hashes = {nm: sink.sha256(p) for nm, p in artifacts.items()}
        observations.append(Observation(
            id=obs_id, sample_index=i, true_label=name_t, pred_clean=name_c, pred_adv=name_a, flipped=is_flipped,
            confidence_clean=float(pc[i].max()), confidence_adv=float(pa[i].max()),
            artifacts=artifacts, artifact_sha256=hashes,
            center_mass_ratio_clean=None, center_mass_ratio_adv=None,
            expl_shift=top_json["expl_shift"],
            top_features_clean=top_clean, top_features_adv=top_adv,   # feature identifiers only, never row text
            metric_note=TABULAR_METRIC_NOTE,
        ))
        per_sample[obs_id] = {
            "flipped": is_flipped, "expl_shift": top_json["expl_shift"], "expl_shift_noise": top_json["expl_shift_noise"],
            "top_features_clean": top_clean, "top_features_adv": top_adv, "top3_changed": top3_changed,
        }

    # campaign-level plots: feature order fixed by the clean ranking, shared x range
    mean_abs_clean = np.abs(v_clean_all).mean(axis=0)
    mean_abs_adv = np.abs(v_adv_all).mean(axis=0)
    order = np.argsort(-mean_abs_clean, kind="stable")
    ordered_names = [names[int(o)] for o in order]
    bar_xmax = float(max(mean_abs_clean.max(), mean_abs_adv.max(), 1e-12)) * 1.1
    swarm_xmax = float(max(np.abs(v_clean_all).max(), np.abs(v_adv_all).max(), 1e-12)) * 1.1
    x_e = x[explained].astype(np.float64)
    xa_e = xa[explained].astype(np.float64)
    campaign_artifacts = {
        "shap_bar_clean.png": sink.put("shap_bar_clean.png", render_bar(
            v_clean_all[:, order], ordered_names, bar_xmax, f"mean |SHAP| clean (n={m})"), "image/png"),
        "shap_bar_adv.png": sink.put("shap_bar_adv.png", render_bar(
            v_adv_all[:, order], ordered_names, bar_xmax, f"mean |SHAP| adversarial (n={m})"), "image/png"),
        "shap_beeswarm_clean.png": sink.put("shap_beeswarm_clean.png", render_beeswarm(
            v_clean_all[:, order], x_e[:, order], ordered_names, swarm_xmax, f"SHAP clean (n={m})", seed),
            "image/png"),
        "shap_beeswarm_adv.png": sink.put("shap_beeswarm_adv.png", render_beeswarm(
            v_adv_all[:, order], xa_e[:, order], ordered_names, swarm_xmax, f"SHAP adversarial (n={m})", seed),
            "image/png"),
    }

    top5_clean = [names[int(i)] for i in np.argsort(-mean_abs_clean, kind="stable")[:TOP_K]]
    top5_adv = [names[int(i)] for i in np.argsort(-mean_abs_adv, kind="stable")[:TOP_K]]
    n_rank_changes = sum(1 for pos, nm in enumerate(top5_clean) if pos >= len(top5_adv) or top5_adv[pos] != nm)
    shift_mean, shift_n, shift_excluded = aggregate(shifts)
    # Noise floor (spec 13.5): the same statistic between the clean attributions and those of the
    # benign-noise control at the same eps. Not computed (None) when no control was explained.
    noise_mean, noise_n, noise_excluded = aggregate(noise_shifts) if xc is not None else (None, None, None)
    n_flipped_expl = int(flipped_idx.size)
    top3_fraction = (sum(top3_changed_flags) / len(top3_changed_flags)) if top3_changed_flags else None
    wall = time.perf_counter() - t0
    nondeterminism = (["TreeExplainer is deterministic"] if deterministic else
                      [f"SHAP KernelExplainer background sampling (background_size={effective_bg}, nsamples={nsamples})"])
    meta: dict[str, Any] = {
        "modality": "tabular", "explainer": explainer_name, "explainers_tried": tried, "shap_version": shap.__version__,
        "deterministic": deterministic, "nsamples": effective_nsamples, "background_size": effective_bg,
        "seed": seed, "explain_k": k, "feature_names": names, "feature_names_source": names_source,
        "n_slice": int(n), "n_flipped_total": int(flipped.sum()),
        "n_explained": int(m), "n_flipped_explained": n_flipped_expl, "n_unflipped_explained": int(unflipped_idx.size),
        "expl_shift_mean": shift_mean, "expl_shift_n": shift_n, "expl_shift_n_excluded": shift_excluded,
        "expl_shift_noise_floor": noise_mean, "expl_shift_noise_floor_n": noise_n,
        "expl_shift_noise_floor_n_excluded": noise_excluded,
        "top5_clean": top5_clean, "top5_adv": top5_adv, "n_rank_changes": n_rank_changes,
        "mean_abs_shap_clean": {names[f]: float(mean_abs_clean[f]) for f in range(n_features)},
        "mean_abs_shap_adv": {names[f]: float(mean_abs_adv[f]) for f in range(n_features)},
        "top3_changed_fraction_flipped": top3_fraction, "top3_changed_n_flipped": len(top3_changed_flags),
        "per_sample": per_sample, "wall_time_s": wall, "nondeterminism": nondeterminism,
        "limitations": [
            SHAP_LIMITATION,
            (f"Explanations were computed on {int(m)} of {int(n)} rows (at most 2 x explain_k = {2 * k}) "
             "at the reference budget only."),
            "Tabular perturbations act in feature space. Feature identifiers are the only per-sample evidence recorded.",
        ] + ([] if deterministic else
             ["KernelExplainer attributions are sampled. The nsamples and background size are recorded."]),
    }
    summary_path = sink.put("shap_summary.json", json.dumps(_jsonable(meta), indent=1).encode(), "application/json")
    campaign_artifacts["shap_summary.json"] = summary_path
    meta["artifacts"] = campaign_artifacts
    meta["artifact_sha256"] = {nm: sink.sha256(p) for nm, p in campaign_artifacts.items()}
    return ExplainOutput(observations=observations, expl_shift_mean=shift_mean, expl_shift_n=shift_n,
                         expl_shift_n_excluded=shift_excluded, expl_shift_noise_floor=noise_mean,
                         expl_shift_noise_floor_n=noise_n, meta=meta)
