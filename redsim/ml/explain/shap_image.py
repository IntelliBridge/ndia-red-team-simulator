"""SHAP explanations for image targets (spec sections 13.2-13.6).

``shap.GradientExplainer`` on ``Target.torch_model()`` (``DeepExplainer`` as
the guarded fallback) explains the **clean-predicted class** on the clean and
adversarial input so ``expl_shift`` compares where the model looks for the
same decision. For flipped samples the adversarial predicted class is shown as
a third, labelled map. Artifacts go through the ``ArtifactSink``. Every PNG,
``.npz`` and meta file is hashed into ``Observation.artifact_sha256``.

Each ``Observation`` carries its own ``expl_shift`` (``None`` when the pair is
undefined) and empty ``top_features_*`` lists: images have no feature
identifiers. The returned ``ExplainOutput`` carries the reference-row
``Measurement`` fields (``expl_shift_mean`` with its ``n`` and exclusions, and
the benign-noise floor with its ``n``) for the campaign to write onto the
evasion measurement at the reference budget (spec 13.5).

Nothing here is faked: no differentiable module -> ``ExplainUnavailable``.
"""

from __future__ import annotations

import io
import json
import math
import time
from typing import TYPE_CHECKING, Any

import numpy as np

from redsim.ml.artifacts import ArtifactSink
from redsim.ml.errors import ExplainUnavailable
from redsim.ml.explain.base import SHAP_LIMITATION, ExplainOutput
from redsim.ml.explain.stability import aggregate, channel_sum, expl_shift, is_defined
from redsim.ml.schema import Observation
from redsim.ml.targets.base import Sample, Target

if TYPE_CHECKING:
    from matplotlib.axes import Axes
    from matplotlib.figure import Figure

CLASS_SELECTION_RULE = ("phi_clean and phi_adv explain the clean-predicted class on the clean and adversarial "
                        "input. For flipped samples phi_adv_predclass explains the adversarial predicted class")
DISPLAY_PX = 128
# The frozen default of ``Observation.metric_note``, repeated in the per-sample meta file.
CENTER_BOX_NOTE: str = str(Observation.model_fields["metric_note"].default)


# --------------------------------------------------------------------------- heuristics

def center_mass_ratio(attr: np.ndarray) -> float | None:
    """Share of total |attribution| inside the centred box covering 50% of the area.

    The box side is ``round(dim / sqrt(2))`` per dimension (spec 13.4). Returns
    ``None`` when the total attribution is (numerically) zero, because the
    ratio is then undefined -- never 0 or 1.
    """
    a = np.abs(channel_sum(np.asarray(attr, dtype=np.float64)))
    if a.ndim != 2:
        raise ValueError(f"expected an H x W map, got shape {a.shape}")
    total = float(a.sum())
    if total < 1e-12:
        return None
    h, w = a.shape
    bh = max(1, round(h / math.sqrt(2)))
    bw = max(1, round(w / math.sqrt(2)))
    top = (h - bh) // 2
    left = (w - bw) // 2
    inside = float(a[top:top + bh, left:left + bw].sum())
    return float(min(1.0, max(0.0, inside / total)))


# --------------------------------------------------------------------------- rendering (matplotlib Agg, no pyplot)

def _figure(title: str) -> tuple[Figure, Axes]:
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    fig = Figure(figsize=(2.8, 3.0), dpi=100)
    FigureCanvasAgg(fig)
    ax = fig.add_axes((0.0, 0.0, 1.0, 0.9))
    ax.set_axis_off()
    fig.text(0.5, 0.955, title, ha="center", va="center", fontsize=7)
    return fig, ax


def _png(fig: Figure) -> bytes:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=100)
    return buf.getvalue()


def _upscale(a: np.ndarray) -> np.ndarray:
    """Nearest-neighbour upscale of an (H, W[, C]) array to at least DISPLAY_PX on the short side."""
    h, w = a.shape[:2]
    f = max(1, math.ceil(DISPLAY_PX / max(1, min(h, w))))
    return np.asarray(np.repeat(np.repeat(a, f, axis=0), f, axis=1))


def _to_hwc(x: np.ndarray) -> np.ndarray:
    """(C, H, W) in [0, 1] -> (H, W, 3) or (H, W) for greyscale."""
    x = np.asarray(x, dtype=np.float32)
    if x.ndim == 2:
        return np.asarray(np.clip(x, 0.0, 1.0))
    if x.ndim == 3 and x.shape[0] in (1, 3, 4):
        x = np.transpose(x, (1, 2, 0))
    if x.shape[-1] == 1:
        return np.asarray(np.clip(x[..., 0], 0.0, 1.0))
    return np.asarray(np.clip(x[..., :3], 0.0, 1.0))


def render_input(x: np.ndarray, title: str) -> bytes:
    fig, ax = _figure(title)
    img = _upscale(_to_hwc(x))
    ax.imshow(img, cmap="gray" if img.ndim == 2 else None, interpolation="nearest", vmin=0.0, vmax=1.0)
    return _png(fig)


def render_overlay(x: np.ndarray, attr_map: np.ndarray, vmax: float, title: str) -> bytes:
    """Attribution overlay: symmetric diverging map on the greyscale input at fixed alpha."""
    fig, ax = _figure(title)
    img = _to_hwc(x)
    grey = img if img.ndim == 2 else img.mean(axis=-1)
    ax.imshow(_upscale(grey), cmap="gray", interpolation="nearest", vmin=0.0, vmax=1.0)
    v = max(float(vmax), 1e-12)
    ax.imshow(_upscale(np.asarray(attr_map, dtype=np.float64)), cmap="RdBu_r", interpolation="nearest",
              vmin=-v, vmax=v, alpha=0.6)
    return _png(fig)


def render_diff(diff_map: np.ndarray, scale: float, title: str) -> bytes:
    fig, ax = _figure(title)
    s = max(float(scale), 1e-12)
    ax.imshow(_upscale(np.clip(np.asarray(diff_map, dtype=np.float64) / s, 0.0, 1.0)), cmap="magma",
              interpolation="nearest", vmin=0.0, vmax=1.0)
    return _png(fig)


# --------------------------------------------------------------------------- shap plumbing

def _select(sv: Any, j: int, cls: int) -> np.ndarray:
    """Pick sample ``j`` / class ``cls`` from shap's output (list-per-class or class-last ndarray)."""
    if isinstance(sv, (list, tuple)):
        return np.asarray(sv[cls][j], dtype=np.float64)
    arr = np.asarray(sv, dtype=np.float64)
    if arr.ndim == 5:  # (n, C, H, W, n_classes): class axis last (shap >= 0.45)
        return np.asarray(arr[j, ..., cls])
    # single-output module (no class axis)
    return np.asarray(arr[j])


def _attributions(shap: Any, torch: Any, model: Any, background: Any, batches: list[np.ndarray],
                  nsamples: int, seed: int) -> tuple[str, list[Any]]:
    """Try GradientExplainer, then DeepExplainer. Raise ExplainUnavailable when both fail."""
    errors: list[str] = []
    for name in ("GradientExplainer", "DeepExplainer"):
        try:
            torch.manual_seed(seed)
            explainer = getattr(shap, name)(model, background)
            outs: list[Any] = []
            for xb in batches:
                xt = torch.from_numpy(np.ascontiguousarray(xb, dtype=np.float32))
                if name == "GradientExplainer":
                    outs.append(explainer.shap_values(xt, nsamples=nsamples, rseed=seed))
                else:
                    outs.append(explainer.shap_values(xt))
            return name, outs
        except Exception as exc:  # noqa: BLE001 -- shap raises bare AssertionError/RuntimeError
            errors.append(f"{name}: {type(exc).__name__}: {str(exc)[:160]}")
    raise ExplainUnavailable("SHAP could not explain this module: " + " | ".join(errors))


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (np.floating, float)):
        f = float(obj)
        return None if math.isnan(f) else f
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, np.bool_):
        return bool(obj)
    if isinstance(obj, np.ndarray):
        return _jsonable(obj.tolist())
    return obj


def _mean(values: list[float | None]) -> float | None:
    vals = [float(v) for v in values if is_defined(v)]
    return float(np.mean(vals)) if vals else None


# --------------------------------------------------------------------------- entry point

def explain(target: Target, sample: Sample, x_adv: np.ndarray, proba_clean: np.ndarray,
            proba_adv: np.ndarray, sink: ArtifactSink, *, k: int, seed: int,
            x_ctrl: np.ndarray | None = None, nsamples: int = 200, background_size: int = 50,
            eps: float | None = None) -> ExplainOutput:
    """Explain the first ``k`` flipped and first ``k`` unflipped samples (slice order) at the reference budget.

    ``x_ctrl`` (optional) is the benign-noise control input at the same eps. When
    given, the explanation noise floor of spec 13.5 is computed and returned as
    ``expl_shift_noise_floor`` with its ``n``. ``eps`` fixes the ``diff.png`` scale
    and defaults to the observed L-inf distance so maps stay comparable.
    """
    model = target.torch_model()
    if model is None:
        raise ExplainUnavailable("target exposes no differentiable torch module, which SHAP GradientExplainer needs")
    if k <= 0:
        raise ExplainUnavailable("explain_k = 0: no samples were requested for explanation, so S_expl has no input")

    import shap  # heavy imports stay local
    import torch

    t0 = time.perf_counter()
    x = np.ascontiguousarray(np.asarray(sample.x, dtype=np.float32))
    xa = np.ascontiguousarray(np.asarray(x_adv, dtype=np.float32))
    if x.shape != xa.shape:
        raise ExplainUnavailable(f"clean/adversarial shapes differ: {x.shape} vs {xa.shape}")
    if x.ndim != 4:
        raise ExplainUnavailable(f"image explainer expects NCHW input, got shape {x.shape}")
    n = x.shape[0]
    pc = np.asarray(proba_clean)
    pa = np.asarray(proba_adv)
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
    background = torch.from_numpy(x[bg_idx])

    batches = [x[explained], xa[explained]]
    xc = None
    if x_ctrl is not None:
        xc = np.ascontiguousarray(np.asarray(x_ctrl, dtype=np.float32))
        if xc.shape != x.shape:
            raise ExplainUnavailable(f"control input shape {xc.shape} differs from clean {x.shape}")
        batches.append(xc[explained])
    explainer_name, outs = _attributions(shap, torch, model, background, batches, nsamples, seed)
    sv_clean, sv_adv = outs[0], outs[1]
    sv_ctrl = outs[2] if xc is not None else None
    effective_nsamples: int | None = nsamples if explainer_name == "GradientExplainer" else None

    eps_f: float = float(np.abs(xa - x).max()) if eps is None else float(eps)
    diff_scale = max(eps_f, 1e-12)

    observations: list[Observation] = []
    shifts: list[float] = []
    noise_shifts: list[float] = []
    per_sample: dict[str, dict[str, Any]] = {}
    cmr: dict[str, dict[str, list[float | None]]] = {"flipped": {"clean": [], "adv": []},
                                                     "unflipped": {"clean": [], "adv": []}}

    for j, i in enumerate(explained.tolist()):
        c = int(pred_clean[i])
        a = int(pred_adv[i])
        is_flipped = bool(flipped[i])
        phi_clean = _select(sv_clean, j, c)
        phi_adv = _select(sv_adv, j, c)
        phi_adv_pred = _select(sv_adv, j, a) if is_flipped else None
        phi_ctrl = _select(sv_ctrl, j, c) if sv_ctrl is not None else None
        map_clean = channel_sum(phi_clean)
        map_adv = channel_sum(phi_adv)
        map_adv_pred = channel_sum(phi_adv_pred) if phi_adv_pred is not None else None
        map_ctrl = channel_sum(phi_ctrl) if phi_ctrl is not None else None

        cmr_clean = center_mass_ratio(map_clean)
        cmr_adv = center_mass_ratio(map_adv)
        shift = expl_shift(map_clean, map_adv)
        shifts.append(shift)
        noise = expl_shift(map_clean, map_ctrl) if map_ctrl is not None else float("nan")
        if map_ctrl is not None:
            noise_shifts.append(noise)
        group = "flipped" if is_flipped else "unflipped"
        cmr[group]["clean"].append(cmr_clean)
        cmr[group]["adv"].append(cmr_adv)

        # one shared symmetric colour scale per sample across all of its maps
        vmax = max(float(np.abs(map_clean).max()), float(np.abs(map_adv).max()),
                   float(np.abs(map_adv_pred).max()) if map_adv_pred is not None else 0.0)
        name_c = class_names[c] if c < len(class_names) else str(c)
        name_a = class_names[a] if a < len(class_names) else str(a)
        name_t = class_names[int(sample.y[i])] if int(sample.y[i]) < len(class_names) else str(int(sample.y[i]))
        prefix = f"obs_{i:03d}"
        diff_map = np.abs(xa[i] - x[i]).sum(axis=0) if x[i].ndim == 3 else np.abs(xa[i] - x[i])

        artifacts: dict[str, str] = {}
        artifacts["clean.png"] = sink.put(f"{prefix}/clean.png",
                                          render_input(x[i], f"clean | true={name_t} pred={name_c}"), "image/png")
        artifacts["adv.png"] = sink.put(f"{prefix}/adv.png",
                                        render_input(xa[i], f"adversarial eps={eps_f:.4g} | pred={name_a}"), "image/png")
        artifacts["diff.png"] = sink.put(f"{prefix}/diff.png",
                                         render_diff(diff_map, diff_scale, f"|x_adv - x| (eps={eps_f:.4g} = full)"),
                                         "image/png")
        artifacts["shap_clean.png"] = sink.put(f"{prefix}/shap_clean.png",
                                               render_overlay(x[i], map_clean, vmax, f"SHAP clean | class={name_c}"),
                                               "image/png")
        artifacts["shap_adv.png"] = sink.put(f"{prefix}/shap_adv.png",
                                             render_overlay(xa[i], map_adv, vmax, f"SHAP adv | class={name_c}"),
                                             "image/png")
        if map_adv_pred is not None:
            artifacts["shap_adv_predclass.png"] = sink.put(
                f"{prefix}/shap_adv_predclass.png",
                render_overlay(xa[i], map_adv_pred, vmax, f"SHAP adv | adv-pred class={name_a}"), "image/png")

        npz_buf = io.BytesIO()
        arrays: dict[str, Any] = {"clean": phi_clean.astype(np.float32), "adv": phi_adv.astype(np.float32),
                                         "indices": np.asarray([i, int(sample.indices[i])], dtype=np.int64)}
        if phi_adv_pred is not None:
            arrays["adv_predclass"] = phi_adv_pred.astype(np.float32)
        if phi_ctrl is not None:
            arrays["control"] = phi_ctrl.astype(np.float32)
        np.savez_compressed(npz_buf, **arrays)
        artifacts["shap_values.npz"] = sink.put(f"{prefix}/shap_values.npz", npz_buf.getvalue(),
                                                "application/octet-stream")

        obs_id = f"o.{i:03d}"
        sample_meta = {
            "observation_id": obs_id, "sample_index": i, "source_index": int(sample.indices[i]),
            "explainer": explainer_name, "shap_version": shap.__version__, "class_explained": name_c,
            "class_explained_index": c, "adv_pred_class": name_a, "flipped": is_flipped,
            "background_size": int(bg_idx.size), "nsamples": effective_nsamples, "seed": seed,
            "center_mass_ratio_clean": cmr_clean, "center_mass_ratio_adv": cmr_adv,
            "expl_shift": None if not is_defined(shift) else shift,
            "expl_shift_noise": None if not is_defined(noise) else noise,
            "norm_clean": float(np.linalg.norm(map_clean)), "norm_adv": float(np.linalg.norm(map_adv)),
            "diff_png_scale_eps": diff_scale, "color_scale_vmax": vmax, "metric_kind": "heuristic",
            "metric_note": CENTER_BOX_NOTE,
        }
        artifacts["shap_meta.json"] = sink.put(f"{prefix}/shap_meta.json",
                                               json.dumps(_jsonable(sample_meta), indent=1).encode(),
                                               "application/json")
        hashes = {name: sink.sha256(path) for name, path in artifacts.items()}
        observations.append(Observation(
            id=obs_id, sample_index=i, true_label=name_t, pred_clean=name_c, pred_adv=name_a,
            flipped=is_flipped, confidence_clean=float(pc[i].max()), confidence_adv=float(pa[i].max()),
            artifacts=artifacts, artifact_sha256=hashes,
            center_mass_ratio_clean=cmr_clean, center_mass_ratio_adv=cmr_adv,
            expl_shift=sample_meta["expl_shift"],
            top_features_clean=[], top_features_adv=[],   # image: no feature identifiers (schema default)
        ))
        per_sample[obs_id] = {
            "flipped": is_flipped, "expl_shift": sample_meta["expl_shift"],
            "expl_shift_noise": sample_meta["expl_shift_noise"],
            "center_mass_ratio_clean": cmr_clean, "center_mass_ratio_adv": cmr_adv,
        }

    shift_mean, shift_n, shift_excluded = aggregate(shifts)
    # Noise floor (spec 13.5): the same statistic between the clean attributions and those of the
    # benign-noise control at the same eps. Not computed (None) when no control was explained.
    noise_mean, noise_n, noise_excluded = aggregate(noise_shifts) if xc is not None else (None, None, None)
    wall = time.perf_counter() - t0
    nondeterminism = [(f"SHAP {explainer_name} background sampling (background_size={int(bg_idx.size)}, "
                       f"nsamples={effective_nsamples})")]
    cmr_summary = {
        g: {"clean": _mean(v["clean"]), "adv": _mean(v["adv"]),
            "n": sum(1 for c_, a_ in zip(v["clean"], v["adv"]) if c_ is not None and a_ is not None)}
        for g, v in cmr.items()
    }
    meta: dict[str, Any] = {
        "modality": "image", "explainer": explainer_name, "shap_version": shap.__version__,
        "nsamples": effective_nsamples, "background_size": int(bg_idx.size), "seed": seed, "explain_k": k,
        "class_selection": CLASS_SELECTION_RULE, "eps": eps_f, "n_slice": int(n),
        "n_flipped_total": int(flipped.sum()), "n_explained": int(explained.size),
        "n_flipped_explained": int(flipped_idx.size), "n_unflipped_explained": int(unflipped_idx.size),
        "expl_shift_mean": shift_mean, "expl_shift_n": shift_n, "expl_shift_n_excluded": shift_excluded,
        "expl_shift_noise_floor": noise_mean, "expl_shift_noise_floor_n": noise_n,
        "expl_shift_noise_floor_n_excluded": noise_excluded,
        "center_mass_ratio_mean": cmr_summary, "per_sample": per_sample,
        "diff_png_scale_eps": diff_scale, "wall_time_s": wall, "nondeterminism": nondeterminism,
        "limitations": [
            SHAP_LIMITATION,
            (f"Explanations were computed on {int(explained.size)} of {int(n)} samples (at most 2 x explain_k = {2 * k}) "
             "at the reference budget only."),
            "The centre-mass heuristic assumes a centred subject and is a proxy, not a segmentation.",
            ("expl_shift compares attributions of the same class and is sensitive to explainer sampling noise "
             "(see the noise floor when a control was explained)."),
        ],
    }
    summary_path = sink.put("shap_summary.json", json.dumps(_jsonable({k_: v for k_, v in meta.items()
                                                                       if k_ != "per_sample"} | {"per_sample": per_sample}),
                                                            indent=1).encode(), "application/json")
    meta["artifacts"] = {"shap_summary.json": summary_path}
    meta["artifact_sha256"] = {"shap_summary.json": sink.sha256(summary_path)}
    return ExplainOutput(observations=observations, expl_shift_mean=shift_mean, expl_shift_n=shift_n,
                         expl_shift_n_excluded=shift_excluded, expl_shift_noise_floor=noise_mean,
                         expl_shift_noise_floor_n=noise_n, meta=meta)
