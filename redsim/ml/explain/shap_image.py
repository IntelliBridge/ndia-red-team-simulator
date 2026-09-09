"""SHAP explanations for image targets (spec sections 13.2-13.6, 13.10).

Two paths, chosen by what the target exposes (spec 13.2):

* **gradient** -- ``shap.GradientExplainer`` on ``Target.torch_model()`` (``DeepExplainer`` as the
  guarded fallback) for any differentiable module;
* **partition** -- ``shap.PartitionExplainer`` with ``shap.maskers.Image`` over ``predict_proba`` when
  the target exposes no differentiable module (converted-ONNX failures, black-box wrappers). It is
  model-agnostic and slower, so ``explain_k`` is capped at ``PARTITION_K_CAP`` (8) on this path, and
  its masking attributions are recorded as a different quantity from gradient attributions.

Both explain the **clean-predicted class** on the clean and adversarial input so ``expl_shift``
compares where the model looks for the same decision. For flipped samples the adversarial predicted
class is shown as a third, labelled map. Artifacts go through the ``ArtifactSink``. Every PNG,
``.npz`` and meta file is hashed into ``Observation.artifact_sha256``.

Per-sample attributions are cached on disk (``explain.base.ExplanationCache``, spec 13.10) under the
run work dir, keyed by ``(model_sha256, dataset_revision, sample_index, attack_id, eps, explainer,
nsamples, seed)`` and guarded by the input digests, so ``explain.run`` and ``verify.replay`` reuse
identical clean attributions; hits are recorded in ``meta["cache"]`` and each ``shap_meta.json``.

Nothing here is faked: when SHAP cannot run on either path ``ExplainerUnavailable`` is raised and no
artifact is written.
"""

from __future__ import annotations

import io
import json
import logging
import math
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np

from redsim.ml.artifacts import ArtifactSink
from redsim.ml.errors import ExplainerUnavailable, ExplainUnavailable
from redsim.ml.explain.base import (
    SHAP_LIMITATION,
    ExplainOutput,
    ExplanationCache,
    array_digest,
    resolve_cache_dir,
)
from redsim.ml.explain.stability import aggregate, channel_sum, expl_shift, is_defined
from redsim.ml.schema import Observation
from redsim.ml.targets.base import Sample, Target

if TYPE_CHECKING:
    from matplotlib.axes import Axes
    from matplotlib.figure import Figure

logger = logging.getLogger(__name__)

CLASS_SELECTION_RULE = ("phi_clean and phi_adv explain the clean-predicted class on the clean and adversarial "
                        "input. For flipped samples phi_adv_predclass explains the adversarial predicted class")
DISPLAY_PX = 128
# The frozen default of ``Observation.metric_note``, repeated in the per-sample meta file.
CENTER_BOX_NOTE: str = str(Observation.model_fields["metric_note"].default)

# Spec 13.2 / 13.10: the model-agnostic fallback is slower, so explain_k is capped on that path.
PARTITION_K_CAP = 8
GRADIENT_EXPLAINERS: tuple[str, ...] = ("GradientExplainer", "DeepExplainer")
EXPLAINER_CHOICES: tuple[str, ...] = ("auto", *GRADIENT_EXPLAINERS, "PartitionExplainer")
# Spec 13.8: masking attributions are a different quantity from gradient attributions.
PARTITION_LIMITATION = ("PartitionExplainer masking attributions (model-agnostic, over predict_proba) are not the "
                        "same quantity as gradient attributions and are not compared across paths.")
PARTITION_METRIC_NOTE = (" Attributions on this observation come from shap.PartitionExplainer (image masking over "
                         "predict_proba), not from gradients.")


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
                  nsamples: int, seed: int, names: tuple[str, ...] = GRADIENT_EXPLAINERS) -> tuple[str, list[Any]]:
    """Gradient path: try the named explainers in order. Raise ``ExplainerUnavailable`` when all fail."""
    errors: list[str] = []
    for name in names:
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
    raise ExplainerUnavailable("SHAP could not explain this module: " + " | ".join(errors))


def _partition_attributions(shap: Any, predict_proba: Callable[[np.ndarray], np.ndarray], mask_value_hwc: np.ndarray,
                            batches: list[np.ndarray], max_evals: int) -> tuple[str, list[Any]]:
    """Partition path (spec 13.2, image without a differentiable module).

    ``shap.PartitionExplainer`` with ``shap.maskers.Image`` sees HWC images and a model function over
    ``predict_proba``; the mask value is the mean of the background images (no OpenCV dependency).
    Outputs are transposed back to ``(n, C, H, W, n_classes)`` so ``_select`` and the CHW artifacts are
    the same shape as on the gradient path. Raises ``ExplainerUnavailable`` when shap cannot run.
    """
    def f(x_hwc: np.ndarray) -> np.ndarray:
        arr = np.asarray(x_hwc, dtype=np.float32)
        return np.asarray(predict_proba(np.ascontiguousarray(np.transpose(arr, (0, 3, 1, 2)))), dtype=np.float64)

    try:
        masker = shap.maskers.Image(np.asarray(mask_value_hwc, dtype=np.float32), shape=mask_value_hwc.shape)
        explainer = shap.PartitionExplainer(f, masker)
        outs: list[Any] = []
        for xb in batches:
            xb_hwc = np.ascontiguousarray(np.transpose(np.asarray(xb, dtype=np.float32), (0, 2, 3, 1)))
            values = np.asarray(explainer(xb_hwc, max_evals=int(max_evals), silent=True).values, dtype=np.float64)
            if values.ndim == 4:                    # single-output model: add a class axis of one
                values = values[..., None]
            if values.ndim != 5:
                raise ExplainerUnavailable(f"PartitionExplainer returned shape {values.shape}, expected (n, H, W, C, K)")
            outs.append(np.transpose(values, (0, 3, 1, 2, 4)))
        return "PartitionExplainer", outs
    except ExplainerUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001 -- shap raises bare exceptions; the state is recorded, not faked
        raise ExplainerUnavailable(f"SHAP PartitionExplainer could not run: {type(exc).__name__}: "
                                   f"{str(exc)[:160]}") from exc


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


def _recorded(phi: np.ndarray) -> np.ndarray:
    """An attribution as it is recorded: float32 precision (the ``.npz`` and cache dtype), held as float64."""
    return np.asarray(phi, dtype=np.float32).astype(np.float64)


def _manifest_str(target: Target, *keys: str) -> str | None:
    try:
        manifest = target.manifest() or {}
    except Exception:  # noqa: BLE001 -- a manifest failure only disables the cache
        return None
    for key in keys:
        v = manifest.get(key)
        if isinstance(v, str) and v:
            return v
    return None


def _torch_module(target: Target) -> Any:
    try:
        return target.torch_model()
    except Exception as exc:  # noqa: BLE001 -- a target that cannot hand out its module takes the fallback path
        logger.debug("torch_model() failed: %s", type(exc).__name__)
        return None


# --------------------------------------------------------------------------- entry point

def explain(target: Target, sample: Sample, x_adv: np.ndarray, proba_clean: np.ndarray,
            proba_adv: np.ndarray, sink: ArtifactSink, *, k: int, seed: int,
            x_ctrl: np.ndarray | None = None, nsamples: int = 200, background_size: int = 50,
            eps: float | None = None, explainer: str = "auto", attack_id: str | None = None,
            model_sha256: str | None = None, dataset_revision: str | None = None,
            cache_dir: str | Path | None = None, use_cache: bool = True) -> ExplainOutput:
    """Explain the first ``k`` flipped and first ``k`` unflipped samples (slice order) at the reference budget.

    ``x_ctrl`` (optional) is the benign-noise control input at the same eps. When
    given, the explanation noise floor of spec 13.5 is computed and returned as
    ``expl_shift_noise_floor`` with its ``n``. ``eps`` fixes the ``diff.png`` scale
    and defaults to the observed L-inf distance so maps stay comparable.

    ``explainer`` is ``"auto"`` (gradient path when the target exposes a torch module, else the
    PartitionExplainer fallback) or one explicit name. On the partition path ``k`` is capped at
    ``PARTITION_K_CAP`` and ``nsamples`` is the explainer's ``max_evals`` budget.

    ``attack_id``, ``model_sha256`` and ``dataset_revision`` complete the spec 13.10 cache key (the
    digests default to the target manifest's ``model_sha256`` / ``weights_sha256`` and
    ``dataset_revision`` / ``revision``); ``cache_dir`` overrides the resolved cache location and
    ``use_cache=False`` turns the cache off. The cache outcome is recorded in ``meta["cache"]``.
    """
    if explainer not in EXPLAINER_CHOICES:
        raise ExplainUnavailable(f"unknown image explainer {explainer!r}; choose one of {EXPLAINER_CHOICES}")
    if k <= 0:
        raise ExplainUnavailable("explain_k = 0: no samples were requested for explanation, so S_expl has no input")

    model = None if explainer == "PartitionExplainer" else _torch_module(target)
    if model is None and explainer in GRADIENT_EXPLAINERS:
        raise ExplainerUnavailable(f"{explainer} was requested but the target exposes no differentiable torch module")
    path = "gradient" if model is not None else "partition"
    if path == "partition" and not callable(getattr(target, "predict_proba", None)):
        raise ExplainerUnavailable("target exposes neither a differentiable torch module (GradientExplainer) nor "
                                   "predict_proba (PartitionExplainer); SHAP cannot run")
    k_requested = int(k)
    if path == "partition":
        k = min(k, PARTITION_K_CAP)

    import shap  # heavy imports stay local

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

    xc = None
    if x_ctrl is not None:
        xc = np.ascontiguousarray(np.asarray(x_ctrl, dtype=np.float32))
        if xc.shape != x.shape:
            raise ExplainUnavailable(f"control input shape {xc.shape} differs from clean {x.shape}")

    eps_f: float = float(np.abs(xa - x).max()) if eps is None else float(eps)
    diff_scale = max(eps_f, 1e-12)

    # --- explanation cache (spec 13.10): per-sample lookups guarded by the input digests ------------------
    explainer_key = "PartitionExplainer" if path == "partition" else (
        explainer if explainer in GRADIENT_EXPLAINERS else "GradientExplainer")
    msha = model_sha256 or _manifest_str(target, "model_sha256", "weights_sha256", "sha256")
    drev = dataset_revision or _manifest_str(target, "dataset_revision", "revision")
    if use_cache:
        cdir, source = resolve_cache_dir(sink, cache_dir)
    else:
        cdir, source = None, "cache disabled by the caller"
    cache = ExplanationCache(cdir, model_sha256=msha, dataset_revision=drev, explainer=explainer_key,
                             nsamples=int(nsamples), seed=int(seed), attack_id=attack_id, eps=eps_f,
                             background_size=int(bg_idx.size), source=source)
    positions = explained.tolist()
    digests: dict[int, dict[str, str | None]] = {}
    hits: dict[int, dict[str, Any]] = {}
    for j, i in enumerate(positions):
        digests[j] = {"clean": array_digest(x[i]), "adv": array_digest(xa[i]),
                      "control": array_digest(xc[i]) if xc is not None else None}
        shapes = {"clean": tuple(x[i].shape), "adv": tuple(xa[i].shape), "control": tuple(x[i].shape)}
        entry = cache.lookup(int(sample.indices[i]), digests=digests[j], class_index=int(pred_clean[i]),
                             adv_class_index=int(pred_adv[i]), shapes=shapes)
        if entry is not None:
            hits[j] = entry

    def compute(miss_positions: list[int]) -> tuple[str, list[Any]]:
        sel = explained[miss_positions]
        batches = [x[sel], xa[sel]] + ([xc[sel]] if xc is not None else [])
        if path == "gradient":
            import torch
            names = (explainer,) if explainer in GRADIENT_EXPLAINERS else GRADIENT_EXPLAINERS
            return _attributions(shap, torch, model, torch.from_numpy(x[bg_idx]), batches, nsamples, seed, names)
        mask_value = np.transpose(x[bg_idx], (0, 2, 3, 1)).mean(axis=0)
        return _partition_attributions(shap, target.predict_proba, mask_value, batches, nsamples)

    misses = [j for j in range(len(positions)) if j not in hits]
    invalidated = 0
    outs: list[Any] = []
    if misses:
        explainer_name, outs = compute(misses)
        stored_names = {str(e["meta"].get("explainer")) for e in hits.values()}
        if stored_names and stored_names != {explainer_name}:
            # Entries computed by a different explainer than the one that just ran are not comparable with the
            # fresh attributions: drop them and compute everything on one explainer. Recorded, never mixed.
            invalidated = len(hits)
            cache.hits = 0
            hits = {}
            misses = list(range(len(positions)))
            explainer_name, outs = compute(misses)
    else:
        stored_names = {str(e["meta"].get("explainer")) for e in hits.values()}
        explainer_name = stored_names.pop() if len(stored_names) == 1 else explainer_key
    batch_pos = {j: idx for idx, j in enumerate(misses)}
    sv_clean = outs[0] if outs else None
    sv_adv = outs[1] if outs else None
    sv_ctrl = outs[2] if outs and xc is not None else None
    if path == "partition":
        effective_nsamples: int | None = int(nsamples)     # PartitionExplainer max_evals budget
    else:
        effective_nsamples = int(nsamples) if explainer_name == "GradientExplainer" else None
    metric_note = CENTER_BOX_NOTE + (PARTITION_METRIC_NOTE if path == "partition" else "")

    observations: list[Observation] = []
    shifts: list[float] = []
    noise_shifts: list[float] = []
    per_sample: dict[str, dict[str, Any]] = {}
    cmr: dict[str, dict[str, list[float | None]]] = {"flipped": {"clean": [], "adv": []},
                                                     "unflipped": {"clean": [], "adv": []}}

    for j, i in enumerate(positions):
        c = int(pred_clean[i])
        a = int(pred_adv[i])
        is_flipped = bool(flipped[i])
        cache_hit = j in hits
        if cache_hit:
            arrays_in = hits[j]["arrays"]
            phi_clean = np.asarray(arrays_in["clean"], dtype=np.float64)
            phi_adv = np.asarray(arrays_in["adv"], dtype=np.float64)
            phi_adv_pred = (np.asarray(arrays_in["adv_predclass"], dtype=np.float64)
                            if is_flipped and "adv_predclass" in arrays_in else None)
            phi_ctrl = np.asarray(arrays_in["control"], dtype=np.float64) if xc is not None else None
        else:
            # Derived values are computed from the float32 arrays that are recorded (shap_values.npz and the
            # cache), so a cached replay reproduces them exactly rather than to float64 rounding.
            jj = batch_pos[j]
            phi_clean = _recorded(_select(sv_clean, jj, c))
            phi_adv = _recorded(_select(sv_adv, jj, c))
            phi_adv_pred = _recorded(_select(sv_adv, jj, a)) if is_flipped else None
            phi_ctrl = _recorded(_select(sv_ctrl, jj, c)) if sv_ctrl is not None else None
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

        arrays: dict[str, Any] = {"clean": phi_clean.astype(np.float32), "adv": phi_adv.astype(np.float32)}
        if phi_adv_pred is not None:
            arrays["adv_predclass"] = phi_adv_pred.astype(np.float32)
        if phi_ctrl is not None:
            arrays["control"] = phi_ctrl.astype(np.float32)
        if not cache_hit:
            cache.store(int(sample.indices[i]), arrays=arrays, digests=digests[j], class_index=c, adv_class_index=a,
                        extra={"explainer": explainer_name, "shap_version": shap.__version__,
                               "flipped": is_flipped, "slice_position": int(i)})
        npz_buf = io.BytesIO()
        np.savez_compressed(npz_buf, **arrays, indices=np.asarray([i, int(sample.indices[i])], dtype=np.int64))
        artifacts["shap_values.npz"] = sink.put(f"{prefix}/shap_values.npz", npz_buf.getvalue(),
                                                "application/octet-stream")

        obs_id = f"o.{i:03d}"
        sample_meta = {
            "observation_id": obs_id, "sample_index": i, "source_index": int(sample.indices[i]),
            "attack_id": attack_id, "eps": eps_f,
            "explainer": explainer_name, "explainer_path": path, "shap_version": shap.__version__,
            "class_explained": name_c, "class_explained_index": c, "adv_pred_class": name_a, "flipped": is_flipped,
            "background_size": int(bg_idx.size), "nsamples": effective_nsamples, "seed": seed,
            "cache_hit": cache_hit, "cache_key": cache.key(int(sample.indices[i])) if cache.enabled else None,
            "center_mass_ratio_clean": cmr_clean, "center_mass_ratio_adv": cmr_adv,
            "expl_shift": None if not is_defined(shift) else shift,
            "expl_shift_noise": None if not is_defined(noise) else noise,
            "norm_clean": float(np.linalg.norm(map_clean)), "norm_adv": float(np.linalg.norm(map_adv)),
            "diff_png_scale_eps": diff_scale, "color_scale_vmax": vmax, "metric_kind": "heuristic",
            "metric_note": metric_note,
        }
        artifacts["shap_meta.json"] = sink.put(f"{prefix}/shap_meta.json",
                                               json.dumps(_jsonable(sample_meta), indent=1).encode(),
                                               "application/json")
        hashes = {name: sink.sha256(path_) for name, path_ in artifacts.items()}
        observations.append(Observation(
            id=obs_id, sample_index=i, true_label=name_t, pred_clean=name_c, pred_adv=name_a,
            flipped=is_flipped, confidence_clean=float(pc[i].max()), confidence_adv=float(pa[i].max()),
            artifacts=artifacts, artifact_sha256=hashes,
            center_mass_ratio_clean=cmr_clean, center_mass_ratio_adv=cmr_adv,
            expl_shift=sample_meta["expl_shift"],
            top_features_clean=[], top_features_adv=[],   # image: no feature identifiers (schema default)
            metric_note=metric_note,
        ))
        per_sample[obs_id] = {
            "flipped": is_flipped, "expl_shift": sample_meta["expl_shift"],
            "expl_shift_noise": sample_meta["expl_shift_noise"],
            "center_mass_ratio_clean": cmr_clean, "center_mass_ratio_adv": cmr_adv, "cache_hit": cache_hit,
        }

    shift_mean, shift_n, shift_excluded = aggregate(shifts)
    # Noise floor (spec 13.5): the same statistic between the clean attributions and those of the
    # benign-noise control at the same eps. Not computed (None) when no control was explained.
    noise_mean, noise_n, noise_excluded = aggregate(noise_shifts) if xc is not None else (None, None, None)
    wall = time.perf_counter() - t0
    if path == "partition":
        nondeterminism = [(f"SHAP PartitionExplainer image masking (background_size={int(bg_idx.size)} images averaged "
                           f"as the mask value, max_evals={effective_nsamples})")]
    else:
        nondeterminism = [(f"SHAP {explainer_name} background sampling (background_size={int(bg_idx.size)}, "
                           f"nsamples={effective_nsamples})")]
    cache_stats = cache.stats() | {"invalidated": invalidated}
    if cache_stats["hits"]:
        nondeterminism.append(f"Explanation cache reused {cache_stats['hits']} of {len(positions)} per-sample "
                              "attributions (spec 13.10; input digests matched)")
    cmr_summary = {
        g: {"clean": _mean(v["clean"]), "adv": _mean(v["adv"]),
            "n": sum(1 for c_, a_ in zip(v["clean"], v["adv"]) if c_ is not None and a_ is not None)}
        for g, v in cmr.items()
    }
    limitations = [
        SHAP_LIMITATION,
        (f"Explanations were computed on {int(explained.size)} of {int(n)} samples (at most 2 x explain_k = {2 * k}) "
         "at the reference budget only."),
        "The centre-mass heuristic assumes a centred subject and is a proxy, not a segmentation.",
        ("expl_shift compares attributions of the same class and is sensitive to explainer sampling noise "
         "(see the noise floor when a control was explained)."),
    ]
    if path == "partition":
        limitations.append(PARTITION_LIMITATION)
        if k_requested > k:
            limitations.append(f"explain_k was capped at {PARTITION_K_CAP} on the PartitionExplainer path "
                               f"(requested {k_requested}).")
    meta: dict[str, Any] = {
        "modality": "image", "explainer": explainer_name, "explainer_path": path, "shap_version": shap.__version__,
        "nsamples": effective_nsamples, "background_size": int(bg_idx.size), "seed": seed,
        "explain_k": k, "explain_k_requested": k_requested,
        "explain_k_cap": PARTITION_K_CAP if path == "partition" else None,
        "attack_id": attack_id, "model_sha256": msha, "dataset_revision": drev,
        "class_selection": CLASS_SELECTION_RULE, "eps": eps_f, "n_slice": int(n),
        "n_flipped_total": int(flipped.sum()), "n_explained": int(explained.size),
        "n_flipped_explained": int(flipped_idx.size), "n_unflipped_explained": int(unflipped_idx.size),
        "expl_shift_mean": shift_mean, "expl_shift_n": shift_n, "expl_shift_n_excluded": shift_excluded,
        "expl_shift_noise_floor": noise_mean, "expl_shift_noise_floor_n": noise_n,
        "expl_shift_noise_floor_n_excluded": noise_excluded,
        "center_mass_ratio_mean": cmr_summary, "per_sample": per_sample, "cache": cache_stats,
        "diff_png_scale_eps": diff_scale, "wall_time_s": wall, "nondeterminism": nondeterminism,
        "limitations": limitations,
    }
    summary_path = sink.put("shap_summary.json", json.dumps(_jsonable({k_: v for k_, v in meta.items()
                                                                       if k_ != "per_sample"} | {"per_sample": per_sample}),
                                                            indent=1).encode(), "application/json")
    meta["artifacts"] = {"shap_summary.json": summary_path}
    meta["artifact_sha256"] = {"shap_summary.json": sink.sha256(summary_path)}
    return ExplainOutput(observations=observations, expl_shift_mean=shift_mean, expl_shift_n=shift_n,
                         expl_shift_n_excluded=shift_excluded, expl_shift_noise_floor=noise_mean,
                         expl_shift_noise_floor_n=noise_n, meta=meta)
