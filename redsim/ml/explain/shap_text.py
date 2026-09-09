"""SHAP token attributions for text targets (spec 13.2 text row, 13.3, 13.5, 13.6; MODALITIES-19).

``shap.Explainer(predict_proba, shap.maskers.Text(MASKER_SPLIT_PATTERN), algorithm="partition")``
on the explained set (the first ``k`` flipped and the first ``k`` unflipped messages
at the reference budget) yields one attribution per token and class for the clean
message, the adversarial message and, when given, the benign-control message. The
masker splits on ``\\W+``: its tokens are exactly the ``\\w+`` words of
``redsim.ml.datasets.sms_spam.tokenize`` (a leading empty token appears when a
message starts with punctuation and is dropped here), so a one-word-for-one-word
substitution keeps the token count and the attribution vectors align position by
position. ``expl_shift`` is then the cosine shift of ``redsim.ml.explain.stability``
over positional token attributions of the clean-predicted class; a pair whose
token counts differ is excluded and counted, never padded or truncated.

Artifacts per explained message (spec 5.8 names for text, MODALITIES-44):
``text_diff.json`` (kind ``ml.text.diff``: tokens clean / adversarial, changed
positions, per-token attributions, class explained, ``expl_shift``),
``shap_text.png`` (kind ``ml.shap.text``: token bars clean vs adversarial on one
colour scale, changed tokens outlined) and ``shap_values.npz`` (kind
``ml.shap.values``). The campaign-level ``shap_summary.json`` (kind
``ml.shap.meta``) carries counts, ranks and shifts only. Message text is dataset
content: it lives in the per-sample artifacts and nowhere else. The
``Observation`` carries no tokens: ``top_features_*`` stay empty, and the text
block (``Observation.text``, wave B0: ``n_tokens``, ``changed_positions``,
``n_changed``, ``top_tokens_clean`` / ``top_tokens_adv`` as position ranks,
``attribution_artifacts``) is attached when the schema has the field.

The Partition explainer is deterministic for a given token hierarchy and
``max_evals``; the setting is recorded in ``meta`` and in the provenance
nondeterminism list so a rerun with another cap is recognisable. The explanation
cache of spec 13.10 is keyed as for the other modalities, with the sha256 of each
message's UTF-8 bytes as the input digest.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import math
import time
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

import numpy as np

from redsim.ml.artifacts import ArtifactSink
from redsim.ml.datasets.sms_spam import MASKER_SPLIT_PATTERN, changed_positions, tokenize
from redsim.ml.errors import ExplainerUnavailable, ExplainUnavailable
from redsim.ml.explain.base import SHAP_LIMITATION, ExplainOutput, ExplanationCache, resolve_cache_dir
from redsim.ml.explain.stability import aggregate, expl_shift, is_defined
from redsim.ml.schema import Observation
from redsim.ml.targets.base import Sample, Target

if TYPE_CHECKING:
    from matplotlib.figure import Figure

logger = logging.getLogger(__name__)

TOP_K = 5
EXPLAINER_NAME = "PartitionExplainer"
DEFAULT_MAX_EVALS = 200
TEXT_DIFF_NAME = "text_diff.json"
TEXT_PLOT_NAME = "shap_text.png"
TEXT_VALUES_NAME = "shap_values.npz"
TEXT_METRIC_NOTE = ("text target: no centre-mass analogue (ratios are None). expl_shift is the cosine shift over "
                    "positional token attributions of the clean-predicted class, valid because a one-word-for-one-word "
                    "substitution preserves the token count; pairs with differing token counts are excluded and counted. "
                    "Token ranks live in the text block and the per-sample artifacts; no message text is recorded here.")
TEXT_EXPLAIN_LIMITATIONS: tuple[str, ...] = (
    ("Token attributions are Partition-explainer masking values over \\W+ tokens: masking deletes a word, so an "
     "attribution describes the model's sensitivity to that word's removal, not its meaning."),
    ("expl_shift for text compares positional token attributions and is defined only for one-word-for-one-word "
     "substitutions; adversarial messages whose token count differs from the clean message are excluded and counted."),
)


def _text_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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


def render_token_bars(tokens_clean: Sequence[str], tokens_adv: Sequence[str], v_clean: np.ndarray, v_adv: np.ndarray,
                      changed: Sequence[int], title: str) -> bytes:
    """Per-token attribution bars, clean vs adversarial, one shared x range; changed positions outlined."""
    n = len(tokens_clean)
    fig = _new_fig(6.0, 0.32 * max(n, 1) + 1.4)
    ax = fig.add_subplot(111)
    y = np.arange(n)
    vmax = float(max(np.abs(v_clean).max(initial=0.0), np.abs(v_adv).max(initial=0.0), 1e-12)) * 1.1
    ax.barh(y - 0.2, v_clean, height=0.4, color="#2a78d6", label="clean")
    ax.barh(y + 0.2, v_adv, height=0.4, color="#eb6834", label="adversarial")
    changed_set = set(int(c) for c in changed)
    for pos in changed_set:
        if 0 <= pos < n:
            ax.axhspan(pos - 0.5, pos + 0.5, facecolor="none", edgecolor="#0b0b0b", linewidth=1.0, linestyle="--")
    labels = [tc if i not in changed_set else f"{tc} -> {ta}"
              for i, (tc, ta) in enumerate(zip(tokens_clean, tokens_adv, strict=True))]
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=7)
    ax.invert_yaxis()
    ax.set_xlim(-vmax, vmax)
    ax.axvline(0.0, color="#888", linewidth=0.8)
    ax.set_xlabel("SHAP token attribution (clean-predicted class); dashed rows = substituted words", fontsize=8)
    ax.set_title(title, fontsize=9)
    ax.legend(fontsize=7, loc="lower right", frameon=False)
    fig.text(0.01, -0.03, "Token labels are dataset content (message words). Attributions describe sensitivity, "
             "not cause.", fontsize=6, color="#52514e")
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


def _as_texts(x: Any) -> list[str]:
    items = x.tolist() if isinstance(x, np.ndarray) else list(x)
    if not all(isinstance(t, str) for t in items):
        raise ExplainUnavailable("the text explainer expects message strings")
    return [str(t) for t in items]


def _word_values(values: Any, tokens: Sequence[str], cls: int) -> np.ndarray | None:
    """The per-word attribution vector for class ``cls`` from one sample's ``(n_tokens, n_classes)`` values.

    Drops the masker's empty tokens (a leading empty segment when the message starts with punctuation). ``None``
    when the shape cannot be read as ``(n_tokens, n_classes)``.
    """
    arr = np.asarray(values, dtype=np.float64)
    if arr.ndim == 1:
        arr = arr.reshape(-1, 1)
    if arr.ndim != 2 or arr.shape[0] != len(tokens):
        return None
    col = cls if cls < arr.shape[1] else arr.shape[1] - 1
    keep = [i for i, t in enumerate(tokens) if str(t).strip() != ""]
    return arr[keep, col]


def _ranking(v: np.ndarray, top: int) -> list[int]:
    """Word positions ranked by |attribution| (stable), top ``top`` only. Positions, never tokens."""
    order = np.argsort(-np.abs(v), kind="stable")
    return [int(i) for i in order[:top]]


def _explain_batch(explainer: Any, texts: Sequence[str], *, max_evals: int, batch_size: int,
                   seed: int) -> tuple[list[Any], list[list[str]]]:
    """Run the explainer on ``texts``; return per-sample values and the masker's tokens per sample."""
    # shap's Partition explainer needs at least 2 * n_tokens + 1 evaluations per text; the effective cap is the
    # larger of the requested ``max_evals`` and that floor, and the caller records what was requested.
    longest = max((len(tokenize(t)) for t in texts), default=0)
    evals = max(int(max_evals), 2 * longest + 1)
    state = np.random.get_state()
    np.random.seed(int(seed) % (2**32))
    try:
        sv = explainer(list(texts), max_evals=evals, batch_size=int(batch_size), silent=True)
    finally:
        np.random.set_state(state)
    values = list(sv.values) if isinstance(sv.values, (list, tuple, np.ndarray)) else [sv.values]
    tokens: list[list[str]] = []
    for j in range(len(texts)):
        data_j = sv.data[j] if sv.data is not None else []
        tokens.append([str(t) for t in np.asarray(data_j, dtype=object).tolist()])
    return values, tokens


def _word_tokens(masker_tokens: Sequence[str]) -> list[str]:
    """The masker's tokens stripped of delimiters and empties; equals ``tokenize(text)`` for a \\W+ split."""
    out: list[str] = []
    for t in masker_tokens:
        words = tokenize(str(t))
        if words:
            out.append(words[0])
    return out


def explain(target: Target, sample: Sample, x_adv: np.ndarray, proba_clean: np.ndarray, proba_adv: np.ndarray,
            sink: ArtifactSink, *, k: int, seed: int, x_ctrl: np.ndarray | None = None, eps: float | None = None,
            attack_id: str | None = None, max_evals: int = DEFAULT_MAX_EVALS, batch_size: int = 50,
            cache_dir: str | None = None, model_sha256: str | None = None,
            dataset_revision: str | None = None) -> ExplainOutput:
    """Explain the first ``k`` flipped and first ``k`` unflipped messages at the reference budget.

    Base contract ``(target, sample, x_adv, proba_clean, proba_adv, sink, *, k, seed)`` plus the optional
    ``x_ctrl`` (the control slice at the same eps, for the noise floor), ``eps`` / ``attack_id`` (recorded),
    ``max_evals`` and ``batch_size`` (Partition explainer caps), and the cache identity.
    """
    if k <= 0:
        raise ExplainUnavailable("explain_k = 0: no samples were requested for explanation, so S_expl has no input")

    import shap  # heavy import stays local

    t0 = time.perf_counter()
    texts = _as_texts(sample.x)
    adv = _as_texts(x_adv)
    if len(texts) != len(adv):
        raise ExplainUnavailable(f"clean/adversarial row counts differ: {len(texts)} vs {len(adv)}")
    ctrl = _as_texts(x_ctrl) if x_ctrl is not None else None
    if ctrl is not None and len(ctrl) != len(texts):
        raise ExplainUnavailable(f"control row count {len(ctrl)} differs from clean {len(texts)}")
    pc = np.asarray(proba_clean, dtype=np.float64)
    pa = np.asarray(proba_adv, dtype=np.float64)
    n = len(texts)
    pred_clean = pc.argmax(axis=1)
    pred_adv = pa.argmax(axis=1)
    flipped = pred_clean != pred_adv
    class_names = list(sample.class_names)

    flipped_idx = np.flatnonzero(flipped)[:k]
    unflipped_idx = np.flatnonzero(~flipped)[:k]
    explained = np.sort(np.concatenate([flipped_idx, unflipped_idx])).astype(int)
    if explained.size == 0:
        raise ExplainUnavailable("empty evaluation slice: nothing to explain")

    def predict_fn(batch: Any) -> np.ndarray:
        items = batch.tolist() if isinstance(batch, np.ndarray) else list(batch)
        return np.asarray(target.predict_proba(np.asarray([str(t) for t in items], dtype=object)), dtype=np.float64)

    try:
        masker = shap.maskers.Text(MASKER_SPLIT_PATTERN)
        explainer = shap.Explainer(predict_fn, masker, algorithm="partition", output_names=class_names)
    except Exception as exc:  # noqa: BLE001 - shap raises bare exceptions for unsupported combinations
        raise ExplainerUnavailable(f"SHAP could not build a Partition explainer over the text masker: "
                                   f"{type(exc).__name__}: {str(exc)[:160]}") from exc

    # Spec 13.10 cache: keyed as for the other modalities, input digests over the message bytes.
    if model_sha256 is None:
        try:
            manifest = target.manifest() or {}
            for key in ("model_sha256", "weights_sha256", "sha256"):
                if isinstance(manifest.get(key), str):
                    model_sha256 = str(manifest[key])
                    break
            if dataset_revision is None and isinstance(manifest.get("dataset_revision"), str):
                dataset_revision = str(manifest["dataset_revision"])
        except Exception:  # noqa: BLE001 - the cache is an optimisation; an unreadable manifest only disables it
            model_sha256 = None
    directory, source = resolve_cache_dir(sink, cache_dir)
    cache = ExplanationCache(directory, model_sha256=model_sha256, dataset_revision=dataset_revision,
                             explainer=EXPLAINER_NAME, nsamples=int(max_evals), seed=seed, attack_id=attack_id,
                             eps=eps, background_size=None, source=source)

    sel = [int(i) for i in explained.tolist()]
    to_run: list[int] = []
    cached: dict[int, dict[str, Any]] = {}
    for i in sel:
        digests = {"clean": _text_digest(texts[i]), "adv": _text_digest(adv[i]),
                   "control": _text_digest(ctrl[i]) if ctrl is not None else None}
        n_w = len(tokenize(texts[i]))
        shapes: dict[str, tuple[int, ...]] = {
            "clean": (n_w,), "adv": (len(tokenize(adv[i])),),
            "control": (len(tokenize(ctrl[i])),) if ctrl is not None else (0,)}
        hit = cache.lookup(i, digests=digests, class_index=int(pred_clean[i]), adv_class_index=int(pred_adv[i]),
                           shapes=shapes)
        if hit is None:
            to_run.append(i)
        else:
            cached[i] = hit["arrays"]

    computed: dict[int, dict[str, np.ndarray | None]] = {}
    if to_run:
        try:
            v_clean_all, tok_clean_all = _explain_batch(explainer, [texts[i] for i in to_run], max_evals=max_evals,
                                                        batch_size=batch_size, seed=seed)
            v_adv_all, tok_adv_all = _explain_batch(explainer, [adv[i] for i in to_run], max_evals=max_evals,
                                                    batch_size=batch_size, seed=seed)
            if ctrl is not None:
                v_ctrl_all, tok_ctrl_all = _explain_batch(explainer, [ctrl[i] for i in to_run], max_evals=max_evals,
                                                          batch_size=batch_size, seed=seed)
            else:
                v_ctrl_all, tok_ctrl_all = [], []
        except Exception as exc:  # noqa: BLE001
            raise ExplainerUnavailable(f"SHAP Partition explainer failed on the text slice: {type(exc).__name__}: "
                                       f"{str(exc)[:160]}") from exc
        for j, i in enumerate(to_run):
            c = int(pred_clean[i])
            entry: dict[str, np.ndarray | None] = {
                "clean": _word_values(v_clean_all[j], tok_clean_all[j], c),
                "adv": _word_values(v_adv_all[j], tok_adv_all[j], c),
                "control": _word_values(v_ctrl_all[j], tok_ctrl_all[j], c) if ctrl is not None else None,
            }
            # The masker's tokens must be the tokenizer contract's words, else the attribution positions are not
            # the attack's positions and the pair is excluded below (never silently realigned).
            if _word_tokens(tok_clean_all[j]) != tokenize(texts[i]):
                entry["clean"] = None
            if _word_tokens(tok_adv_all[j]) != tokenize(adv[i]):
                entry["adv"] = None
            computed[i] = entry
            arrays = {nm: np.asarray(v, dtype=np.float32) for nm, v in entry.items() if v is not None}
            if arrays.get("clean") is not None and arrays.get("adv") is not None:
                cache.store(i, arrays=arrays,
                            digests={"clean": _text_digest(texts[i]), "adv": _text_digest(adv[i]),
                                     "control": _text_digest(ctrl[i]) if ctrl is not None else None},
                            class_index=c, adv_class_index=int(pred_adv[i]),
                            extra={"n_tokens": int(len(tokenize(texts[i])))})

    observations: list[Observation] = []
    shifts: list[float] = []
    noise_shifts: list[float] = []
    per_sample: dict[str, dict[str, Any]] = {}
    top3_changed_flags: list[bool] = []
    n_alignment_excluded = 0
    text_field = "text" in Observation.model_fields
    for i in sel:
        c = int(pred_clean[i])
        a = int(pred_adv[i])
        is_flipped = bool(flipped[i])
        if i in cached:
            v_clean: np.ndarray | None = np.asarray(cached[i]["clean"], dtype=np.float64)
            v_adv: np.ndarray | None = np.asarray(cached[i]["adv"], dtype=np.float64)
            v_ctrl_raw = cached[i].get("control")
            v_ctrl: np.ndarray | None = None if v_ctrl_raw is None else np.asarray(v_ctrl_raw, dtype=np.float64)
        else:
            v_clean, v_adv, v_ctrl = computed[i]["clean"], computed[i]["adv"], computed[i]["control"]
        tokens_clean = tokenize(texts[i])
        tokens_adv = tokenize(adv[i])
        changed = changed_positions(texts[i], adv[i])
        aligned = (changed is not None and v_clean is not None and v_adv is not None
                   and v_clean.shape == v_adv.shape and v_clean.shape[0] == len(tokens_clean))
        shift = expl_shift(v_clean, v_adv) if aligned and v_clean is not None and v_adv is not None else float("nan")
        if not aligned:
            n_alignment_excluded += 1
        shifts.append(shift)
        noise = float("nan")
        if ctrl is not None and v_clean is not None and v_ctrl is not None and v_clean.shape == v_ctrl.shape:
            noise = expl_shift(v_clean, v_ctrl)
        if ctrl is not None:
            noise_shifts.append(noise)
        top_clean = _ranking(v_clean, TOP_K) if v_clean is not None else []
        top_adv = _ranking(v_adv, TOP_K) if v_adv is not None else []
        top3_changed = set(top_clean[:3]) != set(top_adv[:3]) if (top_clean and top_adv) else False
        if is_flipped and aligned:
            top3_changed_flags.append(top3_changed)

        name_c = class_names[c] if c < len(class_names) else str(c)
        name_a = class_names[a] if a < len(class_names) else str(a)
        yi = int(sample.y[i])
        name_t = class_names[yi] if yi < len(class_names) else str(yi)
        prefix = f"obs_{i:03d}"
        obs_id = f"o.{i:03d}"
        shift_value = shift if is_defined(shift) else None
        noise_value = noise if is_defined(noise) else None

        diff_json = {
            "observation_id": obs_id, "sample_index": i, "source_index": int(sample.indices[i]),
            "attack_id": attack_id, "eps": None if eps is None else float(eps),
            "explainer": EXPLAINER_NAME, "shap_version": shap.__version__, "max_evals": int(max_evals),
            "class_explained": name_c, "class_explained_index": c, "adv_pred_class": name_a, "flipped": is_flipped,
            "n_tokens_clean": len(tokens_clean), "n_tokens_adv": len(tokens_adv),
            "aligned": aligned, "changed_positions": changed,
            "tokens_clean": tokens_clean, "tokens_adv": tokens_adv,
            "shap_clean": None if v_clean is None else v_clean.tolist(),
            "shap_adv": None if v_adv is None else v_adv.tolist(),
            "shap_control": None if v_ctrl is None else v_ctrl.tolist(),
            "top_positions_clean": top_clean, "top_positions_adv": top_adv, "top3_changed": top3_changed,
            "expl_shift": shift_value, "expl_shift_noise": noise_value,
            "note": "dataset content: message tokens appear here and in shap_text.png only; the Observation and the "
                    "summary carry positions, counts and shifts",
        }
        artifacts: dict[str, str] = {}
        artifacts[TEXT_DIFF_NAME] = sink.put(f"{prefix}/{TEXT_DIFF_NAME}",
                                             json.dumps(_jsonable(diff_json), indent=1, ensure_ascii=False).encode(),
                                             "application/json")
        if aligned and v_clean is not None and v_adv is not None:
            try:
                artifacts[TEXT_PLOT_NAME] = sink.put(
                    f"{prefix}/{TEXT_PLOT_NAME}",
                    render_token_bars(tokens_clean, tokens_adv, v_clean, v_adv, changed or [],
                                      f"{obs_id} token attributions clean vs adversarial | class={name_c}"),
                    "image/png")
            except ImportError:
                logger.debug("matplotlib unavailable; token plot skipped")
        npz_buf = io.BytesIO()
        npz_arrays: dict[str, Any] = {"indices": np.asarray([i, int(sample.indices[i])], dtype=np.int64)}
        if v_clean is not None:
            npz_arrays["clean"] = v_clean.astype(np.float32)
        if v_adv is not None:
            npz_arrays["adv"] = v_adv.astype(np.float32)
        if v_ctrl is not None:
            npz_arrays["control"] = v_ctrl.astype(np.float32)
        np.savez_compressed(npz_buf, **npz_arrays)
        artifacts[TEXT_VALUES_NAME] = sink.put(f"{prefix}/{TEXT_VALUES_NAME}", npz_buf.getvalue(),
                                               "application/octet-stream")
        hashes = {nm: sink.sha256(p) for nm, p in artifacts.items()}
        text_block: dict[str, Any] = {
            "n_tokens": len(tokens_clean), "changed_positions": list(changed or []),
            "n_changed": len(changed) if changed is not None else None,
            "top_tokens_clean": top_clean, "top_tokens_adv": top_adv,       # position ranks, never token strings
            "attribution_artifacts": sorted(artifacts),
        }
        obs_kwargs: dict[str, Any] = {
            "id": obs_id, "sample_index": i, "true_label": name_t, "pred_clean": name_c, "pred_adv": name_a,
            "flipped": is_flipped, "confidence_clean": float(pc[i].max()), "confidence_adv": float(pa[i].max()),
            "artifacts": artifacts, "artifact_sha256": hashes,
            "center_mass_ratio_clean": None, "center_mass_ratio_adv": None, "expl_shift": shift_value,
            "top_features_clean": [], "top_features_adv": [],     # tabular fields: never repurposed for tokens
            "metric_note": TEXT_METRIC_NOTE,
        }
        if text_field:
            obs_kwargs["text"] = text_block   # Observation.text (wave B0 TextObservation)
        observations.append(Observation(**obs_kwargs))
        per_sample[obs_id] = {"flipped": is_flipped, "aligned": aligned, "expl_shift": shift_value,
                              "expl_shift_noise": noise_value, "n_tokens": len(tokens_clean),
                              "n_changed": text_block["n_changed"], "changed_positions": text_block["changed_positions"],
                              "top_positions_clean": top_clean, "top_positions_adv": top_adv,
                              "top3_changed": top3_changed}

    shift_mean, shift_n, shift_excluded = aggregate(shifts)
    noise_mean, noise_n, noise_excluded = aggregate(noise_shifts) if ctrl is not None else (None, None, None)
    m = int(explained.size)
    top3_fraction = (sum(top3_changed_flags) / len(top3_changed_flags)) if top3_changed_flags else None
    wall = time.perf_counter() - t0
    meta: dict[str, Any] = {
        "modality": "text", "explainer": EXPLAINER_NAME, "shap_version": shap.__version__,
        "deterministic": True, "nsamples": int(max_evals), "max_evals": int(max_evals), "batch_size": int(batch_size),
        "background_size": None, "masker": f"shap.maskers.Text({MASKER_SPLIT_PATTERN!r})",
        "seed": seed, "explain_k": k, "explain_k_requested": k, "attack_id": attack_id,
        "eps": None if eps is None else float(eps),
        "per_sample_artifact_names": [TEXT_DIFF_NAME, TEXT_PLOT_NAME, TEXT_VALUES_NAME],
        "cache": cache.stats(),
        "n_slice": int(n), "n_flipped_total": int(flipped.sum()),
        "n_explained": m, "n_flipped_explained": int(flipped_idx.size), "n_unflipped_explained": int(unflipped_idx.size),
        "n_alignment_excluded": n_alignment_excluded,
        "expl_shift_mean": shift_mean, "expl_shift_n": shift_n, "expl_shift_n_excluded": shift_excluded,
        "expl_shift_noise_floor": noise_mean, "expl_shift_noise_floor_n": noise_n,
        "expl_shift_noise_floor_n_excluded": noise_excluded,
        "top3_changed_fraction_flipped": top3_fraction, "top3_changed_n_flipped": len(top3_changed_flags),
        "per_sample": per_sample, "wall_time_s": wall,
        "nondeterminism": [f"PartitionExplainer sampling (max_evals={int(max_evals)}, batch_size={int(batch_size)}); "
                           "deterministic given the token hierarchy and max_evals"],
        "limitations": [
            SHAP_LIMITATION,
            (f"Explanations were computed on {m} of {n} messages (at most 2 x explain_k = {2 * k}) at the reference "
             "budget only."),
            *TEXT_EXPLAIN_LIMITATIONS,
        ],
    }
    summary_path = sink.put("shap_summary.json", json.dumps(_jsonable(meta), indent=1).encode(), "application/json")
    meta["artifacts"] = {"shap_summary.json": summary_path}
    meta["artifact_sha256"] = {"shap_summary.json": sink.sha256(summary_path)}
    return ExplainOutput(observations=observations, expl_shift_mean=shift_mean, expl_shift_n=shift_n,
                         expl_shift_n_excluded=shift_excluded, expl_shift_noise_floor=noise_mean,
                         expl_shift_noise_floor_n=noise_n, meta=meta)


PredictFn = Callable[[Sequence[str]], np.ndarray]

__all__ = [
    "DEFAULT_MAX_EVALS", "EXPLAINER_NAME", "TEXT_DIFF_NAME", "TEXT_EXPLAIN_LIMITATIONS", "TEXT_METRIC_NOTE",
    "TEXT_PLOT_NAME", "TEXT_VALUES_NAME", "TOP_K", "explain", "render_token_bars",
]
