"""Detection modality runner (spec 12.5, 14, 15.4; register MODALITIES-33..38, -41).

``run_detection(config, target, *, frame) -> ModalityResult`` is the ``ModalityRunner`` the shared campaign
frame (``redsim.ml.campaign.run_campaign`` via ``redsim.ml.runners.base.MODALITY_RUNNERS["detection"]``)
calls for object detectors. It performs the ``sample``, ``clean_eval``, ``attack:<id>`` and ``control``
stages on the frame's evidence lists, hands the frame an explain closure and declares ``mri=False``. It
counts boxes instead of labels:

* a ``Measurement`` row's ``n`` is the number of ground-truth boxes in the slice, ``n_correct`` the boxes
  matched at IoU >= the manifest threshold by a prediction at or above the manifest score threshold, and
  ``accuracy`` is therefore recall (every row says so in ``notes``). ``n_clean_correct`` is the clean matched
  count, ``n_flipped_from_clean`` the boxes matched clean but not under the patch (suppressed), and
  ``attack_success_rate`` the suppression rate over ``n_clean_correct``. ``conf_gap_*`` stay ``None``
  ("undefined for detection"). ``map50`` and the suppression rate go into ``Measurement.detection`` once
  wave B0 adds the field, and always into scalar ``params`` (``det_*``) so the record carries them on
  either side of the rebase;
* the control is a random patch of the same area at the same seeded locations, on rows
  ``m.control.noise.eps<e>`` so the spec 12.4 predicate and rules I1 / I2 apply unchanged;
* the explain closure records ``ExplainerUnavailable("no SHAP explainer for object detectors")`` as an
  ``Interpretation`` plus a limitation and writes box evidence per observed image (drawn clean and patched
  images, a ``boxes.json`` with ground truth, predictions, matched flags and the patch location); it never
  fabricates an attribution map;
* there is no MRI. ``S_conf`` is undefined and ``S_expl`` has no input, so ``compute_mri`` refuses detection
  rows, the frame gets ``mri=False`` with the reason, and the run carries a ``DetectionScorecard`` per attack
  (worst-case recall ratio, suppression rate at the reference budget, recall AUC over the patch-area grid,
  every value with its denominator) as the ``detection_scorecard.json`` artifact.

``run_detection_campaign(config, sink, ...)`` is a thin standalone frame with the same stages for trees
where ``run_campaign`` cannot yet dispatch the ``detection`` modality (before wave B0's schema literals);
``detection_recommendations`` is the R6 / R8 candidate set the rule layer's detection branch can emit.
Pure Python: no Celery, database or HTTP. Tests run it on ``tests/ml/fakes_detection.TinyDetector``.
"""

from __future__ import annotations

import io
import logging
import math
import platform
import socket
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Literal, cast

import numpy as np
from pydantic import BaseModel, Field, model_validator

from redsim.ml.artifacts import ArtifactSink
from redsim.ml.attacks import ATTACKS, CPU_FLOAT32_NOTE, NONDETERMINISM_PREFIX, library_versions
from redsim.ml.attacks import dpatch as _dpatch
from redsim.ml.errors import AttackNotApplicable, ExplainerUnavailable, MLError, TargetUnavailable
from redsim.ml.eval import eps_tag, perturbation_norms
from redsim.ml.runners.base import (
    CampaignFrame,
    ModalityResult,
    dataset_caveats,
    json_bytes,
    manifest_get,
    max_adv_artifact_bytes,
    sha256_indices,
    split_notes,
    uniq,
    utcnow,
)
from redsim.ml.schema import (
    AccuracyPoint,
    CampaignConfig,
    CampaignRecord,
    CandidateRecommendation,
    Interpretation,
    Measurement,
    MeasurementFamily,
    MRIRecord,
    Observation,
    Provenance,
    RobustnessCurve,
    ScoreStatus,
    contains_banned_score_word,
    standing_limitations,
)
from redsim.ml.scoring import (
    MIN_CLEAN_CORRECT_FOR_FINDING,
    ONE_POINT_GRID_LIMITATION,
    control_preserves_accuracy,
    finding_inputs,
    robustness_curves,
    score_run,
    settings_hash,
    trapezoid_auc_normalized,
)
from redsim.ml.targets.base import Target
from redsim.ml.targets.detection import (
    AP_INTERPOLATION_NOTE,
    BUDGET_LABEL,
    DETECTION_MODALITY,
    EXPLAINER_UNAVAILABLE_REASON,
    MODALITY,
    DetectionEval,
    DetectionSample,
    evaluate_detections,
    is_detection_target,
)
from redsim.ml.targets.registry import TARGETS

logger = logging.getLogger(__name__)

try:
    from redsim.ml.campaign import D3_BOUNDS_LIMITATION
except ImportError:  # pragma: no cover - the shared frame keeps the constant; text kept identical here
    D3_BOUNDS_LIMITATION = (
        "Open, unclassified public data only (D3). This tool evaluates and hardens the robustness of a classifier; it "
        "never trains, optimises or deploys targeting or weapons models and connects to no mission system. Results are "
        "evidence for human review, not a readiness or certification determination.")

CONTROL_ATTACK_ID = _dpatch.PATCH_CONTROL_ID
SCORECARD_NAME = "detection_scorecard.json"
BOXES_JSON_NAME = "boxes.json"                      # spec 5.8 kind ml.detection.boxes (per observation)
CLEAN_PNG_NAME = "clean_boxes.png"                  # ml.input.clean with drawn boxes
ADV_PNG_NAME = "adv_boxes.png"                      # ml.input.adv with drawn boxes and the patch location
FLIP_MATRIX_NAME = "flip_matrix.json"
DRAW_MIN_SIDE = 128
FORBIDDEN_SCORECARD_KEYS: frozenset[str] = frozenset({"mri", "grade", "subscores", "S_acc", "S_asr", "S_eps",
                                                      "S_conf", "S_expl", "weights"})

RECALL_NOTE = ("accuracy on this row is recall@IoU>={iou:g} at score threshold {score:g}: n counts ground-truth boxes, "
               "n_correct the boxes matched by a prediction; it is not classification accuracy")
SUPPRESSION_NOTE = ("attack_success_rate is the suppression rate: boxes matched on the clean image and unmatched under "
                    "the patch, over n_clean_correct (clean matched boxes)")
CONF_GAP_NOTE = "conf_gap_mean not computed: undefined for detection (a per-box score is not a class-probability gap)"
NO_MRI_REASON = ("MRI not computed: detection campaigns carry a detection scorecard, never an MRI. S_conf is "
                 "undefined (conf_gap is a classification quantity) and S_expl has no input (no SHAP explainer for "
                 "object detectors); weights are not renormalised and no detection index is defined (spec 15.4).")
NO_MRI_LIMITATION = ("No MRI exists for this detection campaign (S_conf undefined, S_expl unavailable); the "
                     f"{SCORECARD_NAME} artifact carries the worst-case recall ratio, the suppression rate at the "
                     "reference patch area and the recall AUC over the grid, each with its denominator.")
RECALL_LIMITATION = ("Detection rows count ground-truth boxes: 'accuracy' is recall@IoU at the manifest score "
                     "threshold and 'attack_success_rate' is the suppression rate; neither is a classification rate.")
EXPLAIN_LIMITATION = (f"Explain stage unavailable for object detectors ({EXPLAINER_UNAVAILABLE_REASON}); observations "
                      "carry drawn boxes and a boxes.json per image, never an attribution map or a fabricated heatmap.")
PATCH_LIMITATION = ("The patch attack is digital (pasted pixels, no printing, rotation or lighting transforms); "
                    "physical realisability of the patch is not established.")
DETECTION_STANDING = "Detection is evaluated with an in-repo greedy IoU matcher; " + AP_INTERPOLATION_NOTE + "."
CONTROL_NOTE = "control rows never create a Finding and never enter any score"
OBS_METRIC_NOTE = "no attribution metric for detection; see boxes.json (ml.detection.boxes) and the drawn images"
TRAILING_LIMITATIONS: tuple[str, ...] = (RECALL_LIMITATION, DETECTION_STANDING, PATCH_LIMITATION, NO_MRI_LIMITATION)

R8_REFERENCES: tuple[str, ...] = (
    "Liu et al. 2019, DPatch: An Adversarial Patch Attack on Object Detectors, arXiv:1806.02299",
    "Lee and Kolter 2019, On Physical Adversarial Patches for Object Detection, arXiv:1906.11897",
    "Chiang et al. 2020, Certified Defenses for Adversarial Patches, ICLR 2020, arXiv:2003.06693",
)


class DetectionMRIRefused(MLError):
    """An MRI was requested over detection rows; refused by construction (spec 15.4, MODALITIES-36)."""

    code = "detection_mri_refused"


# --- scorecard ---------------------------------------------------------------------------------------------

class ScoredCount(BaseModel):
    """A value with the denominator it was computed over; ``reason`` says why when it is ``None``."""

    value: float | None = None
    n: int = Field(ge=0)
    eps: float | None = None
    reason: str | None = None


class DetectionScorecard(BaseModel):
    """The per-attack detection scorecard. Not an MRI: no index, no grade, no weights, no subscore keys."""

    kind: Literal["detection_scorecard"] = "detection_scorecard"
    attack_id: str
    budget: str = BUDGET_LABEL
    norm: str
    eps_grid: list[float]
    reference_eps: float
    score_threshold: float
    iou_threshold: float
    clean_recall: AccuracyPoint                      # n = ground-truth boxes
    worst_case_recall_ratio: ScoredCount             # min over the grid of recall(eps) / recall(clean), n = gt boxes
    suppression_rate_at_reference: ScoredCount       # n = clean matched boxes
    suppression_by_eps: dict[str, float | None] = Field(default_factory=dict)
    recall_by_eps: dict[str, AccuracyPoint] = Field(default_factory=dict)
    control_recall_by_eps: dict[str, AccuracyPoint] = Field(default_factory=dict)
    map50_clean: float | None = None
    map50_by_eps: dict[str, float | None] = Field(default_factory=dict)
    recall_auc: ScoredCount                          # normalised trapezoid of the recall ratio over the grid
    reason_no_mri: str = NO_MRI_REASON
    settings_hash: str
    computed_at: datetime

    @model_validator(mode="after")
    def _never_an_mri(self) -> DetectionScorecard:
        validate_scorecard_payload(self.model_dump(mode="json"))
        if contains_banned_score_word(self.reason_no_mri):
            raise ValueError("scorecard reason contains a banned readiness word")
        return self


def validate_scorecard_payload(payload: Mapping[str, Any]) -> None:
    """Refuse any scorecard payload that carries an MRI key (``mri``, ``grade``, subscores, weights)."""
    found = sorted(k for k in payload if k in FORBIDDEN_SCORECARD_KEYS)
    if found:
        raise DetectionMRIRefused(f"detection scorecard carries MRI keys {found}; a detection record never holds an MRI")


# --- detection measurement rows -------------------------------------------------------------------------------

def is_detection_measurement(m: Measurement) -> bool:
    """A row built by ``measure_detection``: carries the ``det_n_boxes`` scalar (and ``.detection`` once B0 lands)."""
    if "det_n_boxes" in m.params:
        return True
    return getattr(m, "detection", None) is not None


def refuse_mri(measurements: Sequence[Measurement]) -> None:
    """Raise ``DetectionMRIRefused`` when any row is a detection row (spec 15.4: no MRI for detection)."""
    rows = [m.id for m in measurements if is_detection_measurement(m)]
    if rows:
        raise DetectionMRIRefused(f"MRI refused: {len(rows)} detection row(s) among the measurements "
                                  f"(first: {rows[0]}); {NO_MRI_REASON}")


def compute_mri(*, config: CampaignConfig, measurements: Sequence[Measurement],
                settings_hash: str | None = None) -> tuple[MRIRecord | None, str | None]:
    """``redsim.ml.scoring.score_run`` behind the detection guard: detection rows are refused, never scored."""
    refuse_mri(measurements)
    return score_run(config=config, measurements=measurements, settings_hash=settings_hash)


def _detection_block(ev: DetectionEval, *, n_clean_matched: int | None, n_suppressed: int | None) -> dict[str, Any]:
    """B0 ``DetectionMetrics`` shape: ``n_boxes``, ``n_matched``, ``map50``, ``recall``, ``suppression_rate``."""
    rate = (n_suppressed / n_clean_matched) if (n_clean_matched and n_suppressed is not None) else None
    return {"n_boxes": int(ev.n_gt), "n_matched": int(ev.n_matched), "map50": ev.map50, "recall": ev.recall,
            "suppression_rate": rate}


def _scalar(v: Any) -> float | int | bool | str | None:
    if isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, (np.integer, np.floating, np.bool_)):
        return cast(float | int | bool, v.item())
    return None


def measure_detection(id: str, family: MeasurementFamily, ev: DetectionEval, *, attack_id: str | None = None,
                      params: Mapping[str, Any] | None = None, x_ref: np.ndarray | None = None,
                      x_adv: np.ndarray | None = None, clean_matched: Sequence[np.ndarray] | None = None,
                      wall_time_s: float = 0.0, notes: Sequence[str] = ()) -> Measurement:
    """One detection ``Measurement`` row from an evaluation (see the module docstring for the denominators)."""
    row_notes = [RECALL_NOTE.format(iou=ev.iou_threshold, score=ev.score_threshold), *notes]
    n = int(ev.n_gt)
    n_correct = int(ev.n_matched)
    accuracy = (n_correct / n) if n > 0 else 0.0
    if n == 0:
        row_notes.append("not computed (denominator 0): the slice holds no ground-truth boxes")
    n_clean_matched: int | None = None
    n_suppressed: int | None = None
    asr: float | None = None
    if clean_matched is not None:
        if len(clean_matched) != len(ev.matched):
            raise ValueError("clean_matched must align with the evaluated images")
        n_clean_matched = int(sum(int(np.asarray(c, dtype=bool).sum()) for c in clean_matched))
        n_suppressed = int(sum(int((np.asarray(c, dtype=bool) & ~np.asarray(a, dtype=bool)).sum())
                               for c, a in zip(clean_matched, ev.matched, strict=True)))
        asr = (n_suppressed / n_clean_matched) if n_clean_matched > 0 else None
        row_notes.append(SUPPRESSION_NOTE)
        if asr is None:
            row_notes.append("attack_success_rate not computed (denominator n_clean_correct = 0: no clean box matched)")
    linf: float | None = None
    l2: float | None = None
    if x_ref is not None and x_adv is not None:
        linf, l2 = perturbation_norms(x_ref, x_adv)
    row_notes.append(CONF_GAP_NOTE)
    block = _detection_block(ev, n_clean_matched=n_clean_matched, n_suppressed=n_suppressed)
    clean_params: dict[str, float | int | bool | str] = {}
    for k, v in (params or {}).items():
        s = _scalar(v)
        if s is None:
            row_notes.append(f"param {k!r}={v!r} omitted from params (non-scalar)")
        else:
            clean_params[str(k)] = s
    clean_params.update({"det_n_boxes": block["n_boxes"], "det_n_matched": block["n_matched"],
                         "det_n_images": int(ev.n_images), "det_n_predictions": int(ev.n_predictions),
                         "det_score_threshold": float(ev.score_threshold), "det_iou_threshold": float(ev.iou_threshold)})
    for key in ("map50", "recall", "suppression_rate"):
        if block[key] is not None:
            clean_params[f"det_{key}"] = float(block[key])
    if ev.mean_matched_score is not None:
        clean_params["det_mean_matched_score"] = float(ev.mean_matched_score)
    fields: dict[str, Any] = {
        "id": id, "family": family, "attack_id": attack_id, "params": clean_params,
        "n": n, "n_correct": n_correct, "accuracy": accuracy,
        "n_flipped_from_clean": n_suppressed, "n_clean_correct": n_clean_matched, "attack_success_rate": asr,
        "linf_norm_mean": linf, "l2_norm_mean": l2, "conf_gap_mean": None, "conf_gap_n": None,
        "per_class": {k: dict(v) for k, v in ev.per_class.items()}, "wall_time_s": float(wall_time_s),
        "notes": row_notes,
    }
    # ``Measurement.detection`` is a schema field since wave B0 (``DetectionMetrics``): every detection row
    # carries the box-level block beside the scalar ``det_*`` params, so the report can print each rate with
    # its denominator.
    return Measurement(**fields, detection=block)


# --- small helpers -------------------------------------------------------------------------------------------

def _dist_version(dist: str) -> str:
    try:
        return version(dist)
    except PackageNotFoundError:
        return "not installed"


def _npz_bytes(x_adv: np.ndarray, indices: np.ndarray, targets: Sequence[Mapping[str, np.ndarray]]) -> bytes:
    from redsim.ml.datasets.military_assets import pack_targets

    boxes, labels, offsets = pack_targets([t["boxes"] for t in targets], [t["labels"] for t in targets])
    buf = io.BytesIO()
    np.savez_compressed(buf, x_adv=np.asarray(x_adv, dtype=np.float32), indices=np.asarray(indices, dtype=np.int64),
                        boxes=boxes, labels=labels, offsets=offsets)
    return buf.getvalue()


def resolve_detection_adapters(config: CampaignConfig) -> list[Any]:
    """The attack adapters for a detection campaign, resolved from ``ATTACKS`` by id.

    ``dpatch`` is a registered member of the pinned attack catalog (wave B1 checks the ten ids at import), so
    the registry is the single lookup; an unknown id, a non-evasion adapter or an adapter whose ``domains``
    exclude ``detection`` is refused with ``AttackNotApplicable``."""
    out: list[Any] = []
    for aid in dict.fromkeys(config.attack_ids):
        adapter = ATTACKS.maybe_get(aid)
        if adapter is None:
            raise AttackNotApplicable(f"unknown attack {aid!r}")
        info = adapter.info()
        if info.family != "evasion":
            raise AttackNotApplicable(f"{aid!r} is a {info.family} adapter; the benign patch control runs automatically")
        domains = getattr(adapter, "domains", None) or frozenset({info.domain})
        if MODALITY not in domains:
            raise AttackNotApplicable(f"attack {aid!r} applies to {sorted(domains)}, not {MODALITY!r}")
        out.append(adapter)
    return out


def _run_adapter(adapter: Any, target: Any, x: np.ndarray, y: np.ndarray, params: dict[str, Any], seed: int,
                 targets: Sequence[Mapping[str, np.ndarray]]) -> Any:
    """Hand the ground truth to adapters that take it (``targets=``); plain protocol adapters get the base call."""
    try:
        return adapter.run(target, x, y, params, seed, targets=targets)
    except TypeError as exc:
        if "targets" not in str(exc):
            raise
        return adapter.run(target, x, y, params, seed)


def _thresholds(target: Any, manifest: Mapping[str, Any]) -> tuple[float, float]:
    raw_block = manifest.get("detection")
    det_block: dict[str, Any] = dict(raw_block) if isinstance(raw_block, dict) else {}
    score_thr = float(getattr(target, "score_threshold", None) or det_block.get("score_threshold") or 0.5)
    iou_thr = float(getattr(target, "iou_threshold", None) or det_block.get("iou_threshold") or 0.5)
    return score_thr, iou_thr


# --- box evidence (the honest explain-stage output) ---------------------------------------------------------

def _draw_boxes_png(x_img: np.ndarray, layers: Sequence[tuple[np.ndarray, str]],
                    patch: tuple[int, int, int] | None = None) -> bytes:
    """PNG of one CHW [0, 1] image (upscaled to at least ``DRAW_MIN_SIDE``) with boxes drawn per layer colour."""
    from PIL import Image, ImageDraw

    arr = np.clip(np.asarray(x_img, dtype=np.float32), 0.0, 1.0)
    h, w = int(arr.shape[1]), int(arr.shape[2])
    scale = max(1, int(math.ceil(DRAW_MIN_SIDE / max(1, min(h, w)))))
    img = Image.fromarray(np.rint(arr.transpose(1, 2, 0) * 255.0).astype(np.uint8), mode="RGB")
    if scale > 1:
        img = img.resize((w * scale, h * scale), Image.Resampling.NEAREST)
    draw = ImageDraw.Draw(img)
    for boxes, colour in layers:
        for b in np.asarray(boxes, dtype=np.float32).reshape(-1, 4):
            x0, y0, x1, y1 = (float(v) * scale for v in b)
            if x1 > x0 and y1 > y0:
                draw.rectangle([x0, y0, max(x0 + 1, x1 - 1), max(y0 + 1, y1 - 1)], outline=colour, width=2)
    if patch is not None:
        r, c, s = patch
        draw.rectangle([c * scale, r * scale, (c + s) * scale - 1, (r + s) * scale - 1], outline="#ffd400", width=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _observation(obs_id: str, *, sample_index: int, class_names: Sequence[str], gt: Mapping[str, np.ndarray],
                 pred_clean: Mapping[str, np.ndarray], pred_adv: Mapping[str, np.ndarray],
                 matched_clean: np.ndarray, matched_adv: np.ndarray, score_threshold: float,
                 artifacts: dict[str, str], digests: dict[str, str], patch: dict[str, int] | None) -> Observation:
    labels = np.asarray(gt["labels"], dtype=np.int64)
    n_gt = int(labels.shape[0])
    primary = str(class_names[int(np.bincount(labels).argmax())]) if n_gt else "none"
    k_clean, k_adv = int(matched_clean.sum()), int(matched_adv.sum())
    conf_c = np.asarray(pred_clean.get("scores", np.zeros(0)), dtype=np.float64)
    conf_a = np.asarray(pred_adv.get("scores", np.zeros(0)), dtype=np.float64)
    conf_c = conf_c[conf_c >= score_threshold]
    conf_a = conf_a[conf_a >= score_threshold]
    fields: dict[str, Any] = {
        "id": obs_id, "sample_index": int(sample_index), "true_label": primary,
        "pred_clean": f"{k_clean}/{n_gt} boxes matched", "pred_adv": f"{k_adv}/{n_gt} boxes matched",
        "flipped": bool((matched_clean & ~matched_adv).any()),
        "confidence_clean": float(conf_c.mean()) if conf_c.size else 0.0,
        "confidence_adv": float(conf_a.mean()) if conf_a.size else 0.0,
        "artifacts": artifacts, "artifact_sha256": digests, "metric_note": OBS_METRIC_NOTE,
    }
    # ``Observation.detection`` is a schema field since wave B0 (``DetectionObservation``): ``n_gt``,
    # ``n_matched_clean``, ``n_matched_adv`` and the patch box in pixels of the attacked image
    # (``[x_min, y_min, x_max, y_max]``; None on control rows). The per-box tables stay in boxes.json.
    patch_bbox: list[float] | None = None
    if patch is not None:
        r, c, s = int(patch["row"]), int(patch["col"]), int(patch["side"])
        patch_bbox = [float(c), float(r), float(c + s), float(r + s)]
    block = {"n_gt": n_gt, "n_matched_clean": k_clean, "n_matched_adv": k_adv, "patch_bbox": patch_bbox}
    return Observation(**fields, detection=block)


def write_box_evidence(sink: ArtifactSink, *, attack_id: str, eps: float, sample: DetectionSample, x_adv: np.ndarray,
                       preds_clean: Sequence[Mapping[str, np.ndarray]], preds_adv: Sequence[Mapping[str, np.ndarray]],
                       matched_clean: Sequence[np.ndarray], matched_adv: Sequence[np.ndarray],
                       patch_side: int | None, patch_locations: np.ndarray | None, score_threshold: float,
                       k: int) -> list[Observation]:
    """Up to ``k`` suppressed and ``k`` unsuppressed images: drawn clean / patched PNGs plus a boxes.json each."""
    n = int(sample.x.shape[0])
    suppressed = [i for i in range(n) if bool((matched_clean[i] & ~matched_adv[i]).any())]
    others = [i for i in range(n) if i not in set(suppressed)]
    out: list[Observation] = []
    for i in suppressed[:k] + others[:k]:
        gt = sample.targets[i]
        patch = None
        patch_dict: dict[str, int] | None = None
        if patch_side is not None and patch_locations is not None:
            r, c = int(patch_locations[i, 0]), int(patch_locations[i, 1])
            patch = (r, c, int(patch_side))
            patch_dict = {"row": r, "col": c, "side": int(patch_side)}
        prefix = f"obs_{i:03d}/{attack_id}_{eps_tag(eps)}"
        clean_png = _draw_boxes_png(sample.x[i], [(gt["boxes"], "#1baf7a"), (preds_clean[i]["boxes"], "#2a78d6")])
        adv_png = _draw_boxes_png(x_adv[i], [(gt["boxes"], "#1baf7a"), (preds_adv[i]["boxes"], "#e34948")], patch)
        boxes_doc = {
            "attack_id": attack_id, "eps": float(eps), "sample_index": int(sample.indices[i]),
            "class_names": list(sample.class_names), "score_threshold": float(score_threshold),
            "ground_truth": {"boxes": gt["boxes"].tolist(), "labels": gt["labels"].tolist()},
            "clean": {"boxes": np.asarray(preds_clean[i]["boxes"]).tolist(),
                      "labels": np.asarray(preds_clean[i]["labels"]).tolist(),
                      "scores": np.asarray(preds_clean[i]["scores"]).tolist(),
                      "matched_gt": [bool(v) for v in matched_clean[i]]},
            "adversarial": {"boxes": np.asarray(preds_adv[i]["boxes"]).tolist(),
                            "labels": np.asarray(preds_adv[i]["labels"]).tolist(),
                            "scores": np.asarray(preds_adv[i]["scores"]).tolist(),
                            "matched_gt": [bool(v) for v in matched_adv[i]]},
            "patch": patch_dict, "legend": {"ground_truth": "#1baf7a", "clean_predictions": "#2a78d6",
                                             "adversarial_predictions": "#e34948", "patch": "#ffd400"},
        }
        artifacts = {
            "clean_boxes": sink.put(f"{prefix}/{CLEAN_PNG_NAME}", clean_png, "image/png"),
            "adv_boxes": sink.put(f"{prefix}/{ADV_PNG_NAME}", adv_png, "image/png"),
            "boxes": sink.put(f"{prefix}/{BOXES_JSON_NAME}", json_bytes(boxes_doc), "application/json"),
        }
        digests = {name: sink.sha256(path) for name, path in artifacts.items()}
        out.append(_observation(f"o.{i:03d}.{attack_id}", sample_index=int(sample.indices[i]),
                                class_names=sample.class_names, gt=gt, pred_clean=preds_clean[i], pred_adv=preds_adv[i],
                                matched_clean=np.asarray(matched_clean[i], dtype=bool),
                                matched_adv=np.asarray(matched_adv[i], dtype=bool), score_threshold=score_threshold,
                                artifacts=artifacts, digests=digests, patch=patch_dict))
    return out


# --- scorecard construction ---------------------------------------------------------------------------------

def _point(m: Measurement) -> AccuracyPoint:
    return AccuracyPoint(n=m.n, n_correct=m.n_correct, accuracy=m.accuracy if m.n > 0 else None)


def build_scorecard(config: CampaignConfig, attack_id: str, clean: Measurement, rows: Mapping[float, Measurement],
                    controls: Mapping[float, Measurement], *, score_threshold: float, iou_threshold: float,
                    shash: str) -> DetectionScorecard:
    grid = [float(e) for e in config.eps_grid]
    ref = float(config.reference_eps)
    n_gt = int(clean.n)
    clean_recall = clean.accuracy if n_gt > 0 else None
    ratios: list[float] = []
    worst: tuple[float | None, float | None] = (None, None)
    for e in grid:
        m = rows.get(e)
        if m is None or clean_recall is None or clean_recall <= 0.0:
            continue
        ratio = max(0.0, min(1.0, float(m.accuracy) / float(clean_recall)))
        ratios.append(ratio)
        if worst[0] is None or ratio < worst[0]:
            worst = (ratio, e)
    if clean_recall is None or clean_recall <= 0.0:
        why = f"clean recall is 0 ({clean.n_correct}/{n_gt} boxes matched); ratios undefined"
        worst_sc = ScoredCount(value=None, n=n_gt, reason=why)
        auc_sc = ScoredCount(value=None, n=n_gt, reason=why)
    else:
        worst_sc = ScoredCount(value=worst[0], n=n_gt, eps=worst[1])
        present = [e for e in grid if e in rows]
        auc_sc = ScoredCount(value=trapezoid_auc_normalized(present, ratios) if ratios else None, n=n_gt,
                             reason=None if ratios else "no evasion row on the grid")
    ref_row = rows.get(ref)
    if ref_row is None:
        ref_sc = ScoredCount(value=None, n=0, eps=ref, reason=f"no evasion row at the reference eps {ref:g}")
    elif ref_row.attack_success_rate is None:
        ref_sc = ScoredCount(value=None, n=int(ref_row.n_clean_correct or 0), eps=ref,
                             reason="suppression rate undefined (no clean box matched)")
    else:
        ref_sc = ScoredCount(value=float(ref_row.attack_success_rate), n=int(ref_row.n_clean_correct or 0), eps=ref)
    return DetectionScorecard(
        attack_id=attack_id, norm=str(config.norm), eps_grid=grid, reference_eps=ref, score_threshold=score_threshold,
        iou_threshold=iou_threshold, clean_recall=_point(clean), worst_case_recall_ratio=worst_sc,
        suppression_rate_at_reference=ref_sc,
        suppression_by_eps={f"{e:g}": rows[e].attack_success_rate for e in grid if e in rows},
        recall_by_eps={f"{e:g}": _point(rows[e]) for e in grid if e in rows},
        control_recall_by_eps={f"{e:g}": _point(controls[e]) for e in grid if e in controls},
        map50_clean=cast(float | None, clean.params.get("det_map50")),
        map50_by_eps={f"{e:g}": cast(float | None, rows[e].params.get("det_map50")) for e in grid if e in rows},
        recall_auc=auc_sc, settings_hash=shash, computed_at=utcnow(),
    )


# --- the modality runner (the frame's hook) ------------------------------------------------------------------

def run_detection(config: CampaignConfig, target: Target, *, frame: CampaignFrame) -> ModalityResult:
    """Sample, clean_eval, attack:<id> and control stages for an object detector, plus the explain closure.

    ``ModalityResult.n`` is the number of images in the slice (``config.n_samples`` semantics); every
    measurement row's own ``n`` counts ground-truth boxes and ``flip_matrix_extra`` carries ``n_gt_boxes``
    and the per-box suppression flags. ``flip_matrix[attack][eps]`` is per image: true when any of the
    image's clean-matched boxes was suppressed. ``mri`` is ``False`` with :data:`NO_MRI_REASON`."""
    tgt: Any = target
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
    if not is_detection_target(tgt):
        raise ValueError(f"target {tgt.id!r} is not an object detector (domain {info.domain!r}); use the "
                         "classification runner")
    if config.defense is not None:
        raise AttackNotApplicable("defense_modality_mismatch: preprocessing defenses on detectors are a Phase B2 "
                                  "item (MODALITIES-39); no verify run on a detection target yet")
    score_thr, iou_thr = _thresholds(tgt, manifest)
    shash = settings_hash(config, None if manifest_get(manifest, "model_sha256", "weights_sha256", "sha256") is None
                          else str(manifest_get(manifest, "model_sha256", "weights_sha256", "sha256")))

    # --- sample --------------------------------------------------------------------------------
    sample = tgt.sample(config.n_samples, config.seed)
    if not isinstance(sample, DetectionSample) or not getattr(sample, "targets", None):
        raise ValueError("a detection target's sample() must return a DetectionSample with per-image targets")
    x = np.asarray(sample.x, dtype=np.float32)
    y = np.asarray(sample.y).astype(int)
    n_images = int(x.shape[0])
    class_names = list(sample.class_names)
    gts = sample.targets
    n_boxes = sample.n_boxes
    dataset_name = frame.dataset_name
    slice_note = (f"slice: dataset={dataset_name}, split={config.dataset_split}, n_images={n_images}, "
                  f"n_gt_boxes={n_boxes}, seed={config.seed}, selection=target.sample(n, seed) by primary class")
    limitations.extend(f"Dataset caveat ({dataset_name}): {c}" for c in dataset_caveats(manifest, dict(info.metadata)))
    stage_done("sample")

    # --- clean_eval ----------------------------------------------------------------------------
    t0 = time.perf_counter()
    preds_clean = tgt.predict(x)
    ev_clean = evaluate_detections(preds_clean, gts, class_names, iou_threshold=iou_thr, score_threshold=score_thr)
    m_clean = measure_detection("m.clean", "clean", ev_clean, wall_time_s=time.perf_counter() - t0,
                                notes=[slice_note, AP_INTERPOLATION_NOTE])
    measurements.append(m_clean)
    matched_clean = [np.asarray(f, dtype=bool) for f in ev_clean.matched]
    n_clean_matched = int(m_clean.n_correct)
    stage_done("clean_eval")

    # --- attack --------------------------------------------------------------------------------
    max_adv_bytes = max_adv_artifact_bytes()
    flip_matrix: dict[str, dict[str, list[bool]]] = {}
    suppressed_boxes: dict[str, dict[str, list[list[bool]]]] = {}
    rows_by_attack: dict[str, dict[float, Measurement]] = {}
    evidence_inputs: dict[str, dict[str, Any]] = {}     # attack -> what the explain closure draws at the reference eps
    for adapter in adapters:
        aid = adapter.id
        rows_by_eps: dict[float, Measurement] = {}
        try:
            outputs = []
            for e in grid:
                p = adapter.resolve_params({**params_by_attack[aid], "eps": e})
                out = _run_adapter(adapter, tgt, x, y, p, config.seed, gts)
                versions.update(out.library_versions)
                outputs.append((e, out))
        except AttackNotApplicable as exc:
            frame.record_not_run(aid, str(exc) or type(exc).__name__)
            continue
        flip_matrix[aid] = {}
        suppressed_boxes[aid] = {}
        for e, out in outputs:
            row_notes, nd = split_notes(list(out.notes), NONDETERMINISM_PREFIX)
            nondeterminism.extend(nd)
            x_adv = np.asarray(out.x_adv, dtype=np.float32)
            t1 = time.perf_counter()
            preds_adv = tgt.predict(x_adv)
            ev = evaluate_detections(preds_adv, gts, class_names, iou_threshold=iou_thr, score_threshold=score_thr)
            m = measure_detection(f"m.evasion.{aid}.{eps_tag(e)}", "evasion", ev, attack_id=aid,
                                  params={**out.params, "eps": e, "norm": config.norm, "budget": "patch_area"},
                                  x_ref=x, x_adv=x_adv, clean_matched=matched_clean,
                                  wall_time_s=float(out.wall_time_s) + (time.perf_counter() - t1), notes=row_notes)
            per_box = [[bool(c and not a) for c, a in zip(mc, ma, strict=True)]
                       for mc, ma in zip(matched_clean, ev.matched, strict=True)]
            suppressed_boxes[aid][eps_tag(e)] = per_box
            flip_matrix[aid][eps_tag(e)] = [any(flags) for flags in per_box]
            rows_by_eps[e] = m
            measurements.append(m)
            blob = _npz_bytes(x_adv, np.asarray(sample.indices), gts)
            if len(blob) <= max_adv_bytes:
                sink.put(f"adv_slice/{aid}_{eps_tag(e)}.npz", blob, "application/octet-stream")
            else:
                m.notes.append("full adversarial slice not retained (over REDSIM_ML_MAX_ADV_ARTIFACT_MB)")
            if math.isclose(e, ref, abs_tol=1e-12):
                side = out.params.get("patch_side")
                evidence_inputs[aid] = {
                    "x_adv": x_adv, "preds_adv": preds_adv,
                    "matched_adv": [np.asarray(f, dtype=bool) for f in ev.matched],
                    "patch_side": int(side) if side is not None else None,
                    "locations": (_dpatch.patch_locations(n_images, int(x.shape[2]), int(x.shape[3]), int(side),
                                                          config.seed) if side is not None else None),
                }
        rows_by_attack[aid] = rows_by_eps
        fi = finding_inputs(config, measurements, aid)
        for e, m in rows_by_eps.items():
            if not fi.denominator_ok:
                m.notes.append(f"denominator too small for a finding (n_clean_correct={n_clean_matched} boxes < "
                               f"{MIN_CLEAN_CORRECT_FOR_FINDING}); no Finding is created from this row")
            elif m.attack_success_rate is not None and m.attack_success_rate >= config.finding_asr_threshold:
                m.notes.append(f"suppression rate {m.attack_success_rate:.4f} crosses finding_asr_threshold "
                               f"{config.finding_asr_threshold:g} (first success at patch area {fi.first_success_eps:g})")
        stage_done(f"attack:{aid}")
    in_scope = frame.close_attack_set()
    in_scope_ids = [a.id for a in in_scope]

    # --- control -------------------------------------------------------------------------------
    controls_by_eps: dict[float, Measurement] = {}
    if config.include_control:
        control = _dpatch.CONTROL
        for e in grid:
            p = control.resolve_params({"eps": e})
            out = _run_adapter(control, tgt, x, y, p, config.seed, gts)
            row_notes, nd = split_notes(list(out.notes), NONDETERMINISM_PREFIX)
            nondeterminism.extend(nd)
            x_ctrl = np.asarray(out.x_adv, dtype=np.float32)
            preds_ctrl = tgt.predict(x_ctrl)
            ev = evaluate_detections(preds_ctrl, gts, class_names, iou_threshold=iou_thr, score_threshold=score_thr)
            m = measure_detection(f"m.control.noise.{eps_tag(e)}", "control", ev, attack_id=CONTROL_ATTACK_ID,
                                  params={**out.params, "eps": e, "norm": config.norm, "budget": "patch_area"},
                                  x_ref=x, x_adv=x_ctrl, clean_matched=matched_clean, wall_time_s=out.wall_time_s,
                                  notes=[*row_notes, CONTROL_NOTE])
            preserved = control_preserves_accuracy(m_clean, m) if m_clean.n > 0 else False
            if preserved:
                m.notes.append(f"control preserves recall at patch area {e:g}: {m.n_correct}/{m.n} boxes against "
                               f"clean {m_clean.n_correct}/{m_clean.n} (spec 12.4 predicate)")
            elif m_clean.n > 0:
                m.notes.append(f"a random patch alone reduced recall from {m_clean.n_correct}/{m_clean.n} to "
                               f"{m.n_correct}/{m.n} boxes at patch area {e:g}; the control did not preserve recall")
                interpretation.append(Interpretation(
                    id=f"i.control.occlusion_sensitive.{eps_tag(e)}",
                    statement=(f"The detector is occlusion-sensitive at patch area {e:g}: a random patch of the same "
                               f"area reduced recall from {m_clean.n_correct}/{m_clean.n} to {m.n_correct}/{m.n} "
                               "boxes (spec 12.4 predicate not met); suppression at this budget is not attributable "
                               "to patch optimisation alone."),
                    basis=["m.clean", m.id]))
                limitations.append(f"A random patch alone reduced recall at patch area {e:g} "
                                   f"({m_clean.n_correct}/{m_clean.n} -> {m.n_correct}/{m.n} boxes); suppression at "
                                   "this budget is not attributable to patch optimisation alone.")
            controls_by_eps[e] = m
            measurements.append(m)
        stage_done("control")
    else:
        limitations.append("The benign patch control was disabled for this run (include_control=false); "
                           "optimised suppression cannot be separated from occlusion sensitivity.")

    # --- the detection scorecard and its statements (never an MRI) --------------------------------
    scorecards: dict[str, DetectionScorecard] = {}
    for aid in in_scope_ids:
        scorecards[aid] = build_scorecard(frame.scoring_config, aid, m_clean, rows_by_attack[aid], controls_by_eps,
                                          score_threshold=score_thr, iou_threshold=iou_thr, shash=shash)
    if scorecards:
        payload = {"kind": "detection_scorecards", "reason_no_mri": NO_MRI_REASON,
                   "per_attack": {aid: c.model_dump(mode="json") for aid, c in scorecards.items()}}
        validate_scorecard_payload(payload)
        sink.put(SCORECARD_NAME, json_bytes(payload), "application/json")
    try:  # the guard is exercised on every run: detection rows must be refused by compute_mri
        refuse_mri(measurements)
    except DetectionMRIRefused:
        pass
    else:  # pragma: no cover - measure_detection always stamps det_n_boxes
        raise RuntimeError("detection rows were not recognised by the MRI guard; refusing to continue")
    interpretation.extend(detection_interpretations(config, m_clean, rows_by_attack, controls_by_eps, scorecards))

    # --- explain closure (run by the frame after the curve and flip-matrix artifacts) -----------------
    def explain() -> None:
        unavailable = ExplainerUnavailable(EXPLAINER_UNAVAILABLE_REASON)
        for aid in in_scope_ids:
            ref_row_id = f"m.evasion.{aid}.{eps_tag(ref)}"
            interpretation.append(Interpretation(
                id=f"i.explain.unavailable.{aid}",
                statement=(f"Explanations are unavailable for attack {aid!r} at patch area {ref:g} "
                           f"(ExplainerUnavailable: {unavailable}); no attribution evidence was recorded and S_expl "
                           "has no input. Observations carry drawn boxes and a boxes.json per image instead."),
                basis=[ref_row_id]))
            limitations.append(f"Explain stage unavailable for {aid!r}: ExplainerUnavailable: {unavailable}.")
            ev_in = evidence_inputs.get(aid)
            if ev_in is None:
                continue
            try:
                observations.extend(write_box_evidence(
                    sink, attack_id=aid, eps=ref, sample=sample, x_adv=ev_in["x_adv"], preds_clean=preds_clean,
                    preds_adv=ev_in["preds_adv"], matched_clean=matched_clean, matched_adv=ev_in["matched_adv"],
                    patch_side=ev_in["patch_side"], patch_locations=ev_in["locations"], score_threshold=score_thr,
                    k=config.explain_k))
            except Exception as exc:  # noqa: BLE001 - evidence rendering never fails the run
                limitations.append(f"Box evidence for {aid!r} not written ({type(exc).__name__}: {exc}).")
        limitations.append(EXPLAIN_LIMITATION)

    return ModalityResult(
        n=n_images, indices=np.asarray(sample.indices), flip_matrix=flip_matrix, explain=explain, curves=True,
        mri=False, score_unavailable_reason=NO_MRI_REASON, trailing_limitations=list(TRAILING_LIMITATIONS),
        flip_matrix_extra={"n_gt_boxes": n_boxes, "budget": "patch_area",
                           "clean_matched_boxes": [[bool(v) for v in mc] for mc in matched_clean],
                           "suppressed_boxes": suppressed_boxes,
                           "note": ("flipped[attack][eps][image] is true when any clean-matched box of the image was "
                                    "suppressed; suppressed_boxes[attack][eps][image][box] holds the per-box flags")},
    )


def detection_interpretations(config: CampaignConfig, clean: Measurement,
                              rows_by_attack: Mapping[str, Mapping[float, Measurement]],
                              controls: Mapping[float, Measurement],
                              scorecards: Mapping[str, DetectionScorecard]) -> list[Interpretation]:
    """Detection-worded I1 / I2, the suppression statement and the scorecard statement per attack.

    Ids are ``i.detection.*`` so they never collide with the generic rule layer's ``i.<k>`` ids; every basis id
    is a measurement id that exists in the inputs."""
    ref = float(config.reference_eps)
    thr = config.scoring.interpretation
    ctrl_ref = controls.get(ref)
    out: list[Interpretation] = []
    for aid, rows in rows_by_attack.items():
        ref_row = rows.get(ref)
        card = scorecards.get(aid)
        if ref_row is None or card is None:
            continue
        ctrl_flat = ctrl_ref is not None and clean.n > 0 and control_preserves_accuracy(clean, ctrl_ref)
        drop = float(clean.accuracy) - float(ref_row.accuracy)
        if ctrl_ref is not None and ctrl_flat and drop > thr.evasion_drop:
            out.append(Interpretation(
                id=f"i.detection.I1.{aid}",
                statement=(f"I1: a random patch at area {ref:g} did not reduce recall ({ctrl_ref.n_correct}/{ctrl_ref.n} "
                           f"boxes) while {aid} did ({ref_row.n_correct}/{ref_row.n}, drop {drop:.3f} > "
                           f"{thr.evasion_drop:g}). The suppression is aligned with the detector's loss gradient "
                           "rather than with occlusion alone."),
                basis=["m.clean", ref_row.id, ctrl_ref.id]))
        if (ctrl_ref is not None and not ctrl_flat
                and (float(clean.accuracy) - float(ctrl_ref.accuracy)) > thr.control_drop):
            out.append(Interpretation(
                id=f"i.detection.I2.{aid}",
                statement=(f"I2: a random patch at area {ref:g} also reduced recall ({clean.n_correct}/{clean.n} -> "
                           f"{ctrl_ref.n_correct}/{ctrl_ref.n} boxes, drop > {thr.control_drop:g}). Part of the "
                           "patch effect is occlusion sensitivity, not only adversarial structure."),
                basis=[ctrl_ref.id, "m.clean"]))
        if ref_row.attack_success_rate is not None:
            out.append(Interpretation(
                id=f"i.detection.suppression.{aid}",
                statement=(f"{aid} suppressed {ref_row.n_flipped_from_clean}/{ref_row.n_clean_correct} clean-matched "
                           f"boxes at patch area {ref:g} (suppression rate {ref_row.attack_success_rate:.3f}); recall "
                           f"fell from {clean.n_correct}/{clean.n} to {ref_row.n_correct}/{ref_row.n} boxes."),
                basis=["m.clean", ref_row.id]))
        worst = card.worst_case_recall_ratio
        auc = card.recall_auc
        out.append(Interpretation(
            id=f"i.detection.scorecard.{aid}",
            statement=("Detection scorecard: worst-case recall ratio "
                       + (f"{worst.value:.3f} at patch area {worst.eps:g}" if worst.value is not None
                          else f"unavailable ({worst.reason})")
                       + f" over {worst.n} ground-truth boxes; recall AUC over the patch-area grid "
                       + (f"{auc.value:.3f}" if auc.value is not None else "unavailable")
                       + ". No MRI is computed for detection (S_conf undefined, S_expl unavailable)."),
            basis=["m.clean", *[rows[e].id for e in sorted(rows)]]))
    return out


def detection_recommendations(config: CampaignConfig, measurements: Sequence[Measurement],
                              interpretation: Sequence[Interpretation]) -> list[CandidateRecommendation]:
    """R6 / R8 candidates for detection rows (spec 16.2 detection branch, register MODALITIES-38).

    Emitted per attack whose suppression rate crossed ``finding_asr_threshold`` at some patch area with a
    denominator of at least ``MIN_CLEAN_CORRECT_FOR_FINDING`` clean-matched boxes. Direction only: no gain
    is stated until a verify run measures a recall delta. The rule layer's detection branch can call this."""
    known = {m.id for m in measurements} | {i.id for i in interpretation}
    out: list[CandidateRecommendation] = []
    for aid in dict.fromkeys(config.attack_ids):
        if not any(m.attack_id == aid and is_detection_measurement(m) for m in measurements):
            continue
        fi = finding_inputs(config, measurements, aid)
        if not (fi.crosses_threshold and fi.denominator_ok and fi.first_success_eps is not None):
            continue
        basis = [b for b in (f"m.evasion.{aid}.{eps_tag(fi.first_success_eps)}", f"i.detection.suppression.{aid}")
                 if b in known]
        if not basis:
            continue
        asr_txt = f"{fi.asr_at_first_success:.3f}" if fi.asr_at_first_success is not None else "n/a"
        out.extend([
            CandidateRecommendation(
                id=f"r.R8.patch_adversarial_training.{aid}", title="Patch-aware adversarial training (candidate)",
                rationale=(f"{aid} crossed the suppression threshold {fi.threshold:g} at patch area "
                           f"{fi.first_success_eps:g} (suppression {asr_txt}). Fine-tuning on patched images is the "
                           "direction the DPatch literature reports; no gain is claimed until a verify run measures "
                           "the recall delta."),
                triggered_by=basis, references=[R8_REFERENCES[0], R8_REFERENCES[1], "defense:adversarial_training"]),
            CandidateRecommendation(
                id=f"r.R8.occlusion_detection.{aid}", title="Input anomaly or occlusion detection (candidate)",
                rationale=("A localised high-saliency patch is detectable as an input anomaly before inference; "
                           "certified patch defenses bound the effect of a patch of known maximum area. Direction "
                           "only; not evaluated on this model."),
                triggered_by=basis, references=[R8_REFERENCES[2]]),
            CandidateRecommendation(
                id=f"r.R8.multi_frame_consistency.{aid}", title="Multi-frame consistency checks (candidate)",
                rationale=("Detections that vanish under a static patch while the scene is unchanged can be flagged "
                           "by temporal consistency across frames; applicable only where the deployment sees "
                           "sequences. Not evaluated here."),
                triggered_by=basis, references=[R8_REFERENCES[1]]),
            CandidateRecommendation(
                id=f"r.R6.preprocessing.{aid}", title="Input preprocessing defenses (candidate)",
                rationale=("Recall dropped under the patch attack; ART preprocessing defenses (JPEG compression, "
                           "spatial smoothing) attach to the detector and can be measured in a verify run (Phase "
                           "B2). Direction only."),
                triggered_by=basis, references=["defense:jpeg_compression", "defense:spatial_smoothing"]),
        ])
    return out


# --- standalone frame (until run_campaign dispatches the detection modality) ---------------------------------

def run_detection_campaign(config: CampaignConfig, sink: ArtifactSink, *, target: Target | None = None,
                           explain: bool = True, on_stage: Callable[[str], None] | None = None,
                           baseline_run_id: str | None = None, parent_run_id: str | None = None,
                           target_override: Target | None = None) -> CampaignRecord:
    """Run one detection campaign end to end and return its ``CampaignRecord`` (status ``succeeded``, no MRI).

    The same stages ``redsim.ml.campaign.run_campaign`` performs around :func:`run_detection`, in a frame this
    module owns, so a tree whose ``CampaignConfig.modality`` cannot yet say ``detection`` (before the B0 schema
    literals) still runs the modality. ``target`` (or ``target_override``) bypasses the registry."""
    started_at = utcnow()
    run_id = uuid.uuid4().hex
    tgt: Any = target or target_override or TARGETS.maybe_get(config.target_id)
    if tgt is None:
        raise TargetUnavailable(f"unknown target {config.target_id!r}")
    info = tgt.info()
    if info.status != "available":
        raise TargetUnavailable(info.reason or f"target {config.target_id!r} is {info.status}")
    if not is_detection_target(tgt):
        raise ValueError(f"target {tgt.id!r} is not an object detector (domain {info.domain!r}); use run_campaign")
    if str(config.modality) not in (MODALITY, DETECTION_MODALITY):
        raise ValueError(f"config.modality {config.modality!r} does not name the detection modality")
    tgt.load()
    manifest = dict(tgt.manifest() or {})
    model_sha256 = manifest_get(manifest, "model_sha256", "weights_sha256", "sha256")
    adapters = resolve_detection_adapters(config)
    params_by_attack: dict[str, dict[str, Any]] = {a.id: dict(config.attack_params.get(a.id, {})) for a in adapters}
    grid = [float(e) for e in config.eps_grid]
    ref = float(config.reference_eps)
    for a in adapters:  # validate bounds before running anything (spec 12.1)
        for e in grid:
            a.resolve_params({**params_by_attack[a.id], "eps": e})
    shash = settings_hash(config, None if model_sha256 is None else str(model_sha256))
    dataset_name = (manifest_get(manifest, "dataset", "dataset_id", "dataset_name")
                    or info.metadata.get("dataset") or config.dataset_id)
    dataset_revision = config.dataset_revision or manifest_get(manifest, "dataset_revision", "revision")
    frame = CampaignFrame(
        config=config, sink=sink, target=tgt, info=info, domain=MODALITY, manifest=manifest, adapters=adapters,
        params_by_attack=params_by_attack, grid=grid, ref=ref, l2=False, attack_registry=ATTACKS, explain=explain,
        dataset_name=dataset_name, dataset_revision=dataset_revision, subject_centered=None, on_stage=on_stage,
        nondeterminism=[CPU_FLOAT32_NOTE], versions=library_versions(),
    )
    frame.stage_done("load_target")

    result = run_detection(config, tgt, frame=frame)
    in_scope = frame.close_attack_set()
    in_scope_ids = frame.in_scope_ids
    measurements = frame.measurements
    limitations = frame.limitations

    curves: list[RobustnessCurve] = robustness_curves(frame.scoring_config, measurements) if in_scope else []
    for curve in curves:
        sink.put(f"curve/{curve.attack_id}.json", curve.model_dump_json(indent=2).encode("utf-8"), "application/json")
    sink.put(FLIP_MATRIX_NAME, json_bytes({"attack_ids": in_scope_ids, "eps_grid": grid, "n": int(result.n),
                                           "norm": config.norm, "not_run": frame.not_run,
                                           "indices": [int(i) for i in np.asarray(result.indices)],
                                           "flipped": result.flip_matrix, **result.flip_matrix_extra}),
             "application/json")

    if explain and config.explain_k > 0 and in_scope:
        if result.explain is not None:
            result.explain()
        frame.stage_done("explain")
    else:
        why = "explain disabled" if not explain else "explain_k = 0" if config.explain_k <= 0 else "no in-scope attack ran"
        limitations.append(f"Explanations were not attempted ({why}); no observation was recorded.")

    score_reason = (result.score_unavailable_reason or NO_MRI_REASON) if in_scope else (
        "MRI not computed: no declared attack ran against this target (not_run: "
        + "; ".join(f"{k}: {v}" for k, v in frame.not_run.items()) + "). Nothing to score.")
    limitations.append(score_reason)
    if len(grid) == 1:
        limitations.append(ONE_POINT_GRID_LIMITATION)
    frame.stage_done("score")
    frame.stage_done("interpret")   # the detection statements were appended by the runner

    recommendations: list[CandidateRecommendation] = []
    if config.auto_recommend:
        recommendations = detection_recommendations(config, measurements, frame.interpretation)
        frame.stage_done("recommend")
    else:
        limitations.append("auto_recommend=false: no candidate recommendations were generated in this run.")
    limitations.append("No LLM narrative is produced in the sandbox child; recommendations carry rule text only.")

    finished_at = utcnow()
    versions = frame.versions
    all_limitations = (standing_limitations(str(dataset_name), grid) + [D3_BOUNDS_LIMITATION] + limitations
                       + list(result.trailing_limitations))
    provenance = Provenance(
        redsim_version=_dist_version("redsim-platform"), python=platform.python_version(),
        torch=versions.get("torch", "not installed"), art=versions.get("art", "not installed"),
        shap=_dist_version("shap"), numpy=versions.get("numpy", np.__version__),
        onnxruntime=versions.get("onnxruntime"), sklearn=versions.get("scikit-learn"), xgboost=versions.get("xgboost"),
        model_sha256=None if model_sha256 is None else str(model_sha256), dataset=str(dataset_name),
        dataset_revision=None if dataset_revision is None else str(dataset_revision), dataset_split=config.dataset_split,
        sample_indices_sha256=sha256_indices(result.indices), settings_hash=shash,
        baseline_run_id=baseline_run_id, parent_run_id=parent_run_id, defense=None, llm=None,
        thread_env={},
        model_manifest={**manifest, "seed": config.seed, "n_samples": int(result.n),
                        "n_gt_boxes": result.flip_matrix_extra.get("n_gt_boxes"), "library_versions": versions,
                        "python_executable": sys.executable, "modality": MODALITY},
        started_at=started_at, finished_at=finished_at, hostname=socket.gethostname(),
        device=str(manifest.get("device") or "cpu"), nondeterminism=uniq(frame.nondeterminism),
    )
    frame.stage_done("report")
    record = CampaignRecord(
        run_id=run_id, status="succeeded", stage="report", stages_done=frame.stages_done, created_at=started_at,
        config=config, target=info, attacks=[a.info() for a in in_scope], provenance=provenance,
        measurements=measurements, observations=frame.observations, interpretation=frame.interpretation,
        recommendations=recommendations, score=None, limitations=uniq(all_limitations), kind="attack",
        completed_at=finished_at, settings_hash=shash, baseline_run_id=baseline_run_id, parent_run_id=parent_run_id,
        curve=curves, completeness="partial",
        missing=["S_conf unavailable (conf_gap undefined for detection)",
                 f"S_expl unavailable ({EXPLAINER_UNAVAILABLE_REASON})",
                 f"MRI not computed by construction; see {SCORECARD_NAME}"],
        score_status=ScoreStatus(state="unavailable", reason=score_reason),
    )
    sink.put("run_record.json", record.model_dump_json(indent=2).encode("utf-8"), "application/json")
    return record


__all__ = [
    "ADV_PNG_NAME", "BOXES_JSON_NAME", "CLEAN_PNG_NAME", "CONF_GAP_NOTE", "CONTROL_ATTACK_ID", "DETECTION_STANDING",
    "EXPLAIN_LIMITATION", "FLIP_MATRIX_NAME", "FORBIDDEN_SCORECARD_KEYS", "NO_MRI_LIMITATION", "NO_MRI_REASON",
    "PATCH_LIMITATION", "R8_REFERENCES", "RECALL_LIMITATION", "RECALL_NOTE", "SCORECARD_NAME", "SUPPRESSION_NOTE",
    "TRAILING_LIMITATIONS", "DetectionMRIRefused", "DetectionScorecard", "ScoredCount", "build_scorecard",
    "compute_mri", "detection_interpretations", "detection_recommendations", "is_detection_measurement",
    "measure_detection", "refuse_mri", "resolve_detection_adapters", "run_detection", "run_detection_campaign",
    "validate_scorecard_payload", "write_box_evidence",
]
