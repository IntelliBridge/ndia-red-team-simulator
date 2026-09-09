"""Object-detection targets (spec 12.1 detection row; register MODALITIES-29..31, -36).

Three things live here because they share one contract and one owner:

* the schema constants (``DETECTION_DOMAIN``, ``DETECTION_MODALITY``, ``PATCH_AREA_NORM``): the
  ``"detection"`` ``Domain`` / ``Modality`` literal and the ``"patch_area"`` ``Norm`` literal a detection
  campaign, its target and its adapters are typed against, plus ``detection_spec_block`` (the manifest's
  ``detection`` block on ``schema.DetectionModelSpec``);
* the in-repo detection evaluation (``match_boxes``, ``evaluate_detections``): greedy per-image IoU
  matching at one threshold and one score threshold, recall with its box denominators, per-class
  ``n`` / ``n_correct`` counts, all-point-interpolated AP averaged over classes with ground truth
  (``map50``). No pycocotools or torchmetrics; the interpolation convention is stated on every row so
  nobody compares it with published COCO numbers;
* the detector architecture (torchvision ``fasterrcnn_mobilenet_v3_large_320_fpn``, COCO weights from the
  local torch hub cache only, else random init recorded) and ``BundledDetectionTarget``, which reads
  ``assets/MANIFEST.json`` like ``BundledImageTarget`` and exposes an ART ``PyTorchFasterRCNN`` through
  ``art_estimator()`` (``art_classifier()`` returns the same object so the ``Target`` protocol holds).

A detector is not a classifier: ``predict_proba`` raises ``AttackNotApplicable`` and no MRI is ever
computed from detection rows (``redsim.ml.runners.detection`` builds a detection scorecard instead).
Labels inside the torchvision model are 1-based (0 is background); every public surface here uses the
0-based indices of ``class_names`` and ``LABEL_OFFSET`` says how the two relate.
"""

from __future__ import annotations

import platform
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Protocol, cast, runtime_checkable

import numpy as np

from redsim.ml.datasets import DatasetUnavailable
from redsim.ml.datasets.military_assets import (
    DetectionSplit,
    load_detection_npz,
    primary_labels,
    stratified_detection_indices,
)
from redsim.ml.datasets.sampling import Sample, as_model_input
from redsim.ml.errors import (
    ArtifactDigestMismatch,
    AttackNotApplicable,
    TargetUnavailable,
    UnsupportedArtifact,
)
from redsim.ml.schema import DetectionModelSpec, Domain, Modality, Norm, TargetInfo, TargetStatus
from redsim.ml.targets.artifact import library_versions, model_manifest, sha256_file, verify_sha256
from redsim.ml.targets.bundled import (
    BUILD_HINT,
    MANIFEST_NAME,
    architecture_kwargs,
    assets_dir,
    clean_accuracy_entry,
    manifest_entry,
    read_manifest,
    register_once,
    resolve_asset_path,
    resolve_eval_split,
    verify_bundled_entry,
    weights_ref,
)

# --- schema constants (spec 12.1 detection row; ``schema.Domain`` / ``Modality`` / ``Norm`` literals) ---------

MODALITY = "detection"
DETECTION_DOMAIN: Final[Domain] = "detection"
DETECTION_MODALITY: Final[Modality] = "detection"
PATCH_AREA_NORM: Final[Norm] = "patch_area"
#: ``Measurement.detection`` (``DetectionMetrics``) and ``Observation.detection`` (``DetectionObservation``) are
#: schema fields; the runner fills them on every detection row beside the scalar ``det_*`` params.
MEASUREMENT_HAS_DETECTION: Final = True
OBSERVATION_HAS_DETECTION: Final = True
BUDGET_LABEL = "patch area (share of image)"

# torchvision detection label space: 0 is background, classes start at 1.
LABEL_OFFSET = 1
ARCHITECTURE_ID = "fasterrcnn_mobilenet_v3_large_320_fpn"
COCO_CHECKPOINT_FILENAME = "fasterrcnn_mobilenet_v3_large_320_fpn-907ea3f9.pth"
BUNDLED_DETECTOR_ID = "assets_frcnn_mnv3"
DEFAULT_SCORE_THRESHOLD = 0.5
DEFAULT_IOU_THRESHOLD = 0.5
DEFAULT_INPUT_SIZE = 320
AP_INTERPOLATION_NOTE = ("AP is all-point interpolated over the precision envelope at IoU >= 0.5 (not the "
                         "101-point COCO convention); not comparable with published COCO numbers")
NO_CLASSIFIER_REASON = "an object detector is not a classifier: predict_proba is undefined; use predict()"
EXPLAINER_UNAVAILABLE_REASON = "no SHAP explainer for object detectors"


# --- detection spec block (``MLModelManifest.detection: schema.DetectionModelSpec``) -------------------

def detection_spec_block(*, score_threshold: float, iou_threshold: float, class_names: Sequence[str],
                         input_size: Sequence[int], excluded_classes: Sequence[str] = ()) -> dict[str, Any]:
    """The ``detection`` manifest block: ``schema.DetectionModelSpec`` dumped in field order.

    ``class_names`` are the detector's classes in index order (the spec field is ``classes``);
    ``input_size`` may be given as ``[C, H, W]`` (the slice shape) or ``[H, W]`` (what the spec records).
    Boxes are ``xyxy`` in pixels everywhere in this module. A shape the spec rejects is a bug and raises.
    """
    size = [int(d) for d in input_size]
    if len(size) == 3:
        size = size[1:]
    spec = DetectionModelSpec(
        box_format="xyxy", input_size=size, iou_threshold=float(iou_threshold), score_threshold=float(score_threshold),
        classes=[str(c) for c in class_names], excluded_classes=[str(c) for c in excluded_classes],
    )
    return spec.model_dump(mode="json")


# --- samples ------------------------------------------------------------------------------------------

@dataclass
class DetectionSample(Sample):
    """A ``Sample`` whose ``y`` is the per-image primary class and whose ``targets`` hold the boxes.

    ``targets[i]`` is ``{"boxes": (k, 4) float32 xyxy in pixels, "labels": (k,) int64 0-based}``. ``y`` keeps the
    classification shape so stratification and per-class counting keep working; it is never a prediction target.
    """

    targets: list[dict[str, np.ndarray]] = field(default_factory=list)

    @property
    def n_boxes(self) -> int:
        return int(sum(int(t["boxes"].shape[0]) for t in self.targets))


def detection_sample(split: DetectionSplit, n: int, seed: int) -> DetectionSample:
    """Seeded stratified slice of a ``DetectionSplit`` (by primary class), pixels as float32 in [0, 1]."""
    idx = stratified_detection_indices(split, n, seed)
    sub = split.subset(idx)
    return DetectionSample(
        x=as_model_input(sub.x), y=primary_labels(sub.labels, len(sub.class_names)), indices=np.asarray(sub.indices),
        class_names=list(sub.class_names), targets=sub.targets(),
    )


# --- evaluation ---------------------------------------------------------------------------------------

def box_iou(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Pairwise IoU of xyxy boxes ``a`` (n, 4) and ``b`` (m, 4) -> (n, m)."""
    a = np.asarray(a, dtype=np.float64).reshape(-1, 4)
    b = np.asarray(b, dtype=np.float64).reshape(-1, 4)
    if a.shape[0] == 0 or b.shape[0] == 0:
        return np.zeros((a.shape[0], b.shape[0]), dtype=np.float64)
    x0 = np.maximum(a[:, None, 0], b[None, :, 0])
    y0 = np.maximum(a[:, None, 1], b[None, :, 1])
    x1 = np.minimum(a[:, None, 2], b[None, :, 2])
    y1 = np.minimum(a[:, None, 3], b[None, :, 3])
    inter = np.clip(x1 - x0, 0.0, None) * np.clip(y1 - y0, 0.0, None)
    area_a = np.clip(a[:, 2] - a[:, 0], 0.0, None) * np.clip(a[:, 3] - a[:, 1], 0.0, None)
    area_b = np.clip(b[:, 2] - b[:, 0], 0.0, None) * np.clip(b[:, 3] - b[:, 1], 0.0, None)
    union = area_a[:, None] + area_b[None, :] - inter
    with np.errstate(divide="ignore", invalid="ignore"):
        iou = np.where(union > 0, inter / union, 0.0)
    return np.asarray(iou, dtype=np.float64)


def match_boxes(pred_boxes: np.ndarray, pred_labels: np.ndarray, pred_scores: np.ndarray,
                gt_boxes: np.ndarray, gt_labels: np.ndarray, *, iou_threshold: float = DEFAULT_IOU_THRESHOLD
                ) -> tuple[np.ndarray, np.ndarray]:
    """Greedy one-to-one matching for one image: predictions in descending score order each take the
    unmatched same-class ground-truth box of highest IoU when that IoU is at least ``iou_threshold``.

    Returns ``(gt_matched (n_gt,) bool, pred_tp (n_pred,) bool)`` in the input order of both arrays. A second
    prediction on an already matched box is a false positive (counted once for recall)."""
    pb = np.asarray(pred_boxes, dtype=np.float64).reshape(-1, 4)
    pl = np.asarray(pred_labels, dtype=np.int64).ravel()
    ps = np.asarray(pred_scores, dtype=np.float64).ravel()
    gb = np.asarray(gt_boxes, dtype=np.float64).reshape(-1, 4)
    gl = np.asarray(gt_labels, dtype=np.int64).ravel()
    if pb.shape[0] != pl.shape[0] or pb.shape[0] != ps.shape[0]:
        raise ValueError("prediction boxes, labels and scores must have one row per prediction")
    if gb.shape[0] != gl.shape[0]:
        raise ValueError("ground-truth boxes and labels must have one row per box")
    gt_matched = np.zeros(gb.shape[0], dtype=bool)
    pred_tp = np.zeros(pb.shape[0], dtype=bool)
    if pb.shape[0] == 0 or gb.shape[0] == 0:
        return gt_matched, pred_tp
    iou = box_iou(pb, gb)
    order = np.argsort(-ps, kind="stable")
    for p in order:
        candidates = (gl == pl[p]) & ~gt_matched & (iou[p] >= float(iou_threshold))
        if not candidates.any():
            continue
        best = int(np.argmax(np.where(candidates, iou[p], -1.0)))
        gt_matched[best] = True
        pred_tp[p] = True
    return gt_matched, pred_tp


def average_precision(scores: np.ndarray, tp: np.ndarray, n_gt: int) -> float | None:
    """All-point-interpolated AP for one class from per-prediction ``(score, tp)`` rows; ``None`` when ``n_gt`` is 0."""
    if n_gt <= 0:
        return None
    s = np.asarray(scores, dtype=np.float64).ravel()
    t = np.asarray(tp, dtype=bool).ravel()
    if s.shape[0] == 0:
        return 0.0
    order = np.argsort(-s, kind="stable")
    tp_cum = np.cumsum(t[order].astype(np.float64))
    fp_cum = np.cumsum((~t[order]).astype(np.float64))
    recall = tp_cum / float(n_gt)
    precision = tp_cum / np.maximum(tp_cum + fp_cum, 1e-12)
    mrec = np.concatenate([[0.0], recall, [1.0]])
    mpre = np.concatenate([[0.0], precision, [0.0]])
    for i in range(mpre.shape[0] - 2, -1, -1):
        mpre[i] = max(mpre[i], mpre[i + 1])
    steps = np.flatnonzero(mrec[1:] != mrec[:-1])
    return float(np.sum((mrec[steps + 1] - mrec[steps]) * mpre[steps + 1]))


@dataclass
class DetectionEval:
    """Counts first: ``n_gt`` boxes, ``n_matched`` of them at IoU >= ``iou_threshold`` and score >= ``score_threshold``.

    ``recall`` is ``n_matched / n_gt`` (``None`` when ``n_gt`` is 0), ``map50`` the mean AP over classes with ground
    truth (``None`` when no class has any), ``matched[i]`` the per-box flags of image ``i`` (the flip matrix for
    detection), ``per_class`` the ``{"n", "n_correct"}`` box counts the ``Measurement`` row carries."""

    n_images: int
    n_gt: int
    n_matched: int
    n_predictions: int
    recall: float | None
    map50: float | None
    per_class: dict[str, dict[str, int]]
    matched: list[np.ndarray]
    mean_matched_score: float | None
    iou_threshold: float
    score_threshold: float
    ap_per_class: dict[str, float | None] = field(default_factory=dict)

    def as_metrics(self) -> dict[str, Any]:
        return {"n_images": self.n_images, "n_gt_boxes": self.n_gt, "n_matched": self.n_matched,
                "n_predictions": self.n_predictions, "recall": self.recall, "map50": self.map50,
                "mean_matched_score": self.mean_matched_score, "per_class": dict(self.per_class),
                "ap_per_class": dict(self.ap_per_class), "iou_threshold": self.iou_threshold,
                "score_threshold": self.score_threshold, "interpolation": AP_INTERPOLATION_NOTE}


def evaluate_detections(predictions: Sequence[Mapping[str, np.ndarray]], targets: Sequence[Mapping[str, np.ndarray]],
                        class_names: Sequence[str], *, iou_threshold: float = DEFAULT_IOU_THRESHOLD,
                        score_threshold: float = DEFAULT_SCORE_THRESHOLD) -> DetectionEval:
    """Match every image's predictions (0-based labels, scores) to its ground truth and count.

    Recall and the per-class counts use only predictions with ``score >= score_threshold``; AP ranks every
    prediction by score (the conventional definition), so ``map50`` reads the whole ranking."""
    if len(predictions) != len(targets):
        raise ValueError(f"{len(predictions)} prediction sets for {len(targets)} images")
    names = [str(c) for c in class_names]
    n_gt_c = np.zeros(len(names), dtype=np.int64)
    n_matched_c = np.zeros(len(names), dtype=np.int64)
    ap_scores: list[list[float]] = [[] for _ in names]
    ap_tp: list[list[bool]] = [[] for _ in names]
    matched_flags: list[np.ndarray] = []
    matched_scores: list[float] = []
    n_predictions = 0
    for pred, gt in zip(predictions, targets, strict=True):
        gb = np.asarray(gt["boxes"], dtype=np.float32).reshape(-1, 4)
        gl = np.asarray(gt["labels"], dtype=np.int64).ravel()
        if gl.size and (int(gl.max()) >= len(names) or int(gl.min()) < 0):
            raise ValueError("a ground-truth label falls outside class_names")
        pb = np.asarray(pred.get("boxes", np.zeros((0, 4))), dtype=np.float32).reshape(-1, 4)
        pl = np.asarray(pred.get("labels", np.zeros((0,))), dtype=np.int64).ravel()
        ps = np.asarray(pred.get("scores", np.ones(pb.shape[0])), dtype=np.float64).ravel()
        keep = ps >= float(score_threshold)
        n_predictions += int(keep.sum())
        gt_matched, pred_tp = match_boxes(pb[keep], pl[keep], ps[keep], gb, gl, iou_threshold=iou_threshold)
        matched_flags.append(gt_matched)
        matched_scores.extend(float(v) for v in ps[keep][pred_tp])
        for c in range(len(names)):
            n_gt_c[c] += int((gl == c).sum())
            n_matched_c[c] += int((gt_matched & (gl == c)).sum())
        # AP over the full ranking (all scores), per class.
        _, tp_all = match_boxes(pb, pl, ps, gb, gl, iou_threshold=iou_threshold)
        for c in range(len(names)):
            sel = pl == c
            ap_scores[c].extend(float(v) for v in ps[sel])
            ap_tp[c].extend(bool(v) for v in tp_all[sel])
    n_gt = int(n_gt_c.sum())
    n_matched = int(n_matched_c.sum())
    aps: dict[str, float | None] = {}
    for c, name in enumerate(names):
        aps[name] = average_precision(np.asarray(ap_scores[c]), np.asarray(ap_tp[c], dtype=bool), int(n_gt_c[c]))
    present = [v for v in aps.values() if v is not None]
    return DetectionEval(
        n_images=len(targets), n_gt=n_gt, n_matched=n_matched, n_predictions=n_predictions,
        recall=(n_matched / n_gt) if n_gt > 0 else None,
        map50=(float(sum(present) / len(present)) if present else None),
        per_class={name: {"n": int(n_gt_c[c]), "n_correct": int(n_matched_c[c])} for c, name in enumerate(names)},
        matched=matched_flags,
        mean_matched_score=(float(np.mean(matched_scores)) if matched_scores else None),
        iou_threshold=float(iou_threshold), score_threshold=float(score_threshold), ap_per_class=aps,
    )


# --- the torchvision architecture -----------------------------------------------------------------------

def coco_detector_checkpoint() -> Path | None:
    """The cached torchvision COCO checkpoint for the 320 detector, or ``None``. Never downloads."""
    import torch

    try:
        hub_dir = Path(torch.hub.get_dir())
    except Exception:  # noqa: BLE001 - hub dir resolution can fail on locked-down hosts
        return None
    candidate = hub_dir / "checkpoints" / COCO_CHECKPOINT_FILENAME
    return candidate if candidate.is_file() else None


def detector_architecture_config(*, n_classes: int, image_size: int, anchor_sizes: Sequence[int] | None = None,
                                 score_threshold: float = 0.05, detections_per_img: int = 100) -> dict[str, Any]:
    """Constructor arguments recorded in the asset manifest (``ModelEntry.architecture``)."""
    return {"architecture_id": ARCHITECTURE_ID, "n_classes": int(n_classes), "image_size": int(image_size),
            "anchor_sizes": [int(s) for s in anchor_sizes] if anchor_sizes is not None else None,
            "score_threshold": float(score_threshold), "detections_per_img": int(detections_per_img)}


def build_detector_module(*, n_classes: int, image_size: int = DEFAULT_INPUT_SIZE,
                          anchor_sizes: Sequence[int] | None = None, score_threshold: float = 0.05,
                          detections_per_img: int = 100, **_ignored: Any) -> Any:
    """A torchvision Faster R-CNN (MobileNetV3-Large 320 FPN) with ``n_classes`` foreground classes.

    ``weights=None`` always: weights come from the manifest file or ``init_coco_weights``. With
    ``anchor_sizes`` the model is assembled from the same backbone with a small-anchor RPN (for tiny
    inputs; not loadable from the COCO checkpoint, which the caller records). Inputs are float32 in
    [0, 1] NCHW; the model normalises internally (torchvision's transform) and resizes to ``image_size``.
    """
    if n_classes < 1:
        raise ValueError("n_classes must be >= 1")
    if image_size < 8:
        raise ValueError("image_size must be >= 8")
    from torchvision.models.detection import FasterRCNN, fasterrcnn_mobilenet_v3_large_320_fpn
    from torchvision.models.detection.anchor_utils import AnchorGenerator
    from torchvision.models.detection.backbone_utils import mobilenet_backbone

    common: dict[str, Any] = {"num_classes": int(n_classes) + LABEL_OFFSET, "min_size": int(image_size),
                              "max_size": int(image_size), "box_score_thresh": float(score_threshold),
                              "box_detections_per_img": int(detections_per_img)}
    if anchor_sizes is None:
        return fasterrcnn_mobilenet_v3_large_320_fpn(weights=None, weights_backbone=None, **common)
    sizes = tuple(int(s) for s in anchor_sizes)
    if not sizes:
        raise ValueError("anchor_sizes must not be empty")
    backbone = mobilenet_backbone("mobilenet_v3_large", weights=None, fpn=True, trainable_layers=6)
    generator = AnchorGenerator(sizes=(sizes,) * 3, aspect_ratios=((0.5, 1.0, 2.0),) * 3)
    return FasterRCNN(backbone, rpn_anchor_generator=generator, rpn_pre_nms_top_n_test=200,
                      rpn_post_nms_top_n_test=100, rpn_pre_nms_top_n_train=400, rpn_post_nms_top_n_train=200,
                      box_batch_size_per_image=64, rpn_batch_size_per_image=64, **common)


def init_coco_weights(model: Any) -> tuple[bool, str]:
    """Load the COCO-pretrained backbone, FPN, RPN and box head from the local torch hub cache (never a download).

    The box predictor keeps its random initialisation (the class count differs from COCO's 91). Returns
    ``(loaded, note)``; the note is what the manifest records as ``backbone_init``."""
    import torch

    path = coco_detector_checkpoint()
    if path is None:
        hub = "<torch hub dir unavailable>"
        try:
            hub = str(Path(torch.hub.get_dir()) / "checkpoints" / COCO_CHECKPOINT_FILENAME)
        except Exception:  # noqa: BLE001
            pass
        return False, f"random init (seeded): no cached COCO checkpoint at {hub} (offline build)"
    state = torch.load(path, map_location="cpu", weights_only=True)
    if not isinstance(state, dict):
        return False, f"random init (seeded): {path} is not a state_dict"
    keep = {k: v for k, v in state.items() if not k.startswith("roi_heads.box_predictor.")}
    missing, unexpected = model.load_state_dict(keep, strict=False)
    stray = [k for k in missing if not k.startswith("roi_heads.box_predictor.")] + list(unexpected)
    if stray:
        return False, f"random init (seeded): cached COCO checkpoint does not fit this detector ({stray[:3]})"
    return True, f"coco_v1 backbone, FPN, RPN and box head from local cache {path}; box predictor random (seeded)"


def load_detector_state_dict(path: Path, kwargs: Mapping[str, Any]) -> Any:
    """Rebuild the detector from ``kwargs`` (``detector_architecture_config`` shape) and load tensors strictly."""
    import torch

    arch = dict(kwargs)
    declared = arch.pop("architecture_id", ARCHITECTURE_ID)
    if declared != ARCHITECTURE_ID:
        raise UnsupportedArtifact(f"architecture_missing: detector entry declares {declared!r}, expected {ARCHITECTURE_ID!r}")
    model = build_detector_module(**arch)
    try:
        state = torch.load(str(path), map_location="cpu", weights_only=True)
    except Exception as exc:  # torch raises pickle.UnpicklingError and friends
        raise UnsupportedArtifact("pickle_refused: weights_only load failed (the archive holds objects other than "
                                  f"tensors): {str(exc).splitlines()[0][:200]}") from exc
    if not isinstance(state, dict) or not all(isinstance(v, torch.Tensor) for v in state.values()):
        raise UnsupportedArtifact("unsupported_model_format: the archive is not a state_dict of tensors")
    try:
        model.load_state_dict(state, strict=True)
    except RuntimeError as exc:
        raise UnsupportedArtifact(f"architecture_mismatch: state_dict does not fit {ARCHITECTURE_ID!r}: "
                                  f"{str(exc).splitlines()[0][:300]}") from exc
    model.eval()
    return model


def predict_detections(model: Any, x: np.ndarray, *, batch_size: int = 16,
                       label_offset: int = LABEL_OFFSET) -> list[dict[str, np.ndarray]]:
    """Run a torchvision-style detector on float32 [0, 1] NCHW (or uint8) images; labels come back 0-based."""
    import torch

    xin = as_model_input(np.asarray(x))
    was_training = bool(getattr(model, "training", False))
    model.eval()
    out: list[dict[str, np.ndarray]] = []
    try:
        with torch.no_grad():
            for start in range(0, xin.shape[0], max(1, batch_size)):
                batch = torch.from_numpy(np.ascontiguousarray(xin[start:start + batch_size]))
                for det in model(batch):
                    labels = det["labels"].detach().cpu().numpy().astype(np.int64) - label_offset
                    out.append({"boxes": det["boxes"].detach().cpu().numpy().astype(np.float32).reshape(-1, 4),
                                "labels": labels,
                                "scores": det["scores"].detach().cpu().numpy().astype(np.float32).ravel()})
    finally:
        if was_training:
            model.train()
    return out


def art_targets(targets: Sequence[Mapping[str, np.ndarray]], *, label_offset: int = LABEL_OFFSET
                ) -> list[dict[str, np.ndarray]]:
    """ART / torchvision target dicts (labels shifted into the model's label space, unit scores)."""
    out: list[dict[str, np.ndarray]] = []
    for t in targets:
        boxes = np.asarray(t["boxes"], dtype=np.float32).reshape(-1, 4)
        labels = np.asarray(t["labels"], dtype=np.int64).ravel() + label_offset
        out.append({"boxes": boxes, "labels": labels, "scores": np.ones(boxes.shape[0], dtype=np.float32)})
    return out


def make_art_detector(model: Any, *, input_shape: tuple[int, int, int]) -> Any:
    """``art.estimators.object_detection.PyTorchFasterRCNN`` over a torchvision-style detector (CPU, [0, 1])."""
    from art.estimators.object_detection import PyTorchFasterRCNN

    return PyTorchFasterRCNN(
        model=model, input_shape=tuple(int(d) for d in input_shape), clip_values=(0.0, 1.0), channels_first=True,
        attack_losses=("loss_classifier", "loss_box_reg", "loss_objectness", "loss_rpn_box_reg"), device_type="cpu",
    )


# --- the detection target contract -----------------------------------------------------------------------

@runtime_checkable
class DetectionTarget(Protocol):
    """What ``redsim.ml.runners.detection`` needs beyond the ``Target`` protocol."""

    id: str
    label_offset: int
    score_threshold: float
    iou_threshold: float

    def info(self) -> TargetInfo: ...

    def load(self) -> None: ...

    def sample(self, n: int, seed: int) -> Sample: ...

    def predict(self, x: np.ndarray) -> list[dict[str, np.ndarray]]: ...

    def art_estimator(self) -> Any: ...

    def manifest(self) -> dict[str, Any]: ...


def is_detection_target(target: Any) -> bool:
    """A detector announces itself through ``info().metadata["modality"] == "detection"`` (or the B0 domain)."""
    try:
        info = target.info()
    except Exception:  # noqa: BLE001 - a broken info() is not a detector
        return False
    return str(info.metadata.get("modality", "")) == MODALITY or str(info.domain) == MODALITY


def detection_target_info(target_id: str, name: str, *, status: TargetStatus, reason: str | None = None,
                          metadata: Mapping[str, Any] | None = None) -> TargetInfo:
    """``TargetInfo`` for a detector: domain ``detection`` and ``metadata["modality"] = "detection"``."""
    meta = {"modality": MODALITY, "budget": BUDGET_LABEL, **dict(metadata or {})}
    return TargetInfo(id=target_id, name=name, domain=DETECTION_DOMAIN, status=status, reason=reason, metadata=meta)


INFO_KEYS: tuple[str, ...] = (
    "dataset_id", "dataset_revision", "dataset_split", "license", "source_url", "clean_accuracy", "sha256",
    "architecture_id", "architecture", "input_shape", "n_classes", "class_names", "format", "file",
    "manifest_sha256", "detection", "description", "gradients", "metrics",
)


class BundledDetectionTarget:
    """A bundled torchvision detector (``state_dict`` + catalog architecture) plus its packed evaluation slice.

    Reads the builder-shaped ``assets/MANIFEST.json`` the way ``BundledImageTarget`` does: weights at
    ``models[id].file.path`` (digest checked), constructor kwargs at ``models[id].architecture``, the slice
    at ``datasets[dataset_id].splits[dataset_split].file`` (an ``eval_det.npz`` written by
    ``redsim.ml.datasets.military_assets.save_detection_npz``), thresholds and class names at
    ``models[id].detection``. Registration touches no file; ``info()`` reports ``not_implemented`` with a
    reason while the assets are absent.
    """

    label_offset = LABEL_OFFSET

    def __init__(self, target_id: str = BUNDLED_DETECTOR_ID, *, name: str | None = None,
                 assets_dir: str | Path | None = None, description: str = "") -> None:
        self.id = target_id
        self._name = name or target_id
        self._assets_dir = assets_dir
        self._description = description
        self.unload()

    def unload(self) -> None:
        self._entry: dict[str, Any] | None = None
        self._module: Any = None
        self._split: DetectionSplit | None = None
        self._split_path: str | None = None
        self._split_sha: str | None = None
        self._sha256: str | None = None
        self._verified_by_manifest = False
        self._estimator: Any = None
        self._manifest: dict[str, Any] | None = None
        self._detection: dict[str, Any] | None = None
        self.score_threshold: float = DEFAULT_SCORE_THRESHOLD
        self.iou_threshold: float = DEFAULT_IOU_THRESHOLD

    @property
    def root(self) -> Path:
        return assets_dir(self._assets_dir)

    def _read_entry(self) -> dict[str, Any] | None:
        return manifest_entry(read_manifest(self.root), self.id)

    # -- protocol -------------------------------------------------------------------------------

    def info(self) -> TargetInfo:
        base_meta: dict[str, Any] = {"source": "bundled", "assets_dir": str(self.root)}
        try:
            entry = self._read_entry()
        except UnsupportedArtifact as exc:
            return detection_target_info(self.id, self._name, status="not_implemented",
                                         reason=f"asset manifest unreadable: {exc}",
                                         metadata={**base_meta, "availability": "manifest_invalid"})
        if entry is None:
            return detection_target_info(self.id, self._name, status="not_implemented",
                                         reason=f"bundled assets not found at {self.root / MANIFEST_NAME}; {BUILD_HINT}",
                                         metadata={**base_meta, "availability": "assets_missing"})
        meta = {**base_meta, "availability": "available", "gradients": True,
                **{k: entry[k] for k in INFO_KEYS if k in entry}}
        return detection_target_info(self.id, str(entry.get("name") or self._name), status="available", metadata=meta)

    def load(self) -> None:
        if self._module is not None:
            return
        manifest = read_manifest(self.root)
        entry = manifest_entry(manifest, self.id)
        if entry is None or manifest is None:
            raise TargetUnavailable(f"bundled assets for {self.id!r} are missing: no entry in "
                                    f"{self.root / MANIFEST_NAME}; {BUILD_HINT}")
        fmt = entry.get("format", "torch_state_dict")
        if fmt != "torch_state_dict":
            raise UnsupportedArtifact(f"bundled detector {self.id!r} declares format {fmt!r}; detectors ship as "
                                      "torch_state_dict")
        verified = verify_bundled_entry(manifest, self.root, self.id)
        rel, expected = weights_ref(entry)
        if rel is None:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} has no weights path (file.path or weights)")
        weights = resolve_asset_path(self.root, rel)
        if not weights.is_file():
            raise TargetUnavailable(f"weights for {self.id!r} not found at {weights}; {BUILD_HINT}")
        if not expected:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} carries no sha256 for its weights; refusing to load")
        if verified:
            self._sha256 = expected
        else:
            try:
                self._sha256 = verify_sha256(weights, expected)
            except UnsupportedArtifact as exc:
                raise ArtifactDigestMismatch(str(exc)) from exc
        kwargs = architecture_kwargs(entry)
        arch_id = entry.get("architecture_id") or kwargs.get("architecture_id") or ARCHITECTURE_ID
        if arch_id != ARCHITECTURE_ID:
            raise UnsupportedArtifact(f"architecture_missing: {self.id!r} declares {arch_id!r}; the detector catalog "
                                      f"knows {ARCHITECTURE_ID!r} only")
        names = [str(c) for c in (entry.get("class_names") or [])]
        raw_detection = entry.get("detection")
        detection: dict[str, Any] = dict(raw_detection) if isinstance(raw_detection, dict) else {}
        if not names and isinstance(detection.get("classes"), list):    # DetectionModelSpec.classes
            names = [str(c) for c in detection["classes"]]
        if not names:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} declares no class_names")
        n_classes = int(entry.get("n_classes") or kwargs.get("n_classes") or len(names))
        if n_classes != len(names):
            raise UnsupportedArtifact(f"n_classes {n_classes} disagrees with {len(names)} class_names")
        kwargs.setdefault("n_classes", n_classes)
        split_ref = resolve_eval_split(manifest, entry, self.id)
        split_path = resolve_asset_path(self.root, split_ref.path)
        if not verified and split_ref.sha256 and sha256_file(split_path) != split_ref.sha256.lower():
            raise DatasetUnavailable(f"hash_mismatch: evaluation slice {split_path.name} differs from the manifest digest")
        split = load_detection_npz(split_path)
        if split.class_names != names:
            raise DatasetUnavailable(f"evaluation slice class names {split.class_names} differ from the manifest's {names}")
        image_size = int(kwargs.get("image_size") or split.x.shape[-1])
        kwargs.setdefault("image_size", image_size)
        declared_shape = entry.get("input_shape")
        if declared_shape and tuple(int(d) for d in declared_shape) != tuple(int(d) for d in split.x.shape[1:]):
            raise UnsupportedArtifact(f"shape_mismatch: manifest input_shape {declared_shape} vs slice {split.x.shape[1:]}")
        module = load_detector_state_dict(weights, kwargs)
        probe = predict_detections(module, as_model_input(split.x[:1]), label_offset=self.label_offset)
        if len(probe) != 1 or set(probe[0]) != {"boxes", "labels", "scores"}:
            raise UnsupportedArtifact("shape_mismatch: detector output is not one {boxes, labels, scores} dict per image")
        self.score_threshold = float(detection.get("score_threshold", DEFAULT_SCORE_THRESHOLD))
        self.iou_threshold = float(detection.get("iou_threshold", DEFAULT_IOU_THRESHOLD))
        self._detection = detection_spec_block(score_threshold=self.score_threshold, iou_threshold=self.iou_threshold,
                                               class_names=names, input_size=[int(d) for d in split.x.shape[1:]])
        revision = entry.get("dataset_revision") or split_ref.revision
        self._manifest = model_manifest(
            f"manifest entry {self.id!r}",
            name=str(entry.get("name") or self._name), modality=DETECTION_MODALITY, format="torch_state_dict",
            sha256=self._sha256, size_bytes=weights.stat().st_size, architecture_id=ARCHITECTURE_ID,
            input_shape=[int(d) for d in split.x.shape[1:]], n_classes=n_classes, class_names=names,
            dataset_id=entry.get("dataset_id"), dataset_revision=revision, dataset_split=entry.get("dataset_split"),
            clean_accuracy=clean_accuracy_entry(entry.get("clean_accuracy"), entry.get("dataset_split")),
            status="available", gradients=True, bundled=True, license=entry.get("license"),
            source_url=entry.get("source_url"),
        )
        self._entry, self._module, self._split = entry, module, split
        self._split_path, self._split_sha = split_ref.path, split_ref.sha256
        self._verified_by_manifest = verified

    def sample(self, n: int, seed: int) -> DetectionSample:
        self.load()
        assert self._split is not None
        return detection_sample(self._split, n, seed)

    def predict(self, x: np.ndarray) -> list[dict[str, np.ndarray]]:
        self.load()
        return predict_detections(self._module, x, label_offset=self.label_offset)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        raise AttackNotApplicable(NO_CLASSIFIER_REASON)

    def art_estimator(self) -> Any:
        self.load()
        if self._estimator is None:
            assert self._split is not None
            self._estimator = make_art_detector(self._module, input_shape=cast(tuple[int, int, int],
                                                                               tuple(int(d) for d in self._split.x.shape[1:])))
        return self._estimator

    def art_classifier(self) -> Any:
        """The ART object detector (the ``Target`` protocol name; it is not a classifier)."""
        return self.art_estimator()

    def torch_model(self) -> Any:
        self.load()
        return self._module

    def manifest(self) -> dict[str, Any]:
        self.load()
        assert self._entry is not None and self._manifest is not None and self._split is not None
        return {
            **self._entry,
            "id": self.id, "source": "bundled", "modality_note": "object detector; predict_proba is undefined",
            "weights_sha256_verified": self._sha256,
            "eval_split_file": self._split_path, "eval_split_sha256_verified": self._split_sha,
            "manifest_verified": self._verified_by_manifest,
            "eval_n": int(self._split.n), "eval_n_boxes": int(self._split.n_boxes),
            "eval_per_class_boxes": self._split.per_class_boxes(),
            "excluded_classes": list(self._split.excluded_classes),
            "library_versions": {**library_versions("torch", "torchvision", "adversarial-robustness-toolbox", "numpy"),
                                 "python": platform.python_version()},
            "assets_dir": str(self.root),
            **self._manifest,
            "detection": dict(self._detection or {}),
            "label_offset": self.label_offset,
        }


ASSETS_FRCNN_MNV3 = register_once(BundledDetectionTarget(
    BUNDLED_DETECTOR_ID, name="Bundled Faster R-CNN (MobileNetV3-Large 320 FPN) on the capped military-assets subset",
    description="Demo detection target (register MODALITIES-29); person and weapon classes excluded at build time."))

__all__ = [
    "AP_INTERPOLATION_NOTE", "ARCHITECTURE_ID", "ASSETS_FRCNN_MNV3", "BUDGET_LABEL", "BUNDLED_DETECTOR_ID",
    "COCO_CHECKPOINT_FILENAME", "DEFAULT_INPUT_SIZE", "DEFAULT_IOU_THRESHOLD", "DEFAULT_SCORE_THRESHOLD",
    "DETECTION_DOMAIN", "DETECTION_MODALITY", "EXPLAINER_UNAVAILABLE_REASON", "INFO_KEYS", "LABEL_OFFSET",
    "MEASUREMENT_HAS_DETECTION", "MODALITY", "NO_CLASSIFIER_REASON", "OBSERVATION_HAS_DETECTION", "PATCH_AREA_NORM",
    "BundledDetectionTarget", "DetectionEval", "DetectionSample", "DetectionTarget",
    "art_targets", "average_precision", "box_iou", "build_detector_module", "coco_detector_checkpoint",
    "detection_sample", "detection_spec_block", "detection_target_info", "detector_architecture_config",
    "evaluate_detections", "init_coco_weights", "is_detection_target", "load_detector_state_dict",
    "make_art_detector", "match_boxes", "predict_detections",
]
