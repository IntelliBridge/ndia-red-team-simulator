"""Detection test double (spec 22; register MODALITIES-30, -41): ``TinyDetector`` on 16x16 images, 2 classes.

A random-weight torchvision Faster R-CNN detects nothing at 16 px (its anchors are larger than the image)
and does not fine-tune to non-zero recall in the seconds a CI test allows, so the double is a hand-built
differentiable detector that honours the torchvision contract ART's ``PyTorchFasterRCNN`` relies on:
``model(images)`` in eval mode returns one ``{"boxes", "labels", "scores"}`` dict per image with 1-based
labels, ``model(images, targets)`` in train mode returns the four Faster R-CNN loss terms. It scores a fixed
set of anchor boxes by the mean colour evidence inside each box (red for class 0, blue for class 1), so it
detects the coloured rectangles ``synthetic_detection_split`` draws, its loss gradient with respect to the
input is real (DPatch has something to climb), and it is deterministic without training. It lives only
under ``tests/``: nothing it produces is evidence about any dataset or any model.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np
import torch
from torch import nn

from redsim.ml.datasets.military_assets import (
    SYNTHETIC_CLASS_NAMES,
    SYNTHETIC_DATASET_ID,
    DetectionSplit,
    synthetic_detection_split,
)
from redsim.ml.errors import AttackNotApplicable
from redsim.ml.schema import TargetInfo
from redsim.ml.targets.detection import (
    LABEL_OFFSET,
    DetectionSample,
    detection_sample,
    detection_spec_block,
    detection_target_info,
    make_art_detector,
    predict_detections,
)

IMAGE_SIZE = 16
CLASS_NAMES: list[str] = list(SYNTHETIC_CLASS_NAMES)
ANCHOR_SIDES: tuple[int, ...] = (6, 8, 9)
ANCHOR_STRIDE = 2
SCORE_SLOPE = 12.0          # logit = slope * (mean evidence - midpoint)
SCORE_MIDPOINT = 0.45
EVAL_N = 24                 # images in the synthetic evaluation pool


class _TinyBoxNet(nn.Module):
    """Colour-evidence anchor detector with the torchvision detection contract (see the module docstring)."""

    def __init__(self, image_size: int = IMAGE_SIZE, *, n_classes: int = 2, score_thresh: float = 0.05,
                 nms_iou: float = 0.5, detections_per_img: int = 10) -> None:
        super().__init__()
        if n_classes != 2:
            raise ValueError("the tiny detector scores red and blue evidence: exactly 2 classes")
        self.image_size = int(image_size)
        self.n_classes = int(n_classes)
        self.score_thresh = float(score_thresh)
        self.nms_iou = float(nms_iou)
        self.detections_per_img = int(detections_per_img)
        # Fixed 1x1 colour-evidence filters: red = R - (G + B) / 2, blue = B - (R + G) / 2.
        weight = torch.tensor([[[[1.0]], [[-0.5]], [[-0.5]]], [[[-0.5]], [[-0.5]], [[1.0]]]], dtype=torch.float32)
        self.evidence = nn.Conv2d(3, 2, kernel_size=1, bias=False)
        with torch.no_grad():
            self.evidence.weight.copy_(weight)
        self.evidence.weight.requires_grad_(False)
        boxes: list[list[float]] = []
        for side in ANCHOR_SIDES:
            for r in range(0, self.image_size - side + 1, ANCHOR_STRIDE):
                for c in range(0, self.image_size - side + 1, ANCHOR_STRIDE):
                    boxes.append([float(c), float(r), float(c + side), float(r + side)])
        self.register_buffer("anchors", torch.tensor(boxes, dtype=torch.float32))

    # -- scoring ----------------------------------------------------------------------------------

    def _logits(self, images: torch.Tensor) -> torch.Tensor:
        """``(N, A, 2)`` score logits: one per anchor and class."""
        ev = self.evidence(images)                                  # (N, 2, H, W)
        parts: list[torch.Tensor] = []
        for side in ANCHOR_SIDES:
            pooled = torch.nn.functional.avg_pool2d(ev, kernel_size=side, stride=ANCHOR_STRIDE)   # (N, 2, h, w)
            parts.append(pooled.flatten(2).transpose(1, 2))         # (N, h*w, 2) in row-major (r, c) order
        mean_ev = torch.cat(parts, dim=1)
        return SCORE_SLOPE * (mean_ev - SCORE_MIDPOINT)

    @staticmethod
    def _as_batch(images: torch.Tensor | Sequence[torch.Tensor]) -> torch.Tensor:
        if isinstance(images, torch.Tensor):
            return images if images.dim() == 4 else images.unsqueeze(0)
        return torch.stack(list(images))

    def forward(self, images: torch.Tensor | Sequence[torch.Tensor],
                targets: Sequence[Mapping[str, torch.Tensor]] | None = None) -> Any:
        batch = self._as_batch(images).to(torch.float32)
        logits = self._logits(batch)                                # (N, A, 2)
        if self.training:
            if targets is None:
                raise ValueError("targets are required in training mode")
            return self._losses(logits, targets)
        return self._detections(logits)

    def _losses(self, logits: torch.Tensor, targets: Sequence[Mapping[str, torch.Tensor]]) -> dict[str, torch.Tensor]:
        from torchvision.ops import box_iou

        bce = torch.nn.functional.binary_cross_entropy_with_logits
        cls_terms: list[torch.Tensor] = []
        obj_terms: list[torch.Tensor] = []
        anchors = self.anchors
        for i, t in enumerate(targets):
            gt_boxes = t["boxes"].to(torch.float32).reshape(-1, 4)
            gt_labels = t["labels"].to(torch.int64).reshape(-1) - LABEL_OFFSET
            target = torch.zeros_like(logits[i])
            if gt_boxes.shape[0]:
                iou = box_iou(anchors, gt_boxes)                     # (A, G)
                for g in range(gt_boxes.shape[0]):
                    pos = iou[:, g] >= 0.5
                    target[pos, int(gt_labels[g])] = 1.0
            objectness_target = target.max(dim=1).values
            obj_terms.append(bce(logits[i].max(dim=1).values, objectness_target))
            positive = target.sum(dim=1) > 0
            if bool(positive.any()):
                cls_terms.append(bce(logits[i][positive], target[positive]))
        zero = logits.sum() * 0.0
        return {
            "loss_classifier": torch.stack(cls_terms).mean() if cls_terms else zero,
            "loss_box_reg": zero,
            "loss_objectness": torch.stack(obj_terms).mean() if obj_terms else zero,
            "loss_rpn_box_reg": zero,
        }

    def _detections(self, logits: torch.Tensor) -> list[dict[str, torch.Tensor]]:
        from torchvision.ops import batched_nms

        scores_all = torch.sigmoid(logits)                          # (N, A, 2)
        out: list[dict[str, torch.Tensor]] = []
        for i in range(scores_all.shape[0]):
            scores = scores_all[i].reshape(-1)                      # anchor-major, class-minor
            n_anchor = self.anchors.shape[0]
            labels = torch.arange(self.n_classes).repeat(n_anchor)
            boxes = self.anchors.repeat_interleave(self.n_classes, dim=0)
            keep = scores > self.score_thresh
            boxes, scores, labels = boxes[keep], scores[keep], labels[keep]
            if scores.numel():
                order = batched_nms(boxes, scores, labels, self.nms_iou)[: self.detections_per_img]
                boxes, scores, labels = boxes[order], scores[order], labels[order]
            out.append({"boxes": boxes, "labels": labels + LABEL_OFFSET, "scores": scores})
        return out


class TinyDetector:
    """Detection ``Target`` double: the colour-evidence detector over a seeded synthetic rectangle pool."""

    id = "tiny_detector"
    label_offset = LABEL_OFFSET

    def __init__(self, seed: int = 0, *, n_eval: int = EVAL_N, image_size: int = IMAGE_SIZE,
                 score_threshold: float = 0.5, iou_threshold: float = 0.5) -> None:
        self._seed = int(seed)
        self._net = _TinyBoxNet(image_size).eval()
        self._pool: DetectionSplit = synthetic_detection_split(n_eval, image_size, seed=seed, class_names=CLASS_NAMES)
        self.score_threshold = float(score_threshold)
        self.iou_threshold = float(iou_threshold)
        self._estimator: Any = None
        self.estimator_calls = 0
        self.predict_calls = 0

    def info(self) -> TargetInfo:
        return detection_target_info(self.id, "Tiny colour-evidence detector (test double)", status="available",
                                     metadata={"dataset": SYNTHETIC_DATASET_ID, "n_classes": len(CLASS_NAMES),
                                               "gradients": True, "fixture_only": True})

    def load(self) -> None:
        return None

    def sample(self, n: int, seed: int) -> DetectionSample:
        return detection_sample(self._pool, n, seed)

    def predict(self, x: np.ndarray) -> list[dict[str, np.ndarray]]:
        self.predict_calls += 1
        return predict_detections(self._net, x, label_offset=self.label_offset)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        raise AttackNotApplicable("an object detector is not a classifier: predict_proba is undefined; use predict()")

    def art_estimator(self) -> Any:
        self.estimator_calls += 1
        if self._estimator is None:
            self._estimator = make_art_detector(self._net, input_shape=(3, self._net.image_size, self._net.image_size))
        return self._estimator

    def art_classifier(self) -> Any:
        return self.art_estimator()

    def torch_model(self) -> Any:
        return self._net

    def manifest(self) -> dict[str, Any]:
        blob = b"".join(p.detach().numpy().tobytes() for p in self._net.parameters())
        blob += self._net.anchors.numpy().tobytes()
        size = self._net.image_size
        return {
            "dataset": SYNTHETIC_DATASET_ID, "dataset_id": SYNTHETIC_DATASET_ID, "split": "synthetic",
            "model": "TinyBoxNet", "weights_sha256": hashlib.sha256(blob).hexdigest(), "seed": self._seed,
            "class_names": list(CLASS_NAMES), "n_classes": len(CLASS_NAMES), "input_shape": [3, size, size],
            "detection": detection_spec_block(score_threshold=self.score_threshold, iou_threshold=self.iou_threshold,
                                              class_names=CLASS_NAMES, input_size=[3, size, size]),
            "label_offset": self.label_offset, "eval_n": int(self._pool.n), "eval_n_boxes": int(self._pool.n_boxes),
            "caveats": ["synthetic coloured rectangles scored by a fixed colour-evidence detector; a test double, "
                        "never evidence about any dataset or model"],
        }


__all__ = ["ANCHOR_SIDES", "CLASS_NAMES", "EVAL_N", "IMAGE_SIZE", "TinyDetector"]
