"""Seeded CPU fine-tuning of the bundled detector on the capped military-assets subset (register MODALITIES-29).

``train_detector`` builds ``fasterrcnn_mobilenet_v3_large_320_fpn`` through
``redsim.ml.targets.detection.build_detector_module`` (``weights=None``), loads the COCO-pretrained
weights from the local torch hub cache when they are there (never a download; the training record says
``backbone_init`` either way), replaces nothing but the box predictor's class count, and runs SGD for a
bounded number of epochs on uint8 NCHW images with xyxy boxes. Every number that reaches the manifest
(recall@0.5, mAP@0.5, per-class box counts, wall time) is measured here on the evaluation split with
``redsim.ml.targets.detection.evaluate_detections``; nothing is asserted.

The build entrypoint (``redsim ml build-assets --dataset detection``) belongs to ``redsim.ml.assets.build``;
this module only trains, evaluates and writes the two files a ``ModelEntry`` points at (weights and the
packed ``eval_det.npz`` slice). Tests drive it on ``synthetic_detection_split`` at 16 px for one epoch.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import torch

from redsim.ml.datasets.military_assets import DetectionSplit, save_detection_npz
from redsim.ml.datasets.sampling import as_model_input
from redsim.ml.targets.detection import (
    AP_INTERPOLATION_NOTE,
    ARCHITECTURE_ID,
    DEFAULT_IOU_THRESHOLD,
    DEFAULT_SCORE_THRESHOLD,
    LABEL_OFFSET,
    DetectionEval,
    build_detector_module,
    detection_spec_block,
    detector_architecture_config,
    evaluate_detections,
    init_coco_weights,
    predict_detections,
)

Log = Callable[[str], None]

# Fine-tuning defaults for the COCO-initialised detector on a few hundred images: SGD with momentum, a
# small step, cosine decay; bounded epochs. Recorded in the training record, never asserted.
DEFAULT_EPOCHS = 3
DEFAULT_LR = 0.005
DEFAULT_MOMENTUM = 0.9
DEFAULT_WEIGHT_DECAY = 5e-4
DEFAULT_BATCH_SIZE = 4
MODEST_MAP_NOTE = ("A few-hundred-image CPU fine-tune yields modest mAP; the numbers here describe this build on "
                   "this subset and are not comparable with published detector benchmarks.")


@dataclass
class DetectorTrainingResult:
    model: Any
    metrics: dict[str, Any]
    training: dict[str, Any]
    architecture: dict[str, Any]
    detection: dict[str, Any]
    history: list[dict[str, float]] = field(default_factory=list)


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def _to_targets(split: DetectionSplit, idx: Sequence[int]) -> list[dict[str, torch.Tensor]]:
    out: list[dict[str, torch.Tensor]] = []
    for i in idx:
        boxes = torch.from_numpy(np.asarray(split.boxes[i], dtype=np.float32).reshape(-1, 4))
        labels = torch.from_numpy(np.asarray(split.labels[i], dtype=np.int64) + LABEL_OFFSET)
        out.append({"boxes": boxes, "labels": labels})
    return out


def evaluate_detector(model: Any, split: DetectionSplit, *, score_threshold: float = DEFAULT_SCORE_THRESHOLD,
                      iou_threshold: float = DEFAULT_IOU_THRESHOLD, batch_size: int = 16) -> DetectionEval:
    """Measured recall@IoU, mAP and per-class box counts of ``model`` on ``split`` (nothing asserted)."""
    preds = predict_detections(model, as_model_input(split.x), batch_size=batch_size)
    return evaluate_detections(preds, split.targets(), split.class_names, iou_threshold=iou_threshold,
                               score_threshold=score_threshold)


def train_detector(train: DetectionSplit, eval_split: DetectionSplit, *, epochs: int = DEFAULT_EPOCHS, seed: int = 0,
                   batch_size: int = DEFAULT_BATCH_SIZE, lr: float = DEFAULT_LR, momentum: float = DEFAULT_MOMENTUM,
                   weight_decay: float = DEFAULT_WEIGHT_DECAY, pretrained: bool = True,
                   anchor_sizes: Sequence[int] | None = None, score_threshold: float = DEFAULT_SCORE_THRESHOLD,
                   iou_threshold: float = DEFAULT_IOU_THRESHOLD, threads: int | None = None,
                   log: Log = print) -> DetectorTrainingResult:
    """Fine-tune the detector on ``train`` for ``epochs`` and measure it on ``eval_split``.

    ``pretrained`` asks for the cached COCO weights (only meaningful without ``anchor_sizes``); the
    training record states what was actually loaded. Every epoch's summed loss and the evaluation
    recall / mAP are kept in ``history``; the final metrics are the last epoch's (no selection on the
    evaluation split, so its numbers stay honest).
    """
    if train.x.ndim != 4 or train.x.dtype != np.uint8:
        raise ValueError("train.x must be uint8 NCHW")
    if train.class_names != eval_split.class_names:
        raise ValueError("train and eval splits must declare the same class names")
    if epochs < 1:
        raise ValueError("epochs must be >= 1")
    n_train, _channels, height, width = train.x.shape
    if height != width:
        raise ValueError("images must be square")
    if threads is not None:
        torch.set_num_threads(max(1, int(threads)))
    set_seed(seed)
    class_names = list(train.class_names)
    arch = detector_architecture_config(n_classes=len(class_names), image_size=int(height), anchor_sizes=anchor_sizes,
                                        score_threshold=min(0.05, float(score_threshold)))
    model = build_detector_module(**arch)
    if pretrained and anchor_sizes is None:
        loaded, init_note = init_coco_weights(model)
    elif pretrained:
        loaded, init_note = False, ("random init (seeded): custom anchor_sizes make the RPN head incompatible with the "
                                    "COCO checkpoint")
    else:
        loaded, init_note = False, "random init (seeded): pretrained weights not requested"
    log(f"{ARCHITECTURE_ID}: {init_note}")

    params = [p for p in model.parameters() if p.requires_grad]
    optimizer = torch.optim.SGD(params, lr=lr, momentum=momentum, weight_decay=weight_decay)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    gen = torch.Generator().manual_seed(seed)
    x_train = as_model_input(train.x)
    history: list[dict[str, float]] = []
    t0 = time.perf_counter()
    for epoch in range(1, epochs + 1):
        model.train()
        order = torch.randperm(n_train, generator=gen).numpy()
        running = 0.0
        seen = 0
        for start in range(0, n_train, batch_size):
            idx = [int(i) for i in order[start:start + batch_size]]
            xb = torch.from_numpy(np.ascontiguousarray(x_train[idx]))
            losses = model(xb, _to_targets(train, idx))
            total = sum(losses.values())
            optimizer.zero_grad(set_to_none=True)
            total.backward()
            optimizer.step()
            running += float(total.detach().item()) * len(idx)
            seen += len(idx)
        scheduler.step()
        ev = evaluate_detector(model, eval_split, score_threshold=score_threshold, iou_threshold=iou_threshold)
        row = {"epoch": float(epoch), "train_loss": running / max(seen, 1),
               "eval_recall": float(ev.recall) if ev.recall is not None else float("nan"),
               "eval_map50": float(ev.map50) if ev.map50 is not None else float("nan")}
        history.append(row)
        log(f"epoch {epoch}/{epochs}: train_loss={row['train_loss']:.4f} eval_recall@{iou_threshold:g}="
            f"{ev.n_matched}/{ev.n_gt} eval_map50={row['eval_map50']:.4f}")
    wall = time.perf_counter() - t0
    model.eval()
    final = evaluate_detector(model, eval_split, score_threshold=score_threshold, iou_threshold=iou_threshold)
    metrics = {**final.as_metrics(), "history": history, "notes": [MODEST_MAP_NOTE, AP_INTERPOLATION_NOTE]}
    training = {
        "architecture_id": ARCHITECTURE_ID, "backbone_init": init_note, "coco_weights_loaded": loaded,
        "optimizer": "sgd", "lr": lr, "momentum": momentum, "weight_decay": weight_decay, "batch_size": batch_size,
        "lr_schedule": "cosine_annealing", "epochs": epochs, "seed": seed, "n_train": int(n_train),
        "n_train_boxes": int(train.n_boxes), "n_eval": int(eval_split.n), "n_eval_boxes": int(eval_split.n_boxes),
        "excluded_classes": list(train.excluded_classes), "device": "cpu", "torch_threads": torch.get_num_threads(),
        "wall_time_s": round(wall, 3), "loss": "sum of torchvision Faster R-CNN losses (classifier, box_reg, "
                                               "objectness, rpn_box_reg)",
        "selection": {"method": "last_epoch", "note": "the evaluation split is never used for selection"},
        "nondeterminism": ["thread count may change floating-point reduction order",
                           "torchvision RPN sampling uses torch's global RNG (seeded)"],
    }
    detection = detection_spec_block(score_threshold=score_threshold, iou_threshold=iou_threshold,
                                     class_names=class_names, input_size=[3, int(height), int(width)])
    return DetectorTrainingResult(model=model, metrics=metrics, training=training, architecture=arch,
                                  detection=detection, history=history)


def save_state_dict(model: Any, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), path)
    return path


def write_eval_slice(split: DetectionSplit, path: Path, *, dataset_id: str, dataset_revision: str | None = None) -> str:
    """Write the packed evaluation slice a ``BundledDetectionTarget`` loads; returns its sha256."""
    return save_detection_npz(Path(path), split, dataset_id=dataset_id, dataset_revision=dataset_revision)


__all__ = [
    "DEFAULT_BATCH_SIZE", "DEFAULT_EPOCHS", "DEFAULT_LR", "DEFAULT_MOMENTUM", "DEFAULT_WEIGHT_DECAY",
    "MODEST_MAP_NOTE", "DetectorTrainingResult", "evaluate_detector", "save_state_dict", "set_seed",
    "train_detector", "write_eval_slice",
]
