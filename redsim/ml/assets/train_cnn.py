"""Seeded CPU training of a catalog image architecture for the bundled image models.

Inputs are uint8 NCHW splits from ``redsim.ml.assets.datasets``; pixels are
scaled to float32 [0, 1] per batch and the per-channel mean / std of the
training split are stored inside the model as buffers (spec 11.3.1). Every
number that ends up in the manifest (clean accuracy, per-class counts, loss
curve) is measured here, never asserted.

``train_cnn`` builds the architecture named by ``arch`` from the in-tree
catalog (``small_cnn`` by default, ``resnet18`` for the stronger vehicles
backbone). For ``resnet18`` the ImageNet backbone weights are loaded only from
the local torch hub cache; when they are absent the model starts from a random
init and the training record says so. ``train_small_cnn`` is the original
name and stays as a thin wrapper.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn

from redsim.ml.targets.architectures import (
    CatalogModule,
    ResNet18,
    SmallCNN,
    build_architecture,
    canonical_architecture_id,
)

Log = Callable[[str], None]


@dataclass
class CnnTrainingResult:
    model: CatalogModule
    metrics: dict[str, Any]
    training: dict[str, Any]
    history: list[dict[str, float]] = field(default_factory=list)


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def channel_stats(x_uint8: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Per-channel mean / std in [0, 1] units of a uint8 NCHW array."""
    x = x_uint8.astype(np.float64) / 255.0
    mean = x.mean(axis=(0, 2, 3))
    std = x.std(axis=(0, 2, 3))
    std = np.where(std < 1e-3, 1.0, std)
    return mean.astype(np.float32), std.astype(np.float32)


def _to_float_batch(x_uint8: np.ndarray) -> torch.Tensor:
    return torch.from_numpy(np.ascontiguousarray(x_uint8)).to(torch.float32).div_(255.0)


@torch.no_grad()
def predict_logits(model: nn.Module, x_uint8: np.ndarray, batch_size: int = 256) -> np.ndarray:
    model.eval()
    outs: list[np.ndarray] = []
    for start in range(0, len(x_uint8), batch_size):
        outs.append(model(_to_float_batch(x_uint8[start:start + batch_size])).cpu().numpy())
    if not outs:
        return np.zeros((0, getattr(model, "n_classes", 0)), dtype=np.float32)
    return np.concatenate(outs)


def classification_metrics(y_true: np.ndarray, y_pred: np.ndarray, class_names: list[str]) -> dict[str, Any]:
    """n, n_correct, clean accuracy, per-class n / n_correct, macro F1 (all measured)."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    n = len(y_true)
    n_correct = int((y_true == y_pred).sum())
    per_class: dict[str, dict[str, int]] = {}
    f1s: list[float] = []
    for i, name in enumerate(class_names):
        mask = y_true == i
        tp = int(((y_pred == i) & mask).sum())
        fp = int(((y_pred == i) & ~mask).sum())
        fn = int((mask & (y_pred != i)).sum())
        per_class[name] = {"n": int(mask.sum()), "n_correct": tp}
        denom = 2 * tp + fp + fn
        if mask.any() or fp:
            f1s.append((2 * tp / denom) if denom else 0.0)
    return {
        "n": n,
        "n_correct": n_correct,
        "clean_accuracy": (n_correct / n) if n else 0.0,
        "macro_f1": float(np.mean(f1s)) if f1s else 0.0,
        "per_class": per_class,
    }


def evaluate_model(model: nn.Module, x_uint8: np.ndarray, y: np.ndarray, class_names: list[str],
                   batch_size: int = 256) -> dict[str, Any]:
    logits = predict_logits(model, x_uint8, batch_size)
    return classification_metrics(y, logits.argmax(axis=1), class_names)


def build_image_model(arch: str, *, in_channels: int, n_classes: int, image_size: int,
                      log: Log = print) -> tuple[CatalogModule, dict[str, Any]]:
    """Instantiate the catalog architecture for a build and report how it was initialised.

    ``resnet18`` tries the locally cached ImageNet backbone (never a download); the second
    element records ``backbone_init`` so the manifest states random vs pretrained init.
    """
    model = build_architecture(arch, in_channels=in_channels, n_classes=n_classes, image_size=image_size)
    init: dict[str, Any] = {"backbone_init": "random (seeded)"}
    if isinstance(model, ResNet18):
        loaded, note = model.init_imagenet_backbone()
        init = {"backbone_init": note, "imagenet_backbone_loaded": loaded}
        log(f"resnet18: {note}")
    return model, init


# Fine-tuning defaults for the pretrained backbone: a lower step size with cosine decay,
# light augmentation, and best-epoch selection on a validation slice carved from the
# TRAINING split (the eval split is never used for selection, so its accuracy stays honest).
RESNET18_FINETUNE_LR = 3e-4
SELECTION_VAL_FRACTION = 0.1
SELECTION_MIN_TRAIN = 50


def _augment_batch(xb: torch.Tensor, gen: torch.Generator) -> torch.Tensor:
    """Random horizontal flip plus a random crop after reflect padding (1/16 of the side)."""
    n, _, h, w = xb.shape
    flip = torch.rand(n, generator=gen) < 0.5
    if bool(flip.any()):
        xb = xb.clone()
        xb[flip] = torch.flip(xb[flip], dims=[3])
    pad = max(1, h // 16)
    padded = torch.nn.functional.pad(xb, (pad, pad, pad, pad), mode="reflect")
    dy = int(torch.randint(0, 2 * pad + 1, (1,), generator=gen).item())
    dx = int(torch.randint(0, 2 * pad + 1, (1,), generator=gen).item())
    return padded[:, :, dy:dy + h, dx:dx + w]


def _selection_split(n_train: int, y_train: np.ndarray, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Seeded per-class hold-out of ``SELECTION_VAL_FRACTION`` of the training rows for epoch selection."""
    rng = np.random.default_rng(seed)
    val: list[int] = []
    for cls in np.unique(y_train):
        rows = np.flatnonzero(y_train == cls)
        rng.shuffle(rows)
        k = max(1, int(round(len(rows) * SELECTION_VAL_FRACTION)))
        val.extend(rows[:k].tolist())
    val_idx = np.array(sorted(val), dtype=np.int64)
    mask = np.ones(n_train, dtype=bool)
    mask[val_idx] = False
    return np.flatnonzero(mask), val_idx


def train_cnn(x_train: np.ndarray, y_train: np.ndarray, x_eval: np.ndarray, y_eval: np.ndarray,
              class_names: list[str], *, arch: str = "small_cnn", epochs: int = 3, seed: int = 0,
              batch_size: int = 64, lr: float | None = None, weight_decay: float = 1e-4,
              augment: bool | None = None, select_best: bool | None = None,
              log: Log = print) -> CnnTrainingResult:
    """Train the catalog architecture ``arch`` on CPU with a fixed seed and measure it on the eval split.

    ``lr``, ``augment`` and ``select_best`` default per architecture: ``small_cnn`` keeps the original
    recipe (1e-3, no augmentation, last epoch); ``resnet18`` fine-tunes at ``RESNET18_FINETUNE_LR``
    with cosine decay, flip/crop augmentation and best-epoch selection on a validation slice held out
    of the training split. Every choice is recorded in the returned ``training`` record.
    """
    if x_train.ndim != 4 or x_train.dtype != np.uint8:
        raise ValueError("x_train must be uint8 NCHW")
    if epochs < 1:
        raise ValueError("epochs must be >= 1")
    n_train, in_channels, height, width = x_train.shape
    if height != width:
        raise ValueError("images must be square")
    arch = canonical_architecture_id(arch)
    finetune = arch == "resnet18"
    if lr is None:
        lr = RESNET18_FINETUNE_LR if finetune else 1e-3
    if augment is None:
        augment = finetune
    if select_best is None:
        select_best = finetune
    set_seed(seed)
    torch.set_num_threads(max(1, torch.get_num_threads()))

    model, init = build_image_model(arch, in_channels=in_channels, n_classes=len(class_names), image_size=height,
                                    log=log)
    mean, std = channel_stats(x_train)
    model.set_input_normalization(torch.from_numpy(mean), torch.from_numpy(std))

    y_train_all = np.asarray(y_train, dtype=np.int64)
    selection: dict[str, Any] = {"method": "last_epoch"}
    fit_idx = np.arange(n_train)
    val_idx = np.zeros(0, dtype=np.int64)
    if select_best:
        if n_train >= SELECTION_MIN_TRAIN:
            fit_idx, val_idx = _selection_split(n_train, y_train_all, seed)
            selection = {"method": "best_epoch_by_validation_accuracy", "val_fraction": SELECTION_VAL_FRACTION,
                         "n_fit": int(len(fit_idx)), "n_val": int(len(val_idx)),
                         "note": "validation rows are held out of the training split; the eval split is never "
                                 "used for selection"}
        else:
            selection = {"method": "last_epoch", "note": f"n_train < {SELECTION_MIN_TRAIN}: no validation hold-out"}
            select_best = False

    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs) if finetune else None
    loss_fn = nn.CrossEntropyLoss()
    gen = torch.Generator().manual_seed(seed)
    y_train_t = torch.from_numpy(y_train_all)
    n_fit = int(len(fit_idx))

    history: list[dict[str, float]] = []
    best_state: dict[str, torch.Tensor] | None = None
    best_epoch = 0
    best_val = -1.0
    t0 = time.perf_counter()
    for epoch in range(1, epochs + 1):
        model.train()
        order = fit_idx[torch.randperm(n_fit, generator=gen).numpy()]
        running = 0.0
        seen = 0
        for start in range(0, n_fit, batch_size):
            idx = order[start:start + batch_size]
            if len(idx) < 2 and n_fit > 1:
                continue  # BatchNorm needs more than one sample per batch
            xb = _to_float_batch(x_train[idx])
            if augment:
                xb = _augment_batch(xb, gen)
            yb = y_train_t[idx]
            optimizer.zero_grad(set_to_none=True)
            loss = loss_fn(model(xb), yb)
            loss.backward()
            optimizer.step()
            running += float(loss.item()) * len(idx)
            seen += len(idx)
        if scheduler is not None:
            scheduler.step()
        train_loss = running / max(seen, 1)
        eval_metrics = evaluate_model(model, x_eval, y_eval, class_names)
        row = {"epoch": float(epoch), "train_loss": train_loss,
               "eval_accuracy": float(eval_metrics["clean_accuracy"])}
        msg = f"epoch {epoch}/{epochs}: train_loss={train_loss:.4f} eval_accuracy={eval_metrics['clean_accuracy']:.4f}"
        if select_best:
            val_metrics = evaluate_model(model, x_train[val_idx], y_train_all[val_idx], class_names)
            val_acc = float(val_metrics["clean_accuracy"])
            row["val_accuracy"] = val_acc
            msg += f" val_accuracy={val_acc:.4f}"
            if val_acc > best_val:
                best_val, best_epoch = val_acc, epoch
                best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
                msg += " *"
        history.append(row)
        log(msg)
    wall = time.perf_counter() - t0

    if select_best and best_state is not None:
        model.load_state_dict(best_state, strict=True)
        selection.update({"best_epoch": best_epoch, "best_val_accuracy": best_val})
        log(f"selected epoch {best_epoch}/{epochs} (val_accuracy={best_val:.4f})")
    model.eval()
    metrics = evaluate_model(model, x_eval, y_eval, class_names)
    metrics["history"] = history
    training = {
        "architecture_id": arch, **init,
        "optimizer": "adam", "lr": lr, "weight_decay": weight_decay, "batch_size": batch_size,
        "lr_schedule": "cosine_annealing" if scheduler is not None else "constant",
        "augmentation": ["random_horizontal_flip", "random_crop_reflect_pad"] if augment else [],
        "selection": selection,
        "epochs": epochs, "seed": seed, "n_train": int(n_train), "n_eval": len(y_eval),
        "device": "cpu", "torch_threads": torch.get_num_threads(), "wall_time_s": round(wall, 3),
        "input_mean": mean.tolist(), "input_std": std.tolist(),
        "loss": "cross_entropy", "nondeterminism": ["thread count may change floating-point reduction order"],
    }
    return CnnTrainingResult(model=model, metrics=metrics, training=training, history=history)


def train_small_cnn(x_train: np.ndarray, y_train: np.ndarray, x_eval: np.ndarray, y_eval: np.ndarray,
                    class_names: list[str], *, epochs: int = 3, seed: int = 0, batch_size: int = 64,
                    lr: float = 1e-3, weight_decay: float = 1e-4, log: Log = print) -> CnnTrainingResult:
    """``train_cnn`` with ``arch="small_cnn"`` (the original entry point)."""
    return train_cnn(x_train, y_train, x_eval, y_eval, class_names, arch="small_cnn", epochs=epochs, seed=seed,
                     batch_size=batch_size, lr=lr, weight_decay=weight_decay, log=log)


def save_state_dict(model: nn.Module, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), path)
    return path


def load_small_cnn(path: Path, *, in_channels: int, n_classes: int, image_size: int) -> SmallCNN:
    """Rebuild a ``SmallCNN`` from a ``state_dict`` file (tensors only, ``weights_only=True``)."""
    model = SmallCNN(in_channels=in_channels, n_classes=n_classes, image_size=image_size)
    state = torch.load(Path(path), map_location="cpu", weights_only=True)
    model.load_state_dict(state, strict=True)
    model.eval()
    return model
