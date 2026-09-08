"""Seeded CPU training of ``SmallCNN`` for the bundled image models.

Inputs are uint8 NCHW splits from ``redsim.ml.assets.datasets``; pixels are
scaled to float32 [0, 1] per batch and the per-channel mean / std of the
training split are stored inside the model as buffers (spec 11.3.1). Every
number that ends up in the manifest (clean accuracy, per-class counts, loss
curve) is measured here, never asserted.
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

from redsim.ml.targets.architectures import SmallCNN

Log = Callable[[str], None]


@dataclass
class CnnTrainingResult:
    model: SmallCNN
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


def train_small_cnn(x_train: np.ndarray, y_train: np.ndarray, x_eval: np.ndarray, y_eval: np.ndarray,
                    class_names: list[str], *, epochs: int = 3, seed: int = 0, batch_size: int = 64,
                    lr: float = 1e-3, weight_decay: float = 1e-4, log: Log = print) -> CnnTrainingResult:
    """Train ``SmallCNN`` on CPU with a fixed seed and measure it on the eval split."""
    if x_train.ndim != 4 or x_train.dtype != np.uint8:
        raise ValueError("x_train must be uint8 NCHW")
    if epochs < 1:
        raise ValueError("epochs must be >= 1")
    n_train, in_channels, height, width = x_train.shape
    if height != width:
        raise ValueError("images must be square")
    set_seed(seed)
    torch.set_num_threads(max(1, torch.get_num_threads()))

    model = SmallCNN(in_channels=in_channels, n_classes=len(class_names), image_size=height)
    mean, std = channel_stats(x_train)
    model.set_input_normalization(torch.from_numpy(mean), torch.from_numpy(std))

    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)
    loss_fn = nn.CrossEntropyLoss()
    gen = torch.Generator().manual_seed(seed)
    y_train_t = torch.from_numpy(np.asarray(y_train, dtype=np.int64))

    history: list[dict[str, float]] = []
    t0 = time.perf_counter()
    for epoch in range(1, epochs + 1):
        model.train()
        order = torch.randperm(n_train, generator=gen).numpy()
        running = 0.0
        seen = 0
        for start in range(0, n_train, batch_size):
            idx = order[start:start + batch_size]
            if len(idx) < 2 and n_train > 1:
                continue  # BatchNorm needs more than one sample per batch
            xb = _to_float_batch(x_train[idx])
            yb = y_train_t[idx]
            optimizer.zero_grad(set_to_none=True)
            loss = loss_fn(model(xb), yb)
            loss.backward()
            optimizer.step()
            running += float(loss.item()) * len(idx)
            seen += len(idx)
        train_loss = running / max(seen, 1)
        eval_metrics = evaluate_model(model, x_eval, y_eval, class_names)
        history.append({"epoch": float(epoch), "train_loss": train_loss,
                        "eval_accuracy": float(eval_metrics["clean_accuracy"])})
        log(f"epoch {epoch}/{epochs}: train_loss={train_loss:.4f} eval_accuracy={eval_metrics['clean_accuracy']:.4f}")
    wall = time.perf_counter() - t0

    model.eval()
    metrics = evaluate_model(model, x_eval, y_eval, class_names)
    metrics["history"] = history
    training = {
        "optimizer": "adam", "lr": lr, "weight_decay": weight_decay, "batch_size": batch_size,
        "epochs": epochs, "seed": seed, "n_train": int(n_train), "n_eval": len(y_eval),
        "device": "cpu", "torch_threads": torch.get_num_threads(), "wall_time_s": round(wall, 3),
        "input_mean": mean.tolist(), "input_std": std.tolist(),
        "loss": "cross_entropy", "nondeterminism": ["thread count may change floating-point reduction order"],
    }
    return CnnTrainingResult(model=model, metrics=metrics, training=training, history=history)


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
    return model.eval()
