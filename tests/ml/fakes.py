"""Shared test doubles. ``TinyTarget`` satisfies the Target protocol with a
random-weight 1-conv model on 8x8x3 inputs and 3 classes, so attack / explain /
run tests never need the CIFAR-10 assets or the network."""

from __future__ import annotations

import hashlib
from typing import Any

import numpy as np
import torch
from torch import nn

from aegis.ml.schema import TargetInfo
from aegis.ml.targets.base import Sample

CLASS_NAMES = ["circle", "square", "triangle"]


class _TinyNet(nn.Module):
    def __init__(self, seed: int = 0) -> None:
        super().__init__()
        torch.manual_seed(seed)
        self.conv = nn.Conv2d(3, 4, kernel_size=3, padding=1)
        self.fc = nn.Linear(4 * 8 * 8, len(CLASS_NAMES))

    def forward(self, x: torch.Tensor) -> torch.Tensor:  # noqa: D401
        return self.fc(torch.relu(self.conv(x)).flatten(1))


class TinyTarget:
    id = "tiny"

    def __init__(self, seed: int = 0) -> None:
        self._net = _TinyNet(seed).eval()
        self._clf: Any = None

    def info(self) -> TargetInfo:
        return TargetInfo(id=self.id, name="Tiny random CNN (test double)", domain="image",
                          status="available", metadata={"dataset": "synthetic", "n_classes": 3})

    def load(self) -> None:
        return None

    def sample(self, n: int, seed: int) -> Sample:
        rng = np.random.default_rng(seed)
        x = rng.random((n, 3, 8, 8), dtype=np.float32)
        y = rng.integers(0, len(CLASS_NAMES), size=n)
        return Sample(x=x, y=y, indices=np.arange(n), class_names=list(CLASS_NAMES))

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        with torch.no_grad():
            logits = self._net(torch.from_numpy(np.asarray(x, dtype=np.float32)))
            return torch.softmax(logits, dim=1).numpy()

    def art_classifier(self) -> Any:
        if self._clf is None:
            from art.estimators.classification import PyTorchClassifier
            self._clf = PyTorchClassifier(
                model=self._net, loss=nn.CrossEntropyLoss(), input_shape=(3, 8, 8),
                nb_classes=len(CLASS_NAMES), clip_values=(0.0, 1.0), device_type="cpu",
            )
        return self._clf

    def torch_model(self) -> Any:
        return self._net

    def manifest(self) -> dict[str, Any]:
        blob = b"".join(p.detach().numpy().tobytes() for p in self._net.parameters())
        return {"dataset": "synthetic", "split": "none", "model": "TinyNet",
                "weights_sha256": hashlib.sha256(blob).hexdigest()}
