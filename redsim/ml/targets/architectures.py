"""In-tree architecture catalog for bundled and uploaded ``state_dict`` models.

A PyTorch ``state_dict`` carries tensors only, so the architecture that gives
those tensors meaning has to live in the repository. Free-form uploaded code is
never accepted (spec section 9.2): an upload names one of the ids in
``ARCHITECTURES`` and the loader instantiates that class.

Input contract shared with the attack and explain layers: ``x`` is float32 in
[0, 1], NCHW. Channel normalisation is the first step inside ``forward`` and
its mean / std are buffers, so they travel with the ``state_dict`` and every
consumer (ART, SHAP, the eps sweep) sees the same raw [0, 1] tensor.

``SmallCNN`` is deterministic under ``torch.manual_seed``: two instances built
after the same seed hold identical parameters and produce identical logits.
"""

from __future__ import annotations

from typing import Any

import torch
from torch import nn


class UnknownArchitecture(ValueError):
    """Raised when an ``architecture_id`` is not in the catalog."""


class SmallCNN(nn.Module):
    """Three-block convolutional classifier for small RGB images.

    Works at any ``image_size`` from 8 up because the last block pools to a
    fixed 4x4 grid; 32 is the CIFAR-10 fixture size, 128 the demo build size
    (spec section 11.3.1).
    """

    architecture_id = "small_cnn"
    input_mean: torch.Tensor
    input_std: torch.Tensor

    def __init__(self, in_channels: int = 3, n_classes: int = 10, image_size: int = 32) -> None:
        super().__init__()
        if in_channels < 1:
            raise ValueError("in_channels must be >= 1")
        if n_classes < 2:
            raise ValueError("n_classes must be >= 2")
        if image_size < 8:
            raise ValueError("image_size must be >= 8")
        self.in_channels = int(in_channels)
        self.n_classes = int(n_classes)
        self.image_size = int(image_size)

        # Identity normalisation until the build sets dataset statistics.
        self.register_buffer("input_mean", torch.zeros(1, self.in_channels, 1, 1))
        self.register_buffer("input_std", torch.ones(1, self.in_channels, 1, 1))

        self.features = nn.Sequential(
            nn.Conv2d(self.in_channels, 32, kernel_size=3, padding=1),
            nn.BatchNorm2d(32),
            nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.BatchNorm2d(64),
            nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Conv2d(64, 128, kernel_size=3, padding=1),
            nn.BatchNorm2d(128),
            nn.ReLU(),
            nn.AdaptiveAvgPool2d(4),
        )
        self.classifier = nn.Sequential(
            nn.Flatten(1),
            nn.Linear(128 * 4 * 4, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, self.n_classes),
        )

    @property
    def input_shape(self) -> tuple[int, int, int]:
        """ART ``input_shape`` for this model: (C, H, W)."""
        return (self.in_channels, self.image_size, self.image_size)

    def set_input_normalization(self, mean: torch.Tensor, std: torch.Tensor) -> None:
        """Store per-channel mean / std (in [0, 1] units) as buffers."""
        mean_t = torch.as_tensor(mean, dtype=torch.float32).reshape(1, self.in_channels, 1, 1)
        std_t = torch.as_tensor(std, dtype=torch.float32).reshape(1, self.in_channels, 1, 1)
        if bool((std_t <= 0).any()):
            raise ValueError("std must be strictly positive on every channel")
        self.input_mean.copy_(mean_t)
        self.input_std.copy_(std_t)

    def architecture_config(self) -> dict[str, Any]:
        """Constructor arguments, recorded in the asset manifest."""
        return {
            "architecture_id": self.architecture_id,
            "in_channels": self.in_channels,
            "n_classes": self.n_classes,
            "image_size": self.image_size,
        }

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Logits of shape (n, n_classes) for ``x`` float32 in [0, 1], NCHW."""
        x = (x - self.input_mean) / self.input_std
        logits: torch.Tensor = self.classifier(self.features(x))
        return logits


ARCHITECTURES: dict[str, type[nn.Module]] = {
    SmallCNN.architecture_id: SmallCNN,
}


def build_architecture(architecture_id: str, **kwargs: Any) -> nn.Module:
    """Instantiate a catalog architecture by id; unknown ids are refused."""
    try:
        cls = ARCHITECTURES[architecture_id]
    except KeyError:
        known = ", ".join(sorted(ARCHITECTURES))
        raise UnknownArchitecture(
            f"unknown architecture_id {architecture_id!r}; known ids: {known}"
        ) from None
    return cls(**kwargs)
