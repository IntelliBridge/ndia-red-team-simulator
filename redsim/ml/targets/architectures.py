"""In-tree architecture catalog for bundled and uploaded ``state_dict`` models.

A PyTorch ``state_dict`` carries tensors only, so the architecture that gives
those tensors meaning has to live in the repository. Free-form uploaded code is
never accepted (spec section 9.2): an upload names one of the ids in
``ARCHITECTURES`` and the loader instantiates that class.

Canonical ids are ``small_cnn`` and ``resnet18``. ``smallcnn`` is accepted as an
alias of ``small_cnn`` everywhere an id is read (``ARCHITECTURE_ALIASES``); the
alias resolves to the canonical id and the canonical id is what manifests
record.

Input contract shared with the attack and explain layers: ``x`` is float32 in
[0, 1], NCHW. Channel normalisation is the first step inside ``forward`` and
its mean / std are buffers, so they travel with the ``state_dict`` and every
consumer (ART, SHAP, the eps sweep) sees the same raw [0, 1] tensor.

``SmallCNN`` is deterministic under ``torch.manual_seed``: two instances built
after the same seed hold identical parameters and produce identical logits.
``ResNet18`` wraps torchvision's resnet18 adapted to the task's class count;
ImageNet weights are taken from the local torch hub cache only when present
(never downloaded) and the loader records which initialisation was used.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import torch
from torch import nn


class UnknownArchitecture(ValueError):
    """Raised when an ``architecture_id`` is not in the catalog."""


class CatalogModule(nn.Module):
    """Base of every catalog architecture: [0, 1] NCHW in, logits out, normalisation as buffers."""

    architecture_id: ClassVar[str] = ""
    input_mean: torch.Tensor
    input_std: torch.Tensor

    def __init__(self, in_channels: int, n_classes: int, image_size: int, *, min_image_size: int = 8) -> None:
        super().__init__()
        if in_channels < 1:
            raise ValueError("in_channels must be >= 1")
        if n_classes < 2:
            raise ValueError("n_classes must be >= 2")
        if image_size < min_image_size:
            raise ValueError(f"image_size must be >= {min_image_size}")
        self.in_channels = int(in_channels)
        self.n_classes = int(n_classes)
        self.image_size = int(image_size)
        # Identity normalisation until the build sets dataset statistics.
        self.register_buffer("input_mean", torch.zeros(1, self.in_channels, 1, 1))
        self.register_buffer("input_std", torch.ones(1, self.in_channels, 1, 1))

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
        """Constructor arguments, recorded in the asset manifest (``ModelEntry.architecture``)."""
        return {
            "architecture_id": self.architecture_id,
            "in_channels": self.in_channels,
            "n_classes": self.n_classes,
            "image_size": self.image_size,
        }

    def normalize(self, x: torch.Tensor) -> torch.Tensor:
        return (x - self.input_mean) / self.input_std


class SmallCNN(CatalogModule):
    """Three-block convolutional classifier for small RGB images.

    Works at any ``image_size`` from 8 up because the last block pools to a
    fixed 4x4 grid; 32 is the CIFAR-10 fixture size, 128 the demo build size
    (spec section 11.3.1).
    """

    architecture_id = "small_cnn"

    def __init__(self, in_channels: int = 3, n_classes: int = 10, image_size: int = 32) -> None:
        super().__init__(in_channels, n_classes, image_size, min_image_size=8)
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

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Logits of shape (n, n_classes) for ``x`` float32 in [0, 1], NCHW."""
        logits: torch.Tensor = self.classifier(self.features(self.normalize(x)))
        return logits


# ImageNet-1k weights torchvision publishes for resnet18; only the local hub cache is ever consulted.
RESNET18_IMAGENET_FILENAME = "resnet18-f37072fd.pth"


def imagenet_resnet18_checkpoint() -> Path | None:
    """The cached torchvision ImageNet checkpoint for resnet18, or ``None``. Never downloads."""
    try:
        hub_dir = Path(torch.hub.get_dir())
    except Exception:  # noqa: BLE001 - hub dir resolution can fail on locked-down hosts
        return None
    candidate = hub_dir / "checkpoints" / RESNET18_IMAGENET_FILENAME
    return candidate if candidate.is_file() else None


class ResNet18(CatalogModule):
    """torchvision ``resnet18`` with its head replaced for the task's class count.

    A stronger backbone for the vehicles model (spec 11.3.1 permits it). The
    backbone is randomly initialised unless ``init_imagenet_backbone`` is
    called by the build, which loads the ImageNet-1k weights from the local
    torch hub cache and reports whether it could; nothing is downloaded. The
    ``state_dict`` (backbone + head + normalisation buffers) is what ships, so
    a loader never needs the ImageNet file.
    """

    architecture_id = "resnet18"

    def __init__(self, in_channels: int = 3, n_classes: int = 7, image_size: int = 128) -> None:
        super().__init__(in_channels, n_classes, image_size, min_image_size=8)
        from torchvision.models import resnet18

        backbone = resnet18(weights=None, num_classes=self.n_classes)
        if self.in_channels != 3:
            backbone.conv1 = nn.Conv2d(self.in_channels, 64, kernel_size=7, stride=2, padding=3, bias=False)
        self.backbone = backbone
        self.backbone_init = "random"

    def init_imagenet_backbone(self) -> tuple[bool, str]:
        """Load ImageNet-1k backbone weights from the local hub cache when present; ``(loaded, note)``.

        The classification head keeps its random initialisation (the class count differs from
        ImageNet's 1000). Returns ``False`` with the reason when no cached checkpoint exists or the
        input channel count is not 3; nothing is fetched from the network.
        """
        path = imagenet_resnet18_checkpoint()
        if path is None:
            note = (f"random init: no cached ImageNet checkpoint at "
                    f"{Path(torch.hub.get_dir()) / 'checkpoints' / RESNET18_IMAGENET_FILENAME} (offline build)")
            self.backbone_init = "random"
            return False, note
        if self.in_channels != 3:
            self.backbone_init = "random"
            return False, f"random init: ImageNet weights need in_channels=3, got {self.in_channels}"
        state = torch.load(path, map_location="cpu", weights_only=True)
        if not isinstance(state, dict):
            self.backbone_init = "random"
            return False, f"random init: {path} is not a state_dict"
        backbone_state = {k: v for k, v in state.items() if not k.startswith("fc.")}
        missing, unexpected = self.backbone.load_state_dict(backbone_state, strict=False)
        stray = [k for k in missing if not k.startswith("fc.")] + list(unexpected)
        if stray:
            self.backbone_init = "random"
            return False, f"random init: cached checkpoint does not fit resnet18 ({stray[:3]})"
        self.backbone_init = f"imagenet1k_v1 from local cache {path}"
        return True, self.backbone_init

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Logits of shape (n, n_classes) for ``x`` float32 in [0, 1], NCHW."""
        logits: torch.Tensor = self.backbone(self.normalize(x))
        return logits


ARCHITECTURES: dict[str, type[CatalogModule]] = {
    SmallCNN.architecture_id: SmallCNN,
    ResNet18.architecture_id: ResNet18,
}

# Accepted spellings that are not canonical ids. Read everywhere an id comes in; never written out.
ARCHITECTURE_ALIASES: dict[str, str] = {"smallcnn": "small_cnn"}


def canonical_architecture_id(architecture_id: str) -> str:
    """The catalog id an alias stands for (a canonical id is returned unchanged)."""
    return ARCHITECTURE_ALIASES.get(architecture_id, architecture_id)


def architecture_ids(*, include_aliases: bool = False) -> list[str]:
    ids = set(ARCHITECTURES)
    if include_aliases:
        ids |= set(ARCHITECTURE_ALIASES)
    return sorted(ids)


def build_architecture(architecture_id: str, /, **kwargs: Any) -> CatalogModule:
    """Instantiate a catalog architecture by id (aliases accepted); unknown ids are refused.

    ``kwargs`` may carry the ``architecture_id`` key the builder records inside
    ``ModelEntry.architecture`` (so ``build_architecture(entry.architecture_id,
    **entry.architecture)`` works); it must agree with the positional id and is
    not passed to the constructor.
    """
    canonical = canonical_architecture_id(architecture_id)
    try:
        cls = ARCHITECTURES[canonical]
    except KeyError:
        known = ", ".join(architecture_ids(include_aliases=True))
        raise UnknownArchitecture(
            f"unknown architecture_id {architecture_id!r}; known ids: {known}"
        ) from None
    inner = kwargs.pop("architecture_id", None)
    if inner is not None and canonical_architecture_id(str(inner)) != canonical:
        raise UnknownArchitecture(
            f"architecture kwargs name {inner!r} but the entry declares {architecture_id!r}"
        )
    return cls(**kwargs)


__all__ = [
    "ARCHITECTURES",
    "ARCHITECTURE_ALIASES",
    "RESNET18_IMAGENET_FILENAME",
    "CatalogModule",
    "ResNet18",
    "SmallCNN",
    "UnknownArchitecture",
    "architecture_ids",
    "build_architecture",
    "canonical_architecture_id",
    "imagenet_resnet18_checkpoint",
]
