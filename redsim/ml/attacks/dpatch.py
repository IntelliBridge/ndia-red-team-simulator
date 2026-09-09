"""DPatch adversarial-patch attack on object detectors and its benign patch control (spec 12.2 detection row,
12.4; register MODALITIES-32, -33).

Budget: ``eps`` is the patch area as a share of the image (norm ``patch_area``, grid {0.01, 0.03, 0.05}).
The patch is square with side ``round(sqrt(eps * H * W))`` pixels (at least 1), so the realised share is
``side**2 / (H * W)`` and is recorded next to the requested ``eps`` on every row. One patch is optimised
per slice and per eps with ART's ``DPatch`` (untargeted: gradient ascent on the detector's loss against the
ground-truth boxes), then pasted onto every image at a seeded location. Pixels under the patch are
replaced, not perturbed, so ``linf_norm_mean`` is large by construction and ``notes`` say so.

The control (``patch_noise_control``) pastes a uniform-random patch of the same side at the same seeded
locations; it reads nothing from the model. Both adapters declare ``domains = {"detection"}`` and
``norms = {"patch_area"}``; ``redsim.ml.attacks`` registers both into ``ATTACKS`` with the bundled
adapters (``patch_noise_control`` keeps ``family:control`` so it is never mistaken for an attack).
``RobustDPatch`` (rotations, brightness, crops) is not used: the deviation from a physical patch is
stated in the notes rather than approximated.
"""

from __future__ import annotations

import math
import random
import time
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

import numpy as np

from redsim.ml.attacks import (
    CPU_FLOAT32_NOTE,
    NONDETERMINISM_PREFIX,
    library_versions,
    resolve_from_schema,
    seed_all,
)
from redsim.ml.attacks.base import AttackOutput
from redsim.ml.errors import AttackNotApplicable
from redsim.ml.eval import perturbation_norms
from redsim.ml.schema import AttackInfo, ParamSpec
from redsim.ml.targets.base import Target
from redsim.ml.targets.detection import DETECTION_DOMAIN, MODALITY, art_targets

DPATCH_ID = "dpatch"
PATCH_CONTROL_ID = "patch_noise_control"
DEFAULT_PATCH_AREA_GRID: tuple[float, ...] = (0.01, 0.03, 0.05)
DEFAULT_REFERENCE_PATCH_AREA = 0.03
PATCH_NONDETERMINISM_NOTE = ("DPatch location sampling and sign-gradient ascent use ART's internal RNGs (python "
                             "random, numpy, torch) seeded per run")
PATCH_CONTROL_NOTE = "Uniform-noise patch control drawn with numpy default_rng(seed) at the attack's seeded locations"
UNIVERSAL_PATCH_NOTE = "universal patch: one patch optimised over the whole slice per eps, pasted on every image"
REPLACEMENT_NOTE = ("pixels under the patch are replaced, not perturbed: linf_norm_mean / l2_norm_mean describe the "
                    "pasted patch and are large by construction; the budget is the patch area share (eps)")
DIGITAL_PATCH_NOTE = ("digital patch: no rotation, scale, brightness or printing transforms (RobustDPatch not used); "
                      "physical realisability is not established")


def patch_side(eps: float, height: int, width: int) -> int:
    """Side in pixels of the square patch whose area share is ``eps``: ``round(sqrt(eps * H * W))``, in [1, min(H, W)]."""
    if not 0.0 < float(eps) <= 1.0:
        raise ValueError("eps (patch area share) must lie in (0, 1]")
    side = int(round(math.sqrt(float(eps) * height * width)))
    return max(1, min(side, int(min(height, width))))


def realised_area_share(side: int, height: int, width: int) -> float:
    return float(side * side) / float(height * width)


def patch_locations(n: int, height: int, width: int, side: int, seed: int) -> np.ndarray:
    """Seeded top-left ``(row, col)`` per image, uniform over the placements that keep the patch inside."""
    rng = np.random.default_rng(int(seed))
    rows = rng.integers(0, height - side + 1, size=n)
    cols = rng.integers(0, width - side + 1, size=n)
    return np.stack([rows, cols], axis=1).astype(np.int64)


def paste_patch(x: np.ndarray, patch: np.ndarray, locations: np.ndarray) -> np.ndarray:
    """Paste ``patch`` (C, s, s) onto every image of ``x`` (N, C, H, W) at ``locations[i] = (row, col)``."""
    x_adv = np.array(x, dtype=np.float32, copy=True)
    side = int(patch.shape[-1])
    for i in range(x_adv.shape[0]):
        r, c = int(locations[i, 0]), int(locations[i, 1])
        x_adv[i, :, r:r + side, c:c + side] = patch
    return x_adv


def _estimator(target: Target) -> Any:
    fn = getattr(target, "art_estimator", None)
    est = fn() if callable(fn) else target.art_classifier()
    if not hasattr(est, "loss_gradient"):
        raise AttackNotApplicable("dpatch needs a differentiable object detector: the target's ART estimator has no "
                                  "loss_gradient; recorded as not run")
    return est


def _check_images(x: np.ndarray) -> tuple[int, int, int, int]:
    if x.ndim != 4:
        raise AttackNotApplicable(f"dpatch applies to NCHW images, got shape {x.shape}")
    n, c, h, w = (int(d) for d in x.shape)
    if n == 0:
        raise AttackNotApplicable("empty slice")
    return n, c, h, w


class DPatchAdapter:
    id: str = DPATCH_ID
    domains = frozenset({MODALITY})
    norms: ClassVar[frozenset[str]] = frozenset({"patch_area"})    # the budget is an area share, not a pixel norm
    takes_eps = True
    capabilities: ClassVar[frozenset[str]] = frozenset({"adversarial_ml", "white_box", "takes_eps", "family:evasion"})

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="eps", type="float", default=DEFAULT_REFERENCE_PATCH_AREA, min=1e-4, max=1.0,
                  description="Patch area as a share of the image (norm patch_area); side = round(sqrt(eps * H * W))."),
        ParamSpec(name="max_iter", type="int", default=10, min=1, max=50,
                  description="Sign-gradient ascent steps on the patch (ART DPatch max_iter)."),
        ParamSpec(name="learning_rate", type="float", default=5.0, min=1e-3, max=255.0,
                  description="ART DPatch step size in [0, 1] pixel units per iteration (clipped to [0, 1])."),
        ParamSpec(name="batch_size", type="int", default=4, min=1, max=16,
                  description="Images per gradient batch (bounded: detector gradients are memory-heavy on CPU)."),
    ]

    def info(self) -> AttackInfo:
        return AttackInfo(
            id=self.id, name="DPatch (untargeted adversarial patch on an object detector)", domain=DETECTION_DOMAIN,
            family="evasion",
            description=("One square patch per slice and eps, optimised by sign-gradient ascent on the detector's "
                         "loss against the ground-truth boxes and pasted at a seeded location per image. The budget "
                         "is the patch area share of the image (norm patch_area). Measured as suppressed detections."),
            params_schema=list(self._schema),
            references=["Liu, Yang, Fan, Song, Hu, Xie 2019, DPatch: An Adversarial Patch Attack on Object Detectors, "
                        "arXiv:1806.02299",
                        "art.attacks.evasion.DPatch"],
            phase="B", access="white-box", requires_gradients=True, status="available", reason=None,
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        return resolve_from_schema(self._schema, params)

    def run(self, target: Target, x: np.ndarray, y: np.ndarray, params: dict[str, float | int | bool], seed: int,
            *, targets: Sequence[Mapping[str, np.ndarray]] | None = None) -> AttackOutput:
        """``targets`` are the slice's ground-truth boxes (0-based labels); without them DPatch falls back to the
        detector's own clean predictions as the untargeted objective (ART's default) and the row says so."""
        from art.attacks.evasion import DPatch

        p = self.resolve_params(params)
        eps = float(p["eps"])
        x = np.asarray(x, dtype=np.float32)
        n, c, h, w = _check_images(x)
        estimator = _estimator(target)
        side = patch_side(eps, h, w)
        share = realised_area_share(side, h, w)
        label_offset = int(getattr(target, "label_offset", 1))
        y_art = art_targets(targets, label_offset=label_offset) if targets is not None else None
        if y_art is not None and len(y_art) != n:
            raise AttackNotApplicable(f"{len(y_art)} target dicts for {n} images")

        seed_all(seed)
        random.seed(int(seed))
        t0 = time.perf_counter()
        attack = DPatch(estimator, patch_shape=(c, side, side), learning_rate=float(p["learning_rate"]),
                        max_iter=int(p["max_iter"]), batch_size=int(p["batch_size"]), verbose=False)
        patch = np.asarray(attack.generate(x=x, y=y_art), dtype=np.float32)
        patch = np.clip(patch, 0.0, 1.0)
        locations = patch_locations(n, h, w, side, seed)
        x_adv = np.clip(paste_patch(x, patch, locations), 0.0, 1.0).astype(np.float32)
        linf, l2 = perturbation_norms(x, x_adv)
        wall = time.perf_counter() - t0

        notes = [
            (f"patch area share eps={eps:g} -> side {side} px on {h}x{w} (realised share {share:.4f}); "
             f"max_iter={int(p['max_iter'])}, learning_rate={float(p['learning_rate']):g}"),
            UNIVERSAL_PATCH_NOTE, REPLACEMENT_NOTE, DIGITAL_PATCH_NOTE,
            f"patch pasted at a seeded top-left location per image (numpy default_rng({int(seed)}))",
            ("objective: untargeted loss ascent against the ground-truth boxes" if y_art is not None else
             "objective: no ground truth handed to the adapter; DPatch used the detector's own clean predictions "
             "as the untargeted objective (ART default)"),
            f"{NONDETERMINISM_PREFIX}{PATCH_NONDETERMINISM_NOTE}",
            f"{NONDETERMINISM_PREFIX}{CPU_FLOAT32_NOTE}",
        ]
        versions = library_versions()
        try:
            import torchvision

            versions["torchvision"] = str(torchvision.__version__)
        except Exception:  # noqa: BLE001 - version probing only
            pass
        return AttackOutput(
            x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=wall,
            params={**p, "patch_side": side, "patch_area_share_realised": share},
            library_versions=versions, notes=notes,
        )


class PatchNoiseControlAdapter:
    """Benign control: a uniform-random patch of the same area share at the same seeded locations (spec 12.4)."""

    id: str = PATCH_CONTROL_ID
    domains = frozenset({MODALITY})
    norms: ClassVar[frozenset[str]] = frozenset({"patch_area"})
    takes_eps = True
    capabilities: ClassVar[frozenset[str]] = frozenset({"adversarial_ml", "black_box", "takes_eps", "family:control"})

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="eps", type="float", default=DEFAULT_REFERENCE_PATCH_AREA, min=1e-4, max=1.0,
                  description="Patch area share; mirrors the attack grid so the control sits at the same budget."),
    ]

    def info(self) -> AttackInfo:
        return AttackInfo(
            id=self.id, name="Benign random-patch control", domain=DETECTION_DOMAIN,
            family="control",
            description=("Same slice with a uniform-random patch of the same area share pasted at the same seeded "
                         "locations as the attack; separates patch-optimised suppression from occlusion "
                         "sensitivity. Never creates a Finding."),
            params_schema=list(self._schema),
            references=["spec section 12.4 (benign random-noise control)"],
            phase="B", access="black-box", requires_gradients=False, status="available", reason=None,
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        return resolve_from_schema(self._schema, params)

    def run(self, target: Target, x: np.ndarray, y: np.ndarray, params: dict[str, float | int | bool], seed: int,
            *, targets: Sequence[Mapping[str, np.ndarray]] | None = None) -> AttackOutput:
        p = self.resolve_params(params)
        eps = float(p["eps"])
        x = np.asarray(x, dtype=np.float32)
        n, c, h, w = _check_images(x)
        side = patch_side(eps, h, w)
        share = realised_area_share(side, h, w)
        t0 = time.perf_counter()
        rng = np.random.default_rng(int(seed))
        patch = rng.uniform(0.0, 1.0, size=(c, side, side)).astype(np.float32)
        locations = patch_locations(n, h, w, side, seed)
        x_adv = np.clip(paste_patch(x, patch, locations), 0.0, 1.0).astype(np.float32)
        linf, l2 = perturbation_norms(x, x_adv)
        wall = time.perf_counter() - t0
        notes = [
            f"control patch: uniform noise, side {side} px on {h}x{w} (realised share {share:.4f}) for eps={eps:g}",
            "gradient-free control: no model access at all; pasted at the same seeded locations as the attack",
            REPLACEMENT_NOTE,
            f"{NONDETERMINISM_PREFIX}{PATCH_CONTROL_NOTE}", f"{NONDETERMINISM_PREFIX}{CPU_FLOAT32_NOTE}",
        ]
        return AttackOutput(
            x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=wall,
            params={**p, "patch_side": side, "patch_area_share_realised": share},
            library_versions=library_versions(), notes=notes,
        )


ADAPTER: DPatchAdapter = DPatchAdapter()
CONTROL: PatchNoiseControlAdapter = PatchNoiseControlAdapter()

__all__ = [
    "ADAPTER", "CONTROL", "DEFAULT_PATCH_AREA_GRID", "DEFAULT_REFERENCE_PATCH_AREA", "DIGITAL_PATCH_NOTE",
    "DPATCH_ID", "PATCH_CONTROL_ID", "PATCH_CONTROL_NOTE", "PATCH_NONDETERMINISM_NOTE",
    "REPLACEMENT_NOTE", "UNIVERSAL_PATCH_NOTE", "DPatchAdapter", "PatchNoiseControlAdapter", "paste_patch",
    "patch_locations", "patch_side", "realised_area_share",
]
