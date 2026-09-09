"""Benign random-noise control at the same eps and norm as the attack (spec 12.4).

No gradient, no query, no model access beyond the final prediction: the adapter
touches the target only to read the valid clipping range. Family ``control``;
it never creates a Finding and never enters the MRI. It has no entry in
``ATLAS_TECHNIQUES`` because a control demonstrates no adversarial technique
(spec 27.2).

Tabular targets (spec 12.9): the noise is drawn in min-max-scaled space on the declared
perturbable features only (``u ~ Uniform(-eps, eps)`` per scaled feature, or a random
direction over those features scaled to L2 norm eps), mapped back to raw units, clipped
to the declared range, and integer features are rounded. Norms are in scaled units.
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

import numpy as np

from redsim.ml.attacks import (
    CPU_FLOAT32_NOTE,
    NONDETERMINISM_PREFIX,
    TabularScaling,
    apply_mask,
    clip_range,
    library_versions,
    perturbable_mask,
    resolve_from_schema,
)
from redsim.ml.attacks.base import AttackOutput
from redsim.ml.eval import perturbation_norms
from redsim.ml.schema import AttackInfo, ParamSpec
from redsim.ml.targets.base import Target

NOISE_CONTROL_NOTE = "Uniform noise control drawn with numpy default_rng(seed)"
FROZEN_METHOD = "drawing the noise on the declared perturbable features only (frozen features receive no noise)"


class NoiseControlAdapter:
    id = "noise_control"
    domains = frozenset({"image", "tabular"})
    takes_eps = True
    capabilities: ClassVar[frozenset[str]] = frozenset({"adversarial_ml", "black_box", "takes_eps",
                                                        "family:control", "modality:image", "modality:tabular"})

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="eps", type="float", default=0.03, min=1e-6, max=1.0,
                  description=("Perturbation budget; mirrors the attack grid (L-inf: per element; tabular: "
                               "fraction of each declared feature's range).")),
        ParamSpec(name="norm_l2", type="bool", default=False,
                  description="Draw a random direction scaled to L2 norm eps instead of uniform L-inf noise."),
    ]

    def info(self) -> AttackInfo:
        return AttackInfo(
            id=self.id, name="Benign random-noise control", domain="image", family="control",
            description=("Same slice perturbed by uniform random noise inside the same eps ball as the "
                         "attack; separates gradient-aligned failure from ordinary noise sensitivity. "
                         "Never creates a Finding."),
            params_schema=list(self._schema),
            references=["spec section 12.4 (benign random-noise control)"],
            # No gradient and no model access beyond the final prediction, so it is listed as
            # black-box; ``requires_gradients`` is False for the same reason.
            phase="A", access="black-box", requires_gradients=False, status="available", reason=None,
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        return resolve_from_schema(self._schema, params)

    def run(self, target: Target, x: np.ndarray, y: np.ndarray,
            params: dict[str, float | int | bool], seed: int) -> AttackOutput:
        p = self.resolve_params(params)
        eps = float(p["eps"])
        x = np.asarray(x, dtype=np.float32)
        scaling = TabularScaling.from_target(target, x)
        t0 = time.perf_counter()
        rng = np.random.default_rng(int(seed))
        if scaling is not None:
            base, lo, hi = scaling.scale(x), np.float32(0.0), np.float32(1.0)
            mask = scaling.mask
        else:
            base = x
            lo, hi = clip_range(target, x)
            mask = perturbable_mask(target, x)
        if bool(p["norm_l2"]):
            direction = rng.standard_normal(size=x.shape).astype(np.float32)
            if mask is not None:
                direction = direction * mask  # the direction lives in the perturbable subspace
            flat = direction.reshape(x.shape[0], -1)
            norms = np.linalg.norm(flat, axis=1, keepdims=True)
            norms[norms < 1e-12] = 1.0
            u = (flat / norms * eps).reshape(x.shape)
            norm_note = "norm=L2: random direction scaled to norm eps"
        else:
            u = rng.uniform(-eps, eps, size=x.shape).astype(np.float32)
            if mask is not None:
                u = u * mask
            norm_note = "norm=Linf: u ~ Uniform(-eps, eps) per element"
        x_adv_base = np.clip(base + u, lo, hi).astype(np.float32)
        if scaling is not None:
            x_adv = scaling.finish(x, scaling.unscale(x_adv_base))
            linf, l2 = scaling.norms(x, x_adv)
        else:
            x_adv = apply_mask(x, x_adv_base, mask)
            linf, l2 = perturbation_norms(x, x_adv)
        wall = time.perf_counter() - t0
        notes = [norm_note, "gradient-free control: no model access beyond the final prediction"]
        if scaling is not None:
            notes.append("noise drawn in min-max-scaled feature space (eps as a fraction of each declared range) "
                         "and mapped back to raw units")
            notes.extend(scaling.notes(frozen_method=FROZEN_METHOD))
        elif mask is not None:
            notes.append(f"frozen features held at their clean values by {FROZEN_METHOD}")
        notes.extend([f"{NONDETERMINISM_PREFIX}{NOISE_CONTROL_NOTE}", f"{NONDETERMINISM_PREFIX}{CPU_FLOAT32_NOTE}"])
        return AttackOutput(
            x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=wall, params=dict(p),
            library_versions=library_versions(), notes=notes,
        )


ADAPTER: NoiseControlAdapter = NoiseControlAdapter()
