"""Benign random-noise control at the same eps and norm as the attack (spec 12.4).

No gradient, no query, no model access beyond the final prediction: the adapter
touches the target only to read the valid clipping range. Family ``control``;
it never creates a Finding and never enters the MRI. Its ATLAS technique is
``None`` because a control demonstrates no adversarial technique (spec 27.2).
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

import numpy as np

from redsim.ml.attacks import (
    CPU_FLOAT32_NOTE,
    NONDETERMINISM_PREFIX,
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


class NoiseControlAdapter:
    id = "noise_control"
    domains = frozenset({"image", "tabular"})
    takes_eps = True

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="eps", type="float", default=0.03, min=1e-6, max=1.0,
                  description="Perturbation budget; mirrors the attack grid (L-inf: per element)."),
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
            atlas_technique_id=None, atlas_technique_name=None,
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        return resolve_from_schema(self._schema, params)

    def run(self, target: Target, x: np.ndarray, y: np.ndarray,
            params: dict[str, float | int | bool], seed: int) -> AttackOutput:
        p = self.resolve_params(params)
        eps = float(p["eps"])
        x = np.asarray(x, dtype=np.float32)
        t0 = time.perf_counter()
        rng = np.random.default_rng(int(seed))
        if bool(p["norm_l2"]):
            direction = rng.standard_normal(size=x.shape).astype(np.float32)
            flat = direction.reshape(x.shape[0], -1)
            norms = np.linalg.norm(flat, axis=1, keepdims=True)
            norms[norms < 1e-12] = 1.0
            u = (flat / norms * eps).reshape(x.shape)
            norm_note = "norm=L2: random direction scaled to norm eps"
        else:
            u = rng.uniform(-eps, eps, size=x.shape).astype(np.float32)
            norm_note = "norm=Linf: u ~ Uniform(-eps, eps) per element"
        lo, hi = clip_range(target, x)
        x_adv = np.clip(x + u, lo, hi).astype(np.float32)
        x_adv = apply_mask(x, x_adv, perturbable_mask(target, x))
        wall = time.perf_counter() - t0
        linf, l2 = perturbation_norms(x, x_adv)
        return AttackOutput(
            x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=wall, params=dict(p),
            library_versions=library_versions(),
            notes=[norm_note, "gradient-free control: no model access beyond the final prediction",
                   f"{NONDETERMINISM_PREFIX}{NOISE_CONTROL_NOTE}",
                   f"{NONDETERMINISM_PREFIX}{CPU_FLOAT32_NOTE}"],
        )


ADAPTER: NoiseControlAdapter = NoiseControlAdapter()
