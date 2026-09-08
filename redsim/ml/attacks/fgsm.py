"""FGSM adapter over ``art.attacks.evasion.FastGradientMethod`` (spec 12.2).

One L-inf gradient step, untargeted, at the eps supplied from the campaign grid.
White-box: needs ``Target.art_classifier()`` to expose loss gradients.
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

import numpy as np

from redsim.ml.attacks import (
    ATLAS_CRAFT_ADVERSARIAL_DATA,
    CPU_FLOAT32_NOTE,
    NONDETERMINISM_PREFIX,
    apply_mask,
    library_versions,
    perturbable_mask,
    resolve_from_schema,
    seed_all,
)
from redsim.ml.attacks.base import AttackOutput
from redsim.ml.errors import AttackNotApplicable
from redsim.ml.eval import perturbation_norms
from redsim.ml.schema import AttackInfo, ParamSpec
from redsim.ml.targets.base import Target


class FGSMAdapter:
    id = "fgsm"
    domains = frozenset({"image"})
    takes_eps = True

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="eps", type="float", default=0.03, min=1e-6, max=1.0,
                  description="L-inf budget as a fraction of the [0, 1] input range; supplied from the eps grid."),
        ParamSpec(name="batch_size", type="int", default=64, min=1, max=1024,
                  description="Gradient batch size (no effect on the result)."),
    ]

    def info(self) -> AttackInfo:
        return AttackInfo(
            id=self.id, name="Fast Gradient Sign Method (L-inf)", domain="image", family="evasion",
            description="Single-step L-inf gradient-sign perturbation; the cheapest white-box attack.",
            params_schema=list(self._schema),
            references=["Goodfellow, Shlens, Szegedy 2015, arXiv:1412.6572",
                        "art.attacks.evasion.FastGradientMethod"],
            atlas_technique_id=ATLAS_CRAFT_ADVERSARIAL_DATA[0],
            atlas_technique_name=ATLAS_CRAFT_ADVERSARIAL_DATA[1],
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        return resolve_from_schema(self._schema, params)

    def run(self, target: Target, x: np.ndarray, y: np.ndarray,
            params: dict[str, float | int | bool], seed: int) -> AttackOutput:
        from art.attacks.evasion import FastGradientMethod

        p = self.resolve_params(params)
        eps = float(p["eps"])
        x = np.asarray(x, dtype=np.float32)
        y = np.asarray(y).astype(int)
        clf = target.art_classifier()
        if not hasattr(clf, "loss_gradient"):
            raise AttackNotApplicable("fgsm needs a differentiable estimator (no loss_gradient)")
        seed_all(seed)
        t0 = time.perf_counter()
        attack = FastGradientMethod(estimator=clf, norm=np.inf, eps=eps, eps_step=eps, targeted=False,
                                    num_random_init=0, batch_size=int(p["batch_size"]), minimal=False)
        x_adv = np.asarray(attack.generate(x=x, y=y), dtype=np.float32)
        x_adv = apply_mask(x, x_adv, perturbable_mask(target, x))
        wall = time.perf_counter() - t0
        linf, l2 = perturbation_norms(x, x_adv)
        return AttackOutput(
            x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=wall, params=dict(p),
            library_versions=library_versions(),
            notes=["norm=Linf; untargeted; single step", f"{NONDETERMINISM_PREFIX}{CPU_FLOAT32_NOTE}"],
        )


ADAPTER: FGSMAdapter = FGSMAdapter()
