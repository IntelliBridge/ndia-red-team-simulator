"""PGD adapter over ``art.attacks.evasion.ProjectedGradientDescent`` (spec 12.2).

L-inf by default, L2 on request (``norm_l2``). ``eps_step`` follows the ratio rule
``eps_step = eps_step_ratio * eps`` (default 1/4) so the step scales across the
sweep; the resolved step is recorded in ``params``. ``num_random_init > 0`` is
permitted and recorded as a nondeterminism source.

The adapter runs against whatever differentiable estimator ``Target.art_classifier()``
returns. The tabular surrogate-transfer path (spec 12.9) belongs to the tabular target:
if its estimator is a surrogate, the target's manifest says so and the campaign copies
that note onto the rows.
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


class PGDAdapter:
    id = "pgd"
    domains = frozenset({"image", "tabular"})
    takes_eps = True

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="eps", type="float", default=0.03, min=1e-6, max=1.0,
                  description="Budget in the chosen norm; supplied from the eps grid."),
        ParamSpec(name="eps_step_ratio", type="float", default=0.25, min=0.01, max=1.0,
                  description="Step size as a fraction of eps (eps_step = eps_step_ratio * eps; spec 12.2)."),
        ParamSpec(name="max_iter", type="int", default=10, min=1, max=50,
                  description="Number of projected gradient steps."),
        ParamSpec(name="num_random_init", type="int", default=0, min=0, max=10,
                  description="Random restarts inside the eps ball; > 0 adds a nondeterminism source."),
        ParamSpec(name="norm_l2", type="bool", default=False,
                  description="Use the L2 norm instead of L-inf (needs an L2 eps grid; spec 12.3)."),
        ParamSpec(name="batch_size", type="int", default=64, min=1, max=1024,
                  description="Gradient batch size (no effect on the result)."),
    ]

    def info(self) -> AttackInfo:
        return AttackInfo(
            id=self.id, name="Projected Gradient Descent (L-inf default, L2 option)", domain="image",
            family="evasion",
            description="Iterative gradient attack projected back into the eps ball after each step.",
            params_schema=list(self._schema),
            references=["Madry, Makelov, Schmidt, Tsipras, Vladu 2018, arXiv:1706.06083",
                        "art.attacks.evasion.ProjectedGradientDescent"],
            atlas_technique_id=ATLAS_CRAFT_ADVERSARIAL_DATA[0],
            atlas_technique_name=ATLAS_CRAFT_ADVERSARIAL_DATA[1],
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        given = dict(params or {})
        given.pop("eps_step", None)  # derived; recomputed below from the ratio rule
        p = resolve_from_schema(self._schema, given)
        p["eps_step"] = float(p["eps"]) * float(p["eps_step_ratio"])
        return p

    def run(self, target: Target, x: np.ndarray, y: np.ndarray,
            params: dict[str, float | int | bool], seed: int) -> AttackOutput:
        from art.attacks.evasion import ProjectedGradientDescent

        p = self.resolve_params(params)
        eps = float(p["eps"])
        norm: float | int = 2 if bool(p["norm_l2"]) else np.inf
        x = np.asarray(x, dtype=np.float32)
        y = np.asarray(y).astype(int)
        clf = target.art_classifier()
        if not hasattr(clf, "loss_gradient"):
            raise AttackNotApplicable("pgd needs a differentiable estimator (no loss_gradient)")
        seed_all(seed)
        t0 = time.perf_counter()
        attack = ProjectedGradientDescent(
            estimator=clf, norm=norm, eps=eps, eps_step=float(p["eps_step"]), max_iter=int(p["max_iter"]),
            targeted=False, num_random_init=int(p["num_random_init"]), batch_size=int(p["batch_size"]),
            random_eps=False, verbose=False,
        )
        x_adv = np.asarray(attack.generate(x=x, y=y), dtype=np.float32)
        x_adv = apply_mask(x, x_adv, perturbable_mask(target, x))
        wall = time.perf_counter() - t0
        linf, l2 = perturbation_norms(x, x_adv)
        notes = [(f"norm={'L2' if norm == 2 else 'Linf'}; untargeted; eps_step = {p['eps_step']:.6g} "
                  f"(= {p['eps_step_ratio']:g} * eps); max_iter = {p['max_iter']}"),
                 f"{NONDETERMINISM_PREFIX}{CPU_FLOAT32_NOTE}"]
        if int(p["num_random_init"]) > 0:
            notes.append(f"{NONDETERMINISM_PREFIX}PGD random start (num_random_init > 0, seed={int(seed)})")
        return AttackOutput(
            x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=wall, params=dict(p),
            library_versions=library_versions(), notes=notes,
        )


ADAPTER: PGDAdapter = PGDAdapter()
