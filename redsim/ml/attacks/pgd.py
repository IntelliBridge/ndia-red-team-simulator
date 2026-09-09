"""PGD adapter over ``art.attacks.evasion.ProjectedGradientDescent`` (spec 12.2).

L-inf by default, L2 on request (``norm_l2``). ``eps_step`` follows the ratio rule
``eps_step = eps_step_ratio * eps`` (default 1/4) so the step scales across the
sweep. The resolved step is recorded in ``params``. ``num_random_init > 0`` is
permitted and recorded as a nondeterminism source.

Estimator selection (spec 12.1, 12.9): the adapter attacks ``Target.art_classifier()``
when it exposes ``loss_gradient`` (torch models, PyTorch state_dict uploads, converted
ONNX). A tree ensemble has no gradients, so when the estimator is not differentiable
the adapter attacks the target's declared build-time surrogate
(``Target.surrogate_art_classifier()``) instead. That is surrogate transfer, and the
surrogate's kind, sha256 and clean agreement are recorded in ``notes``. Measurement
never moves: the adapter returns raw rows and the campaign scores them on the real
model's ``predict_proba``. With neither a differentiable estimator nor a surrogate the
run is refused with ``AttackNotApplicable`` (recorded as not run, never faked).

Tabular budgets (spec 12.9) go through ``TabularScaling``: eps is a fraction of each
declared feature's range and is handed to ART as a per-feature array (coordinate-wise
L-inf projection makes this identical to attacking in min-max-scaled space), frozen
features go to ART as ``mask`` so they are held on every step, integer features are
rounded after the attack, and norms are reported in scaled units. Tabular L2 is refused:
the L2 ball in scaled space is an ellipsoid in raw units, ART's array-eps L2 projection is
not that geometry, and spec 12.3 declares no tabular L2 grid in Phase A.
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

import numpy as np

from redsim.ml.attacks import (
    CPU_FLOAT32_NOTE,
    NONDETERMINISM_PREFIX,
    SURROGATE_NONDETERMINISM_NOTE,
    TabularScaling,
    apply_mask,
    library_versions,
    perturbable_mask,
    resolve_from_schema,
    seed_all,
    surrogate_estimator,
)
from redsim.ml.attacks.base import AttackOutput
from redsim.ml.errors import AttackNotApplicable
from redsim.ml.eval import perturbation_norms
from redsim.ml.schema import AttackInfo, ParamSpec
from redsim.ml.targets.base import Target

FROZEN_METHOD = "ART mask on every projected gradient step (mask= passed to generate)"


class PGDAdapter:
    id = "pgd"
    domains = frozenset({"image", "tabular"})
    takes_eps = True
    capabilities: ClassVar[frozenset[str]] = frozenset({"adversarial_ml", "white_box", "surrogate_transfer",
                                                        "takes_eps", "family:evasion",
                                                        "modality:image", "modality:tabular"})

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="eps", type="float", default=0.03, min=1e-6, max=1.0,
                  description=("Budget in the chosen norm; supplied from the eps grid. Images: fraction of the "
                               "[0, 1] range. Tabular: fraction of each declared feature's range (spec 12.9).")),
        ParamSpec(name="eps_step_ratio", type="float", default=0.25, min=0.01, max=1.0,
                  description="Step size as a fraction of eps (eps_step = eps_step_ratio * eps; spec 12.2)."),
        ParamSpec(name="max_iter", type="int", default=10, min=1, max=50,
                  description="Number of projected gradient steps."),
        ParamSpec(name="num_random_init", type="int", default=0, min=0, max=10,
                  description="Random restarts inside the eps ball; > 0 adds a nondeterminism source."),
        ParamSpec(name="norm_l2", type="bool", default=False,
                  description="Use the L2 norm instead of L-inf (needs an L2 eps grid; spec 12.3). Images only."),
        ParamSpec(name="batch_size", type="int", default=64, min=1, max=1024,
                  description="Gradient batch size (no effect on the result)."),
    ]

    def info(self) -> AttackInfo:
        return AttackInfo(
            id=self.id, name="Projected Gradient Descent (L-inf default, L2 option)", domain="image",
            family="evasion",
            description=("Iterative gradient attack projected back into the eps ball after each step. On tabular "
                         "tree ensembles it runs against the declared build-time surrogate and is scored on the "
                         "real model (surrogate transfer, spec 12.9)."),
            params_schema=list(self._schema),
            references=["Madry, Makelov, Schmidt, Tsipras, Vladu 2018, arXiv:1706.06083",
                        "art.attacks.evasion.ProjectedGradientDescent"],
            phase="A", access="white-box", requires_gradients=True, status="available", reason=None,
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        given = dict(params or {})
        given.pop("eps_step", None)  # derived; recomputed below from the ratio rule
        p = resolve_from_schema(self._schema, given)
        p["eps_step"] = float(p["eps"]) * float(p["eps_step_ratio"])
        return p

    def _estimator(self, target: Target) -> tuple[Any, list[str]]:
        """The differentiable estimator to attack and the notes that say which one it was."""
        clf = target.art_classifier()
        if hasattr(clf, "loss_gradient"):
            return clf, []
        sur, note = surrogate_estimator(target)
        if sur is None:
            raise AttackNotApplicable(
                "pgd needs a differentiable estimator: the target's art_classifier() has no loss_gradient and "
                "the target declares no build-time surrogate (manifest 'surrogate'); recorded as not run")
        return sur, [str(note), f"{NONDETERMINISM_PREFIX}{SURROGATE_NONDETERMINISM_NOTE}"]

    def run(self, target: Target, x: np.ndarray, y: np.ndarray,
            params: dict[str, float | int | bool], seed: int) -> AttackOutput:
        from art.attacks.evasion import ProjectedGradientDescent

        p = self.resolve_params(params)
        eps = float(p["eps"])
        norm: float | int = 2 if bool(p["norm_l2"]) else np.inf
        x = np.asarray(x, dtype=np.float32)
        y = np.asarray(y).astype(int)
        scaling = TabularScaling.from_target(target, x)
        if scaling is not None and norm == 2:
            raise AttackNotApplicable(
                "pgd on a tabular target supports the L-inf per-feature-scaled grid only (spec 12.3 declares no "
                "tabular L2 grid; the scaled-space L2 ball is not ART's array-eps projection); recorded as not run")
        estimator, notes = self._estimator(target)
        seed_all(seed)

        eps_arg: float | np.ndarray = eps
        eps_step_arg: float | np.ndarray = float(p["eps_step"])
        mask: np.ndarray | None
        if scaling is not None:
            eps_arg = scaling.eps_per_feature(eps)
            eps_step_arg = (float(p["eps_step_ratio"]) * eps_arg).astype(np.float32)
            mask = scaling.mask
        else:
            mask = perturbable_mask(target, x)
        kwargs: dict[str, Any] = {} if mask is None else {"mask": mask}

        t0 = time.perf_counter()
        attack = ProjectedGradientDescent(
            estimator=estimator, norm=norm, eps=eps_arg, eps_step=eps_step_arg, max_iter=int(p["max_iter"]),
            targeted=False, num_random_init=int(p["num_random_init"]), batch_size=int(p["batch_size"]),
            random_eps=False, verbose=False,
        )
        x_adv = np.asarray(attack.generate(x=x, y=y, **kwargs), dtype=np.float32)
        if scaling is not None:
            x_adv = scaling.finish(x, x_adv)
            linf, l2 = scaling.norms(x, x_adv)
        else:
            x_adv = apply_mask(x, x_adv, mask)
            linf, l2 = perturbation_norms(x, x_adv)
        wall = time.perf_counter() - t0

        notes = [(f"norm={'L2' if norm == 2 else 'Linf'}; untargeted; eps_step = {p['eps_step']:.6g} "
                  f"(= {p['eps_step_ratio']:g} * eps); max_iter = {p['max_iter']}"), *notes]
        if scaling is not None:
            notes.extend(scaling.notes(frozen_method=FROZEN_METHOD))
            notes.append("eps and eps_step are fractions of each feature's range; the raw-unit budget per feature "
                         "is eps * (max - min)")
        elif mask is not None:
            notes.append(f"frozen features held at their clean values via {FROZEN_METHOD}")
        notes.append(f"{NONDETERMINISM_PREFIX}{CPU_FLOAT32_NOTE}")
        if int(p["num_random_init"]) > 0:
            notes.append(f"{NONDETERMINISM_PREFIX}PGD random start (num_random_init > 0, seed={int(seed)})")
        return AttackOutput(
            x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=wall, params=dict(p),
            library_versions=library_versions(), notes=notes,
        )


ADAPTER: PGDAdapter = PGDAdapter()
