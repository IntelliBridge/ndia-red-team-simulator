"""Carlini-Wagner L2 adapter over ``art.attacks.evasion.CarliniL2Method`` (spec 12.2, Phase B).

White-box, image domain, minimal-norm: the attack takes no eps. It minimises the L2 size of a
perturbation that changes the prediction (the ``confidence`` margin is the only "budget"), and
the campaign then thresholds the achieved per-sample L2 against every eps of the L2 evaluation
grid ``redsim.ml.scoring.DEFAULT_EPS_GRID_L2`` (spec 12.3 minimal-norm paragraph, 15.1). So
``takes_eps`` is ``False`` and ``norms`` is ``{"l2"}``: a campaign under the L-inf grid may not
name it (``registry.attack_supports_norm``), because comparing an L2-minimal perturbation with
an L-inf budget would measure the wrong thing.

Cost is bounded by ``binary_search_steps * max_iter`` gradient steps per batch (spec 12.8; the
schema caps ``max_iter`` at 50). When the search finds no adversarial example inside that
budget ART returns the clean input for that sample, which the thresholding already reads as not
flipped; nothing is interpolated. The estimator must expose class gradients (ART
``ClassGradientsMixin``): a tree ensemble or a predict-only endpoint is refused with
``AttackNotApplicable`` and recorded ``not_run``.

The search itself is deterministic given the model (no random initialisation); CPU float32
reductions are the recorded nondeterminism source (12.7).

CPU budget (ATTACKS_HARDEN-22, measured 2026-09-09 on the bundled ``vehicles_cnn``, resnet18 @
128x128, CPU-only Apple silicon laptop, torch 2.14.0 pinned to 2 threads, ART 1.20.1, n=8, seed 0):
the schema defaults (``binary_search_steps`` 5, ``max_iter`` 10, ``initial_const`` 0.01) took
48 s for 8 samples, about 6 s per sample, and changed 6/8 inputs with a median achieved L2 of
0.27 (``initial_const`` 0.1 and 1.0 cost the same and landed in the same range, so ART's default
0.01 is kept). n_samples=100 is therefore about 10 minutes inside the 1200 s sandbox wall clock;
keep CW campaigns at n_samples <= 100. The figures are budgets, not evidence about the model.
On the 8x8 random test double the same defaults find nothing (c stays below the logit scale),
which the record then states as 0/n changed rather than inventing a perturbation.
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

import numpy as np

from redsim.ml.attacks import (
    CPU_FLOAT32_NOTE,
    MINIMAL_NORM_NOTE,
    NONDETERMINISM_PREFIX,
    achieved_norm_note,
    apply_mask,
    clip_range,
    library_versions,
    perturbable_mask,
    require_class_gradients,
    resolve_from_schema,
    seed_all,
)
from redsim.ml.attacks.base import AttackOutput
from redsim.ml.eval import perturbation_norms
from redsim.ml.schema import AttackInfo, ParamSpec
from redsim.ml.scoring import DEFAULT_EPS_GRID_L2
from redsim.ml.targets.base import Target

PERT_NOTE = ("pert = achieved L2 of each successful example (spec 12.5); when the search finds no adversarial "
             "example within binary_search_steps x max_iter steps ART returns the clean input and the sample shows "
             "as not flipped")


class CWL2Adapter:
    id = "cw_l2"
    domains = frozenset({"image"})
    takes_eps = False
    norms = frozenset({"l2"})
    capabilities: ClassVar[frozenset[str]] = frozenset({"adversarial_ml", "white_box", "minimal_norm",
                                                        "family:evasion", "modality:image", "norm:l2"})

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="confidence", type="float", default=0.0, min=0.0, max=10.0,
                  description="Logit margin the adversarial class must win by (kappa in the paper); 0 = any flip."),
        ParamSpec(name="learning_rate", type="float", default=0.01, min=1e-4, max=1.0,
                  description="Adam step size of the inner optimisation in tanh space."),
        ParamSpec(name="binary_search_steps", type="int", default=5, min=1, max=10,
                  description="Binary-search steps over the misclassification/distance trade-off constant c."),
        ParamSpec(name="max_iter", type="int", default=10, min=1, max=50,
                  description="Gradient steps per binary-search step (bounded cost, spec 12.8)."),
        ParamSpec(name="initial_const", type="float", default=0.01, min=1e-4, max=10.0,
                  description="Initial trade-off constant c between distance and misclassification loss."),
        ParamSpec(name="max_halving", type="int", default=5, min=1, max=10,
                  description="Maximum step-size halvings in the line search."),
        ParamSpec(name="max_doubling", type="int", default=5, min=1, max=10,
                  description="Maximum step-size doublings in the line search."),
        ParamSpec(name="batch_size", type="int", default=64, min=1, max=1024,
                  description="Gradient batch size (no effect on the result)."),
    ]

    def info(self) -> AttackInfo:
        return AttackInfo(
            id=self.id, name="Carlini-Wagner L2 (minimal-norm, white-box)", domain="image", family="evasion",
            description=("Optimises the smallest L2 perturbation that changes the prediction, with a bounded "
                         "iteration budget. Takes no eps: the achieved L2 per sample is thresholded against the "
                         "L2 evaluation grid (spec 12.3); pert is the achieved L2 of each success. Cost per batch "
                         "is binary_search_steps x max_iter forward/backward passes."),
            params_schema=list(self._schema),
            references=["Carlini, Wagner 2017, arXiv:1608.04644",
                        "art.attacks.evasion.CarliniL2Method"],
            phase="B", access="white-box", requires_gradients=True, status="available", reason=None,
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        return resolve_from_schema(self._schema, params)

    def run(self, target: Target, x: np.ndarray, y: np.ndarray,
            params: dict[str, float | int | bool], seed: int) -> AttackOutput:
        from art.attacks.evasion import CarliniL2Method

        p = self.resolve_params(params)
        x = np.asarray(x, dtype=np.float32)
        y = np.asarray(y).astype(int)
        clf = target.art_classifier()
        require_class_gradients(clf, self.id)
        mask = perturbable_mask(target, x)
        lo, hi = clip_range(target, x)
        seed_all(seed)
        t0 = time.perf_counter()
        attack = CarliniL2Method(
            classifier=clf, confidence=float(p["confidence"]), targeted=False,
            learning_rate=float(p["learning_rate"]), binary_search_steps=int(p["binary_search_steps"]),
            max_iter=int(p["max_iter"]), initial_const=float(p["initial_const"]),
            max_halving=int(p["max_halving"]), max_doubling=int(p["max_doubling"]),
            batch_size=int(p["batch_size"]), verbose=False,
        )
        x_adv = np.asarray(attack.generate(x=x, y=y), dtype=np.float32)
        x_adv = apply_mask(x, x_adv, mask)
        x_adv = np.clip(x_adv, lo, hi).astype(np.float32)
        wall = time.perf_counter() - t0
        linf, l2 = perturbation_norms(x, x_adv)
        notes = [
            (f"norm=L2; untargeted; white-box via class gradients; confidence={p['confidence']:g}; "
             f"binary_search_steps={p['binary_search_steps']} x max_iter={p['max_iter']} steps per batch"),
            MINIMAL_NORM_NOTE,
            f"evaluation grid: the campaign's L2 grid (default {list(DEFAULT_EPS_GRID_L2)})",
            PERT_NOTE,
            achieved_norm_note(x, x_adv, l2=True, grid=DEFAULT_EPS_GRID_L2),
        ]
        if mask is not None:
            notes.append("frozen features re-imposed after the attack (CarliniL2Method has no mask argument)")
        notes.append(f"{NONDETERMINISM_PREFIX}{CPU_FLOAT32_NOTE}")
        return AttackOutput(
            x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=wall, params=dict(p),
            library_versions=library_versions(), notes=notes,
        )


ADAPTER: CWL2Adapter = CWL2Adapter()
