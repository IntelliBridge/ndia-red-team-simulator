"""DeepFool adapter over ``art.attacks.evasion.DeepFool`` (spec 12.2, Phase B).

White-box, image domain, minimal-norm L2: DeepFool linearises the classifier around the
current point and steps to the nearest linearised decision boundary until the prediction
changes or ``max_iter`` is spent, then overshoots by ``(1 + epsilon)``. It takes no eps and
its perturbation is unbounded by design, so the campaign thresholds the achieved per-sample
L2 against the L2 evaluation grid (``redsim.ml.scoring.DEFAULT_EPS_GRID_L2``, spec 12.3,
15.1): a sample whose minimal perturbation exceeds every grid eps shows as not flipped at
those budgets, which is the honest reading. ``takes_eps`` is ``False``; ``norms`` is ``{"l2"}``.

Cost: up to ``min(nb_grads, n_classes)`` class-gradient passes per step and ``max_iter``
steps per sample (the schema default 20 is a fifth of ART's 100, spec 12.8). The estimator
must expose class gradients; otherwise the run is refused with ``AttackNotApplicable`` and
recorded ``not_run``. DeepFool ignores ``y``: it moves away from the model's own prediction.

CPU budget (ATTACKS_HARDEN-22, measured 2026-09-09 on the bundled ``vehicles_cnn``, resnet18 @
128x128, CPU-only Apple silicon laptop, torch 2.14.0 pinned to 2 threads, ART 1.20.1, n=8, seed 0):
the schema defaults took 10.4 s for 8 samples, about 1.3 s per sample, changed 8/8 inputs with a
median achieved L2 of 0.22 (max 0.52, so some samples exceed the 0.25 and 0.5 grid rows). The
default n_samples=200 is then about 4.5 minutes inside the 1200 s sandbox wall clock. Budgets,
not evidence about the model.
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

PERT_NOTE = ("pert = achieved L2 of each successful example (spec 12.5); DeepFool's perturbation is unbounded by "
             "design, so a sample can exceed every grid eps and then shows as not flipped at those budgets")


class DeepFoolAdapter:
    id = "deepfool"
    domains = frozenset({"image"})
    takes_eps = False
    norms = frozenset({"l2"})
    capabilities: ClassVar[frozenset[str]] = frozenset({"adversarial_ml", "white_box", "minimal_norm",
                                                        "family:evasion", "modality:image", "norm:l2"})

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="max_iter", type="int", default=20, min=1, max=100,
                  description="Linearisation steps per sample (ART default 100; capped for CPU budgets)."),
        ParamSpec(name="epsilon", type="float", default=1e-6, min=0.0, max=0.1,
                  description="Overshoot: the final perturbation is scaled by (1 + epsilon) to cross the boundary."),
        ParamSpec(name="nb_grads", type="int", default=10, min=1, max=10,
                  description="Class gradients computed per step (top-nb_grads classes; ART uses min(nb_grads, "
                              "n_classes))."),
        ParamSpec(name="batch_size", type="int", default=64, min=1, max=1024,
                  description="Gradient batch size (no effect on the result)."),
    ]

    def info(self) -> AttackInfo:
        return AttackInfo(
            id=self.id, name="DeepFool (minimal-norm L2, white-box)", domain="image", family="evasion",
            description=("Iteratively steps to the nearest linearised decision boundary; the smallest L2 "
                         "perturbation it finds is thresholded against the L2 evaluation grid (spec 12.3). "
                         "Takes no eps; pert is the achieved L2 of each success. Cost per step is up to "
                         "min(nb_grads, n_classes) class-gradient passes."),
            params_schema=list(self._schema),
            references=["Moosavi-Dezfooli, Fawzi, Frossard 2016, arXiv:1511.04599",
                        "art.attacks.evasion.DeepFool"],
            phase="B", access="white-box", requires_gradients=True, status="available", reason=None,
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        return resolve_from_schema(self._schema, params)

    def run(self, target: Target, x: np.ndarray, y: np.ndarray,
            params: dict[str, float | int | bool], seed: int) -> AttackOutput:
        from art.attacks.evasion import DeepFool

        p = self.resolve_params(params)
        x = np.asarray(x, dtype=np.float32)
        clf = target.art_classifier()
        require_class_gradients(clf, self.id)
        mask = perturbable_mask(target, x)
        lo, hi = clip_range(target, x)
        n_classes = int(getattr(clf, "nb_classes", 0) or np.asarray(target.predict_proba(x[:1])).shape[1])
        effective_grads = min(int(p["nb_grads"]), n_classes)
        seed_all(seed)
        t0 = time.perf_counter()
        attack = DeepFool(classifier=clf, max_iter=int(p["max_iter"]), epsilon=float(p["epsilon"]),
                          nb_grads=int(p["nb_grads"]), batch_size=int(p["batch_size"]), verbose=False)
        # y=None: DeepFool moves away from the model's own prediction (it does not use labels).
        x_adv = np.asarray(attack.generate(x=x, y=None), dtype=np.float32)
        x_adv = apply_mask(x, x_adv, mask)
        x_adv = np.clip(x_adv, lo, hi).astype(np.float32)
        wall = time.perf_counter() - t0
        linf, l2 = perturbation_norms(x, x_adv)
        notes = [
            (f"norm=L2; untargeted (away from the model's own prediction); white-box via class gradients; "
             f"max_iter={p['max_iter']}; overshoot epsilon={p['epsilon']:g}; class gradients per step = "
             f"{effective_grads} (min(nb_grads={p['nb_grads']}, n_classes={n_classes}))"),
            MINIMAL_NORM_NOTE,
            f"evaluation grid: the campaign's L2 grid (default {list(DEFAULT_EPS_GRID_L2)})",
            PERT_NOTE,
            achieved_norm_note(x, x_adv, l2=True, grid=DEFAULT_EPS_GRID_L2),
        ]
        if mask is not None:
            notes.append("frozen features re-imposed after the attack (DeepFool has no mask argument)")
        notes.append(f"{NONDETERMINISM_PREFIX}{CPU_FLOAT32_NOTE}")
        return AttackOutput(
            x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=wall, params=dict(p),
            library_versions=library_versions(), notes=notes,
        )


ADAPTER: DeepFoolAdapter = DeepFoolAdapter()
