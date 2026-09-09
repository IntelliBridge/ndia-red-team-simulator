"""Zeroth-Order Optimization adapter over ``art.attacks.evasion.ZooAttack`` (spec 12.2, Phase B).

Score-based black-box for tabular targets: ZOO estimates coordinate-wise gradients from the
model's probability outputs by finite differences (no gradients, no surrogate), and minimises a
Carlini-Wagner style loss plus the L2 size of the perturbation. It takes no eps, so the campaign
thresholds the achieved per-sample norm against the tabular grid in the campaign norm (spec
12.3, 15.1); ``norms`` is ``{"linf", "l2"}`` and the notes say the attack minimised L2 while the
comparison ran in whichever norm the campaign chose.

Tabular specifics (spec 12.9) follow the HopSkipJump tabular path: the real model's
``predict_proba`` is wrapped in an ART ``BlackBoxClassifier`` over the min-max-scaled unit cube
(each query is unscaled before it reaches the model), predict rows are counted so
``queries_mean`` can be recorded, integer features are rounded after the search and the
rounded row is what is measured. ``ZooAttack.generate`` has no ``mask`` argument, so frozen
features are re-imposed after the attack rather than held during it; that can undo part of the
adversarial effect, and the honest outcome is then a lower ASR on the real model, never a fake.

ART's ZOO accepts feature-vector inputs only with ``batch_size=1`` and turns its image-only
resizing and importance sampling off for them; both are fixed here, not parameters. The
coordinate sampling is seeded (``seed_all``) but recorded as a nondeterminism source (12.7).
Score-based attacks need probabilities: a target that returns labels only makes ZOO not
applicable (``AttackNotApplicable``, recorded ``not_run``).

Defaults (recorded, not assumed): ART's image defaults ``learning_rate=0.01`` and
``variable_h=1e-4`` were tried on the two seeded tree-ensemble test doubles
(``tests/ml/fakes.TinyTabularTarget``, 12 features, and the 6-feature double in
``tests/ml/test_attacks.py``) on 2026-09-09 and moved nothing: a tree ensemble's
``predict_proba`` is piecewise constant, so a finite-difference step of 1e-4 of a feature's
range sees a zero gradient everywhere and ``abort_early`` stops the search at once. With
``variable_h=0.05`` and ``learning_rate=0.1`` (both in scaled units) the same runs flipped
6/12 and 1..3/8 samples at about a hundred queries per flip. Those are the defaults here;
``variable_h`` may go up to 0.5. They are cost and effectiveness settings for the search, not a
claim about any model.

CPU budget (ATTACKS_HARDEN-22, measured 2026-09-09 on the bundled ``url_trees``, scikit-learn
HistGradientBoosting on 16 features, CPU-only Apple silicon laptop, n=16, seed 0): the defaults
took 91 s for 16 samples, about 5.7 s per sample (ZOO queries the model one row at a time, 1104
predict calls), and flipped 11/16 samples at 100 predict rows per flip. The default
n_samples=200 is then about 19 minutes and does not fit the 1200 s sandbox wall clock; keep ZOO
campaigns at n_samples <= 100 (about 9.5 minutes). Budgets, not evidence about the model.
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

import numpy as np

from redsim.ml.attacks import (
    CPU_FLOAT32_NOTE,
    MINIMAL_NORM_NOTE,
    NONDETERMINISM_PREFIX,
    QUERIES_DENOMINATOR_NOTE,
    TabularScaling,
    achieved_norm_note,
    library_versions,
    queries_summary,
    resolve_from_schema,
    seed_all,
)
from redsim.ml.attacks.base import AttackOutput
from redsim.ml.errors import AttackNotApplicable
from redsim.ml.schema import AttackInfo, ParamSpec
from redsim.ml.targets.base import Target

ZOO_NONDETERMINISM = "ZOO random coordinate sampling (seed={seed}; numpy global RNG seeded before generate)"
FROZEN_METHOD = "re-imposing their clean values after the attack (ZooAttack has no mask argument)"


class ZooAdapter:
    id = "zoo"
    domains = frozenset({"tabular"})
    takes_eps = False
    norms = frozenset({"linf", "l2"})
    capabilities: ClassVar[frozenset[str]] = frozenset({"adversarial_ml", "black_box", "query_counted", "score_based",
                                                        "minimal_norm", "family:evasion", "modality:tabular",
                                                        "norm:linf", "norm:l2"})

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="confidence", type="float", default=0.0, min=0.0, max=10.0,
                  description="Probability margin the adversarial class must win by; 0 = any flip."),
        ParamSpec(name="learning_rate", type="float", default=0.1, min=1e-4, max=1.0,
                  description="Adam step size of the coordinate updates, in scaled feature units (fraction of each "
                              "feature's range per step)."),
        ParamSpec(name="max_iter", type="int", default=10, min=1, max=50,
                  description="Coordinate-descent iterations per binary-search step."),
        ParamSpec(name="binary_search_steps", type="int", default=1, min=1, max=10,
                  description="Binary-search steps over the trade-off constant c."),
        ParamSpec(name="initial_const", type="float", default=1e-3, min=1e-5, max=10.0,
                  description="Initial trade-off constant c between distance and misclassification loss."),
        ParamSpec(name="abort_early", type="bool", default=True,
                  description="Stop an iteration block early when the loss stops improving."),
        ParamSpec(name="nb_parallel", type="int", default=16, min=1, max=128,
                  description="Coordinates estimated per step (capped at the feature count; each costs two queries)."),
        ParamSpec(name="variable_h", type="float", default=0.05, min=1e-6, max=0.5,
                  description="Finite-difference step for the gradient estimate, in scaled feature units. Tree "
                              "ensembles are piecewise constant, so the step must straddle split thresholds (ART's "
                              "image default 1e-4 sees no gradient on them and moves nothing)."),
    ]

    def info(self) -> AttackInfo:
        return AttackInfo(
            id=self.id, name="Zeroth-Order Optimization (score-based black-box)", domain="tabular",
            family="evasion",
            description=("Estimates gradients from probability outputs by coordinate-wise finite differences and "
                         "minimises an L2 Carlini-Wagner loss through the real model's predict_proba; no gradients, "
                         "no surrogate, queries counted. Takes no eps: the achieved norm is thresholded against the "
                         "tabular grid. Needs probabilities (labels-only targets are not applicable)."),
            params_schema=list(self._schema),
            references=["Chen, Zhang, Sharma, Yi, Hsieh 2017, arXiv:1708.03999",
                        "art.attacks.evasion.ZooAttack"],
            phase="B", access="black-box", requires_gradients=False, status="available", reason=None,
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        return resolve_from_schema(self._schema, params)

    def run(self, target: Target, x: np.ndarray, y: np.ndarray,
            params: dict[str, float | int | bool], seed: int) -> AttackOutput:
        from art.attacks.evasion import ZooAttack
        from art.estimators.classification import BlackBoxClassifier

        p = self.resolve_params(params)
        x = np.asarray(x, dtype=np.float32)
        n = int(x.shape[0])
        scaling = TabularScaling.from_target(target, x)
        if scaling is None:
            raise AttackNotApplicable(
                "zoo runs on tabular targets only (a 2-D feature slice in min-max-scaled space, spec 12.9); "
                "recorded as not run")
        d = int(x.shape[1])
        # Setup probe for the class count and the probability requirement. Runs before the timer and is not
        # counted as an attack query.
        probe = np.asarray(target.predict_proba(x[:1]), dtype=np.float32)
        if probe.ndim != 2 or probe.shape[1] < 2:
            raise AttackNotApplicable("zoo is score-based and needs class probabilities from predict_proba; the "
                                      "target returned no probability row; recorded as not run")
        nb_classes = int(probe.shape[1])

        counter = {"rows": 0, "calls": 0}

        def predict_fn(inputs: np.ndarray) -> np.ndarray:
            arr = np.asarray(inputs, dtype=np.float32)
            counter["rows"] += int(arr.shape[0])
            counter["calls"] += 1
            return np.asarray(target.predict_proba(scaling.unscale(arr)), dtype=np.float32)

        clf = BlackBoxClassifier(predict_fn=predict_fn, input_shape=(d,), nb_classes=nb_classes,
                                 clip_values=(0.0, 1.0))
        nb_parallel = min(int(p["nb_parallel"]), d)
        seed_all(seed)
        t0 = time.perf_counter()
        attack = ZooAttack(
            classifier=clf, confidence=float(p["confidence"]), targeted=False,
            learning_rate=float(p["learning_rate"]), max_iter=int(p["max_iter"]),
            binary_search_steps=int(p["binary_search_steps"]), initial_const=float(p["initial_const"]),
            abort_early=bool(p["abort_early"]), use_resize=False, use_importance=False,
            nb_parallel=nb_parallel, batch_size=1, variable_h=float(p["variable_h"]), verbose=False,
        )
        # y=None: move away from the model's own clean prediction (the attacker sees scores, not labels).
        x_scaled = scaling.scale(x)
        x_adv_scaled = np.asarray(attack.generate(x=x_scaled, y=None), dtype=np.float32)
        # Coordinates ZOO did not move keep their exact clean value: the scale / unscale round trip would
        # otherwise leave float32 noise on untouched features and record a perturbation that never happened.
        untouched = np.abs(x_adv_scaled.astype(np.float64) - x_scaled.astype(np.float64)) <= 1e-7
        x_adv_raw = np.where(untouched, x, scaling.unscale(x_adv_scaled)).astype(np.float32)
        x_adv = scaling.finish(x, x_adv_raw)
        linf, l2 = scaling.norms(x, x_adv)
        wall = time.perf_counter() - t0

        # Flips are read on the real model after the attack (measurement, not attack queries).
        y_clean = np.asarray(target.predict_proba(x)).argmax(axis=1)
        y_adv = np.asarray(target.predict_proba(x_adv)).argmax(axis=1)
        n_flipped = int((y_clean != y_adv).sum())
        queries_mean, queries_note = queries_summary(counter["rows"], counter["calls"], n, n_flipped)

        notes = [
            (f"black-box score-based (probability outputs); no gradients, no surrogate; ZOO minimises L2 in "
             f"min-max-scaled feature space and the campaign thresholds the achieved norm in its own norm; "
             f"max_iter={p['max_iter']} x binary_search_steps={p['binary_search_steps']}; nb_parallel={nb_parallel} "
             f"(requested {p['nb_parallel']}, capped at {d} features); batch_size=1, use_resize=False and "
             "use_importance=False are fixed by ART for feature-vector inputs"),
            MINIMAL_NORM_NOTE,
            queries_note, QUERIES_DENOMINATOR_NOTE,
            ("ZOO searched min-max-scaled feature space (unit cube over the declared ranges) through the real "
             "model's predict_proba; the achieved norm is in scaled units"),
            achieved_norm_note(scaling.scale(x), scaling.scale(x_adv), l2=False),
            achieved_norm_note(scaling.scale(x), scaling.scale(x_adv), l2=True),
            *scaling.notes(frozen_method=FROZEN_METHOD),
        ]
        if scaling.mask is not None:
            notes.append("frozen features re-imposed after the attack (ZooAttack has no mask argument); the search "
                         "may have spent queries on them and re-imposition can lower the achieved flip rate, which "
                         "is measured on the real model as is")
        notes.extend([f"{NONDETERMINISM_PREFIX}{ZOO_NONDETERMINISM.format(seed=int(seed))}",
                      f"{NONDETERMINISM_PREFIX}{CPU_FLOAT32_NOTE}"])
        return AttackOutput(
            x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=wall, params=dict(p),
            library_versions=library_versions(), queries_mean=queries_mean, notes=notes,
        )


ADAPTER: ZooAdapter = ZooAdapter()
