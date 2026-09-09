"""HopSkipJump adapter over ``art.attacks.evasion.HopSkipJump`` (spec 12.2, black-box).

Decision-based: it uses only the model's ``predict`` output, which the adapter counts so
``queries_mean`` can be recorded. It takes no eps: the campaign thresholds the achieved
perturbation norm against each grid eps (spec 15.1), so ``takes_eps`` is ``False``.
Defaults are capped below ART's own for CPU budgets. Its random initial point and
Monte-Carlo gradient estimate are seeded but recorded as a nondeterminism source (12.7).

``queries_mean`` denominator (spec 12.5 ``queries(a)``, settled here): predict rows spent
divided by the number of samples whose prediction the attack flipped away from the
model's clean prediction, that is the query cost of one successful boundary crossing.
When no sample flipped the value is ``None`` (denominator 0) and the spent total is in
``notes``. The per-attacked-sample rate (rows / n) is always in ``notes`` too, so either
reading is available and neither is invented.

Tabular targets (spec 12.9) are searched in min-max-scaled feature space: the adapter
wraps the real model's ``predict_proba`` in an ART ``BlackBoxClassifier`` over the unit
cube (unscaling each query before it reaches the model), so a step of 0.01 means one
percent of every feature's declared range and the achieved norm is directly comparable
with the scaled eps grid. Frozen features go to ART as ``mask``, integer features are
rounded after the search, and the rounded row is what is measured. Image targets keep
running through ``Target.art_classifier()``.
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
    library_versions,
    perturbable_mask,
    resolve_from_schema,
    seed_all,
)
from redsim.ml.attacks.base import AttackOutput
from redsim.ml.eval import perturbation_norms
from redsim.ml.schema import AttackInfo, ParamSpec
from redsim.ml.targets.base import Target

HSJ_NONDETERMINISM = ("HopSkipJump random initial adversarial point and Monte-Carlo gradient estimate "
                      "(seed={seed}; ART draws the initial point from an unseeded RandomState, so repeated "
                      "runs differ even under the same seed)")
QUERIES_DENOMINATOR_NOTE = ("queries_mean denominator = samples flipped from the model's clean prediction (the "
                            "query cost of one successful decision-boundary crossing); the rate over all "
                            "attacked samples is recorded beside it")
FROZEN_METHOD = "ART mask on every HopSkipJump step (mask= passed to generate)"


class HopSkipJumpAdapter:
    id = "hopskipjump"
    domains = frozenset({"tabular", "image"})
    takes_eps = False
    capabilities: ClassVar[frozenset[str]] = frozenset({"adversarial_ml", "black_box", "query_counted",
                                                        "minimal_norm", "family:evasion",
                                                        "modality:image", "modality:tabular"})

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="norm_l2", type="bool", default=False,
                  description="Search in L2 instead of L-inf (must match the campaign's eps grid norm)."),
        ParamSpec(name="max_iter", type="int", default=20, min=1, max=50,
                  description="Boundary-walk iterations."),
        ParamSpec(name="max_eval", type="int", default=1000, min=100, max=5000,
                  description="Maximum model evaluations per iteration for the gradient estimate."),
        ParamSpec(name="init_eval", type="int", default=100, min=1, max=1000,
                  description="Initial evaluations for the gradient estimate (must not exceed max_eval)."),
        ParamSpec(name="init_size", type="int", default=100, min=1, max=1000,
                  description="Trials for the random initial adversarial point."),
        ParamSpec(name="batch_size", type="int", default=64, min=1, max=1024,
                  description="Prediction batch size (no effect on the result)."),
    ]

    def info(self) -> AttackInfo:
        return AttackInfo(
            id=self.id, name="HopSkipJump (decision-based black-box)", domain="tabular", family="evasion",
            description=("Query-efficient successor of the Boundary Attack: walks the decision boundary "
                         "using only predicted labels. No gradients, no surrogate; queries are counted."),
            params_schema=list(self._schema),
            references=["Chen, Jordan, Wainwright 2020, arXiv:1904.02144",
                        "art.attacks.evasion.HopSkipJump"],
            phase="A", access="black-box", requires_gradients=False, status="available", reason=None,
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        p = resolve_from_schema(self._schema, params)
        if int(p["init_eval"]) > int(p["max_eval"]):
            raise ValueError(f"init_eval={p['init_eval']} must not exceed max_eval={p['max_eval']}")
        return p

    def run(self, target: Target, x: np.ndarray, y: np.ndarray,
            params: dict[str, float | int | bool], seed: int) -> AttackOutput:
        from art.attacks.evasion import HopSkipJump

        p = self.resolve_params(params)
        norm: float | int = 2 if bool(p["norm_l2"]) else np.inf
        x = np.asarray(x, dtype=np.float32)
        n = int(x.shape[0])
        scaling = TabularScaling.from_target(target, x)
        seed_all(seed)

        # Query counter (spec 12.5 ``queries(a)``): rows handed to the model's predict during the attack.
        counter = {"rows": 0, "calls": 0}
        restore: Any = None
        mask: np.ndarray | None
        if scaling is not None:
            from art.estimators.classification import BlackBoxClassifier

            # Setup probe for the class count. It runs before the timer and is not counted as an attack query.
            nb_classes = int(np.asarray(target.predict_proba(x[:1])).shape[1])

            def predict_fn(inputs: np.ndarray) -> np.ndarray:
                arr = np.asarray(inputs, dtype=np.float32)
                counter["rows"] += int(arr.shape[0])
                counter["calls"] += 1
                return np.asarray(target.predict_proba(scaling.unscale(arr)), dtype=np.float32)

            clf: Any = BlackBoxClassifier(predict_fn=predict_fn, input_shape=(int(x.shape[1]),),
                                          nb_classes=nb_classes, clip_values=(0.0, 1.0))
            x_run = scaling.scale(x)
            mask = scaling.mask
        else:
            clf = target.art_classifier()
            original_predict = clf.predict

            def counting_predict(inputs: np.ndarray, *args: Any, **kwargs: Any) -> np.ndarray:
                # ART's HopSkipJump works in float64 internally but the target's estimator expects the
                # slice dtype (float32), so cast before forwarding. Counting is by rows (spec 12.5).
                arr = np.asarray(inputs, dtype=x.dtype)
                counter["rows"] += int(arr.shape[0])
                counter["calls"] += 1
                return np.asarray(original_predict(arr, *args, **kwargs))

            # Shadow the instance's predict for the duration of the attack so ART's isinstance checks on
            # the estimator still hold.
            clf.predict = counting_predict
            restore = clf
            x_run = x
            mask = perturbable_mask(target, x)
        kwargs: dict[str, Any] = {} if mask is None else {"mask": mask}

        t0 = time.perf_counter()
        try:
            attack = HopSkipJump(classifier=clf, batch_size=int(p["batch_size"]), targeted=False, norm=norm,
                                 max_iter=int(p["max_iter"]), max_eval=int(p["max_eval"]),
                                 init_eval=int(p["init_eval"]), init_size=int(p["init_size"]), verbose=False)
            # y=None: move away from the model's own clean prediction (the attacker sees labels only).
            x_adv_run = np.asarray(attack.generate(x=x_run, y=None, **kwargs), dtype=np.float32)
        finally:
            if restore is not None:
                try:
                    del restore.predict  # restore the class method
                except AttributeError:  # pragma: no cover - already absent
                    pass
        if scaling is not None:
            x_adv = scaling.finish(x, scaling.unscale(x_adv_run))
            linf, l2 = scaling.norms(x, x_adv)
        else:
            x_adv = apply_mask(x, x_adv_run, mask)
            linf, l2 = perturbation_norms(x, x_adv)
        wall = time.perf_counter() - t0

        # Flips are read on the real model after the attack (measurement, not attack queries).
        y_clean = np.asarray(target.predict_proba(x)).argmax(axis=1)
        y_adv = np.asarray(target.predict_proba(x_adv)).argmax(axis=1)
        n_flipped = int((y_clean != y_adv).sum())
        rows, calls = counter["rows"], counter["calls"]
        per_attacked = rows / n if n else 0.0
        queries_mean: float | None
        if n_flipped > 0:
            queries_mean = rows / n_flipped
            queries_note = (f"queries_mean = {queries_mean:.1f} predict rows per flipped sample ({rows} rows in "
                            f"{calls} predict calls; {n_flipped}/{n} samples flipped from the model's clean "
                            f"prediction; {per_attacked:.1f} rows per attacked sample)")
        else:
            queries_mean = None
            queries_note = (f"queries_mean not computed (denominator 0: 0/{n} samples flipped from the model's "
                            f"clean prediction); {rows} predict rows in {calls} predict calls were spent "
                            f"({per_attacked:.1f} rows per attacked sample)")
        notes = [f"norm={'L2' if norm == 2 else 'Linf'}; black-box decision-based; no gradients, no surrogate",
                 ("minimal-norm attack: success at eps is defined by thresholding the achieved perturbation "
                  "norm against each grid eps (spec 15.1)"),
                 queries_note, QUERIES_DENOMINATOR_NOTE]
        if scaling is not None:
            notes.append("HopSkipJump searched min-max-scaled feature space (unit cube over the declared ranges) "
                         "through the real model's predict; the achieved norm is in scaled units")
            notes.extend(scaling.notes(frozen_method=FROZEN_METHOD))
        elif mask is not None:
            notes.append(f"frozen features held at their clean values via {FROZEN_METHOD}")
        notes.extend([f"{NONDETERMINISM_PREFIX}{HSJ_NONDETERMINISM.format(seed=int(seed))}",
                      f"{NONDETERMINISM_PREFIX}{CPU_FLOAT32_NOTE}"])
        return AttackOutput(
            x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=wall, params=dict(p),
            library_versions=library_versions(), queries_mean=queries_mean, notes=notes,
        )


ADAPTER: HopSkipJumpAdapter = HopSkipJumpAdapter()
