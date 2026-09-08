"""HopSkipJump adapter over ``art.attacks.evasion.HopSkipJump`` (spec 12.2, black-box).

Decision-based: it uses only the estimator's ``predict`` output, which the adapter
counts so ``queries_mean`` (predict rows per sample) can be recorded. It takes no
eps: the campaign thresholds the achieved perturbation norm against each grid eps
(spec 15.1), so ``takes_eps`` is ``False``. Defaults are capped below ART's own for
CPU budgets. Its random initial point and Monte-Carlo gradient estimate are seeded
but recorded as a nondeterminism source (spec 12.7).
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

import numpy as np

from redsim.ml.attacks import (
    CPU_FLOAT32_NOTE,
    NONDETERMINISM_PREFIX,
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


class HopSkipJumpAdapter:
    id = "hopskipjump"
    domains = frozenset({"tabular", "image"})
    takes_eps = False

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
        clf = target.art_classifier()
        seed_all(seed)

        # Query counter: shadow the instance's predict for the duration of the attack so ART's
        # isinstance checks on the estimator still hold (spec 12.5 ``queries(a)``).
        counter = {"rows": 0, "calls": 0}
        original_predict = clf.predict

        def counting_predict(inputs: np.ndarray, *args: Any, **kwargs: Any) -> np.ndarray:
            # ART's HopSkipJump works in float64 internally but the target's estimator expects the
            # slice dtype (float32), so cast before forwarding. Counting is by rows (spec 12.5).
            arr = np.asarray(inputs, dtype=x.dtype)
            counter["rows"] += int(arr.shape[0])
            counter["calls"] += 1
            return np.asarray(original_predict(arr, *args, **kwargs))

        t0 = time.perf_counter()
        try:
            clf.predict = counting_predict
            attack = HopSkipJump(classifier=clf, batch_size=int(p["batch_size"]), targeted=False, norm=norm,
                                 max_iter=int(p["max_iter"]), max_eval=int(p["max_eval"]),
                                 init_eval=int(p["init_eval"]), init_size=int(p["init_size"]), verbose=False)
            # y=None: move away from the model's own clean prediction (the attacker sees labels only).
            x_adv = np.asarray(attack.generate(x=x, y=None), dtype=np.float32)
        finally:
            try:
                del clf.predict  # restore the class method
            except AttributeError:  # pragma: no cover - already absent
                pass
        x_adv = apply_mask(x, x_adv, perturbable_mask(target, x))
        wall = time.perf_counter() - t0
        linf, l2 = perturbation_norms(x, x_adv)
        n = max(int(x.shape[0]), 1)
        queries_mean = counter["rows"] / n
        return AttackOutput(
            x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=wall, params=dict(p),
            library_versions=library_versions(), queries_mean=float(queries_mean),
            notes=[f"norm={'L2' if norm == 2 else 'Linf'}; black-box decision-based; no gradients, no surrogate",
                   ("minimal-norm attack: success at eps is defined by thresholding the achieved perturbation "
                    "norm against each grid eps (spec 15.1)"),
                   (f"queries_mean = {queries_mean:.1f} predict rows per sample "
                    f"({counter['rows']} rows in {counter['calls']} predict calls over n={n})"),
                   f"{NONDETERMINISM_PREFIX}{HSJ_NONDETERMINISM.format(seed=int(seed))}",
                   f"{NONDETERMINISM_PREFIX}{CPU_FLOAT32_NOTE}"],
        )


ADAPTER: HopSkipJumpAdapter = HopSkipJumpAdapter()
