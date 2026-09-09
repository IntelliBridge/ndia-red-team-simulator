"""Black-box explainers (register ATTACKS_HARDEN-07, -08, -09; ENDPOINT-14).

KernelExplainer on a predict-only tabular target with the spec 13.2 seeded 100-row background, the explicit
explainer choice with no silent fallback, the endpoint query caps (``EXPLAIN_QUERY_CAPS``) with the queries
counted per purpose, the catalog roster, and the recorded (not built) decision on KernelSHAP for images.

The predict-only double wraps ``tests.ml.fakes.TinyTabularTarget`` and exposes ``predict_proba`` through an
ART ``BlackBoxClassifier`` only: no ``sklearn_model``, no ``.model``, no torch module. It counts every call
it receives so the explainer's own tally is checked against an independent one.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("shap")
pytest.importorskip("sklearn")
pytest.importorskip("art")

import numpy as np

from redsim.ml.artifacts import FilesystemSink
from redsim.ml.errors import ExplainerUnavailable, ExplainUnavailable
from redsim.ml.explain import base, shap_image, shap_tabular
from redsim.ml.explain.base import (
    ENDPOINT_ACCESS,
    EXPLAIN_QUERY_CAPS,
    EXPLAINER_KIND_BY_NAME,
    EXPLAINER_KINDS,
    EXPLAINER_ROSTER,
    KERNEL_BACKGROUND_ROWS,
    ExplainQueryCaps,
    QueryCounter,
    estimate_kernel_explain_rows,
    explain_caps_for,
    explainer_kind,
)
from redsim.ml.schema import Observation, TargetInfo
from redsim.ml.targets.base import Sample
from tests.ml.fakes import (
    TABULAR_CLASS_NAMES,
    TABULAR_DATASET,
    TABULAR_FEATURE_NAMES,
    TinyTabularTarget,
    TinyTarget,
)

pytestmark = pytest.mark.ml

FEATURES = list(TABULAR_FEATURE_NAMES)


# --------------------------------------------------------------------------- doubles

class PredictOnlyTabularTarget:
    """The Target protocol over ``TinyTabularTarget.predict_proba`` and nothing else (no tree, no gradients).

    ``access`` lands in ``info().metadata["access"]`` (``"black-box-endpoint"`` makes it look like an endpoint
    target). ``purposes`` records every ``purpose(...)`` context the caller entered, the hook an endpoint
    broker uses to tally queries per purpose.
    """

    id = "tiny_tabular_predict_only"

    def __init__(self, seed: int = 0, *, access: str | None = "black-box") -> None:
        self._inner = TinyTabularTarget(seed=seed, surrogate=False)
        self._access = access
        self.calls = 0
        self.rows = 0
        self.purposes: list[str] = []

    def info(self) -> TargetInfo:
        metadata: dict[str, Any] = {"dataset": TABULAR_DATASET, "n_classes": len(TABULAR_CLASS_NAMES),
                                    "gradients": False}
        if self._access is not None:
            metadata["access"] = self._access
        return TargetInfo(id=self.id, name="Predict-only tabular (test double)", domain="tabular",
                          status="available", metadata=metadata)

    def load(self) -> None:
        return None

    def sample(self, n: int, seed: int) -> Sample:
        return self._inner.sample(n, seed)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        arr = np.asarray(x, dtype=np.float32)
        self.calls += 1
        self.rows += int(arr.shape[0])
        return self._inner.predict_proba(arr)

    def art_classifier(self) -> Any:
        from art.estimators.classification import BlackBoxClassifier

        return BlackBoxClassifier(predict_fn=self.predict_proba, input_shape=(len(FEATURES),),
                                  nb_classes=len(TABULAR_CLASS_NAMES), clip_values=(0.0, 1.0))

    def torch_model(self) -> Any:
        return None

    def manifest(self) -> dict[str, Any]:
        out = dict(self._inner.manifest())
        out.update({"model": "predict-only wrapper", "explainer": None})
        out.pop("surrogate", None)
        return out

    @contextlib.contextmanager
    def purpose(self, name: str) -> Iterator[None]:
        self.purposes.append(name)
        yield

    def reset_counts(self) -> None:
        self.calls = 0
        self.rows = 0


class LinearTabularTarget(PredictOnlyTabularTarget):
    """Exposes a fitted non-tree estimator, so ``auto`` tries TreeExplainer first and must record the failure."""

    def __init__(self, seed: int = 0) -> None:
        from sklearn.linear_model import LogisticRegression

        super().__init__(seed=seed, access=None)
        s = self._inner.sample(120, seed)
        self._linear = LogisticRegression(max_iter=500).fit(s.x, s.y)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        arr = np.asarray(x, dtype=np.float32)
        self.calls += 1
        self.rows += int(arr.shape[0])
        return np.asarray(self._linear.predict_proba(arr), dtype=np.float32)

    def sklearn_model(self) -> Any:
        return self._linear


def _case(target: Any, n: int, seed: int = 0):
    sample = target.sample(n, seed)
    rng = np.random.default_rng(seed + 7)
    x_adv = np.clip(sample.x + rng.uniform(-0.4, 0.4, sample.x.shape).astype(np.float32), 0, 1)
    x_ctrl = np.clip(sample.x + rng.uniform(-0.03, 0.03, sample.x.shape).astype(np.float32), 0, 1)
    pc, pa = target.predict_proba(sample.x), target.predict_proba(x_adv)
    if hasattr(target, "reset_counts"):
        target.reset_counts()
    return sample, x_adv, x_ctrl, pc, pa


def _written(tmp_path) -> list:
    root = tmp_path / "artifacts"
    return [p for p in root.rglob("*") if p.is_file()] if root.exists() else []


# --------------------------------------------------------------------------- ATTACKS_HARDEN-07: KernelSHAP on a predict-only target

def test_kernel_explainer_on_predict_only_tabular_target(tmp_path):
    """KernelExplainer over predict_proba, seeded 100-row background, nsamples recorded, expl_shift and the
    noise floor present, queries counted for purpose=explain, the explainer family on every record."""
    target = PredictOnlyTabularTarget(seed=0)
    sample, x_adv, x_ctrl, pc, pa = _case(target, n=140)   # 140 rows leave a pool > 100 outside the explained rows
    out = shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=3, seed=0,
                               feature_names=None, x_ctrl=x_ctrl, attack_id="hopskipjump", eps=0.1)
    m = out.meta
    assert m["explainer"] == "KernelExplainer" and m["explainer_kind"] == "kernel"
    assert m["explainer_requested"] == "auto" and m["explainers_tried"] == []   # no tree model, nothing to try
    assert m["deterministic"] is False
    assert m["background_size"] == KERNEL_BACKGROUND_ROWS == 100 == m["background_size_requested"]
    assert m["background_pool_size"] == 140 - m["n_explained"]
    assert len(m["background_indices"]) == 100 and len(set(m["background_indices"])) == 100
    assert m["nsamples"] == 200 == m["nsamples_requested"]
    assert m["seed"] == 0 and m["query_caps"] is None and m["query_caps_source"] == "none"
    assert m["explain_k"] == m["explain_k_requested"] == 3 and m["explain_k_cap"] is None
    assert any("KernelExplainer" in s and "background_size=100" in s and "nsamples=200" in s
               for s in m["nondeterminism"])
    assert shap_tabular.KERNEL_LIMITATION in m["limitations"]
    # the background never contains an explained row
    explained = {o.sample_index for o in out.observations}
    assert explained.isdisjoint(set(m["background_indices"]))
    # S_expl inputs: per-sample expl_shift in [0, 1], the aggregate with its denominators, the noise floor with n
    assert out.observations and all(o.expl_shift is None or 0.0 <= o.expl_shift <= 1.0 for o in out.observations)
    assert out.expl_shift_mean is not None and 0.0 <= out.expl_shift_mean <= 1.0
    assert out.expl_shift_n + out.expl_shift_n_excluded == len(out.observations)
    assert out.expl_shift_noise_floor is not None and 0.0 <= out.expl_shift_noise_floor <= 1.0
    assert out.expl_shift_noise_floor_n is not None and out.expl_shift_noise_floor_n >= 1
    # queries: counted on the explainer side, equal to what the double saw, within the recorded bound
    q = m["queries"]
    assert q["purpose"] == "explain" and q["calls"] == target.calls and q["rows"] == target.rows > 0
    assert q["rows"] <= q["rows_upper_bound"] == estimate_kernel_explain_rows(
        k=3, background_rows=100, nsamples=200, with_control=True)
    assert q["purpose_hook"] is True and target.purposes == ["explain"]
    # the explainer family travels on the observation and in the per-sample file, beside the heuristic label
    for o in out.observations:
        assert o.metric_kind == "heuristic"
        assert "KernelExplainer" in o.metric_note and "kind: kernel" in o.metric_note
        assert "feature identifiers" in o.metric_note
        assert 1 <= len(o.top_features_clean) <= 5 and set(o.top_features_clean) <= set(FEATURES)
        assert 1 <= len(o.top_features_adv) <= 5 and set(o.top_features_adv) <= set(FEATURES)
        diff = json.loads((tmp_path / o.artifacts[base.FEATURE_DIFF_NAME]).read_bytes())
        assert diff["explainer"] == "KernelExplainer" and diff["explainer_kind"] == "kernel"
        assert diff["explainer_requested"] == "auto" and diff["metric_kind"] == "heuristic"
        assert diff["nsamples"] == 200 and diff["background_size"] == 100 and diff["query_caps"] is None
        assert diff["attack_id"] == "hopskipjump" and diff["eps"] == 0.1
        Observation.model_validate(o.model_dump(mode="json"))
    # the provenance block the campaign lifts into Provenance
    prov = m["explainer_provenance"]
    assert prov["explainer"] == "KernelExplainer" and prov["explainer_kind"] == "kernel"
    assert prov["queries"] == q and prov["background_size"] == 100 and prov["seed"] == 0
    summary = json.loads((tmp_path / m["artifacts"]["shap_summary.json"]).read_bytes())
    assert summary["explainer_kind"] == "kernel" and summary["queries"]["rows"] == q["rows"]


def test_kernel_explainer_is_seeded(tmp_path):
    """Same seed, same attributions: the coalition sampling runs under the recorded seed."""
    target = PredictOnlyTabularTarget(seed=1)
    sample, x_adv, x_ctrl, pc, pa = _case(target, n=40)
    outs = []
    for name in ("a", "b"):
        outs.append(shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path / name), k=2, seed=3,
                                         feature_names=FEATURES, nsamples=60, background_size=15))
    a, b = outs
    assert a.meta["background_indices"] == b.meta["background_indices"] and len(a.meta["background_indices"]) == 15
    assert a.meta["per_sample"] == b.meta["per_sample"]
    assert a.expl_shift_mean == b.expl_shift_mean
    for oa, ob in zip(a.observations, b.observations, strict=True):
        with np.load(tmp_path / "a" / oa.artifacts["shap_values.npz"]) as za, \
                np.load(tmp_path / "b" / ob.artifacts["shap_values.npz"]) as zb:
            assert np.array_equal(za["clean"], zb["clean"]) and np.array_equal(za["adv"], zb["adv"])
    # a different seed draws a different background (deterministic given the seed, never a fixed subset)
    c = shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path / "c"), k=2, seed=4,
                             feature_names=FEATURES, nsamples=60, background_size=15)
    assert c.meta["background_indices"] != a.meta["background_indices"]


def test_explicit_explainer_choice_is_honoured_without_fallback(tmp_path):
    tree = TinyTabularTarget(seed=0)
    sample, x_adv, _x_ctrl, pc, pa = _case(tree, n=40)
    # auto on a tree model: TreeExplainer, exact, no queries
    auto = shap_tabular.explain(tree, sample, x_adv, pc, pa, FilesystemSink(tmp_path / "auto"), k=2, seed=0,
                                feature_names=FEATURES)
    assert auto.meta["explainer"] == "TreeExplainer" and auto.meta["explainer_kind"] == "tree"
    assert auto.meta["deterministic"] is True and auto.meta["explainers_tried"] == []
    assert auto.meta["queries"]["rows"] == 0 and auto.meta["queries"]["rows_upper_bound"] == 0
    assert auto.meta["nsamples"] is None and auto.meta["background_size"] == 0
    assert auto.meta["background_indices"] == [] and auto.meta["nsamples_requested"] is None
    assert all("TreeExplainer" in o.metric_note and "kind: tree" in o.metric_note for o in auto.observations)
    assert shap_tabular.KERNEL_LIMITATION not in auto.meta["limitations"]
    # an explicit KernelExplainer on the same tree model never consults the tree
    kern = shap_tabular.explain(tree, sample, x_adv, pc, pa, FilesystemSink(tmp_path / "kern"), k=2, seed=0,
                                feature_names=FEATURES, explainer="KernelExplainer", nsamples=40, background_size=10)
    assert kern.meta["explainer"] == "KernelExplainer" and kern.meta["explainer_requested"] == "KernelExplainer"
    assert kern.meta["explainers_tried"] == [] and kern.meta["queries"]["rows"] > 0
    assert kern.meta["nsamples"] == 40 and kern.meta["background_size"] == 10
    # an explicit TreeExplainer on a predict-only target is a typed refusal, nothing written
    predict_only = PredictOnlyTabularTarget(seed=0)
    sample_p, x_adv_p, _x, pc_p, pa_p = _case(predict_only, n=40)
    with pytest.raises(ExplainerUnavailable) as exc:
        shap_tabular.explain(predict_only, sample_p, x_adv_p, pc_p, pa_p, FilesystemSink(tmp_path / "tree_refused"),
                             k=2, seed=0, feature_names=FEATURES, explainer="TreeExplainer")
    assert exc.value.code == "explainer_unavailable" and "TreeExplainer was requested" in str(exc.value)
    assert _written(tmp_path / "tree_refused") == [] and predict_only.rows == 0
    # a non-tree estimator: auto records the TreeExplainer failure and falls back; explicit tree refuses
    linear = LinearTabularTarget(seed=0)
    sample_l, x_adv_l, _x, pc_l, pa_l = _case(linear, n=40)
    fell_back = shap_tabular.explain(linear, sample_l, x_adv_l, pc_l, pa_l, FilesystemSink(tmp_path / "fallback"), k=2,
                                     seed=0, feature_names=FEATURES, nsamples=40, background_size=10)
    assert fell_back.meta["explainer"] == "KernelExplainer" and fell_back.meta["explainer_requested"] == "auto"
    assert len(fell_back.meta["explainers_tried"]) == 1 and fell_back.meta["explainers_tried"][0].startswith("TreeExplainer")
    with pytest.raises(ExplainerUnavailable) as exc2:
        shap_tabular.explain(linear, sample_l, x_adv_l, pc_l, pa_l, FilesystemSink(tmp_path / "linear_tree"), k=2,
                             seed=0, feature_names=FEATURES, explainer="TreeExplainer")
    assert "no fallback" in str(exc2.value) and _written(tmp_path / "linear_tree") == []


def test_image_and_unknown_explainer_names_are_refused_on_tabular(tmp_path):
    tree = TinyTabularTarget(seed=0)
    sample, x_adv, _x_ctrl, pc, pa = _case(tree, n=30)
    for name in shap_tabular.IMAGE_ONLY_EXPLAINERS:
        with pytest.raises(ExplainUnavailable) as exc:
            shap_tabular.explain(tree, sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=2, seed=0,
                                 feature_names=FEATURES, explainer=name)
        assert "image explainer" in str(exc.value) and name in str(exc.value)
    with pytest.raises(ExplainUnavailable) as exc:
        shap_tabular.explain(tree, sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=2, seed=0,
                             feature_names=FEATURES, explainer="LimeExplainer")
    assert "unknown tabular explainer" in str(exc.value)
    assert _written(tmp_path) == []
    assert shap_tabular.EXPLAINER_CHOICES == ("auto", "TreeExplainer", "KernelExplainer")


# --------------------------------------------------------------------------- ENDPOINT-14: query caps

def test_endpoint_caps_bound_the_query_budget_and_are_recorded(tmp_path):
    target = PredictOnlyTabularTarget(seed=0, access=ENDPOINT_ACCESS)
    assert explain_caps_for(target) == EXPLAIN_QUERY_CAPS
    sample, x_adv, x_ctrl, pc, pa = _case(target, n=60)
    out = shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=16, seed=0,
                               feature_names=FEATURES, x_ctrl=x_ctrl, nsamples=500, background_size=100)
    m = out.meta
    assert m["explainer"] == "KernelExplainer" and m["query_caps"] == EXPLAIN_QUERY_CAPS.as_dict()
    assert m["query_caps_source"] == "target metadata access=black-box-endpoint"
    assert m["explain_k"] == 8 and m["explain_k_requested"] == 16 and m["explain_k_cap"] == 8
    assert m["n_explained"] <= 16
    # the effective value and the caller's request are both recorded, never only the capped one
    assert m["background_size"] == 20 and m["background_size_requested"] == 100   # requested 100 -> capped to 20
    assert m["nsamples"] == 200 and m["nsamples_requested"] == 500                # requested 500 -> capped to 200
    q = m["queries"]
    assert q["rows"] == target.rows > 0 and q["rows"] <= q["rows_upper_bound"]
    assert q["rows_upper_bound"] <= EXPLAIN_QUERY_CAPS.estimate_rows(16, with_control=True)
    assert q["rows_upper_bound"] == estimate_kernel_explain_rows(k=8, background_rows=20, nsamples=200)
    cap_lines = [s for s in m["limitations"] if "black-box endpoint caps" in s]
    assert len(cap_lines) == 1 and "explain_k 16 -> 8" in cap_lines[0]
    assert "background_size 100 -> 20" in cap_lines[0] and "nsamples 500 -> 200" in cap_lines[0]
    assert "coarse estimate" in cap_lines[0]
    assert target.purposes == ["explain"]
    # the noise floor and S_expl inputs are still computed under the caps
    assert out.expl_shift_mean is not None and out.expl_shift_noise_floor_n is not None
    for o in out.observations:
        diff = json.loads((tmp_path / o.artifacts[base.FEATURE_DIFF_NAME]).read_bytes())
        assert diff["query_caps"] == EXPLAIN_QUERY_CAPS.as_dict() and diff["background_size"] == 20


def test_explicit_query_caps_apply_to_any_target_and_local_targets_are_uncapped(tmp_path):
    target = PredictOnlyTabularTarget(seed=0)   # access "black-box", not an endpoint
    assert explain_caps_for(target) is None and explain_caps_for(TinyTabularTarget()) is None
    assert explain_caps_for(object()) is None
    sample, x_adv, _x_ctrl, pc, pa = _case(target, n=40)
    caps = ExplainQueryCaps(background_rows=5, nsamples=30, explain_k=1)
    out = shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path / "caps"), k=3, seed=0,
                               feature_names=FEATURES, query_caps=caps)
    assert out.meta["explain_k"] == 1 and out.meta["background_size"] == 5 and out.meta["nsamples"] == 30
    assert out.meta["query_caps_source"] == "argument" and len(out.observations) <= 2
    assert out.meta["queries"]["rows"] <= out.meta["queries"]["rows_upper_bound"]
    # the same caps as a mapping (a config block), and no cap line when nothing exceeded them
    loose = shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path / "loose"), k=1, seed=0,
                                 feature_names=FEATURES, nsamples=20, background_size=4,
                                 query_caps={"background_rows": 5, "nsamples": 30, "explain_k": 1})
    assert loose.meta["query_caps"] == caps.as_dict()
    assert any("no requested value exceeded a cap" in s for s in loose.meta["limitations"])
    uncapped = shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path / "none"), k=3, seed=0,
                                    feature_names=FEATURES, nsamples=40, background_size=10)
    assert uncapped.meta["query_caps"] is None and uncapped.meta["explain_k_cap"] is None
    assert not any("endpoint caps" in s for s in uncapped.meta["limitations"])


def test_explain_query_caps_constants_and_estimates():
    assert EXPLAIN_QUERY_CAPS == ExplainQueryCaps(background_rows=20, nsamples=200, explain_k=8)
    assert EXPLAIN_QUERY_CAPS.as_dict() == {"background_rows": 20, "nsamples": 200, "explain_k": 8}
    assert ExplainQueryCaps.from_mapping(EXPLAIN_QUERY_CAPS.as_dict()) == EXPLAIN_QUERY_CAPS
    assert EXPLAIN_QUERY_CAPS.per_observation_rows() == 3 * (200 * 20 + 1)
    assert EXPLAIN_QUERY_CAPS.per_observation_rows(with_control=False) == 2 * (200 * 20 + 1)
    assert estimate_kernel_explain_rows(k=8, background_rows=20, nsamples=200) == 2 * 8 * 3 * (200 * 20 + 1) + 20
    assert EXPLAIN_QUERY_CAPS.estimate_rows(64) == EXPLAIN_QUERY_CAPS.estimate_rows(8)   # k is capped inside
    assert EXPLAIN_QUERY_CAPS.explain_k == shap_image.PARTITION_K_CAP   # one black-box k cap across modalities
    assert KERNEL_BACKGROUND_ROWS == 100
    with pytest.raises(dataclasses.FrozenInstanceError):
        EXPLAIN_QUERY_CAPS.nsamples = 1   # type: ignore[misc]  # frozen: the caps are constants


def test_query_counter_counts_calls_and_rows():
    seen: list[int] = []

    def f(x: np.ndarray) -> np.ndarray:
        seen.append(int(x.shape[0]))
        return np.zeros((x.shape[0], 2))

    counter = QueryCounter(f)
    counter(np.zeros((7, 3)))
    counter(np.zeros((5, 3)))
    assert counter.calls == 2 and counter.rows == 12 and seen == [7, 5]
    assert counter.as_dict()["purpose"] == "explain" and counter.as_dict()["rows"] == 12


# --------------------------------------------------------------------------- ATTACKS_HARDEN-09: roster; -08: the image decision

def test_explainer_roster_and_kinds_are_consistent():
    assert set(EXPLAINER_KINDS) == {"kernel", "tree", "gradient", "partition"}
    assert {explainer_kind(n) for n in EXPLAINER_KIND_BY_NAME} == set(EXPLAINER_KINDS)
    assert explainer_kind("DeepExplainer") == "gradient" and explainer_kind("PartitionExplainer") == "partition"
    with pytest.raises(ValueError):
        explainer_kind("LimeExplainer")
    image, tabular, endpoint = EXPLAINER_ROSTER["image"], EXPLAINER_ROSTER["tabular"], EXPLAINER_ROSTER["endpoint"]
    assert image["white_box"] == ["GradientExplainer", "DeepExplainer"] and image["black_box"] == ["PartitionExplainer"]
    assert image["k_cap_black_box"] == shap_image.PARTITION_K_CAP == 8
    assert image["kernel_shap"] == "not built" and "PartitionExplainer" in image["kernel_shap_reason"]
    assert tabular["tree"] == ["TreeExplainer"] and tabular["non_tree_or_black_box"] == ["KernelExplainer"]
    assert tabular["kernel_background_rows"] == KERNEL_BACKGROUND_ROWS
    assert endpoint == {"image": ["PartitionExplainer"], "tabular": ["KernelExplainer"],
                        "query_caps": EXPLAIN_QUERY_CAPS.as_dict()}
    assert EXPLAINER_ROSTER["kinds"] == EXPLAINER_KIND_BY_NAME
    # every roster name is a shap class the image or tabular module actually offers
    offered = set(shap_image.EXPLAINER_CHOICES) | set(shap_tabular.EXPLAINER_CHOICES)
    listed = set(image["white_box"] + image["black_box"] + tabular["tree"] + tabular["non_tree_or_black_box"])
    assert listed <= offered
    json.dumps(EXPLAINER_ROSTER)   # pure data for the catalog route


def test_kernel_explainer_request_on_image_is_refused_with_reason(tmp_path):
    """ATTACKS_HARDEN-08: recorded, not built. The image module refuses KernelExplainer and keeps the
    PartitionExplainer path; the reason is stated once in ``explain.base`` and in the tabular module docstring."""
    assert "KernelExplainer" not in shap_image.EXPLAINER_CHOICES
    assert "PartitionExplainer" in shap_image.EXPLAINER_CHOICES
    note = base.KERNEL_IMAGE_INFEASIBLE_NOTE
    assert "49,152" in note and "PartitionExplainer" in note and "rate-limited endpoint" in note
    assert "KernelSHAP for black-box images" in (shap_tabular.__doc__ or "")
    target = TinyTarget(seed=0)
    sample = target.sample(12, 0)
    x_adv = np.random.default_rng(1).random(sample.x.shape, dtype=np.float32)
    pc, pa = target.predict_proba(sample.x), target.predict_proba(x_adv)
    with pytest.raises(ExplainUnavailable) as exc:
        shap_image.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=2, seed=0,
                           explainer="KernelExplainer")
    assert "KernelExplainer" in str(exc.value) and "PartitionExplainer" in str(exc.value)
    assert _written(tmp_path) == []
