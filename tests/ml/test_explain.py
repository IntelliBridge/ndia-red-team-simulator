"""Explain stage: SHAP image/tabular explainers, stability metric, text summary (spec 13, 22.3).

Built against the frozen M0 contract: ``Observation.expl_shift`` / ``top_features_*`` per sample, the
reference-row ``Measurement`` fields on ``ExplainOutput``, and ``MRIRecord`` in the text summary.
"""

from __future__ import annotations

import hashlib
import json
import math
import string
from datetime import UTC, datetime
from typing import Any

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("shap")

import numpy as np

from redsim.ml.artifacts import FilesystemSink
from redsim.ml.errors import ExplainUnavailable
from redsim.ml.explain import (
    MEASUREMENT_FIELDS,
    ExplainOutput,
    shap_image,
    shap_tabular,
)
from redsim.ml.explain.stability import aggregate, channel_sum, expl_shift
from redsim.ml.explain.summary import FIXED_SENTENCE, text_summary
from redsim.ml.schema import (
    GRADE_STATEMENT,
    Measurement,
    MRIInputRow,
    MRIRecord,
    MRIWeights,
    Observation,
    Subscores,
    TargetInfo,
    contains_banned_score_word,
)
from redsim.ml.targets.base import Sample
from tests.ml.fakes import TinyTarget

pytestmark = pytest.mark.ml

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
REQUIRED_IMAGE_PNGS = ("clean.png", "adv.png", "shap_clean.png", "shap_adv.png")


# --------------------------------------------------------------------------- helpers / doubles

def _image_case(n: int = 24, seed: int = 0):
    target = TinyTarget(seed=seed)
    sample = target.sample(n, seed)
    rng = np.random.default_rng(seed + 1)
    # "adversarial" inputs for the explainer: fresh random images guarantee some flips on a random net
    x_adv = rng.random(sample.x.shape, dtype=np.float32)
    x_ctrl = np.clip(sample.x + rng.uniform(-0.03, 0.03, sample.x.shape).astype(np.float32), 0, 1)
    return target, sample, x_adv, x_ctrl, target.predict_proba(sample.x), target.predict_proba(x_adv)


class _NoTorchTarget(TinyTarget):
    def torch_model(self) -> Any:
        return None


FEATURES = ["url_length", "digit_ratio", "letter_ratio", "count_dot", "count_hyphen", "count_at", "count_query",
            "count_percent", "count_equals", "subdomain_count", "path_depth", "has_ip_host"]


class TinyTabularTarget:
    """RandomForest on a seeded 12-feature, 3-class synthetic table (a local double, fakes.py is not ours)."""

    id = "tiny_tabular"

    def __init__(self, seed: int = 0, model: str = "tree") -> None:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression

        rng = np.random.default_rng(seed)
        x = rng.random((120, len(FEATURES))).astype(np.float32)
        y = (x[:, 0] + x[:, 3] + x[:, 9] > 1.5).astype(int) + (x[:, 11] > 0.8).astype(int)
        self._x, self._y = x, y
        if model == "tree":
            self._model = RandomForestClassifier(n_estimators=6, max_depth=3, random_state=seed).fit(x, y)
        else:
            self._model = LogisticRegression(max_iter=300).fit(x, y)
        self._kind = model

    def info(self) -> TargetInfo:
        return TargetInfo(id=self.id, name="Tiny tabular (test double)", domain="tabular", status="available")

    def load(self) -> None:
        return None

    def sample(self, n: int, seed: int) -> Sample:
        return Sample(x=self._x[:n], y=self._y[:n], indices=np.arange(n), class_names=["benign", "suspicious", "malicious"])

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        p = self._model.predict_proba(np.asarray(x, dtype=np.float32))
        if p.shape[1] < 3:  # keep three columns even if a class is absent from training
            full = np.zeros((p.shape[0], 3))
            full[:, self._model.classes_] = p
            return full
        return p

    def art_classifier(self) -> Any:
        class _Wrap:
            model = self._model
        return _Wrap()

    def torch_model(self) -> Any:
        return None

    def manifest(self) -> dict[str, Any]:
        return {"dataset": "synthetic", "model": self._kind, "feature_names": FEATURES}


def _tabular_case(kind: str = "tree", n: int = 40, seed: int = 0):
    target = TinyTabularTarget(seed=seed, model=kind)
    sample = target.sample(n, seed)
    rng = np.random.default_rng(seed + 7)
    x_adv = np.clip(sample.x + rng.uniform(-0.4, 0.4, sample.x.shape).astype(np.float32), 0, 1)
    return target, sample, x_adv, target.predict_proba(sample.x), target.predict_proba(x_adv)


def _sha(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ref_row(out: ExplainOutput, attack: str = "fgsm", n: int = 24) -> Measurement:
    """The campaign's use of ``measurement_fields()``: written onto the evasion row at the reference budget."""
    base = Measurement(id=f"m.evasion.{attack}.eps0.03", family="evasion", attack_id=attack,
                       params={"eps": 0.03, "norm": "linf"}, n=n, n_correct=n // 2, accuracy=0.5)
    return base.model_copy(update=out.measurement_fields())


# --------------------------------------------------------------------------- stability

def test_expl_shift_identical_maps_is_zero():
    a = np.random.default_rng(0).normal(size=(8, 8))
    assert expl_shift(a, a) == pytest.approx(0.0, abs=1e-12)
    assert expl_shift(a, 3.0 * a) == pytest.approx(0.0, abs=1e-12)


def test_expl_shift_orthogonal_is_one_and_anticorrelated_clamps_to_one():
    a = np.zeros((4, 4))
    a[0, 0] = 1.0
    b = np.zeros((4, 4))
    b[1, 1] = 1.0
    assert expl_shift(a, b) == pytest.approx(1.0)
    assert expl_shift(a, -a) == 1.0  # 1 - (-1) = 2, clamped to 1


def test_expl_shift_range_and_undefined_pairs():
    rng = np.random.default_rng(1)
    for _ in range(20):
        v = expl_shift(rng.normal(size=(3, 8, 8)), rng.normal(size=(3, 8, 8)))
        assert 0.0 <= v <= 1.0
    assert math.isnan(expl_shift(np.zeros((4, 4)), np.ones((4, 4))))
    mean, n, excluded = aggregate([0.2, float("nan"), 0.4, None])
    assert mean == pytest.approx(0.3) and n == 2 and excluded == 2
    assert aggregate([float("nan")]) == (None, 0, 1)
    with pytest.raises(ValueError):
        expl_shift(np.ones(3), np.ones(4))


def test_channel_sum_collapses_chw():
    a = np.ones((3, 8, 8))
    assert channel_sum(a).shape == (8, 8) and float(channel_sum(a)[0, 0]) == 3.0
    assert channel_sum(np.ones((8, 8))).shape == (8, 8)


# --------------------------------------------------------------------------- centre-mass heuristic

def test_center_mass_ratio_bounds_and_extremes():
    center = np.zeros((8, 8))
    center[3:5, 3:5] = 1.0
    assert shap_image.center_mass_ratio(center) == pytest.approx(1.0)
    corner = np.zeros((8, 8))
    corner[0, 0] = 1.0
    assert shap_image.center_mass_ratio(corner) == pytest.approx(0.0)
    uniform = np.ones((8, 8))
    r = shap_image.center_mass_ratio(uniform)
    assert 0.4 <= r <= 0.7  # central box is round(8/sqrt 2)=6 -> 36/64
    assert shap_image.center_mass_ratio(np.zeros((8, 8))) is None
    assert 0.0 <= shap_image.center_mass_ratio(np.random.default_rng(2).normal(size=(3, 8, 8))) <= 1.0


# --------------------------------------------------------------------------- image explainer

def test_image_explain_writes_pngs_ratios_and_hashes(tmp_path):
    target, sample, x_adv, x_ctrl, pc, pa = _image_case()
    sink = FilesystemSink(tmp_path)
    k = 2
    out = shap_image.explain(target, sample, x_adv, pc, pa, sink, k=k, seed=0, x_ctrl=x_ctrl, nsamples=20)
    assert isinstance(out, ExplainOutput)
    n_flipped_total = int((pc.argmax(1) != pa.argmax(1)).sum())
    assert 1 <= len(out.observations) <= 2 * k
    assert sum(o.flipped for o in out.observations) == min(k, n_flipped_total)
    for o in out.observations:
        assert isinstance(o, Observation) and o.metric_kind == "heuristic"
        for name in REQUIRED_IMAGE_PNGS:
            rel = o.artifacts[name]
            path = tmp_path / rel
            assert path.exists() and path.read_bytes()[:8] == PNG_MAGIC
            assert o.artifact_sha256[name] == _sha(path) == sink.sha256(rel)
        assert "shap_values.npz" in o.artifacts and "shap_meta.json" in o.artifacts
        if o.flipped:
            assert "shap_adv_predclass.png" in o.artifacts
        else:
            assert "shap_adv_predclass.png" not in o.artifacts
        assert o.center_mass_ratio_clean is not None and 0.0 <= o.center_mass_ratio_clean <= 1.0
        assert o.center_mass_ratio_adv is not None and 0.0 <= o.center_mass_ratio_adv <= 1.0
        assert o.true_label in sample.class_names and o.pred_clean in sample.class_names
        assert (o.pred_clean != o.pred_adv) == o.flipped
        with np.load(tmp_path / o.artifacts["shap_values.npz"]) as z:
            assert z["clean"].shape == sample.x.shape[1:] and z["adv"].shape == sample.x.shape[1:]
            assert "control" in z.files
        meta = json.loads((tmp_path / o.artifacts["shap_meta.json"]).read_bytes())
        assert meta["metric_kind"] == "heuristic" and meta["class_explained"] == o.pred_clean
        assert meta["expl_shift"] is None or 0.0 <= meta["expl_shift"] <= 1.0
        # per-sample explanation shift lives on the Observation (frozen schema); images have no feature identifiers
        assert o.expl_shift == meta["expl_shift"] and (o.expl_shift is None or 0.0 <= o.expl_shift <= 1.0)
        assert o.top_features_clean == [] and o.top_features_adv == []
    assert out.expl_shift_mean is not None and 0.0 <= out.expl_shift_mean <= 1.0
    m = out.meta
    assert m["explainer"] in ("GradientExplainer", "DeepExplainer") and m["shap_version"]
    assert m["nsamples"] == 20 and m["background_size"] >= 1 and m["wall_time_s"] >= 0.0
    assert m["expl_shift_n"] + m["expl_shift_n_excluded"] == len(out.observations)
    assert m["expl_shift_noise_floor"] is not None and 0.0 <= m["expl_shift_noise_floor"] <= 1.0
    assert m["expl_shift_noise_floor_n"] >= 1
    assert any("SHAP" in s and "nsamples=20" in s for s in m["nondeterminism"])
    assert (tmp_path / m["artifacts"]["shap_summary.json"]).exists()
    assert set(m["per_sample"]) == {o.id for o in out.observations}
    # reference-row Measurement fields (spec 13.5) come back on the output with their denominators
    assert out.expl_shift_n + out.expl_shift_n_excluded == len(out.observations) and out.expl_shift_n >= 1
    assert (out.expl_shift_n, out.expl_shift_n_excluded) == (m["expl_shift_n"], m["expl_shift_n_excluded"])
    assert out.expl_shift_noise_floor == m["expl_shift_noise_floor"] and out.expl_shift_noise_floor_n >= 1
    defined = [o.expl_shift for o in out.observations if o.expl_shift is not None]
    assert out.expl_shift_mean == pytest.approx(sum(defined) / len(defined)) and len(defined) == out.expl_shift_n
    assert set(out.measurement_fields()) == set(MEASUREMENT_FIELDS)
    ref = _ref_row(out)
    assert ref.expl_shift_mean == out.expl_shift_mean and ref.expl_shift_noise_floor_n == out.expl_shift_noise_floor_n
    assert Measurement.model_validate(ref.model_dump(mode="json")) == ref


def test_image_explain_is_deterministic_for_same_seed(tmp_path):
    target, sample, x_adv, _, pc, pa = _image_case()
    a = shap_image.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path / "a"), k=2, seed=3, nsamples=10)
    b = shap_image.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path / "b"), k=2, seed=3, nsamples=10)
    assert [o.id for o in a.observations] == [o.id for o in b.observations]
    assert a.expl_shift_mean == pytest.approx(b.expl_shift_mean)
    assert [o.artifact_sha256["shap_values.npz"] for o in a.observations] == \
        [o.artifact_sha256["shap_values.npz"] for o in b.observations]
    assert [o.expl_shift for o in a.observations] == [o.expl_shift for o in b.observations]
    # no control was explained: the noise floor is "not computed", never 0
    assert a.expl_shift_noise_floor is None and a.expl_shift_noise_floor_n is None
    assert a.meta["expl_shift_noise_floor"] is None and a.meta["expl_shift_noise_floor_n"] is None
    assert _ref_row(a).expl_shift_noise_floor is None


def test_image_explain_raises_when_no_torch_module_or_k_zero(tmp_path):
    target, sample, x_adv, _, pc, pa = _image_case()
    with pytest.raises(ExplainUnavailable):
        shap_image.explain(_NoTorchTarget(), sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=2, seed=0)
    with pytest.raises(ExplainUnavailable):
        shap_image.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=0, seed=0)
    # nothing is faked: a refused explanation writes no artifact at all
    assert list((tmp_path / "artifacts").rglob("*")) == []


# --------------------------------------------------------------------------- tabular explainer

def test_tabular_tree_explain_writes_plots_and_top_features(tmp_path):
    target, sample, x_adv, pc, pa = _tabular_case("tree")
    sink = FilesystemSink(tmp_path)
    out = shap_tabular.explain(target, sample, x_adv, pc, pa, sink, k=3, seed=0, feature_names=FEATURES)
    assert out.meta["explainer"] == "TreeExplainer" and out.meta["deterministic"] is True
    assert "TreeExplainer is deterministic" in out.meta["nondeterminism"]
    for name in ("shap_bar_clean.png", "shap_bar_adv.png", "shap_beeswarm_clean.png", "shap_beeswarm_adv.png"):
        path = tmp_path / out.meta["artifacts"][name]
        assert path.read_bytes()[:8] == PNG_MAGIC and out.meta["artifact_sha256"][name] == _sha(path)
    assert 1 <= len(out.observations) <= 6
    for o in out.observations:
        assert o.center_mass_ratio_clean is None and o.center_mass_ratio_adv is None
        assert o.metric_kind == "heuristic" and "feature identifiers" in o.metric_note
        # tabular per-sample evidence: feature identifiers ranked by |SHAP| on the Observation itself
        assert 1 <= len(o.top_features_clean) <= 5 and set(o.top_features_clean) <= set(FEATURES)
        assert 1 <= len(o.top_features_adv) <= 5 and set(o.top_features_adv) <= set(FEATURES)
        assert o.expl_shift is None or 0.0 <= o.expl_shift <= 1.0
        top = json.loads((tmp_path / o.artifacts["top_features.json"]).read_bytes())
        assert top["top_features_clean"] == o.top_features_clean and top["top_features_adv"] == o.top_features_adv
        assert top["expl_shift"] == o.expl_shift
        assert len(top["features"]) == len(FEATURES) and {f["name"] for f in top["features"]} == set(FEATURES)
        assert o.artifact_sha256["top_features.json"] == _sha(tmp_path / o.artifacts["top_features.json"])
        assert (tmp_path / o.artifacts["shap_pair.png"]).read_bytes()[:8] == PNG_MAGIC
        dumped = json.dumps(o.model_dump(mode="json"))
        assert "http://" not in dumped and "https://" not in dumped and "www." not in dumped
    assert set(out.meta["top5_clean"]) <= set(FEATURES) and 0 <= out.meta["n_rank_changes"] <= 5
    assert out.expl_shift_mean is None or 0.0 <= out.expl_shift_mean <= 1.0
    assert out.expl_shift_n + out.expl_shift_n_excluded == len(out.observations)
    assert out.expl_shift_noise_floor is None and out.expl_shift_noise_floor_n is None   # no control passed
    assert Measurement.model_validate(_ref_row(out, n=40).model_dump(mode="json")).expl_shift_n == out.expl_shift_n
    # no raw URL-shaped string anywhere in the artifacts
    for p in (tmp_path / "artifacts").rglob("*.json"):
        text = p.read_text()
        assert "http://" not in text and "https://" not in text and "www." not in text


def test_tabular_explain_with_control_reports_the_noise_floor(tmp_path):
    target, sample, x_adv, pc, pa = _tabular_case("tree")
    rng = np.random.default_rng(11)
    x_ctrl = np.clip(sample.x + rng.uniform(-0.03, 0.03, sample.x.shape).astype(np.float32), 0, 1)
    out = shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=3, seed=0,
                               feature_names=FEATURES, x_ctrl=x_ctrl)
    assert out.expl_shift_noise_floor_n is not None and out.expl_shift_noise_floor_n >= 1
    assert out.expl_shift_noise_floor is None or 0.0 <= out.expl_shift_noise_floor <= 1.0
    assert out.expl_shift_noise_floor_n + out.meta["expl_shift_noise_floor_n_excluded"] == len(out.observations)
    for o in out.observations:
        with np.load(tmp_path / o.artifacts["shap_values.npz"]) as z:
            assert "control" in z.files


def test_tabular_explain_refuses_url_shaped_feature_identifiers(tmp_path):
    """Feature identifiers are manifest names. A raw URL string must never become per-sample evidence."""
    target, sample, x_adv, pc, pa = _tabular_case("tree")
    bad = ["https://example.invalid/login?user=x"] + FEATURES[1:]
    with pytest.raises(ExplainUnavailable) as exc:
        shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=2, seed=0, feature_names=bad)
    assert "URL" in str(exc.value) and "example.invalid" not in str(exc.value)   # refused without echoing it
    with pytest.raises(ExplainUnavailable):
        shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=2, seed=0,
                             feature_names=["www.example.invalid"] + FEATURES[1:])
    assert list((tmp_path / "artifacts").rglob("*")) == []   # nothing written before the refusal


def test_tabular_kernel_fallback_for_non_tree_model(tmp_path):
    target, sample, x_adv, pc, pa = _tabular_case("linear", n=30)
    out = shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=2, seed=0,
                               feature_names=FEATURES, nsamples=60, background_size=15)
    assert out.meta["explainer"] == "KernelExplainer" and out.meta["nsamples"] == 60
    assert out.meta["background_size"] == 15
    assert any("KernelExplainer" in s for s in out.meta["nondeterminism"])
    assert out.observations and all(o.artifacts.get("top_features.json") for o in out.observations)


def test_tabular_explain_rejects_bad_inputs(tmp_path):
    target, sample, x_adv, pc, pa = _tabular_case("tree")
    with pytest.raises(ExplainUnavailable):
        shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=0, seed=0, feature_names=FEATURES)
    with pytest.raises(ExplainUnavailable):
        shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path), k=2, seed=0, feature_names=["a"])


def test_tabular_feature_names_fall_back_to_manifest_then_generic(tmp_path):
    target, sample, x_adv, pc, pa = _tabular_case("tree")
    out = shap_tabular.explain(target, sample, x_adv, pc, pa, FilesystemSink(tmp_path / "m"), k=1, seed=0,
                               feature_names=None)
    assert out.meta["feature_names"] == FEATURES and out.meta["feature_names_source"] == "manifest.feature_names"

    class _NoNames(TinyTabularTarget):
        def manifest(self):
            return {"dataset": "synthetic"}

    out2 = shap_tabular.explain(_NoNames(), sample, x_adv, pc, pa, FilesystemSink(tmp_path / "g"), k=1, seed=0,
                                feature_names=None)
    assert out2.meta["feature_names"] == [f"feature_{i:02d}" for i in range(len(FEATURES))]
    assert out2.meta["feature_names_source"].startswith("generic")


# --------------------------------------------------------------------------- text summary

T = datetime(2026, 9, 8, tzinfo=UTC)


def _measurements(with_expl: bool = True) -> list[Measurement]:
    ref = {"expl_shift_mean": 0.55, "expl_shift_n": 4, "expl_shift_n_excluded": 0, "expl_shift_noise_floor": 0.1,
           "expl_shift_noise_floor_n": 4, "conf_gap_mean": 0.62, "conf_gap_n": 100} if with_expl else {}
    return [
        Measurement(id="m.clean", family="clean", n=100, n_correct=80, accuracy=0.8),
        Measurement(id="m.evasion.fgsm.eps0.03", family="evasion", attack_id="fgsm", params={"eps": 0.03, "norm": "linf"},
                    n=100, n_correct=40, accuracy=0.4, n_flipped_from_clean=40, n_clean_correct=80,
                    attack_success_rate=0.5, linf_norm_mean=0.03, **ref),
        Measurement(id="m.control.noise.eps0.03", family="control", attack_id="noise_control",
                    params={"eps": 0.03, "norm": "linf"}, n=100, n_correct=79, accuracy=0.79),
    ]


def _score(**over) -> MRIRecord:
    base = {"scoring_version": "mri-1", "weights": MRIWeights(), "eps_grid": [0.01, 0.03, 0.1], "reference_eps": 0.03,
            "norm": "linf", "attack_ids": ["fgsm"], "finding_asr_threshold": 0.2, "settings_hash": "h" * 64,
            "inputs": [MRIInputRow(attack_id="fgsm", eps=0.03, acc_clean=0.8, acc_adv=0.4, asr=0.5, conf_gap=0.62,
                                   expl_shift=0.55, n=100, n_correct_clean=80, n_attacked=100, n_explained=4)],
            "subscores": Subscores(S_acc=50.0, S_asr=50.0, S_eps=30.0, S_conf=40.0, S_expl=45.0), "mri": 41,
            "grade": "D", "completeness": "complete",
            "reading": "The cheapest in-scope attack succeeded at the reference budget.", "computed_at": T}
    base.update(over)
    return MRIRecord(**base)


def test_text_summary_contains_metrics_scoring_and_fixed_sentence():
    obs = [Observation(id="o.001", sample_index=1, true_label="a", pred_clean="a", pred_adv="b", flipped=True,
                       confidence_clean=0.9, confidence_adv=0.8, artifacts={}, center_mass_ratio_clean=0.7,
                       center_mass_ratio_adv=0.4, expl_shift=0.6)]
    meta = {"modality": "image", "n_flipped_explained": 2, "n_unflipped_explained": 2,
            "center_mass_ratio_mean": {"flipped": {"clean": 0.7, "adv": 0.4, "n": 2}}, "explainer": "GradientExplainer",
            "shap_version": "0.52.0", "nsamples": 200, "background_size": 50}
    text = text_summary(_measurements(), obs, _score(), explain_meta=meta, limitations=["small slice"])
    assert "m.clean" in text and "80/100" in text and "40/80" in text and "ASR 0.500" in text
    assert "MRI = 41" in text and "grade D" in text and "S_expl=45.0" in text and "acc=0.35" in text
    assert "Reading: The cheapest in-scope attack" in text and GRADE_STATEMENT in text
    # the reference-row aggregates with their denominators (spec 13.5), read from the Measurement fields
    assert "For fgsm at eps = 0.03 (L-inf)" in text and "0.550 over n = 4" in text and "0.100 over n = 4" in text
    assert "conf_gap_mean=0.620 over n=100" in text
    assert "o.001" in text and "0.700" in text and "0.400" in text and "expl_shift=0.600" in text
    assert "GradientExplainer" in text and "nsamples=200" in text
    assert "heuristic" in text and "small slice" in text
    assert text.rstrip().endswith(FIXED_SENTENCE)
    assert not contains_banned_score_word(text)


def test_text_summary_without_score_and_scrubs_secrets():
    # Assembled at runtime so secret scanners do not see an AWS-key-shaped literal in the source.
    fake_key = "AKIA" + string.ascii_uppercase[:16]
    ms = _measurements(with_expl=False)
    ms[0] = ms[0].model_copy(update={"notes": [f"token {fake_key} leaked into a note"]})
    text = text_summary(ms, [], None, scoring_reason="S_expl unavailable (explain stage absent)")
    assert "MRI not computed" in text and "S_expl unavailable" in text and "never renormalised" in text
    assert fake_key not in text and "REDACTED" in text
    assert "Observations: none" in text and "S_expl has no input" in text
    assert text.rstrip().endswith(FIXED_SENTENCE)


def test_text_summary_partial_score_record_names_the_missing_dimension():
    partial = _score(mri=None, grade=None, completeness="partial", missing=["S_expl unavailable (explain stage absent)"],
                     subscores=Subscores(S_acc=50.0, S_asr=50.0, S_eps=30.0, S_conf=40.0), inputs=[])
    text = text_summary(_measurements(with_expl=False), [], partial)
    assert "MRI not computed: S_expl unavailable (explain stage absent)" in text
    assert "S_acc=50.0" in text and "S_expl" not in text.split("MRI not computed")[1].split("Weights")[0].replace(
        "S_expl unavailable (explain stage absent)", "")
    assert "MRI =" not in text and "grade" not in text.lower().split("scoring")[1].split("\n")[1]
    assert text.rstrip().endswith(FIXED_SENTENCE)


def test_text_summary_tabular_uses_feature_identifiers_only():
    obs = [Observation(id="o.002", sample_index=2, true_label="benign", pred_clean="benign", pred_adv="malicious",
                       flipped=True, confidence_clean=0.9, confidence_adv=0.7, artifacts={}, expl_shift=0.3,
                       top_features_clean=["url_length", "count_dot"], top_features_adv=["count_dot", "url_length"])]
    ms = _measurements(with_expl=False)
    ms[1] = ms[1].model_copy(update={"expl_shift_mean": 0.3, "expl_shift_n": 2, "expl_shift_n_excluded": 1})
    meta = {"modality": "tabular", "top5_clean": ["url_length", "count_dot"], "top5_adv": ["count_dot", "url_length"],
            "n_rank_changes": 2, "n_explained": 2, "top3_changed_fraction_flipped": 0.5, "top3_changed_n_flipped": 2,
            "explainer": "TreeExplainer"}
    text = text_summary(ms, obs, None, explain_meta=meta)
    assert "url_length, count_dot" in text and "2 of the top 5 changed rank" in text
    assert "0.300 over n = 2 (1 pairs excluded as undefined)" in text and "not computed (no control explained)" in text
    assert "top features clean: url_length, count_dot" in text and "adversarial: count_dot, url_length" in text
    assert "http" not in text
