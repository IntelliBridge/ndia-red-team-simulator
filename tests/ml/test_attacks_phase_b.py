"""Phase B attack adapters on the tiny doubles (ATTACKS_HARDEN-01..05, -22; spec 12.2, 12.3, 12.9; ``ml`` tier).

Carlini-Wagner L2 and DeepFool (image, white-box, minimal-norm, evaluated on the L2 grid), ZOO
(tabular, score-based black-box, frozen features re-imposed after the attack), the ``norms``
declaration with its ``norm:*`` capability tags and ``attack_supports_norm``, HopSkipJump's
image-domain cost defaults and its listing under both modalities. Asserts output shapes,
values in the valid range, seeded determinism, declared norms, parameter bounds and recorded
library versions. Nothing here is evidence about any model: ``TinyTarget`` and
``TinyTabularTarget`` are seeded random doubles.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("art")

import numpy as np

from redsim.ml.attacks import (
    ATLAS_TECHNIQUES,
    ATTACKS,
    KNOWN_ATTACK_CAPABILITIES,
    KNOWN_NORMS,
    MINIMAL_NORM_NOTE,
    NONDETERMINISM_PREFIX,
    OPTIONAL_ADAPTER_MODULES,
    OPTIONAL_ADAPTER_SKIPPED,
    QUERIES_DENOMINATOR_NOTE,
    achieved_norm_note,
    apply_domain_defaults,
    attack_capabilities,
    attack_domain_defaults,
    attack_norms,
    attack_supports_norm,
    attacks_with_capability,
    get_attack,
    list_attack_capabilities,
    queries_summary,
    register_attack,
)
from redsim.ml.attacks.base import AttackAdapter, AttackOutput
from redsim.ml.attacks.hopskipjump import IMAGE_DEFAULTS, MEASUREMENT
from redsim.ml.errors import AttackNotApplicable
from redsim.ml.eval import per_sample_norm
from redsim.ml.schema import AttackInfo, ParamSpec
from redsim.ml.scoring import DEFAULT_EPS_GRID_L2, DEFAULT_EPS_GRID_LINF
from tests.ml.fakes import TABULAR_FEATURE_NAMES, TABULAR_FROZEN, TinyTabularTarget, TinyTarget

pytestmark = pytest.mark.ml

N = 12
TOL = 1e-6
PHASE_B_IDS = ["cw_l2", "deepfool", "zoo"]
# The adapters this package registers itself. Sibling tracks (text, detection) may add more through the optional
# module hook once the schema carries their modality, so registry pins below are filtered to this set.
BUNDLED_IDS = frozenset({"cw_l2", "deepfool", "fgsm", "hopskipjump", "noise_control", "pgd", "zoo"})
# CW parameters that find adversarial examples on the brittle random double (the schema defaults, tuned for the
# bundled resnet18, keep c too small for TinyNet's logit scale: that run is asserted separately as an honest miss).
CW_TINY = {"initial_const": 1.0}
FROZEN_COLS = [i for i, n_ in enumerate(TABULAR_FEATURE_NAMES) if n_ in TABULAR_FROZEN]
FREE_COLS = [i for i, n_ in enumerate(TABULAR_FEATURE_NAMES) if n_ not in TABULAR_FROZEN]


@pytest.fixture(scope="module")
def target() -> TinyTarget:
    return TinyTarget(seed=0)


@pytest.fixture(scope="module")
def slice_(target: TinyTarget):
    return target.sample(N, seed=0)


@pytest.fixture(scope="module")
def tab_target() -> TinyTabularTarget:
    return TinyTabularTarget(seed=0)


@pytest.fixture(scope="module")
def tab_slice(tab_target: TinyTabularTarget):
    return tab_target.sample(N, seed=0)


def _bundled(adapters: list[Any]) -> list[str]:
    return [a.id for a in adapters if a.id in BUNDLED_IDS]


def _flips(target: Any, x: np.ndarray, x_adv: np.ndarray) -> int:
    y_clean = np.asarray(target.predict_proba(x)).argmax(1)
    y_adv = np.asarray(target.predict_proba(x_adv)).argmax(1)
    return int((y_clean != y_adv).sum())


def _assert_common_output(out: AttackOutput, x: np.ndarray) -> None:
    assert isinstance(out, AttackOutput)
    assert out.x_adv.shape == x.shape and out.x_adv.dtype == np.float32
    assert out.wall_time_s >= 0.0 and out.linf_norm_mean >= 0.0 and out.l2_norm_mean >= 0.0
    assert "art" in out.library_versions and "numpy" in out.library_versions
    assert any(n_.startswith(NONDETERMINISM_PREFIX) for n_ in out.notes)


# --- registry: ids, ATLAS, norms and tags -----------------------------------------------------

def test_registry_lists_phase_a_and_phase_b_adapters():
    assert [i for i in ATTACKS.ids() if i in BUNDLED_IDS] == sorted(BUNDLED_IDS)
    assert ATTACKS.ids() == sorted(ATTACKS.ids())
    for adapter in ATTACKS:
        assert isinstance(adapter, AttackAdapter)
    infos = {i.id: i for i in (a.info() for a in ATTACKS)}
    for aid in PHASE_B_IDS:
        info = infos[aid]
        assert isinstance(info, AttackInfo) and info.phase == "B" and info.status == "available"
        assert info.reason is None and info.family == "evasion" and info.references
        assert info.params_schema and all(isinstance(p, ParamSpec) for p in info.params_schema)
        assert AttackInfo.model_validate(info.model_dump(mode="json")) == info
        assert not any("atlas" in k for k in info.model_dump())
    assert infos["cw_l2"].access == "white-box" and infos["cw_l2"].requires_gradients is True
    assert infos["deepfool"].access == "white-box" and infos["deepfool"].requires_gradients is True
    assert infos["zoo"].access == "black-box" and infos["zoo"].requires_gradients is False
    assert infos["hopskipjump"].phase == "A"   # one adapter, one phase; the image row's Phase B is a docs note
    # Optional sibling modules (text, detection) are registered only when they import and validate; every module
    # that did not register has its reason recorded, and a registered one is absent from the skipped table.
    assert OPTIONAL_ADAPTER_MODULES == ("word_substitution", "dpatch", "adv_patch")
    registered_optional = set(ATTACKS.ids()) - BUNDLED_IDS
    for name in OPTIONAL_ADAPTER_MODULES:
        if name in OPTIONAL_ADAPTER_SKIPPED:
            assert OPTIONAL_ADAPTER_SKIPPED[name]
        else:
            assert registered_optional, name


def test_atlas_mapping_covers_the_new_adapters_and_no_control():
    assert set(ATLAS_TECHNIQUES) == {"fgsm", "pgd", "cw_l2", "deepfool", "hopskipjump", "zoo"}
    for aid in ("cw_l2", "deepfool"):
        assert ATLAS_TECHNIQUES[aid].id == "AML.T0043" and ATLAS_TECHNIQUES[aid].name == "Craft Adversarial Data"
    assert ATLAS_TECHNIQUES["zoo"].id == "AML.T0040" and ATLAS_TECHNIQUES["zoo"].name == "ML Model Inference API Access"
    assert "noise_control" not in ATLAS_TECHNIQUES


def test_norms_declared_or_derived_and_exposed_as_tags():
    """ATTACKS_HARDEN-03: every adapter has a non-empty norm set inside KNOWN_NORMS, exposed as norm:* tags."""
    assert KNOWN_NORMS == {"linf", "l2", "edit", "patch_area"}
    assert {f"norm:{n_}" for n_ in KNOWN_NORMS} <= KNOWN_ATTACK_CAPABILITIES
    expected = {
        "fgsm": {"linf"},                    # derived: no norm_l2 parameter
        "pgd": {"linf", "l2"},               # derived: norm_l2 parameter
        "noise_control": {"linf", "l2"},     # derived: norm_l2 parameter
        "hopskipjump": {"linf", "l2"},       # declared
        "cw_l2": {"l2"},                     # declared: minimal-norm L2 only
        "deepfool": {"l2"},                  # declared: minimal-norm L2 only
        "zoo": {"linf", "l2"},               # declared: minimises L2, thresholded in the campaign norm
    }
    caps = list_attack_capabilities()
    assert set(expected) <= set(caps)
    for aid, norms in expected.items():
        adapter = get_attack(aid)
        assert attack_norms(adapter) == frozenset(norms), aid
        assert {t for t in caps[aid] if t.startswith("norm:")} == {f"norm:{n_}" for n_ in norms}, aid
        for n_ in KNOWN_NORMS:
            assert attack_supports_norm(adapter, n_) is (n_ in norms), (aid, n_)
        assert set(caps[aid]) <= KNOWN_ATTACK_CAPABILITIES
    # The L2-only attacks are exactly the ones that may not run under the L-inf grid.
    assert _bundled([a for a in ATTACKS if not attack_supports_norm(a, "linf")]) == ["cw_l2", "deepfool"]
    assert _bundled(attacks_with_capability("norm:l2")) == ["cw_l2", "deepfool", "hopskipjump", "noise_control",
                                                            "pgd", "zoo"]
    assert _bundled(attacks_with_capability("norm:linf")) == ["fgsm", "hopskipjump", "noise_control", "pgd", "zoo"]
    # No bundled adapter is evaluated in the text or detection norms; a sibling adapter that is must serve that modality.
    assert _bundled(attacks_with_capability("norm:edit")) == [] and _bundled(attacks_with_capability("norm:patch_area")) == []
    for a in attacks_with_capability("norm:edit"):
        assert "modality:text" in attack_capabilities(a)
    for a in attacks_with_capability("norm:patch_area"):
        assert "modality:detection" in attack_capabilities(a)


def test_norms_derive_from_the_modality_for_text_and_detection_adapters():
    """A sibling adapter that declares domains but no norms is evaluated in its modality's own norm."""
    base = get_attack("fgsm").info()

    def _fake(domain_tag: str) -> Any:
        class _Fake:
            id = f"fake_{domain_tag}"
            domains = frozenset({domain_tag})
            takes_eps = True

            def info(self) -> AttackInfo:
                # ``domain`` stays a literal the frozen schema carries in this tree; ``domains`` drives the tags.
                return base.model_copy(update={"id": self.id})

            def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
                return {}

            def run(self, target: Any, x: np.ndarray, y: np.ndarray, params: dict[str, Any], seed: int) -> AttackOutput:
                raise AssertionError("never runs")

        return _Fake()

    text, det = _fake("text"), _fake("detection")
    assert attack_norms(text) == frozenset({"edit"}) and attack_norms(det) == frozenset({"patch_area"})
    assert attack_supports_norm(text, "edit") and not attack_supports_norm(text, "linf")
    assert attack_supports_norm(det, "patch_area") and not attack_supports_norm(det, "l2")
    assert {"modality:text", "norm:edit", "takes_eps"} <= attack_capabilities(text)
    assert {"modality:detection", "norm:patch_area", "takes_eps"} <= attack_capabilities(det)
    assert "fake_text" not in ATTACKS and "fake_detection" not in ATTACKS


def test_capability_tags_of_the_new_adapters():
    caps = list_attack_capabilities()
    assert {"white_box", "minimal_norm", "family:evasion", "modality:image", "norm:l2"} <= set(caps["cw_l2"])
    assert {"white_box", "minimal_norm", "family:evasion", "modality:image", "norm:l2"} <= set(caps["deepfool"])
    for aid in ("cw_l2", "deepfool"):
        assert "takes_eps" not in caps[aid] and "modality:tabular" not in caps[aid] and "black_box" not in caps[aid]
    assert {"black_box", "query_counted", "score_based", "minimal_norm", "family:evasion",
            "modality:tabular"} <= set(caps["zoo"])
    assert "modality:image" not in caps["zoo"] and "decision_based" not in caps["zoo"]
    assert {"decision_based", "query_counted", "modality:image", "modality:tabular"} <= set(caps["hopskipjump"])
    assert "score_based" not in caps["hopskipjump"]
    assert _bundled(attacks_with_capability("black_box")) == ["hopskipjump", "noise_control", "zoo"]
    assert _bundled(attacks_with_capability("white_box")) == ["cw_l2", "deepfool", "fgsm", "pgd"]
    assert _bundled(attacks_with_capability("minimal_norm")) == ["cw_l2", "deepfool", "hopskipjump", "zoo"]
    assert _bundled(attacks_with_capability("modality:image")) == ["cw_l2", "deepfool", "fgsm", "hopskipjump",
                                                                   "noise_control", "pgd"]
    assert _bundled(attacks_with_capability("modality:tabular")) == ["hopskipjump", "noise_control", "pgd", "zoo"]
    assert _bundled(attacks_with_capability("score_based")) == ["zoo"]
    assert _bundled(attacks_with_capability("decision_based")) == ["hopskipjump"]
    # Sibling-track vocabulary is present so their adapters can register; no bundled adapter carries it.
    for tag in ("modality:text", "modality:detection", "norm:edit", "norm:patch_area"):
        assert tag in KNOWN_ATTACK_CAPABILITIES and _bundled(attacks_with_capability(tag)) == []


def test_unknown_norm_declaration_is_refused_at_registration():
    pgd_info = get_attack("pgd").info()

    class _BadNorm:
        id = "bad_norm_attack"
        norms = frozenset({"l7"})

        def info(self) -> AttackInfo:
            return pgd_info.model_copy(update={"id": self.id})

        def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
            return {}

        def run(self, target: Any, x: np.ndarray, y: np.ndarray, params: dict[str, Any], seed: int) -> AttackOutput:
            raise AssertionError("never runs")

    with pytest.raises(ValueError, match="unknown norm"):
        attack_norms(_BadNorm())
    with pytest.raises(ValueError, match="unknown norm"):
        register_attack(_BadNorm())
    assert "bad_norm_attack" not in ATTACKS


# --- HopSkipJump image defaults ---------------------------------------------------------------

def test_hopskipjump_image_defaults_are_bounded_measured_and_applied_only_when_omitted():
    """ATTACKS_HARDEN-04 / -22: image cost defaults inside the spec 12 bounds, explicit values win, both modalities."""
    hsj = get_attack("hopskipjump")
    assert hsj.domains == frozenset({"tabular", "image"})
    assert set(IMAGE_DEFAULTS) == {"max_iter", "max_eval", "init_eval", "init_size"}
    assert IMAGE_DEFAULTS["max_iter"] <= 50 and IMAGE_DEFAULTS["max_eval"] <= 5000
    assert IMAGE_DEFAULTS["init_eval"] <= IMAGE_DEFAULTS["max_eval"]
    assert attack_domain_defaults(hsj, "image") == IMAGE_DEFAULTS
    assert attack_domain_defaults(hsj, "tabular") == {} and attack_domain_defaults(hsj, None) == {}
    # the schema defaults stay the spec 12.2 tabular caps
    tab = hsj.resolve_params({})
    assert (tab["max_iter"], tab["max_eval"], tab["init_eval"], tab["init_size"]) == (20, 1000, 100, 100)
    img = hsj.resolve_params({}, domain="image")
    assert {k: img[k] for k in IMAGE_DEFAULTS} == IMAGE_DEFAULTS
    assert img["norm_l2"] is False and img["batch_size"] == 64
    # an explicit key is never overridden; the rest of the image block still applies
    mixed = apply_domain_defaults(hsj, "image", {"max_eval": 300})
    assert mixed["max_eval"] == 300 and mixed["init_eval"] == IMAGE_DEFAULTS["init_eval"]
    resolved = hsj.resolve_params({"max_eval": 300}, domain="image")
    assert resolved["max_eval"] == 300 and resolved["max_iter"] == IMAGE_DEFAULTS["max_iter"]
    # bounds still hold through the domain path
    with pytest.raises(ValueError):
        hsj.resolve_params({"init_eval": 400}, domain="image")   # init_eval > image max_eval 250
    # the measurement record behind the defaults names the real target and never an accuracy
    assert MEASUREMENT["target"].startswith("vehicles_cnn") and MEASUREMENT["params"] == IMAGE_DEFAULTS
    assert "accuracy" not in {k for k in MEASUREMENT if k != "note"}
    for key in ("wall_time_s_total", "wall_time_s_per_sample", "predict_rows_per_sample"):
        assert key in MEASUREMENT        # present: either a measured float or None when not taken, never invented
        assert MEASUREMENT[key] is None or float(MEASUREMENT[key]) > 0
    assert "image" in hsj.info().description and "n_samples" in hsj.info().description


def test_hopskipjump_image_run_records_cost_params_and_queries(target, slice_):
    hsj = get_attack("hopskipjump")
    small = slice_.x[:4]
    p = hsj.resolve_params({"max_iter": 1, "max_eval": 100, "init_eval": 10, "init_size": 3}, domain="image")
    out = hsj.run(target, small, slice_.y[:4], p, seed=0)
    _assert_common_output(out, small)
    assert out.x_adv.min() >= 0.0 and out.x_adv.max() <= 1.0
    assert any(n_.startswith("cost parameters in effect: max_iter=1, max_eval=100, init_eval=10") for n_ in out.notes)
    assert MINIMAL_NORM_NOTE in out.notes and QUERIES_DENOMINATOR_NOTE in out.notes
    assert any(n_.startswith("queries_mean") for n_ in out.notes)


# --- Carlini-Wagner L2 and DeepFool on TinyTarget ---------------------------------------------

@pytest.mark.parametrize("attack_id,params", [("cw_l2", CW_TINY), ("deepfool", {})])
def test_minimal_norm_image_attacks_shape_range_determinism(target, slice_, attack_id, params):
    adapter = get_attack(attack_id)
    assert adapter.takes_eps is False and adapter.domains == frozenset({"image"})
    p = adapter.resolve_params(params)
    out = adapter.run(target, slice_.x, slice_.y, p, seed=0)
    _assert_common_output(out, slice_.x)
    assert "torch" in out.library_versions
    assert out.x_adv.min() >= 0.0 - TOL and out.x_adv.max() <= 1.0 + TOL
    assert out.queries_mean is None                                   # white-box: no query count
    assert "eps" not in out.params and set(out.params) == {s.name for s in adapter.info().params_schema}
    again = adapter.run(target, slice_.x, slice_.y, p, seed=0)
    np.testing.assert_array_equal(out.x_adv, again.x_adv)
    # on the brittle random net the minimal-norm search changes inputs and flips predictions
    l2 = per_sample_norm(slice_.x, out.x_adv, l2=True)
    assert (l2 > 0).any() and _flips(target, slice_.x, out.x_adv) > 0
    assert out.l2_norm_mean == pytest.approx(float(l2.mean()), rel=1e-5)
    # the notes state the L2 grid semantics and the achieved per-sample norm with k/n denominators
    joined = "\n".join(out.notes)
    assert MINIMAL_NORM_NOTE in out.notes and "pert = achieved L2" in joined
    assert f"default {list(DEFAULT_EPS_GRID_L2)}" in joined
    m = re.search(r"achieved L2 norm per sample: (\d+)/(\d+) samples changed", joined)
    assert m is not None and int(m.group(2)) == N and int(m.group(1)) == int((l2 > 0).sum())
    for e in DEFAULT_EPS_GRID_L2:
        k = int(((l2 > 0) & (l2 <= e + 1e-9)).sum())
        assert f"eps={e:g}: {k}/{N}" in joined
    assert "frozen features" not in joined                            # images declare none


def test_cw_l2_thresholding_against_the_l2_grid_matches_the_campaign_rule(target, slice_):
    """ATTACKS_HARDEN-06 inheritance: success at eps iff achieved L2 <= eps; over-budget samples revert."""
    cw = get_attack("cw_l2")
    out = cw.run(target, slice_.x, slice_.y, cw.resolve_params(CW_TINY), seed=0)
    norms = per_sample_norm(slice_.x, out.x_adv, l2=True)
    y_clean = target.predict_proba(slice_.x).argmax(1)
    for e in DEFAULT_EPS_GRID_L2:
        within = norms <= e + 1e-9
        x_e = np.where(within.reshape(-1, 1, 1, 1), out.x_adv, slice_.x)
        y_e = target.predict_proba(x_e).argmax(1)
        # a sample outside the budget is the clean input again and cannot count as flipped at this eps
        assert not ((~within) & (y_e != y_clean)).any()
        assert per_sample_norm(slice_.x, x_e, l2=True).max() <= e + 1e-6


def test_cw_l2_defaults_run_and_report_an_honest_miss_on_the_random_double(target, slice_):
    """The schema defaults (c=0.01, 5 x 10 steps) may find nothing on TinyNet; the record then says 0/n changed."""
    cw = get_attack("cw_l2")
    out = cw.run(target, slice_.x, slice_.y, cw.resolve_params({}), seed=0)
    _assert_common_output(out, slice_.x)
    l2 = per_sample_norm(slice_.x, out.x_adv, l2=True)
    k = int((l2 > 0).sum())
    assert f"achieved L2 norm per sample: {k}/{N} samples changed" in "\n".join(out.notes)
    if k == 0:
        np.testing.assert_array_equal(out.x_adv, slice_.x)
        assert out.l2_norm_mean == 0.0 and _flips(target, slice_.x, out.x_adv) == 0


def test_deepfool_records_effective_class_gradients_and_overshoot(target, slice_):
    df = get_attack("deepfool")
    out = df.run(target, slice_.x, slice_.y, df.resolve_params({"max_iter": 5, "nb_grads": 10}), seed=0)
    first = out.notes[0]
    assert "class gradients per step = 3 (min(nb_grads=10, n_classes=3))" in first
    assert "max_iter=5" in first and "overshoot epsilon=1e-06" in first
    assert "unbounded by design" in "\n".join(out.notes)


@pytest.mark.parametrize("attack_id", ["cw_l2", "deepfool"])
def test_minimal_norm_image_attacks_refuse_estimators_without_class_gradients(attack_id, tab_target, tab_slice):
    """A tree ensemble exposes no class gradients: AttackNotApplicable, to be recorded not_run, never faked."""
    adapter = get_attack(attack_id)
    assert not hasattr(tab_target.art_classifier(), "class_gradient")
    with pytest.raises(AttackNotApplicable, match="class gradients"):
        adapter.run(tab_target, tab_slice.x, tab_slice.y, adapter.resolve_params({}), seed=0)


@pytest.mark.parametrize("attack_id", ["cw_l2", "deepfool"])
def test_minimal_norm_image_attacks_never_call_predict_counting_or_eps(target, slice_, attack_id, monkeypatch):
    """White-box: gradients are used (spied), and no eps parameter exists to pass."""
    adapter = get_attack(attack_id)
    clf = target.art_classifier()
    original = clf.class_gradient
    calls = {"grad": 0}

    def spy(*args, **kwargs):
        calls["grad"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(clf, "class_gradient", spy, raising=True)
    adapter.run(target, slice_.x[:4], slice_.y[:4], adapter.resolve_params({"max_iter": 2}), seed=0)
    assert calls["grad"] > 0
    with pytest.raises(ValueError, match="unknown parameter"):
        adapter.resolve_params({"eps": 0.5})


# --- ZOO on TinyTabularTarget -----------------------------------------------------------------

def test_zoo_tabular_scaled_rounded_frozen_and_query_counted(tab_target, tab_slice):
    """ATTACKS_HARDEN-05: frozen feature_10/11 unchanged, values inside the declared ranges, queries counted,
    same seed identical rows, norms in scaled units."""
    zoo = get_attack("zoo")
    assert zoo.takes_eps is False and zoo.domains == frozenset({"tabular"})
    p = zoo.resolve_params({})
    out = zoo.run(tab_target, tab_slice.x, tab_slice.y, p, seed=0)
    _assert_common_output(out, tab_slice.x)
    assert "scikit-learn" in out.library_versions
    x = tab_slice.x
    mins, maxs = tab_target.feature_ranges()
    assert (out.x_adv >= mins - TOL).all() and (out.x_adv <= maxs + TOL).all()
    np.testing.assert_array_equal(out.x_adv[:, FROZEN_COLS], x[:, FROZEN_COLS])
    # the search moved perturbable features and flipped predictions on the real forest
    changed = np.abs(out.x_adv - x).max(1) > 0
    assert changed.any() and np.abs(out.x_adv[:, FREE_COLS] - x[:, FREE_COLS]).max() > 0
    n_flipped = _flips(tab_target, x, out.x_adv)
    assert n_flipped > 0 and out.queries_mean is not None and out.queries_mean > 0
    note = next(n_ for n_ in out.notes if n_.startswith("queries_mean = "))
    m = re.search(r"\((\d+) rows in (\d+) predict calls; (\d+)/(\d+) samples flipped", note)
    assert m is not None, note
    rows, calls, flipped, total = (int(g) for g in m.groups())
    assert total == N and flipped == n_flipped and out.queries_mean == pytest.approx(rows / flipped)
    assert f"{rows / N:.1f} rows per attacked sample" in note
    assert QUERIES_DENOMINATOR_NOTE in out.notes and MINIMAL_NORM_NOTE in out.notes
    # scaled-unit norms: ranges are [0, 1] on this double so scaled == raw
    d = np.abs(out.x_adv.astype(np.float64) - x)
    assert out.linf_norm_mean == pytest.approx(float(d.max(1).mean()), rel=1e-4)
    assert out.l2_norm_mean == pytest.approx(float(np.sqrt((d * d).sum(1)).mean()), rel=1e-4)
    joined = "\n".join(out.notes)
    assert "min-max-scaled feature space" in joined and "predict_proba" in joined
    assert "re-imposed after the attack (ZooAttack has no mask argument)" in joined
    assert "feature_10" in joined and "feature_11" in joined
    assert "nb_parallel=12 (requested 16, capped at 12 features)" in joined
    assert "batch_size=1" in joined and "score-based" in joined
    assert f"{NONDETERMINISM_PREFIX}ZOO random coordinate sampling (seed=0" in joined
    # untouched rows keep their exact clean values (no float noise from the scale / unscale round trip)
    np.testing.assert_array_equal(out.x_adv[~changed], x[~changed])
    # seeded: identical rows under the same seed
    again = zoo.run(tab_target, tab_slice.x, tab_slice.y, p, seed=0)
    np.testing.assert_array_equal(out.x_adv, again.x_adv)
    assert again.queries_mean == out.queries_mean


def test_zoo_uses_only_predict_proba_and_never_gradients(tab_target, tab_slice, monkeypatch):
    zoo = get_attack("zoo")
    clf = tab_target.art_classifier()
    assert not hasattr(clf, "loss_gradient")

    def art_predict_spy(*args, **kwargs):
        raise AssertionError("zoo goes through target.predict_proba, not the target's ART estimator")

    monkeypatch.setattr(clf, "predict", art_predict_spy, raising=True)
    calls = {"proba": 0}
    original = tab_target.predict_proba

    def proba_spy(x):
        calls["proba"] += 1
        return original(x)

    monkeypatch.setattr(tab_target, "predict_proba", proba_spy)
    out = zoo.run(tab_target, tab_slice.x[:4], tab_slice.y[:4], zoo.resolve_params({"max_iter": 2}), seed=0)
    assert calls["proba"] > 3                        # probe, attack queries, and the two measurement passes
    assert out.x_adv.shape == (4, len(TABULAR_FEATURE_NAMES))


def test_zoo_refuses_image_targets(target, slice_):
    with pytest.raises(AttackNotApplicable, match="tabular targets only"):
        get_attack("zoo").run(target, slice_.x, slice_.y, {}, seed=0)


def test_zoo_labels_only_target_is_not_applicable(tab_target, tab_slice):
    """Score-based needs probabilities: a labels-only predict_proba (one column) is refused, not faked."""

    class _LabelsOnly:
        id = "labels_only"

        def info(self):
            return tab_target.info()

        def manifest(self):
            return tab_target.manifest()

        def predict_proba(self, x):
            return np.asarray(tab_target.predict_proba(x)).argmax(1).reshape(-1, 1).astype(np.float32)

    with pytest.raises(AttackNotApplicable, match="needs class probabilities"):
        get_attack("zoo").run(_LabelsOnly(), tab_slice.x, tab_slice.y, {}, seed=0)


# --- resolve_params bounds ---------------------------------------------------------------------

@pytest.mark.parametrize("attack_id,expected_defaults", [
    ("cw_l2", {"confidence": 0.0, "learning_rate": 0.01, "binary_search_steps": 5, "max_iter": 10,
               "initial_const": 0.01, "max_halving": 5, "max_doubling": 5, "batch_size": 64}),
    ("deepfool", {"max_iter": 20, "epsilon": 1e-6, "nb_grads": 10, "batch_size": 64}),
    ("zoo", {"confidence": 0.0, "learning_rate": 0.1, "max_iter": 10, "binary_search_steps": 1,
             "initial_const": 1e-3, "abort_early": True, "nb_parallel": 16, "variable_h": 0.05}),
])
def test_resolve_params_defaults(attack_id, expected_defaults):
    adapter = get_attack(attack_id)
    p = adapter.resolve_params({})
    assert p == expected_defaults
    assert {s.name for s in adapter.info().params_schema} == set(expected_defaults)
    for spec in adapter.info().params_schema:
        if spec.type != "bool":
            assert spec.min is not None and spec.max is not None and spec.min <= spec.default <= spec.max
        assert spec.description


@pytest.mark.parametrize("attack_id,bad", [
    ("cw_l2", {"max_iter": 51}), ("cw_l2", {"max_iter": 0}), ("cw_l2", {"confidence": -1}),
    ("cw_l2", {"binary_search_steps": 11}), ("cw_l2", {"initial_const": 0.0}), ("cw_l2", {"learning_rate": 2.0}),
    ("cw_l2", {"eps": 0.5}), ("cw_l2", {"max_iter": 2.5}),
    ("deepfool", {"max_iter": 101}), ("deepfool", {"epsilon": -1e-3}), ("deepfool", {"epsilon": 0.5}),
    ("deepfool", {"nb_grads": 0}), ("deepfool", {"nb_grads": 11}), ("deepfool", {"bogus": 1}),
    ("zoo", {"max_iter": 51}), ("zoo", {"nb_parallel": 0}), ("zoo", {"nb_parallel": 129}),
    ("zoo", {"variable_h": 0.6}), ("zoo", {"variable_h": 0.0}), ("zoo", {"abort_early": "yes"}),
    ("zoo", {"binary_search_steps": 0}), ("zoo", {"batch_size": 1}), ("zoo", {"eps": 0.1}),
    ("hopskipjump", {"max_iter": 51}), ("hopskipjump", {"max_eval": 5001}),
])
def test_resolve_params_rejects_out_of_range(attack_id, bad):
    with pytest.raises(ValueError):
        get_attack(attack_id).resolve_params(bad)


# --- shared helpers ------------------------------------------------------------------------------

def test_queries_summary_and_achieved_norm_note_carry_denominators():
    mean, note = queries_summary(rows=300, calls=30, n=10, n_flipped=3)
    assert mean == pytest.approx(100.0)
    assert "queries_mean = 100.0 predict rows per flipped sample (300 rows in 30 predict calls; 3/10 samples flipped" in note
    assert "30.0 rows per attacked sample" in note
    none, note0 = queries_summary(rows=300, calls=30, n=10, n_flipped=0)
    assert none is None and "denominator 0: 0/10 samples flipped" in note0 and "300 predict rows in 30 predict calls" in note0
    x = np.zeros((4, 2), dtype=np.float32)
    x_adv = np.array([[0.0, 0.0], [0.0, 0.5], [0.0, 1.0], [0.0, 0.0]], dtype=np.float32)   # exact in float32
    note = achieved_norm_note(x, x_adv, l2=True, grid=(0.25, 0.5, 1.0))
    assert note.startswith("achieved L2 norm per sample: 2/4 samples changed")
    assert "min 0.5, median 0.75, max 1 over the changed samples" in note
    assert "eps=0.25: 0/4; eps=0.5: 1/4; eps=1: 2/4" in note
    assert achieved_norm_note(x, x, l2=False) == "achieved Linf norm per sample: 0/4 samples changed"
    assert DEFAULT_EPS_GRID_LINF == (0.01, 0.03, 0.1)   # the grids the notes refer to are unchanged


def test_attack_capabilities_of_every_registered_adapter_validate():
    for adapter in ATTACKS:
        tags = attack_capabilities(adapter)
        assert tags <= KNOWN_ATTACK_CAPABILITIES
        assert any(t.startswith("norm:") for t in tags) and any(t.startswith("modality:") for t in tags)
