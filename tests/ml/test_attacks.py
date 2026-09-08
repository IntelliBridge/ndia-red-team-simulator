"""Attack adapters on the TinyTarget double (spec section 22.3, ``ml`` tier).

Asserts: the eps ball is respected and values stay in [0, 1]; the same seed
reproduces FGSM / PGD; the benign control stays in the ball with no gradient call;
``resolve_params`` fills defaults and rejects out-of-range values; every output
carries ``art`` and ``torch`` versions and an ATLAS technique where one applies.
"""

from __future__ import annotations

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("art")

import numpy as np

from redsim.ml.attacks import ATTACKS, get_attack, list_attacks, resolve_from_schema
from redsim.ml.attacks.base import AttackAdapter, AttackOutput
from redsim.ml.schema import ParamSpec
from tests.ml.fakes import TinyTarget

pytestmark = pytest.mark.ml

N = 16
TOL = 1e-6


@pytest.fixture(scope="module")
def target() -> TinyTarget:
    return TinyTarget(seed=0)


@pytest.fixture(scope="module")
def slice_(target: TinyTarget):
    return target.sample(N, seed=0)


def _linf_per_sample(x: np.ndarray, x_adv: np.ndarray) -> np.ndarray:
    return np.abs(x_adv.astype(np.float64) - x.astype(np.float64)).reshape(x.shape[0], -1).max(axis=1)


# --- registry ------------------------------------------------------------------------------

def test_registry_lists_phase_a_adapters():
    assert ATTACKS.ids() == ["fgsm", "hopskipjump", "noise_control", "pgd"]
    for adapter in ATTACKS:
        assert isinstance(adapter, AttackAdapter)
    infos = {i.id: i for i in list_attacks()}
    assert infos["fgsm"].family == "evasion"
    assert infos["pgd"].family == "evasion"
    assert infos["hopskipjump"].family == "evasion"
    assert infos["noise_control"].family == "control"


def test_atlas_technique_tags():
    infos = {i.id: i for i in list_attacks()}
    for aid in ("fgsm", "pgd"):
        assert infos[aid].atlas_technique_id == "AML.T0043"
        assert infos[aid].atlas_technique_name == "Craft Adversarial Data"
    assert infos["hopskipjump"].atlas_technique_id == "AML.T0040"
    assert infos["hopskipjump"].atlas_technique_name == "ML Model Inference API Access"
    # A control demonstrates no adversarial technique (spec 27.2) and never creates a Finding.
    assert infos["noise_control"].atlas_technique_id is None


# --- eps ball, range, determinism -------------------------------------------------------------

@pytest.mark.parametrize("attack_id,extra", [("fgsm", {}), ("pgd", {"max_iter": 5})])
@pytest.mark.parametrize("eps", [0.01, 0.03, 0.1])
def test_white_box_attacks_respect_eps_ball_and_range(target, slice_, attack_id, extra, eps):
    adapter = get_attack(attack_id)
    params = adapter.resolve_params({"eps": eps, **extra})
    out = adapter.run(target, slice_.x, slice_.y, params, seed=0)
    assert isinstance(out, AttackOutput)
    assert out.x_adv.shape == slice_.x.shape
    assert out.x_adv.dtype == np.float32
    assert _linf_per_sample(slice_.x, out.x_adv).max() <= eps + TOL
    assert out.x_adv.min() >= 0.0 - TOL and out.x_adv.max() <= 1.0 + TOL
    assert 0.0 <= out.linf_norm_mean <= eps + TOL
    assert out.l2_norm_mean >= 0.0
    assert out.params["eps"] == eps
    assert "art" in out.library_versions and "torch" in out.library_versions
    assert any(n.startswith("nondeterminism: ") for n in out.notes)


@pytest.mark.parametrize("attack_id,extra", [("fgsm", {}), ("pgd", {"max_iter": 5})])
def test_same_seed_gives_identical_output(target, slice_, attack_id, extra):
    adapter = get_attack(attack_id)
    params = adapter.resolve_params({"eps": 0.03, **extra})
    a = adapter.run(target, slice_.x, slice_.y, params, seed=7).x_adv
    b = adapter.run(target, slice_.x, slice_.y, params, seed=7).x_adv
    np.testing.assert_array_equal(a, b)


def test_fgsm_flips_at_least_one_prediction_on_brittle_model(target, slice_):
    out = get_attack("fgsm").run(target, slice_.x, slice_.y, {"eps": 0.03}, seed=0)
    y_clean = target.predict_proba(slice_.x).argmax(1)
    y_adv = target.predict_proba(out.x_adv).argmax(1)
    assert int(((y_clean == slice_.y) & (y_adv != slice_.y)).sum()) > 0


def test_pgd_eps_step_ratio_rule_and_l2_option(target, slice_):
    pgd = get_attack("pgd")
    p = pgd.resolve_params({"eps": 0.03})
    assert p["eps_step"] == pytest.approx(0.0075)
    assert p["max_iter"] == 10 and p["num_random_init"] == 0 and p["norm_l2"] is False
    p2 = pgd.resolve_params({"eps": 0.5, "norm_l2": True, "max_iter": 3})
    out = pgd.run(target, slice_.x, slice_.y, p2, seed=0)
    d = (out.x_adv.astype(np.float64) - slice_.x).reshape(N, -1)
    assert np.sqrt((d * d).sum(axis=1)).max() <= 0.5 + 1e-4
    assert "norm=L2" in out.notes[0]


def test_pgd_random_init_records_nondeterminism(target, slice_):
    pgd = get_attack("pgd")
    out = pgd.run(target, slice_.x, slice_.y, {"eps": 0.03, "max_iter": 2, "num_random_init": 1}, seed=0)
    assert any("PGD random start" in n for n in out.notes)


# --- resolve_params --------------------------------------------------------------------------

@pytest.mark.parametrize("attack_id", ["fgsm", "pgd", "noise_control"])
def test_resolve_params_fills_defaults_and_coerces(attack_id):
    adapter = get_attack(attack_id)
    p = adapter.resolve_params({"eps": 1})  # int-like eps coerces to float
    assert isinstance(p["eps"], float) and p["eps"] == 1.0
    for spec in adapter.info().params_schema:
        assert spec.name in p


@pytest.mark.parametrize("attack_id,bad", [
    ("fgsm", {"eps": 1.5}), ("fgsm", {"eps": 0.0}), ("fgsm", {"eps": -0.1}),
    ("pgd", {"eps": 0.03, "max_iter": 0}), ("pgd", {"eps": 0.03, "max_iter": 51}),
    ("pgd", {"eps": 0.03, "max_iter": 2.5}), ("pgd", {"eps": 0.03, "bogus": 1}),
    ("pgd", {"eps": float("nan")}), ("pgd", {"eps": 0.03, "norm_l2": "yes"}),
    ("hopskipjump", {"max_eval": 50}), ("hopskipjump", {"max_eval": 6000}),
    ("hopskipjump", {"max_eval": 100, "init_eval": 200}),
    ("noise_control", {"eps": 2.0}),
])
def test_resolve_params_rejects_out_of_range(attack_id, bad):
    with pytest.raises(ValueError):
        get_attack(attack_id).resolve_params(bad)


def test_resolve_from_schema_bool_and_int_rules():
    schema = [ParamSpec(name="flag", type="bool", default=False),
              ParamSpec(name="k", type="int", default=3, min=1, max=5)]
    assert resolve_from_schema(schema, {}) == {"flag": False, "k": 3}
    assert resolve_from_schema(schema, {"flag": 1, "k": 5.0}) == {"flag": True, "k": 5}
    with pytest.raises(ValueError):
        resolve_from_schema(schema, {"flag": 2})
    with pytest.raises(ValueError):
        resolve_from_schema(schema, {"k": True})


# --- noise control ---------------------------------------------------------------------------

@pytest.mark.parametrize("eps", [0.01, 0.03, 0.1])
def test_noise_control_stays_in_ball_and_is_gradient_free(target, slice_, eps, monkeypatch):
    control = get_attack("noise_control")
    clf = target.art_classifier()
    calls = {"grad": 0}

    def spy(*args, **kwargs):
        calls["grad"] += 1
        raise AssertionError("noise control must not call loss_gradient")

    monkeypatch.setattr(clf, "loss_gradient", spy, raising=True)
    out = control.run(target, slice_.x, slice_.y, {"eps": eps}, seed=0)
    assert calls["grad"] == 0
    assert out.x_adv.shape == slice_.x.shape
    assert _linf_per_sample(slice_.x, out.x_adv).max() <= eps + TOL
    assert out.x_adv.min() >= 0.0 and out.x_adv.max() <= 1.0
    assert out.linf_norm_mean <= eps + TOL
    assert control.info().family == "control"
    assert any("Uniform noise control drawn with numpy default_rng(seed)" in n for n in out.notes)


def test_noise_control_is_seeded_and_l2_option_respects_norm(target, slice_):
    control = get_attack("noise_control")
    a = control.run(target, slice_.x, slice_.y, {"eps": 0.03}, seed=3).x_adv
    b = control.run(target, slice_.x, slice_.y, {"eps": 0.03}, seed=3).x_adv
    c = control.run(target, slice_.x, slice_.y, {"eps": 0.03}, seed=4).x_adv
    np.testing.assert_array_equal(a, b)
    assert not np.array_equal(a, c)
    out = control.run(target, slice_.x, slice_.y, {"eps": 0.5, "norm_l2": True}, seed=0)
    d = (out.x_adv.astype(np.float64) - slice_.x).reshape(N, -1)
    assert np.sqrt((d * d).sum(axis=1)).max() <= 0.5 + 1e-4


# --- hopskipjump -----------------------------------------------------------------------------

def test_hopskipjump_runs_black_box_and_records_queries(target, slice_, monkeypatch):
    hsj = get_attack("hopskipjump")
    assert hsj.takes_eps is False
    clf = target.art_classifier()

    def spy(*args, **kwargs):
        raise AssertionError("hopskipjump must not use gradients")

    monkeypatch.setattr(clf, "loss_gradient", spy, raising=True)
    monkeypatch.setattr(clf, "class_gradient", spy, raising=True)
    small = slice_.x[:4]
    out = hsj.run(target, small, slice_.y[:4], {"max_iter": 1, "max_eval": 100, "init_eval": 10, "init_size": 3}, seed=0)
    assert out.x_adv.shape == small.shape and out.x_adv.dtype == np.float32
    assert out.x_adv.min() >= 0.0 and out.x_adv.max() <= 1.0
    assert any(n.startswith("queries_mean = ") for n in out.notes)
    assert any("HopSkipJump random initial adversarial point" in n for n in out.notes)
    assert "art" in out.library_versions
    # predict is restored after the run (the counting shadow is removed from the instance)
    assert "predict" not in vars(clf)
    assert hsj.resolve_params({})["max_eval"] == 1000 and hsj.resolve_params({})["max_iter"] == 20
