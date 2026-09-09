"""Attack adapters on the TinyTarget double (spec section 22.3, ``ml`` tier).

Asserts: the eps ball is respected and values stay in [0, 1]; the same seed
reproduces FGSM / PGD; the benign control stays in the ball with no gradient call;
``resolve_params`` fills defaults and rejects out-of-range values; every output
carries ``art`` and ``torch`` versions; ``AttackInfo`` follows the frozen M0
contract (phase, access, requires_gradients, status, reason, no ATLAS field) and the
ATLAS mapping is kept aside for Phase B2 rather than stamped on records.

Tabular (spec 12.9, gap register G-ATK1..G-ATK5) on a seeded local double with a
declared surrogate (``TinyTabularTarget`` below, since ``tests/ml/fakes.py`` belongs to
the campaign-runner track): PGD attacks the surrogate and the rows are measured on the
real tree. eps is scaled per feature over the manifest ranges and integer features
are rounded. Frozen features are handed to ART as ``mask`` and never move.
``queries_mean`` is per flipped sample with the totals recorded. The registry carries
capability tags.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("art")

import numpy as np

from redsim.ml.attacks import (
    ATLAS_TECHNIQUES,
    ATLAS_VERSION,
    ATTACKS,
    KNOWN_ATTACK_CAPABILITIES,
    NONDETERMINISM_PREFIX,
    REGISTERED_IDS,
    SURROGATE_NONDETERMINISM_NOTE,
    SURROGATE_TRANSFER_NOTE_PREFIX,
    TabularScaling,
    attack_capabilities,
    attacks_with_capability,
    get_attack,
    list_attack_capabilities,
    list_attacks,
    register_attack,
    resolve_from_schema,
)
from redsim.ml.attacks.base import AttackAdapter, AttackOutput
from redsim.ml.attacks.hopskipjump import QUERIES_DENOMINATOR_NOTE
from redsim.ml.errors import AttackNotApplicable
from redsim.ml.schema import AtlasTechnique, AttackInfo, ParamSpec, TargetInfo
from redsim.ml.targets.base import Sample
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


# --- tabular double with a declared surrogate (spec 12.9, local to this module) -----------------

TAB_FEATURES: list[dict[str, Any]] = [
    {"name": "url_length", "dtype": "int", "min": 0.0, "max": 200.0, "perturbable": True},
    {"name": "digit_ratio", "dtype": "float", "min": 0.0, "max": 1.0, "perturbable": True},
    {"name": "count_dot", "dtype": "int", "min": 0.0, "max": 20.0, "perturbable": True},
    {"name": "shannon_entropy", "dtype": "float", "min": 0.0, "max": 6.0, "perturbable": True},
    {"name": "has_ip_host", "dtype": "bool", "min": 0.0, "max": 1.0, "perturbable": False},
    {"name": "is_https", "dtype": "bool", "min": 0.0, "max": 1.0, "perturbable": False},
]
TAB_NAMES = [f["name"] for f in TAB_FEATURES]
TAB_MINS = np.asarray([f["min"] for f in TAB_FEATURES], dtype=np.float64)
TAB_MAXS = np.asarray([f["max"] for f in TAB_FEATURES], dtype=np.float64)
TAB_RANGES = TAB_MAXS - TAB_MINS
TAB_INT_COLS = [i for i, f in enumerate(TAB_FEATURES) if f["dtype"] in {"int", "bool"}]
TAB_FROZEN_COLS = [i for i, f in enumerate(TAB_FEATURES) if not f["perturbable"]]
TAB_CLASSES = ["benign", "phishing", "malware"]
TAB_N = 8


class TinyTabularTarget:
    """Seeded RandomForest on a 6-feature synthetic table with a logistic-regression surrogate fitted, as
    the build does, on the forest's predicted labels. The forest's ART estimator has no gradients, the
    surrogate's does. ``declare_ranges=False`` drops min/max from the manifest (observed-range fallback)."""

    id = "tiny_tabular"

    def __init__(self, seed: int = 0, *, with_surrogate: bool = True, declare_ranges: bool = True) -> None:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression

        rng = np.random.default_rng(seed)
        n = 160
        cols = [rng.integers(0, 201, n), rng.random(n), rng.integers(0, 21, n), rng.random(n) * 6.0,
                rng.integers(0, 2, n), rng.integers(0, 2, n)]
        x = np.column_stack(cols).astype(np.float32)
        score = x[:, 0] / 200 + x[:, 1] + x[:, 2] / 20 + x[:, 3] / 6
        y = np.digitize(score, [1.6, 2.4]).astype(np.int64)
        self._x, self._y = x, y
        self._model = RandomForestClassifier(n_estimators=8, max_depth=4, random_state=seed).fit(x, y)
        pred = np.asarray(self._model.predict(x), dtype=np.int64)
        if len(np.unique(pred)) < len(TAB_CLASSES):  # keep the surrogate defined on every class
            pred = y
        self._surrogate = LogisticRegression(max_iter=2000).fit(x, pred) if with_surrogate else None
        self._agree = int((self._surrogate.predict(x) == pred).sum()) if with_surrogate else 0
        self._sur_sha = (hashlib.sha256(self._surrogate.coef_.tobytes()).hexdigest() if with_surrogate else None)
        self._declare_ranges = declare_ranges
        self._clf: Any = None
        self._sur_clf: Any = None

    def info(self) -> TargetInfo:
        return TargetInfo(id=self.id, name="Tiny tabular (test double)", domain="tabular", status="available",
                          metadata={"dataset": "synthetic", "gradients": self._surrogate is not None})

    def load(self) -> None:
        return None

    def sample(self, n: int, seed: int) -> Sample:
        return Sample(x=self._x[:n].copy(), y=self._y[:n].copy(), indices=np.arange(n), class_names=list(TAB_CLASSES))

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        p = np.asarray(self._model.predict_proba(np.asarray(x, dtype=np.float32)), dtype=np.float32)
        if p.shape[1] < len(TAB_CLASSES):
            full = np.zeros((p.shape[0], len(TAB_CLASSES)), dtype=np.float32)
            full[:, self._model.classes_] = p
            return full
        return p

    def _ranges(self) -> tuple[np.ndarray, np.ndarray] | None:
        if not self._declare_ranges:
            return None
        return TAB_MINS.astype(np.float32), TAB_MAXS.astype(np.float32)

    def art_classifier(self) -> Any:
        if self._clf is None:
            from art.estimators.classification import SklearnClassifier
            self._clf = SklearnClassifier(model=self._model, clip_values=self._ranges())
        return self._clf

    def surrogate_art_classifier(self) -> Any:
        if self._surrogate is None:
            return None
        if self._sur_clf is None:
            from art.estimators.classification import SklearnClassifier
            self._sur_clf = SklearnClassifier(model=self._surrogate, clip_values=self._ranges())
        return self._sur_clf

    def torch_model(self) -> Any:
        return None

    def manifest(self) -> dict[str, Any]:
        features = [dict(f) for f in TAB_FEATURES]
        if not self._declare_ranges:
            for f in features:
                f.pop("min"), f.pop("max")
        surrogate = None
        if self._surrogate is not None:
            surrogate = {"kind": "logistic_regression", "sha256": self._sur_sha,
                         "agreement_clean": {"n": int(self._x.shape[0]), "n_correct": self._agree,
                                             "accuracy": self._agree / self._x.shape[0]}}
        return {"dataset": "synthetic", "features": features, "feature_names": list(TAB_NAMES),
                "perturbable": [bool(f["perturbable"]) for f in TAB_FEATURES], "surrogate": surrogate}


@pytest.fixture(scope="module")
def tab_target() -> TinyTabularTarget:
    return TinyTabularTarget(seed=0)


@pytest.fixture(scope="module")
def tab_slice(tab_target: TinyTabularTarget) -> Sample:
    return tab_target.sample(TAB_N, seed=0)


def _assert_tabular_row_shape(x: np.ndarray, x_adv: np.ndarray, eps: float | None) -> None:
    """Integer features integral, every value inside the declared range, frozen features untouched and,
    when ``eps`` is given, every feature inside its own raw budget ``eps * range`` (+0.5 for rounding)."""
    assert x_adv.shape == x.shape and x_adv.dtype == np.float32
    assert np.array_equal(np.rint(x_adv[:, TAB_INT_COLS]), x_adv[:, TAB_INT_COLS])
    assert (x_adv >= TAB_MINS - 1e-6).all() and (x_adv <= TAB_MAXS + 1e-6).all()
    np.testing.assert_array_equal(x_adv[:, TAB_FROZEN_COLS], x[:, TAB_FROZEN_COLS])
    if eps is not None:
        d = np.abs(x_adv.astype(np.float64) - x.astype(np.float64))
        for j, f in enumerate(TAB_FEATURES):
            slack = 0.5 if f["dtype"] in {"int", "bool"} else 1e-4
            assert d[:, j].max() <= eps * TAB_RANGES[j] + slack, (f["name"], d[:, j].max())


# --- registry and the frozen AttackInfo ------------------------------------------------------

# The whole catalog the attacks package registers: Phase A (fgsm, pgd, hopskipjump, noise_control), the Phase B
# minimal-norm and score-based adapters (cw_l2, deepfool, zoo), the text attack and the detection pair.
ALL_IDS = ["cw_l2", "deepfool", "dpatch", "fgsm", "hopskipjump", "noise_control", "patch_noise_control", "pgd",
           "word_substitution", "zoo"]


def _ids(adapters):
    return [a.id for a in adapters]


def test_registry_lists_phase_a_adapters():
    ids = ATTACKS.ids()
    assert ids == sorted(ids) == ALL_IDS == list(REGISTERED_IDS)
    for adapter in ATTACKS:
        assert isinstance(adapter, AttackAdapter)
    infos = {i.id: i for i in list_attacks()}
    assert infos["fgsm"].family == "evasion"
    assert infos["pgd"].family == "evasion"
    assert infos["hopskipjump"].family == "evasion"
    assert infos["noise_control"].family == "control"


def test_attack_info_follows_the_frozen_contract():
    infos = {i.id: i for i in list_attacks()}
    expected = {"fgsm": ("white-box", True), "pgd": ("white-box", True),
                "hopskipjump": ("black-box", False), "noise_control": ("black-box", False)}
    for aid, (access, needs_grad) in expected.items():
        info = infos[aid]
        assert isinstance(info, AttackInfo)
        assert info.phase == "A" and info.status == "available" and info.reason is None
        assert info.access == access and info.requires_gradients is needs_grad
        assert info.params_schema and all(isinstance(p, ParamSpec) for p in info.params_schema)
        assert info.references
        assert AttackInfo.model_validate(info.model_dump(mode="json")) == info
    assert not {f for f in AttackInfo.model_fields if "atlas" in f}
    assert not any("atlas" in k for i in infos.values() for k in i.model_dump())


def test_atlas_mapping_is_kept_for_phase_b2_and_never_stamped_in_phase_a():
    # Every registered evasion adapter maps to one technique; no control does.
    assert set(ATLAS_TECHNIQUES) == {a.id for a in ATTACKS if a.info().family == "evasion"}
    assert not any(a.info().family == "control" for a in ATTACKS if a.id in ATLAS_TECHNIQUES)
    for aid in ("fgsm", "pgd"):
        t = ATLAS_TECHNIQUES[aid]
        assert isinstance(t, AtlasTechnique)
        assert t.id == "AML.T0043" and t.name == "Craft Adversarial Data" and t.atlas_version == ATLAS_VERSION
    assert ATLAS_TECHNIQUES["hopskipjump"].id == "AML.T0040"
    assert ATLAS_TECHNIQUES["hopskipjump"].name == "ML Model Inference API Access"
    # A control demonstrates no adversarial technique (spec 27.2) and never creates a Finding.
    assert "noise_control" not in ATLAS_TECHNIQUES


def test_registry_capability_tags():
    """G-ATK5: every adapter carries spec 12.1 capability tags drawn from a checked vocabulary."""
    caps = list_attack_capabilities()
    assert set(caps) == set(ATTACKS.ids()) == set(ALL_IDS)
    for aid, tags in caps.items():
        assert "adversarial_ml" in tags and "explainability" not in tags, aid
        assert set(tags) <= KNOWN_ATTACK_CAPABILITIES
        info = ATTACKS.get(aid).info()
        assert ("white_box" in tags) == (info.access == "white-box")
        assert ("black_box" in tags) == (info.access == "black-box")
        assert f"family:{info.family}" in tags
    assert {"white_box", "surrogate_transfer", "takes_eps", "family:evasion",
            "modality:image", "modality:tabular"} <= set(caps["pgd"])
    assert {"white_box", "takes_eps", "modality:image"} <= set(caps["fgsm"]) and "modality:tabular" not in caps["fgsm"]
    assert {"black_box", "query_counted", "minimal_norm", "modality:tabular", "modality:image"} <= set(caps["hopskipjump"])
    assert "takes_eps" not in caps["hopskipjump"]
    assert "family:control" in caps["noise_control"] and "family:evasion" not in caps["noise_control"]
    assert _ids(attacks_with_capability("black_box")) == ["hopskipjump", "noise_control", "patch_noise_control",
                                                          "word_substitution", "zoo"]
    assert _ids(attacks_with_capability("modality:tabular")) == ["hopskipjump", "noise_control", "pgd", "zoo"]
    assert _ids(attacks_with_capability("white_box")) == ["cw_l2", "deepfool", "dpatch", "fgsm", "pgd"]
    assert attacks_with_capability("explainability") == []
    with pytest.raises(ValueError, match="unknown capability tag"):
        attacks_with_capability("teleport")
    # An adapter whose declared tags leave the vocabulary is refused at registration, not registered anyway.
    pgd_info = get_attack("pgd").info()

    class _Bad:
        id = "bad_attack"
        capabilities = frozenset({"teleport"})

        def info(self) -> AttackInfo:
            return pgd_info.model_copy(update={"id": self.id})

        def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
            return {}

        def run(self, target: Any, x: np.ndarray, y: np.ndarray, params: dict[str, Any], seed: int) -> AttackOutput:
            raise AssertionError("never runs")

    with pytest.raises(ValueError, match="unknown capability tag"):
        register_attack(_Bad())
    assert "bad_attack" not in ATTACKS
    with pytest.raises(ValueError, match="unknown capability tag"):
        attack_capabilities(_Bad())


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
    assert out.queries_mean is None                      # white-box: no query count
    assert "art" in out.library_versions and "torch" in out.library_versions
    assert any(n.startswith("nondeterminism: ") for n in out.notes)
    # image targets have no frozen features and no surrogate: neither note appears
    assert not any("frozen features" in n or n.startswith(SURROGATE_TRANSFER_NOTE_PREFIX) for n in out.notes)


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

_QUERIES_RE = re.compile(r"\((\d+) rows in (\d+) predict calls; (\d+)/(\d+) samples flipped")
_NO_QUERIES_RE = re.compile(r"denominator 0: 0/(\d+) samples flipped.*?(\d+) predict rows in (\d+) predict calls")


def _check_queries_contract(target: Any, x: np.ndarray, out: AttackOutput) -> None:
    """G-ATK4: ``queries_mean`` = predict rows / samples flipped from the model's clean prediction, or
    ``None`` with the spent total recorded when nothing flipped. Both readings are in the notes."""
    assert QUERIES_DENOMINATOR_NOTE in out.notes
    y_clean = np.asarray(target.predict_proba(x)).argmax(1)
    y_adv = np.asarray(target.predict_proba(out.x_adv)).argmax(1)
    n_flipped = int((y_clean != y_adv).sum())
    n = int(x.shape[0])
    if out.queries_mean is not None:
        note = next(n_ for n_ in out.notes if n_.startswith("queries_mean = "))
        m = _QUERIES_RE.search(note)
        assert m is not None, note
        rows, calls, flipped, total = (int(g) for g in m.groups())
        assert rows > 0 and calls > 0 and total == n and flipped == n_flipped > 0
        assert out.queries_mean == pytest.approx(rows / flipped)
        assert f"{rows / n:.1f} rows per attacked sample" in note
    else:
        note = next(n_ for n_ in out.notes if n_.startswith("queries_mean not computed"))
        m = _NO_QUERIES_RE.search(note)
        assert m is not None, note
        assert int(m.group(1)) == n and n_flipped == 0 and int(m.group(2)) > 0


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
    _check_queries_contract(target, small, out)
    assert any("HopSkipJump random initial adversarial point" in n for n in out.notes)
    assert "art" in out.library_versions
    # predict is restored after the run (the counting shadow is removed from the instance)
    assert "predict" not in vars(clf)
    assert hsj.resolve_params({})["max_eval"] == 1000 and hsj.resolve_params({})["max_iter"] == 20


def test_hopskipjump_queries_mean_denominator_is_flipped_samples(tab_target, tab_slice):
    """G-ATK4 on the tabular double: the denominator is the flipped-sample count, both totals recorded."""
    hsj = get_attack("hopskipjump")
    out = hsj.run(tab_target, tab_slice.x, tab_slice.y,
                  {"max_iter": 1, "max_eval": 100, "init_eval": 10, "init_size": 5}, seed=0)
    _check_queries_contract(tab_target, tab_slice.x, out)
    _assert_tabular_row_shape(tab_slice.x, out.x_adv, eps=None)
    assert any("min-max-scaled feature space" in n for n in out.notes)
    assert 0.0 <= out.linf_norm_mean <= 1.0 + 0.5 / TAB_RANGES[TAB_INT_COLS].min()   # scaled units


# --- tabular: surrogate transfer, per-feature eps, rounding, frozen features (spec 12.9) ------------

def test_tabular_scaling_reads_the_manifest_and_ignores_images(tab_target, tab_slice, target, slice_):
    assert TabularScaling.from_target(target, slice_.x) is None
    s = TabularScaling.from_target(tab_target, tab_slice.x)
    assert s is not None and s.source == "manifest" and s.names == TAB_NAMES
    np.testing.assert_allclose(s.eps_per_feature(0.1), 0.1 * TAB_RANGES, rtol=1e-6)
    assert s.mask is not None and s.mask.tolist() == [1.0, 1.0, 1.0, 1.0, 0.0, 0.0]
    assert s.integer.tolist() == [True, False, True, False, True, True]
    np.testing.assert_allclose(s.unscale(s.scale(tab_slice.x)), tab_slice.x, atol=1e-4)
    assert (s.scale(tab_slice.x) >= -1e-6).all() and (s.scale(tab_slice.x) <= 1 + 1e-6).all()
    # observed-range fallback is stated, never silent
    s2 = TabularScaling.from_target(TinyTabularTarget(seed=0, declare_ranges=False), tab_slice.x)
    assert s2 is not None and s2.source == "observed"
    assert any("observed range of the evaluation slice" in n for n in s2.notes(frozen_method="x"))


def test_tabular_eps_per_feature_scaled_and_ints_rounded(tab_target, tab_slice):
    """G-ATK2: eps * (max - min) per feature, integer features rounded, norms in scaled units."""
    pgd = get_attack("pgd")
    eps = 0.1
    out = pgd.run(tab_target, tab_slice.x, tab_slice.y, pgd.resolve_params({"eps": eps, "max_iter": 5}), seed=0)
    _assert_tabular_row_shape(tab_slice.x, out.x_adv, eps=eps)
    d = np.abs(out.x_adv.astype(np.float64) - tab_slice.x)
    # url_length (range 200) got a raw budget of 20, far beyond an unscaled eps of 0.1. digit_ratio (range 1) did not
    assert d[:, 0].max() > 1.0 and d[:, 1].max() <= eps + 1e-4
    # scaled norms: inside the ball up to the rounding slack (0.5 raw units of the narrowest integer feature)
    slack = 0.5 / TAB_RANGES[TAB_INT_COLS].min()
    assert 0.0 < out.linf_norm_mean <= eps + slack + TOL
    scaled = (d / TAB_RANGES).max(axis=1)
    assert scaled.max() <= eps + slack + TOL
    assert out.params["eps"] == eps and out.params["eps_step"] == pytest.approx(eps * 0.25)
    joined = "\n".join(out.notes)
    assert "eps * (max - min)" in joined and "min-max-scaled units" in joined
    assert "rounded to the nearest integer" in joined and "url_length" in joined and "count_dot" in joined
    # same seed, same rows
    again = pgd.run(tab_target, tab_slice.x, tab_slice.y, pgd.resolve_params({"eps": eps, "max_iter": 5}), seed=0)
    np.testing.assert_array_equal(out.x_adv, again.x_adv)


def test_frozen_features_untouched(tab_target, tab_slice, monkeypatch):
    """G-ATK3: frozen features go to ART as ``mask`` (held on every step) and never move, in every adapter."""
    import art.attacks.evasion as evasion

    seen: dict[str, Any] = {}

    class SpyPGD(evasion.ProjectedGradientDescent):
        def generate(self, x, y=None, **kwargs):
            seen["pgd"] = kwargs.get("mask")
            return super().generate(x, y, **kwargs)

    class SpyHSJ(evasion.HopSkipJump):
        def generate(self, x, y=None, **kwargs):
            seen["hopskipjump"] = kwargs.get("mask")
            return super().generate(x, y, **kwargs)

    monkeypatch.setattr(evasion, "ProjectedGradientDescent", SpyPGD)
    monkeypatch.setattr(evasion, "HopSkipJump", SpyHSJ)
    x, y = tab_slice.x, tab_slice.y
    expected_mask = [1.0, 1.0, 1.0, 1.0, 0.0, 0.0]

    out_pgd = get_attack("pgd").run(tab_target, x, y, {"eps": 0.1, "max_iter": 3}, seed=0)
    out_hsj = get_attack("hopskipjump").run(tab_target, x, y, {"max_iter": 1, "max_eval": 100, "init_eval": 10,
                                                              "init_size": 3}, seed=0)
    out_ctl = get_attack("noise_control").run(tab_target, x, y, {"eps": 0.1}, seed=0)
    out_ctl2 = get_attack("noise_control").run(tab_target, x, y, {"eps": 0.1, "norm_l2": True}, seed=0)
    for aid in ("pgd", "hopskipjump"):
        assert isinstance(seen[aid], np.ndarray) and seen[aid].tolist() == expected_mask, aid
    for out in (out_pgd, out_hsj, out_ctl, out_ctl2):
        np.testing.assert_array_equal(out.x_adv[:, TAB_FROZEN_COLS], x[:, TAB_FROZEN_COLS])
        note = next(n for n in out.notes if n.startswith("frozen features held at their clean values"))
        assert "has_ip_host" in note and "is_https" in note
    assert "ART mask" in next(n for n in out_pgd.notes if n.startswith("frozen features"))
    assert "ART mask" in next(n for n in out_hsj.notes if n.startswith("frozen features"))
    assert "perturbable features only" in next(n for n in out_ctl.notes if n.startswith("frozen features"))
    # the perturbable features did move
    assert np.abs(out_pgd.x_adv[:, :4] - x[:, :4]).max() > 0
    assert np.abs(out_ctl.x_adv[:, :4] - x[:, :4]).max() > 0


def test_pgd_uses_surrogate_on_tabular_double(tab_target, tab_slice, monkeypatch):
    """G-ATK1: gradients come from the declared surrogate, rows are measured on the real tree, provenance noted."""
    pgd = get_attack("pgd")
    real = tab_target.art_classifier()
    assert not hasattr(real, "loss_gradient")                     # the tree ensemble has no gradients
    sur = tab_target.surrogate_art_classifier()
    original = sur.loss_gradient
    calls = {"grad": 0, "real_predict": 0}

    def grad_spy(*args, **kwargs):
        calls["grad"] += 1
        return original(*args, **kwargs)

    def real_predict_spy(*args, **kwargs):
        calls["real_predict"] += 1
        raise AssertionError("the real model's ART estimator is not queried by the surrogate-transfer attack")

    monkeypatch.setattr(sur, "loss_gradient", grad_spy, raising=True)
    monkeypatch.setattr(real, "predict", real_predict_spy, raising=True)
    out = pgd.run(tab_target, tab_slice.x, tab_slice.y, {"eps": 0.1, "max_iter": 4}, seed=0)
    assert calls["grad"] > 0 and calls["real_predict"] == 0
    _assert_tabular_row_shape(tab_slice.x, out.x_adv, eps=0.1)
    m = tab_target.manifest()["surrogate"]
    note = next(n for n in out.notes if n.startswith(SURROGATE_TRANSFER_NOTE_PREFIX))
    assert "kind=logistic_regression" in note and f"sha256={m['sha256']}" in note
    k, n = m["agreement_clean"]["n_correct"], m["agreement_clean"]["n"]
    assert f"clean agreement with the target {k}/{n}" in note and "measured on the real model" in note
    assert f"{NONDETERMINISM_PREFIX}{SURROGATE_NONDETERMINISM_NOTE}" in out.notes
    # measurement stays on the real model: the returned rows feed the real tree's predict_proba unchanged
    proba = tab_target.predict_proba(out.x_adv)
    assert proba.shape == (TAB_N, len(TAB_CLASSES)) and np.allclose(proba.sum(1), 1.0, atol=1e-5)
    assert "scikit-learn" in out.library_versions


def test_pgd_refuses_tabular_without_surrogate_and_tabular_l2(tab_target, tab_slice):
    pgd = get_attack("pgd")
    bare = TinyTabularTarget(seed=0, with_surrogate=False)
    assert bare.surrogate_art_classifier() is None
    with pytest.raises(AttackNotApplicable, match="declares no build-time surrogate"):
        pgd.run(bare, tab_slice.x, tab_slice.y, {"eps": 0.1, "max_iter": 2}, seed=0)
    with pytest.raises(AttackNotApplicable, match="L-inf per-feature-scaled grid only"):
        pgd.run(tab_target, tab_slice.x, tab_slice.y, {"eps": 0.1, "max_iter": 2, "norm_l2": True}, seed=0)


def test_noise_control_tabular_is_scaled_rounded_and_seeded(tab_target, tab_slice):
    control = get_attack("noise_control")
    eps = 0.1
    a = control.run(tab_target, tab_slice.x, tab_slice.y, {"eps": eps}, seed=3)
    b = control.run(tab_target, tab_slice.x, tab_slice.y, {"eps": eps}, seed=3)
    np.testing.assert_array_equal(a.x_adv, b.x_adv)
    _assert_tabular_row_shape(tab_slice.x, a.x_adv, eps=eps)
    slack = 0.5 / TAB_RANGES[TAB_INT_COLS].min()
    assert 0.0 < a.linf_norm_mean <= eps + slack + TOL
    assert any("min-max-scaled feature space" in n for n in a.notes)
    l2 = control.run(tab_target, tab_slice.x, tab_slice.y, {"eps": 0.3, "norm_l2": True}, seed=0)
    _assert_tabular_row_shape(tab_slice.x, l2.x_adv, eps=None)
    d_scaled = (l2.x_adv.astype(np.float64) - tab_slice.x) / TAB_RANGES
    l2_slack = float(np.sqrt(((0.5 / TAB_RANGES[TAB_INT_COLS]) ** 2).sum()))
    assert np.sqrt((d_scaled * d_scaled).sum(axis=1)).max() <= 0.3 + l2_slack + 1e-4
