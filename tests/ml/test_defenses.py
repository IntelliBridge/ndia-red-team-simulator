"""ART preprocessing defenses keep the Target protocol and change the inputs (spec section 16.6)."""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("art")
sklearn = pytest.importorskip("sklearn")

import numpy as np
from art.defences.preprocessor import FeatureSqueezing, JpegCompression, SpatialSmoothing
from sklearn.ensemble import RandomForestClassifier

from redsim.ml import defenses
from redsim.ml.schema import ParamSpec, TargetInfo
from redsim.ml.targets.base import Sample, Target
from tests.ml.fakes import TinyTarget

pytestmark = pytest.mark.ml

ART_CLASSES = {"feature_squeezing": FeatureSqueezing, "spatial_smoothing": SpatialSmoothing,
               "jpeg_compression": JpegCompression}


class _TabularDouble:
    """Minimal tabular Target: a random forest on 6 features, 3 classes (no assets, no network)."""

    id = "tiny_tabular"

    def __init__(self) -> None:
        rng = np.random.default_rng(0)
        self._x = rng.random((90, 6), dtype=np.float32)
        self._y = rng.integers(0, 3, size=90)
        self._rf = RandomForestClassifier(n_estimators=5, random_state=0).fit(self._x, self._y)
        self._clf: Any = None

    def info(self) -> TargetInfo:
        return TargetInfo(id=self.id, name="tiny tabular double", domain="tabular", status="available")

    def load(self) -> None:
        return None

    def sample(self, n: int, seed: int) -> Sample:
        idx = np.random.default_rng(seed).permutation(90)[:n]
        return Sample(x=self._x[idx], y=self._y[idx], indices=idx, class_names=["a", "b", "c"])

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        return self._rf.predict_proba(np.asarray(x, dtype=np.float32)).astype(np.float32)

    def art_classifier(self) -> Any:
        if self._clf is None:
            from art.estimators.classification import SklearnClassifier
            self._clf = SklearnClassifier(model=self._rf, clip_values=(0.0, 1.0))
        return self._clf

    def torch_model(self) -> Any:
        return None

    def manifest(self) -> dict[str, Any]:
        return {"model": "RandomForest", "n_features": 6}


def test_list_defenses_catalog_shape() -> None:
    rows = defenses.list_defenses()
    assert [r["id"] for r in rows] == ["feature_squeezing", "spatial_smoothing", "jpeg_compression"]
    for r in rows:
        assert r["name"] and r["art_class"].startswith("art.defences.preprocessor.")
        assert all(isinstance(p, ParamSpec) for p in r["params_schema"]) and r["params_schema"]
        assert any("adaptive attacks" in ref for ref in r["references"])
        assert "image" in r["domains"]
    assert "tabular" in defenses.get_defense("feature_squeezing")["domains"]
    assert "tabular" not in defenses.get_defense("jpeg_compression")["domains"]


def test_resolve_params_defaults_and_bounds() -> None:
    assert defenses.resolve_defense_params("feature_squeezing", None) == {"bit_depth": 4}
    assert defenses.resolve_defense_params("spatial_smoothing", {"window_size": 5}) == {"window_size": 5}
    assert defenses.resolve_defense_params("jpeg_compression", {"quality": 75.0}) == {"quality": 75}
    for did, bad in [("feature_squeezing", {"bit_depth": 0}), ("feature_squeezing", {"bit_depth": 9}),
                     ("spatial_smoothing", {"window_size": 8}), ("jpeg_compression", {"quality": 0}),
                     ("jpeg_compression", {"quality": 2.5}), ("feature_squeezing", {"bits": 4}),
                     ("feature_squeezing", {"bit_depth": "4"}), ("feature_squeezing", {"bit_depth": True})]:
        with pytest.raises(ValueError):
            defenses.resolve_defense_params(did, bad)
    with pytest.raises(ValueError, match="unknown defense"):
        defenses.resolve_defense_params("adversarial_training", {})
    with pytest.raises(ValueError, match="unknown defense"):
        defenses.apply_defense(TinyTarget(), "distillation", {})


@pytest.mark.parametrize("defense_id,params", [("feature_squeezing", {"bit_depth": 2}),
                                               ("spatial_smoothing", {"window_size": 3}),
                                               ("jpeg_compression", {"quality": 30})])
def test_defended_image_target_keeps_protocol_and_changes_inputs(defense_id: str, params: dict[str, Any]) -> None:
    base = TinyTarget(seed=0)
    defended = defenses.apply_defense(base, defense_id, params)
    assert isinstance(defended, Target)
    assert defended.id == base.id
    info = defended.info()
    assert info.domain == "image" and info.metadata["defense"]["id"] == defense_id
    assert info.metadata["defense"]["params"] == params and info.name != base.info().name

    s = defended.sample(12, seed=3)
    assert np.array_equal(s.indices, base.sample(12, seed=3).indices)

    x = s.x
    xd = defended.defend(x)
    assert xd.shape == x.shape and xd.dtype == np.float32
    assert xd.min() >= 0.0 and xd.max() <= 1.0
    assert float(np.abs(xd - x).max()) > 1e-3            # the defense changed the inputs

    proba = defended.predict_proba(x)
    assert proba.shape == (12, 3) and np.allclose(proba.sum(axis=1), 1.0, atol=1e-5)
    assert np.allclose(proba, base.predict_proba(xd), atol=1e-6)   # same preprocessing as ART sees

    clf = defended.art_classifier()
    assert any(isinstance(d, ART_CLASSES[defense_id]) for d in clf.preprocessing_defences)
    assert np.array_equal(clf.predict(x).argmax(1), proba.argmax(1))
    assert clf.loss_gradient(x, np.eye(3, dtype=np.float32)[s.y]).shape == x.shape   # still white-box capable
    assert base.art_classifier().preprocessing_defences is None                        # the base is untouched
    assert defended.torch_model() is base.torch_model()
    assert defended.manifest()["defense"]["torch_model_defended"] is False
    assert defended.manifest()["defense"]["art_class"].endswith(ART_CLASSES[defense_id].__name__)


def test_feature_squeezing_quantises_to_bit_depth() -> None:
    defended = defenses.apply_defense(TinyTarget(), "feature_squeezing", {"bit_depth": 1})
    xd = defended.defend(np.random.default_rng(0).random((4, 3, 8, 8), dtype=np.float32))
    assert set(np.unique(xd).tolist()) <= {0.0, 1.0}


def test_image_only_defenses_reject_tabular_and_feature_squeezing_wraps_sklearn() -> None:
    tab = _TabularDouble()
    for did in ("spatial_smoothing", "jpeg_compression"):
        with pytest.raises(ValueError, match="applies to"):
            defenses.apply_defense(tab, did, {})
    defended = defenses.apply_defense(tab, "feature_squeezing", {"bit_depth": 2})
    assert isinstance(defended, Target)
    s = defended.sample(10, seed=0)
    xd = defended.defend(s.x)
    assert xd.shape == s.x.shape and float(np.abs(xd - s.x).max()) > 1e-3
    proba = defended.predict_proba(s.x)
    assert proba.shape == (10, 3) and np.allclose(proba.sum(axis=1), 1.0, atol=1e-5)
    assert np.allclose(proba, tab.predict_proba(xd))
    clf = defended.art_classifier()
    assert type(clf).__name__.startswith("Scikitlearn")
    assert any(isinstance(d, FeatureSqueezing) for d in clf.preprocessing_defences)
    assert clf.predict(s.x).shape == (10, 3)
    assert tab.art_classifier().preprocessing_defences is None
    assert defended.torch_model() is None


def test_stacking_two_numpy_defenses_on_a_torch_estimator_is_refused() -> None:
    inner = defenses.apply_defense(TinyTarget(), "feature_squeezing", {"bit_depth": 3})
    outer = defenses.apply_defense(inner, "spatial_smoothing", {"window_size": 3})
    assert outer.predict_proba(inner.sample(4, 0).x).shape == (4, 3)   # predict_proba composes fine
    with pytest.raises(ValueError, match="at most one"):
        outer.art_classifier()                                          # ART's torch estimator cannot chain them
