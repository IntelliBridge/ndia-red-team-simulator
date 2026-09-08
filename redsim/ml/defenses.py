"""ART preprocessing defenses for the verify-after-harden loop (spec section 16.6).

``apply_defense(target, defense, params)`` returns a wrapped ``Target`` whose
``art_classifier()`` carries the ART preprocessor (``FeatureSqueezing``,
``SpatialSmoothing``, ``JpegCompression``) and whose ``predict_proba`` applies the
same preprocessing, so attacks run through ART and measurements taken through
``predict_proba`` see one and the same defended model. ``defense`` is either a
catalog id with separate ``params`` or a ``schema.DefenseConfig`` (``id``,
``art_class``, ``params``), the shape ``CampaignConfig.defense`` carries; a config
whose ``art_class`` contradicts the catalog entry for its id is refused.

The wrapper is honest about what it does not do: ``torch_model()`` still returns
the undefended module (the preprocessors are numpy transforms with no torch
counterpart here), which the manifest records as ``torch_model_defended: False``
so SHAP evidence on a defended run is labelled accordingly. All three defenses
are input transformations; the rationale text for any recommendation that names
them must disclose the adaptive-attack bypass (Athalye, Carlini, Wagner 2018).
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

import numpy as np
from pydantic import ValidationError

from redsim.ml.schema import DefenseConfig, ParamSpec, TargetInfo
from redsim.ml.targets.base import Sample, Target

DefenseSpec = str | DefenseConfig | Mapping[str, Any]

_ADAPTIVE_BYPASS = ("Gradient-masking / input-transformation defenses are bypassed by adaptive attacks "
                    "(Athalye, Carlini, Wagner 2018, arXiv:1802.00420).")

DEFENSES: tuple[dict[str, Any], ...] = (
    {
        "id": "feature_squeezing",
        "name": "Feature squeezing (bit-depth reduction)",
        "art_class": "art.defences.preprocessor.FeatureSqueezing",
        "domains": ("image", "tabular"),
        "description": "Quantise inputs to `bit_depth` bits inside the estimator's clip range before prediction.",
        "params_schema": [ParamSpec(name="bit_depth", type="int", default=4, min=1, max=8,
                                    description="Bits kept per input value (8 = no squeezing).")],
        "references": ["Xu, Evans, Qi 2018, Feature Squeezing, NDSS (arXiv:1704.01155)", _ADAPTIVE_BYPASS],
    },
    {
        "id": "spatial_smoothing",
        "name": "Spatial smoothing (local median filter)",
        "art_class": "art.defences.preprocessor.SpatialSmoothing",
        "domains": ("image",),
        "description": "Median filter over a `window_size` x `window_size` neighbourhood, per channel.",
        "params_schema": [ParamSpec(name="window_size", type="int", default=3, min=1, max=7,
                                    description="Side of the median window in pixels (odd values are typical).")],
        "references": ["Xu, Evans, Qi 2018, Feature Squeezing, NDSS (arXiv:1704.01155)", _ADAPTIVE_BYPASS],
    },
    {
        "id": "jpeg_compression",
        "name": "JPEG compression",
        "art_class": "art.defences.preprocessor.JpegCompression",
        "domains": ("image",),
        "description": "Round-trip each image through JPEG at `quality` before prediction.",
        "params_schema": [ParamSpec(name="quality", type="int", default=50, min=1, max=100,
                                    description="JPEG quality factor (100 = least compression).")],
        "references": ["Dziugaite, Ghahramani, Roy 2016 (arXiv:1608.00853)", _ADAPTIVE_BYPASS],
    },
)


def list_defenses() -> list[dict[str, Any]]:
    """Catalog rows: ``id``, ``name``, ``params_schema`` (``ParamSpec`` list) plus description / domains / ART class."""
    return [{**d, "domains": list(d["domains"]), "params_schema": list(d["params_schema"])} for d in DEFENSES]


def get_defense(defense_id: str) -> dict[str, Any]:
    for d in DEFENSES:
        if d["id"] == defense_id:
            return d
    raise ValueError(f"unknown defense: {defense_id!r}; known: {[d['id'] for d in DEFENSES]}")


def resolve_defense_spec(defense: DefenseSpec, params: Mapping[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
    """``(defense_id, raw params)`` from a catalog id plus ``params``, or from a ``DefenseConfig`` / its mapping form.

    A config carries its own ``params``, so passing ``params`` alongside one is refused rather than merged.
    ``art_class`` on a config is checked against the catalog: an id that names a different ART class is a
    contradiction, never a silent override.
    """
    if isinstance(defense, str):
        return defense, dict(params or {})
    if isinstance(defense, DefenseConfig):
        cfg = defense
    elif isinstance(defense, Mapping):
        try:
            cfg = DefenseConfig.model_validate(dict(defense))
        except ValidationError as exc:
            raise ValueError(f"invalid defense config: {exc}") from exc
    else:
        raise TypeError(f"defense must be an id, a DefenseConfig or a mapping, not {type(defense).__name__}")
    if params:
        raise ValueError(f"defense {cfg.id!r}: pass parameters inside the DefenseConfig, not alongside it")
    spec = get_defense(cfg.id)
    if cfg.art_class is not None and cfg.art_class != spec["art_class"]:
        raise ValueError(f"defense {cfg.id!r} is {spec['art_class']}, not {cfg.art_class!r}")
    return cfg.id, dict(cfg.params)


def resolve_defense_params(defense_id: str, params: Mapping[str, Any] | None) -> dict[str, float | int | bool]:
    """Fill defaults, coerce types, reject unknown names and out-of-range values (``ValueError``)."""
    spec = get_defense(defense_id)
    schema = {p.name: p for p in spec["params_schema"]}
    given = dict(params or {})
    unknown = sorted(set(given) - set(schema))
    if unknown:
        raise ValueError(f"{defense_id}: unknown parameters {unknown}; accepted {sorted(schema)}")
    out: dict[str, float | int | bool] = {}
    for name, p in schema.items():
        raw = given.get(name, p.default)
        if p.type == "bool":
            if not isinstance(raw, (bool, int)):
                raise ValueError(f"{defense_id}.{name} must be a bool")
            out[name] = bool(raw)
            continue
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ValueError(f"{defense_id}.{name} must be a number")  # noqa: TRY004  (ValueError -> HTTP 422)
        value: float | int = int(raw) if p.type == "int" else float(raw)
        if p.type == "int" and float(raw) != float(value):
            raise ValueError(f"{defense_id}.{name} must be an integer, got {raw!r}")
        if p.min is not None and value < p.min:
            raise ValueError(f"{defense_id}.{name}={value} is below the minimum {p.min}")
        if p.max is not None and value > p.max:
            raise ValueError(f"{defense_id}.{name}={value} is above the maximum {p.max}")
        out[name] = value
    return out


def _dtype_preserving(cls: type) -> type:
    """Subclass an ART preprocessor so it returns the input dtype.

    ART stores ``clip_values`` as float64 and, under NumPy 2 promotion rules, ``x - clip_min`` turns a
    float32 batch into float64, which a float32 torch module then rejects. Casting back keeps the ART
    class (``isinstance`` still holds) and the [0, 1] contract intact.
    """
    class _Preserving(cls):
        def __call__(self, x: np.ndarray, y: Any = None) -> tuple[np.ndarray, Any]:
            x_arr = np.asarray(x)
            out, y_out = super().__call__(x_arr, y)
            dtype = x_arr.dtype if np.issubdtype(x_arr.dtype, np.floating) else np.float32
            return np.asarray(out, dtype=dtype), y_out

    _Preserving.__name__ = cls.__name__
    _Preserving.__qualname__ = cls.__qualname__
    _Preserving.__doc__ = f"dtype-preserving {cls.__name__} (redsim.ml.defenses)"
    return _Preserving


def build_preprocessor(defense_id: str, params: dict[str, Any] | None, *, clip_values: Any = (0.0, 1.0),
                       channels_first: bool = True) -> Any:
    """Instantiate the ART preprocessor for ``defense_id`` with resolved ``params``."""
    from art.defences.preprocessor import FeatureSqueezing, JpegCompression, SpatialSmoothing

    resolved = resolve_defense_params(defense_id, params)
    clip = clip_values if clip_values is not None else (0.0, 1.0)
    if defense_id == "feature_squeezing":
        return _dtype_preserving(FeatureSqueezing)(clip_values=clip, bit_depth=int(resolved["bit_depth"]),
                                                   apply_fit=False, apply_predict=True)
    if defense_id == "spatial_smoothing":
        return _dtype_preserving(SpatialSmoothing)(window_size=int(resolved["window_size"]),
                                                   channels_first=channels_first, clip_values=clip,
                                                   apply_fit=False, apply_predict=True)
    if defense_id == "jpeg_compression":
        return _dtype_preserving(JpegCompression)(clip_values=clip, quality=int(resolved["quality"]),
                                                  channels_first=channels_first, apply_fit=False,
                                                  apply_predict=True, verbose=False)
    raise ValueError(f"unknown defense: {defense_id!r}")  # pragma: no cover - get_defense already refused


def _with_defence(base_clf: Any, preprocessor: Any) -> Any:
    """A new ART estimator equal to ``base_clf`` plus ``preprocessor`` in ``preprocessing_defences``."""
    from art.estimators.classification import PyTorchClassifier

    existing = list(getattr(base_clf, "preprocessing_defences", None) or [])
    defences = existing + [preprocessor]
    if isinstance(base_clf, PyTorchClassifier):
        if len(defences) > 1:
            raise ValueError("ART's PyTorch estimator applies at most one numpy preprocessing defense; "
                             "stack defenses by re-running verify on the defended target instead")
        params = base_clf.get_params()
        params["preprocessing_defences"] = defences
        return type(base_clf)(**params)
    clf = copy.copy(base_clf)
    clf.set_params(preprocessing_defences=defences)
    return clf


class DefendedTarget:
    """``Target`` whose inputs pass through one ART preprocessing defense before the wrapped model."""

    def __init__(self, base: Target, defense: DefenseSpec, params: Mapping[str, Any] | None = None) -> None:
        defense_id, params = resolve_defense_spec(defense, params)
        spec = get_defense(defense_id)
        base_info = base.info()
        if base_info.domain not in spec["domains"]:
            raise ValueError(f"defense {defense_id!r} applies to {list(spec['domains'])} targets, not "
                             f"{base_info.domain!r}")
        self.base = base
        self.id = base.id
        self.defense_id = defense_id
        self.params = resolve_defense_params(defense_id, params)
        self._spec = spec
        self._domain = base_info.domain
        self._pre: Any = None
        self._clf: Any = None

    # -- defense plumbing ---------------------------------------------------------------

    def _clip_values(self) -> Any:
        clip = getattr(self.base.art_classifier(), "clip_values", None)
        return (0.0, 1.0) if clip is None else clip

    def preprocessor(self) -> Any:
        if self._pre is None:
            self._pre = build_preprocessor(self.defense_id, self.params, clip_values=self._clip_values(),
                                           channels_first=(self._domain == "image"))
        return self._pre

    def defend(self, x: np.ndarray) -> np.ndarray:
        """The defended inputs, as the wrapped model will see them."""
        out, _ = self.preprocessor()(np.asarray(x, dtype=np.float32))
        return np.asarray(out, dtype=np.float32)

    def defense_config(self) -> DefenseConfig:
        """The applied defense as the ``schema.DefenseConfig`` a verify campaign records (resolved params)."""
        return DefenseConfig(id=self.defense_id, art_class=self._spec["art_class"], params=dict(self.params))

    def describe(self) -> dict[str, Any]:
        """``defense_config()`` plus the catalog name, references and what the wrapper does not defend."""
        return {**self.defense_config().model_dump(mode="json"), "name": self._spec["name"],
                "references": list(self._spec["references"]), "torch_model_defended": False}

    # -- Target protocol -------------------------------------------------------------------

    def info(self) -> TargetInfo:
        info = self.base.info()
        return info.model_copy(update={
            "name": f"{info.name} + {self._spec['name']}",
            "metadata": {**info.metadata, "defense": self.describe()},
        })

    def load(self) -> None:
        self.base.load()

    def sample(self, n: int, seed: int) -> Sample:
        return self.base.sample(n, seed)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        return self.base.predict_proba(self.defend(x))

    def art_classifier(self) -> Any:
        if self._clf is None:
            self._clf = _with_defence(self.base.art_classifier(), self.preprocessor())
        return self._clf

    def torch_model(self) -> Any:
        """The undefended module (SHAP attributions on a defended run describe the model behind the defense)."""
        return self.base.torch_model()

    def manifest(self) -> dict[str, Any]:
        return {**self.base.manifest(), "defense": self.describe()}


def apply_defense(target: Target, defense: DefenseSpec, params: Mapping[str, Any] | None = None) -> Target:
    """Wrap ``target`` with an ART preprocessing defense.

    ``defense`` is a catalog id (with ``params``) or a ``schema.DefenseConfig`` / its ``{id, art_class, params}``
    mapping. ``ValueError`` on an unknown id, bad params, a contradicting ``art_class`` or the wrong domain.
    """
    return DefendedTarget(target, defense, params)


__all__ = ["DEFENSES", "DefendedTarget", "DefenseSpec", "apply_defense", "build_preprocessor", "get_defense",
           "list_defenses", "resolve_defense_params", "resolve_defense_spec"]
