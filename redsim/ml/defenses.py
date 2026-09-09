"""ART defenses for the verify-after-harden loop (spec section 16.6).

Two kinds of catalog row share one id space and one reference prefix
(:data:`REFERENCE_PREFIX`, ``defense:<id>``: the form ``recommend.rules`` writes into
a recommendation's references and the verify route reads back):

* ``kind: "preprocessing"`` (``feature_squeezing``, ``spatial_smoothing``,
  ``jpeg_compression``). ``apply_defense(target, defense, params)`` returns a wrapped
  ``Target`` whose ``art_classifier()`` carries the ART preprocessor and whose
  ``predict_proba`` applies the same preprocessing, so attacks run through ART and
  measurements taken through ``predict_proba`` see one and the same defended model.
  ``defense`` is either a catalog id with separate ``params`` or a
  ``schema.DefenseConfig`` (``id``, ``art_class``, ``params``), the shape
  ``CampaignConfig.defense`` carries; a config whose ``art_class`` contradicts the
  catalog entry for its id is refused. The wrapper is honest about what it does not
  do: ``torch_model()`` still returns the undefended module (the preprocessors are
  numpy transforms with no torch counterpart here), which the manifest records as
  ``torch_model_defended: False`` so SHAP evidence on a defended run is labelled
  accordingly. All three are input transformations; the rationale text for any
  recommendation that names them must disclose the adaptive-attack bypass (Athalye,
  Carlini, Wagner 2018).

* ``kind: "training"`` (``adversarial_training``, ``defensive_distillation``). These
  re-train a copy of a torch target's weights inside the sandbox child as the
  ``defense_apply`` stage of a verify run (``redsim.ml.harden.apply.apply_training_defense``)
  and yield a derived model with its own digest. They are catalog rows here so the API
  serves them and admission resolves their parameters, but :func:`apply_defense`
  refuses them: a training defense is not an input transformation and needs the
  training slice, the seed and the campaign's reference eps. Their ``domains`` are
  image only and they require a torch module: a tabular tree ensemble has no
  gradient-based adversarial training in ART (register item ATTACKS_HARDEN-20).

:data:`DEFENSES` stays the preprocessing tuple the Phase A verify admission treats as
runnable (``services.ml_campaigns._resolve_verify_defense``); :data:`TRAINING_DEFENSES`
holds the training rows and :data:`ALL_DEFENSES` both, which is what
:func:`list_defenses` and :func:`get_defense` see. Importing this module imports no
ML framework (``tests/test_review22_catalog_api_only.py``).
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any, Literal

import numpy as np
from pydantic import ValidationError

from redsim.ml.schema import DefenseConfig, ParamSpec, TargetInfo
from redsim.ml.targets.base import Sample, Target

DefenseSpec = str | DefenseConfig | Mapping[str, Any]
DefenseKind = Literal["preprocessing", "training"]
DEFENSE_KINDS: tuple[DefenseKind, ...] = ("preprocessing", "training")

# The one reference prefix a recommendation uses to cite a defense (spec 16.2, 16.4 (4)); the verify
# route dispatches on the catalog ``kind``, never on a second prefix.
REFERENCE_PREFIX = "defense:"

_ADAPTIVE_BYPASS = ("Gradient-masking / input-transformation defenses are bypassed by adaptive attacks "
                    "(Athalye, Carlini, Wagner 2018, arXiv:1802.00420).")
ADVERSARIAL_TRAINING_LIMIT = (
    "Known limit: adversarial fine-tuning yields robustness specific to the training threat model (norm, eps, "
    "inner attack) and to the bounded budget it ran with (n_train, epochs, wall clock); the measured delta MRI "
    "is an upper bound against the evaluated attacks only, and the derived model is a separate target, not the "
    "deployed model.")
DISTILLATION_BYPASS = (
    "Broken by the Carlini-Wagner attack (Carlini & Wagner 2017, arXiv:1608.04644); listed for completeness and "
    "ranked last. A verify run whose attack set has cw_l2 measures that bypass directly.")
DISTILLATION_IMPLEMENTATION = (
    "redsim.ml.harden.distillation (native torch: student initialised from the teacher, KL to "
    "softmax(teacher / T) scaled by T^2, evaluated at T = 1; Papernot et al. 2016)")
DISTILLATION_ART_NOTE = (
    "art.defences.transformer.evasion.DefensiveDistillation is cited as the reference implementation and is not "
    "called: it requires both classifiers to return probabilities (the bundled models return logits) and has no "
    "temperature parameter.")

# Shared bounded-budget parameters of the two training defenses (spec 3.3: sample models stay small; the
# verify child must finish under the sandbox wall clock, so the budget stops training early and records the
# epochs run rather than failing).
_TRAINING_BUDGET_PARAMS: tuple[ParamSpec, ...] = (
    ParamSpec(name="epochs", type="int", default=2, min=1, max=5,
              description="Fine-tuning epochs over the training slice (the wall budget may stop earlier)."),
    ParamSpec(name="train_n", type="int", default=1024, min=32, max=2000,
              description="Rows of the bundled training slice used (seeded, stratified; capped at the slice size)."),
    ParamSpec(name="batch_size", type="int", default=32, min=8, max=128,
              description="Training batch size."),
    ParamSpec(name="lr", type="float", default=1e-4, min=1e-5, max=1e-2,
              description="Adam learning rate over the trainable parameters."),
    ParamSpec(name="backbone_frozen", type="bool", default=True,
              description=("Train only the classification head (the last parametrised module) and keep every "
                           "other weight and normalisation statistic fixed; false trains every parameter.")),
    ParamSpec(name="wall_budget_s", type="int", default=300, min=1, max=600,
              description="Wall-clock budget in seconds; checked after every epoch, epochs run are recorded."),
)

DEFENSES: tuple[dict[str, Any], ...] = (
    {
        "id": "feature_squeezing",
        "kind": "preprocessing",
        "phase": "A",
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
        "kind": "preprocessing",
        "phase": "A",
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
        "kind": "preprocessing",
        "phase": "A",
        "name": "JPEG compression",
        "art_class": "art.defences.preprocessor.JpegCompression",
        "domains": ("image",),
        "description": "Round-trip each image through JPEG at `quality` before prediction.",
        "params_schema": [ParamSpec(name="quality", type="int", default=50, min=1, max=100,
                                    description="JPEG quality factor (100 = least compression).")],
        "references": ["Dziugaite, Ghahramani, Roy 2016 (arXiv:1608.00853)", _ADAPTIVE_BYPASS],
    },
)

TRAINING_DEFENSES: tuple[dict[str, Any], ...] = (
    {
        "id": "adversarial_training",
        "kind": "training",
        "phase": "B",
        "name": "Adversarial fine-tuning (PGD/FGSM-based)",
        "art_class": "art.defences.trainer.AdversarialTrainer",
        "art_class_role": "implementation",
        "implementation": "redsim.ml.harden.adversarial_training (ART AdversarialTrainer over a PyTorchClassifier)",
        "domains": ("image",),
        "requires": {"torch_module": True, "train_slice": True},
        "description": ("Fine-tune a copy of the model on a mix of clean and adversarial rows (ratio `ratio`) "
                        "crafted on the fly by PGD (`pgd_iters` steps) or FGSM (`pgd_iters` = 0) at `eps` in the "
                        "campaign norm; the derived weights are a new model with their own digest."),
        "params_schema": [
            ParamSpec(name="eps", type="float", default=0.0, min=0.0, max=1.0,
                      description=("Training perturbation budget in the campaign norm; 0 (default) = the "
                                   "campaign's reference eps (spec 16.6).")),
            ParamSpec(name="pgd_iters", type="int", default=3, min=0, max=7,
                      description="Inner PGD steps per batch; 0 = single-step FGSM."),
            ParamSpec(name="eps_step_ratio", type="float", default=0.25, min=0.01, max=1.0,
                      description="PGD step size as a fraction of eps (eps_step = eps_step_ratio * eps)."),
            ParamSpec(name="ratio", type="float", default=0.5, min=0.1, max=1.0,
                      description="Fraction of each batch replaced by adversarial rows (1.0 = all)."),
            *_TRAINING_BUDGET_PARAMS,
        ],
        "references": ["Madry, Makelov, Schmidt, Tsipras, Vladu 2018, Towards Deep Learning Models Resistant to "
                       "Adversarial Attacks (arXiv:1706.06083)",
                       "Goodfellow, Shlens, Szegedy 2015, Explaining and Harnessing Adversarial Examples "
                       "(arXiv:1412.6572)",
                       ADVERSARIAL_TRAINING_LIMIT],
    },
    {
        "id": "defensive_distillation",
        "kind": "training",
        "phase": "B",
        "name": "Defensive distillation (temperature-softened student)",
        "art_class": "art.defences.transformer.evasion.DefensiveDistillation",
        "art_class_role": "reference",
        "implementation": DISTILLATION_IMPLEMENTATION,
        "domains": ("image",),
        "requires": {"torch_module": True, "train_slice": True},
        "description": ("Train a student of the same architecture, initialised from the teacher, on the teacher's "
                        "probabilities softened at `temperature`; the student is used at temperature 1."),
        "params_schema": [
            ParamSpec(name="temperature", type="float", default=20.0, min=1.0, max=40.0,
                      description="Softmax temperature T for the teacher's soft labels and the student's loss."),
            *_TRAINING_BUDGET_PARAMS,
        ],
        "references": ["Papernot, McDaniel, Wu, Jha, Swami 2016, Distillation as a Defense to Adversarial "
                       "Perturbations against Deep Neural Networks (arXiv:1511.04508)",
                       DISTILLATION_BYPASS, DISTILLATION_ART_NOTE],
    },
)

ALL_DEFENSES: tuple[dict[str, Any], ...] = DEFENSES + TRAINING_DEFENSES


def _row_copy(d: dict[str, Any]) -> dict[str, Any]:
    out = {**d, "domains": list(d["domains"]), "params_schema": list(d["params_schema"]),
           "references": list(d["references"])}
    if "requires" in d:
        out["requires"] = dict(d["requires"])
    return out


def list_defenses() -> list[dict[str, Any]]:
    """Catalog rows (preprocessing then training): ``id``, ``kind``, ``name``, ``params_schema`` (``ParamSpec``
    list) plus description / domains / ART class; training rows add ``requires`` and ``implementation``."""
    return [_row_copy(d) for d in ALL_DEFENSES]


def get_defense(defense_id: str) -> dict[str, Any]:
    for d in ALL_DEFENSES:
        if d["id"] == defense_id:
            return d
    raise ValueError(f"unknown defense: {defense_id!r}; known: {[d['id'] for d in ALL_DEFENSES]}")


def defense_kind(defense_id: str) -> DefenseKind:
    kind = str(get_defense(defense_id)["kind"])
    if kind not in DEFENSE_KINDS:  # pragma: no cover - the catalog is a constant
        raise ValueError(f"defense {defense_id!r} has an unknown kind {kind!r}")
    return "training" if kind == "training" else "preprocessing"


def is_training_defense(defense_id: str) -> bool:
    """True for a ``kind: training`` row (applied by ``redsim.ml.harden.apply``, never by ``apply_defense``)."""
    return defense_kind(defense_id) == "training"


def training_defense_ids() -> list[str]:
    return [str(d["id"]) for d in TRAINING_DEFENSES]


def defense_reference(defense_id: str) -> str:
    """The ``defense:<id>`` reference a recommendation carries for a catalog defense (one prefix for both kinds)."""
    return f"{REFERENCE_PREFIX}{get_defense(defense_id)['id']}"


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
    """Fill defaults, coerce types, reject unknown names and out-of-range values (``ValueError``).

    Works for both kinds; a training row's ``eps`` of 0 means "the campaign reference eps" and is substituted
    by ``redsim.ml.harden.apply.resolve_training_params``, which knows that eps.
    """
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


def _training_refusal(defense_id: str, what: str) -> ValueError:
    return ValueError(
        f"defense {defense_id!r} is a training defense (kind 'training'): it derives a new model through "
        f"redsim.ml.harden.apply.apply_training_defense (the defense_apply stage of a verify run), not an input "
        f"preprocessor, so {what}")


def build_preprocessor(defense_id: str, params: dict[str, Any] | None, *, clip_values: Any = (0.0, 1.0),
                       channels_first: bool = True) -> Any:
    """Instantiate the ART preprocessor for ``defense_id`` with resolved ``params`` (preprocessing rows only)."""
    from art.defences.preprocessor import FeatureSqueezing, JpegCompression, SpatialSmoothing

    if is_training_defense(defense_id):
        raise _training_refusal(defense_id, "it has no ART preprocessor")
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
        if spec["kind"] != "preprocessing":
            raise _training_refusal(defense_id, "apply_defense cannot wrap a target with it")
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
        """``defense_config()`` plus the catalog kind, name, references and what the wrapper does not defend."""
        return {**self.defense_config().model_dump(mode="json"), "kind": self._spec["kind"],
                "name": self._spec["name"], "references": list(self._spec["references"]),
                "torch_model_defended": False}

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
    mapping. ``ValueError`` on an unknown id, bad params, a contradicting ``art_class``, the wrong domain, or a
    ``kind: training`` id (those go through ``redsim.ml.harden.apply.apply_training_defense``).
    """
    return DefendedTarget(target, defense, params)


__all__ = ["ALL_DEFENSES", "DEFENSES", "DEFENSE_KINDS", "REFERENCE_PREFIX", "TRAINING_DEFENSES", "DefendedTarget",
           "DefenseKind", "DefenseSpec", "apply_defense", "build_preprocessor", "defense_kind", "defense_reference",
           "get_defense", "is_training_defense", "list_defenses", "resolve_defense_params", "resolve_defense_spec",
           "training_defense_ids"]
