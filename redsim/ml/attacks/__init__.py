"""ART-backed attack adapters (spec section 12).

Importing this package registers the Phase A adapters into ``ATTACKS``
(``redsim.ml.attacks.registry``): ``fgsm``, ``pgd``, ``hopskipjump`` and the
benign ``noise_control``. The helpers below are shared by the adapter modules
and are defined BEFORE the registration imports at the bottom of this file so
the submodules can import them while the package is still initialising.

Tabular specifics (spec 12.9) live in one place, ``TabularScaling``: eps is a
fraction of each declared feature's training-split range, frozen features are
handed to ART as a ``mask`` so they are held on every step, integer-valued
features are rounded after the attack, and perturbation norms are reported in
min-max-scaled units. The adapters return ``x_adv`` in raw feature units so the
campaign measures the real model on exactly the rows it will store.

Nothing here imports torch or ART at module import time; the adapters import
them lazily inside ``run`` so listing the catalog stays cheap.

Third-party adapters (the ``redsim.ml.attacks`` entry-point group) are not
registered here: ``redsim.plugins.load_ml_attack_plugins`` does that behind the
``REDSIM_PLUGINS=1`` gate, and it is called by the offline CLI (``redsim ml
attack``), by the ``redsim.scanners`` import, and once per API process by
``GET /v1/attacks``, so :func:`list_attacks` reports whatever has joined
``ATTACKS`` by the time it runs.
"""

from __future__ import annotations

import contextlib
import importlib
import math
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from typing import Any

import numpy as np

from redsim.ml.eval import perturbation_norms
from redsim.ml.schema import AtlasTechnique, ParamSpec

# Canonical nondeterminism strings (spec 14.4). The worker folds AttackOutput.notes
# that start with NONDETERMINISM_PREFIX into Provenance.nondeterminism.
NONDETERMINISM_PREFIX = "nondeterminism: "
CPU_FLOAT32_NOTE = "CPU float32 reductions; results may differ across BLAS builds and thread counts"
# Spec 12.7 canonical string for the tabular white-box path.
SURROGATE_NONDETERMINISM_NOTE = "surrogate-transfer PGD: surrogate fitted at build time, seed recorded in manifest"
# Row-note prefix for the surrogate provenance (kind, sha256, clean agreement k/n) on tabular PGD rows.
SURROGATE_TRANSFER_NOTE_PREFIX = "white-box via surrogate transfer: "
# Manifest ``features[].dtype`` values whose adversarial values are rounded after the attack (spec 12.9).
INTEGER_DTYPES: frozenset[str] = frozenset({"int", "integer", "bool", "boolean"})

# MITRE ATLAS mapping (spec 27.2, 27.4), Phase B2. The registry is the one place the
# mapping lives; ``AttackInfo`` carries no ATLAS field and no Phase A record is stamped
# with a technique. B2 stamps ``MLFindingDetail.atlas_technique`` from this table when a
# Finding is created and pins the exact ATLAS release it re-verified the names against.
# The ids and names are the ones written in spec section 27.2; the version string marks
# the major release those names were read from, not a claim about a specific point
# release. A control demonstrates no adversarial technique and has no entry.
ATLAS_VERSION = "4.x"
ATLAS_TECHNIQUES: dict[str, AtlasTechnique] = {
    "fgsm": AtlasTechnique(id="AML.T0043", name="Craft Adversarial Data", atlas_version=ATLAS_VERSION),
    "pgd": AtlasTechnique(id="AML.T0043", name="Craft Adversarial Data", atlas_version=ATLAS_VERSION),
    "hopskipjump": AtlasTechnique(id="AML.T0040", name="ML Model Inference API Access",
                                  atlas_version=ATLAS_VERSION),
}


def _pkg_version(dist: str, module: str | None = None) -> str | None:
    try:
        return version(dist)
    except PackageNotFoundError:
        pass
    if module is not None:
        try:
            return str(getattr(importlib.import_module(module), "__version__", None))
        except Exception:  # noqa: BLE001 - optional dependency probing
            return None
    return None


def library_versions() -> dict[str, str]:
    """``art`` and ``numpy`` always; ``torch``, ``scikit-learn``, ``onnxruntime`` and ``xgboost``
    when installed (spec 12.5, 14.4)."""
    out: dict[str, str] = {}
    for key, dist, module in (("art", "adversarial-robustness-toolbox", "art"),
                              ("numpy", "numpy", "numpy"),
                              ("torch", "torch", "torch"),
                              ("scikit-learn", "scikit-learn", "sklearn"),
                              ("onnxruntime", "onnxruntime", "onnxruntime"),
                              ("xgboost", "xgboost", "xgboost")):
        v = _pkg_version(dist, module)
        if v is not None:
            out[key] = v
    return out


def seed_all(seed: int) -> None:
    """Seed numpy's global RNG (ART reads it) and torch (spec 12.7)."""
    np.random.seed(int(seed) % (2**32))
    try:
        import torch
    except Exception:  # noqa: BLE001 - torch is optional for tabular targets
        return
    torch.manual_seed(int(seed))


def resolve_from_schema(schema: list[ParamSpec], params: dict[str, Any] | None) -> dict[str, float | int | bool]:
    """Fill defaults, coerce types and reject unknown or out-of-range values (spec 12.1).

    ``ValueError`` is the contract: admission maps it to HTTP 422 and the worker calls
    this again before running so a stale client cannot widen a bound."""
    given = dict(params or {})
    known = {spec.name for spec in schema}
    unknown = sorted(set(given) - known)
    if unknown:
        raise ValueError(f"unknown parameter(s): {', '.join(unknown)}; accepted: {sorted(known)}")
    resolved: dict[str, float | int | bool] = {}
    for spec in schema:
        raw = given.get(spec.name, spec.default)
        if spec.type == "bool":
            if isinstance(raw, (bool, np.bool_)):
                value: float | int | bool = bool(raw)
            elif isinstance(raw, (int, float)) and raw in (0, 1):
                value = bool(raw)
            else:
                raise ValueError(f"parameter {spec.name!r} must be a bool, got {raw!r}")
        elif spec.type == "int":
            if isinstance(raw, bool) or not isinstance(raw, (int, float, np.integer, np.floating)):
                raise ValueError(f"parameter {spec.name!r} must be an int, got {raw!r}")
            if float(raw) != math.floor(float(raw)):
                raise ValueError(f"parameter {spec.name!r} must be an int, got {raw!r}")
            value = int(raw)
        else:  # float
            if isinstance(raw, bool) or not isinstance(raw, (int, float, np.integer, np.floating)):
                raise ValueError(f"parameter {spec.name!r} must be a number, got {raw!r}")
            value = float(raw)
            if not math.isfinite(value):
                raise ValueError(f"parameter {spec.name!r} must be finite, got {raw!r}")
        if spec.type != "bool":
            if spec.min is not None and value < spec.min:
                raise ValueError(f"parameter {spec.name!r}={value} below minimum {spec.min}")
            if spec.max is not None and value > spec.max:
                raise ValueError(f"parameter {spec.name!r}={value} above maximum {spec.max}")
        resolved[spec.name] = value
    return resolved


def clip_range(target: Any, x: np.ndarray) -> tuple[Any, Any]:
    """Valid input range for clipping: the ART estimator's ``clip_values`` when it has them,
    else ``[0, 1]`` for images and the observed per-feature range for tabular data."""
    try:
        clf = target.art_classifier()
        cv = getattr(clf, "clip_values", None)
    except Exception:  # noqa: BLE001 - estimator construction is the target's business
        cv = None
    if cv is not None:
        lo, hi = cv
        return np.asarray(lo, dtype=np.float32), np.asarray(hi, dtype=np.float32)
    domain = None
    with contextlib.suppress(Exception):  # info() is not load-bearing for clipping; fall back to [0, 1]
        domain = target.info().domain
    if domain == "tabular" and x.ndim == 2:
        return x.min(axis=0), x.max(axis=0)
    return np.float32(0.0), np.float32(1.0)


def perturbable_mask(target: Any, x: np.ndarray) -> np.ndarray | None:
    """Tabular only: a ``(n_features,)`` 0/1 mask from the manifest's ``features[].perturbable``
    flags (spec 12.9). ``None`` when every dimension may be perturbed (images, or no declaration)."""
    try:
        manifest = target.manifest() or {}
    except Exception:  # noqa: BLE001
        return None
    features = manifest.get("features")
    if not isinstance(features, list) or x.ndim != 2 or len(features) != x.shape[1]:
        return None
    if not all(isinstance(f, dict) and "perturbable" in f for f in features):
        return None
    mask = np.asarray([1.0 if f.get("perturbable") else 0.0 for f in features], dtype=np.float32)
    if mask.all():
        return None
    return mask


def apply_mask(x: np.ndarray, x_adv: np.ndarray, mask: np.ndarray | None) -> np.ndarray:
    """Re-impose frozen features after an attack step (spec 12.9)."""
    if mask is None:
        return x_adv
    return np.asarray(x_adv * mask + x * (1.0 - mask), dtype=x_adv.dtype)


def _manifest_rows(manifest: dict[str, Any], n_features: int) -> list[dict[str, Any]] | None:
    features = manifest.get("features")
    if not isinstance(features, list) or len(features) != n_features:
        return None
    if not all(isinstance(f, dict) for f in features):
        return None
    return [dict(f) for f in features]


@dataclass(frozen=True)
class TabularScaling:
    """Per-feature min-max scaling for tabular attacks (spec 12.9).

    - ``eps_per_feature(eps)`` is ``eps * (max_j - min_j)``: the L-inf budget in raw units for a
      budget ``eps`` declared as a fraction of each feature's range. Passing this array to an
      L-inf ART attack is the same as running the attack in scaled space (the L-inf projection
      is coordinate-wise), so the adapters stay in raw units and hand the real model raw rows.
    - ``mask`` holds the frozen features (``features[].perturbable`` false, plus constant
      features whose declared range is 0) on every ART step.
    - ``finish`` rounds integer-valued features (``INTEGER_DTYPES``), clips to the declared
      range and re-imposes frozen features. The post-rounding row is what the campaign measures.
    - ``norms`` reports L-inf / L2 in scaled units.

    ``source`` is ``"manifest"`` when every feature declares ``min``/``max`` (the training-split
    ranges the build wrote) and ``"observed"`` when the adapter had to fall back to the range of
    the evaluation slice. The fallback is stated in ``notes()`` rather than hidden.
    """

    mins: np.ndarray
    maxs: np.ndarray
    ranges: np.ndarray
    integer: np.ndarray
    perturbable: np.ndarray
    names: list[str]
    source: str

    @classmethod
    def from_target(cls, target: Any, x: np.ndarray) -> TabularScaling | None:
        """``None`` for anything but a 2-D slice of a tabular target."""
        try:
            domain = target.info().domain
        except Exception:  # noqa: BLE001 - a broken info() means no scaling, never a crash here
            return None
        if domain != "tabular" or x.ndim != 2 or x.shape[1] == 0:
            return None
        try:
            manifest = dict(target.manifest() or {})
        except Exception:  # noqa: BLE001
            manifest = {}
        d = int(x.shape[1])
        rows = _manifest_rows(manifest, d)
        names: list[str]
        if rows is not None:
            names = [str(f.get("name", f"f{i}")) for i, f in enumerate(rows)]
        else:
            declared = manifest.get("feature_names")
            names = ([str(n) for n in declared] if isinstance(declared, list) and len(declared) == d
                     else [f"f{i}" for i in range(d)])
        if rows is not None and all(f.get("min") is not None and f.get("max") is not None for f in rows):
            mins = np.asarray([float(f["min"]) for f in rows], dtype=np.float64)
            maxs = np.asarray([float(f["max"]) for f in rows], dtype=np.float64)
            source = "manifest"
        else:
            xf = np.asarray(x, dtype=np.float64)
            mins, maxs, source = xf.min(axis=0), xf.max(axis=0), "observed"
        if rows is not None:
            integer = np.asarray([str(f.get("dtype", "")).lower() in INTEGER_DTYPES for f in rows], dtype=bool)
            perturbable = np.asarray([bool(f.get("perturbable", True)) for f in rows], dtype=bool)
        else:
            integer = np.zeros(d, dtype=bool)
            flags = manifest.get("perturbable")
            perturbable = (np.asarray([bool(v) for v in flags], dtype=bool)
                           if isinstance(flags, list) and len(flags) == d else np.ones(d, dtype=bool))
        ranges = maxs - mins
        constant = ranges <= 0
        ranges = np.where(constant, 1.0, ranges)
        perturbable = perturbable & ~constant
        return cls(mins=mins, maxs=maxs, ranges=ranges, integer=integer, perturbable=perturbable,
                   names=names, source=source)

    # -- geometry -----------------------------------------------------------------------------

    @property
    def mask(self) -> np.ndarray | None:
        """ART ``mask`` (0/1 float32 per feature), ``None`` when every feature may move."""
        if self.perturbable.all():
            return None
        return self.perturbable.astype(np.float32)

    def eps_per_feature(self, eps: float) -> np.ndarray:
        """Raw-unit L-inf budget per feature: ``eps * (max - min)`` (float32)."""
        return (float(eps) * self.ranges).astype(np.float32)

    def scale(self, x: np.ndarray) -> np.ndarray:
        scaled = (np.asarray(x, dtype=np.float64) - self.mins) / self.ranges
        return np.asarray(scaled, dtype=np.float32)

    def unscale(self, xs: np.ndarray) -> np.ndarray:
        raw = np.asarray(xs, dtype=np.float64) * self.ranges + self.mins
        return np.asarray(raw, dtype=np.float32)

    def finish(self, x: np.ndarray, x_adv: np.ndarray) -> np.ndarray:
        """Round integer features, clip to the declared range and re-impose frozen features."""
        out = np.array(x_adv, dtype=np.float64, copy=True)
        if self.integer.any():
            out[:, self.integer] = np.rint(out[:, self.integer])
        out = np.clip(out, self.mins, self.maxs)
        keep = np.broadcast_to(self.perturbable, out.shape)
        return np.where(keep, out, np.asarray(x, dtype=np.float64)).astype(np.float32)

    def norms(self, x: np.ndarray, x_adv: np.ndarray) -> tuple[float, float]:
        """Mean per-sample L-inf and L2 of the perturbation in min-max-scaled units."""
        return perturbation_norms(self.scale(x), self.scale(x_adv))

    def rounding_slack(self, eps: float) -> float:
        """Largest scaled-unit overshoot of the eps ball that rounding an integer feature can cause."""
        rounded = self.integer & self.perturbable
        if not rounded.any():
            return 0.0
        return float((0.5 / self.ranges[rounded]).max())

    # -- notes --------------------------------------------------------------------------------

    def notes(self, *, frozen_method: str) -> list[str]:
        """Row notes stating how eps, rounding and frozen features were handled (spec 12.9)."""
        k, d = int(self.perturbable.sum()), int(self.perturbable.shape[0])
        out = [(f"tabular eps scaled per feature: eps * (max - min) over the {self.source} feature ranges "
                f"({k} perturbable of {d} features); linf_norm_mean / l2_norm_mean are in min-max-scaled units")]
        if self.source != "manifest":
            out.append("manifest declares no feature ranges; eps was scaled over the observed range of the evaluation "
                       "slice instead of the training-split ranges spec 12.9 expects")
        rounded = [n for n, i, p in zip(self.names, self.integer, self.perturbable, strict=True) if i and p]
        if rounded:
            out.append("integer-valued features rounded to the nearest integer after the attack; the post-rounding "
                       "prediction is what is measured and rounding can move a value up to 0.5 raw units past the "
                       f"eps ball: {', '.join(rounded)}")
        frozen = [n for n, p in zip(self.names, self.perturbable, strict=True) if not p]
        if frozen:
            out.append(f"frozen features held at their clean values via {frozen_method}: {', '.join(frozen)}")
        return out


def surrogate_estimator(target: Any) -> tuple[Any, str | None]:
    """``(estimator, provenance_note)`` for a target that declares a build-time PGD surrogate (spec 12.9).

    Looks for ``surrogate_art_classifier()`` on the target and, failing that, on a wrapped ``base``
    (a defended target proxies neither). Returns ``(None, None)`` when no surrogate is declared or
    the declared one exposes no ``loss_gradient``. The note carries kind, sha256 and the clean
    agreement ``k/n`` from ``manifest()["surrogate"]`` so the row states what was attacked.
    """
    fn = getattr(target, "surrogate_art_classifier", None)
    via_base = False
    if not callable(fn):
        fn = getattr(getattr(target, "base", None), "surrogate_art_classifier", None)
        via_base = callable(fn)
    if not callable(fn):
        return None, None
    est = fn()
    if est is None or not hasattr(est, "loss_gradient"):
        return None, None
    decl: dict[str, Any] = {}
    with contextlib.suppress(Exception):
        block = (target.manifest() or {}).get("surrogate")
        if isinstance(block, dict):
            decl = block
    kind = decl.get("kind", type(getattr(est, "model", est)).__name__)
    sha = decl.get("sha256")
    agreement = decl.get("agreement_clean")
    parts = [f"kind={kind}"]
    if sha:
        parts.append(f"sha256={sha}")
    if isinstance(agreement, dict) and agreement.get("n"):
        n = int(agreement["n"])
        k = agreement.get("n_correct")
        if k is None and agreement.get("value") is not None:
            k = int(round(float(agreement["value"]) * n))
        if k is None and agreement.get("accuracy") is not None:
            k = int(round(float(agreement["accuracy"]) * n))
        parts.append(f"clean agreement with the target {k}/{n}" if k is not None else f"clean agreement n={n}")
    else:
        parts.append("clean agreement with the target not recorded in the manifest")
    note = SURROGATE_TRANSFER_NOTE_PREFIX + "; ".join(parts) + (
        " (surrogate taken from the undefended base target; the defense is not in the gradient path)"
        if via_base else "") + "; every metric is measured on the real model"
    return est, note


# --- registration --------------------------------------------------------------------------
# Imported last so the adapter modules can use the helpers above.
from redsim.ml.attacks import fgsm, hopskipjump, noise_control, pgd  # noqa: E402  (late import: registration)
from redsim.ml.attacks.registry import (  # noqa: E402  (late import: registration)
    ATTACKS,
    KNOWN_ATTACK_CAPABILITIES,
    attack_capabilities,
    attacks_with_capability,
    get_attack,
    list_attack_capabilities,
    list_attacks,
    register_attack,
)

for _adapter in (fgsm.ADAPTER, pgd.ADAPTER, hopskipjump.ADAPTER, noise_control.ADAPTER):
    if ATTACKS.maybe_get(_adapter.id) is None:
        register_attack(_adapter)
del _adapter

__all__ = [
    "ATLAS_TECHNIQUES",
    "ATLAS_VERSION",
    "ATTACKS",
    "CPU_FLOAT32_NOTE",
    "INTEGER_DTYPES",
    "KNOWN_ATTACK_CAPABILITIES",
    "NONDETERMINISM_PREFIX",
    "SURROGATE_NONDETERMINISM_NOTE",
    "SURROGATE_TRANSFER_NOTE_PREFIX",
    "TabularScaling",
    "apply_mask",
    "attack_capabilities",
    "attacks_with_capability",
    "clip_range",
    "get_attack",
    "library_versions",
    "list_attack_capabilities",
    "list_attacks",
    "perturbable_mask",
    "register_attack",
    "resolve_from_schema",
    "seed_all",
    "surrogate_estimator",
]
