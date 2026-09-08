"""ART-backed attack adapters (spec section 12).

Importing this package registers the Phase A adapters into ``ATTACKS``
(``redsim.ml.attacks.registry``): ``fgsm``, ``pgd``, ``hopskipjump`` and the
benign ``noise_control``. The helpers below are shared by the adapter modules
and are defined BEFORE the registration imports at the bottom of this file so
the submodules can import them while the package is still initialising.

Nothing here imports torch or ART at module import time; the adapters import
them lazily inside ``run`` so listing the catalog stays cheap.
"""

from __future__ import annotations

import contextlib
import importlib
import math
from importlib.metadata import PackageNotFoundError, version
from typing import Any

import numpy as np

from redsim.ml.schema import AtlasTechnique, ParamSpec

# Canonical nondeterminism strings (spec 14.4). The worker folds AttackOutput.notes
# that start with NONDETERMINISM_PREFIX into Provenance.nondeterminism.
NONDETERMINISM_PREFIX = "nondeterminism: "
CPU_FLOAT32_NOTE = "CPU float32 reductions; results may differ across BLAS builds and thread counts"

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


# --- registration --------------------------------------------------------------------------
# Imported last so the adapter modules can use the helpers above.
from redsim.ml.attacks import fgsm, hopskipjump, noise_control, pgd  # noqa: E402  (late import: registration)
from redsim.ml.attacks.registry import (  # noqa: E402  (late import: registration)
    ATTACKS,
    get_attack,
    list_attacks,
)

for _adapter in (fgsm.ADAPTER, pgd.ADAPTER, hopskipjump.ADAPTER, noise_control.ADAPTER):
    if ATTACKS.maybe_get(_adapter.id) is None:
        ATTACKS.register(_adapter)
del _adapter

__all__ = [
    "ATLAS_TECHNIQUES",
    "ATLAS_VERSION",
    "ATTACKS",
    "CPU_FLOAT32_NOTE",
    "NONDETERMINISM_PREFIX",
    "apply_mask",
    "clip_range",
    "get_attack",
    "library_versions",
    "list_attacks",
    "perturbable_mask",
    "resolve_from_schema",
    "seed_all",
]
