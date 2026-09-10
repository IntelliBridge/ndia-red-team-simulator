"""Explain-stage output contract (master plan section 5, spec 13.3 and 13.5) and shared helpers.

Besides ``ExplainOutput`` this module holds the on-disk explanation cache of spec
13.10 (``ExplanationCache``), the artifact-name compatibility table for the
tabular per-sample files renamed to the spec 5.8 names, and the explainer
roster shared by every explainer and by the catalog route (spec 13.2, 17.2):
the four explainer families (``EXPLAINER_KINDS``), the per-modality roster
(``EXPLAINER_ROSTER``), the spec 13.2 background size for the KernelExplainer
(``KERNEL_BACKGROUND_ROWS``) and the query caps a black-box endpoint target is
explained under (``EXPLAIN_QUERY_CAPS``, ``explain_caps_for``,
``estimate_kernel_explain_rows``). It imports nothing heavy: the API process
may import it for the roster without pulling shap, torch or sklearn.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import numpy as np

from redsim.ml.schema import STANDING_LIMITATIONS, Observation

logger = logging.getLogger(__name__)

# The frozen wording of the SHAP limitation (first entry of ``schema.STANDING_LIMITATIONS``). Explainers
# state it in ``meta["limitations"]`` so a campaign that lists explainer limitations carries one sentence.
SHAP_LIMITATION: str = STANDING_LIMITATIONS[0]

# The reference-row fields of ``Measurement`` that the explain stage supplies (spec 13.5).
MEASUREMENT_FIELDS: tuple[str, ...] = (
    "expl_shift_mean", "expl_shift_n", "expl_shift_n_excluded", "expl_shift_noise_floor", "expl_shift_noise_floor_n",
)

# Spec 13.10: explanation results are cached by this tuple so two ``explain.run`` steps over the same
# inputs reuse identical clean attributions. ``background_size`` is an additive component (it changes the attributions
# of every sampled explainer); it only reduces hits, never widens them.
CACHE_KEY_FIELDS: tuple[str, ...] = (
    "model_sha256", "dataset_revision", "sample_index", "attack_id", "eps", "explainer", "nsamples", "seed",
    "background_size",
)
CACHE_DIR_ENV = "REDSIM_ML_EXPLAIN_CACHE"
CACHE_DIR_NAME = "explain_cache"
CACHE_FORMAT = 1

# Spec 5.8 names for the tabular per-sample files, and the names they replaced. ``artifact_path`` reads both.
FEATURE_DIFF_NAME = "feature_diff.json"
FORCE_PLOT_PREFIX = "shap_force_"
LEGACY_ARTIFACT_NAMES: dict[str, str] = {
    "top_features.json": FEATURE_DIFF_NAME,
    "shap_pair.png": f"{FORCE_PLOT_PREFIX}<i>.png",
}


def force_plot_name(sample_index: int) -> str:
    """``shap_force_<i>.png`` for an explained sample (spec 5.8 / 13.6)."""
    return f"{FORCE_PLOT_PREFIX}{int(sample_index):03d}.png"


def artifact_path(observation: Observation, name: str) -> str | None:
    """Look an artifact up by its current name or by a pre-rename name (``top_features.json``, ``shap_pair.png``).

    Returns the run-relative path recorded on the observation, or ``None`` when the observation carries no
    such artifact. Nothing is invented: the legacy names resolve only to files that exist under the new name.
    """
    direct = observation.artifacts.get(name)
    if direct is not None:
        return direct
    if name == "top_features.json":
        return observation.artifacts.get(FEATURE_DIFF_NAME)
    if name == "shap_pair.png":
        for key, path in observation.artifacts.items():
            if key.startswith(FORCE_PLOT_PREFIX) and key.endswith(".png"):
                return path
    return None


@dataclass
class ExplainOutput:
    """What an explainer hands back to the campaign.

    ``observations`` are per-sample evidence rows (spec 13.3 step 5). Each carries
    its own ``expl_shift`` and, for tabular targets, the feature identifiers ranked
    by |SHAP| (``top_features_clean`` / ``top_features_adv``, empty for images).

    The five scalar fields are the reference-row fields of ``Measurement`` (spec
    13.5). The campaign writes them onto the evasion measurement at the reference
    budget through ``measurement_fields()``. ``expl_shift_mean`` is the mean over
    the explained pairs whose shift is defined, ``expl_shift_n`` that count and
    ``expl_shift_n_excluded`` the pairs left out because an attribution norm was
    below the floor. ``expl_shift_noise_floor`` is the same statistic between the
    clean attributions and those of the benign-noise control at the same eps, and
    it is ``None`` (with ``expl_shift_noise_floor_n`` ``None``) when no control was
    explained.

    ``meta`` carries explainer provenance (name, shap version, nsamples, background
    size, wall time, nondeterminism notes, the explanation-cache outcome), derived
    summaries with their denominators and the run-relative paths of campaign-level
    artifacts. Nothing in ``meta`` is a claim.
    """

    observations: list[Observation]
    expl_shift_mean: float | None
    expl_shift_n: int = 0
    expl_shift_n_excluded: int = 0
    expl_shift_noise_floor: float | None = None
    expl_shift_noise_floor_n: int | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def measurement_fields(self) -> dict[str, Any]:
        """The reference-row ``Measurement`` fields as an update mapping for ``Measurement.model_copy``."""
        return {name: getattr(self, name) for name in MEASUREMENT_FIELDS}


# --------------------------------------------------------------------------- explainer roster, kinds, query caps

#: The four explainer families (spec 13.2, 13.8). Every explanation records the shap class that ran as
#: ``explainer`` and its family as ``explainer_kind``, so a reader never has to infer the family from a name.
ExplainerKind = Literal["kernel", "tree", "gradient", "partition"]
EXPLAINER_KINDS: tuple[str, ...] = ("kernel", "tree", "gradient", "partition")
EXPLAINER_KIND_BY_NAME: dict[str, str] = {
    "TreeExplainer": "tree",
    "KernelExplainer": "kernel",
    "GradientExplainer": "gradient",
    "DeepExplainer": "gradient",
    "PartitionExplainer": "partition",
}


def explainer_kind(name: str) -> str:
    """The family (``kernel | tree | gradient | partition``) of a shap explainer class name."""
    try:
        return EXPLAINER_KIND_BY_NAME[name]
    except KeyError:
        raise ValueError(f"unknown explainer {name!r}; known: {sorted(EXPLAINER_KIND_BY_NAME)}") from None


#: Spec 13.2 (Tabular non-tree, Black-box any): the KernelExplainer background is a seeded 100-row sample of
#: the evaluation slice, drawn outside the explained rows. The effective size is recorded whenever the slice
#: is smaller.
KERNEL_BACKGROUND_ROWS = 100

#: ``TargetInfo.metadata["access"]`` value a black-box endpoint target declares (register ENDPOINT-04).
ENDPOINT_ACCESS = "black-box-endpoint"


@dataclass(frozen=True)
class ExplainQueryCaps:
    """Query budget an explainer runs under when every model call is a remote request (ENDPOINT-14).

    ``background_rows`` caps the KernelExplainer background, ``nsamples`` the coalition samples per explained
    input (the PartitionExplainer's ``max_evals`` on the image path) and ``explain_k`` the flipped / unflipped
    rows explained. The caps bound the cost, they do not change what is recorded: the effective values and the
    requested ones both land in the explainer meta.
    """

    background_rows: int
    nsamples: int
    explain_k: int

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> ExplainQueryCaps:
        return cls(background_rows=int(m["background_rows"]), nsamples=int(m["nsamples"]),
                   explain_k=int(m["explain_k"]))

    def per_observation_rows(self, with_control: bool = True) -> int:
        """Worst-case predict rows for one explained observation (clean, adversarial and, if any, control)."""
        return (3 if with_control else 2) * (self.nsamples * self.background_rows + 1)

    def estimate_rows(self, k: int, with_control: bool = True) -> int:
        """Worst-case predict rows for a whole explain stage at these caps (``estimate_kernel_explain_rows``)."""
        return estimate_kernel_explain_rows(k=min(int(k), self.explain_k), background_rows=self.background_rows,
                                            nsamples=self.nsamples, with_control=with_control)

    def as_dict(self) -> dict[str, int]:
        return {"background_rows": self.background_rows, "nsamples": self.nsamples, "explain_k": self.explain_k}


#: The endpoint caps (register ENDPOINT-14): background <= 20 rows, nsamples <= 200, explain_k <= 8. The
#: endpoint track imports these for admission budgets; the explainers apply them when ``explain_caps_for``
#: recognises the target or when a caller passes ``query_caps`` explicitly.
EXPLAIN_QUERY_CAPS = ExplainQueryCaps(background_rows=20, nsamples=200, explain_k=8)


def estimate_kernel_explain_rows(*, k: int, background_rows: int, nsamples: int, with_control: bool = True) -> int:
    """Upper bound on the predict rows a KernelExplainer stage issues (ENDPOINT-08 explain estimate).

    shap evaluates at most ``nsamples`` coalitions against every background row per explained input, plus the
    input itself, and the background once for the null expectation. Up to ``2 * k`` rows are explained, each
    on two inputs (clean, adversarial) or three when a control is explained. The real count is measured by
    ``QueryCounter`` and recorded beside this bound; the bound is never reported as a measurement.
    """
    inputs = 3 if with_control else 2
    return 2 * int(k) * inputs * (int(nsamples) * int(background_rows) + 1) + int(background_rows)


def explain_caps_for(target: Any) -> ExplainQueryCaps | None:
    """``EXPLAIN_QUERY_CAPS`` when the target declares ``metadata["access"] == "black-box-endpoint"``, else None.

    Tolerant of any target: a failing or absent ``info()`` means no caps (the local paths are not budgeted).
    """
    info_fn = getattr(target, "info", None)
    if not callable(info_fn):
        return None
    try:
        info = info_fn()
    except Exception as exc:  # noqa: BLE001 -- caps are a bound on cost, never a reason to fail
        logger.debug("explain_caps_for: info() failed: %s", type(exc).__name__)
        return None
    metadata = getattr(info, "metadata", None)
    if not isinstance(metadata, Mapping):
        return None
    return EXPLAIN_QUERY_CAPS if metadata.get("access") == ENDPOINT_ACCESS else None


class QueryCounter:
    """Counts the calls and rows a sampled explainer sends through ``predict_proba`` (purpose ``explain``).

    The count is taken on the explainer side, so it is the same for a local model and for an endpoint
    transport; the endpoint broker keeps its own tally and the two are recorded side by side, never summed.
    """

    def __init__(self, fn: Callable[[np.ndarray], np.ndarray], purpose: str = "explain") -> None:
        self._fn = fn
        self.purpose = purpose
        self.calls = 0
        self.rows = 0

    def __call__(self, x: np.ndarray) -> np.ndarray:
        arr = np.asarray(x)
        self.calls += 1
        self.rows += int(arr.shape[0]) if arr.ndim >= 1 else 1
        return self._fn(arr)

    def as_dict(self) -> dict[str, Any]:
        return {"purpose": self.purpose, "calls": self.calls, "rows": self.rows,
                "counted_by": "explainer-side wrapper around target.predict_proba"}


#: Register ATTACKS_HARDEN-08, recorded and not built. KernelSHAP over image pixels treats every pixel as a
#: feature: the bundled input is 3 x 128 x 128 = 49,152 features and shap's default ``nsamples`` is
#: ``2 * M + 2048``, about 100,000 predict calls per explained sample, hours on CPU and impossible against a
#: rate-limited endpoint. ``shap_image`` takes the spec 13.2 black-box image path instead
#: (``PartitionExplainer`` with ``shap.maskers.Image``, ``explain_k`` capped at 8). A request for
#: ``KernelExplainer`` on an image target is refused by ``shap_image.explain`` (it is not one of its choices).
KERNEL_IMAGE_INFEASIBLE_NOTE = (
    "KernelExplainer is not offered for images: KernelSHAP over 3x128x128 = 49,152 pixel features needs about "
    "2 x M + 2048 (~100k) predict calls per explained sample, hours on CPU and impossible against a rate-limited "
    "endpoint. The black-box image explainer is shap.PartitionExplainer with shap.maskers.Image over "
    "predict_proba (explain_k capped at 8), whose masking attributions are recorded as a different quantity "
    "from gradient attributions."
)

#: The catalog roster (register ATTACKS_HARDEN-09, spec 17.2 ``GET /v1/ml/capabilities``): which shap
#: explainers each modality and access level gets. Pure data. ``k_cap_black_box`` mirrors
#: ``shap_image.PARTITION_K_CAP`` (asserted equal in the tests so the two cannot drift).
EXPLAINER_ROSTER: dict[str, dict[str, Any]] = {
    "image": {
        "white_box": ["GradientExplainer", "DeepExplainer"],
        "black_box": ["PartitionExplainer"],
        "k_cap_black_box": 8,
        "kernel_shap": "not built",
        "kernel_shap_reason": KERNEL_IMAGE_INFEASIBLE_NOTE,
    },
    "tabular": {
        "tree": ["TreeExplainer"],
        "non_tree_or_black_box": ["KernelExplainer"],
        "kernel_background_rows": KERNEL_BACKGROUND_ROWS,
    },
    "endpoint": {
        "image": ["PartitionExplainer"],
        "tabular": ["KernelExplainer"],
        "query_caps": EXPLAIN_QUERY_CAPS.as_dict(),
    },
    "kinds": {name: kind for name, kind in EXPLAINER_KIND_BY_NAME.items()},
}


# --------------------------------------------------------------------------- explanation cache (spec 13.10)

def array_digest(a: np.ndarray) -> str:
    """sha256 of one input array's float32 bytes; the guard that a cache entry belongs to *these* inputs."""
    return hashlib.sha256(np.ascontiguousarray(a, dtype=np.float32).tobytes()).hexdigest()


def resolve_cache_dir(sink: Any, cache_dir: str | Path | None) -> tuple[Path | None, str]:
    """Where the explanation cache lives, with the reason when it does not.

    Order: an explicit ``cache_dir``; ``REDSIM_ML_EXPLAIN_CACHE``; ``<sink.work_dir>/explain_cache`` (the
    sandbox child's per-job work dir); ``<sink.root>/explain_cache`` (``FilesystemSink``); else disabled.
    A worker that wants several ``explain.run`` steps to share entries passes the shared directory
    (``REDSIM_ML_WORK_DIR/explain_cache``) explicitly or through the environment variable.
    """
    if cache_dir is not None:
        return Path(cache_dir), "argument"
    env = os.environ.get(CACHE_DIR_ENV, "").strip()
    if env:
        return Path(env), CACHE_DIR_ENV
    work_dir = getattr(sink, "work_dir", None)
    if isinstance(work_dir, (str, Path)):
        return Path(work_dir) / CACHE_DIR_NAME, "sink.work_dir"
    root = getattr(sink, "root", None)
    if isinstance(root, (str, Path)):
        return Path(root) / CACHE_DIR_NAME, "sink.root"
    return None, "no cache directory: the sink exposes no work dir and none was configured"


class ExplanationCache:
    """Digest-keyed on-disk cache of per-sample attributions (spec 13.10).

    One entry per explained sample: ``<dir>/<kk>/<key>.npz`` (float32 arrays) beside ``<key>.json``. The key
    is the sha256 of the ``CACHE_KEY_FIELDS`` tuple. A stored entry also carries the sha256 of the clean,
    adversarial and control inputs it was computed on and the class indices it explained; ``lookup`` returns
    it only when all of those match the request, so attributions are never served for different inputs
    (that outcome is counted as ``stale``, not as a hit). Every failure inside the cache is a miss or a
    counted store error, never an exception for the caller: the cache is an optimisation, not evidence.

    ``enabled`` is false when the model digest is unknown (a different model with the same inputs would
    give different attributions and could not be told apart) or when no directory could be resolved; the
    reason is recorded in ``stats()`` so the run record says why nothing was reused.
    """

    def __init__(self, directory: Path | None, *, model_sha256: str | None, dataset_revision: str | None,
                 explainer: str, nsamples: int | None, seed: int, attack_id: str | None, eps: float | None,
                 background_size: int | None, source: str | None = None) -> None:
        self.directory = directory
        self.source = source   # how the directory was resolved, or why there is none (``resolve_cache_dir``)
        self.reason: str | None = None
        if directory is None:
            self.reason = source or "no cache directory"
        elif not model_sha256:
            self.reason = "model sha256 unknown; entries could not be bound to one model"
        self.enabled = self.reason is None
        self.base_key: dict[str, Any] = {
            "model_sha256": model_sha256, "dataset_revision": dataset_revision, "attack_id": attack_id,
            "eps": None if eps is None else float(eps), "explainer": explainer, "nsamples": nsamples,
            "seed": int(seed), "background_size": background_size,
        }
        self.hits = 0
        self.misses = 0
        self.stale = 0
        self.stored = 0
        self.store_errors = 0

    # -- keys -------------------------------------------------------------------------------------------

    def key(self, sample_index: int) -> str:
        fields = dict(self.base_key, sample_index=int(sample_index))
        blob = json.dumps({k: fields[k] for k in CACHE_KEY_FIELDS}, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _paths(self, key: str) -> tuple[Path, Path]:
        assert self.directory is not None
        folder = self.directory / key[:2]
        return folder / f"{key}.npz", folder / f"{key}.json"

    # -- lookup / store ---------------------------------------------------------------------------------

    def lookup(self, sample_index: int, *, digests: dict[str, str | None], class_index: int,
               adv_class_index: int, shapes: dict[str, tuple[int, ...]]) -> dict[str, Any] | None:
        """The stored entry for this sample when its inputs and classes match, else ``None``.

        ``digests`` maps ``clean`` / ``adv`` / ``control`` to the sha256 of the requested inputs (``None``
        when no control is requested). ``shapes`` gives the expected array shape per name.
        """
        if not self.enabled:
            return None
        npz_path, meta_path = self._paths(self.key(sample_index))
        if not (npz_path.exists() and meta_path.exists()):
            self.misses += 1
            return None
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if meta.get("format") != CACHE_FORMAT:
                self.misses += 1
                return None
            stored = meta.get("input_sha256", {})
            want_names = [nm for nm, d in digests.items() if d is not None]
            if any(stored.get(nm) != digests[nm] for nm in want_names):
                self.stale += 1
                return None
            if int(meta.get("class_index", -1)) != int(class_index) or \
                    int(meta.get("adv_class_index", -1)) != int(adv_class_index):
                self.stale += 1
                return None
            with np.load(npz_path) as z:
                arrays = {nm: np.asarray(z[nm], dtype=np.float32) for nm in z.files}
            for nm in want_names:
                if nm not in arrays or tuple(arrays[nm].shape) != tuple(shapes[nm]):
                    self.misses += 1
                    return None
            if class_index != adv_class_index and "adv_predclass" not in arrays:
                self.misses += 1
                return None
        except Exception as exc:  # noqa: BLE001 -- a corrupt entry is a miss, never a failure
            logger.debug("explanation cache entry unreadable: %s", type(exc).__name__)
            self.misses += 1
            return None
        self.hits += 1
        return {"arrays": arrays, "meta": meta}

    def store(self, sample_index: int, *, arrays: dict[str, np.ndarray], digests: dict[str, str | None],
              class_index: int, adv_class_index: int, extra: dict[str, Any] | None = None) -> bool:
        if not self.enabled:
            return False
        npz_path, meta_path = self._paths(self.key(sample_index))
        try:
            npz_path.parent.mkdir(parents=True, exist_ok=True)
            meta = {
                "format": CACHE_FORMAT, "key": dict(self.base_key, sample_index=int(sample_index)),
                "input_sha256": {nm: d for nm, d in digests.items() if d is not None},
                "class_index": int(class_index), "adv_class_index": int(adv_class_index),
                "arrays": sorted(arrays), "created_at": datetime.now(UTC).isoformat(),
                **(extra or {}),
            }
            payload: dict[str, Any] = {nm: np.asarray(a, dtype=np.float32) for nm, a in arrays.items()}
            fd, tmp = tempfile.mkstemp(dir=npz_path.parent, suffix=".tmp")
            with os.fdopen(fd, "wb") as fh:
                np.savez_compressed(fh, **payload)
            os.replace(tmp, npz_path)
            fd, tmp = tempfile.mkstemp(dir=npz_path.parent, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(meta, fh, indent=1)
            os.replace(tmp, meta_path)
        except Exception as exc:  # noqa: BLE001 -- a failed store is counted, never raised
            logger.debug("explanation cache store failed: %s", type(exc).__name__)
            self.store_errors += 1
            return False
        self.stored += 1
        return True

    def stats(self) -> dict[str, Any]:
        """The recorded outcome for ``meta["cache"]``: hits with their denominator, or the reason it was off."""
        n = self.hits + self.misses + self.stale
        return {
            "enabled": self.enabled, "dir": None if self.directory is None else str(self.directory),
            "source": self.source, "reason": self.reason, "key_fields": list(CACHE_KEY_FIELDS),
            "explainer_key": self.base_key["explainer"],
            "hits": self.hits, "misses": self.misses, "stale": self.stale, "n": n,
            "stored": self.stored, "store_errors": self.store_errors,
        }
