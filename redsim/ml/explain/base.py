"""Explain-stage output contract (master plan section 5, spec 13.3 and 13.5) and shared helpers.

Besides ``ExplainOutput`` this module holds the on-disk explanation cache of spec
13.10 (``ExplanationCache``) and the artifact-name compatibility table for the
tabular per-sample files renamed to the spec 5.8 names. It imports nothing heavy.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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

# Spec 13.10: explanation results are cached by this tuple so ``explain.run`` and ``verify.replay`` reuse
# identical clean attributions. ``background_size`` is an additive component (it changes the attributions
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


# --------------------------------------------------------------------------- explanation cache (spec 13.10)

def array_digest(a: np.ndarray) -> str:
    """sha256 of one input array's float32 bytes; the guard that a cache entry belongs to *these* inputs."""
    return hashlib.sha256(np.ascontiguousarray(a, dtype=np.float32).tobytes()).hexdigest()


def resolve_cache_dir(sink: Any, cache_dir: str | Path | None) -> tuple[Path | None, str]:
    """Where the explanation cache lives, with the reason when it does not.

    Order: an explicit ``cache_dir``; ``REDSIM_ML_EXPLAIN_CACHE``; ``<sink.work_dir>/explain_cache`` (the
    sandbox child's per-job work dir); ``<sink.root>/explain_cache`` (``FilesystemSink``); else disabled.
    A worker that wants ``explain.run`` and ``verify.replay`` to share entries passes the shared directory
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
