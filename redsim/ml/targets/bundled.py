"""Bundled image targets over ``assets/MANIFEST.json`` (spec sections 9.2, 11.5).

Asset layout, as written by ``redsim ml build-assets`` (``redsim.ml.assets.build`` /
``redsim.ml.assets.manifest``) and read here:

    <assets_dir>/MANIFEST.json
    {
      "schema_version": 1, "builder": "redsim ml build-assets", "built_at": ..., "library_versions": {...},
      "datasets": {
        "hf:leibnitz-lab/military_vehicles": {
          "id": "...", "revision": "<hub commit sha>", "class_names": [...], "license": "MIT",
          "splits": {"test_coarse": {"name": "test_coarse", "n": 1621,
                                     "file": {"path": "datasets/.../test_coarse.npz", "sha256": "...", "size_bytes": 1}},
                     "train_coarse": {...}}
        }
      },
      "models": {
        "vehicles_cnn": {                       # a schema.MLModelManifest plus the build record
          "id": "vehicles_cnn", "name": "...", "modality": "image", "format": "torch_state_dict",
          "sha256": "<weights sha256>", "size_bytes": 1,
          "file": {"path": "bundled/vehicles_cnn/weights.pt", "sha256": "<weights sha256>", "size_bytes": 1},
          "architecture_id": "small_cnn",
          "architecture": {"architecture_id": "small_cnn", "in_channels": 3, "n_classes": 7, "image_size": 128},
          "input_shape": [3, 128, 128], "n_classes": 7, "class_names": [...],
          "dataset_id": "hf:leibnitz-lab/military_vehicles", "dataset_revision": "<hub commit sha>",
          "dataset_split": "test_coarse", "clean_accuracy": {"value": 0.0, "n": 0, "split": "test_coarse"},
          "manifest_sha256": "...", "fixture_only": false, ...
        }
      }
    }

Weights come from ``models[id].file.path`` (digest ``file.sha256`` == ``sha256``), the constructor
kwargs from ``models[id].architecture``, and the evaluation slice from
``datasets[models[id].dataset_id].splits[models[id].dataset_split].file`` -- the same binding the
upload path resolves for ``dataset_id``. The pre-manifest flat shape (``weights`` / ``sha256`` /
``architecture_kwargs`` / ``eval_split`` / ``eval_split_sha256`` on the model entry, ``models`` as a
list of entries carrying an ``id``) is still read. Relative paths resolve against the manifest's
directory and may not escape it. Legacy ids (``url_classifier``) resolve to the id the registry
serves (``LEGACY_MODEL_IDS``).

Every ``load()`` verifies the manifest first: for a builder-shaped manifest
``redsim.ml.assets.manifest.verify_model_assets`` checks this model's weights (and surrogate)
digests, the entry's ``manifest_sha256`` and the bound evaluation split; a missing, tampered or
unbound split raises ``DatasetUnavailable`` (spec 9.5), a weights digest mismatch
``ArtifactDigestMismatch``. Only then is ``torch.load(weights_only=True)`` reached.

Registration at import touches no file: ``info()`` reads the manifest lazily and reports the target as
``not_implemented`` with a reason while the assets are absent, since ``TargetStatus`` has no third value.

``manifest()`` returns the ``schema.MLModelManifest`` fields (validated at load, so a malformed entry is
refused before anything runs) merged over the raw asset entry and the load-time provenance
(``weights_sha256_verified``, ``eval_n``, ``eval_per_class``, ``library_versions``).
"""

from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from pydantic import ValidationError

from redsim.ml.assets import LEGACY_MODEL_IDS
from redsim.ml.datasets import DatasetUnavailable
from redsim.ml.datasets.sampling import as_model_input, per_class_counts, stratified_sample
from redsim.ml.errors import ArtifactDigestMismatch, TargetUnavailable, UnsupportedArtifact
from redsim.ml.schema import TargetInfo
from redsim.ml.targets.artifact import (
    detect_format,
    library_versions,
    load_state_dict_module,
    model_manifest,
    sha256_file,
    verify_sha256,
)
from redsim.ml.targets.base import Sample
from redsim.ml.targets.registry import TARGETS

ASSETS_DIR_ENV = "REDSIM_ML_ASSETS_DIR"
DEFAULT_ASSETS_DIR = "./assets"
MANIFEST_NAME = "MANIFEST.json"
BUILD_HINT = "run `redsim ml build-assets` (assets branch) or point REDSIM_ML_ASSETS_DIR at a built asset tree"


def assets_dir(explicit: str | Path | None = None) -> Path:
    if explicit is not None:
        return Path(explicit).expanduser()
    return Path(os.environ.get(ASSETS_DIR_ENV, "").strip() or DEFAULT_ASSETS_DIR).expanduser()


def read_manifest(root: Path) -> dict[str, Any] | None:
    """Parse ``<root>/MANIFEST.json``; ``None`` when absent, ``UnsupportedArtifact`` when malformed."""
    path = root / MANIFEST_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UnsupportedArtifact(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise UnsupportedArtifact(f"{path} must hold a JSON object")
    return data


def _lookup_entry(models: Any, model_id: str) -> dict[str, Any] | None:
    if isinstance(models, dict):
        entry = models.get(model_id)
        return dict(entry) if isinstance(entry, dict) else None
    if isinstance(models, list):
        for entry in models:
            if isinstance(entry, dict) and entry.get("id") == model_id:
                return dict(entry)
    return None


def manifest_entry(manifest: dict[str, Any] | None, model_id: str) -> dict[str, Any] | None:
    """``models[model_id]`` (dict or list form), else the entry under a legacy id that now maps to ``model_id``."""
    if manifest is None:
        return None
    models = manifest.get("models")
    entry = _lookup_entry(models, model_id)
    if entry is not None:
        return entry
    for legacy, current in LEGACY_MODEL_IDS.items():
        if current == model_id:
            entry = _lookup_entry(models, legacy)
            if entry is not None:
                return entry
    return None


def resolve_asset_path(root: Path, rel: str) -> Path:
    """A manifest path resolved inside the asset tree (absolute paths and ``..`` escapes are refused)."""
    root_r = root.resolve()
    candidate = (root_r / rel).resolve()
    if candidate != root_r and root_r not in candidate.parents:
        raise UnsupportedArtifact(f"asset path escapes the asset tree: {rel!r}")
    return candidate


# --------------------------------------------------------------------------------------
# Reading the builder's ModelEntry shape (with the flat pre-manifest shape as fallback)
# --------------------------------------------------------------------------------------

def file_ref(block: Any) -> tuple[str | None, str | None]:
    """``(path, sha256)`` of a ``FileEntry`` block; ``(None, None)`` when it is not one."""
    if isinstance(block, dict) and isinstance(block.get("path"), str) and block["path"]:
        sha = block.get("sha256")
        return block["path"], (str(sha).lower() if isinstance(sha, str) and sha else None)
    return None, None


def weights_ref(entry: dict[str, Any]) -> tuple[str | None, str | None]:
    """Weights ``(relative path, expected sha256)``: ``entry.file`` (builder) or ``entry.weights`` (legacy).

    ``entry.sha256`` and ``entry.file.sha256`` must agree when both are present.
    """
    path, file_sha = file_ref(entry.get("file"))
    top = entry.get("sha256")
    top_sha = str(top).lower() if isinstance(top, str) and top else None
    if path is None:
        legacy = entry.get("weights")
        path = legacy if isinstance(legacy, str) and legacy else None
    if file_sha and top_sha and file_sha != top_sha:
        raise UnsupportedArtifact("manifest entry declares sha256 "
                                  f"{top_sha[:12]}... but its file block says {file_sha[:12]}...")
    return path, top_sha or file_sha


def architecture_kwargs(entry: dict[str, Any]) -> dict[str, Any]:
    """Constructor kwargs: ``entry.architecture`` (builder) or ``entry.architecture_kwargs`` (legacy)."""
    for key in ("architecture", "architecture_kwargs"):
        block = entry.get(key)
        if isinstance(block, dict):
            return dict(block)
    return {}


@dataclass(frozen=True)
class EvalSplitRef:
    """Where a model's evaluation slice lives and what the dataset entry says about it."""

    path: str                       # relative to the asset tree
    sha256: str | None
    split: str
    dataset: dict[str, Any] | None  # the ``datasets[dataset_id]`` entry when the manifest has one

    @property
    def class_names(self) -> list[str] | None:
        names = self.dataset.get("class_names") if self.dataset else None
        return [str(n) for n in names] if isinstance(names, list) and names else None

    @property
    def revision(self) -> str | None:
        rev = self.dataset.get("revision") if self.dataset else None
        return str(rev) if rev is not None else None


def dataset_entry(manifest: dict[str, Any] | None, dataset_id: Any) -> dict[str, Any] | None:
    if manifest is None or not isinstance(dataset_id, str):
        return None
    raw = manifest.get("datasets")
    if isinstance(raw, dict):
        block = raw.get(dataset_id)
        if isinstance(block, dict):
            return dict(block)
        for value in raw.values():
            if isinstance(value, dict) and value.get("id") == dataset_id:
                return dict(value)
    elif isinstance(raw, list):
        for value in raw:
            if isinstance(value, dict) and value.get("id") == dataset_id:
                return dict(value)
    return None


def resolve_eval_split(manifest: dict[str, Any] | None, entry: dict[str, Any], model_id: str) -> EvalSplitRef:
    """Bind the model to ``datasets[dataset_id].splits[dataset_split].file``, else the legacy ``eval_split``.

    Raises ``DatasetUnavailable`` when no evaluation slice is bound (spec 9.5: a run never guesses one).
    """
    dataset_id = entry.get("dataset_id")
    split_name = str(entry.get("dataset_split") or "test")
    dataset = dataset_entry(manifest, dataset_id)
    if dataset is not None:
        splits = dataset.get("splits")
        split_block: Any = None
        if isinstance(splits, dict):
            split_block = splits.get(split_name)
        elif isinstance(splits, list):
            split_block = next((s for s in splits if isinstance(s, dict) and s.get("name") == split_name), None)
        if isinstance(split_block, dict):
            path, sha = file_ref(split_block.get("file"))
            if path is not None:
                return EvalSplitRef(path=path, sha256=sha, split=split_name, dataset=dataset)
    legacy = entry.get("eval_split")
    if isinstance(legacy, str) and legacy:
        sha = entry.get("eval_split_sha256")
        return EvalSplitRef(path=legacy, sha256=str(sha).lower() if isinstance(sha, str) and sha else None,
                            split=split_name, dataset=dataset)
    where = (f"dataset {dataset_id!r} has no bundled split {split_name!r} in the manifest's datasets"
             if dataset is not None else f"dataset {dataset_id!r} is not in the manifest's datasets")
    raise DatasetUnavailable(f"model {model_id!r} is bound to no evaluation slice: {where}, and the entry carries "
                             f"no eval_split path; {BUILD_HINT}")


def verify_bundled_entry(manifest: dict[str, Any], root: Path, model_id: str) -> bool:
    """Run the asset-manifest verification for one model when the manifest has the builder shape.

    Returns ``True`` when the verification ran and passed (weights, surrogate and evaluation-split
    digests, and the entry's ``manifest_sha256``); ``False`` when the manifest is not a
    ``redsim.ml.assets.manifest.AssetManifest`` (the flat test shape), in which case the caller does its
    own per-file checks. Problems raise: a split problem ``DatasetUnavailable``, a weights digest
    mismatch ``ArtifactDigestMismatch``, a missing weights file ``TargetUnavailable``, anything else
    ``UnsupportedArtifact``.
    """
    from redsim.ml.assets.manifest import AssetManifest, model_entry, verify_model_assets

    try:
        parsed = AssetManifest.model_validate(manifest)
    except ValidationError:
        return False
    if model_entry(parsed, model_id) is None:
        return False
    problems = verify_model_assets(parsed, root, model_id)
    if problems.dataset:
        raise DatasetUnavailable("evaluation slice check failed: " + "; ".join(problems.dataset))
    for problem in problems.model:
        if "missing file" in problem:
            raise TargetUnavailable(f"{problem}; {BUILD_HINT}")
        if "sha256 mismatch" in problem:
            raise ArtifactDigestMismatch(f"hash_mismatch: {problem}")
    if problems.model:
        raise UnsupportedArtifact("asset manifest check failed: " + "; ".join(problems.model))
    return True


def accuracy_point(block: Any) -> dict[str, Any] | None:
    """``schema.AccuracyPoint`` fields from a manifest count block.

    Accepts ``{"n", "n_correct"[, "accuracy"]}`` as written, or the rate form ``{"value", "n"}`` from which
    ``n_correct`` is ``round(value * n)``. Anything else yields ``None`` (unknown, never guessed).
    """
    if not isinstance(block, dict):
        return None
    if "n" in block and "n_correct" in block:
        n, n_correct = int(block["n"]), int(block["n_correct"])
        acc = block.get("accuracy")
        accuracy = float(acc) if acc is not None else (n_correct / n if n else None)
        return {"n": n, "n_correct": n_correct, "accuracy": accuracy}
    if "n" in block and "value" in block:
        n, rate = int(block["n"]), float(block["value"])
        return {"n": n, "n_correct": round(rate * n), "accuracy": rate}
    return None


def clean_accuracy_entry(block: Any, default_split: Any) -> dict[str, Any] | None:
    """``schema.CleanAccuracy`` fields from an entry's ``clean_accuracy`` block (``split`` falls back to the
    evaluation split). A block that is not a mapping is malformed and refused."""
    if block is None:
        return None
    if not isinstance(block, dict):
        raise UnsupportedArtifact(f"clean_accuracy must be a {{value, n, split}} block, got {block!r}")
    return {**block, "split": block.get("split") or default_split}


def surrogate_info_entry(block: Any) -> dict[str, Any] | None:
    """``schema.SurrogateInfo`` fields from an entry's ``surrogate`` block (its file stays in the raw entry)."""
    if block is None:
        return None
    if not isinstance(block, dict):
        raise UnsupportedArtifact(f"surrogate must be a {{kind, file|path, sha256, agreement_clean}} block, got {block!r}")
    return {"kind": block.get("kind"), "sha256": block.get("sha256"),
            "agreement_clean": accuracy_point(block.get("agreement_clean"))}


def surrogate_ref(block: dict[str, Any]) -> tuple[str | None, str | None]:
    """Surrogate ``(relative path, sha256)``: ``surrogate.file`` (builder) or ``surrogate.path`` (legacy)."""
    path, file_sha = file_ref(block.get("file"))
    if path is None:
        legacy = block.get("path")
        path = legacy if isinstance(legacy, str) and legacy else None
    top = block.get("sha256")
    top_sha = str(top).lower() if isinstance(top, str) and top else None
    if file_sha and top_sha and file_sha != top_sha:
        raise UnsupportedArtifact("surrogate block declares sha256 "
                                  f"{top_sha[:12]}... but its file block says {file_sha[:12]}...")
    return path, top_sha or file_sha


def load_eval_split(path: Path, *, expected_sha256: str | None = None
                    ) -> tuple[np.ndarray, np.ndarray, np.ndarray | None, list[str] | None]:
    """``(x, y, indices | None, class_names | None)`` from an ``.npz`` or an HF image parquet.

    A missing, tampered (digest) or unreadable slice raises ``DatasetUnavailable`` (spec 9.5).
    """
    if not path.is_file():
        raise DatasetUnavailable(f"evaluation split not found: {path}; {BUILD_HINT}")
    if expected_sha256 and sha256_file(path) != expected_sha256.lower():
        raise DatasetUnavailable(f"hash_mismatch: evaluation split {path.name} differs from the manifest digest")
    if path.suffix.lower() == ".parquet":
        from redsim.ml.datasets.cifar10 import load_parquet

        x, y = load_parquet(path)
        return x, y, None, None
    try:
        with np.load(path, allow_pickle=False) as npz:
            x = np.asarray(npz["x"])
            y = np.asarray(npz["y"]).reshape(-1).astype(np.int64)
            idx = np.asarray(npz["indices"]).astype(np.int64) if "indices" in npz else None
            names = [str(s) for s in np.asarray(npz["class_names"]).tolist()] if "class_names" in npz else None
    except (OSError, KeyError, ValueError) as exc:
        raise DatasetUnavailable(f"evaluation split {path} is unreadable: {exc}") from exc
    return x, y, idx, names


INFO_KEYS: tuple[str, ...] = (
    "dataset_id", "dataset_revision", "dataset_split", "license", "source_url", "clean_accuracy", "sha256",
    "architecture_id", "architecture", "input_shape", "n_classes", "class_names", "format", "file",
    "manifest_sha256", "preprocessing", "onnx", "onnx_sha256", "description", "gradients",
)


class BundledImageTarget:
    """A bundled CNN (torch ``state_dict`` + allowlisted architecture) plus its evaluation split."""

    def __init__(self, target_id: str, *, name: str | None = None, assets_dir: str | Path | None = None,
                 fixture_only: bool = False, description: str = "") -> None:
        self.id = target_id
        self._name = name or target_id
        self._assets_dir = assets_dir
        self._fixture_only = fixture_only
        self._description = description
        self.unload()

    def unload(self) -> None:
        """Drop everything ``load()`` cached so the next call re-reads the asset tree."""
        self._entry: dict[str, Any] | None = None
        self._split: EvalSplitRef | None = None
        self._module: Any = None
        self._x: np.ndarray | None = None
        self._y: np.ndarray | None = None
        self._indices: np.ndarray | None = None
        self._class_names: list[str] = []
        self._sha256: str | None = None
        self._verified_by_manifest = False
        self._clf: Any = None
        self._manifest: dict[str, Any] | None = None

    # -- manifest access -----------------------------------------------------------------

    @property
    def root(self) -> Path:
        return assets_dir(self._assets_dir)

    def _read_entry(self) -> dict[str, Any] | None:
        return manifest_entry(read_manifest(self.root), self.id)

    def _require_entry(self, manifest: dict[str, Any] | None) -> dict[str, Any]:
        entry = manifest_entry(manifest, self.id)
        if entry is None:
            raise TargetUnavailable(f"bundled assets for {self.id!r} are missing: no entry in "
                                    f"{self.root / MANIFEST_NAME}; {BUILD_HINT}")
        return entry

    # -- protocol -------------------------------------------------------------------------

    def info(self) -> TargetInfo:
        base_meta: dict[str, Any] = {"source": "bundled", "fixture_only": self._fixture_only,
                                     "assets_dir": str(self.root)}
        try:
            entry = self._read_entry()
        except UnsupportedArtifact as exc:
            return TargetInfo(id=self.id, name=self._name, domain="image", status="not_implemented",
                              reason=f"asset manifest unreadable: {exc}",
                              metadata={**base_meta, "availability": "manifest_invalid"})
        if entry is None:
            return TargetInfo(id=self.id, name=self._name, domain="image", status="not_implemented",
                              reason=f"bundled assets not found at {self.root / MANIFEST_NAME}; {BUILD_HINT}",
                              metadata={**base_meta, "availability": "assets_missing"})
        meta = {**base_meta, "availability": "available", "gradients": True,
                **{k: entry[k] for k in INFO_KEYS if k in entry}}
        if entry.get("fixture_only"):
            meta["fixture_only"] = True
        return TargetInfo(id=self.id, name=str(entry.get("name") or self._name), domain="image",
                          status="available", metadata=meta)

    def load(self) -> None:
        if self._x is not None:
            return
        manifest = read_manifest(self.root)
        entry = self._require_entry(manifest)
        assert manifest is not None
        fmt = entry.get("format", "torch_state_dict")
        if fmt != "torch_state_dict":
            raise UnsupportedArtifact(f"bundled image target {self.id!r} declares format {fmt!r}; "
                                      "bundled CNNs ship as torch_state_dict")
        # Manifest verification first (spec 9.5): digests of this model's files and its evaluation slice.
        verified = verify_bundled_entry(manifest, self.root, self.id)
        rel, expected = weights_ref(entry)
        if rel is None:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} has no weights path (file.path or weights)")
        weights = resolve_asset_path(self.root, rel)
        if not weights.is_file():
            raise TargetUnavailable(f"weights for {self.id!r} not found at {weights}; {BUILD_HINT}")
        if not expected:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} carries no sha256 for its weights; refusing to load")
        detect_format(weights, "torch_state_dict")
        self._sha256 = expected if verified else verify_sha256(weights, expected)
        module = load_state_dict_module(weights, entry.get("architecture_id"), architecture_kwargs(entry))

        split = resolve_eval_split(manifest, entry, self.id)
        x, y, idx, split_names = load_eval_split(resolve_asset_path(self.root, split.path),
                                                 expected_sha256=None if verified else split.sha256)
        names = entry.get("class_names") or split.class_names or split_names
        if not names:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} declares no class_names")
        names = [str(n) for n in names]
        n_classes = int(entry.get("n_classes") or len(names))
        if n_classes != len(names):
            raise UnsupportedArtifact(f"n_classes {n_classes} disagrees with {len(names)} class_names")
        if x.ndim != 4 or x.shape[0] != y.shape[0] or x.shape[0] == 0:
            raise DatasetUnavailable(f"evaluation split must be non-empty NCHW, got {x.shape}")
        if y.min() < 0 or y.max() >= n_classes:
            raise DatasetUnavailable("evaluation labels fall outside the declared class list")
        declared_shape = entry.get("input_shape")
        if declared_shape and tuple(int(d) for d in declared_shape) != tuple(int(d) for d in x.shape[1:]):
            raise UnsupportedArtifact(f"shape_mismatch: manifest input_shape {declared_shape} vs split {x.shape[1:]}")
        probe = self._logits(module, as_model_input(x[:1]))
        if probe.ndim != 2 or probe.shape[1] != n_classes:
            raise UnsupportedArtifact(f"shape_mismatch: model emits {probe.shape[1:]} outputs for {n_classes} classes")
        revision = entry.get("dataset_revision") or split.revision
        self._manifest = model_manifest(
            f"manifest entry {self.id!r}",
            name=str(entry.get("name") or self._name), modality="image", format="torch_state_dict",
            sha256=self._sha256, size_bytes=weights.stat().st_size, architecture_id=entry.get("architecture_id"),
            input_shape=[int(d) for d in x.shape[1:]], n_classes=n_classes, class_names=names,
            dataset_id=entry.get("dataset_id"), dataset_revision=revision,
            dataset_split=entry.get("dataset_split"),
            clean_accuracy=clean_accuracy_entry(entry.get("clean_accuracy"), entry.get("dataset_split")),
            status="available", gradients=True, bundled=True, license=entry.get("license"),
            source_url=entry.get("source_url"),
        )
        self._entry, self._split, self._module, self._class_names = entry, split, module, names
        self._verified_by_manifest = verified
        self._x, self._y, self._indices = x, y, idx

    @staticmethod
    def _logits(module: Any, x: np.ndarray) -> np.ndarray:
        import torch

        with torch.no_grad():
            out = module(torch.from_numpy(np.ascontiguousarray(x, dtype=np.float32)))
        return np.asarray(out.cpu().numpy())

    def sample(self, n: int, seed: int) -> Sample:
        self.load()
        assert self._x is not None and self._y is not None
        return stratified_sample(self._x, self._y, n, seed, self._class_names, source_indices=self._indices)

    def train_sample(self, n: int, seed: int) -> Sample:
        """Seeded stratified draw over the build's training slice (``models[id].train_slice_split``, ATTACKS_HARDEN-11).

        The slice is the ``train_slice.npz`` the image build wrote beside the weights and recorded as a split
        of the dataset; it never overlaps the evaluation split. An entry that names no slice raises
        ``LookupError``, which ``redsim.ml.harden.apply.load_train_slice`` reports as the typed
        ``TrainingDefenseUnavailable`` (the defense recorded unavailable, score withheld).
        """
        self.load()
        assert self._entry is not None and self._class_names is not None
        slice_name = self._entry.get("train_slice_split")
        if not isinstance(slice_name, str) or not slice_name:
            raise LookupError(f"manifest entry {self.id!r} names no train_slice_split; rebuild with the training slice")
        # Bind through the same splits table the evaluation split uses; the legacy ``eval_split`` fallback is
        # removed so a missing slice is ``DatasetUnavailable`` rather than the evaluation data.
        entry = {k: v for k, v in self._entry.items() if k != "eval_split"}
        entry["dataset_split"] = slice_name
        ref = resolve_eval_split(read_manifest(self.root), entry, self.id)
        x, y, idx, names = load_eval_split(resolve_asset_path(self.root, ref.path), expected_sha256=ref.sha256)
        if x.ndim != 4 or x.shape[0] != y.shape[0] or x.shape[0] == 0:
            raise DatasetUnavailable(f"training slice {slice_name!r} must be non-empty NCHW, got {x.shape}")
        if tuple(int(d) for d in x.shape[1:]) != tuple(int(d) for d in (self._x.shape[1:] if self._x is not None else x.shape[1:])):
            raise DatasetUnavailable(f"training slice {slice_name!r} shape {x.shape[1:]} differs from the evaluation split")
        if y.min() < 0 or y.max() >= len(self._class_names):
            raise DatasetUnavailable(f"training slice {slice_name!r} labels fall outside the declared class list")
        return stratified_sample(x, y, n, seed, self._class_names, source_indices=idx)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        self.load()
        import torch

        xin = as_model_input(np.asarray(x))
        outs = []
        for start in range(0, xin.shape[0], 256):
            logits = torch.from_numpy(self._logits(self._module, xin[start:start + 256]))
            outs.append(torch.softmax(logits, dim=1).numpy().astype(np.float32))
        return np.concatenate(outs) if outs else np.empty((0, len(self._class_names)), dtype=np.float32)

    def art_classifier(self) -> Any:
        self.load()
        if self._clf is None:
            from art.estimators.classification import PyTorchClassifier
            from torch import nn

            assert self._x is not None
            self._clf = PyTorchClassifier(model=self._module, loss=nn.CrossEntropyLoss(),
                                          input_shape=tuple(int(d) for d in self._x.shape[1:]),
                                          nb_classes=len(self._class_names), clip_values=(0.0, 1.0),
                                          device_type="cpu")
        return self._clf

    def torch_model(self) -> Any:
        self.load()
        return self._module

    def manifest(self) -> dict[str, Any]:
        """Raw asset entry + load-time provenance, with the validated ``MLModelManifest`` fields on top."""
        self.load()
        assert self._entry is not None and self._manifest is not None and self._y is not None
        assert self._split is not None
        return {
            **self._entry,
            "id": self.id, "source": "bundled", "fixture_only": bool(self._entry.get("fixture_only", self._fixture_only)),
            "weights_sha256_verified": self._sha256,
            "eval_split_file": self._split.path, "eval_split_sha256_verified": self._split.sha256,
            "manifest_verified": self._verified_by_manifest,
            "eval_n": int(self._y.shape[0]), "eval_per_class": per_class_counts(self._y, self._class_names),
            "library_versions": {**library_versions("torch", "adversarial-robustness-toolbox", "numpy"),
                                 "python": platform.python_version()},
            "assets_dir": str(self.root),
            **self._manifest,
        }


def register_once(target: Any) -> Any:
    """Register unless the id is already present (module reloads in tests must not raise)."""
    return target if target.id in TARGETS else TARGETS.register(target)


VEHICLES_CNN = register_once(BundledImageTarget(
    "vehicles_cnn", name="Bundled CNN on leibnitz-lab/military_vehicles (coarse 7-class task)",
    description="Demo image target (spec section 11.3.1). Ground-level photographs, MIT-licensed compilation."))
CIFAR10_SMALLCNN = register_once(BundledImageTarget(
    "cifar10_smallcnn", name="CIFAR-10 small CNN (CI fixture, never a demo target)", fixture_only=True,
    description="CI / fixture target over the uoft-cs/cifar10 test split (spec section 11.3.5)."))

__all__ = [
    "ASSETS_DIR_ENV", "BUILD_HINT", "CIFAR10_SMALLCNN", "DEFAULT_ASSETS_DIR", "INFO_KEYS", "MANIFEST_NAME",
    "VEHICLES_CNN", "BundledImageTarget", "EvalSplitRef", "accuracy_point", "architecture_kwargs", "assets_dir",
    "clean_accuracy_entry", "dataset_entry", "file_ref", "load_eval_split", "manifest_entry", "read_manifest",
    "register_once", "resolve_asset_path", "resolve_eval_split", "surrogate_info_entry", "surrogate_ref",
    "verify_bundled_entry", "weights_ref",
]
