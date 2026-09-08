"""Bundled image targets over ``assets/MANIFEST.json`` (spec sections 9.2, 11.5).

Asset layout (written by ``redsim ml build-assets`` on the assets branch, read here):

    <assets_dir>/MANIFEST.json
    {
      "schema": "redsim.ml.assets/1",
      "library_versions": {...},
      "models": {
        "<target id>": {
          "name": "...", "modality": "image", "format": "torch_state_dict",
          "architecture_id": "smallcnn", "architecture_kwargs": {"in_channels": 3, "n_classes": 7, "image_size": 128},
          "weights": "models/vehicles_cnn/model.pt", "sha256": "<weights sha256>",
          "onnx": "models/vehicles_cnn/model.onnx", "onnx_sha256": "...",
          "input_shape": [3, 128, 128], "n_classes": 7, "class_names": [...],
          "eval_split": "datasets/military_vehicles/test_coarse.npz", "eval_split_sha256": "...",
          "dataset_id": "leibnitz-lab/military_vehicles", "dataset_revision": "<hub commit sha>",
          "dataset_split": "test_coarse", "license": "MIT", "source_url": "...",
          "preprocessing": {...}, "training": {...}, "clean_accuracy": {"value": 0.0, "n": 0, "split": "..."},
          "fixture_only": false
        }
      }
    }

``models`` may also be a list of entries carrying an ``id``. Relative paths resolve against the
manifest's directory and may not escape it. The evaluation split is an ``.npz`` with ``x`` (uint8
or float32 NCHW), ``y`` (int) and optional ``indices`` / ``class_names``; a ``.parquet`` in the HF
image-classification layout (``img`` struct, ``label``) is also accepted.

Every load verifies the weights digest against the manifest before ``torch.load(weights_only=True)``.
Registration at import touches no file: ``info()`` reads the manifest lazily and reports the target as
``not_implemented`` with a reason while the assets are absent, since ``TargetStatus`` has no third value.
"""

from __future__ import annotations

import json
import os
import platform
from pathlib import Path
from typing import Any

import numpy as np

from redsim.ml.datasets.sampling import as_model_input, per_class_counts, stratified_sample
from redsim.ml.errors import TargetUnavailable, UnsupportedArtifact
from redsim.ml.schema import TargetInfo
from redsim.ml.targets.artifact import (
    detect_format,
    library_versions,
    load_state_dict_module,
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


def manifest_entry(manifest: dict[str, Any] | None, model_id: str) -> dict[str, Any] | None:
    if manifest is None:
        return None
    models = manifest.get("models")
    if isinstance(models, dict):
        entry = models.get(model_id)
        return dict(entry) if isinstance(entry, dict) else None
    if isinstance(models, list):
        for entry in models:
            if isinstance(entry, dict) and entry.get("id") == model_id:
                return dict(entry)
    return None


def resolve_asset_path(root: Path, rel: str) -> Path:
    """A manifest path resolved inside the asset tree (absolute paths and ``..`` escapes are refused)."""
    root_r = root.resolve()
    candidate = (root_r / rel).resolve()
    if candidate != root_r and root_r not in candidate.parents:
        raise UnsupportedArtifact(f"asset path escapes the asset tree: {rel!r}")
    return candidate


def load_eval_split(path: Path, *, expected_sha256: str | None = None
                    ) -> tuple[np.ndarray, np.ndarray, np.ndarray | None, list[str] | None]:
    """``(x, y, indices | None, class_names | None)`` from an ``.npz`` or an HF image parquet."""
    if not path.is_file():
        raise TargetUnavailable(f"evaluation split not found: {path}")
    if expected_sha256 and sha256_file(path) != expected_sha256.lower():
        raise UnsupportedArtifact(f"hash_mismatch: evaluation split {path.name} differs from the manifest digest")
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
        raise UnsupportedArtifact(f"evaluation split {path} is unreadable: {exc}") from exc
    return x, y, idx, names


class BundledImageTarget:
    """A bundled CNN (torch ``state_dict`` + allowlisted architecture) plus its evaluation split."""

    def __init__(self, target_id: str, *, name: str | None = None, assets_dir: str | Path | None = None,
                 fixture_only: bool = False, description: str = "") -> None:
        self.id = target_id
        self._name = name or target_id
        self._assets_dir = assets_dir
        self._fixture_only = fixture_only
        self._description = description
        self._entry: dict[str, Any] | None = None
        self._module: Any = None
        self._x: np.ndarray | None = None
        self._y: np.ndarray | None = None
        self._indices: np.ndarray | None = None
        self._class_names: list[str] = []
        self._sha256: str | None = None
        self._clf: Any = None

    # -- manifest access -----------------------------------------------------------------

    @property
    def root(self) -> Path:
        return assets_dir(self._assets_dir)

    def _read_entry(self) -> dict[str, Any] | None:
        return manifest_entry(read_manifest(self.root), self.id)

    def _require_entry(self) -> dict[str, Any]:
        entry = self._read_entry()
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
        keys = ("dataset_id", "dataset_revision", "dataset_split", "license", "source_url", "clean_accuracy",
                "sha256", "architecture_id", "input_shape", "n_classes", "class_names", "format",
                "preprocessing", "onnx", "onnx_sha256", "description")
        meta = {**base_meta, "availability": "available", "gradients": True,
                **{k: entry[k] for k in keys if k in entry}}
        if entry.get("fixture_only"):
            meta["fixture_only"] = True
        return TargetInfo(id=self.id, name=str(entry.get("name") or self._name), domain="image",
                          status="available", metadata=meta)

    def load(self) -> None:
        if self._x is not None:
            return
        entry = self._require_entry()
        fmt = entry.get("format", "torch_state_dict")
        if fmt != "torch_state_dict":
            raise UnsupportedArtifact(f"bundled image target {self.id!r} declares format {fmt!r}; "
                                      "bundled CNNs ship as torch_state_dict")
        rel = entry.get("weights")
        if not isinstance(rel, str):
            raise UnsupportedArtifact(f"manifest entry {self.id!r} has no 'weights' path")
        weights = resolve_asset_path(self.root, rel)
        if not weights.is_file():
            raise TargetUnavailable(f"weights for {self.id!r} not found at {weights}; {BUILD_HINT}")
        expected = entry.get("sha256")
        if not isinstance(expected, str) or not expected:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} carries no sha256 for its weights; refusing to load")
        detect_format(weights, "torch_state_dict")
        self._sha256 = verify_sha256(weights, expected)
        module = load_state_dict_module(weights, entry.get("architecture_id"), entry.get("architecture_kwargs"))

        split_rel = entry.get("eval_split")
        if not isinstance(split_rel, str):
            raise UnsupportedArtifact(f"manifest entry {self.id!r} has no 'eval_split' path")
        x, y, idx, split_names = load_eval_split(resolve_asset_path(self.root, split_rel),
                                                 expected_sha256=entry.get("eval_split_sha256"))
        names = entry.get("class_names") or split_names
        if not names:
            raise UnsupportedArtifact(f"manifest entry {self.id!r} declares no class_names")
        names = [str(n) for n in names]
        n_classes = int(entry.get("n_classes") or len(names))
        if n_classes != len(names):
            raise UnsupportedArtifact(f"n_classes {n_classes} disagrees with {len(names)} class_names")
        if x.ndim != 4 or x.shape[0] != y.shape[0] or x.shape[0] == 0:
            raise UnsupportedArtifact(f"evaluation split must be non-empty NCHW, got {x.shape}")
        if y.min() < 0 or y.max() >= n_classes:
            raise UnsupportedArtifact("evaluation labels fall outside the declared class list")
        declared_shape = entry.get("input_shape")
        if declared_shape and tuple(int(d) for d in declared_shape) != tuple(int(d) for d in x.shape[1:]):
            raise UnsupportedArtifact(f"shape_mismatch: manifest input_shape {declared_shape} vs split {x.shape[1:]}")
        probe = self._logits(module, as_model_input(x[:1]))
        if probe.ndim != 2 or probe.shape[1] != n_classes:
            raise UnsupportedArtifact(f"shape_mismatch: model emits {probe.shape[1:]} outputs for {n_classes} classes")
        self._entry, self._module, self._class_names = entry, module, names
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
        self.load()
        assert self._entry is not None and self._y is not None and self._x is not None
        return {
            **self._entry,
            "id": self.id, "source": "bundled", "fixture_only": bool(self._entry.get("fixture_only", self._fixture_only)),
            "weights_sha256_verified": self._sha256, "class_names": self._class_names,
            "input_shape": [int(d) for d in self._x.shape[1:]], "gradients": True,
            "eval_n": int(self._y.shape[0]), "eval_per_class": per_class_counts(self._y, self._class_names),
            "library_versions": {**library_versions("torch", "adversarial-robustness-toolbox", "numpy"),
                                 "python": platform.python_version()},
            "assets_dir": str(self.root),
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
    "ASSETS_DIR_ENV", "BUILD_HINT", "CIFAR10_SMALLCNN", "DEFAULT_ASSETS_DIR", "MANIFEST_NAME", "VEHICLES_CNN",
    "BundledImageTarget", "assets_dir", "load_eval_split", "manifest_entry", "read_manifest", "register_once",
    "resolve_asset_path",
]
