"""``assets/MANIFEST.json``: the record every bundled model and dataset carries.

The manifest is the only place clean-accuracy figures, dataset revisions and
weight hashes are written (spec sections 11.2, 11.5, 20.1 step 3). Runs copy
it into ``Provenance.model_manifest``; the catalog reads it for ``TargetInfo``.
Reads are lenient (unknown keys are ignored) and validation happens at write
time, matching the platform's convention for stored payloads.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import tempfile
from collections.abc import Iterable
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

MANIFEST_NAME = "MANIFEST.json"
BUILDER_NAME = "redsim ml build-assets"

DatasetSource = Literal["huggingface", "kaggle", "local"]
Modality = Literal["image", "tabular"]
ModelFormat = Literal["torch_state_dict", "sklearn_joblib", "xgboost_json", "onnx"]
FeatureDType = Literal["int", "float", "bool"]


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class FileEntry(_Lenient):
    """A file under the assets root, addressed by path relative to that root."""

    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)


class SplitEntry(_Lenient):
    name: str
    n: int = Field(ge=0)
    per_class: dict[str, int] = Field(default_factory=dict)
    seed: int | None = None                 # split seed when the dataset has no official split
    indices_sha256: str | None = None       # sha256 of the int64 source indices, for reproducibility
    file: FileEntry | None = None           # bundled slice (npz / csv), if written


class DatasetEntry(_Lenient):
    id: str                                  # "hf:uoft-cs/cifar10", "kaggle:sid321axn/malicious-urls-dataset", "local:..."
    source: DatasetSource
    revision: str | None = None              # HF commit sha, or source-file sha256 for Kaggle
    url: str | None = None
    license: str | None = None               # as declared on the distribution page
    license_note: str | None = None          # what the declaration does and does not cover
    class_names: list[str] = Field(default_factory=list)
    # Files as fetched from the source, hashed at fetch time. Paths are source-relative (hub rfilename,
    # Kaggle file name); they live in the download cache, not under the assets root, so verify_files
    # does not re-check them. Bundled outputs (split slices, weights) are verified.
    source_files: list[FileEntry] = Field(default_factory=list)
    size_bytes: int | None = None
    splits: dict[str, SplitEntry] = Field(default_factory=dict)
    preprocessing: dict[str, Any] = Field(default_factory=dict)
    n_duplicates_removed: int | None = None
    fixture_only: bool = False               # never a demo target, never evidence (spec 11.1)
    notes: list[str] = Field(default_factory=list)


class FeatureSpecEntry(_Lenient):
    name: str
    dtype: FeatureDType
    perturbable: bool
    min: float | None = None                 # training-split range
    max: float | None = None


class SurrogateEntry(_Lenient):
    kind: str                                # e.g. "sklearn_logistic_regression"
    file: FileEntry
    agreement_eval: float = Field(ge=0.0, le=1.0)
    n_eval: int = Field(ge=0)


class ModelEntry(_Lenient):
    id: str
    modality: Modality
    format: ModelFormat
    architecture_id: str
    architecture: dict[str, Any] = Field(default_factory=dict)
    file: FileEntry
    dataset_id: str
    dataset_revision: str | None = None
    train_split: str
    eval_split: str
    class_names: list[str]
    seed: int
    epochs: int | None = None
    training: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)   # clean accuracy, per-class n / n_correct, ...
    features: list[FeatureSpecEntry] | None = None          # tabular
    extractor_version: str | None = None                    # tabular
    surrogate: SurrogateEntry | None = None                 # tabular tree ensembles
    library_versions: dict[str, str] = Field(default_factory=dict)
    fixture_only: bool = False
    license: str | None = None
    notes: list[str] = Field(default_factory=list)


class AssetManifest(_Lenient):
    schema_version: Literal[1] = 1
    builder: str = BUILDER_NAME
    built_at: datetime
    redsim_version: str
    python: str
    platform: str
    library_versions: dict[str, str] = Field(default_factory=dict)
    datasets: dict[str, DatasetEntry] = Field(default_factory=dict)
    models: dict[str, ModelEntry] = Field(default_factory=dict)

    @classmethod
    def new(cls) -> AssetManifest:
        return cls(
            built_at=datetime.now(UTC),
            redsim_version=redsim_version(),
            python=sys.version.split()[0],
            platform=platform.platform(),
            library_versions=library_versions(),
        )

    def touch(self) -> None:
        """Refresh the environment stamp after a (re)build."""
        self.built_at = datetime.now(UTC)
        self.redsim_version = redsim_version()
        self.python = sys.version.split()[0]
        self.platform = platform.platform()
        self.library_versions = library_versions()


# ---------------------------------------------------------------------------
# Hashing and environment
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def file_entry(root: Path, path: Path) -> FileEntry:
    """Hash ``path`` and record it relative to the assets ``root``."""
    rel = path.resolve().relative_to(root.resolve())
    return FileEntry(path=rel.as_posix(), sha256=sha256_file(path), size_bytes=path.stat().st_size)


_LIBRARIES: tuple[str, ...] = (
    "torch", "torchvision", "numpy", "scikit-learn", "xgboost", "pyarrow", "pillow", "httpx",
    "adversarial-robustness-toolbox", "shap", "onnx", "onnxruntime", "pydantic",
)


def library_versions(names: Iterable[str] = _LIBRARIES) -> dict[str, str]:
    """Installed versions of the libraries that shape an asset; missing ones are omitted."""
    out: dict[str, str] = {}
    for name in names:
        try:
            out[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
    return out


def redsim_version() -> str:
    try:
        return metadata.version("redsim-platform")
    except metadata.PackageNotFoundError:
        return "0.0.0+unknown"


# ---------------------------------------------------------------------------
# Load / write / verify
# ---------------------------------------------------------------------------

def load_manifest(path: Path) -> AssetManifest:
    return AssetManifest.model_validate_json(Path(path).read_text(encoding="utf-8"))


def load_or_new(path: Path) -> AssetManifest:
    path = Path(path)
    if path.exists():
        return load_manifest(path)
    return AssetManifest.new()


def write_manifest(manifest: AssetManifest, path: Path) -> None:
    """Atomically write the manifest as sorted, indented JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".manifest-", suffix=".json", dir=path.parent)
    replaced = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp_name, path)
        replaced = True
    finally:
        if not replaced and os.path.exists(tmp_name):
            os.unlink(tmp_name)


def iter_file_entries(manifest: AssetManifest) -> Iterable[tuple[str, FileEntry]]:
    """Every bundled file the manifest references (slices, weights, surrogates), with a label for messages."""
    for ds_id, ds in manifest.datasets.items():
        for split_name, split in ds.splits.items():
            if split.file is not None:
                yield f"dataset {ds_id} split {split_name}", split.file
    for model_id, model in manifest.models.items():
        yield f"model {model_id}", model.file
        if model.surrogate is not None:
            yield f"model {model_id} surrogate", model.surrogate.file


def verify_files(manifest: AssetManifest, root: Path) -> list[str]:
    """Return one message per referenced file that is missing or whose sha256 differs."""
    problems: list[str] = []
    root = Path(root)
    for label, entry in iter_file_entries(manifest):
        target = root / entry.path
        if not target.exists():
            problems.append(f"{label}: missing file {entry.path}")
            continue
        actual = sha256_file(target)
        if actual != entry.sha256:
            problems.append(f"{label}: sha256 mismatch for {entry.path} (manifest {entry.sha256[:12]}..., file {actual[:12]}...)")
    return problems
