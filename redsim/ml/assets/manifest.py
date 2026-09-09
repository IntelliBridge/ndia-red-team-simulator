"""``assets/MANIFEST.json``: the record every bundled model and dataset carries.

The manifest is the only place clean-accuracy figures, dataset revisions and
weight hashes are written (spec sections 11.2, 11.5, 20.1 step 3). Each
``models[<id>]`` entry is a ``redsim.ml.schema.MLModelManifest``, the frozen P0
shape that ``targets.detail`` stores and every loader reads, extended with the
build's own record (constructor arguments, file paths, split names, seed,
epochs, the training recipe, measured metrics, library versions). Runs copy
the entry into ``Provenance.model_manifest``; the catalog reads it for
``TargetInfo``. Reads are lenient (unknown keys are ignored) and validation
happens at write time, matching the platform's convention for stored payloads.

Dataset caveats (spec 11.3, 14.5) and the ``subject_centered`` flag (spec 13.4)
are recorded on the dataset entry and copied onto every model entry bound to
that dataset (``dataset_caveats`` / ``subject_centered``), because the loaders
hand the raw model entry to the campaign as ``Target.manifest()`` and the
campaign appends ``caveats`` / ``dataset_caveats`` it finds there to the run's
limitations. Both are build-record fields outside the frozen projection, so
``manifest_sha256`` does not change when they are added and manifests written
before they existed still verify (they read back as ``[]`` / ``None``).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from redsim.ml.schema import AccuracyPoint, MLModelManifest, ModelStatus, SurrogateInfo

MANIFEST_NAME = "MANIFEST.json"
BUILDER_NAME = "redsim ml build-assets"

DatasetSource = Literal["huggingface", "kaggle", "local"]


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
    # The bundled slice a loader consumes: an ``.npz`` with ``x`` / ``y`` / ``indices`` (uint8 NCHW images,
    # or float32 precomputed features for tabular data). ``rows_csv`` is the human-readable row listing the
    # tabular build writes beside it (``index,url,type``); URL strings there are data, never fetched.
    file: FileEntry | None = None
    rows_csv: FileEntry | None = None


class DatasetEntry(_Lenient):
    id: str                                  # "hf:uoft-cs/cifar10", "kaggle:sid321axn/malicious-urls-dataset", "local:..."
    source: DatasetSource
    revision: str | None = None              # HF commit sha, or source-file sha256 for Kaggle
    url: str | None = None                   # distribution page; recorded, never fetched by a consumer
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
    source_file_sha256: str | None = None    # sha256 of the file the rows were read from (Kaggle CSV, or the sample)
    archive_sha256: str | None = None        # sha256 of the archive that file was extracted from (the Kaggle zip)
    n_rows: int | None = None                # data rows read from that file
    sampled_from: dict[str, Any] | None = None   # committed sample: the source digest, row indices and sampling rule
    fixture_only: bool = False               # never a demo target, never evidence (spec 11.1)
    notes: list[str] = Field(default_factory=list)
    # Spec 11.3 caveats: appended to the limitations of every campaign on this dataset (spec 14.5). Build-time
    # record; ``[]`` on manifests written before the field existed.
    caveats: list[str] = Field(default_factory=list)
    # Spec 13.4: whether subjects are reliably centred / tightly framed, so the centre-mass heuristic is meaningful.
    # ``False`` adds the weak-subject caveat to every image observation; ``None`` means the dataset does not say.
    subject_centered: bool | None = None


class SurrogateEntry(SurrogateInfo):
    """``schema.SurrogateInfo`` plus the bundled file. ``sha256`` is that file's digest.

    ``agreement_clean`` is measured on the clean evaluation split: ``n`` rows,
    ``n_correct`` of them where the surrogate's label equals the ensemble's.
    """

    model_config = ConfigDict(extra="ignore")

    file: FileEntry
    agreement_clean: AccuracyPoint

    @model_validator(mode="after")
    def _sha_matches_file(self) -> SurrogateEntry:
        if self.sha256 != self.file.sha256:
            raise ValueError("surrogate sha256 must equal file.sha256")
        return self


class ModelEntry(MLModelManifest):
    """One ``models[<id>]`` entry: the frozen ``MLModelManifest`` plus the build record.

    Every ``MLModelManifest`` field is present, so
    ``MLModelManifest.model_validate(entry.model_dump(mode="json"))`` holds for
    what is written to disk (``model_manifest`` below). The extra fields say
    how the weights were produced and are ignored by consumers that read the
    schema shape. ``sha256`` / ``size_bytes`` are the bundled file's, and
    ``dataset_split`` names the split ``clean_accuracy`` was measured on.
    """

    model_config = ConfigDict(extra="ignore")

    id: str
    architecture_id: str                                    # bundled models always name their architecture
    architecture: dict[str, Any] = Field(default_factory=dict)   # constructor arguments
    file: FileEntry
    train_split: str
    seed: int
    epochs: int | None = None
    training: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)   # clean accuracy, per-class n / n_correct, ...
    extractor_version: str | None = None                    # tabular
    surrogate: SurrogateEntry | None = None                 # tabular tree ensembles
    library_versions: dict[str, str] = Field(default_factory=dict)
    fixture_only: bool = False
    notes: list[str] = Field(default_factory=list)
    # The bound dataset's ``caveats`` / ``subject_centered``, copied here so ``Target.manifest()`` (the raw entry)
    # carries them into the campaign (spec 11.3, 13.4, 14.5). Outside the frozen projection: no digest change.
    dataset_caveats: list[str] = Field(default_factory=list)
    subject_centered: bool | None = None
    status: ModelStatus = "available"
    bundled: bool = True

    @model_validator(mode="after")
    def _file_and_measurements_agree(self) -> ModelEntry:
        if self.sha256 != self.file.sha256 or self.size_bytes != self.file.size_bytes:
            raise ValueError("sha256 and size_bytes must equal the bundled file's")
        if self.clean_accuracy is None:
            raise ValueError("a bundled model records its measured clean accuracy")
        if self.clean_accuracy.split != self.dataset_split:
            raise ValueError("clean_accuracy.split must equal dataset_split")
        return self


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
# The MLModelManifest projection and its digest
# ---------------------------------------------------------------------------

def model_manifest(entry: MLModelManifest) -> MLModelManifest:
    """The frozen ``MLModelManifest`` projection of an entry (what ``targets.detail`` stores).

    Goes through a JSON dump so a ``ModelEntry`` loses its build-only fields
    instead of being passed through as a subclass instance.
    """
    return MLModelManifest.model_validate(entry.model_dump(mode="json"))


def manifest_digest(entry: MLModelManifest) -> str:
    """``manifest_sha256``: sha256 of the projection's canonical JSON, ``manifest_sha256`` itself excluded.

    Canonical means ``json.dumps(..., sort_keys=True, separators=(",", ":"))``
    of ``model_dump(mode="json")``. A consumer holding only the
    ``MLModelManifest`` shape recomputes the same digest.
    """
    payload = model_manifest(entry).model_dump(mode="json", exclude={"manifest_sha256"})
    return sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def stamp_manifest_sha256(entry: ModelEntry) -> ModelEntry:
    """Return ``entry`` with ``manifest_sha256`` set from its projection."""
    return entry.model_copy(update={"manifest_sha256": manifest_digest(entry)})


def with_dataset_caveats(entry: ModelEntry, dataset: DatasetEntry) -> ModelEntry:
    """Return ``entry`` carrying ``dataset``'s caveats and ``subject_centered`` flag (spec 11.3, 13.4).

    The copy is what reaches the campaign: the loaders return the raw model entry as ``Target.manifest()``
    and ``redsim.ml.campaign`` reads ``dataset_caveats`` / ``subject_centered`` from it. Both fields sit
    outside the frozen ``MLModelManifest`` projection, so ``manifest_sha256`` is unchanged.
    """
    if entry.dataset_id != dataset.id:
        raise ValueError(f"model {entry.id!r} is bound to dataset {entry.dataset_id!r}, not {dataset.id!r}")
    return entry.model_copy(update={"dataset_caveats": list(dataset.caveats),
                                    "subject_centered": dataset.subject_centered})


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


def model_entry(manifest: AssetManifest, model_id: str) -> ModelEntry | None:
    """``models[model_id]``, also found under a legacy id that now maps to ``model_id`` (``url_classifier``)."""
    from redsim.ml.assets import LEGACY_MODEL_IDS

    entry = manifest.models.get(model_id)
    if entry is not None:
        return entry
    for legacy, current in LEGACY_MODEL_IDS.items():
        if current == model_id and legacy in manifest.models:
            return manifest.models[legacy]
    return None


def iter_split_files(ds_id: str, ds: DatasetEntry, split_name: str | None = None
                     ) -> Iterable[tuple[str, FileEntry]]:
    """Bundled files of one dataset (every split, or ``split_name`` only)."""
    for name, split in ds.splits.items():
        if split_name is not None and name != split_name:
            continue
        if split.file is not None:
            yield f"dataset {ds_id} split {name}", split.file
        if split.rows_csv is not None:
            yield f"dataset {ds_id} split {name} rows", split.rows_csv


def iter_model_files(model_id: str, model: ModelEntry) -> Iterable[tuple[str, FileEntry]]:
    yield f"model {model_id}", model.file
    if model.surrogate is not None:
        yield f"model {model_id} surrogate", model.surrogate.file


def iter_file_entries(manifest: AssetManifest) -> Iterable[tuple[str, FileEntry]]:
    """Every bundled file the manifest references (slices, weights, surrogates), with a label for messages."""
    for ds_id, ds in manifest.datasets.items():
        yield from iter_split_files(ds_id, ds)
    for model_id, model in manifest.models.items():
        yield from iter_model_files(model_id, model)


def _check_files(entries: Iterable[tuple[str, FileEntry]], root: Path) -> list[str]:
    problems: list[str] = []
    root = Path(root)
    for label, entry in entries:
        target = root / entry.path
        if not target.exists():
            problems.append(f"{label}: missing file {entry.path}")
            continue
        actual = sha256_file(target)
        if actual != entry.sha256:
            problems.append(f"{label}: sha256 mismatch for {entry.path} (manifest {entry.sha256[:12]}..., file {actual[:12]}...)")
    return problems


def verify_files(manifest: AssetManifest, root: Path) -> list[str]:
    """Return one message per referenced file that is missing or whose sha256 differs."""
    return _check_files(iter_file_entries(manifest), root)


def _check_entry(model_id: str, model: ModelEntry) -> list[str]:
    expected = manifest_digest(model)
    if model.manifest_sha256 != expected:
        recorded = (model.manifest_sha256 or "unset")[:12]
        return [f"model {model_id}: manifest_sha256 mismatch (manifest {recorded}..., computed {expected[:12]}...)"]
    return []


def verify_entries(manifest: AssetManifest) -> list[str]:
    """Return one message per model entry whose ``manifest_sha256`` does not match its projection."""
    problems: list[str] = []
    for model_id, model in manifest.models.items():
        problems.extend(_check_entry(model_id, model))
    return problems


def verify_manifest(manifest: AssetManifest, root: Path) -> list[str]:
    """Files and entry digests together; a run refuses to start on any problem (spec 9.5, 11.3.3)."""
    return verify_files(manifest, root) + verify_entries(manifest)


@dataclass(frozen=True)
class ModelAssetProblems:
    """``verify_model_assets`` result, split by what failed so a loader can raise the right class."""

    model: list[str]        # the weights / surrogate files, or the entry's manifest_sha256
    dataset: list[str]      # the evaluation split the model is bound to

    def __bool__(self) -> bool:
        return bool(self.model or self.dataset)


def verify_model_assets(manifest: AssetManifest, root: Path, model_id: str) -> ModelAssetProblems:
    """Verify one bundled model's files and the evaluation split its manifest binds it to (spec 9.5, ATTACK-42).

    Scoped to the model so a missing slice of another dataset does not block this target; the loaders
    call this at every ``load()``. Problems with the split (missing, tampered, no such dataset or split
    in ``datasets``) are reported separately from problems with the model's own files.
    """
    entry = model_entry(manifest, model_id)
    if entry is None:
        return ModelAssetProblems(model=[f"model {model_id}: no entry in the manifest"], dataset=[])
    model_problems = _check_files(iter_model_files(model_id, entry), root) + _check_entry(model_id, entry)
    dataset_problems: list[str] = []
    ds = manifest.datasets.get(entry.dataset_id)
    if ds is None:
        dataset_problems.append(f"model {model_id}: dataset {entry.dataset_id!r} is not in the manifest's datasets")
    else:
        split = ds.splits.get(entry.dataset_split)
        if split is None or split.file is None:
            dataset_problems.append(f"model {model_id}: dataset {entry.dataset_id!r} has no bundled split "
                                    f"{entry.dataset_split!r}")
        else:
            dataset_problems.extend(_check_files(iter_split_files(entry.dataset_id, ds, entry.dataset_split), root))
        if entry.dataset_revision is not None and ds.revision is not None and entry.dataset_revision != ds.revision:
            dataset_problems.append(f"model {model_id}: dataset_revision {entry.dataset_revision!r} differs from the "
                                    f"dataset entry's revision {ds.revision!r}")
    return ModelAssetProblems(model=model_problems, dataset=dataset_problems)
