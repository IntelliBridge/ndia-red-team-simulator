"""Uploaded ML model targets: dataset binding, worker-side materialization, soft delete.

Two callers share this module and it stays light for both:

* The API process imports :func:`check_upload_dataset` (the static dataset
  compatibility check of spec 9.3 / 17.3 ``dataset_incompatible``) and
  :func:`delete_model_target`. Both read only ``MANIFEST.json`` and the ORM and
  import no ML library, so ``tests/test_api_process_has_no_ml.py`` holds.
* The worker and the sandbox child import :func:`uploaded_model_file`,
  :func:`uploaded_target` and :func:`artifact_target_from_path`, the only
  helpers that touch model bytes.

Dataset binding. ``redsim ml build-assets`` records evaluation splits under
``datasets[<dataset_id>].splits[<split>].file`` (``redsim.ml.assets.manifest``:
``DatasetEntry`` / ``SplitEntry`` / ``FileEntry``) with the class names and the
resolved revision on the dataset entry. :func:`resolve_dataset_binding` reads
that shape first and still accepts the pre-manifest flat ``models[*].eval_split``
entries, so an upload declared against a bundled dataset binds to the same
slice a bundled model is measured on.

Deletion. ``DELETE /v1/models/{id}`` is a soft delete: every upload creates an
``ml.ingest`` Run whose ``target_id`` references the Target, and campaigns
reference it from ``ml_campaigns``, so the row must stay for history (spec 17:
"Run, Finding, Artifact and audit rows are retained"). The target's
``detail.status`` becomes ``"deleted"`` (an API-side terminal marker layered
over the frozen ``ModelStatus`` vocabulary; the frozen manifest copy under
``detail.manifest`` keeps its last validated status), the catalog hides it,
campaign admission refuses it (``409 model_load_refused``: status is not
``available``) and the blob is removed unless another live model target shares
the same content-addressed bytes. The ``target.manage`` audit event is written
before the row changes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig
    from redsim.db.models import Target
    from redsim.ml.schema import Domain
    from redsim.ml.targets.artifact import ArtifactTarget
    from redsim.storage import BlobStore

logger = logging.getLogger(__name__)

ML_KINDS = frozenset({"ml_model_artifact", "ml_model_endpoint"})

#: ``targets.detail.status`` of a soft-deleted model target.
DELETED_STATUS = "deleted"

# Same names ``redsim.ml.targets.bundled`` reads; kept as literals so the API
# process can locate the manifest without importing the ML target package.
ASSETS_DIR_ENV = "REDSIM_ML_ASSETS_DIR"
DEFAULT_ASSETS_DIR = "./assets"
MANIFEST_NAME = "MANIFEST.json"

# Keys the asset builder writes into ``DatasetEntry.preprocessing`` for each
# modality (``redsim/ml/assets/datasets.py``, ``redsim/ml/assets/build.py``).
_TABULAR_PREPROCESSING_KEYS = frozenset({"features", "extractor", "extractor_version"})
_IMAGE_PREPROCESSING_KEYS = frozenset({"layout", "resolution", "channel_order", "resize", "value_range"})


class DatasetBindingError(ValueError):
    """The declared dataset cannot be bound to a bundled evaluation split.

    Maps to ``422 dataset_incompatible`` at the API (spec 17.3) and to
    ``UnsupportedArtifact("dataset_incompatible: ...")`` on the worker.
    ``field`` names the request field the message is about.
    """

    code = "dataset_incompatible"

    def __init__(self, message: str, *, field: str = "dataset_id") -> None:
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class DatasetBinding:
    """A bundled evaluation slice an uploaded model is evaluated on."""

    dataset_id: str
    split: str
    file_path: str                  # relative to the assets root
    file_sha256: str | None
    class_names: list[str]
    revision: str | None
    modality: str | None            # None when the manifest does not say
    fixture_only: bool = False
    legacy: bool = False            # resolved from a flat ``models[*].eval_split`` entry


# ---------------------------------------------------------------------------
# Asset manifest reads (plain JSON; no ML imports)
# ---------------------------------------------------------------------------


def assets_root(explicit: str | Path | None = None) -> Path:
    if explicit is not None:
        return Path(explicit).expanduser()
    return Path(os.environ.get(ASSETS_DIR_ENV, "").strip() or DEFAULT_ASSETS_DIR).expanduser()


def read_asset_manifest(root: str | Path | None = None) -> dict[str, Any]:
    """Parse ``<assets root>/MANIFEST.json`` as a plain object."""
    path = assets_root(root) / MANIFEST_NAME
    if not path.is_file():
        raise DatasetBindingError(
            f"bundled asset manifest is missing at {path}; run `redsim ml build-assets` "
            f"or point {ASSETS_DIR_ENV} at a built asset tree"
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DatasetBindingError(f"bundled asset manifest is unreadable: {exc}") from exc
    if not isinstance(document, dict):
        raise DatasetBindingError("bundled asset manifest is not an object")
    return document


def _model_entries(document: dict[str, Any]) -> list[dict[str, Any]]:
    raw = document.get("models")
    if isinstance(raw, dict):
        return [dict(value) for value in raw.values() if isinstance(value, dict)]
    if isinstance(raw, list):
        return [dict(value) for value in raw if isinstance(value, dict)]
    return []


def _dataset_entries(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """``datasets`` keyed by id (the mapping key and the entry's own ``id`` both resolve)."""
    raw = document.get("datasets")
    entries: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            if not isinstance(value, dict):
                continue
            entries[str(key)] = dict(value)
            own_id = value.get("id")
            if isinstance(own_id, str) and own_id and own_id != str(key):
                entries.setdefault(own_id, dict(value))
    elif isinstance(raw, list):
        for value in raw:
            if isinstance(value, dict) and isinstance(value.get("id"), str) and value["id"]:
                entries[str(value["id"])] = dict(value)
    return entries


def _entry_dataset_id(entry: dict[str, Any]) -> Any:
    return entry.get("dataset_id") or entry.get("dataset")


def _dataset_modality(
    entry: dict[str, Any], dataset_id: str, models: list[dict[str, Any]],
) -> str | None:
    """The dataset's modality as recorded, or ``None`` when the manifest does not say."""
    preprocessing = entry.get("preprocessing")
    preprocessing = preprocessing if isinstance(preprocessing, dict) else {}
    for candidate in (entry.get("modality"), preprocessing.get("modality")):
        if isinstance(candidate, str) and candidate:
            return candidate
    for model in models:
        if _entry_dataset_id(model) == dataset_id and isinstance(model.get("modality"), str):
            return str(model["modality"])
    keys = set(preprocessing)
    if keys & _TABULAR_PREPROCESSING_KEYS or entry.get("features"):
        return "tabular"
    if keys & _IMAGE_PREPROCESSING_KEYS:
        return "image"
    return None


def _bundled_splits(entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Splits that carry a bundled file: the only ones an upload can be evaluated on."""
    raw = entry.get("splits")
    if isinstance(raw, dict):
        items = [(str(key), value) for key, value in raw.items()]
    elif isinstance(raw, list):
        items = [(str(value.get("name")), value) for value in raw if isinstance(value, dict)]
    else:
        items = []
    out: dict[str, dict[str, Any]] = {}
    for name, value in items:
        if not isinstance(value, dict):
            continue
        file_entry = value.get("file")
        if isinstance(file_entry, dict) and file_entry.get("path"):
            out[str(value.get("name") or name)] = value
    return out


def _select_split(dataset_id: str, splits: dict[str, dict[str, Any]], requested: str | None) -> str:
    if requested:
        if requested in splits:
            return requested
        raise DatasetBindingError(
            f"dataset {dataset_id!r} has no bundled evaluation split named {requested!r}; "
            f"bundled splits: {sorted(splits) or 'none'}",
            field="dataset_split",
        )
    if not splits:
        raise DatasetBindingError(f"dataset {dataset_id!r} has no bundled evaluation split")
    if "test" in splits:
        return "test"
    if len(splits) == 1:
        return next(iter(splits))
    raise DatasetBindingError(
        f"dataset {dataset_id!r} has several bundled splits {sorted(splits)}; declare dataset_split",
        field="dataset_split",
    )


def _legacy_binding(
    dataset_id: str, requested: str | None, models: list[dict[str, Any]],
) -> DatasetBinding | None:
    """Pre-manifest layout: a flat ``eval_split`` path on the bundled model entry."""
    for entry in models:
        if _entry_dataset_id(entry) != dataset_id:
            continue
        split = str(entry.get("dataset_split") or entry.get("eval_split_name") or "test")
        if requested and split != requested:
            continue
        relative = entry.get("eval_split")
        class_names = entry.get("class_names")
        if not (isinstance(relative, str) and relative and isinstance(class_names, list) and class_names):
            continue
        digest = entry.get("eval_split_sha256")
        revision = entry.get("dataset_revision")
        modality = entry.get("modality")
        return DatasetBinding(
            dataset_id=dataset_id,
            split=split,
            file_path=relative,
            file_sha256=str(digest) if isinstance(digest, str) and digest else None,
            class_names=[str(value) for value in class_names],
            revision=None if revision is None else str(revision),
            modality=modality if isinstance(modality, str) and modality else None,
            fixture_only=bool(entry.get("fixture_only", False)),
            legacy=True,
        )
    return None


def resolve_dataset_binding(
    dataset_id: str,
    *,
    dataset_split: str | None = None,
    document: dict[str, Any] | None = None,
    root: str | Path | None = None,
) -> DatasetBinding:
    """Bind a declared dataset (and optional split) to a bundled evaluation slice.

    ``datasets[<id>].splits[<split>].file`` is authoritative; class names and the
    revision come from the dataset entry (falling back to a bundled model bound
    to the same dataset for class names). Without ``dataset_split`` the split
    named ``test`` is used, else the dataset's only bundled split; several
    bundled splits must be disambiguated by the caller. Flat legacy
    ``models[*].eval_split`` entries are still honoured. Never guesses: every
    failure is a :class:`DatasetBindingError` naming the field.
    """
    dataset_id = (dataset_id or "").strip()
    if not dataset_id:
        raise DatasetBindingError(
            "dataset_id is required: an uploaded model is evaluated on a bundled dataset only"
        )
    if document is None:
        document = read_asset_manifest(root)
    requested = (dataset_split or "").strip() or None
    models = _model_entries(document)
    datasets = _dataset_entries(document)
    entry = datasets.get(dataset_id)

    if entry is not None:
        splits = _bundled_splits(entry)
        if splits:
            try:
                split_name = _select_split(dataset_id, splits, requested)
            except DatasetBindingError:
                legacy = _legacy_binding(dataset_id, requested, models)
                if legacy is not None:
                    return legacy
                raise
            file_entry = splits[split_name]["file"]
            class_names = [str(value) for value in (entry.get("class_names") or [])]
            if not class_names:
                for model in models:
                    names = model.get("class_names")
                    if _entry_dataset_id(model) == dataset_id and isinstance(names, list) and names:
                        class_names = [str(value) for value in names]
                        break
            if not class_names:
                raise DatasetBindingError(
                    f"dataset {dataset_id!r} records no class names; an upload cannot be bound to it"
                )
            digest = file_entry.get("sha256")
            revision = entry.get("revision")
            return DatasetBinding(
                dataset_id=dataset_id,
                split=split_name,
                file_path=str(file_entry["path"]),
                file_sha256=str(digest) if isinstance(digest, str) and digest else None,
                class_names=class_names,
                revision=None if revision is None else str(revision),
                modality=_dataset_modality(entry, dataset_id, models),
                fixture_only=bool(entry.get("fixture_only", False)),
            )

    legacy = _legacy_binding(dataset_id, requested, models)
    if legacy is not None:
        return legacy
    if entry is None:
        raise DatasetBindingError(
            f"unknown bundled dataset {dataset_id!r}; bundled datasets: {sorted(datasets) or 'none'}"
        )
    raise DatasetBindingError(
        f"dataset {dataset_id!r} has no bundled evaluation split"
        + (f" named {requested!r}" if requested else ""),
        field="dataset_split" if requested else "dataset_id",
    )


def check_upload_dataset(
    dataset_id: str,
    *,
    modality: str,
    dataset_split: str | None = None,
    document: dict[str, Any] | None = None,
    root: str | Path | None = None,
) -> DatasetBinding:
    """The static compatibility check the API runs before any byte is persisted.

    Confirms the dataset is bundled, has an evaluation split, and (when the
    manifest records one) is of the declared modality. Shape and class-count
    checks against the model stay on the worker inside the sandbox.
    """
    binding = resolve_dataset_binding(dataset_id, dataset_split=dataset_split, document=document, root=root)
    if binding.modality is not None and binding.modality != modality:
        raise DatasetBindingError(
            f"dataset {binding.dataset_id!r} is a {binding.modality} dataset; "
            f"the upload declares modality {modality!r}",
            field="dataset_id",
        )
    return binding


# ---------------------------------------------------------------------------
# Worker side: materialize uploaded bytes and bind them to the evaluation slice
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evaluation_binding(
    dataset_id: str,
    *,
    dataset_split: str | None,
) -> tuple[Path, list[str], str | None, str]:
    """Resolve a declared upload dataset to a confined, digest-verified bundled eval split.

    Returns ``(split file path, class names, dataset revision, split name)``.
    """
    from redsim.ml.errors import UnsupportedArtifact
    from redsim.ml.targets.bundled import assets_dir, resolve_asset_path

    root = assets_dir()
    try:
        binding = resolve_dataset_binding(dataset_id, dataset_split=dataset_split, root=root)
    except DatasetBindingError as exc:
        raise UnsupportedArtifact(f"dataset_incompatible: {exc}") from exc
    path = resolve_asset_path(root, binding.file_path)
    if not path.is_file():
        raise UnsupportedArtifact(
            f"dataset_incompatible: bundled split file {binding.file_path!r} is missing under {root}"
        )
    if binding.file_sha256 is not None:
        actual = _sha256_file(path)
        if actual != binding.file_sha256.strip().lower():
            raise UnsupportedArtifact(
                f"dataset_incompatible: bundled split {binding.file_path!r} has sha256 {actual}, "
                f"manifest says {binding.file_sha256}"
            )
    return path, binding.class_names, binding.revision, binding.split


def artifact_target_from_path(
    target_id: str,
    path: Path,
    detail: dict[str, Any],
) -> ArtifactTarget:
    """Build an uploaded target around already-confined model bytes."""
    from redsim.ml.targets.artifact import ArtifactTarget

    manifest = (
        dict(detail["manifest"])
        if isinstance(detail.get("manifest"), dict)
        else dict(detail)
    )
    declared_format = str(manifest.get("format") or detail.get("format") or "")
    dataset_id = str(manifest.get("dataset_id") or "")
    dataset_split = str(manifest.get("dataset_split") or "").strip() or None
    eval_path, class_names, dataset_revision, resolved_split = _evaluation_binding(
        dataset_id, dataset_split=dataset_split,
    )
    return ArtifactTarget(
        target_id,
        path,
        class_names=class_names,
        eval_data=eval_path,
        dataset_id=dataset_id,
        declared_format=declared_format,
        expected_sha256=str(manifest.get("sha256") or "") or None,
        architecture_id=manifest.get("architecture_id"),
        architecture_kwargs=dict(manifest.get("architecture_kwargs") or {}),
        input_shape=tuple(manifest.get("input_shape") or ()) or None,
        name=str(manifest.get("name") or target_id),
        domain=cast("Domain", str(manifest.get("modality") or "image")),
        dataset_split=resolved_split,
        dataset_revision=(
            str(manifest.get("dataset_revision"))
            if manifest.get("dataset_revision") is not None
            else dataset_revision
        ),
        license=manifest.get("license"),
    )


@contextmanager
def uploaded_model_file(
    target: Target,
    blob_store: BlobStore,
) -> Iterator[tuple[Path, dict[str, Any]]]:
    """Materialize opaque uploaded bytes without deserializing them."""
    detail = dict(target.detail or {})
    manifest = (
        dict(detail["manifest"])
        if isinstance(detail.get("manifest"), dict)
        else dict(detail)
    )
    declared_format = str(manifest.get("format") or detail.get("format") or "")
    suffix = {
        "onnx": ".onnx",
        "torch_state_dict": ".pt",
        "safetensors_state_dict": ".safetensors",
    }.get(declared_format, Path(str(detail.get("original_filename") or "")).suffix)
    data = blob_store.get(str(target.value))
    fd, raw_path = tempfile.mkstemp(prefix="redsim-model-", suffix=suffix)
    path = Path(raw_path)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        yield path, detail
    finally:
        path.unlink(missing_ok=True)


@contextmanager
def uploaded_target(target: Target, blob_store: BlobStore) -> Iterator[ArtifactTarget]:
    """Yield an ArtifactTarget for callers already isolated from API processes."""
    with uploaded_model_file(target, blob_store) as (path, detail):
        yield artifact_target_from_path(target.id, path, detail)


# ---------------------------------------------------------------------------
# Soft delete (``DELETE /v1/models/{id}``)
# ---------------------------------------------------------------------------


def is_deleted(detail: Any) -> bool:
    """True for a soft-deleted model target (``detail.status == "deleted"``)."""
    return isinstance(detail, dict) and detail.get("status") == DELETED_STATUS


def _delete_blob(store: Any, location: str) -> bool:
    """Best-effort removal of one content-addressed blob; ``False`` when it stays.

    ``BlobStore`` has no delete operation, so the backends are handled by
    shape: an explicit ``delete``, the S3 client of ``S3BlobStore``, or the
    ``base`` directory of ``FilesystemBlobStore`` (only files under it are
    ever unlinked). Anything else is logged and retained, never pretended.
    """
    try:
        delete = getattr(store, "delete", None)
        if callable(delete):
            delete(location)
            return True
        client, bucket = getattr(store, "client", None), getattr(store, "bucket", None)
        if client is not None and bucket:
            key = location.split("/", 3)[3] if location.startswith("s3://") else location
            client.delete_object(Bucket=bucket, Key=key)
            return True
        base = getattr(store, "base", None)
        if base is not None:
            base_r = Path(base).resolve()
            digest = Path(location).name
            for candidate in (Path(base) / digest[:2] / digest, Path(location), Path(base) / location):
                resolved = candidate.resolve()
                if resolved != base_r and base_r in resolved.parents and resolved.is_file():
                    resolved.unlink()
                    return True
            logger.warning("model blob %s is not a file under the blob root %s; nothing removed",
                           location, base_r)
            return False
    except Exception:  # noqa: BLE001 - the row is already marked deleted; report, do not fake
        logger.warning("model blob %s could not be deleted", location, exc_info=True)
        return False
    logger.warning("blob store %s has no delete operation; model blob %s is retained",
                   type(store).__name__, location)
    return False


def delete_model_target(
    *,
    target_id: str,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
    blob_store: BlobStore | None = None,
) -> dict[str, Any]:
    """Admission boundary for ``DELETE /v1/models/{id}``: audit first, then soft delete.

    Raises ``LookupError`` (``model_not_found``) for an unknown, non-ML or
    already deleted target and ``ValueError("campaign_in_flight: ...")`` while
    a Run on the model is queued or running. Historical Run, Job, Finding,
    Artifact, ``ml_campaigns`` and audit rows are untouched. The blob is
    removed unless another live model target shares the same bytes; the
    outcome is reported in ``blob_deleted`` (``None`` for bundled targets,
    whose assets are shared and never deleted here).
    """
    from sqlalchemy import select

    from redsim.db.models import Run, Target
    from redsim.db.session import get_session
    from redsim.safety import authorize

    with get_session() as sess:
        target = sess.get(Target, target_id)
        if target is None or target.kind not in ML_KINDS or is_deleted(target.detail):
            raise LookupError(f"model_not_found: model not found: {target_id}")
        active = sess.execute(
            select(Run.id).where(
                Run.target_id == target_id, Run.status.in_(["queued", "running"]),
            ).limit(1)
        ).first()
        if active is not None:
            raise ValueError(
                f"campaign_in_flight: run {active[0]} on model {target_id} is queued or running"
            )
        project_id, kind, value = target.project_id, target.kind, str(target.value)
        detail = dict(target.detail or {})
        siblings = sess.execute(
            select(Target).where(
                Target.value == target.value, Target.id != target_id, Target.kind.in_(ML_KINDS),
            )
        ).scalars().all()
        blob_shared = any(not is_deleted(row.detail) for row in siblings)

    manifest_value = detail.get("manifest")
    manifest: dict[str, Any] = manifest_value if isinstance(manifest_value, dict) else {}
    bundled = value.startswith("bundled:") or detail.get("source") == "bundled"
    source = detail.get("source") or ("bundled" if bundled else "upload")
    previous_status = detail.get("status") or manifest.get("status")

    # The chained event precedes the row change (spec 6.7 invariant 4). ML
    # targets are in-boundary artifacts, not network locations: target=None
    # records allowlist_check "n/a", as model.register does.
    authorize(
        "target.manage",
        None,
        allowlist=config.target_allowlist,
        actor=actor,
        writer=audit_writer,
        project_id=project_id,
        detail={
            "actor": actor,
            "op": "delete",
            "kind": kind,
            "target_id": target_id,
            "value": value,
            "source": source,
            "sha256": detail.get("sha256") or manifest.get("sha256"),
            "previous_status": previous_status,
            "soft_delete": True,
            "blob_shared": blob_shared,
        },
    )

    deleted_at = datetime.now(UTC).isoformat()
    with get_session() as sess:
        target = sess.get(Target, target_id)
        if target is None:
            raise LookupError(f"model_not_found: model not found: {target_id}")
        target.detail = {
            **detail,
            "status": DELETED_STATUS,
            "previous_status": previous_status,
            "deleted_at": deleted_at,
            "deleted_by": actor,
        }
        sess.add(target)

    blob_deleted: bool | None = None
    if not bundled:
        if blob_shared:
            blob_deleted = False
            logger.info("delete_model_target target_id=%s blob %s shared with another live model; retained",
                        target_id, value)
        else:
            if blob_store is None:
                from redsim.storage.blobs import open_blob_store

                blob_store = open_blob_store()
            blob_deleted = _delete_blob(blob_store, value)
    logger.info("delete_model_target project_id=%s target_id=%s kind=%s blob_deleted=%s",
                project_id, target_id, kind, blob_deleted)
    return {
        "deleted": target_id,
        "project_id": project_id,
        "status": DELETED_STATUS,
        "deleted_at": deleted_at,
        "blob_deleted": blob_deleted,
    }


__all__ = [
    "DELETED_STATUS",
    "ML_KINDS",
    "DatasetBinding",
    "DatasetBindingError",
    "artifact_target_from_path",
    "check_upload_dataset",
    "delete_model_target",
    "is_deleted",
    "read_asset_manifest",
    "resolve_dataset_binding",
    "uploaded_model_file",
    "uploaded_target",
]
