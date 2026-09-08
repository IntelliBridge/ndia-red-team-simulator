"""Worker-side materialization of uploaded ML model targets."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from redsim.db.models import Target
    from redsim.ml.schema import Domain
    from redsim.ml.targets.artifact import ArtifactTarget
    from redsim.storage import BlobStore


def _model_entries(document: dict[str, Any]) -> list[dict[str, Any]]:
    raw = document.get("models")
    if isinstance(raw, dict):
        return [dict(value) for value in raw.values() if isinstance(value, dict)]
    if isinstance(raw, list):
        return [dict(value) for value in raw if isinstance(value, dict)]
    return []


def _evaluation_binding(
    dataset_id: str,
    *,
    dataset_split: str,
) -> tuple[Path, list[str], str | None]:
    """Resolve a declared upload dataset to a confined bundled eval split."""
    from redsim.ml.errors import UnsupportedArtifact
    from redsim.ml.targets.bundled import (
        MANIFEST_NAME,
        assets_dir,
        resolve_asset_path,
    )

    root = assets_dir()
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file():
        raise UnsupportedArtifact(
            f"dataset_incompatible: bundled manifest is missing at {manifest_path}"
        )
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UnsupportedArtifact(
            f"dataset_incompatible: bundled manifest is unreadable: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise UnsupportedArtifact("dataset_incompatible: bundled manifest is not an object")

    for entry in _model_entries(document):
        entry_dataset = entry.get("dataset_id") or entry.get("dataset")
        if entry_dataset != dataset_id:
            continue
        split = entry.get("dataset_split") or entry.get("eval_split_name") or "test"
        if dataset_split and split != dataset_split:
            continue
        relative = entry.get("eval_split")
        class_names = entry.get("class_names")
        if isinstance(relative, str) and isinstance(class_names, list) and class_names:
            return (
                resolve_asset_path(root, relative),
                [str(value) for value in class_names],
                None if entry.get("dataset_revision") is None
                else str(entry["dataset_revision"]),
            )
    raise UnsupportedArtifact(
        f"dataset_incompatible: no bundled {dataset_split!r} evaluation split "
        f"matches dataset {dataset_id!r}"
    )


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
    dataset_split = str(manifest.get("dataset_split") or "test")
    eval_path, class_names, dataset_revision = _evaluation_binding(
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
        dataset_split=dataset_split,
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


__all__ = [
    "artifact_target_from_path",
    "uploaded_model_file",
    "uploaded_target",
]