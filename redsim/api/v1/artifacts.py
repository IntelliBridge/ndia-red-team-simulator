"""Tenant-gated artifact listing and blob streaming."""

from __future__ import annotations

from collections.abc import Iterator
from itertools import chain
from pathlib import PurePath
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import ensure_run_access

router = APIRouter(tags=["ml-artifacts"])


def _row(artifact: Any) -> dict[str, Any]:
    return {
        "id": artifact.id, "run_id": artifact.run_id, "project_id": artifact.project_id,
        "kind": artifact.kind, "sha256": artifact.sha256, "content_type": artifact.content_type,
        "size_bytes": artifact.size_bytes, "created_at": artifact.created_at,
    }


@router.get("/runs/{run_id}/artifacts")
def list_run_artifacts(
    run_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    from sqlalchemy import select

    from redsim.db.models import Artifact
    from redsim.db.session import get_session

    ensure_run_access(user, run_id)
    with get_session() as sess:
        rows = sess.execute(select(Artifact).where(Artifact.run_id == run_id)).scalars().all()
        artifacts = [_row(item) for item in rows]
    return {"artifacts": artifacts, "count": len(artifacts)}


@router.get("/artifacts/{artifact_id}")
def get_artifact(
    artifact_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> StreamingResponse:
    from redsim.db.models import Artifact
    from redsim.db.session import get_session
    from redsim.storage.blobs import open_blob_store

    with get_session() as sess:
        artifact = sess.get(Artifact, artifact_id)
        if artifact is None:
            raise HTTPException(status_code=404, detail={
                "code": "artifact_not_found", "message": "artifact not found"})
        record = _row(artifact)
        location = str(artifact.location)
    project_id = ensure_run_access(user, str(record["run_id"]))
    if project_id != record["project_id"]:
        raise HTTPException(status_code=404, detail={
            "code": "artifact_not_found", "message": "artifact not found"})

    # Locations are opaque blob-store references. Refuse relative traversal
    # rather than allowing a filesystem backend to interpret it.
    if not location.startswith("s3://") and ".." in PurePath(location).parts:
        raise HTTPException(status_code=404, detail={
            "code": "artifact_blob_missing", "message": "artifact blob is missing"})
    try:
        store = open_blob_store()
        base = getattr(store, "base", None)
        if base is not None and PurePath(location).is_absolute():
            from pathlib import Path

            root = Path(base).resolve()
            candidate = Path(location).resolve()
            if candidate != root and root not in candidate.parents:
                raise FileNotFoundError(location)
        iterator: Iterator[bytes] = iter(store.stream(location))
        first = next(iterator)
    except Exception:  # noqa: BLE001 - storage backends expose optional error classes
        raise HTTPException(status_code=404, detail={
            "code": "artifact_blob_missing", "message": "artifact blob is missing"}) from None

    content_type = str(record["content_type"] or "application/octet-stream")
    headers = {
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'",
        "ETag": f'"{record["sha256"]}"',
    }
    if content_type != "image/png":
        raw_name = f"{artifact_id}-{PurePath(location).name}"
        filename = "".join(c if c.isalnum() or c in "._-" else "_" for c in raw_name)
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return StreamingResponse(chain((first,), iterator), media_type=content_type, headers=headers)