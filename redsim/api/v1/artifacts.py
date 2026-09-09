"""Tenant-gated artifact listing and blob streaming (spec 17.2).

``GET /v1/artifacts/{id}`` streams the blob with ``X-Content-Type-Options:
nosniff``, ``Content-Security-Policy: default-src 'none'`` and ``ETag`` =
sha256; PNGs are served inline, everything else as an attachment. Unknown ids
and rows whose blob is gone are both 404 (``not_found``); the latter carries
``reason: artifact_blob_missing`` so the UI can say which it was.
"""

from __future__ import annotations

from collections.abc import Iterator
from itertools import chain
from pathlib import PurePath
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import NOT_FOUND, api_error
from redsim.api.policy import ensure_run_access

router = APIRouter(tags=["ml-artifacts"])

#: ``reason`` on the 404 for an Artifact row whose blob cannot be read (spec 17.2).
ARTIFACT_BLOB_MISSING = "artifact_blob_missing"


def _row(artifact: Any) -> dict[str, Any]:
    return {
        "id": artifact.id, "run_id": artifact.run_id, "project_id": artifact.project_id,
        "kind": artifact.kind, "sha256": artifact.sha256, "content_type": artifact.content_type,
        "size_bytes": artifact.size_bytes, "created_at": artifact.created_at,
    }


def _not_found() -> HTTPException:
    return api_error(NOT_FOUND, "artifact not found")


def _blob_missing() -> HTTPException:
    return api_error(NOT_FOUND, "artifact blob is missing", reason=ARTIFACT_BLOB_MISSING)


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
        rows = sess.execute(
            select(Artifact).where(Artifact.run_id == run_id)
            .order_by(Artifact.created_at.desc(), Artifact.id.desc())
        ).scalars().all()
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
            raise _not_found()
        record = _row(artifact)
        location = str(artifact.location)
    project_id = ensure_run_access(user, str(record["run_id"]))
    if project_id != record["project_id"]:
        raise _not_found()

    # Locations are opaque blob-store references. Refuse relative traversal
    # rather than allowing a filesystem backend to interpret it.
    if not location.startswith("s3://") and ".." in PurePath(location).parts:
        raise _blob_missing()
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
        raise _blob_missing() from None

    content_type = str(record["content_type"] or "application/octet-stream")
    headers = {
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'",
        "ETag": f'"{record["sha256"]}"',
        "Cache-Control": "private, no-store",
    }
    if content_type != "image/png":
        raw_name = f"{artifact_id}-{PurePath(location).name}"
        filename = "".join(c if c.isalnum() or c in "._-" else "_" for c in raw_name)
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    else:
        headers["Content-Disposition"] = "inline"
    return StreamingResponse(chain((first,), iterator), media_type=content_type, headers=headers)
