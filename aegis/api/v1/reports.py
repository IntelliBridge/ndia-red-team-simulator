"""Report streaming routes.

Phase 4 v0.3.1 F12: every read enforces project-access via
``ensure_run_access``. Bodies are served from the blob store when one
is configured (``AEGIS_BLOB_BACKEND`` / ``AEGIS_DB_URL``), with a
filesystem fallback for the offline / Phase 2 path. v0.4.0 hardens
the HTML response with CSP + escaping in F14d; this module is the
project-access layer only.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import FileResponse

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import ensure_run_access
from aegis.config import load_config

router = APIRouter(prefix="/runs", tags=["reports"])

_CONTENT_TYPES = {
    "md": "text/markdown",
    "json": "application/json",
    "html": "text/html",
}


def _blob_key(run_id: str, ext: str) -> str:
    return f"runs/{run_id}/report.{ext}"


@router.get("/{run_id}/report.{ext}")
def get_report(run_id: str, ext: str,
               user: CurrentUser = Depends(get_current_user)):
    if ext not in _CONTENT_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="ext must be one of md|json|html")
    # F12: project-access gate (also yields 404 for unknown runs).
    ensure_run_access(user, run_id)

    config = load_config()

    # Prefer the blob store when one is configured. Phase 2 / offline
    # callers still have the filesystem path; the worker writes both
    # destinations when a blob backend is wired in.
    try:
        from aegis.blobs import open_blob_store
        blob = open_blob_store(config)
        data = blob.get(_blob_key(run_id, ext))
        return Response(content=data, media_type=_CONTENT_TYPES[ext])
    except (FileNotFoundError, KeyError):
        pass
    except Exception:  # noqa: BLE001 — blob backend not available, try fs
        pass

    path = Path(config.output_dir) / "runs" / run_id / f"report.{ext}"
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="report not yet rendered")
    return FileResponse(path, media_type=_CONTENT_TYPES[ext])
