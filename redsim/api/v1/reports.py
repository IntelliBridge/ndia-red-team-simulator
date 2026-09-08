"""Report streaming routes.

Phase 4 v0.4.0 F14d layers CSP + nosniff + Content-Disposition on top
of the F12 project-access gate. HTML responses carry the strict
``default-src 'none'`` policy from
``redsim.api.security_headers.REPORT_CSP``; JSON / Markdown responses
land as downloads with nosniff. The renderer itself escapes every
interpolation (see ``redsim.report.render_inline_markdown``), so an injected
``<script>…</script>`` payload in finding evidence is double-defended:
escaped before write, and would be blocked at the browser by CSP if
it ever reached the document.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import FileResponse

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import Action, check, ensure_run_access
from redsim.api.security_headers import (
    html_report_headers,
    non_html_report_headers,
)
from redsim.config import load_config

router = APIRouter(prefix="/runs", tags=["reports"])
logger = logging.getLogger(__name__)

_CONTENT_TYPES = {
    "md": "text/markdown",
    "json": "application/json",
    "html": "text/html",
}


def _blob_key(run_id: str, ext: str) -> str:
    return f"runs/{run_id}/report.{ext}"


def _report_headers(run_id: str, ext: str) -> dict[str, str]:
    if ext == "html":
        return html_report_headers()
    return non_html_report_headers(filename=f"redsim-{run_id}-report.{ext}")


@router.get("/{run_id}/report.{ext}")
def get_report(run_id: str, ext: str,
               user: CurrentUser = Depends(get_current_user)) -> Response:
    if ext not in _CONTENT_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="ext must be one of md|json|html")
    # F12: project-access gate (also yields 404 for unknown runs).
    project_id = ensure_run_access(user, run_id)
    check(user, Action.REPORT_EXPORT, project_id)

    config = load_config()
    headers = _report_headers(run_id, ext)

    # ML campaign reports are authoritative Artifact rows. Their locations are
    # opaque blob references, not the legacy runs/<id>/report.<ext> key.
    try:
        from sqlalchemy import select

        from redsim.db.models import Artifact
        from redsim.db.session import get_session
        from redsim.storage.blobs import open_blob_store

        with get_session() as sess:
            artifact = sess.execute(select(Artifact).where(
                Artifact.run_id == run_id,
                Artifact.project_id == project_id,
                Artifact.kind == f"ml.report_{ext}",
            )).scalar_one_or_none()
            location = str(artifact.location) if artifact is not None else None
            expected = str(artifact.sha256) if artifact is not None else None
        if location and expected:
            data = open_blob_store().get(location)
            raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
            import hashlib
            if hashlib.sha256(raw).hexdigest() != expected:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="report artifact digest mismatch",
                )
            return Response(
                content=raw, media_type=_CONTENT_TYPES[ext], headers=headers
            )
    except HTTPException:
        raise
    except Exception:
        logger.debug("artifact-backed ML report lookup failed", exc_info=True)

    # Prefer the blob store when one is configured. Phase 2 / offline
    # callers still have the filesystem path; the worker writes both
    # destinations when a blob backend is wired in.
    try:
        from redsim.storage import open_blob_store
        blob = open_blob_store(config)
        data = blob.get(_blob_key(run_id, ext))
        return Response(content=data, media_type=_CONTENT_TYPES[ext],
                        headers=headers)
    except (FileNotFoundError, KeyError):
        pass
    except Exception:  # blob backend not available, try fs
        logger.debug("blob-backed report lookup failed; trying filesystem", exc_info=True)

    path = Path(config.output_dir) / "runs" / run_id / f"report.{ext}"
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="report not yet rendered")
    return FileResponse(path, media_type=_CONTENT_TYPES[ext], headers=headers)
