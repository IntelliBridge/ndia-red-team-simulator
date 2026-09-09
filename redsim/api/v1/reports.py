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

Adversarial-ML campaign reports (spec 14.8, 17.1) are ``Artifact`` rows the
worker writes at run completion and on ``report.render``. This route serves
the newest row for the requested format after checking its bytes against the
recorded digest; ``report.pdf`` is Phase B and answers ``501 not_implemented``.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import FileResponse

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import NOT_IMPLEMENTED, api_error
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

# Spec 17.4: PDF export is Phase B. Named so the route can refuse it honestly.
_PHASE_B_FORMATS = frozenset({"pdf"})


def _blob_key(run_id: str, ext: str) -> str:
    return f"runs/{run_id}/report.{ext}"


def _report_kinds(ext: str) -> tuple[str, str]:
    """Both spellings of the report artifact kind: the spec 5.8 name (``report.md``)
    and the name the worker's artifact sink derives from the file (``ml.report_md``)."""
    return (f"ml.report_{ext}", f"report.{ext}")


def _report_headers(run_id: str, ext: str) -> dict[str, str]:
    if ext == "html":
        return html_report_headers()
    return non_html_report_headers(filename=f"redsim-{run_id}-report.{ext}")


def _artifact_report(run_id: str, project_id: str, ext: str) -> tuple[bytes, str] | None:
    """The newest report artifact's bytes and digest, or ``None`` when no row exists.

    A row whose blob no longer matches its recorded digest is a ``409``: the
    report is evidence and a mismatch is never served as if it were the record.
    """
    from sqlalchemy import select

    from redsim.db.models import Artifact
    from redsim.db.session import get_session
    from redsim.storage.blobs import open_blob_store

    with get_session() as sess:
        artifact = sess.execute(select(Artifact).where(
            Artifact.run_id == run_id,
            Artifact.project_id == project_id,
            Artifact.kind.in_(_report_kinds(ext)),
        ).order_by(Artifact.created_at.desc(), Artifact.id.desc())).scalars().first()
        if artifact is None:
            return None
        location, expected = str(artifact.location), str(artifact.sha256)
    data = open_blob_store().get(location)
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "report_artifact_digest_mismatch",
                    "message": "report artifact bytes do not match the recorded digest"},
        )
    return raw, expected


@router.get("/{run_id}/report.{ext}")
def get_report(run_id: str, ext: str,
               user: CurrentUser = Depends(get_current_user)) -> Response:
    if ext not in _CONTENT_TYPES and ext not in _PHASE_B_FORMATS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="ext must be one of md|json|html")
    # F12: project-access gate (also yields 404 for unknown runs), then the
    # REPORT_EXPORT role check (spec 7.3, 17.1) before any format decision.
    project_id = ensure_run_access(user, run_id)
    check(user, Action.REPORT_EXPORT, project_id)
    if ext in _PHASE_B_FORMATS:
        raise api_error(NOT_IMPLEMENTED, "PDF export is not implemented in Phase A", phase="B",
                        field="ext")

    config = load_config()
    headers = _report_headers(run_id, ext)

    # ML campaign reports are authoritative Artifact rows. Their locations are
    # opaque blob references, not the legacy runs/<id>/report.<ext> key.
    try:
        served = _artifact_report(run_id, project_id, ext)
    except HTTPException:
        raise
    except Exception:
        served = None
        logger.debug("artifact-backed ML report lookup failed", exc_info=True)
    if served is not None:
        raw, digest = served
        return Response(
            content=raw, media_type=_CONTENT_TYPES[ext],
            headers={**headers, "ETag": f'"{digest}"'},
        )

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
