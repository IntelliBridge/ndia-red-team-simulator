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

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import FileResponse

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import ensure_run_access
from redsim.api.security_headers import (
    html_report_headers,
    non_html_report_headers,
)
from redsim.config import load_config

router = APIRouter(prefix="/runs", tags=["reports"])

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
    ensure_run_access(user, run_id)

    config = load_config()
    headers = _report_headers(run_id, ext)

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
    except Exception:  # noqa: BLE001 — blob backend not available, try fs
        pass

    path = Path(config.output_dir) / "runs" / run_id / f"report.{ext}"
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="report not yet rendered")
    return FileResponse(path, media_type=_CONTENT_TYPES[ext], headers=headers)
