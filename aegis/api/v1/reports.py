"""Report streaming routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse

from aegis.api.auth import CurrentUser, get_current_user
from aegis.config import load_config

router = APIRouter(prefix="/runs", tags=["reports"])

_CONTENT_TYPES = {
    "md": "text/markdown",
    "json": "application/json",
    "html": "text/html",
}


@router.get("/{run_id}/report.{ext}")
def get_report(run_id: str, ext: str,
               user: CurrentUser = Depends(get_current_user)):
    if ext not in _CONTENT_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="ext must be one of md|json|html")
    config = load_config()
    path = Path(config.output_dir) / "runs" / run_id / f"report.{ext}"
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="report not yet rendered")
    return FileResponse(path, media_type=_CONTENT_TYPES[ext])
