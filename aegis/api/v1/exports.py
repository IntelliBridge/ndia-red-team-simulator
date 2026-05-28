"""Vulnfixer JSON export streaming."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.config import load_config

router = APIRouter(prefix="/runs", tags=["exports"])


@router.get("/{run_id}/exports/vulnfixer")
def vulnfixer_export(run_id: str,
                     user: CurrentUser = Depends(get_current_user)) -> dict:
    config = load_config()
    path = Path(config.output_dir) / "runs" / run_id / "vulnfixer-export.json"
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="vulnfixer export not produced for this run")
    return json.loads(path.read_text())
