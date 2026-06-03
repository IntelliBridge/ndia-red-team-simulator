"""Vulnfixer JSON export streaming.

Phase 4 v0.3.1 F12: project-access enforced via ``ensure_run_access``;
body is served from the blob store when available, filesystem fallback
otherwise.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from aegis.api.auth import CurrentUser, get_current_user
from aegis.api.policy import ensure_run_access
from aegis.config import load_config

router = APIRouter(prefix="/runs", tags=["exports"])


@router.get("/{run_id}/exports/vulnfixer")
def vulnfixer_export(run_id: str,
                     user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    ensure_run_access(user, run_id)
    config = load_config()

    try:
        from aegis.storage import open_blob_store
        blob = open_blob_store(config)
        data = blob.get(f"runs/{run_id}/vulnfixer-export.json")
        return json.loads(data.decode("utf-8"))
    except (FileNotFoundError, KeyError):
        pass
    except Exception:  # noqa: BLE001 — blob backend not available
        pass

    path = Path(config.output_dir) / "runs" / run_id / "vulnfixer-export.json"
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="vulnfixer export not produced for this run")
    return json.loads(path.read_text())
