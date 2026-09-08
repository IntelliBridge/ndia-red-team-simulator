"""ART defense catalog; importing this router does not import ART."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from redsim.api.auth import CurrentUser, get_current_user

router = APIRouter(prefix="/defenses", tags=["ml-defenses"])


def _catalog_unavailable(exc: ImportError) -> HTTPException:
    """The defense registry could not be imported in this API process: 503, never an empty ``200``."""
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail={
        "code": "ml_catalog_unavailable",
        "message": "defense catalog is unavailable in this API process",
        "reason": str(exc),
    })


@router.get("")
def list_defense_catalog(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    try:
        from redsim.ml.defenses import list_defenses

        source = list_defenses()
    except ImportError as exc:
        raise _catalog_unavailable(exc) from exc
    defenses = [{
        **row,
        "modalities": list(row.get("domains", [])),
        "params_schema": [
            p.model_dump(mode="json", exclude_none=True) if hasattr(p, "model_dump") else p
            for p in row.get("params_schema", [])
        ],
        "phase": "A",
        "status": "available",
    } for row in source]
    for row in defenses:
        row.pop("domains", None)
    return {"defenses": defenses, "count": len(defenses)}