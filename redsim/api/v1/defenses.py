"""ART defense catalog; importing this router does not import ART."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from redsim.api.auth import CurrentUser, get_current_user

router = APIRouter(prefix="/defenses", tags=["ml-defenses"])


@router.get("")
def list_defense_catalog(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    try:
        from redsim.ml.defenses import list_defenses

        source = list_defenses()
    except ImportError:
        source = []
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