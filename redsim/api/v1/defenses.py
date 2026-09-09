"""ART defense catalog (spec 17.2 ``GET /v1/defenses``); importing this router does not import ART."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.v1.ml_capabilities import catalog_unavailable

router = APIRouter(prefix="/defenses", tags=["ml-defenses"])


@router.get("")
def list_defense_catalog(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    try:
        from redsim.ml.defenses import list_defenses

        source = list_defenses()
    except ImportError as exc:
        # 503 with the reason, never an empty 200 (review #22 F2).
        raise catalog_unavailable(exc, "defense") from exc
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
