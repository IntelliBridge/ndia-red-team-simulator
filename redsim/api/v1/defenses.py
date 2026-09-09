"""ART defense catalog (spec 17.2 ``GET /v1/defenses``); importing this router does not import ART.

Every row is the catalog's own (``redsim.ml.defenses.list_defenses``): ``kind``
(``preprocessing`` / ``training``), ``phase`` (``A`` for the Phase A preprocessors,
``B`` for the training defenses that landed with plan 12) and ``status`` are read
from the row and never stamped here, so a training row says ``phase: "B"`` and a
future row that is catalogued but not runnable can say so. ``modalities`` is the
row's ``domains`` under the API's name and ``params_schema`` is JSON.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.v1.ml_capabilities import catalog_unavailable

router = APIRouter(prefix="/defenses", tags=["ml-defenses"])

#: What a catalog row without an explicit ``status`` is: every row of ``redsim.ml.defenses.ALL_DEFENSES``
#: has an implementation (``build_preprocessor`` / ``redsim.ml.harden``); a row that is catalogued but not
#: runnable must carry its own ``status`` and ``reason``.
DEFAULT_STATUS = "available"
#: Rows predating the ``phase`` key are Phase A preprocessors.
DEFAULT_PHASE = "A"


def _projection(row: dict[str, Any]) -> dict[str, Any]:
    out = {
        **row,
        "modalities": list(row.get("domains", [])),
        "params_schema": [
            p.model_dump(mode="json", exclude_none=True) if hasattr(p, "model_dump") else p
            for p in row.get("params_schema", [])
        ],
        "phase": str(row.get("phase") or DEFAULT_PHASE),
        "status": str(row.get("status") or DEFAULT_STATUS),
    }
    out.pop("domains", None)
    return out


@router.get("")
def list_defense_catalog(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    try:
        from redsim.ml.defenses import list_defenses

        source = list_defenses()
    except ImportError as exc:
        # 503 with the reason, never an empty 200 (review #22 F2).
        raise catalog_unavailable(exc, "defense") from exc
    defenses = [_projection(row) for row in source]
    return {"defenses": defenses, "count": len(defenses)}
