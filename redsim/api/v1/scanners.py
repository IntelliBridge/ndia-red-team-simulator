"""GET /v1/scanners — the registered scanner / attack adapter roster."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from redsim.api.auth import CurrentUser, get_current_user

router = APIRouter(prefix="/scanners", tags=["scanners"])


@router.get("")
def list_registered_scanners(
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Names + capabilities of every adapter in the scanner registry.

    Drives the web UI's scanner picker so clients never hardcode adapter names.
    The pentest built-ins were removed with the pentest domain; until an
    adversarial-ML attack adapter (``redsim.ml.attacks``) or a signed plugin
    registers, the roster is empty and clients must render an explicit
    "no adapter registered" state rather than offer a scan that
    ``POST /v1/scans`` would reject with 400.
    """
    from redsim.scanners import get, list_scanners

    scanners = []
    for name in list_scanners():
        adapter = get(name)
        scanners.append({
            "name": name,
            "capabilities": sorted(getattr(adapter, "capabilities", None) or []),
        })
    return {"scanners": scanners, "count": len(scanners)}
