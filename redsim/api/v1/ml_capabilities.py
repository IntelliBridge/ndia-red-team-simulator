"""Honest, secret-free ML feature roster (spec 17.2 ``GET /v1/ml/capabilities``).

The response names what this deployment can do so the web app renders honest
disabled states (spec 18.5). It never carries the Pythia key or base URL: the
``llm_narrative`` block says whether the gateway is configured, which model
would be routed and whether a persona is set, nothing more.

``sandbox_enabled`` is always ``True``: the ML model sandbox has no switch
(spec 9.4, "there is no in-process path for model bytes; REDSIM_PLUGINS_SANDBOX=0
has no effect on ML"). The architecture list is the loader allowlist of
``redsim.ml.targets.artifact`` (canonical ids and their aliases), which mirrors
``redsim.ml.targets.architectures`` without importing torch.
"""

from __future__ import annotations

import importlib.util
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from redsim.api.auth import CurrentUser, get_current_user

router = APIRouter(prefix="/ml", tags=["ml-capabilities"])

#: Operational 503 the catalog routes share when a registry cannot be imported in
#: this process. Not a spec 17.3 admission code (the table has no import-failure
#: row), so it is spelled once here and reused by every catalog route.
ML_CATALOG_UNAVAILABLE = "ml_catalog_unavailable"

#: Formats an upload may declare (spec 9.2, 17.2). Bundled-only formats are not here.
UPLOAD_FORMATS: tuple[str, ...] = ("onnx", "torch_state_dict", "safetensors_state_dict")

#: ``REDSIM_ML_UPLOAD_MAX_MB`` default (spec 9.3 step 2).
DEFAULT_UPLOAD_MAX_MB = 512


def upload_max_bytes() -> int:
    """The streaming upload cap in bytes (``REDSIM_ML_UPLOAD_MAX_MB``, default 512)."""
    raw = os.environ.get("REDSIM_ML_UPLOAD_MAX_MB", "").strip()
    try:
        megabytes = int(raw) if raw else DEFAULT_UPLOAD_MAX_MB
    except ValueError:
        megabytes = DEFAULT_UPLOAD_MAX_MB
    return max(megabytes, 1) * 1024 * 1024


def catalog_unavailable(exc: ImportError | str, what: str) -> HTTPException:
    """A catalog registry could not be imported in this API process.

    The roster is only honest when it comes from the registries, so this is a
    503 with the ImportError text rather than a ``200`` with empty lists.
    """
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail={
        "code": ML_CATALOG_UNAVAILABLE,
        "message": f"{what} catalog is unavailable in this API process",
        "reason": str(exc),
    })


def architecture_allowlist() -> list[str]:
    """Accepted ``architecture_id`` spellings; ``ImportError`` when the loader module is absent."""
    from redsim.ml.targets.artifact import architecture_ids

    return list(architecture_ids())


@router.get("/capabilities")
def capabilities(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    model = os.environ.get("REDSIM_ML_LLM_MODEL", "").strip() or None
    pythia_ready = bool(
        model
        and os.environ.get("PYTHIA_BASE_URL", "").strip()
        and os.environ.get("PYTHIA_API_KEY", "").strip()
    )
    try:
        architectures = architecture_allowlist()
    except ImportError as exc:
        raise catalog_unavailable(exc, "architecture") from exc
    try:
        from redsim.ml.defenses import list_defenses

        defense_ids = [str(row["id"]) for row in list_defenses()]
    except ImportError as exc:
        raise catalog_unavailable(exc, "defense") from exc
    try:
        from redsim.ml.targets import list_targets

        bundled = [
            {"id": item.id, "name": item.name, "modality": item.domain, "status": item.status,
             **({"reason": item.reason} if item.reason else {})}
            for item in list_targets()
            if item.metadata.get("source") == "bundled" and not item.metadata.get("fixture_only")
        ]
    except ImportError as exc:
        raise catalog_unavailable(exc, "bundled model") from exc
    return {
        "modalities": {
            "image": {"status": "available", "phase": "A"},
            "tabular": {"status": "available", "phase": "A"},
            "llm": {"status": "not_implemented", "phase": "B",
                    "reason": "LLM and endpoint red-teaming is Phase B"},
            "text": {"status": "not_implemented", "phase": "B",
                     "reason": "text red-teaming is Phase B"},
            "detection": {"status": "not_implemented", "phase": "B",
                          "reason": "object-detection red-teaming is Phase B"},
        },
        "upload_formats": list(UPLOAD_FORMATS),
        "upload_max_mb": upload_max_bytes() // (1024 * 1024),
        "pickle_accepted": False,
        "architectures": architectures,
        "explainers": {"image": "shap", "tabular": "shap"},
        "defenses": defense_ids,
        "llm_narrative": {
            "configured": pythia_ready,
            "gateway": "pythia",
            "model": model,
            "persona_set": bool(os.environ.get("PYTHIA_PERSONA", "").strip()),
            **({} if pythia_ready else {"reason": "Pythia credentials and an ML narrative model are required"}),
        },
        # What this process can see; the worker image is where the extra must be installed.
        "worker_ml_extra": all(importlib.util.find_spec(name) is not None for name in ("numpy", "torch", "art")),
        # The ML sandbox cannot be switched off (spec 9.4): model bytes are only ever opened in the child.
        "sandbox_enabled": True,
        "endpoint_connector": {
            "status": "not_implemented",
            "reason": "black-box model endpoints are Phase B",
            "phase": "B",
        },
        "bundled_models": bundled,
    }
