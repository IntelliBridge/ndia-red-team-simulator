"""Honest, secret-free ML feature roster."""

from __future__ import annotations

import importlib.util
import os
from typing import Any

from fastapi import APIRouter, Depends

from redsim.api.auth import CurrentUser, get_current_user

router = APIRouter(prefix="/ml", tags=["ml-capabilities"])


@router.get("/capabilities")
def capabilities(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    model = os.environ.get("REDSIM_ML_LLM_MODEL", "").strip() or None
    pythia_ready = bool(
        model
        and os.environ.get("PYTHIA_BASE_URL", "").strip()
        and os.environ.get("PYTHIA_API_KEY", "").strip()
    )
    try:
        from redsim.ml.targets.artifact import architecture_ids

        architectures: list[str] = architecture_ids()
    except ImportError:
        architectures = []
    try:
        from redsim.ml.defenses import list_defenses

        defense_ids = [str(row["id"]) for row in list_defenses()]
    except ImportError:
        defense_ids = []
    try:
        from redsim.ml.targets import list_targets

        bundled = [
            {"id": item.id, "name": item.name, "modality": item.domain}
            for item in list_targets()
            if item.metadata.get("source") == "bundled" and not item.metadata.get("fixture_only")
        ]
    except ImportError:
        bundled = []
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
        "upload_formats": ["onnx", "torch_state_dict", "safetensors_state_dict"],
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
        "worker_ml_extra": all(importlib.util.find_spec(name) is not None for name in ("numpy", "torch", "art")),
        "sandbox_enabled": os.environ.get("REDSIM_PLUGINS_SANDBOX", "1").lower() not in {"0", "false", "no"},
        "endpoint_connector": {
            "status": "not_implemented",
            "reason": "black-box model endpoints are Phase B",
            "phase": "B",
        },
        "bundled_models": bundled,
    }