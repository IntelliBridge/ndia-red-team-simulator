"""Honest, secret-free ML feature roster (spec 17.2 ``GET /v1/ml/capabilities``).

The response names what this deployment can do so the web app renders honest
disabled states (spec 18.5). It never carries the Pythia key or base URL: the
``llm_narrative`` block says whether the gateway is configured, which model
would be routed and whether a persona is set, nothing more.

Every Phase B block is read from the tree, never asserted (spec 26.24: a path
is ``available`` only when it runs, ``not_implemented`` with a reason
otherwise): ``text`` and ``detection`` are available when their runner module
imports and the attack registry carries an adapter tagged ``modality:<m>``;
``llm`` when the probe routes are mounted and the committed probe catalog
loads; ``endpoint_connector`` when the ``endpoint-v1`` contract module imports,
and its block carries the contract summary. ``explainers`` names the method per
modality and ``explainer_roster`` the SHAP explainer classes per modality from
``redsim.ml.explain.base`` (object detection has no explainer and says so).
``interop`` is the spec 27 block: dataset export and consume, the pinned ATLAS
release and the integrations roster (statuses and booleans, never a host).

``sandbox_enabled`` is always ``True``: the ML model sandbox has no switch
(spec 9.4, "there is no in-process path for model bytes; REDSIM_PLUGINS_SANDBOX=0
has no effect on ML"). The architecture list is the loader allowlist of
``redsim.ml.targets.artifact`` (canonical ids and their aliases), which mirrors
``redsim.ml.targets.architectures`` without importing torch. Nothing here
imports torch, ART, ONNX or SHAP: the registries and roster modules the route
reads are the light ones the API process already serves.
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

#: Phase B classification-style modalities: the runner module that must import and the capability tag
#: at least one registered attack must carry for the modality to be admitted end to end (wave B1/B2).
PHASE_B_MODALITIES: dict[str, tuple[str, str]] = {
    "text": ("redsim.ml.runners.text", "modality:text"),
    "detection": ("redsim.ml.runners.detection", "modality:detection"),
}

#: The explainer method per modality, read from the explainer modules on the tree (spec 13, MODALITIES).
EXPLAINER_MODULES: dict[str, str] = {
    "image": "redsim.ml.explain.shap_image",
    "tabular": "redsim.ml.explain.shap_tabular",
    "text": "redsim.ml.explain.shap_text",
}
#: Why object detection has no explainer (the detection runner records box evidence instead).
DETECTION_EXPLAINER_REASON = ("no SHAP explainer for object detectors; the detection runner records box evidence "
                              "(boxes.json) and S_expl has no input, so the detection MRI is never complete")


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


def _module_present(name: str) -> bool:
    """Whether ``name`` can be imported here, without importing it (a blocked parent package is absent)."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _attack_tags() -> dict[str, list[str]]:
    """``{attack_id: capability tags}`` from the registry; ``ImportError`` propagates to the caller."""
    from redsim.ml.attacks import list_attack_capabilities

    return list_attack_capabilities()


def modality_rows(tags_by_id: dict[str, list[str]]) -> dict[str, dict[str, Any]]:
    """The ``modalities`` block: Phase A rows fixed, Phase B rows read from the runner modules and the tags."""
    rows: dict[str, dict[str, Any]] = {
        "image": {"status": "available", "phase": "A"},
        "tabular": {"status": "available", "phase": "A"},
    }
    for modality, (runner, tag) in PHASE_B_MODALITIES.items():
        attacks = sorted(attack_id for attack_id, tags in tags_by_id.items() if tag in tags)
        runner_present = _module_present(runner)
        if runner_present and attacks:
            rows[modality] = {"status": "available", "phase": "B", "runner": runner, "attacks": attacks,
                              "explainer": EXPLAINER_MODULES.get(modality)}
            continue
        reasons = []
        if not runner_present:
            reasons.append(f"{runner} is not importable in this deployment")
        if not attacks:
            reasons.append(f"no registered attack carries the {tag} capability tag")
        rows[modality] = {"status": "not_implemented", "phase": "B", "reason": "; ".join(reasons)}
    rows["llm"] = llm_row()
    return rows


def llm_row() -> dict[str, Any]:
    """LLM probes (spec 25): ``available`` when the probe routes are mounted and the committed catalog loads.

    Probe hit rates never enter an MRI and a probe run has no campaign record
    (D9); the row says so. The catalog is pure JSON plus pydantic, so reading it
    here imports no garak.
    """
    if not _module_present("redsim.api.v1.llm"):
        return {"status": "not_implemented", "phase": "B", "reason": "the LLM probe routes are not mounted"}
    try:
        from redsim.ml.llm.catalog import CORE_SET, EXTENDED_SET, load_catalog

        catalog = load_catalog()
    except Exception as exc:  # noqa: BLE001 - a missing or malformed catalog is a reason, never hidden
        return {"status": "not_implemented", "phase": "B",
                "reason": f"probe catalog unavailable: {type(exc).__name__}: {exc}"[:300]}
    return {
        "status": "available", "phase": "B", "kind": "probe",
        "probe_sets": [CORE_SET, EXTENDED_SET],
        "n_probes": len(catalog.probes),
        "garak_version_expected": catalog.garak_version,
        "hf_detectors_enabled": _truthy("REDSIM_LLM_PROBE_HF_DETECTORS"),
        "routes": ["GET /v1/llm/probes", "POST /v1/models/{id}/probes", "GET /v1/runs/{id}/llm-scorecard"],
        "note": ("probe hit rates never enter an MRI; a probe run has no campaign record (D9), so /campaign, "
                 "/compare and /attacks refuse an LLM target with llm_target_required"),
    }


def endpoint_connector(tags_by_id: dict[str, list[str]]) -> dict[str, Any]:
    """The black-box endpoint connector (spec 21, ENDPOINT-02): status plus the ``endpoint-v1`` contract summary."""
    try:
        from redsim.ml.targets.endpoint_contract import MODALITY_INPUT_FORMAT, contract_summary
    except ImportError as exc:
        return {"status": "not_implemented", "phase": "B",
                "reason": f"the endpoint contract module is not importable: {exc}"}
    from redsim.services.ml_models import SUPPORTED_ENDPOINT_AUTH_KINDS

    black_box = sorted(attack_id for attack_id, tags in tags_by_id.items()
                       if "black_box" in tags and "family:control" not in tags
                       and any(tag == f"modality:{m}" for m in MODALITY_INPUT_FORMAT for tag in tags))
    return {
        "status": "available", "phase": "B",
        "registration": "POST /v1/models with source=endpoint (target.manage, admin)",
        "modalities": sorted(MODALITY_INPUT_FORMAT),
        "auth_kinds": sorted(SUPPORTED_ENDPOINT_AUTH_KINDS),
        "gradients": False,
        "attacks": black_box,
        "queries_leave_from": "the worker-parent predict broker only; the sandbox child holds no credential",
        "ownership_verification": {"status": "not_implemented", "phase": "B",
                                   "reason": "no DNS-TXT ownership check (spec 21.7; owner default ENDPOINT-26): "
                                             "the host allowlist, admin RBAC and the audited D3 attestation gate "
                                             "registration"},
        "limits_env": ["REDSIM_ML_ENDPOINT_RPS", "REDSIM_ML_ENDPOINT_BATCH_ROWS", "REDSIM_ML_ENDPOINT_TIMEOUT_S",
                       "REDSIM_ML_ENDPOINT_MAX_ROWS", "REDSIM_ML_ENDPOINT_MAX_REQUESTS"],
        "contract": contract_summary(),
    }


def explainer_blocks() -> tuple[dict[str, str | None], dict[str, Any]]:
    """``explainers`` (method per modality) and ``explainer_roster`` (classes per modality, spec 13.2)."""
    from redsim.ml.explain.base import EXPLAINER_ROSTER

    methods: dict[str, str | None] = {
        modality: ("shap" if _module_present(module) else None) for modality, module in EXPLAINER_MODULES.items()
    }
    methods["detection"] = None
    roster: dict[str, Any] = {key: dict(value) for key, value in EXPLAINER_ROSTER.items()}
    roster.setdefault("text", {})
    roster["text"] = {**roster["text"],
                      "status": "available" if methods["text"] else "not_implemented",
                      "black_box": ["PartitionExplainer (shap.maskers.Text)"], "module": EXPLAINER_MODULES["text"]}
    roster["detection"] = {"status": "not_implemented", "phase": "B", "reason": DETECTION_EXPLAINER_REASON}
    return methods, roster


def interop_block() -> dict[str, Any]:
    """Spec 27: dataset export and consume, the pinned ATLAS release, the integrations roster (no host, no token)."""
    from redsim.config import load_config
    from redsim.integrations import roster
    from redsim.ml.atlas import release_citation
    from redsim.services import ml_datasets

    config = load_config()
    integrations = roster(allowlist=list(getattr(config, "target_allowlist", None) or []))
    return {
        "dataset_export": {
            "status": "available", "phase": "B",
            "route": "POST /v1/runs/{id}/dataset", "read": "GET /v1/datasets/{run_id}",
            "formats": ["croissant-1.0 JSON-LD manifest", "parquet shards (clean, control, adversarial)"],
            "fixture_runs": "refused with fixture_not_exportable (D3)",
        },
        "dataset_consume": {
            "status": "available", "phase": "B",
            "route": "POST /v1/datasets", "read": "GET /v1/datasets and GET /v1/datasets/{id}",
            "formats": ["croissant JSON-LD manifest plus parquet", "parquet with the schema declared in the form"],
            "modalities": list(ml_datasets.SUPPORTED_MODALITIES),
            "not_implemented_modalities": list(ml_datasets.PHASE_B_MODALITIES),
            "upload_max_mb": ml_datasets.upload_max_bytes() // (1024 * 1024),
            "max_rows": ml_datasets.max_rows(),
            "binding": "an available slice of the same project binds a model upload or a campaign (INTEROP-16)",
        },
        "atlas": {"status": "available", "phase": "B",
                  "stamp": "schema_blob.ml.atlas_technique on every new finding; GET /v1/attacks per row",
                  "coverage": "GET /v1/runs/{id}/atlas-coverage", **release_citation()},
        "integrations": integrations["integrations"],
    }


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
        from redsim.ml.targets import list_targets

        bundled = [
            {"id": item.id, "name": item.name, "modality": item.domain, "status": item.status,
             **({"reason": item.reason} if item.reason else {})}
            for item in list_targets()
            if item.metadata.get("source") == "bundled" and not item.metadata.get("fixture_only")
        ]
    except ImportError as exc:
        raise catalog_unavailable(exc, "bundled model") from exc
    try:
        tags_by_id = _attack_tags()
    except ImportError as exc:
        raise catalog_unavailable(exc, "attack") from exc
    try:
        explainers, explainer_roster = explainer_blocks()
    except ImportError as exc:
        raise catalog_unavailable(exc, "explainer") from exc
    try:
        interop = interop_block()
    except ImportError as exc:
        raise catalog_unavailable(exc, "interop") from exc
    return {
        "modalities": modality_rows(tags_by_id),
        "upload_formats": list(UPLOAD_FORMATS),
        "upload_max_mb": upload_max_bytes() // (1024 * 1024),
        "pickle_accepted": False,
        "architectures": architectures,
        "explainers": explainers,
        "explainer_roster": explainer_roster,
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
        "endpoint_connector": endpoint_connector(tags_by_id),
        "interop": interop,
        "bundled_models": bundled,
    }
