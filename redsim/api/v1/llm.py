"""LLM probe routes (spec 17.4 garak through Pythia; plan 12 wave B2 ``llm-api``; register LLM-12, -13).

* ``GET /v1/llm/probes``: the committed probe catalog (``redsim.ml.llm.catalog``,
  read lazily, never a garak import): probe sets and probes with a ``status`` of
  ``offline`` (string/trigger detectors), ``extended`` (needs a Hugging Face
  detector model, ``detector_mode="hf"``) or ``excluded`` (owner decision) and
  the reason for each. Authenticated. A tree without the llm-core package
  answers ``501 not_implemented`` with the reason, never an empty list.
* ``POST /v1/models/{model_id}/probes``: a probe run against an LLM target.
  ``404`` for an unknown model, membership, the ``llm.probe.run`` gate
  (remediator), then :func:`redsim.services.ml_llm.admit_llm_probe_run`, which
  writes the audit row before the ``Run`` / ``Job`` rows and the enqueue on the
  default queue. Refusals are the 17.3 envelope (``llm_target_required``,
  ``probe_set_unknown``, ``probe_key_required`` and the rest) and every one is
  a ``success=False`` row on the project chain. ``202`` with the JobHandle.
* ``GET /v1/runs/{run_id}/llm-scorecard``: the k/n probe scorecard artifact,
  never an MRI (spec 15.9, D9). Membership; ``409 score_unavailable`` while the
  run is not terminal; ``409 llm_target_required`` for a campaign run.
* ``GET /v1/llm/models``: the Pythia models the configured key is entitled to
  (spec 17.4; register LLM-26), for the web UI's model picker when an LLM
  target is registered. Always ``200``; ``configured=false`` with an empty list
  when ``PYTHIA_*`` is unset, ``error`` (key material stripped) when the gateway
  call fails. Never cached, never the key.

Nothing here imports garak, an OpenAI client or any ML library
(``tests/test_api_process_has_no_ml.py``).
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Body, Depends, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import NOT_FOUND, ApiError, api_error
from redsim.api.policy import Action, check, ensure_project_access, ensure_run_access
from redsim.api.v1.integrations import not_built
from redsim.api.v1.ml_capabilities import catalog_unavailable
from redsim.services.ml_llm import (
    CatalogUnavailable,
    LLMProbeRequest,
    admit_llm_probe_run,
    probe_catalog_response,
    read_llm_scorecard,
)

router = APIRouter(tags=["ml-llm"])

_ML_KINDS = frozenset({"ml_model_artifact", "ml_model_endpoint"})

#: The gate in force: ``Action.LLM_PROBE_RUN`` ("llm.probe.run", remediator; register LLM-25). Kept
#: under the name the wave B0 stub exported so ``tests/ml/test_phase_b_stubs.py`` still resolves it.
LLM_PROBE_RUN: Action = Action.LLM_PROBE_RUN

#: Key material that must never reach a response: ``Authorization: Bearer ...`` header text and
#: ``pk_...`` Pythia key tokens.
_KEY_MATERIAL = re.compile(r"(?i)(authorization\s*[:=]\s*)?bearer\s+\S+|pk_[A-Za-z0-9_\-]+")


def _target_project(model_id: str) -> str:
    """The project of a live ML ``Target`` row; ``404 not_found`` for anything else."""
    from redsim.db.models import Target
    from redsim.db.session import get_session
    from redsim.services.ml_models import is_deleted

    with get_session() as sess:
        target = sess.get(Target, model_id)
        if target is None or target.kind not in _ML_KINDS or is_deleted(target.detail):
            raise api_error(NOT_FOUND, "model not found")
        return str(target.project_id)


@router.get("/llm/probes")
def list_probes(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """The committed probe catalog with per-probe status and reasons (spec 11.6; register LLM-07, -12)."""
    try:
        return probe_catalog_response()
    except CatalogUnavailable as exc:
        if exc.kind == "not_built":
            raise not_built("the LLM probe catalog is not on this tree", wave="B2", track="llm-core",
                            catalog_reason=exc.reason) from exc
        raise catalog_unavailable(exc.reason, "LLM probe") from exc


@router.post("/models/{model_id}/probes", status_code=status.HTTP_202_ACCEPTED)
def start_probe_run(
    model_id: str,
    body: LLMProbeRequest | None = Body(default=None),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """A garak probe run through Pythia (spec 17.4): 404, membership, ``llm.probe.run``, then admission."""
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config

    project_id = _target_project(model_id)
    ensure_project_access(user, project_id)
    check(user, LLM_PROBE_RUN, project_id)
    config = load_config()
    try:
        handle = admit_llm_probe_run(
            project_id=project_id, target_id=model_id, body=body, actor=f"user:{user.sub}",
            config=config, audit_writer=resolve_writer(config),
        )
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    return handle.to_response()


def _redact(exc: BaseException) -> str:
    """``<class name>: <first line of the message>`` with any bearer token or ``pk_`` key stripped."""
    message = str(exc).splitlines()[0] if str(exc).strip() else ""
    message = _KEY_MATERIAL.sub("[redacted]", message)
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__


@router.get("/llm/models")
def list_models(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """The Pythia models the configured key is entitled to (spec 17.4; register LLM-26). Always 200, never the key."""
    from redsim.llm import pythia
    from redsim.services.ml_llm import gateway_host

    # The roster needs the gateway and the key only. REDSIM_ML_LLM_MODEL picks
    # the narrative writer's model and is reported as default_model when set;
    # requiring it here left the register form without a list on every stack
    # that had a key but no narrative model.
    settings = pythia.PythiaSettings.from_env(require_model=False)
    if settings is None:
        return {"configured": False, "gateway_url": None, "gateway_host": None, "persona": None,
                "default_model": None, "models": [], "count": 0}
    out: dict[str, Any] = {
        "configured": True, "gateway_url": settings.base_url, "gateway_host": gateway_host(settings.base_url) or None,
        "persona": settings.persona, "default_model": settings.model or None, "models": [], "count": 0,
    }
    try:
        raw = pythia.list_models(settings)
    except Exception as exc:  # httpx errors, non-2xx, PythiaUnavailable: one line, no key material
        out["error"] = _redact(exc)
        return out
    models: list[dict[str, Any]] = [
        {"id": str(m["id"]), "owned_by": m.get("owned_by"), "name": m.get("name")}
        for m in raw if m.get("id")
    ]
    models.sort(key=lambda m: str(m["id"]))
    out["models"], out["count"] = models, len(models)
    return out


@router.get("/runs/{run_id}/llm-scorecard")
def llm_scorecard(run_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """The k/n probe scorecard of a probe run, never an MRI (spec 15.9, D9): membership, then the artifact."""
    from redsim.db.session import get_session

    ensure_run_access(user, run_id)
    try:
        with get_session() as sess:
            scorecard, meta = read_llm_scorecard(sess, run_id)
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    return {"run_id": run_id, "kind": "llm_probe", "scorecard": scorecard, "artifact": meta,
            "status_url": f"/v1/runs/{run_id}", "artifacts_url": f"/v1/runs/{run_id}/artifacts"}


__all__ = ["LLM_PROBE_RUN", "list_models", "list_probes", "llm_scorecard", "router", "start_probe_run"]
