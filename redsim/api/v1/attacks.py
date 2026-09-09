"""Attack catalog and campaign admission endpoint.

``POST /v1/models/{id}/attacks`` is the spec 17.2 campaign launcher. The route
only locates the model, runs the membership and ``ATTACK_RUN`` gates and hands
the body to :func:`redsim.services.ml_campaigns.create_attack_campaign`; every
refusal the service raises is a typed :class:`redsim.api.errors.ApiError` whose
section 17.3 code and status become the ``{"detail": {"code", ...}}`` envelope
here. Nothing is parsed out of exception text. An optional ``parent_run_id`` in
the body admits a rerun of a failed or cancelled campaign with the parent's
configuration (spec 10.6, lineage in ``ml_campaigns.parent_run_id``).

``GET /v1/attacks`` lists the registry (each row with its ``capabilities`` tags and
the ``domains`` derived from them; ``?modality=`` filters on those tags, the same
rule admission applies) after giving opt-in third-party adapters
(``REDSIM_PLUGINS=1``, ``redsim.ml.attacks`` entry points) one chance per API
process to register through :func:`redsim.plugins.load_ml_attack_plugins`. The
discovery rows travel in the response under ``plugins`` so a rejected or skipped
plugin is visible to the caller, never silently absent from the catalog.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import NOT_FOUND, ApiError, api_error
from redsim.api.policy import Action, check, ensure_project_access
from redsim.audit.chain import resolve_writer
from redsim.config import load_config
from redsim.safety import AuthorizationError

if TYPE_CHECKING:
    from redsim.plugins import PluginInfo

router = APIRouter(tags=["ml-attacks"])

_ML_KINDS = frozenset({"ml_model_artifact", "ml_model_endpoint"})

# Discovery rows from the one plugin load this API process performed, ``None``
# until the gate is on and a request has loaded them. A load that raised is not
# cached, so the next request retries once the operator fixes the configuration.
_PLUGIN_ROWS: list[PluginInfo] | None = None
_PLUGIN_LOCK = threading.Lock()


def _plugins_unavailable(exc: Exception) -> HTTPException:
    """``REDSIM_PLUGINS=1`` but the loader itself failed (signature keyring, entry-point metadata).

    Per-plugin failures never raise: they are ``rejected`` rows. What reaches here
    is a deployment that asked for plugins and cannot honour the request. A ``200``
    listing the built-ins only would hide that, so say so with a 503.
    """
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail={
        "code": "ml_plugins_unavailable",
        "message": "REDSIM_PLUGINS=1 but third-party attack adapters could not be loaded",
        "reason": f"{type(exc).__name__}: {exc}",
    })


def _attack_plugins() -> dict[str, Any]:
    """Load the opt-in attack plugins once per process and report the discovery rows.

    ``{"enabled": False}`` when ``REDSIM_PLUGINS`` is not ``1``. Nothing is
    scanned or imported in that case. Otherwise the first call runs
    :func:`redsim.plugins.load_ml_attack_plugins` (the allowlist, conformance
    and signature gates) and caches its rows. Later calls return the same rows.
    The loader is idempotent, so a second call in the same process (for
    example when ``redsim.scanners`` imported the group first) reports the same
    ``loaded`` rows for the plugins it already registered and never a duplicate
    refusal. A plugin whose id is already taken by the built-in catalog is
    ``rejected`` and is never substituted for the registered adapter. Loader
    exceptions propagate to the caller.
    """
    from redsim.plugins import load_ml_attack_plugins, plugins_enabled

    if not plugins_enabled():
        return {"enabled": False}
    global _PLUGIN_ROWS
    with _PLUGIN_LOCK:
        if _PLUGIN_ROWS is None:
            _PLUGIN_ROWS = load_ml_attack_plugins()
        rows = list(_PLUGIN_ROWS)
    return {"enabled": True, "rows": [row.to_dict() for row in rows]}


def _catalog_unavailable(exc: ImportError) -> HTTPException:
    """The catalog registry could not be imported in this API process.

    Say so with a 503 and the ImportError text; an empty ``200`` would present a
    deployment that can neither list nor launch anything as a healthy one.
    """
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail={
        "code": "ml_catalog_unavailable",
        "message": "attack catalog is unavailable in this API process",
        "reason": str(exc),
    })


@router.get("/attacks")
def list_attack_catalog(
    modality: str | None = None,
    _user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """The attack catalog: built-in adapters plus opt-in plugins, with the plugin discovery rows.

    Plugins are loaded before the listing so a third-party adapter appears on the
    first request of the process, whether or not ``redsim.scanners`` was imported
    first. A loader failure is a ``503 ml_plugins_unavailable`` carrying the
    reason, and an unimportable registry stays ``503 ml_catalog_unavailable``.
    """
    try:
        from redsim.ml.attacks import list_attack_capabilities, list_attacks
    except ImportError as exc:
        raise _catalog_unavailable(exc) from exc
    try:
        plugins = _attack_plugins()
    except Exception as exc:  # noqa: BLE001 - reported to the caller with its reason, never swallowed
        raise _plugins_unavailable(exc) from exc
    # Spec 27.2 / 27.4 (INTEROP-20): the ATLAS technique per row is route-level enrichment from the
    # registry mapping (``redsim.ml.atlas``); the frozen ``AttackInfo`` gains no field.
    from redsim.ml.atlas import attack_atlas_row, release_citation

    # The capability tags admission decides applicability from (``modality:<domain>`` for every domain
    # the adapter serves, ``dd2bbd4``): the additive ``capabilities`` and ``domains`` keys carry them, and
    # ``?modality=`` filters on the tag rather than on ``AttackInfo.domain``, so ``hopskipjump`` is listed
    # for ``image`` and ``pgd`` for ``tabular`` exactly when ``POST /v1/models/{id}/attacks`` admits them.
    tags_by_id = list_attack_capabilities()
    attacks = []
    for row in list_attacks():
        tags = list(tags_by_id.get(row.id, ()))
        domains = sorted(tag.removeprefix("modality:") for tag in tags if tag.startswith("modality:"))
        attacks.append({**row.model_dump(mode="json", exclude_none=True), **attack_atlas_row(row.id),
                        "capabilities": tags, "domains": domains or [row.domain]})
    if modality:
        attacks = [row for row in attacks if modality in row["domains"]]
    return {"attacks": attacks, "count": len(attacks), "plugins": plugins, "atlas": release_citation()}


@router.post("/models/{model_id}/attacks", status_code=status.HTTP_202_ACCEPTED)
def start_attack_campaign(
    model_id: str,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Admit a campaign (``202`` JobHandle) or refuse it with a spec 17.3 envelope.

    The admission service owns every deep check (target status, attack registry,
    grid rules, dataset binding, rerun lineage) and writes the ``attack.run``
    audit row, ``success=False`` on refusal, before any row or enqueue.
    """
    from redsim.db.models import Target
    from redsim.db.session import get_session

    with get_session() as sess:
        target = sess.get(Target, model_id)
        if target is None or target.kind not in _ML_KINDS:
            raise api_error(NOT_FOUND, "model not found")
        project_id = target.project_id
    ensure_project_access(user, project_id)
    check(user, Action.ATTACK_RUN, project_id)

    # The service module reaches the attack registry (numpy) and is imported per
    # request so the API process stays light at start-up.
    from redsim.services.ml_campaigns import create_attack_campaign

    app_config = load_config()
    parent_run_id = body.get("parent_run_id")
    campaign = {key: value for key, value in body.items() if key != "parent_run_id"}
    campaign["target_id"] = model_id
    try:
        handle = create_attack_campaign(
            campaign=campaign,
            project_id=project_id,
            actor=f"user:{user.sub}",
            config=app_config,
            audit_writer=resolve_writer(app_config),
            parent_run_id=parent_run_id,
        )
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    return handle.to_response()
