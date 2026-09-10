"""The signed evidence pack of one run and the signer roster.

``GET /v1/runs/{run_id}/evidence-pack`` streams the zip
:func:`redsim.services.evidence_pack.build_run_evidence_pack` assembles: the
digest-checked run record, the rendered reports, the run's audit chain with
its verdict, the artifact index and a manifest signed with the API's Ed25519
evidence key when one is configured. Same gate as a report download
(``report.export``, scanner) after the project-membership check the run
resolves to. Reads only: no audit row, no database write, the way the report
routes behave.

``GET /v1/evidence/signer`` says whether the deployment signs packs and with
which key id, so the Exports page can label the download. Never the key, never
the public PEM (that travels inside the pack itself).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import NOT_FOUND, api_error
from redsim.api.policy import Action, check, ensure_run_access
from redsim.config import load_config

router = APIRouter(tags=["evidence"])
logger = logging.getLogger(__name__)


@router.get("/evidence/signer")
def evidence_signer(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """``{configured, algorithm, key_id}``; ``reason`` when no key is configured."""
    from redsim.services.evidence_pack import load_evidence_signer, signer_status

    try:
        signer = load_evidence_signer()
    except (OSError, TypeError, ValueError) as exc:
        logger.error("evidence signing key unreadable: %s", exc.__class__.__name__)
        return {"configured": False, "algorithm": None, "key_id": None,
                "reason": f"the configured evidence signing key could not be read ({exc.__class__.__name__})"}
    return signer_status(signer)


@router.get("/runs/{run_id}/evidence-pack")
def get_evidence_pack(run_id: str, user: CurrentUser = Depends(get_current_user)) -> Response:
    """The zip, ``application/zip``, with ``X-Redsim-Evidence-Signed`` and the key id when signed."""
    from redsim.db.session import get_session
    from redsim.services.evidence_pack import build_run_evidence_pack, load_evidence_signer

    project_id = ensure_run_access(user, run_id)
    check(user, Action.REPORT_EXPORT, project_id)

    config = load_config()
    try:
        signer = load_evidence_signer()
    except (OSError, TypeError, ValueError) as exc:
        logger.error("evidence signing key unreadable: %s", exc.__class__.__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "evidence_signer_unavailable",
                    "message": "the configured evidence signing key could not be read"},
        ) from exc
    try:
        with get_session() as sess:
            pack = build_run_evidence_pack(sess, run_id, config=config, signer=signer)
    except LookupError as exc:
        raise api_error(NOT_FOUND, "no run record for this run yet", reason=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "report_artifact_digest_mismatch",
                    "message": "an artifact of this run no longer matches its recorded digest",
                    "reason": str(exc)},
        ) from exc

    headers = {
        "Content-Disposition": f'attachment; filename="{pack.filename}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
        "X-Redsim-Evidence-Signed": "true" if pack.signed else "false",
        "X-Redsim-Evidence-Pack-Hash": pack.pack_hash,
    }
    if pack.key_id:
        headers["X-Redsim-Evidence-Key-Id"] = pack.key_id
    return Response(content=pack.zip_bytes, media_type="application/zip", headers=headers)
