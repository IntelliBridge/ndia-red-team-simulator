"""``GET /v1/exports``: the export inventory behind the web Exports page.

One read route. A row per campaign run of the caller's projects (or
of ``?project=`` after the membership gate) with the state of its report
formats (spec 14.8, 17.1) and of its adversarial dataset export (spec 27.1),
composed server-side by ``services.ml_exports.list_exports`` so the page loads
in one request instead of one artifacts and one snapshots call per run.

The route lists; it exports nothing. Downloads stay on
``GET /v1/runs/{id}/report.{ext}`` (``report.export``, scanner) and
``GET /v1/datasets/{id}``, and the actions stay on
``POST /v1/runs/{id}/report.render`` (``report.render``) and
``POST /v1/runs/{id}/dataset`` (``dataset.export``, remediator), each with its
own gate and audit row. A viewer therefore reads the inventory the way a viewer
reads ``GET /v1/runs``, and every row carries ids, digests, sizes and counts
only, never a score (spec 15.7).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import DB_UNAVAILABLE, PARAMS_OUT_OF_RANGE, api_error
from redsim.api.policy import accessible_project_ids, ensure_project_access

router = APIRouter(prefix="/exports", tags=["exports"])

_LIMIT_MAX = 500
_LIMIT_DEFAULT = 50


@router.get("")
def list_exports_route(project: str | None = None, limit: int = _LIMIT_DEFAULT,
                       user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """The export inventory: ``{exports, count, report_formats, dataset_format, limit}``."""
    from redsim.db.session import get_session
    from redsim.services.ml_exports import DATASET_FORMAT, REPORT_FORMATS, list_exports

    if not 1 <= limit <= _LIMIT_MAX:
        raise api_error(PARAMS_OUT_OF_RANGE, f"limit must be between 1 and {_LIMIT_MAX}", field="limit",
                        minimum=1, maximum=_LIMIT_MAX)

    if project is not None:
        ensure_project_access(user, project)
        project_ids: list[str] | None = [project]
    else:
        project_ids = accessible_project_ids(user)

    try:
        with get_session() as sess:
            rows = list_exports(sess, project_ids=project_ids, limit=limit)
    except RuntimeError as exc:  # REDSIM_DB_URL missing
        raise api_error(DB_UNAVAILABLE, str(exc)) from exc
    return {
        "exports": rows,
        "count": len(rows),
        "report_formats": list(REPORT_FORMATS),
        "dataset_format": DATASET_FORMAT,
        "limit": limit,
    }
