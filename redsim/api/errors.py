"""Spec section 17.3 error-code table for the ML routes.

Every refusal a new ML route returns carries ``{"detail": {"code": <snake_case>,
"message": <human text>, ...}}`` so the web app renders it without parsing prose.
This module is the single copy of that table: one constant per code, the HTTP
status each maps to, and :func:`error_detail` / :func:`api_error` to build the
envelope. Routes and services import the constants instead of spelling the
strings inline, so a divergence from the spec is a failing import, not a typo
discovered in the UI.

Four codes (``forbidden``, ``not_found``, ``rate_limited``, ``db_unavailable``)
are listed in the spec with a plain string ``detail`` because the retained aegis
routes already emit them that way; they are in the table so the vocabulary is
complete, and :data:`STRING_DETAIL_CODES` names them.

Nothing here imports FastAPI at module import time: services raise
:class:`ApiError` and the route converts it, so the worker and CLI can share the
same typed refusals without pulling the web stack.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from fastapi import HTTPException

# --- Codes (spec section 17.3, in table order) --------------------------------

USE_MODELS_ROUTE: Final = "use_models_route"
FORBIDDEN: Final = "forbidden"
NOT_FOUND: Final = "not_found"
ALREADY_REGISTERED: Final = "already_registered"
CAMPAIGN_IN_FLIGHT: Final = "campaign_in_flight"
MODEL_LOAD_REFUSED: Final = "model_load_refused"
CAMPAIGN_NOT_TERMINAL: Final = "campaign_not_terminal"
JOB_IN_FLIGHT: Final = "job_in_flight"
RUN_TERMINAL: Final = "run_terminal"
INCOMPATIBLE_CAMPAIGNS: Final = "incompatible_campaigns"
SCORE_UNAVAILABLE: Final = "score_unavailable"
MODEL_TOO_LARGE: Final = "model_too_large"
UNSUPPORTED_MODEL_FORMAT: Final = "unsupported_model_format"
PICKLE_REFUSED: Final = "pickle_refused"
ARCHITECTURE_REQUIRED: Final = "architecture_required"
ARCHITECTURE_NOT_ALLOWLISTED: Final = "architecture_not_allowlisted"
DATASET_INCOMPATIBLE: Final = "dataset_incompatible"
UNKNOWN_ATTACK: Final = "unknown_attack"
UNKNOWN_DEFENSE: Final = "unknown_defense"
ATTACK_MODALITY_MISMATCH: Final = "attack_modality_mismatch"
DEFENSE_MODALITY_MISMATCH: Final = "defense_modality_mismatch"
ATTACK_REQUIRES_GRADIENTS: Final = "attack_requires_gradients"
EPS_GRID_INVALID: Final = "eps_grid_invalid"
REFERENCE_EPS_NOT_IN_GRID: Final = "reference_eps_not_in_grid"
PARAMS_OUT_OF_RANGE: Final = "params_out_of_range"
RATE_LIMITED: Final = "rate_limited"
NOT_IMPLEMENTED: Final = "not_implemented"
QUEUE_UNAVAILABLE: Final = "queue_unavailable"
DB_UNAVAILABLE: Final = "db_unavailable"

# --- HTTP status per code -----------------------------------------------------

HTTP_STATUS: Final = MappingProxyType({
    USE_MODELS_ROUTE: 400,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    ALREADY_REGISTERED: 409,
    CAMPAIGN_IN_FLIGHT: 409,
    MODEL_LOAD_REFUSED: 409,
    CAMPAIGN_NOT_TERMINAL: 409,
    JOB_IN_FLIGHT: 409,
    RUN_TERMINAL: 409,
    INCOMPATIBLE_CAMPAIGNS: 409,
    SCORE_UNAVAILABLE: 409,
    MODEL_TOO_LARGE: 413,
    UNSUPPORTED_MODEL_FORMAT: 415,
    PICKLE_REFUSED: 415,
    ARCHITECTURE_REQUIRED: 422,
    ARCHITECTURE_NOT_ALLOWLISTED: 422,
    DATASET_INCOMPATIBLE: 422,
    UNKNOWN_ATTACK: 422,
    UNKNOWN_DEFENSE: 422,
    ATTACK_MODALITY_MISMATCH: 422,
    DEFENSE_MODALITY_MISMATCH: 422,
    ATTACK_REQUIRES_GRADIENTS: 422,
    EPS_GRID_INVALID: 422,
    REFERENCE_EPS_NOT_IN_GRID: 422,
    PARAMS_OUT_OF_RANGE: 422,
    RATE_LIMITED: 429,
    NOT_IMPLEMENTED: 501,
    QUEUE_UNAVAILABLE: 503,
    DB_UNAVAILABLE: 503,
})

#: Every code of the section 17.3 table, in table order.
ALL_CODES: Final = tuple(HTTP_STATUS)

#: Codes the spec lists with a plain string ``detail`` (retained-route wording).
STRING_DETAIL_CODES: Final = frozenset({FORBIDDEN, NOT_FOUND, RATE_LIMITED, DB_UNAVAILABLE})

#: Codes whose envelope must carry ``phase`` (spec: ``not_implemented`` "always carries phase").
PHASE_REQUIRED_CODES: Final = frozenset({NOT_IMPLEMENTED})

#: The only phase a Phase A build names for work it does not do.
DEFAULT_PHASE: Final = "B"

# Operator-safe default messages, used when a caller passes none.
_DEFAULT_MESSAGE: Final = MappingProxyType({
    USE_MODELS_ROUTE: "ML targets are registered through POST /v1/models",
    FORBIDDEN: "forbidden",
    NOT_FOUND: "not found",
    ALREADY_REGISTERED: "bundled model is already registered in this project",
    CAMPAIGN_IN_FLIGHT: "a campaign for this model is queued or running",
    MODEL_LOAD_REFUSED: "model is not available for campaigns",
    CAMPAIGN_NOT_TERMINAL: "the campaign has not reached a terminal status",
    JOB_IN_FLIGHT: "a job of this type is already queued or running for this finding",
    RUN_TERMINAL: "the run is already terminal",
    INCOMPATIBLE_CAMPAIGNS: "campaigns with different settings cannot be compared",
    SCORE_UNAVAILABLE: "a compared run has no score",
    MODEL_TOO_LARGE: "uploaded model exceeds the size cap",
    UNSUPPORTED_MODEL_FORMAT: "model format is not accepted",
    PICKLE_REFUSED: "pickle-serialized models are refused",
    ARCHITECTURE_REQUIRED: "state_dict formats need a declared architecture_id",
    ARCHITECTURE_NOT_ALLOWLISTED: "architecture_id is not in the catalog",
    DATASET_INCOMPATIBLE: "dataset shape or class count does not match the model manifest",
    UNKNOWN_ATTACK: "attack id is not in the registry",
    UNKNOWN_DEFENSE: "defense id is not in the registry",
    ATTACK_MODALITY_MISMATCH: "attack domain differs from the model modality",
    DEFENSE_MODALITY_MISMATCH: "defense domain differs from the model modality",
    ATTACK_REQUIRES_GRADIENTS: "attack needs loss gradients the target does not expose",
    EPS_GRID_INVALID: "eps_grid violates the grid rules",
    REFERENCE_EPS_NOT_IN_GRID: "reference_eps is not a member of eps_grid",
    PARAMS_OUT_OF_RANGE: "attack or defense parameters are out of range",
    RATE_LIMITED: "rate limited",
    NOT_IMPLEMENTED: "not implemented in this phase",
    QUEUE_UNAVAILABLE: "job queue is unavailable",
    DB_UNAVAILABLE: "database is unavailable",
})


def http_status(code: str) -> int:
    """HTTP status for a section 17.3 ``code``; ``KeyError`` for anything else."""
    if code not in HTTP_STATUS:
        raise KeyError(f"{code!r} is not a spec 17.3 error code")
    return HTTP_STATUS[code]


def error_detail(code: str, message: str | None = None, **fields: Any) -> dict[str, Any]:
    """The ``detail`` object of an ML-route refusal: ``{"code", "message", ...fields}``.

    ``code`` must be one of :data:`ALL_CODES` (``ValueError`` otherwise, so an
    off-table string fails in the route's own tests rather than in the UI).
    Optional fields follow the spec envelope: ``phase``, ``field``, ``reasons``
    and any route-specific context such as ``status`` or ``refusal_reason``.
    ``not_implemented`` always carries ``phase`` (``"B"`` when none is given).
    Pass the result as ``HTTPException(status_code=http_status(code), detail=...)``
    and FastAPI wraps it into the ``{"detail": {...}}`` body.
    """
    if code not in HTTP_STATUS:
        raise ValueError(f"{code!r} is not a spec 17.3 error code")
    detail: dict[str, Any] = {"code": code, "message": message or _DEFAULT_MESSAGE[code]}
    if code in PHASE_REQUIRED_CODES and not fields.get("phase"):
        fields["phase"] = DEFAULT_PHASE
    detail.update(fields)
    return detail


class ApiError(Exception):
    """A typed refusal a service raises; the route turns it into the 17.3 envelope.

    Services stay free of FastAPI: they raise ``ApiError(code, message, **fields)``
    and the route calls :meth:`as_http_exception`. ``code``/``status``/``detail``
    are the same values :func:`error_detail` and :func:`http_status` return.
    """

    def __init__(self, code: str, message: str | None = None, **fields: Any) -> None:
        self.detail = error_detail(code, message, **fields)
        self.code: str = code
        self.status: int = HTTP_STATUS[code]
        super().__init__(str(self.detail["message"]))

    def as_http_exception(self) -> HTTPException:
        """The FastAPI exception carrying this refusal (imports FastAPI lazily)."""
        return api_error(self.code, str(self.detail["message"]), **{
            k: v for k, v in self.detail.items() if k not in {"code", "message"}
        })


def api_error(code: str, message: str | None = None, **fields: Any) -> HTTPException:
    """``HTTPException`` with the table status and the :func:`error_detail` body.

    String-detail codes (:data:`STRING_DETAIL_CODES`) keep the retained routes'
    plain-string ``detail`` unless extra fields are supplied, so ``forbidden`` and
    ``not_found`` responses stay byte-compatible with the existing clients.
    """
    from fastapi import HTTPException

    detail = error_detail(code, message, **fields)
    if code in STRING_DETAIL_CODES and not fields:
        return HTTPException(status_code=HTTP_STATUS[code], detail=str(detail["message"]))
    return HTTPException(status_code=HTTP_STATUS[code], detail=detail)


__all__ = [
    "ALL_CODES",
    "ALREADY_REGISTERED",
    "ARCHITECTURE_NOT_ALLOWLISTED",
    "ARCHITECTURE_REQUIRED",
    "ATTACK_MODALITY_MISMATCH",
    "ATTACK_REQUIRES_GRADIENTS",
    "CAMPAIGN_IN_FLIGHT",
    "CAMPAIGN_NOT_TERMINAL",
    "DATASET_INCOMPATIBLE",
    "DB_UNAVAILABLE",
    "DEFAULT_PHASE",
    "DEFENSE_MODALITY_MISMATCH",
    "EPS_GRID_INVALID",
    "FORBIDDEN",
    "HTTP_STATUS",
    "INCOMPATIBLE_CAMPAIGNS",
    "JOB_IN_FLIGHT",
    "MODEL_LOAD_REFUSED",
    "MODEL_TOO_LARGE",
    "NOT_FOUND",
    "NOT_IMPLEMENTED",
    "PARAMS_OUT_OF_RANGE",
    "PHASE_REQUIRED_CODES",
    "PICKLE_REFUSED",
    "QUEUE_UNAVAILABLE",
    "RATE_LIMITED",
    "REFERENCE_EPS_NOT_IN_GRID",
    "RUN_TERMINAL",
    "SCORE_UNAVAILABLE",
    "STRING_DETAIL_CODES",
    "UNKNOWN_ATTACK",
    "UNKNOWN_DEFENSE",
    "UNSUPPORTED_MODEL_FORMAT",
    "USE_MODELS_ROUTE",
    "ApiError",
    "api_error",
    "error_detail",
    "http_status",
]
