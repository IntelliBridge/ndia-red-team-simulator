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

The Phase B codes (spec 17.3 addendum of 2026-09-09; plan 12 wave B0) sit in
the same table with the same rules. One of them, ``capacity_deferred``, is a
``202`` marker: it rides in the body of an accepted response to say the run
was admitted but not yet dispatched, so it is never raised as a refusal and
:data:`MARKER_CODES` names it (:class:`ApiError` and :func:`api_error` refuse it).
The addendum's second table (wave B2, ``codes-b2`` track, same date) adds the
codes the register named and wave B0 left out: endpoint credentials and query
budgets, the LLM probe key, batch and bulk admission, idempotency keys, dataset
export of fixture runs, and the review and snapshot conflicts. Every one is a
refusal (4xx) with the structured envelope; none joins the string-detail set.
The addendum's third table (wave B4, ``fix-api-services`` track, same date) adds
the codes the wave B2 routes had resolved with ``getattr`` fallbacks onto a
documented neighbour: the D3 attestation, the scoring weight vector, the LLM-12
registration and probe-run set, and the endpoint credential refusal on a
synchronous call. Every one is a refusal; ``endpoint_auth_failed`` is a ``502``
like ``endpoint_unreachable`` because the upstream endpoint, not the caller,
produced the answer.

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

# --- Codes (spec 17.3 addendum, Phase B, 2026-09-09; in addendum table order) --

# Accepted-but-deferred marker (202 body, never a refusal): BULK capacity caps.
CAPACITY_DEFERRED: Final = "capacity_deferred"
# Endpoint (black-box) targets and LLM probe runs.
ENDPOINT_NOT_ALLOWLISTED: Final = "endpoint_not_allowlisted"
EGRESS_REFUSED: Final = "egress_refused"
SNAPSHOT_NOT_FOUND: Final = "snapshot_not_found"
LLM_TARGET_REQUIRED: Final = "llm_target_required"
EXPORT_IN_FLIGHT: Final = "export_in_flight"
EXPORT_UNAVAILABLE: Final = "export_unavailable"
RESOLUTION_BLOCKED: Final = "resolution_blocked"
REVIEW_TRANSITION_INVALID: Final = "review_transition_invalid"
DATASET_TOO_LARGE: Final = "dataset_too_large"
UNSUPPORTED_DATASET_FORMAT: Final = "unsupported_dataset_format"
ENDPOINT_URL_INVALID: Final = "endpoint_url_invalid"
AUTH_PROFILE_KIND_UNSUPPORTED: Final = "auth_profile_kind_unsupported"
ENDPOINT_SCHEMA_MISMATCH: Final = "endpoint_schema_mismatch"
PROBE_SET_UNKNOWN: Final = "probe_set_unknown"
# ``license_required`` was spelled inline in ``redsim/api/v1/models.py`` before
# the addendum gave it a table row; the value is unchanged.
LICENSE_REQUIRED: Final = "license_required"
REMOTE_REFERENCE_REFUSED: Final = "remote_reference_refused"
SCHEMA_UNDECLARED: Final = "schema_undeclared"
BATCH_MODALITY_MISMATCH: Final = "batch_modality_mismatch"
BATCH_TOO_LARGE: Final = "batch_too_large"
DAILY_BUDGET_EXCEEDED: Final = "daily_budget_exceeded"
INTEGRATION_DISABLED: Final = "integration_disabled"
ENDPOINT_UNREACHABLE: Final = "endpoint_unreachable"

# --- Codes (spec 17.3 addendum, second table: wave B2 ``codes-b2``, 2026-09-09) --
# In table order (by HTTP status). Register ids name the rows that need them.

# The structured spelling of the review independence refusal (REVIEW_REPORTS-12);
# the Phase A dismissal alias keeps its string-detail ``forbidden``.
REVIEWER_NOT_INDEPENDENT: Final = "reviewer_not_independent"
# Endpoint credentials (ENDPOINT-18): a live target still references the profile.
AUTH_PROFILE_IN_USE: Final = "auth_profile_in_use"
# ``Idempotency-Key`` (REVIEW_REPORTS-32, BULK-11): same key, different request;
# same key, original still reserved (the register's ``idempotency_in_flight``).
IDEMPOTENCY_KEY_REUSED: Final = "idempotency_key_reused"
IDEMPOTENCY_CONFLICT: Final = "idempotency_conflict"
# Review compare-and-set loser (REVIEW_REPORTS-06); archived snapshot (REVIEW_REPORTS-22).
REVIEW_STATE_CONFLICT: Final = "review_state_conflict"
SNAPSHOT_ARCHIVED: Final = "snapshot_archived"
# Bulk upload caps (BULK-13): total bytes, then file count.
BULK_TOO_LARGE: Final = "bulk_too_large"
# Endpoint registration without a credential reference (ENDPOINT-06); LLM target
# or probe run without a probe-key profile (LLM-03, LLM-04, LLM-26).
AUTH_PROFILE_REQUIRED: Final = "auth_profile_required"
PROBE_KEY_REQUIRED: Final = "probe_key_required"
# Batch pre-pass refusal (BULK-03): the whole batch is refused, nothing admitted.
BATCH_MEMBER_REFUSED: Final = "batch_member_refused"
BULK_TOO_MANY_FILES: Final = "bulk_too_many_files"
# Dataset export of a CI-fixture run (INTEROP-10; D3).
FIXTURE_NOT_EXPORTABLE: Final = "fixture_not_exportable"
# Worst-case endpoint query estimate above the per-job caps (ENDPOINT-08). The
# broker enforcing the cap at run time is a job failure, never this HTTP code.
QUERY_BUDGET_EXCEEDED: Final = "query_budget_exceeded"

# --- Codes (spec 17.3 addendum, third table: wave B4 ``fix-api-services``, 2026-09-09) --
# In table order (by HTTP status). Until this table the routes resolved these by
# ``getattr`` and fell back to ``license_required`` / ``params_out_of_range`` /
# ``probe_set_unknown`` / ``rate_limited`` with the planned name in ``reason``.

# The D3 attestation of an endpoint registration (ENDPOINT-31): absent or false.
ATTESTATION_REQUIRED: Final = "attestation_required"
# A partial or non-unit MRI weight vector on the project scoring override (REVIEW_REPORTS-28).
SCORING_WEIGHTS_INVALID: Final = "scoring_weights_invalid"
# LLM target registration (LLM-12): a non-canonical Pythia id, an embedding model, no gateway URL.
MODEL_ID_INVALID: Final = "model_id_invalid"
MODEL_NOT_CHAT: Final = "model_not_chat"
GATEWAY_URL_REQUIRED: Final = "gateway_url_required"
# Probe-run admission (LLM-09, LLM-12): an id outside the catalog, an excluded probe, a detector
# whose model is not permitted or not cached in this deployment.
UNKNOWN_PROBE: Final = "unknown_probe"
PROBE_EXCLUDED: Final = "probe_excluded"
PROBE_DETECTOR_UNAVAILABLE: Final = "probe_detector_unavailable"
# The per-project daily probe-run quota (LLM-21); a budget refusal like ``daily_budget_exceeded``.
LLM_PROBE_QUOTA_EXCEEDED: Final = "llm_probe_quota_exceeded"
# The endpoint answered 401 or 403 to the AuthProfile credential on a synchronous call made on
# the caller's behalf; inside validate or a campaign it stays ``refusal_reason: load_failed``.
ENDPOINT_AUTH_FAILED: Final = "endpoint_auth_failed"

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
    # Phase B addendum (2026-09-09).
    CAPACITY_DEFERRED: 202,
    ENDPOINT_NOT_ALLOWLISTED: 403,
    EGRESS_REFUSED: 403,
    SNAPSHOT_NOT_FOUND: 404,
    LLM_TARGET_REQUIRED: 409,
    EXPORT_IN_FLIGHT: 409,
    EXPORT_UNAVAILABLE: 409,
    RESOLUTION_BLOCKED: 409,
    REVIEW_TRANSITION_INVALID: 409,
    DATASET_TOO_LARGE: 413,
    UNSUPPORTED_DATASET_FORMAT: 415,
    ENDPOINT_URL_INVALID: 422,
    AUTH_PROFILE_KIND_UNSUPPORTED: 422,
    ENDPOINT_SCHEMA_MISMATCH: 422,
    PROBE_SET_UNKNOWN: 422,
    LICENSE_REQUIRED: 422,
    REMOTE_REFERENCE_REFUSED: 422,
    SCHEMA_UNDECLARED: 422,
    BATCH_MODALITY_MISMATCH: 422,
    BATCH_TOO_LARGE: 422,
    DAILY_BUDGET_EXCEEDED: 429,
    INTEGRATION_DISABLED: 501,
    ENDPOINT_UNREACHABLE: 502,
    # Phase B addendum, second table (wave B2 codes-b2, 2026-09-09).
    REVIEWER_NOT_INDEPENDENT: 403,
    AUTH_PROFILE_IN_USE: 409,
    IDEMPOTENCY_KEY_REUSED: 409,
    IDEMPOTENCY_CONFLICT: 409,
    REVIEW_STATE_CONFLICT: 409,
    SNAPSHOT_ARCHIVED: 409,
    BULK_TOO_LARGE: 413,
    AUTH_PROFILE_REQUIRED: 422,
    PROBE_KEY_REQUIRED: 422,
    BATCH_MEMBER_REFUSED: 422,
    BULK_TOO_MANY_FILES: 422,
    FIXTURE_NOT_EXPORTABLE: 422,
    QUERY_BUDGET_EXCEEDED: 429,
    # Phase B addendum, third table (wave B4 fix-api-services, 2026-09-09).
    ATTESTATION_REQUIRED: 422,
    SCORING_WEIGHTS_INVALID: 422,
    MODEL_ID_INVALID: 422,
    MODEL_NOT_CHAT: 422,
    GATEWAY_URL_REQUIRED: 422,
    UNKNOWN_PROBE: 422,
    PROBE_EXCLUDED: 422,
    PROBE_DETECTOR_UNAVAILABLE: 422,
    LLM_PROBE_QUOTA_EXCEEDED: 429,
    ENDPOINT_AUTH_FAILED: 502,
})

#: Every code of the section 17.3 table, in table order.
ALL_CODES: Final = tuple(HTTP_STATUS)

#: Codes the spec lists with a plain string ``detail`` (retained-route wording).
STRING_DETAIL_CODES: Final = frozenset({FORBIDDEN, NOT_FOUND, RATE_LIMITED, DB_UNAVAILABLE})

#: Codes whose envelope must carry ``phase`` (spec: ``not_implemented`` "always carries phase").
PHASE_REQUIRED_CODES: Final = frozenset({NOT_IMPLEMENTED})

#: 2xx marker codes: embedded in an accepted response body, never raised as a refusal.
MARKER_CODES: Final = frozenset({CAPACITY_DEFERRED})

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
    # Phase B addendum (2026-09-09).
    CAPACITY_DEFERRED: "run admitted; dispatch is deferred until project capacity frees",
    ENDPOINT_NOT_ALLOWLISTED: "endpoint host is not in the egress allowlist",
    EGRESS_REFUSED: "outbound request refused by the egress policy",
    SNAPSHOT_NOT_FOUND: "report snapshot not found",
    LLM_TARGET_REQUIRED: "this route needs an LLM endpoint target",
    EXPORT_IN_FLIGHT: "a dataset export for this run is queued or running",
    EXPORT_UNAVAILABLE: "the run has no export that can be served",
    RESOLUTION_BLOCKED: "the finding does not meet every resolution condition",
    REVIEW_TRANSITION_INVALID: "the review decision is not valid from the current state",
    DATASET_TOO_LARGE: "uploaded dataset exceeds the size cap",
    UNSUPPORTED_DATASET_FORMAT: "dataset format is not accepted",
    ENDPOINT_URL_INVALID: "endpoint URL is not an https URL without userinfo or query",
    AUTH_PROFILE_KIND_UNSUPPORTED: "auth profile kind is not usable for this endpoint",
    ENDPOINT_SCHEMA_MISMATCH: "endpoint response does not match the declared schema",
    PROBE_SET_UNKNOWN: "probe set id is not in the catalog",
    LICENSE_REQUIRED: "license_statement is required: only licensed models and datasets are registered",
    REMOTE_REFERENCE_REFUSED: "manifest references content outside the upload",
    SCHEMA_UNDECLARED: "dataset feature or image schema is not declared",
    BATCH_MODALITY_MISMATCH: "a batch is one modality; the selected targets span several",
    BATCH_TOO_LARGE: "batch exceeds the member cap",
    DAILY_BUDGET_EXCEEDED: "the project's daily run budget is spent",
    INTEGRATION_DISABLED: "this integration is not enabled in this deployment",
    ENDPOINT_UNREACHABLE: "endpoint did not answer",
    # Phase B addendum, second table (wave B2 codes-b2, 2026-09-09).
    REVIEWER_NOT_INDEPENDENT: "the reviewer is not independent of this finding",
    AUTH_PROFILE_IN_USE: "auth profile is referenced by a live endpoint target",
    IDEMPOTENCY_KEY_REUSED: "Idempotency-Key was already used for a different request",
    IDEMPOTENCY_CONFLICT: "a request with this Idempotency-Key is still in flight",
    REVIEW_STATE_CONFLICT: "the finding's review state changed since it was read",
    SNAPSHOT_ARCHIVED: "the report snapshot is archived",
    BULK_TOO_LARGE: "bulk upload exceeds the total size cap",
    AUTH_PROFILE_REQUIRED: "endpoint registration needs an auth_profile_id",
    PROBE_KEY_REQUIRED: "LLM targets need an auth profile that carries the probe key",
    BATCH_MEMBER_REFUSED: "a batch member failed admission; the batch was refused whole",
    BULK_TOO_MANY_FILES: "bulk upload exceeds the file-count cap",
    FIXTURE_NOT_EXPORTABLE: "runs on a CI fixture target are never exported",
    QUERY_BUDGET_EXCEEDED: "estimated endpoint query volume exceeds the per-job budget",
    # Phase B addendum, third table (wave B4 fix-api-services, 2026-09-09).
    ATTESTATION_REQUIRED: "evaluation_instance_attestation must be true: only non-operational evaluation "
                          "instances are registered (D3)",
    SCORING_WEIGHTS_INVALID: "ml_scoring.weights must name all five weights and sum to 1; nothing is renormalised",
    MODEL_ID_INVALID: "model_id must be a canonical Pythia id (<vendor>/<model> or pythia/auto)",
    MODEL_NOT_CHAT: "model_id names an embedding model; probes need a chat completion endpoint",
    GATEWAY_URL_REQUIRED: "gateway_url is required when PYTHIA_BASE_URL is not set on the API",
    UNKNOWN_PROBE: "probe id is not in the committed probe catalog",
    PROBE_EXCLUDED: "probe is excluded from this deployment's catalog",
    PROBE_DETECTOR_UNAVAILABLE: "the probe's detector model is not permitted or not cached in this deployment",
    LLM_PROBE_QUOTA_EXCEEDED: "the project's daily LLM probe-run quota is spent",
    ENDPOINT_AUTH_FAILED: "the endpoint refused the AuthProfile credential",
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


def _refuse_marker(code: str) -> None:
    """``ValueError`` for a 2xx marker code: it is a response body, not a refusal."""
    if code in MARKER_CODES:
        raise ValueError(
            f"{code!r} is a {HTTP_STATUS[code]} marker, not a refusal; "
            "embed error_detail(code, ...) in the accepted response body instead"
        )


class ApiError(Exception):
    """A typed refusal a service raises; the route turns it into the 17.3 envelope.

    Services stay free of FastAPI: they raise ``ApiError(code, message, **fields)``
    and the route calls :meth:`as_http_exception`. ``code``/``status``/``detail``
    are the same values :func:`error_detail` and :func:`http_status` return.
    """

    def __init__(self, code: str, message: str | None = None, **fields: Any) -> None:
        _refuse_marker(code)
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

    _refuse_marker(code)
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
    "ATTESTATION_REQUIRED",
    "AUTH_PROFILE_IN_USE",
    "AUTH_PROFILE_KIND_UNSUPPORTED",
    "AUTH_PROFILE_REQUIRED",
    "BATCH_MEMBER_REFUSED",
    "BATCH_MODALITY_MISMATCH",
    "BATCH_TOO_LARGE",
    "BULK_TOO_LARGE",
    "BULK_TOO_MANY_FILES",
    "CAMPAIGN_IN_FLIGHT",
    "CAMPAIGN_NOT_TERMINAL",
    "CAPACITY_DEFERRED",
    "DAILY_BUDGET_EXCEEDED",
    "DATASET_INCOMPATIBLE",
    "DATASET_TOO_LARGE",
    "DB_UNAVAILABLE",
    "DEFAULT_PHASE",
    "DEFENSE_MODALITY_MISMATCH",
    "EGRESS_REFUSED",
    "ENDPOINT_AUTH_FAILED",
    "ENDPOINT_NOT_ALLOWLISTED",
    "ENDPOINT_SCHEMA_MISMATCH",
    "ENDPOINT_UNREACHABLE",
    "ENDPOINT_URL_INVALID",
    "EPS_GRID_INVALID",
    "EXPORT_IN_FLIGHT",
    "EXPORT_UNAVAILABLE",
    "FIXTURE_NOT_EXPORTABLE",
    "FORBIDDEN",
    "GATEWAY_URL_REQUIRED",
    "HTTP_STATUS",
    "IDEMPOTENCY_CONFLICT",
    "IDEMPOTENCY_KEY_REUSED",
    "INCOMPATIBLE_CAMPAIGNS",
    "INTEGRATION_DISABLED",
    "JOB_IN_FLIGHT",
    "LICENSE_REQUIRED",
    "LLM_PROBE_QUOTA_EXCEEDED",
    "LLM_TARGET_REQUIRED",
    "MARKER_CODES",
    "MODEL_ID_INVALID",
    "MODEL_LOAD_REFUSED",
    "MODEL_NOT_CHAT",
    "MODEL_TOO_LARGE",
    "NOT_FOUND",
    "NOT_IMPLEMENTED",
    "PARAMS_OUT_OF_RANGE",
    "PHASE_REQUIRED_CODES",
    "PICKLE_REFUSED",
    "PROBE_DETECTOR_UNAVAILABLE",
    "PROBE_EXCLUDED",
    "PROBE_KEY_REQUIRED",
    "PROBE_SET_UNKNOWN",
    "QUERY_BUDGET_EXCEEDED",
    "QUEUE_UNAVAILABLE",
    "RATE_LIMITED",
    "REFERENCE_EPS_NOT_IN_GRID",
    "REMOTE_REFERENCE_REFUSED",
    "RESOLUTION_BLOCKED",
    "REVIEWER_NOT_INDEPENDENT",
    "REVIEW_STATE_CONFLICT",
    "REVIEW_TRANSITION_INVALID",
    "RUN_TERMINAL",
    "SCHEMA_UNDECLARED",
    "SCORE_UNAVAILABLE",
    "SCORING_WEIGHTS_INVALID",
    "SNAPSHOT_ARCHIVED",
    "SNAPSHOT_NOT_FOUND",
    "STRING_DETAIL_CODES",
    "UNKNOWN_ATTACK",
    "UNKNOWN_DEFENSE",
    "UNKNOWN_PROBE",
    "UNSUPPORTED_DATASET_FORMAT",
    "UNSUPPORTED_MODEL_FORMAT",
    "USE_MODELS_ROUTE",
    "ApiError",
    "api_error",
    "error_detail",
    "http_status",
]
