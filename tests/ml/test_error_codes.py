"""``redsim.api.errors`` is the error-code table, one constant per code.

The table is spelled out here in four dated blocks (the Phase A table frozen at
M0 plus the three Phase B addenda) so a code added, renamed or moved to another
HTTP status in ``redsim/api/errors.py`` fails here rather than in the UI.
"""

from __future__ import annotations

import pytest

from redsim.api import errors

#: The Phase A table as frozen at M0, minus the two defense codes that left with the defenses
#: on 2026-09-09 (27 codes): code -> HTTP.
PHASE_A_CODES = {
    "use_models_route": 400,
    "forbidden": 403,
    "not_found": 404,
    "already_registered": 409,
    "campaign_in_flight": 409,
    "campaign_not_terminal": 409,
    "incompatible_campaigns": 409,
    "job_in_flight": 409,
    "model_load_refused": 409,
    "run_terminal": 409,
    "score_unavailable": 409,
    "model_too_large": 413,
    "pickle_refused": 415,
    "unsupported_model_format": 415,
    "architecture_not_allowlisted": 422,
    "architecture_required": 422,
    "attack_modality_mismatch": 422,
    "attack_requires_gradients": 422,
    "dataset_incompatible": 422,
    "eps_grid_invalid": 422,
    "params_out_of_range": 422,
    "reference_eps_not_in_grid": 422,
    "unknown_attack": 422,
    "rate_limited": 429,
    "not_implemented": 501,
    "db_unavailable": 503,
    "queue_unavailable": 503,
}

#: The first Phase B addendum (2026-09-09, wave B0): code -> HTTP.
PHASE_B_CODES = {
    "capacity_deferred": 202,
    "endpoint_not_allowlisted": 403,
    "egress_refused": 403,
    "snapshot_not_found": 404,
    "llm_target_required": 409,
    "export_in_flight": 409,
    "export_unavailable": 409,
    "resolution_blocked": 409,
    "review_transition_invalid": 409,
    "dataset_too_large": 413,
    "unsupported_dataset_format": 415,
    "endpoint_url_invalid": 422,
    "auth_profile_kind_unsupported": 422,
    "endpoint_schema_mismatch": 422,
    "probe_set_unknown": 422,
    "license_required": 422,
    "remote_reference_refused": 422,
    "schema_undeclared": 422,
    "batch_modality_mismatch": 422,
    "batch_too_large": 422,
    "daily_budget_exceeded": 429,
    "integration_disabled": 501,
    "endpoint_unreachable": 502,
}

#: The second Phase B addendum (2026-09-09, wave B2): code -> HTTP.
PHASE_B2_CODES = {
    "reviewer_not_independent": 403,
    "auth_profile_in_use": 409,
    "idempotency_key_reused": 409,
    "idempotency_conflict": 409,
    "review_state_conflict": 409,
    "snapshot_archived": 409,
    "bulk_too_large": 413,
    "auth_profile_required": 422,
    "probe_key_required": 422,
    "batch_member_refused": 422,
    "bulk_too_many_files": 422,
    "fixture_not_exportable": 422,
    "query_budget_exceeded": 429,
}

#: The third Phase B addendum (2026-09-09, wave B4): the codes the B2 routes had resolved with
#: ``getattr`` fallbacks.
PHASE_B4_CODES = {
    "attestation_required": 422,
    "scoring_weights_invalid": 422,
    "model_id_invalid": 422,
    "model_not_chat": 422,
    "gateway_url_required": 422,
    "unknown_probe": 422,
    "probe_excluded": 422,
    "probe_detector_unavailable": 422,
    "llm_probe_quota_exceeded": 429,
    "endpoint_auth_failed": 502,
}


def _table() -> dict[str, int]:
    """``{code: http}`` over the four blocks; the blocks are disjoint."""
    blocks = (PHASE_A_CODES, PHASE_B_CODES, PHASE_B2_CODES, PHASE_B4_CODES)
    table: dict[str, int] = {}
    for block in blocks:
        for code, http in block.items():
            assert code not in table, f"{code} appears in two blocks"
            table[code] = http
    assert len(PHASE_A_CODES) == 27
    return table


def test_table_constants_present() -> None:
    """Every code in the table is a constant whose name is the upper-cased code, with its status."""
    table = _table()
    for code, http in table.items():
        constant = code.upper()
        assert hasattr(errors, constant), f"redsim.api.errors lacks {constant} for {code!r}"
        assert getattr(errors, constant) == code
        assert errors.HTTP_STATUS[code] == http, f"{code}: table says {http}, errors says {errors.HTTP_STATUS[code]}"
        assert errors.http_status(code) == http
        assert constant in errors.__all__, f"{constant} is missing from errors.__all__"
    # And nothing beyond the table: it is the whole vocabulary.
    assert set(errors.ALL_CODES) == set(table)
    assert set(errors.HTTP_STATUS) == set(table)


def test_addendum_blocks_are_disjoint_and_in_status_order() -> None:
    assert set(PHASE_B2_CODES).isdisjoint(PHASE_B_CODES)
    assert set(PHASE_B4_CODES).isdisjoint(PHASE_B_CODES) and set(PHASE_B4_CODES).isdisjoint(PHASE_B2_CODES)
    for block in (PHASE_B2_CODES, PHASE_B4_CODES):
        statuses = list(block.values())
        assert statuses == sorted(statuses)


def test_b4_codes_in_table_and_the_routes_no_longer_fall_back() -> None:
    """Constants, statuses, envelopes; the getattr fallbacks of the B2 routes resolve to the table."""
    for code, http in PHASE_B4_CODES.items():
        constant = code.upper()
        assert getattr(errors, constant) == code
        assert constant in errors.__all__, constant
        assert errors.HTTP_STATUS[code] == http
        assert errors.http_status(code) == http
        assert 400 <= http < 600 and code not in errors.MARKER_CODES, f"{code} is a refusal, never a marker"
        detail = errors.error_detail(code)
        assert detail == {"code": code, "message": detail["message"]} and detail["message"]
        exc = errors.ApiError(code, "why", field="x")
        assert exc.status == http and exc.detail == {"code": code, "message": "why", "field": "x"}
    assert errors.STRING_DETAIL_CODES.isdisjoint(PHASE_B4_CODES)
    assert errors.PHASE_REQUIRED_CODES.isdisjoint(PHASE_B4_CODES)
    assert errors.HTTP_STATUS[errors.ENDPOINT_AUTH_FAILED] == errors.HTTP_STATUS[errors.ENDPOINT_UNREACHABLE] == 502
    # The modules that resolved these by name now carry the table spelling, not the stand-in.
    try:
        from redsim.api.v1 import models as models_route
        from redsim.api.v1 import projects as projects_route
        from redsim.services import ml_llm
    except Exception:  # noqa: BLE001 - the web stack is optional for the table itself
        pytest.skip("the API routes are not importable here")
    assert models_route.ATTESTATION_REQUIRED == errors.ATTESTATION_REQUIRED
    assert projects_route.SCORING_WEIGHTS_INVALID == errors.SCORING_WEIGHTS_INVALID
    for name in ("MODEL_ID_INVALID", "MODEL_NOT_CHAT", "GATEWAY_URL_REQUIRED", "UNKNOWN_PROBE", "PROBE_EXCLUDED",
                 "PROBE_DETECTOR_UNAVAILABLE", "LLM_PROBE_QUOTA_EXCEEDED"):
        assert getattr(ml_llm, name) == getattr(errors, name), name
    try:
        from redsim.ml import errors as ml_errors
    except Exception:  # noqa: BLE001 - the ml extra is optional for the table itself
        return
    assert ml_errors.EndpointAuthFailed.code == errors.ENDPOINT_AUTH_FAILED


def test_b2_codes_in_table() -> None:
    """The B2 codes: constant, status, envelope."""
    for code, http in PHASE_B2_CODES.items():
        constant = code.upper()
        assert getattr(errors, constant) == code
        assert constant in errors.__all__, constant
        assert errors.HTTP_STATUS[code] == http
        assert errors.http_status(code) == http
        assert 400 <= http < 500, f"{code} is a refusal, never a marker"
        assert code not in errors.MARKER_CODES
        detail = errors.error_detail(code)
        assert detail == {"code": code, "message": detail["message"]}
        assert isinstance(detail["message"], str) and detail["message"]
        exc = errors.ApiError(code, "why", field="x")
        assert exc.status == http
        assert exc.detail == {"code": code, "message": "why", "field": "x"}
    # The brief's statuses, spelled once more so a table edit cannot silently move one.
    assert errors.HTTP_STATUS[errors.AUTH_PROFILE_REQUIRED] == 422
    assert errors.HTTP_STATUS[errors.AUTH_PROFILE_IN_USE] == 409
    assert errors.HTTP_STATUS[errors.QUERY_BUDGET_EXCEEDED] == 429
    assert errors.HTTP_STATUS[errors.BATCH_MEMBER_REFUSED] == 422
    assert errors.HTTP_STATUS[errors.BULK_TOO_LARGE] == 413
    assert errors.HTTP_STATUS[errors.BULK_TOO_MANY_FILES] == 422
    assert errors.HTTP_STATUS[errors.IDEMPOTENCY_KEY_REUSED] == 409
    assert errors.HTTP_STATUS[errors.IDEMPOTENCY_CONFLICT] == 409
    assert errors.HTTP_STATUS[errors.FIXTURE_NOT_EXPORTABLE] == 422
    assert errors.HTTP_STATUS[errors.REVIEW_STATE_CONFLICT] == 409
    assert errors.HTTP_STATUS[errors.REVIEWER_NOT_INDEPENDENT] == 403
    assert errors.HTTP_STATUS[errors.SNAPSHOT_ARCHIVED] == 409
    assert errors.HTTP_STATUS[errors.PROBE_KEY_REQUIRED] == 422


def test_b2_envelopes_carry_the_documented_fields() -> None:
    """Each refusal carries its documented context; the envelope passes it through untouched."""
    members = [{"target_id": "t2", "code": "attack_requires_gradients", "message": "no gradients"}]
    batch = errors.ApiError(errors.BATCH_MEMBER_REFUSED, members=members)
    assert batch.status == 422 and batch.detail["members"] == members
    budget = errors.ApiError(errors.QUERY_BUDGET_EXCEEDED, estimate=640_000, cap=500_000)
    assert budget.status == 429 and (budget.detail["estimate"], budget.detail["cap"]) == (640_000, 500_000)
    in_use = errors.ApiError(errors.AUTH_PROFILE_IN_USE, target_ids=["t1", "t2"])
    assert in_use.detail["target_ids"] == ["t1", "t2"]
    reused = errors.ApiError(errors.IDEMPOTENCY_KEY_REUSED, request_sha256="0" * 64)
    assert reused.detail["request_sha256"] == "0" * 64
    conflict = errors.ApiError(errors.REVIEW_STATE_CONFLICT, status="open", review_state="in_review")
    assert conflict.detail == {"code": "review_state_conflict", "message": conflict.detail["message"],
                               "status": "open", "review_state": "in_review"}
    independence = errors.ApiError(errors.REVIEWER_NOT_INDEPENDENT, relation="campaign_creator")
    assert independence.status == 403 and independence.detail["relation"] == "campaign_creator"
    # 403 with a structured body: the string-detail shortcut is for the retained routes only.
    fastapi = pytest.importorskip("fastapi")
    http = errors.api_error(errors.REVIEWER_NOT_INDEPENDENT, relation="revision_author")
    assert isinstance(http, fastapi.HTTPException)
    assert http.status_code == 403
    assert http.detail == {"code": "reviewer_not_independent",
                           "message": errors.error_detail(errors.REVIEWER_NOT_INDEPENDENT)["message"],
                           "relation": "revision_author"}
    plain = errors.api_error(errors.REVIEWER_NOT_INDEPENDENT)
    assert isinstance(plain.detail, dict), "a B2 code never collapses to a plain string"


def test_query_budget_code_matches_the_broker_error_class() -> None:
    """The broker's ``QueryBudgetExceeded.code`` is the table spelling, so the two never drift."""
    try:
        from redsim.ml import endpoint_broker
    except Exception:  # noqa: BLE001 - the broker needs the ml extra; the table does not
        pytest.skip("redsim.ml.endpoint_broker is not importable here")
    cls = getattr(endpoint_broker, "QueryBudgetExceeded", None)
    if cls is None:
        pytest.skip("QueryBudgetExceeded is not defined in the broker")
    assert getattr(cls, "code", None) == errors.QUERY_BUDGET_EXCEEDED


def test_phase_b_codes_in_table() -> None:
    """The B0 codes: constant, status, envelope."""
    for code, http in PHASE_B_CODES.items():
        constant = code.upper()
        assert getattr(errors, constant) == code
        assert errors.HTTP_STATUS[code] == http
        detail = errors.error_detail(code)
        assert detail["code"] == code
        assert isinstance(detail["message"], str) and detail["message"]
        assert "phase" not in detail, f"{code} is a real code, not a phase deferral"
        if code in errors.MARKER_CODES:
            continue
        exc = errors.ApiError(code, "why", field="x")
        assert exc.status == http
        assert exc.detail == {"code": code, "message": "why", "field": "x"}
    # The brief's statuses, spelled once more so a table edit cannot silently move one.
    assert errors.HTTP_STATUS[errors.ENDPOINT_URL_INVALID] == 422
    assert errors.HTTP_STATUS[errors.ENDPOINT_NOT_ALLOWLISTED] == 403
    assert errors.HTTP_STATUS[errors.AUTH_PROFILE_KIND_UNSUPPORTED] == 422
    assert errors.HTTP_STATUS[errors.ENDPOINT_UNREACHABLE] == 502
    assert errors.HTTP_STATUS[errors.ENDPOINT_SCHEMA_MISMATCH] == 422
    assert errors.HTTP_STATUS[errors.EGRESS_REFUSED] == 403
    assert errors.HTTP_STATUS[errors.PROBE_SET_UNKNOWN] == 422
    assert errors.HTTP_STATUS[errors.LLM_TARGET_REQUIRED] == 409
    assert errors.HTTP_STATUS[errors.DATASET_TOO_LARGE] == 413
    assert errors.HTTP_STATUS[errors.UNSUPPORTED_DATASET_FORMAT] == 415
    assert errors.HTTP_STATUS[errors.REMOTE_REFERENCE_REFUSED] == 422
    assert errors.HTTP_STATUS[errors.SCHEMA_UNDECLARED] == 422
    assert errors.HTTP_STATUS[errors.EXPORT_IN_FLIGHT] == 409
    assert errors.HTTP_STATUS[errors.EXPORT_UNAVAILABLE] == 409
    assert errors.HTTP_STATUS[errors.INTEGRATION_DISABLED] == 501
    assert errors.HTTP_STATUS[errors.BATCH_MODALITY_MISMATCH] == 422
    assert errors.HTTP_STATUS[errors.BATCH_TOO_LARGE] == 422
    assert errors.HTTP_STATUS[errors.CAPACITY_DEFERRED] == 202
    assert errors.HTTP_STATUS[errors.DAILY_BUDGET_EXCEEDED] == 429
    assert errors.HTTP_STATUS[errors.RESOLUTION_BLOCKED] == 409
    assert errors.HTTP_STATUS[errors.REVIEW_TRANSITION_INVALID] == 409
    assert errors.HTTP_STATUS[errors.SNAPSHOT_NOT_FOUND] == 404
    assert errors.HTTP_STATUS[errors.LICENSE_REQUIRED] == 422


def test_license_required_matches_the_upload_route_spelling() -> None:
    """``license_required`` moved into the table with the value the upload route already emits."""
    assert errors.LICENSE_REQUIRED == "license_required"
    try:
        from redsim.api.v1 import models as models_route
    except Exception:  # noqa: BLE001 - the route needs the web stack; the table does not
        pytest.skip("redsim.api.v1.models is not importable here")
    local = getattr(models_route, "LICENSE_REQUIRED", None)
    if local is not None:
        assert local == errors.LICENSE_REQUIRED, "models.py spells license_required differently from the table"


def test_capacity_deferred_is_a_marker_not_a_refusal() -> None:
    """The 202 marker rides in an accepted body; raising it as an exception is a programming error."""
    assert errors.MARKER_CODES == {errors.CAPACITY_DEFERRED}
    assert errors.MARKER_CODES <= set(errors.ALL_CODES)
    for code in errors.MARKER_CODES:
        assert 200 <= errors.HTTP_STATUS[code] < 300
    for code in set(errors.ALL_CODES) - errors.MARKER_CODES:
        assert errors.HTTP_STATUS[code] >= 400, f"{code} is a refusal code with a non-error status"
    body = errors.error_detail(errors.CAPACITY_DEFERRED, resets_at="2026-09-10T00:00:00Z")
    assert body == {
        "code": "capacity_deferred",
        "message": errors.error_detail(errors.CAPACITY_DEFERRED)["message"],
        "resets_at": "2026-09-10T00:00:00Z",
    }
    with pytest.raises(ValueError, match="marker, not a refusal"):
        errors.ApiError(errors.CAPACITY_DEFERRED)
    fastapi = pytest.importorskip("fastapi")
    with pytest.raises(ValueError, match="marker, not a refusal"):
        errors.api_error(errors.CAPACITY_DEFERRED)
    assert fastapi is not None


def test_phase_b_codes_keep_the_structured_envelope() -> None:
    """None of the addendum codes joins the plain-string set, and none grows a phase."""
    assert errors.STRING_DETAIL_CODES.isdisjoint(PHASE_B_CODES)
    assert errors.PHASE_REQUIRED_CODES.isdisjoint(PHASE_B_CODES)
    assert errors.STRING_DETAIL_CODES.isdisjoint(PHASE_B2_CODES)
    assert errors.PHASE_REQUIRED_CODES.isdisjoint(PHASE_B2_CODES)
    assert errors.MARKER_CODES.isdisjoint(PHASE_B2_CODES)
    # ``integration_disabled`` is a 501 for a configuration state, not a phase deferral:
    # it must not borrow ``not_implemented``'s phase marker.
    assert "phase" not in errors.error_detail(errors.INTEGRATION_DISABLED, integration="foundry")
    fastapi = pytest.importorskip("fastapi")
    exc = errors.api_error(errors.BATCH_MODALITY_MISMATCH, groups={"image": ["t1"], "tabular": ["t2"]})
    assert isinstance(exc, fastapi.HTTPException)
    assert exc.status_code == 422
    assert exc.detail["groups"] == {"image": ["t1"], "tabular": ["t2"]}
    blocked = errors.ApiError(errors.RESOLUTION_BLOCKED, unmet=["validation_state", "settings_hash"])
    assert blocked.status == 409
    assert blocked.detail["unmet"] == ["validation_state", "settings_hash"]


def test_string_detail_codes_are_the_retained_route_ones() -> None:
    assert errors.STRING_DETAIL_CODES == {"forbidden", "not_found", "rate_limited", "db_unavailable"}
    assert errors.STRING_DETAIL_CODES <= set(errors.ALL_CODES)


def test_error_detail_shape() -> None:
    detail = errors.error_detail(errors.INCOMPATIBLE_CAMPAIGNS, "settings differ", reasons=["eps_grid"])
    assert detail == {
        "code": "incompatible_campaigns",
        "message": "settings differ",
        "reasons": ["eps_grid"],
    }
    # A default message exists for every code, so a bare call is still a full envelope.
    for code in errors.ALL_CODES:
        bare = errors.error_detail(code)
        assert bare["code"] == code
        assert isinstance(bare["message"], str) and bare["message"]


def test_not_implemented_always_carries_phase() -> None:
    assert errors.error_detail(errors.NOT_IMPLEMENTED)["phase"] == "B"
    assert errors.error_detail(errors.NOT_IMPLEMENTED, "garak", phase="B")["phase"] == "B"
    # Other codes do not grow a phase they were not given.
    assert "phase" not in errors.error_detail(errors.MODEL_LOAD_REFUSED)


def test_error_detail_refuses_off_table_codes() -> None:
    with pytest.raises(ValueError, match="not a spec 17.3 error code"):
        errors.error_detail("model_not_found")
    with pytest.raises(ValueError):
        errors.ApiError("campaign_not_implemented")
    with pytest.raises(KeyError):
        errors.http_status("artifact_not_found")
    # The register's alternative spellings are not codes: the addendum names the table name.
    for alias in ("project_run_budget_exceeded", "export_blocked_pending_d006",
                  "dataset_not_exported", "integration_not_configured",
                  # REVIEW_REPORTS-32's spelling of the in-flight case is ``idempotency_conflict``.
                  "idempotency_in_flight"):
        with pytest.raises(ValueError):
            errors.error_detail(alias)


def test_api_error_carries_code_status_and_detail() -> None:
    exc = errors.ApiError(errors.MODEL_LOAD_REFUSED, "model is refused", status="refused",
                          refusal_reason="pickle_refused")
    assert exc.code == "model_load_refused"
    assert exc.status == 409
    assert exc.detail == {
        "code": "model_load_refused",
        "message": "model is refused",
        "status": "refused",
        "refusal_reason": "pickle_refused",
    }
    assert str(exc) == "model is refused"
    http = exc.as_http_exception()
    assert http.status_code == 409
    assert http.detail == exc.detail


def test_api_error_helper_matches_table_and_keeps_string_details() -> None:
    fastapi = pytest.importorskip("fastapi")
    structured = errors.api_error(errors.MODEL_TOO_LARGE, "512 MB cap", field="file")
    assert isinstance(structured, fastapi.HTTPException)
    assert structured.status_code == 413
    assert structured.detail == {"code": "model_too_large", "message": "512 MB cap", "field": "file"}
    plain = errors.api_error(errors.NOT_FOUND, "run not found")
    assert plain.status_code == 404
    assert plain.detail == "run not found"
    phased = errors.api_error(errors.NOT_IMPLEMENTED, "endpoint connector")
    assert phased.status_code == 501
    assert phased.detail["phase"] == "B"
