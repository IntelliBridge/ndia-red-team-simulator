"""G-ERR1: ``redsim.api.errors`` is the spec section 17.3 table, one constant per code.

The table is read from the spec document itself (the 17.3 table plus its dated
Phase B addendum and the addendum's second table of wave B2) so a code added or
renamed there fails here rather than in the UI.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from redsim.api import errors

_SPEC = (
    Path(__file__).resolve().parents[2]
    / "docs" / "superpowers" / "specs" / "2026-09-08-adversarial-ml-redteam-spec.md"
)
_ROW = re.compile(r"^\|\s*(?P<codes>(?:`[a-z_]+`(?:\s*\([^)]*\))?\s*/?\s*)+)\|\s*(?P<http>\d{3})\s*\|")

#: The Phase A table as frozen at M0 (29 codes).
_PHASE_A_COUNT = 29

#: The 17.3 addendum of 2026-09-09 (plan 12 wave B0, actions-and-codes track): code -> HTTP.
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

#: The addendum's second table (wave B2, ``codes-b2`` track, 2026-09-09): code -> HTTP.
#: The brief's statuses win over the register where they differ (see the spec note).
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
_B2_MARKER = "17.3 addendum, second table (Phase B wave B2, `codes-b2` track, 2026-09-09)"

#: The addendum's third table (wave B4, ``fix-api-services`` track, 2026-09-09): the codes the B2 routes
#: resolved with ``getattr`` fallbacks (ENDPOINT-31, REVIEW_REPORTS-28, LLM-09/-12/-21, ENDPOINT-28 note).
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
_B4_MARKER = "17.3 addendum, third table (Phase B wave B4, `fix-api-services` track, 2026-09-09)"


def _section_173() -> str:
    text = _SPEC.read_text(encoding="utf-8")
    start = text.index("### 17.3 Conventions and error codes")
    end = text.index("### 17.4", start)
    return text[start:end]


def _spec_table() -> dict[str, int]:
    """``{code: http}`` from the 17.3 table and its addendum; ``a / b`` rows yield two codes."""
    table: dict[str, int] = {}
    for line in _section_173().splitlines():
        match = _ROW.match(line)
        if not match:
            continue
        for code in re.findall(r"`([a-z_]+)`", match.group("codes")):
            assert code not in table, f"{code} has two rows in spec 17.3"
            table[code] = int(match.group("http"))
    expected = _PHASE_A_COUNT + len(PHASE_B_CODES) + len(PHASE_B2_CODES) + len(PHASE_B4_CODES)
    assert len(table) >= expected, f"parsed only {len(table)} codes from the spec table"
    return table


def test_table_constants_present() -> None:
    """Every code named in spec 17.3 is a constant whose name is the upper-cased code."""
    table = _spec_table()
    for code, http in table.items():
        constant = code.upper()
        assert hasattr(errors, constant), f"redsim.api.errors lacks {constant} for {code!r}"
        assert getattr(errors, constant) == code
        assert errors.HTTP_STATUS[code] == http, f"{code}: spec says {http}, table says {errors.HTTP_STATUS[code]}"
        assert errors.http_status(code) == http
        assert constant in errors.__all__, f"{constant} is missing from errors.__all__"
    # And nothing beyond the spec: the table is the whole vocabulary.
    assert set(errors.ALL_CODES) == set(table)
    assert set(errors.HTTP_STATUS) == set(table)


def test_phase_b_addendum_is_dated_and_parsed() -> None:
    """The 17.3 addendum sits inside 17.3, carries its date, and lists exactly the Phase B codes."""
    section = _section_173()
    assert "17.3 addendum (Phase B, 2026-09-09)" in section
    table = _spec_table()
    for code, http in PHASE_B_CODES.items():
        assert table.get(code) == http, f"{code}: addendum says {table.get(code)}, expected {http}"
    # The Phase A rows are untouched: what is not in any addendum set is the original 29.
    assert len(set(table) - set(PHASE_B_CODES) - set(PHASE_B2_CODES) - set(PHASE_B4_CODES)) == _PHASE_A_COUNT
    # Every Phase B code sits after the original table and before 17.4.
    addendum_at = section.index("17.3 addendum (Phase B, 2026-09-09)")
    for code in PHASE_B_CODES:
        assert section.index(f"| `{code}`") > addendum_at, code


def test_b2_addendum_table_is_dated_and_parsed() -> None:
    """The second addendum table sits after the first, inside 17.3, and lists exactly the B2 codes."""
    section = _section_173()
    assert _B2_MARKER in section
    first_at = section.index("17.3 addendum (Phase B, 2026-09-09)")
    second_at = section.index(_B2_MARKER)
    assert second_at > first_at
    table = _spec_table()
    for code, http in PHASE_B2_CODES.items():
        assert table.get(code) == http, f"{code}: spec says {table.get(code)}, expected {http}"
        assert section.index(f"| `{code}`") > second_at, code
    # The addendum sets are disjoint and none overlaps Phase A.
    assert set(PHASE_B2_CODES).isdisjoint(PHASE_B_CODES)
    assert set(PHASE_B4_CODES).isdisjoint(PHASE_B_CODES) and set(PHASE_B4_CODES).isdisjoint(PHASE_B2_CODES)
    # The B0 rows stay where they were: every B0 code appears before the second table.
    for code in PHASE_B_CODES:
        assert section.index(f"| `{code}`") < second_at, code
    # The rows are in status order, like the tables before them.
    statuses = [http for _, http in PHASE_B2_CODES.items()]
    assert statuses == sorted(statuses)
    # The note records where the brief overrode the register, so a reader finds the rationale.
    for phrase in ("`query_budget_exceeded` is `429`", "`idempotency_key_reused` is `409`",
                   "`fixture_not_exportable` is `422`", "`idempotency_in_flight` is `idempotency_conflict`"):
        assert phrase in section, phrase


def test_b4_addendum_table_is_dated_and_parsed() -> None:
    """The third table sits after the second, inside 17.3, lists exactly the B4 codes, in status order."""
    section = _section_173()
    assert _B4_MARKER in section
    second_at = section.index(_B2_MARKER)
    third_at = section.index(_B4_MARKER)
    assert third_at > second_at
    table = _spec_table()
    for code, http in PHASE_B4_CODES.items():
        assert table.get(code) == http, f"{code}: spec says {table.get(code)}, expected {http}"
        assert section.index(f"| `{code}`") > third_at, code
    for code in PHASE_B2_CODES:
        assert section.index(f"| `{code}`") < third_at, code
    statuses = [http for _, http in PHASE_B4_CODES.items()]
    assert statuses == sorted(statuses)
    # The row that named the register's working contract now names the built one.
    row = next(line for line in section.splitlines() if line.startswith("| `endpoint_schema_mismatch`"))
    assert "`endpoint-v1`" in row and "outside the `redsim-predict-proba/1` contract" not in row


def test_b4_codes_in_table_and_the_routes_no_longer_fall_back() -> None:
    """ENDPOINT-31, REVIEW_REPORTS-28, LLM-12: constants, statuses, envelopes; the getattr fallbacks resolve."""
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
    """Register ENDPOINT-06/-08/-18, LLM-03/-04, BULK-03/-10/-11/-13, INTEROP-10, REVIEW_REPORTS-06/-12/-22."""
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
    """The spec rows name the context each refusal carries; the envelope passes it through untouched."""
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
    """ENDPOINT-06: the broker's ``QueryBudgetExceeded.code`` is the table spelling, so the two never drift."""
    try:
        from redsim.ml import endpoint_broker
    except Exception:  # noqa: BLE001 - the broker needs the ml extra; the table does not
        pytest.skip("redsim.ml.endpoint_broker is not importable here")
    cls = getattr(endpoint_broker, "QueryBudgetExceeded", None)
    if cls is None:
        pytest.skip("QueryBudgetExceeded is not defined in the broker")
    assert getattr(cls, "code", None) == errors.QUERY_BUDGET_EXCEEDED


def test_phase_b_codes_in_table() -> None:
    """Register ENDPOINT-06 / INTEROP-03 / BULK-10 / REVIEW_REPORTS-04: constant, status, envelope."""
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
