"""G-ERR1: ``redsim.api.errors`` is the spec section 17.3 table, one constant per code.

The table is read from the spec document itself so a code added or renamed there
fails here rather than in the UI.
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


def _spec_table() -> dict[str, int]:
    """``{code: http}`` from the 17.3 table; ``a / b`` rows yield two codes."""
    text = _SPEC.read_text(encoding="utf-8")
    start = text.index("### 17.3 Conventions and error codes")
    end = text.index("### 17.4", start)
    table: dict[str, int] = {}
    for line in text[start:end].splitlines():
        match = _ROW.match(line)
        if not match:
            continue
        for code in re.findall(r"`([a-z_]+)`", match.group("codes")):
            table[code] = int(match.group("http"))
    assert len(table) >= 29, f"parsed only {len(table)} codes from the spec table"
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
    # And nothing beyond the spec: the table is the whole vocabulary.
    assert set(errors.ALL_CODES) == set(table)
    assert set(errors.HTTP_STATUS) == set(table)


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
