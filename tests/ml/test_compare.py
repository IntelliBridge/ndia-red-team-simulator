"""``GET /v1/runs/{id}/compare`` (register G-CMP1, spec 15.6, 17.2, 17.3).

Variable-level ``409 incompatible_campaigns`` reasons, strict ``409 score_unavailable``
on a partial score, two full scorecards for the same settings on a different model
(``mode`` is always ``side_by_side``; nothing is computed between the runs), and
membership on both runs. Harness: ``ml_api`` from ``test_findings_routes.py``.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from tests.ml.test_findings_routes import (  # noqa: F401 - fixture import
    BASELINE,
    FOREIGN,
    OTHER_MODEL,
    OTHER_PROJECT,
    OTHER_SEED,
    PARTIAL,
    _user,
    ml_api,
)

pytestmark = pytest.mark.integration

_REMOVED_KEYS = ("delta", "delta_mri", "delta_source", "delta_note", "delta_dimensions", "delta_acc_clean",
                 "delta_families", "mri_before", "mri_after", "verify_run_id", "baseline_run_id", "defense")


def _compare(client: Any, run_id: str, other: str) -> Any:
    return client.get(f"/v1/runs/{run_id}/compare", params={"with": other})


def test_incompatible_score_unavailable_and_side_by_side(ml_api: dict[str, Any]) -> None:  # noqa: F811
    client = ml_api["as_user"](_user("reader", "viewer"))

    # Different seed and slice: every mismatched variable is named, nothing else is revealed.
    incompatible = _compare(client, BASELINE, OTHER_SEED)
    assert incompatible.status_code == 409
    detail = incompatible.json()["detail"]
    assert detail["code"] == "incompatible_campaigns"
    assert detail["reasons"] == ["n_samples", "seed", "sample_indices_sha256"]
    assert set(detail) == {"code", "message", "reasons"}
    # Symmetric.
    assert _compare(client, OTHER_SEED, BASELINE).json()["detail"]["reasons"] == detail["reasons"]

    # A partial score (mri None) is refused, not compared on the subscores it does have.
    partial = _compare(client, BASELINE, PARTIAL)
    assert partial.status_code == 409
    assert partial.json()["detail"]["code"] == "score_unavailable"
    assert partial.json()["detail"]["reasons"] == [f"{PARTIAL}: MRI not computed (S_expl unavailable (explainer failed))"]

    # Same settings, different model: two scorecards, nothing computed between them.
    side = _compare(client, BASELINE, OTHER_MODEL)
    assert side.status_code == 200, side.text
    body = side.json()
    assert body["compatible"] is True and body["mode"] == "side_by_side"
    assert not any(key in body for key in _REMOVED_KEYS), sorted(set(body) & set(_REMOVED_KEYS))
    assert body["changed_variables"] == ["model", "target"]
    assert "model_sha256" not in body["unchanged_variables"] and "seed" in body["unchanged_variables"]
    for variable in ("seed", "n_samples", "eps_grid", "reference_eps", "norm", "attack_ids", "dataset_id",
                     "modality", "sample_indices_sha256"):
        assert variable in body["unchanged_variables"], variable
    assert "defense" not in body["unchanged_variables"] and "defense" not in body["ignored_variables"]
    assert "llm_narrative" in body["ignored_variables"] and "reviewer_notes" in body["ignored_variables"]
    assert [card["run_id"] for card in body["scorecards"]] == [BASELINE, OTHER_MODEL]
    for card in body["scorecards"]:
        assert card["mri"] == 42 and card["grade"] == "D"
        assert card["subscores"] and card["inputs"] and card["per_attack"]
        assert len(card["measurements"]) == 10 and len(card["curve"]) == 2
        assert card["limitations"]
        assert not any(key in card for key in _REMOVED_KEYS)
    assert body["scorecards"][0]["model_sha256"] == "d0" * 32
    assert body["scorecards"][1]["model_sha256"] == "e1" * 32
    assert body["caveats"] == sorted(set(body["caveats"]))
    # The comparison is symmetric in what it reveals.
    assert _compare(client, OTHER_MODEL, BASELINE).json()["mode"] == "side_by_side"

    # Membership on both runs, before either record is read.
    foreign = _compare(client, BASELINE, FOREIGN)
    assert foreign.status_code == 403 and "reasons" not in str(foreign.json())
    assert _compare(client, FOREIGN, BASELINE).status_code == 403
    assert _compare(client, BASELINE, "run-missing").status_code == 404
    outsider = ml_api["as_user"](_user("outsider", "admin", project=OTHER_PROJECT))
    assert _compare(outsider, BASELINE, FOREIGN).status_code == 403
    assert _compare(outsider, FOREIGN, FOREIGN).status_code == 200
