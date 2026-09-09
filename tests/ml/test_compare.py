"""``GET /v1/runs/{id}/compare`` (register G-CMP1, spec 15.6, 17.2, 17.3).

Variable-level ``409 incompatible_campaigns`` reasons, strict ``409 score_unavailable``
on a partial score, the verify pairing's measured delta (persisted, or computed through
``redsim.ml.scoring.delta`` whose ``IncompatibleCampaigns`` becomes the 409), two full
scorecards for the same settings on a different model, and membership on both runs.
Harness: ``ml_api`` from ``test_findings_routes.py``.
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
    VERIFY,
    VERIFY_HASH_DRIFT,
    VERIFY_UNSCORED_DELTA,
    _user,
    ml_api,
)

pytestmark = pytest.mark.integration


def _compare(client: Any, run_id: str, other: str) -> Any:
    return client.get(f"/v1/runs/{run_id}/compare", params={"with": other})


def test_incompatible_verify_delta_and_side_by_side(ml_api: dict[str, Any]) -> None:  # noqa: F811
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

    # Verify pairing with the worker's persisted delta.
    paired = _compare(client, BASELINE, VERIFY)
    assert paired.status_code == 200, paired.text
    body = paired.json()
    assert body["compatible"] is True and body["mode"] == "verify_delta"
    assert body["delta_source"] == "persisted"
    assert body["verify_run_id"] == VERIFY and body["baseline_run_id"] == BASELINE
    assert body["defense"]["id"] == "feature_squeezing"
    assert body["mri_before"] == 42 and body["mri_after"] == 55 and body["delta_mri"] == 13
    assert body["delta_dimensions"]["S_asr"] == 20.0
    assert body["delta_acc_clean"]["before"]["n"] == 200 and body["delta_acc_clean"]["delta"] == -0.01
    assert body["delta_families"] == [{
        "family": "m.evasion.fgsm.eps0.03", "before": 0.56, "after": 0.75,
        "n_before": 200, "n_after": 200, "delta": 0.19,
    }]
    assert body["changed_variables"] == ["defense"]
    for variable in ("seed", "n_samples", "eps_grid", "reference_eps", "norm", "attack_ids", "dataset_id",
                     "modality", "sample_indices_sha256", "model_sha256", "settings_hash"):
        assert variable in body["unchanged_variables"], variable
    assert "defense" not in body["unchanged_variables"]
    assert "llm_narrative" in body["ignored_variables"] and "reviewer_notes" in body["ignored_variables"]
    assert body["caveats"] and "delta" not in body  # the measured block is named, never a bare "delta" key
    # The pairing is recognised from either side.
    assert _compare(client, VERIFY, BASELINE).json()["delta_mri"] == 13

    # No persisted delta: the same scoring.delta over the two stored records (identical here).
    computed = _compare(client, BASELINE, VERIFY_UNSCORED_DELTA)
    assert computed.status_code == 200, computed.text
    assert computed.json()["mode"] == "verify_delta" and computed.json()["delta_source"] == "computed"
    assert computed.json()["delta_mri"] == 0 and computed.json()["mri_before"] == 42
    assert all(f["n_before"] == 200 and f["n_after"] == 200 for f in computed.json()["delta_families"])
    assert len(computed.json()["delta_families"]) == 6

    # scoring.delta's typed refusal is the 409 with its reasons.
    drift = _compare(client, BASELINE, VERIFY_HASH_DRIFT)
    assert drift.status_code == 409
    assert drift.json()["detail"]["code"] == "incompatible_campaigns"
    assert drift.json()["detail"]["reasons"] == ["settings_hash differs"]

    # Same settings, different model: two scorecards, never one delta.
    side = _compare(client, BASELINE, OTHER_MODEL)
    assert side.status_code == 200, side.text
    body = side.json()
    assert body["mode"] == "side_by_side" and body["delta"] is None
    assert body["changed_variables"] == ["model", "target"]
    assert "model_sha256" not in body["unchanged_variables"] and "seed" in body["unchanged_variables"]
    assert [card["run_id"] for card in body["scorecards"]] == [BASELINE, OTHER_MODEL]
    for card in body["scorecards"]:
        assert card["mri"] == 42 and card["grade"] == "D"
        assert card["subscores"] and card["inputs"] and card["per_attack"]
        assert len(card["measurements"]) == 10 and len(card["curve"]) == 2
        assert card["limitations"]
    assert body["scorecards"][0]["model_sha256"] == "d0" * 32
    assert body["scorecards"][1]["model_sha256"] == "e1" * 32
    assert body["caveats"] == sorted(set(body["caveats"]))

    # Membership on both runs, before either record is read.
    foreign = _compare(client, BASELINE, FOREIGN)
    assert foreign.status_code == 403 and "reasons" not in str(foreign.json())
    assert _compare(client, FOREIGN, BASELINE).status_code == 403
    assert _compare(client, BASELINE, "run-missing").status_code == 404
    outsider = ml_api["as_user"](_user("outsider", "admin", project=OTHER_PROJECT))
    assert _compare(outsider, BASELINE, FOREIGN).status_code == 403
    assert _compare(outsider, FOREIGN, FOREIGN).status_code == 200
