"""Batch campaigns, batch cancel, batch compare and bulk verify (register BULK-03..09, -15; plan 12 wave B3).

Offline over the ``tests/ml/test_campaign_routes.py`` harness: a file-backed sqlite
database with the ``ml_campaigns`` mirror (now carrying ``batch_id``), the real
FastAPI app in dev auth with the user dependency overridden, a recording in-memory
audit writer and ``ml_campaign_run.delay`` replaced by a fake. Nothing here imports
an ML library beyond what the admission service itself loads.

Pinned:

* a batch of two same-modality models admits both through the single-run boundary
  (one ``batch.create`` row first, then one ``attack.run`` row per member before its
  ``Run`` exists), stamps ``batch_id`` on every member's campaign row, ``Run`` and
  ``Job``, and rolls up ``queued`` -> ``running`` -> ``succeeded`` / ``partial`` from
  the member runs without ever carrying an aggregate score;
* a cross-modality request is ``422 batch_modality_mismatch`` with ``groups`` and
  writes nothing but the refusal row;
* a per-member refusal is collected on the batch (``refused``) while the other member
  runs; when every member is refused the batch is ``422 batch_member_refused`` with
  ``members``;
* cancel writes ``batch.cancel`` first, then ``run.cancel`` per live member, and a
  second cancel is ``409 run_terminal``;
* the compare route groups scorecards by comparability with no delta, mean or rank,
  answers ``409 incompatible_campaigns`` listing the groups when settings differ and
  lists unscored members under ``unavailable``;
* bulk verify admits one defended run per (defense, params) over every selected
  finding of the baseline run with ``Job.detail.finding_ids`` and one ``verify.replay``
  row per finding, and skips findings that are in flight or dismissed;
* RBAC: viewer and stranger are refused with the plain 403, ``batch.run`` is the
  scanner tier and cancel and bulk verify the remediator tier.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import HTTP_STATUS
from redsim.db.models import Artifact, Finding, Job, MlBatch, Run
from redsim.ml import compare as cmp
from redsim.ml.schema import CampaignRecord
from redsim.services.ml_batches import (
    BATCH_MAX_MEMBERS_ENV,
    batch_max_members,
    rollup_status,
)
from tests.ml.test_admission import seed_verify_baseline
from tests.ml.test_campaign_routes import (
    ACTOR,
    MODEL,
    PROJECT,
    SHA256,
    Harness,
    build_harness,
    seed_model,
)

pytestmark = pytest.mark.integration


CAPACITY_ENV = "REDSIM_ML_MAX_CONCURRENT_RUNS_PER_PROJECT"
BUDGET_ENVS = ("REDSIM_ML_DAILY_RUN_BUDGET", "REDSIM_ML_PROJECT_DAILY_RUN_BUDGET")


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Harness]:
    """The campaign-routes harness (file-backed sqlite, real app, recording writer, fake Celery delay).

    The per-project capacity caps of ``redsim.services.ml_capacity`` (a sibling track) are pinned wide
    open so the batch semantics under test do not depend on the deployment defaults; the two tests
    that exercise the capacity seam narrow them explicitly.
    """
    import redsim.api.middleware.rate_limit as rl

    monkeypatch.setenv(CAPACITY_ENV, "100")
    for name in BUDGET_ENVS:
        monkeypatch.delenv(name, raising=False)
    rl._BUCKETS.clear()
    yield build_harness(tmp_path, monkeypatch, with_api=True)
    rl._BUCKETS.clear()


def _capacity_available() -> bool:
    try:
        from redsim.services import ml_capacity  # noqa: F401
    except ImportError:
        return False
    return True

FIXTURE = Path(__file__).parent / "fixtures" / "run_record.json"
MODEL_2 = "model-image-2"
MODEL_TABULAR = "model-tabular-1"
BATCH_ROUTE = "/v1/campaigns/batch"
FORBIDDEN_AT_BATCH_LEVEL = {"mri", "grade", "mean", "rank", "average", "aggregate"}


def _as(harness: Harness, role: str | None, *, project: str = PROJECT, sub: str | None = None) -> None:
    """Switch the app's caller: ``role`` on ``project`` (``None`` means a stranger on another project)."""
    assert harness.client is not None
    if role is None:
        user = CurrentUser(sub="dev:stranger@test", email="stranger@test", project_memberships={"project-9": "admin"})
    else:
        user = CurrentUser(sub=sub or f"dev:{role}@test", email=f"{role}@test", project_memberships={project: role})
    harness.client.app.dependency_overrides[get_current_user] = lambda: user  # type: ignore[attr-defined]


def _post_batch(harness: Harness, body: dict[str, Any], **kwargs: Any) -> Any:
    assert harness.client is not None
    return harness.client.post(BATCH_ROUTE, json=body, **kwargs)


def _body(*target_ids: str, **campaign: Any) -> dict[str, Any]:
    return {"project_id": PROJECT, "target_ids": list(target_ids),
            "campaign": {"attack_ids": ["fgsm"], **campaign}}


def _set_run_status(harness: Harness, run_id: str, status: str) -> None:
    with harness.Session.begin() as session:
        run = session.get(Run, run_id)
        assert run is not None
        run.status = status
        if status in {"succeeded", "failed", "cancelled"}:
            run.completed_at = datetime.now(UTC)
        for job in session.query(Job).filter(Job.run_id == run_id):
            job.status = status if status != "queued" else "queued"


def _assert_no_aggregate(payload: Any, path: str = "") -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            assert str(key).lower() not in FORBIDDEN_AT_BATCH_LEVEL, f"aggregate key {key!r} at {path}"
            _assert_no_aggregate(value, f"{path}/{key}")
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            _assert_no_aggregate(item, f"{path}[{index}]")


# --------------------------------------------------------------------------- roll-up vocabulary


@pytest.mark.parametrize(
    ("statuses", "n_refused", "expected"),
    [
        ([], 0, "queued"),
        ([], 2, "failed"),
        (["queued", "queued"], 0, "queued"),
        (["queued", "succeeded"], 0, "running"),
        (["running", "queued"], 0, "running"),
        (["succeeded", "succeeded"], 0, "succeeded"),
        (["succeeded", "succeeded"], 1, "partial"),
        (["succeeded", "failed"], 0, "partial"),
        (["failed", "failed"], 0, "failed"),
        (["cancelled", "cancelled"], 0, "cancelled"),
        (["cancelled", "succeeded"], 0, "partial"),
    ],
)
def test_rollup_status_vocabulary(statuses: list[str], n_refused: int, expected: str) -> None:
    assert rollup_status(statuses, n_refused=n_refused) == expected


def test_batch_member_cap_reads_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BATCH_MAX_MEMBERS_ENV, raising=False)
    assert batch_max_members() == 20
    monkeypatch.setenv(BATCH_MAX_MEMBERS_ENV, "3")
    assert batch_max_members() == 3
    monkeypatch.setenv(BATCH_MAX_MEMBERS_ENV, "nonsense")
    assert batch_max_members() == 20


# --------------------------------------------------------------------------- batch admission and roll-up


def test_batch_of_two_models_admits_each_through_the_single_boundary_and_rolls_up(api: Harness) -> None:
    seed_model(api)
    seed_model(api, MODEL_2)

    response = _post_batch(api, _body(MODEL, MODEL_2, n_samples=50))

    assert response.status_code == 202, response.text
    body = response.json()
    batch_id = body["batch_id"]
    assert batch_id.startswith("batch-") and body["kind"] == "campaign" and body["modality"] == "image"
    assert body["status"] == "queued" and body["status_url"] == f"{BATCH_ROUTE}/{batch_id}"
    assert [m["target_id"] for m in body["members"]] == [MODEL, MODEL_2]
    assert body["refused"] == [] and body["n_members"] == 2 and body["n_refused"] == 0
    assert len(body["run_ids"]) == 2 and body["run_ids"] == [m["run_id"] for m in body["members"]]
    assert all(m["deferred"] is False for m in body["members"])
    _assert_no_aggregate(body)

    # Every member is a real single-run admission carrying the batch id.
    assert api.counts() == {"runs": 2, "jobs": 2, "campaigns": 2}
    assert api.delay_calls == [m["job_ids"][0] for m in body["members"]]
    for member in body["members"]:
        row = api.campaign_row(member["run_id"])
        assert row is not None and row["batch_id"] == batch_id and row["kind"] == "attack"
        assert row["config"]["n_samples"] == 50 and row["config"]["target_id"] == member["target_id"]
        with api.Session() as session:
            run = session.get(Run, member["run_id"])
            job = session.get(Job, member["job_ids"][0])
        assert run is not None and run.stage_table["batch_id"] == batch_id and run.status == "queued"
        assert job is not None and job.detail["batch_id"] == batch_id and "deferred" not in job.detail
        assert job.detail["campaign_config"]["target_id"] == member["target_id"]
    with api.Session() as session:
        batch = session.get(MlBatch, batch_id)
    assert batch is not None and batch.project_id == PROJECT and batch.kind == "campaign"
    assert batch.status == "queued" and batch.created_by == ACTOR
    assert batch.config["target_ids"] == [MODEL, MODEL_2] and batch.config["modality"] == "image"
    assert batch.config["campaign"]["attack_ids"] == ["fgsm"] and batch.config["refused"] == []

    # Audit order: batch.create on the project chain, then attack.run per member before its Run existed.
    actions = [(e.action, e.success) for e in api.writer.events]
    assert actions == [("batch.create", True), ("attack.run", True), ("attack.run", True)]
    batch_row = api.writer.events[0]
    assert batch_row.run_id is None and batch_row.project_id == PROJECT
    assert batch_row.detail["batch_id"] == batch_id and batch_row.detail["target_ids"] == [MODEL, MODEL_2]
    assert batch_row.detail["n_members"] == 2 and batch_row.detail["modality"] == "image"
    assert len(batch_row.detail["config_hash"]) == 64 and batch_row.detail["config_hash"] == body["config_hash"]
    assert "campaign" not in batch_row.detail and "body" not in batch_row.detail
    assert api.writer.run_existed_at_append == [None, False, False]
    assert [e.run_id for e in api.writer.events[1:]] == body["run_ids"]

    # The roll-up view: queued, then running, then partial / succeeded, never an aggregate score.
    assert api.client is not None
    view = api.client.get(f"{BATCH_ROUTE}/{batch_id}").json()
    assert view["batch_id"] == batch_id and view["status"] == "queued" and view["state"] == "active"
    assert view["counts"] == {"queued": 2, "running": 0, "succeeded": 0, "failed": 0, "cancelled": 0, "refused": 0}
    assert [m["run_id"] for m in view["members"]] == body["run_ids"]
    assert all(m["score_status"] == "pending" and m["scorecard_url"] is None for m in view["members"])
    assert all(m["status_url"] == f"/v1/runs/{m['run_id']}" for m in view["members"])
    assert view["requested"]["target_ids"] == [MODEL, MODEL_2] and view["cancel_requested_at"] is None
    _assert_no_aggregate(view)

    first, second = body["run_ids"]
    _set_run_status(api, first, "succeeded")
    view = api.client.get(f"{BATCH_ROUTE}/{batch_id}").json()
    assert view["status"] == "running" and view["state"] == "active"
    assert view["counts"]["succeeded"] == 1 and view["counts"]["queued"] == 1

    _set_run_status(api, second, "failed")
    view = api.client.get(f"{BATCH_ROUTE}/{batch_id}").json()
    assert view["status"] == "partial" and view["state"] == "terminal"
    member_status = {m["run_id"]: m["status"] for m in view["members"]}
    assert member_status == {first: "succeeded", second: "failed"}
    assert {m["score_status"] for m in view["members"]} == {"unavailable"}, "no score row was persisted"

    _set_run_status(api, second, "succeeded")
    assert api.client.get(f"{BATCH_ROUTE}/{batch_id}").json()["status"] == "succeeded"

    # The list is membership-scoped and summarises without members' scores.
    listed = api.client.get(BATCH_ROUTE).json()
    assert listed["count"] == 1 and listed["batches"][0]["batch_id"] == batch_id
    assert listed["batches"][0]["status"] == "succeeded" and listed["batches"][0]["run_ids"] == body["run_ids"]
    assert api.client.get(f"{BATCH_ROUTE}?project={PROJECT}").json()["count"] == 1
    _assert_no_aggregate(listed)


def test_flat_body_form_is_accepted_and_target_fields_are_refused(api: Harness) -> None:
    seed_model(api)
    flat = _post_batch(api, {"project_id": PROJECT, "target_ids": [MODEL], "attack_ids": ["fgsm"]})
    assert flat.status_code == 202, flat.text

    refused = _post_batch(api, _body(MODEL, target_id=MODEL))
    assert refused.status_code == 422, refused.text
    detail = refused.json()["detail"]
    assert detail["code"] == "params_out_of_range" and detail["field"] == "campaign.target_id"
    rerun = _post_batch(api, {"project_id": PROJECT, "target_ids": [MODEL],
                              "campaign": {"parent_run_id": "run-x"}})
    assert rerun.json()["detail"]["field"] == "campaign.parent_run_id"
    # Both refusals were audited on the project chain, nothing else was written.
    failed = [e for e in api.events("batch.create") if not e.success]
    assert len(failed) == 2 and all(e.detail["code"] == "params_out_of_range" for e in failed)
    assert api.counts() == {"runs": 1, "jobs": 1, "campaigns": 1}


def test_cross_modality_batch_is_refused_with_groups(api: Harness) -> None:
    seed_model(api)
    seed_model(api, MODEL_2)
    seed_model(api, MODEL_TABULAR, modality="tabular")

    response = _post_batch(api, _body(MODEL, MODEL_TABULAR, MODEL_2))

    assert response.status_code == HTTP_STATUS["batch_modality_mismatch"] == 422, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "batch_modality_mismatch"
    assert detail["groups"] == {"image": [MODEL, MODEL_2], "tabular": [MODEL_TABULAR]}
    assert detail["field"] == "target_ids"
    # Nothing was admitted: no Run, Job, campaign or batch row, no enqueue; one refusal row on the chain.
    assert api.counts() == {"runs": 0, "jobs": 0, "campaigns": 0} and api.delay_calls == []
    with api.Session() as session:
        assert session.query(MlBatch).count() == 0
    events = api.writer.events
    assert [(e.action, e.success) for e in events] == [("batch.create", False)]
    assert events[0].detail["code"] == "batch_modality_mismatch" and events[0].detail["groups"] == detail["groups"]
    assert events[0].detail["target_ids"] == [MODEL, MODEL_TABULAR, MODEL_2] and events[0].run_id is None


def test_batch_too_large_and_unknown_target(api: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    seed_model(api)
    seed_model(api, MODEL_2)
    monkeypatch.setenv(BATCH_MAX_MEMBERS_ENV, "1")
    too_large = _post_batch(api, _body(MODEL, MODEL_2))
    assert too_large.status_code == 422 and too_large.json()["detail"]["code"] == "batch_too_large"
    assert too_large.json()["detail"]["cap"] == 1 and too_large.json()["detail"]["requested"] == 2
    monkeypatch.delenv(BATCH_MAX_MEMBERS_ENV)

    missing = _post_batch(api, _body(MODEL, "no-such-model"))
    assert missing.status_code == 404, missing.text
    assert missing.json()["detail"]["code"] == "not_found"
    assert missing.json()["detail"]["target_ids"] == ["no-such-model"]

    empty = _post_batch(api, {"project_id": PROJECT, "target_ids": [], "campaign": {"attack_ids": ["fgsm"]}})
    assert empty.status_code == 422 and empty.json()["detail"]["field"] == "target_ids"
    repeated = _post_batch(api, _body(MODEL, MODEL))
    assert repeated.status_code == 422 and repeated.json()["detail"]["field"] == "target_ids"

    assert api.counts() == {"runs": 0, "jobs": 0, "campaigns": 0}
    assert all(e.action == "batch.create" and not e.success for e in api.writer.events)
    assert len(api.writer.events) == 4


def test_member_refusal_is_collected_and_the_other_member_runs(api: Harness) -> None:
    seed_model(api)
    seed_model(api, MODEL_2, gradients=False)   # fgsm needs gradients: this member is refused

    response = _post_batch(api, _body(MODEL, MODEL_2))

    assert response.status_code == 202, response.text
    body = response.json()
    assert [m["target_id"] for m in body["members"]] == [MODEL]
    assert len(body["refused"]) == 1 and body["n_refused"] == 1
    refused = body["refused"][0]
    assert refused["target_id"] == MODEL_2 and refused["code"] == "attack_requires_gradients"
    assert refused["attempted"] is True and refused["message"]
    assert body["status"] == "queued"
    assert api.counts() == {"runs": 1, "jobs": 1, "campaigns": 1}
    # The member's own refusal row names the code; the batch row keeps the refusal.
    actions = [(e.action, e.success) for e in api.writer.events]
    assert actions == [("batch.create", True), ("attack.run", True), ("attack.run", False)]
    assert api.writer.events[2].detail["code"] == "attack_requires_gradients"
    assert api.writer.events[2].detail["target_id"] == MODEL_2
    with api.Session() as session:
        batch = session.get(MlBatch, body["batch_id"])
    assert batch is not None and batch.config["refused"][0]["code"] == "attack_requires_gradients"

    assert api.client is not None
    view = api.client.get(f"{BATCH_ROUTE}/{body['batch_id']}").json()
    assert view["refused"] == body["refused"] and view["counts"]["refused"] == 1
    _set_run_status(api, body["run_ids"][0], "succeeded")
    view = api.client.get(f"{BATCH_ROUTE}/{body['batch_id']}").json()
    assert view["status"] == "partial", "a succeeded member beside a refused one is never 'succeeded'"


def test_every_member_refused_is_422_batch_member_refused(api: Harness) -> None:
    seed_model(api, gradients=False)
    seed_model(api, MODEL_2, gradients=False)

    response = _post_batch(api, _body(MODEL, MODEL_2))

    assert response.status_code == HTTP_STATUS["batch_member_refused"] == 422, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "batch_member_refused"
    assert [m["target_id"] for m in detail["members"]] == [MODEL, MODEL_2]
    assert {m["code"] for m in detail["members"]} == {"attack_requires_gradients"}
    batch_id = detail["batch_id"]
    assert api.counts() == {"runs": 0, "jobs": 0, "campaigns": 0} and api.delay_calls == []
    with api.Session() as session:
        batch = session.get(MlBatch, batch_id)
    assert batch is not None and batch.status == "failed", "the batch row survives with the refusals"
    assert [m["code"] for m in batch.config["refused"]] == ["attack_requires_gradients"] * 2
    actions = [(e.action, e.success) for e in api.writer.events]
    assert actions == [("batch.create", True), ("attack.run", False), ("attack.run", False), ("batch.create", False)]
    assert api.writer.events[-1].detail["code"] == "batch_member_refused"
    assert api.writer.events[-1].detail["refused_codes"] == ["attack_requires_gradients"]
    assert api.client is not None
    view = api.client.get(f"{BATCH_ROUTE}/{batch_id}").json()
    assert view["status"] == "failed" and view["members"] == [] and view["counts"]["refused"] == 2


def test_queue_unavailable_member_stops_the_batch_and_is_collected(api: Harness,
                                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    seed_model(api)
    seed_model(api, MODEL_2)

    def broken_delay(_job_id: str) -> Any:
        raise ConnectionError("broker unreachable")

    monkeypatch.setattr("redsim.workers.tasks.ml_campaign.ml_campaign_run.delay", broken_delay)
    response = _post_batch(api, _body(MODEL, MODEL_2))
    assert response.status_code == 422, response.text
    members = response.json()["detail"]["members"]
    assert [m["code"] for m in members] == ["queue_unavailable", "queue_unavailable"]
    assert [m["attempted"] for m in members] == [True, False], "the second member was never attempted"
    assert api.counts() == {"runs": 0, "jobs": 0, "campaigns": 0}, "the first member's rows were rolled back"


def test_max_parallel_defers_members_beyond_the_bound(api: Harness) -> None:
    seed_model(api)
    seed_model(api, MODEL_2)
    response = _post_batch(api, {**_body(MODEL, MODEL_2), "max_parallel": 1})
    assert response.status_code == 202, response.text
    body = response.json()
    assert [m["deferred"] for m in body["members"]] == [False, True]
    assert api.delay_calls == [body["members"][0]["job_ids"][0]], "only the first member was enqueued"
    with api.Session() as session:
        deferred_job = session.get(Job, body["members"][1]["job_ids"][0])
    assert deferred_job is not None and deferred_job.detail["deferred"] is True
    assert deferred_job.celery_task_id is None and deferred_job.status == "queued"
    assert api.client is not None
    view = api.client.get(f"{BATCH_ROUTE}/{body['batch_id']}").json()
    assert [m["deferred"] for m in view["members"]] == [False, True]


@pytest.mark.skipif(not _capacity_available(), reason="redsim.services.ml_capacity is not on this tree")
def test_capacity_cap_defers_members_through_the_capacity_service(api: Harness,
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(CAPACITY_ENV, "1")
    seed_model(api)
    seed_model(api, MODEL_2)
    response = _post_batch(api, _body(MODEL, MODEL_2))
    assert response.status_code == 202, response.text
    body = response.json()
    assert [m["deferred"] for m in body["members"]] == [False, True]
    assert api.delay_calls == [body["members"][0]["job_ids"][0]]
    with api.Session() as session:
        job = session.get(Job, body["members"][1]["job_ids"][0])
        run = session.get(Run, body["members"][1]["run_id"])
    assert job is not None and job.detail["deferred"] is True and job.detail["batch_id"] == body["batch_id"]
    assert "capacity" in job.detail, "the capacity service stamped its decision"
    assert run is not None and run.stage_table["deferred"] is True and run.stage_table["batch_id"] == body["batch_id"]
    assert api.client is not None
    view = api.client.get(f"{BATCH_ROUTE}/{body['batch_id']}").json()
    assert [m["deferred"] for m in view["members"]] == [False, True] and view["status"] == "queued"


@pytest.mark.skipif(not _capacity_available(), reason="redsim.services.ml_capacity is not on this tree")
def test_spent_daily_budget_is_a_collected_member_refusal_with_its_own_row(api: Harness,
                                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(BUDGET_ENVS[0], "1")
    seed_model(api)
    seed_model(api, MODEL_2)
    response = _post_batch(api, _body(MODEL, MODEL_2))
    assert response.status_code == 202, response.text
    body = response.json()
    assert [m["target_id"] for m in body["members"]] == [MODEL]
    (refused,) = body["refused"]
    assert refused["target_id"] == MODEL_2 and refused["code"] == "daily_budget_exceeded"
    assert HTTP_STATUS["daily_budget_exceeded"] == 429
    assert api.counts() == {"runs": 1, "jobs": 1, "campaigns": 1}
    budget_rows = [e for e in api.writer.events if not e.success]
    assert len(budget_rows) == 1 and budget_rows[0].detail["code"] == "daily_budget_exceeded"
    assert budget_rows[0].detail["batch_id"] == body["batch_id"] and budget_rows[0].detail["target_id"] == MODEL_2
    assert budget_rows[0].project_id == PROJECT


# --------------------------------------------------------------------------- cancel


def test_cancel_batch_audits_first_then_cancels_every_live_member(api: Harness) -> None:
    seed_model(api)
    seed_model(api, MODEL_2)
    seed_model(api, "model-image-3")
    body = _post_batch(api, _body(MODEL, MODEL_2, "model-image-3")).json()
    batch_id = body["batch_id"]
    done, live_1, live_2 = body["run_ids"]
    _set_run_status(api, done, "succeeded")
    _set_run_status(api, live_2, "running")
    api.writer.events.clear()
    assert api.client is not None

    _as(api, "scanner")
    assert api.client.post(f"{BATCH_ROUTE}/{batch_id}/cancel").status_code == 403, "run.cancel is remediator"
    assert api.writer.events == []

    _as(api, "remediator")
    response = api.client.post(f"{BATCH_ROUTE}/{batch_id}/cancel")
    assert response.status_code == 200, response.text
    outcome = response.json()
    assert outcome["batch_id"] == batch_id and outcome["status"] == "partial"
    assert outcome["cancelled"] == [live_1, live_2] and outcome["jobs_cancelled"] == 2
    assert outcome["already_terminal"] == [{"run_id": done, "status": "succeeded"}]
    actions = [(e.action, e.success, e.run_id) for e in api.writer.events]
    assert actions == [("batch.cancel", True, None), ("run.cancel", True, live_1), ("run.cancel", True, live_2)]
    assert api.writer.events[0].detail["batch_id"] == batch_id
    assert api.writer.events[0].detail["cancelling"] == [live_1, live_2]
    assert api.writer.events[0].detail["already_terminal"] == [done]
    with api.Session() as session:
        statuses = {run_id: session.get(Run, run_id).status for run_id in body["run_ids"]}  # type: ignore[union-attr]
        jobs = {job.run_id: job.status for job in session.query(Job)}
        batch = session.get(MlBatch, batch_id)
    assert statuses == {done: "succeeded", live_1: "cancelled", live_2: "cancelled"}
    assert jobs[live_1] == "cancelled" and jobs[live_2] == "cancelled"
    assert batch is not None and batch.cancelled_at is not None and batch.status == "partial"

    view = api.client.get(f"{BATCH_ROUTE}/{batch_id}").json()
    assert view["status"] == "partial" and view["state"] == "terminal" and view["cancel_requested_at"]
    assert view["counts"]["cancelled"] == 2 and view["counts"]["succeeded"] == 1

    # Every member terminal now: a second cancel is 409 run_terminal with a refusal row.
    again = api.client.post(f"{BATCH_ROUTE}/{batch_id}/cancel")
    assert again.status_code == 409, again.text
    assert again.json()["detail"]["code"] == "run_terminal" and again.json()["detail"]["batch_id"] == batch_id
    last = api.writer.events[-1]
    assert last.action == "batch.cancel" and not last.success and last.detail["code"] == "run_terminal"

    assert api.client.post(f"{BATCH_ROUTE}/no-such-batch/cancel").status_code == 404


def test_cancel_of_an_all_queued_batch_reads_cancelled(api: Harness) -> None:
    seed_model(api)
    body = _post_batch(api, _body(MODEL)).json()
    assert api.client is not None
    _as(api, "admin")
    assert api.client.post(f"{BATCH_ROUTE}/{body['batch_id']}/cancel").status_code == 200
    view = api.client.get(f"{BATCH_ROUTE}/{body['batch_id']}").json()
    assert view["status"] == "cancelled" and view["state"] == "terminal"


# --------------------------------------------------------------------------- RBAC and membership


def test_rbac_negatives_on_every_batch_route(api: Harness) -> None:
    seed_model(api)
    body = _post_batch(api, _body(MODEL)).json()
    batch_id = body["batch_id"]
    assert api.client is not None
    before = api.counts()
    n_events = len(api.writer.events)

    def plain_403(response: Any) -> None:
        assert response.status_code == 403, response.text
        assert isinstance(response.json()["detail"], str), "the gate speaks with the plain detail, never an envelope"

    _as(api, "viewer")
    plain_403(_post_batch(api, _body(MODEL)))
    plain_403(api.client.post(f"{BATCH_ROUTE}/{batch_id}/cancel"))
    # Reads are open to any member.
    assert api.client.get(f"{BATCH_ROUTE}/{batch_id}").status_code == 200
    assert api.client.get(BATCH_ROUTE).json()["count"] == 1

    _as(api, "scanner")
    assert _post_batch(api, _body(MODEL)).status_code == 202, "batch.run is the scanner tier"
    plain_403(api.client.post(f"{BATCH_ROUTE}/{batch_id}/cancel"))

    _as(api, None)
    plain_403(_post_batch(api, _body(MODEL)))
    plain_403(api.client.get(f"{BATCH_ROUTE}/{batch_id}"))
    plain_403(api.client.get(f"{BATCH_ROUTE}/{batch_id}/compare"))
    plain_403(api.client.post(f"{BATCH_ROUTE}/{batch_id}/cancel"))
    plain_403(api.client.get(f"{BATCH_ROUTE}?project={PROJECT}"))
    assert api.client.get(BATCH_ROUTE).json() == {"batches": [], "count": 0}, "the list is membership-scoped"
    assert api.client.get(f"{BATCH_ROUTE}/no-such-batch").status_code == 404

    # The refused calls wrote nothing (the scanner's admitted one-member batch is the only addition).
    assert api.counts() == {k: v + 1 for k, v in before.items()}
    events = api.writer.events[n_events:]
    assert [e.action for e in events] == ["batch.create", "attack.run"]

    _as(api, "admin")
    missing_project = api.client.post(BATCH_ROUTE, json={"target_ids": [MODEL], "campaign": {}})
    assert missing_project.status_code == 422
    assert missing_project.json()["detail"]["field"] == "project_id"


# --------------------------------------------------------------------------- compare


class _MemoryBlobStore:
    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}

    def get(self, key: str) -> bytes:
        return self.blobs[key]


def _seed_record_member(api: Harness, store: _MemoryBlobStore, *, batch_id: str, run_id: str,
                        record: dict[str, Any], target_id: str, with_artifact: bool = True) -> None:
    parsed = CampaignRecord.model_validate(record)
    raw = parsed.model_dump_json().encode()
    location = f"memory://{PROJECT}/{run_id}/run_record.json"
    store.blobs[location] = raw
    with api.Session.begin() as session:
        session.add(Run(id=run_id, project_id=PROJECT, target_id=target_id, mode="api", scanner="ml.campaign",
                        status="succeeded", created_by=ACTOR, stage_table={"batch_id": batch_id}))
        session.flush()
        if with_artifact:
            session.add(Artifact(id=f"artifact-{run_id}", run_id=run_id, project_id=PROJECT, kind="ml.run_record",
                                 sha256=hashlib.sha256(raw).hexdigest(), location=location,
                                 content_type="application/json", size_bytes=len(raw)))
        session.execute(api.campaigns.insert().values(
            run_id=run_id, project_id=PROJECT, target_id=target_id, kind="attack", modality="image",
            config=parsed.config.model_dump(mode="json"), settings_hash=parsed.settings_hash,
            provenance=parsed.provenance.model_dump(mode="json") if parsed.provenance else None,
            score=parsed.score.model_dump(mode="json") if parsed.score else None,
            limitations=list(parsed.limitations), batch_id=batch_id,
        ))


def _seed_batch_row(api: Harness, batch_id: str, target_ids: list[str]) -> None:
    with api.Session.begin() as session:
        session.add(MlBatch(id=batch_id, project_id=PROJECT, kind="campaign", status="succeeded", created_by=ACTOR,
                            config={"target_ids": target_ids, "modality": "image", "refused": [],
                                    "config_hash": "0" * 64}))


def _variant(base: dict[str, Any], run_id: str, *, model_sha: str | None = None, target_id: str | None = None,
             seed: int | None = None, partial: bool = False) -> dict[str, Any]:
    rec = copy.deepcopy(base)
    rec["run_id"] = run_id
    if model_sha is not None:
        rec["provenance"]["model_sha256"] = model_sha
        rec["settings_hash"] = model_sha[:64]
        rec["provenance"]["settings_hash"] = model_sha[:64]
        rec["score"]["settings_hash"] = model_sha[:64]
    if target_id is not None:
        rec["config"]["target_id"] = target_id
    if seed is not None:
        rec["config"]["seed"] = seed
        rec["provenance"]["sample_indices_sha256"] = f"{seed:02x}" * 32
    if partial:
        rec["score"].update({"mri": None, "grade": None, "completeness": "partial",
                             "missing": ["S_expl unavailable (explainer failed)"]})
        rec["score"]["subscores"]["S_expl"] = None
        rec.update({"completeness": "partial", "missing": ["S_expl unavailable (explainer failed)"]})
    return rec


def test_comparability_groups_pure_helper() -> None:
    base = json.loads(FIXTURE.read_text())
    same_settings_other_model = _variant(base, "run-b", model_sha="e1" * 32, target_id="tgt-other")
    other_seed = _variant(base, "run-c", seed=7)
    partial = _variant(base, "run-d", partial=True)

    run_a = _variant(base, "run-a")
    table = cmp.comparability_groups([("run-a", run_a, None), ("run-b", same_settings_other_model, None),
                                      ("run-c", other_seed, None), ("run-d", partial, None),
                                      ("run-e", None, {"unavailable_reason": "run-e: no record"})])

    assert table["mode"] == "batch_side_by_side" and table["compatible"] is False and table["n_groups"] == 2
    assert [g["run_ids"] for g in table["groups"]] == [["run-a", "run-b"], ["run-c"]]
    first = table["groups"][0]
    assert [card["run_id"] for card in first["scorecards"]] == ["run-a", "run-b"]
    assert first["changed_variables"] == ["model"] and "seed" in first["unchanged_variables"]
    assert "model_sha256" not in first["unchanged_variables"]
    assert first["key"]["seed"] == base["config"]["seed"] and first["key"]["sample_indices_sha256"]
    assert all(card["mri"] == 42 and card["measurements"] and card["curve"] for card in first["scorecards"])
    assert table["incompatible_pairs"] == [{"runs": ["run-a", "run-c"], "reasons": ["seed", "sample_indices_sha256"]}]
    assert [u["run_id"] for u in table["unavailable"]] == ["run-d", "run-e"]
    assert table["unavailable"][0]["reasons"] == ["run-d: MRI not computed (S_expl unavailable (explainer failed))"]
    assert table["unavailable"][1]["reasons"] == ["run-e: no record"]
    for group in table["groups"]:
        assert "delta" not in group
    _assert_no_aggregate({k: v for k, v in table.items() if k != "groups"})
    for group in table["groups"]:
        _assert_no_aggregate({k: v for k, v in group.items() if k != "scorecards"})
    with pytest.raises(ValueError):
        cmp.comparability_groups([("run-a", run_a, None), ("run-a", run_a, None)])


def test_batch_compare_route_groups_scorecards_and_lists_groups_on_409(api: Harness,
                                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    base = json.loads(FIXTURE.read_text())
    store = _MemoryBlobStore()
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: store)
    batch_id = "batch-compare-1"
    _seed_batch_row(api, batch_id, ["tgt-a", "tgt-b"])
    _seed_record_member(api, store, batch_id=batch_id, run_id="run-cmp-a", record=_variant(base, "run-cmp-a"),
                        target_id="tgt-a")
    _seed_record_member(api, store, batch_id=batch_id, run_id="run-cmp-b",
                        record=_variant(base, "run-cmp-b", model_sha="e1" * 32, target_id="tgt-b"), target_id="tgt-b")
    assert api.client is not None

    response = api.client.get(f"{BATCH_ROUTE}/{batch_id}/compare")
    assert response.status_code == 200, response.text
    table = response.json()
    assert table["batch_id"] == batch_id and table["kind"] == "campaign" and table["modality"] == "image"
    assert table["n_groups"] == 1 and table["compatible"] is True and table["unavailable"] == []
    (group,) = table["groups"]
    assert group["run_ids"] == ["run-cmp-a", "run-cmp-b"]
    assert [card["model_sha256"] for card in group["scorecards"]] == ["d0" * 32, "e1" * 32]
    for card in group["scorecards"]:
        assert card["mri"] == 42 and card["subscores"] and card["inputs"] and card["per_attack"]
        assert len(card["measurements"]) == 10 and len(card["curve"]) == 2 and card["limitations"]
    assert group["changed_variables"] == ["model"]
    assert "delta" not in group and "delta" not in table
    _assert_no_aggregate({k: v for k, v in table.items() if k != "groups"})
    assert table["caveats"] == sorted(set(table["caveats"]))

    # A member without a complete score is listed, not compared; a running member has no record yet.
    _seed_record_member(api, store, batch_id=batch_id, run_id="run-cmp-p",
                        record=_variant(base, "run-cmp-p", partial=True), target_id="tgt-a")
    _seed_record_member(api, store, batch_id=batch_id, run_id="run-cmp-n",
                        record=_variant(base, "run-cmp-n"), target_id="tgt-a", with_artifact=False)
    _set_run_status(api, "run-cmp-n", "running")
    table = api.client.get(f"{BATCH_ROUTE}/{batch_id}/compare").json()
    assert table["n_groups"] == 1 and [u["run_id"] for u in table["unavailable"]] == ["run-cmp-p", "run-cmp-n"]
    assert "MRI not computed" in table["unavailable"][0]["reasons"][0]
    assert "running" in table["unavailable"][1]["reasons"][0]

    # A member under other settings splits the batch into groups: 409 naming them, no scorecards leave.
    _seed_record_member(api, store, batch_id=batch_id, run_id="run-cmp-s",
                        record=_variant(base, "run-cmp-s", seed=7), target_id="tgt-a")
    response = api.client.get(f"{BATCH_ROUTE}/{batch_id}/compare")
    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "incompatible_campaigns" and detail["batch_id"] == batch_id
    assert [g["run_ids"] for g in detail["groups"]] == [["run-cmp-a", "run-cmp-b"], ["run-cmp-s"]]
    assert detail["reasons"] == ["sample_indices_sha256", "seed"]
    assert detail["pairs"] == [{"runs": ["run-cmp-a", "run-cmp-s"], "reasons": ["seed", "sample_indices_sha256"]}]
    assert "scorecards" not in json.dumps(detail)

    # Membership before any record is read.
    _as(api, None)
    assert api.client.get(f"{BATCH_ROUTE}/{batch_id}/compare").status_code == 403
    _as(api, "admin")
    assert api.client.get(f"{BATCH_ROUTE}/no-such/compare").status_code == 404


def test_batch_compare_with_no_scored_member_is_409_score_unavailable(api: Harness,
                                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    base = json.loads(FIXTURE.read_text())
    store = _MemoryBlobStore()
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: store)
    _seed_batch_row(api, "batch-compare-2", ["tgt-a"])
    _seed_record_member(api, store, batch_id="batch-compare-2", run_id="run-only-partial",
                        record=_variant(base, "run-only-partial", partial=True), target_id="tgt-a")
    assert api.client is not None
    response = api.client.get(f"{BATCH_ROUTE}/batch-compare-2/compare")
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "score_unavailable"
    assert response.json()["detail"]["reasons"] == [
        "run-only-partial: MRI not computed (S_expl unavailable (explainer failed))"]


# --------------------------------------------------------------------------- bulk verify (BULK-15 / BULK-16)


def test_bulk_verify_admits_one_defended_run_per_defense_over_every_selected_finding(
    api: Harness, monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = seed_verify_baseline(api, monkeypatch)
    fgsm, pgd = ids["fgsm"], ids["pgd"]
    assert api.client is not None

    _as(api, "scanner")
    refused = api.client.post(f"/v1/findings/{fgsm}/verify/bulk", json={})
    assert refused.status_code == 403 and isinstance(refused.json()["detail"], str), "verify.replay is remediator"
    assert api.writer.events == []

    _as(api, "remediator")
    response = api.client.post(
        f"/v1/findings/{fgsm}/verify/bulk",
        json={"defenses": [{"defense": "feature_squeezing"}, {"defense": "jpeg_compression", "params": {"quality": 60}},
                           {"defense": "feature_squeezing"}]},   # the duplicate collapses
    )
    assert response.status_code == 202, response.text
    body = response.json()
    batch_id = body["batch_id"]
    assert body["kind"] == "verify" and body["baseline_run_id"] == ids["run_id"] and body["modality"] == "image"
    assert body["finding_ids"] == [fgsm, pgd] and body["primary_finding_id"] == fgsm and body["skipped"] == []
    assert len(body["members"]) == 2 and body["refused"] == []
    assert [m["defense"]["id"] for m in body["members"]] == ["feature_squeezing", "jpeg_compression"]
    assert body["members"][1]["defense"]["params"] == {"quality": 60}
    # One verify in flight per finding: the second defense takes the next selected finding as its primary.
    assert [m["primary_finding_id"] for m in body["members"]] == [fgsm, pgd]

    with api.Session() as session:
        jobs = {m["run_id"]: session.get(Job, m["job_ids"][0]) for m in body["members"]}
        runs = {m["run_id"]: session.get(Run, m["run_id"]) for m in body["members"]}
        statuses = {fid: session.get(Finding, fid).status for fid in (fgsm, pgd)}  # type: ignore[union-attr]
        batch = session.get(MlBatch, batch_id)
    for member in body["members"]:
        job, run = jobs[member["run_id"]], runs[member["run_id"]]
        assert job is not None and job.type == "verify.replay"
        assert job.detail["finding_ids"] == [fgsm, pgd] and job.detail["batch_id"] == batch_id
        assert job.detail["finding_id"] == member["primary_finding_id"]
        assert job.detail["baseline_run_id"] == ids["run_id"]
        assert run is not None and run.scanner == "ml.verify" and run.stage_table["batch_id"] == batch_id
        assert run.stage_table["finding_ids"] == [fgsm, pgd] and run.stage_table["baseline_run_id"] == ids["run_id"]
        row = api.campaign_row(member["run_id"])
        assert row is not None and row["kind"] == "verify" and row["batch_id"] == batch_id
        assert row["baseline_run_id"] == ids["run_id"]
    assert statuses == {fgsm: "fixing", pgd: "fixing"}
    assert batch is not None and batch.kind == "verify" and batch.config["finding_ids"] == [fgsm, pgd]
    assert [d["defense"] for d in batch.config["defenses"]] == ["feature_squeezing", "jpeg_compression"]
    assert api.delay_calls == [m["job_ids"][0] for m in body["members"]]

    # Audit: batch.create, then per member the single route's verify.replay row (before its Run existed)
    # followed by one verify.replay row per additional finding naming the shared run.
    events = api.writer.events
    assert events[0].action == "batch.create" and events[0].success and events[0].run_id is None
    assert events[0].detail["kind"] == "verify" and events[0].detail["finding_ids"] == [fgsm, pgd]
    assert events[0].detail["defense_ids"] == ["feature_squeezing", "jpeg_compression"]
    assert events[0].detail["baseline_run_id"] == ids["run_id"] and events[0].detail["n_members"] == 2
    verify_rows = [e for e in events[1:] if e.action == "verify.replay"]
    assert len(verify_rows) == 4 and all(e.success for e in verify_rows)
    run_a, run_b = body["run_ids"]
    assert [(e.run_id, e.detail["finding_id"]) for e in verify_rows] == [
        (run_a, fgsm), (run_a, pgd), (run_b, pgd), (run_b, fgsm)]
    assert verify_rows[1].detail["shared_run_id"] == run_a and verify_rows[1].detail["batch_id"] == batch_id
    assert verify_rows[1].detail["primary_finding_id"] == fgsm
    assert verify_rows[1].detail["defense"]["id"] == "feature_squeezing"
    assert api.writer.run_existed_at_append[:2] == [None, False], "the batch row and the first admission row precede the Run"
    assert set(events[1].detail) >= {"finding_id", "baseline_run_id", "defense"}
    assert "campaign_config" not in events[0].detail

    # The view shows the verify members with their findings and whether the worker has projected onto them.
    view = api.client.get(f"{BATCH_ROUTE}/{batch_id}").json()
    assert view["kind"] == "verify" and view["requested"]["finding_ids"] == [fgsm, pgd]
    assert view["requested"]["baseline_run_id"] == ids["run_id"]
    for member in view["members"]:
        assert member["kind"] == "verify" and member["baseline_run_id"] == ids["run_id"]
        assert member["finding_ids"] == [fgsm, pgd]
        assert [f["projected"] for f in member["findings"]] == [False, False]
        assert member["defense"]["id"] in {"feature_squeezing", "jpeg_compression"}
    _assert_no_aggregate(view)

    # Both findings now carry a verify in flight: a further bulk verify has nothing to select.
    nothing = api.client.post(f"/v1/findings/{fgsm}/verify/bulk", json={})
    assert nothing.status_code == 422, nothing.text
    detail = nothing.json()["detail"]
    assert detail["code"] == "params_out_of_range" and detail["field"] == "finding_ids"
    assert [(s["finding_id"], s["status"]) for s in detail["skipped"]] == [(fgsm, "fixing"), (pgd, "fixing")]
    assert api.writer.events[-1].action == "batch.create" and not api.writer.events[-1].success


def test_bulk_verify_skips_dismissed_findings_and_collects_defense_refusals(
    api: Harness, monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = seed_verify_baseline(api, monkeypatch)
    fgsm, pgd = ids["fgsm"], ids["pgd"]
    with api.Session.begin() as session:
        session.get(Finding, pgd).status = "false_positive"  # type: ignore[union-attr]
    assert api.client is not None
    _as(api, "remediator")

    # An unknown defense: the member is refused with the single route's code, nothing is admitted.
    response = api.client.post(f"/v1/findings/{fgsm}/verify/bulk", json={"defense": "nope"})
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "batch_member_refused"
    assert detail["members"][0]["code"] == "unknown_defense" and detail["members"][0]["defense"] == "nope"
    assert api.counts() == {"runs": 1, "jobs": 0, "campaigns": 1}, "only the seeded baseline exists"
    with api.Session() as session:
        assert session.get(Finding, fgsm).status == "open"  # type: ignore[union-attr]

    # The default defense on the one selectable finding; the dismissed one is skipped with its reason.
    response = api.client.post(f"/v1/findings/{fgsm}/verify/bulk", json={})
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["finding_ids"] == [fgsm]
    assert body["skipped"] == [{"finding_id": pgd, "status": "false_positive", "reason": "dismissed as a false positive"}]
    assert len(body["members"]) == 1 and body["members"][0]["defense"]["id"] == "feature_squeezing"
    with api.Session() as session:
        job = session.get(Job, body["members"][0]["job_ids"][0])
    assert job is not None and job.detail["finding_ids"] == [fgsm]
    verify_rows = [e for e in api.writer.events if e.action == "verify.replay" and e.success]
    assert len(verify_rows) == 1, "no additional finding, no additional row"

    # finding_ids outside the run's ML findings are refused before anything is written.
    n_events = len(api.writer.events)
    outside = api.client.post(f"/v1/findings/{fgsm}/verify/bulk", json={"finding_ids": ["finding-elsewhere"]})
    assert outside.status_code == 422 and outside.json()["detail"]["field"] == "finding_ids"
    assert outside.json()["detail"]["reasons"] == ["finding-elsewhere"]
    assert len(api.writer.events) == n_events + 1 and not api.writer.events[-1].success

    assert api.client.post("/v1/findings/no-such-finding/verify/bulk", json={}).status_code == 404
    _as(api, None)
    assert api.client.post(f"/v1/findings/{fgsm}/verify/bulk", json={}).status_code == 403


def test_seeded_model_sha_is_the_fixture_constant() -> None:
    """Guard for the harness contract this file leans on (``seed_model`` writes ``SHA256`` into the manifest)."""
    assert len(SHA256) == 64 and MODEL == "model-image-1"


# --------------------------------------------------------------------------- BULK-20/-21: the single routes


def _seed_live_job(api: Harness, target_id: str) -> tuple[str, str]:
    """A ``running`` campaign Job in the project: one concurrency slot in use (the state the cap exists for)."""
    run_id, job_id = "run-live-slot", "job-live-slot"
    with api.Session.begin() as session:
        session.add(Run(id=run_id, project_id=PROJECT, target_id=target_id, mode="api", status="running",
                        scanner="ml.campaign", created_by=ACTOR, stage_table={"stage": "attack", "jobs": {}}))
        session.flush()
        session.add(Job(id=job_id, run_id=run_id, project_id=PROJECT, type="attack.run", status="running",
                        created_by=ACTOR, detail={"campaign_config": {}}))
    return run_id, job_id


@pytest.mark.skipif(not _capacity_available(), reason="redsim.services.ml_capacity is not on this tree")
def test_single_attack_route_is_deferred_over_the_concurrency_cap(api: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    """BULK-21 (b): the single route never refuses on concurrency; the admission is written queued + deferred,
    not enqueued, and the 202 body carries ``deferred`` and the ``capacity_deferred`` marker (a marker code)."""
    from redsim.api.errors import CAPACITY_DEFERRED, MARKER_CODES
    from redsim.services.ml_capacity import CAPACITY_KEY, DEFERRED_KEY

    monkeypatch.setenv(CAPACITY_ENV, "1")
    seed_model(api)
    _seed_live_job(api, MODEL)
    assert api.client is not None
    _as(api, "scanner")
    response = api.client.post(f"/v1/models/{MODEL}/attacks", json={"attack_ids": ["fgsm"]})
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["deferred"] is True and body["capacity"]["code"] == CAPACITY_DEFERRED in MARKER_CODES
    assert body["capacity"]["active_runs"] == 1 and body["capacity"]["max_concurrent_runs"] == 1
    assert api.delay_calls == [], "a deferred admission sends no broker message"
    with api.Session() as session:
        job = session.get(Job, body["job_ids"][0])
        run = session.get(Run, body["run_id"])
    assert job is not None and job.status == "queued" and job.celery_task_id is None
    assert job.detail[DEFERRED_KEY] is True and job.detail[CAPACITY_KEY]["active_runs"] == 1
    assert run is not None and run.status == "queued" and run.stage_table[DEFERRED_KEY] is True
    # The admission row itself is the usual success row; capacity refused nothing.
    admission = api.events("attack.run")
    assert len(admission) == 1 and admission[0].success and admission[0].run_id == body["run_id"]
    # With the slot free the same route enqueues at once and the body carries no capacity keys.
    with api.Session.begin() as session:
        live = session.get(Job, "job-live-slot")
        assert live is not None
        live.status = "succeeded"
    second = api.client.post(f"/v1/models/{MODEL}/attacks", json={"attack_ids": ["fgsm"]})
    assert second.status_code == 202, second.text
    assert "deferred" not in second.json() and "capacity" not in second.json()
    assert api.delay_calls == [second.json()["job_ids"][0]]


@pytest.mark.skipif(not _capacity_available(), reason="redsim.services.ml_capacity is not on this tree")
def test_single_attack_route_refuses_a_spent_daily_budget_with_an_audited_row(api: Harness,
                                                                              monkeypatch: pytest.MonkeyPatch) -> None:
    """BULK-21 (a): the second admission of the UTC day is ``429 daily_budget_exceeded`` after a ``success=False``
    row; no Run, Job or campaign row is written for it."""
    monkeypatch.setenv(BUDGET_ENVS[0], "1")
    seed_model(api)
    assert api.client is not None
    _as(api, "scanner")
    first = api.client.post(f"/v1/models/{MODEL}/attacks", json={"attack_ids": ["fgsm"]})
    assert first.status_code == 202, first.text
    before = api.counts()
    refused = api.client.post(f"/v1/models/{MODEL}/attacks", json={"attack_ids": ["fgsm"]})
    assert refused.status_code == 429, refused.text
    detail = refused.json()["detail"]
    assert detail["code"] == "daily_budget_exceeded" and detail["budget"] == 1 and detail["used"] == 1
    assert detail["requested"] == 1 and detail["resets_at"].endswith("Z") and detail["retry_after"] >= 1
    assert api.counts() == before, "a refused admission writes no rows"
    rows = [e for e in api.events("attack.run") if not e.success]
    assert len(rows) == 1 and rows[0].detail["code"] == "daily_budget_exceeded" and rows[0].run_id is None
    assert rows[0].detail["target_id"] == MODEL and rows[0].project_id == PROJECT
    assert api.delay_calls == [first.json()["job_ids"][0]]


@pytest.mark.skipif(not _capacity_available(), reason="redsim.services.ml_capacity is not on this tree")
def test_single_verify_route_is_deferred_over_the_concurrency_cap(api: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    from redsim.services.ml_capacity import DEFERRED_KEY

    ids = seed_verify_baseline(api, monkeypatch)
    monkeypatch.setenv(CAPACITY_ENV, "1")
    _seed_live_job(api, MODEL)
    assert api.client is not None
    _as(api, "remediator")
    response = api.client.post(f"/v1/findings/{ids['fgsm']}/verify", json={})
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["deferred"] is True and body["capacity"]["code"] == "capacity_deferred"
    assert api.delay_calls == []
    with api.Session() as session:
        job = session.get(Job, body["job_ids"][0])
        finding = session.get(Finding, ids["fgsm"])
    assert job is not None and job.status == "queued" and job.detail[DEFERRED_KEY] is True
    assert finding is not None and finding.status == "fixing", "admitted, waiting for a slot"


@pytest.mark.skipif(not _capacity_available(), reason="redsim.services.ml_capacity is not on this tree")
def test_batch_members_are_decided_once_by_the_batch_service(api: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    """The batch passes ``capacity_check=False``: with the budget at exactly two admissions both members are
    admitted (the single boundary does not count them a second time) and nothing is refused."""
    monkeypatch.setenv(BUDGET_ENVS[0], "2")
    seed_model(api)
    seed_model(api, MODEL_2)
    response = _post_batch(api, _body(MODEL, MODEL_2))
    assert response.status_code == 202, response.text
    body = response.json()
    assert [m["target_id"] for m in body["members"]] == [MODEL, MODEL_2] and body["refused"] == []
    assert api.delay_calls == [m["job_ids"][0] for m in body["members"]]
    assert not [e for e in api.writer.events if not e.success]


# --------------------------------------------------------------------------- rows before the broker message


def test_batch_stamps_land_before_the_broker_message(api: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    """The batch stamps (``batch_id``, a verify's ``finding_ids`` and its per-finding ``verify.replay`` rows) are
    written through the boundary's ``before_enqueue`` hook, so the Job the broker (or an eager worker) picks up
    already carries them (BULK-16: the projection reaches every selected finding whenever the worker runs)."""
    from redsim.services import ml_campaigns

    seen_at_enqueue: list[dict[str, Any]] = []

    def recording_enqueue(job_id: str) -> str | None:
        with api.Session() as session:
            job = session.get(Job, job_id)
            assert job is not None
            replay_rows = [e for e in api.writer.events if e.action == "verify.replay" and e.run_id == job.run_id]
            seen_at_enqueue.append({"job_id": job_id, "batch_id": job.detail.get("batch_id"),
                                    "finding_ids": job.detail.get("finding_ids"),
                                    "n_replay_rows": len(replay_rows)})
        api.delay_calls.append(job_id)
        return f"task-{job_id}"

    monkeypatch.setattr(ml_campaigns, "_enqueue_campaign", recording_enqueue)

    # a campaign batch: batch_id is on the Job before the message
    seed_model(api)
    seed_model(api, MODEL_2)
    response = _post_batch(api, _body(MODEL, MODEL_2))
    assert response.status_code == 202, response.text
    batch_id = response.json()["batch_id"]
    assert [s["batch_id"] for s in seen_at_enqueue] == [batch_id, batch_id]
    seen_at_enqueue.clear()

    # a verify batch: finding_ids and one verify.replay row per selected finding precede the message
    ids = seed_verify_baseline(api, monkeypatch)
    _as(api, "remediator")
    assert api.client is not None
    response = api.client.post(f"/v1/findings/{ids['fgsm']}/verify/bulk", json={"defense": "feature_squeezing"})
    assert response.status_code == 202, response.text
    (member,) = response.json()["members"]
    assert len(seen_at_enqueue) == 1 and seen_at_enqueue[0]["job_id"] == member["job_ids"][0]
    assert seen_at_enqueue[0]["finding_ids"] == [ids["fgsm"], ids["pgd"]]
    assert seen_at_enqueue[0]["batch_id"] == response.json()["batch_id"]
    assert seen_at_enqueue[0]["n_replay_rows"] == 2, "the admission row and the second finding's row"
