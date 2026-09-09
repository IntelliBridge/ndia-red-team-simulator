"""``POST /v1/runs/{id}/cancel`` on a terminal run is ``409 run_terminal`` (spec 6.3, 10.7, 17.3).

A cancelled, failed or succeeded campaign is terminal: the route refuses to
cancel it again, the run and its jobs keep their status and completion time,
and the refusal leaves exactly one ``run.cancel`` ``success=False`` row on the
run chain (a refused admission is still audited). A live run still cancels
(``200``) with the ``run.cancel`` row written first.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from redsim.api.errors import HTTP_STATUS, RUN_TERMINAL
from redsim.db.models import Job, Run
from tests.ml.test_campaign_routes import ACTOR, MODEL, PROJECT, Harness, build_harness, seed_model

pytestmark = pytest.mark.integration


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Harness]:
    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    yield build_harness(tmp_path, monkeypatch, with_api=True)
    rl._BUCKETS.clear()


def _seed_run(harness: Harness, run_id: str, status: str, *, job_status: str) -> datetime | None:
    completed = datetime(2026, 9, 8, 12, 0, tzinfo=UTC) if status in {"succeeded", "failed", "cancelled"} else None
    with harness.Session.begin() as session:
        session.add(Run(id=run_id, project_id=PROJECT, target_id=MODEL, mode="api", status=status,
                        scanner="ml.campaign", created_by=ACTOR, completed_at=completed,
                        stage_table={"stage": "score", "stages_done": ["attack"], "jobs": {}}))
        session.flush()
        session.add(Job(id=f"job-{run_id}", run_id=run_id, project_id=PROJECT, type="attack.run",
                        status=job_status, created_by=ACTOR, detail={}))
    return completed


@pytest.mark.parametrize("status", ["succeeded", "failed", "cancelled"])
def test_cancel_terminal_run_409(api: Harness, status: str) -> None:
    seed_model(api)
    completed = _seed_run(api, f"run-{status}", status, job_status=status)
    assert api.client is not None

    response = api.client.post(f"/v1/runs/run-{status}/cancel")

    assert response.status_code == HTTP_STATUS[RUN_TERMINAL] == 409, response.text
    detail = response.json()["detail"]
    assert detail["code"] == RUN_TERMINAL == "run_terminal"
    assert detail["run_id"] == f"run-{status}" and detail["status"] == status
    with api.Session() as session:
        run = session.get(Run, f"run-{status}")
        job = session.get(Job, f"job-run-{status}")
    assert run is not None and run.status == status and run.completed_at is not None
    assert run.completed_at.replace(tzinfo=UTC) == completed
    assert run.stage_table == {"stage": "score", "stages_done": ["attack"], "jobs": {}}
    assert job is not None and job.status == status
    events = api.events("run.cancel")
    assert [event.success for event in events] == [False], "a refused cancel is audited once, as a refusal"
    refused = events[0]
    assert refused.run_id == f"run-{status}" and refused.project_id == PROJECT
    assert refused.detail["reason"] == RUN_TERMINAL and refused.detail["run_status"] == status


def test_cancel_live_run_still_admits(api: Harness) -> None:
    seed_model(api)
    _seed_run(api, "run-live", "running", job_status="running")
    assert api.client is not None

    response = api.client.post("/v1/runs/run-live/cancel")

    assert response.status_code == 200, response.text
    assert response.json() == {"run_id": "run-live", "status": "cancelled", "jobs_cancelled": 1}
    with api.Session() as session:
        run = session.get(Run, "run-live")
        job = session.get(Job, "job-run-live")
    assert run is not None and run.status == "cancelled" and run.completed_at is not None
    assert job is not None and job.status == "cancelled"
    events = api.events("run.cancel")
    assert len(events) == 1 and events[0].success and events[0].run_id == "run-live"

    again = api.client.post("/v1/runs/run-live/cancel")
    assert again.status_code == 409 and again.json()["detail"]["code"] == "run_terminal"
    assert [event.success for event in api.events("run.cancel")] == [True, False]
    with api.Session() as session:
        run = session.get(Run, "run-live")
    assert run is not None and run.status == "cancelled", "the second cancel changed nothing"
