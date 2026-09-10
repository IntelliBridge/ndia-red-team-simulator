"""Per-project Foundry settings, the push fallback, the exports block and the auto-push hook (2026-09-10).

Reuses the seeded app of ``tests/ml/test_atlas_foundry.py`` (dev auth over
sqlite, a live campaign run with its record, a fixture run, a running run, a
bearer and a form profile, the Foundry environment off until
``api.enable_foundry()``).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("numpy")
pytest.importorskip("cryptography")
pytest.importorskip("httpx")

from redsim.api.errors import (
    AUTH_PROFILE_KIND_UNSUPPORTED,
    AUTH_PROFILE_REQUIRED,
    FIXTURE_NOT_EXPORTABLE,
    INTEGRATION_DISABLED,
    NOT_FOUND,
    PARAMS_OUT_OF_RANGE,
)
from redsim.db.models import Job, Project, Run
from redsim.integrations import ADMISSION_ACTION, PUSH_RUN_KIND, PUSH_SCANNER
from redsim.services.ml_integrations import AUTO_PUSH_ACTOR, foundry_project_settings
from redsim.workers.tasks.foundry_auto_push import auto_push_after_campaign
from tests.ml import test_atlas_foundry as _atlas
from tests.ml.fake_foundry_server import DEFAULT_DATASET_RID
from tests.ml.test_atlas_foundry import ADMIN, FIXTURE_RUN, PROJECT, RUN, RUNNING_RUN, VIEWER, _detail

# The seeded app fixture of the atlas-foundry module, registered here under its own name.
api = _atlas.api

pytestmark = pytest.mark.integration

ROUTE = f"/v1/projects/{PROJECT}/integrations/foundry"
PROJECT_RID = "ri.foundry.main.dataset.9bc42537-e3d6-4c3d-8591-f560e9a34c16"


def _settings_rows(api: SimpleNamespace) -> list[Any]:
    return [e for e in api.writer.events if e.action == "project.settings"]


# --------------------------------------------------------------------------- GET / PUT the project settings


def test_view_unconfigured_names_every_blocker(api: SimpleNamespace) -> None:
    resp = api.call(VIEWER, "GET", ROUTE)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["project_id"] == PROJECT and body["project"] == PROJECT
    assert body["deployment"]["status"] == "disabled" and body["deployment"]["host"] is None
    assert body["settings"] == {"dataset_rid": None, "auth_profile_id": None, "auth_profile_name": None,
                                "auto_push": False, "updated_at": None, "updated_by": None}
    assert body["effective"]["ready"] is False
    assert body["effective"]["blockers"] == ["integration_disabled", "auth_profile_missing", "dataset_rid_missing"]


def test_put_is_admin_only_and_refusals_are_typed_and_audited(api: SimpleNamespace) -> None:
    assert api.call(VIEWER, "PUT", ROUTE, {"auto_push": True}).status_code == 403
    cases: list[tuple[dict[str, Any], int, str]] = [
        ({"unknown": 1}, 422, PARAMS_OUT_OF_RANGE),
        ({"dataset_rid": "https://foundry.invalid/x"}, 422, PARAMS_OUT_OF_RANGE),
        ({"auth_profile_id": api.other_profile_id}, 404, NOT_FOUND),
        ({"auth_profile_id": "authprof-missing"}, 404, NOT_FOUND),
        ({"auth_profile_id": api.form_profile_id}, 422, AUTH_PROFILE_KIND_UNSUPPORTED),
        ({"auto_push": "yes"}, 422, PARAMS_OUT_OF_RANGE),
        ({"auto_push": True}, 501, INTEGRATION_DISABLED),
    ]
    for body, status, code in cases:
        api.writer.events.clear()
        resp = api.call(ADMIN, "PUT", ROUTE, body)
        assert resp.status_code == status, (body, resp.text)
        assert _detail(resp)["code"] == code, (body, resp.text)
        rows = _settings_rows(api)
        assert len(rows) == 1 and rows[0].success is False and rows[0].detail["refusal"] == code
        assert "foundry.invalid" not in str(rows[0].detail)
    with api.Session() as sess:
        assert sess.get(Project, PROJECT).ml_integrations is None, "a refused PUT writes nothing"


def test_auto_push_needs_a_ready_configuration(api: SimpleNamespace) -> None:
    api.enable_foundry()
    # configured deployment, but no profile yet: the toggle is refused with the blockers named
    resp = api.call(ADMIN, "PUT", ROUTE, {"auto_push": True})
    assert resp.status_code == 422 and _detail(resp)["code"] == PARAMS_OUT_OF_RANGE, resp.text
    assert _detail(resp)["reason"] == "auto_push_not_ready" and "auth_profile_missing" in _detail(resp)["blockers"]


def test_put_stores_the_settings_audited_before_the_write(api: SimpleNamespace) -> None:
    api.enable_foundry()
    api.writer.events.clear()
    resp = api.call(ADMIN, "PUT", ROUTE, {"dataset_rid": PROJECT_RID, "auth_profile_id": api.profile_id,
                                          "auto_push": True})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deployment"]["status"] == "configured" and body["deployment"]["host"] == "127.0.0.1"
    assert body["deployment"]["default_dataset_rid"] == DEFAULT_DATASET_RID
    assert body["settings"]["dataset_rid"] == PROJECT_RID and body["settings"]["auth_profile_id"] == api.profile_id
    assert body["settings"]["auth_profile_name"] == "foundry-token" and body["settings"]["auto_push"] is True
    assert body["settings"]["updated_by"] == f"user:{ADMIN.sub}" and body["settings"]["updated_at"]
    assert body["effective"] == {"dataset_rid": PROJECT_RID, "ready": True, "blockers": []}
    rows = _settings_rows(api)
    assert len(rows) == 1 and rows[0].success is True
    assert rows[0].detail["field"] == "ml_integrations.foundry" and rows[0].detail["auto_push"] is True
    assert rows[0].detail["dataset_rid"] == PROJECT_RID and rows[0].detail["old_sha256"] != rows[0].detail["new_sha256"]
    with api.Session() as sess:
        stored = foundry_project_settings(sess.get(Project, PROJECT))
    assert stored["dataset_rid"] == PROJECT_RID and stored["auto_push"] is True
    # a partial PUT keeps the other keys; null clears one
    assert api.call(ADMIN, "PUT", ROUTE, {"auto_push": False}).json()["settings"]["dataset_rid"] == PROJECT_RID
    cleared = api.call(ADMIN, "PUT", ROUTE, {"dataset_rid": None}).json()
    assert cleared["settings"]["dataset_rid"] is None
    assert cleared["effective"]["dataset_rid"] == DEFAULT_DATASET_RID, "the deployment default fills in"
    assert api.call(VIEWER, "GET", ROUTE).json()["settings"]["auth_profile_id"] == api.profile_id


# --------------------------------------------------------------------------- the push falls back to the project


def test_push_with_an_empty_body_uses_the_project_settings(api: SimpleNamespace) -> None:
    api.enable_foundry()
    api.writer.events.clear()
    refused = api.call(ADMIN, "POST", f"/v1/runs/{RUN}/integrations/foundry", {})
    assert refused.status_code == 422 and _detail(refused)["code"] == AUTH_PROFILE_REQUIRED, refused.text
    assert api.call(ADMIN, "PUT", ROUTE, {"dataset_rid": PROJECT_RID, "auth_profile_id": api.profile_id}).status_code == 200
    api.writer.events.clear()
    pushed = api.call(ADMIN, "POST", f"/v1/runs/{RUN}/integrations/foundry", {})
    assert pushed.status_code == 202, pushed.text
    handle = pushed.json()
    assert handle["target_ref"] == PROJECT_RID and handle["campaign_run_id"] == RUN and handle["kind"] == PUSH_RUN_KIND
    assert api.enqueued and api.enqueued[-1][0] == handle["job_ids"][0]
    admission = [e for e in api.writer.events if e.action == ADMISSION_ACTION]
    assert len(admission) == 1 and admission[0].success is True
    assert admission[0].detail["auth_profile_id"] == api.profile_id
    assert admission[0].detail["auth_profile_from_project"] is True
    with api.Session() as sess:
        job = sess.get(Job, handle["job_ids"][0])
        assert job.detail["auth_profile_id"] == api.profile_id and job.detail["target_ref"] == PROJECT_RID


# --------------------------------------------------------------------------- the exports inventory


def _rows(api: SimpleNamespace) -> dict[str, dict[str, Any]]:
    resp = api.call(ADMIN, "GET", f"/v1/exports?project={PROJECT}")
    assert resp.status_code == 200, resp.text
    return {row["run_id"]: row for row in resp.json()["exports"]}


def test_exports_rows_carry_the_foundry_state(api: SimpleNamespace) -> None:
    rows = _rows(api)
    assert rows[RUN]["foundry"] == {"status": "not_configured", "auto_push": False, "push_run_id": None,
                                    "transaction_rid": None, "pushed_at": None, "error": None, "blockers": []}
    assert rows[FIXTURE_RUN]["foundry"]["blockers"] == ["fixture_target"]
    assert rows[RUNNING_RUN]["foundry"]["blockers"] == ["not_terminal"]

    api.enable_foundry()
    assert api.call(ADMIN, "PUT", ROUTE, {"auth_profile_id": api.profile_id, "auto_push": True}).status_code == 200
    rows = _rows(api)
    assert rows[RUN]["foundry"]["status"] == "not_pushed" and rows[RUN]["foundry"]["auto_push"] is True

    handle = api.call(ADMIN, "POST", f"/v1/runs/{RUN}/integrations/foundry", {}).json()
    rows = _rows(api)
    assert rows[RUN]["foundry"]["status"] == "queued" and rows[RUN]["foundry"]["push_run_id"] == handle["run_id"]
    assert handle["run_id"] not in rows, "the follow-up push run is not an export row"

    # the worker's outcome is read from the push run: a receipt stamp, or the failed stage's error
    with api.Session() as sess:
        push_run = sess.get(Run, handle["run_id"])
        push_run.status = "succeeded"
        push_run.stage_table = {**push_run.stage_table, "transaction_rid": "ri.foundry.main.transaction.t-1",
                                "pushed_at": "2026-09-10T03:40:40+00:00"}
        sess.commit()
    foundry = _rows(api)[RUN]["foundry"]
    assert foundry["status"] == "pushed" and foundry["transaction_rid"] == "ri.foundry.main.transaction.t-1"
    assert foundry["pushed_at"] == "2026-09-10T03:40:40+00:00"
    with api.Session() as sess:
        push_run = sess.get(Run, handle["run_id"])
        push_run.status = "failed"
        push_run.stage_table = {**push_run.stage_table, "stages": {"push": {"status": "failed",
                                                                            "error": "foundry_push_failed: HTTP 401"}}}
        sess.commit()
    foundry = _rows(api)[RUN]["foundry"]
    assert foundry["status"] == "failed" and foundry["error"] == "foundry_push_failed: HTTP 401"


# --------------------------------------------------------------------------- the worker hook


def _campaign_job(api: SimpleNamespace, run_id: str, *, status: str = "succeeded") -> str:
    job_id = f"job-{run_id}-campaign"
    with api.Session() as sess:
        sess.add(Job(id=job_id, run_id=run_id, project_id=PROJECT, type="attack.run", status=status,
                     created_by="user:creator", detail={}))
        sess.commit()
    return job_id


def test_auto_push_hook_is_a_no_op_until_the_toggle_is_on(api: SimpleNamespace) -> None:
    api.enable_foundry()
    job_id = _campaign_job(api, RUN)
    assert auto_push_after_campaign(job_id) is None
    assert auto_push_after_campaign("job-unknown") is None
    assert api.enqueued == [] and [e for e in api.writer.events if e.action == ADMISSION_ACTION] == []


def test_auto_push_hook_admits_through_the_boundary(api: SimpleNamespace) -> None:
    api.enable_foundry()
    assert api.call(ADMIN, "PUT", ROUTE, {"dataset_rid": PROJECT_RID, "auth_profile_id": api.profile_id,
                                          "auto_push": True}).status_code == 200
    api.writer.events.clear()
    result = auto_push_after_campaign(_campaign_job(api, RUN))
    assert result is not None and result["kind"] == PUSH_RUN_KIND and result["campaign_run_id"] == RUN
    assert result["target_ref"] == PROJECT_RID
    assert api.enqueued == [(result["job_ids"][0], "default")]
    admission = [e for e in api.writer.events if e.action == ADMISSION_ACTION]
    assert len(admission) == 1 and admission[0].success is True and admission[0].actor == AUTO_PUSH_ACTOR
    assert admission[0].detail["requested_by"] == AUTO_PUSH_ACTOR if "requested_by" in admission[0].detail else True
    with api.Session() as sess:
        push_run = sess.get(Run, result["run_id"])
        assert push_run.scanner == PUSH_SCANNER and push_run.created_by == AUTO_PUSH_ACTOR
        assert push_run.stage_table["parent_run_id"] == RUN
        assert sess.get(Run, RUN).status == "succeeded", "the campaign run is never touched"
    # a second completion of the same campaign while the push is queued is refused (job_in_flight), audited, no raise
    api.writer.events.clear()
    again = auto_push_after_campaign(_campaign_job(api, RUN) if False else f"job-{RUN}-campaign")
    assert again == {"refused": "job_in_flight", "campaign_run_id": RUN}
    refused_rows = [e for e in api.writer.events if e.action == ADMISSION_ACTION]
    assert len(refused_rows) == 1 and refused_rows[0].success is False


def test_auto_push_hook_skips_non_succeeded_runs_and_records_refusals(api: SimpleNamespace) -> None:
    api.enable_foundry()
    assert api.call(ADMIN, "PUT", ROUTE, {"dataset_rid": PROJECT_RID, "auth_profile_id": api.profile_id,
                                          "auto_push": True}).status_code == 200
    api.writer.events.clear()
    assert auto_push_after_campaign(_campaign_job(api, RUNNING_RUN, status="running")) is None
    assert api.enqueued == []
    # a fixture run that succeeded: the boundary refuses (D3) and the hook records it without raising
    result = auto_push_after_campaign(_campaign_job(api, FIXTURE_RUN))
    assert result == {"refused": FIXTURE_NOT_EXPORTABLE, "campaign_run_id": FIXTURE_RUN}
    rows = [e for e in api.writer.events if e.action == ADMISSION_ACTION]
    assert len(rows) == 1 and rows[0].success is False and rows[0].detail["code"] == FIXTURE_NOT_EXPORTABLE
    assert api.enqueued == []
