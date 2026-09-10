"""Admission services: audit-before-rows and rerun lineage.

Register rows G-API-ATTACKS (audit order, refused rows) and G-API-RERUN
(``parent_run_id`` copies the parent configuration and stores the lineage,
original untouched). Offline, on the harness of ``tests/ml/test_campaign_routes.py``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from redsim.api.errors import ApiError
from redsim.config import RedsimConfig
from redsim.db.models import Job, Run
from redsim.services.ml_campaigns import create_attack_campaign
from tests.ml.test_campaign_routes import (
    ACTOR,
    CELERY_TASK_ID,
    DATASET,
    MODEL,
    PROJECT,
    SHA256,
    Harness,
    build_harness,
    launch,
    parent_config,
    seed_campaign_run,
    seed_model,
)

pytestmark = pytest.mark.integration

GRID = [0.01, 0.03, 0.1]


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Harness]:
    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    yield build_harness(tmp_path, monkeypatch, with_api=True)
    rl._BUCKETS.clear()


# --------------------------------------------------------------------------- attack.run order

def test_create_attack_campaign_audits_before_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    harness = build_harness(tmp_path, monkeypatch, with_api=False)
    seed_model(harness)
    seen_at_enqueue: dict[str, Any] = {}

    def observing_delay(job_id: str) -> Any:
        # By the time Celery is touched the audit row and the durable rows both exist.
        seen_at_enqueue["events"] = [(event.action, event.success) for event in harness.writer.events]
        seen_at_enqueue["counts"] = harness.counts()
        harness.delay_calls.append(job_id)
        return type("_Task", (), {"id": CELERY_TASK_ID})()

    monkeypatch.setattr("redsim.workers.tasks.ml_campaign.ml_campaign_run.delay", observing_delay)

    handle = create_attack_campaign(
        campaign={"target_id": MODEL, "attack_ids": ["fgsm", "pgd"], "seed": 3},
        project_id=PROJECT, actor=ACTOR, config=RedsimConfig(), audit_writer=harness.writer,
    )

    assert harness.writer.run_existed_at_append == [False], "the attack.run row precedes the Run row"
    assert seen_at_enqueue["events"] == [("attack.run", True)]
    assert seen_at_enqueue["counts"] == {"runs": 1, "jobs": 1, "campaigns": 1}
    assert harness.delay_calls == handle.job_ids
    with harness.Session() as session:
        run = session.get(Run, handle.run_id)
        job = session.get(Job, handle.job_ids[0])
    assert run is not None and run.status == "queued" and run.scanner == "ml.campaign"
    assert job is not None and job.celery_task_id == CELERY_TASK_ID
    assert job.detail["campaign_config"]["attack_ids"] == ["fgsm", "pgd"]
    assert job.detail["campaign_config"]["seed"] == 3
    assert job.detail["campaign_config"]["eps_grid"] == GRID
    row = harness.campaign_row(handle.run_id)
    assert row is not None and row["kind"] == "attack" and row["target_id"] == MODEL
    event = harness.writer.events[0]
    assert event.action == "attack.run" and event.success and event.run_id == handle.run_id
    assert event.detail["model_sha256"] == SHA256 and event.detail["attack_ids"] == ["fgsm", "pgd"]


def test_create_attack_campaign_refusal_writes_a_failed_row_and_nothing_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = build_harness(tmp_path, monkeypatch, with_api=False)
    seed_model(harness)

    with pytest.raises(ApiError) as excinfo:
        create_attack_campaign(
            campaign={"target_id": MODEL, "attack_ids": ["fgsm", "nope"]},
            project_id=PROJECT, actor=ACTOR, config=RedsimConfig(), audit_writer=harness.writer,
        )

    assert excinfo.value.code == "unknown_attack" and excinfo.value.status == 422
    assert excinfo.value.detail["field"] == "attack_ids"
    assert harness.counts() == {"runs": 0, "jobs": 0, "campaigns": 0} and harness.delay_calls == []
    assert [(e.action, e.success) for e in harness.writer.events] == [("attack.run", False)]
    refused = harness.writer.events[0]
    assert refused.run_id is None and refused.project_id == PROJECT
    assert refused.detail["code"] == "unknown_attack" and refused.detail["target_id"] == MODEL
    assert refused.detail["attack_ids"] == ["fgsm", "nope"]


# --------------------------------------------------------------------------- rerun lineage

def test_rerun_links_parent(api: Harness) -> None:
    seed_model(api)
    config = parent_config()
    seed_campaign_run(api, "run-parent-failed", status="failed", config=config)
    with api.Session() as session:
        before = session.get(Run, "run-parent-failed")
        assert before is not None
        parent_before = {"status": before.status, "stage_table": dict(before.stage_table),
                         "completed_at": before.completed_at, "created_by": before.created_by}
    parent_row_before = dict(api.campaign_row("run-parent-failed") or {})

    response = launch(api, {"parent_run_id": "run-parent-failed"})

    assert response.status_code == 202, response.text
    body = response.json()
    run_id, (job_id,) = body["run_id"], body["job_ids"]
    assert run_id != "run-parent-failed"
    with api.Session() as session:
        run = session.get(Run, run_id)
        job = session.get(Job, job_id)
        parent = session.get(Run, "run-parent-failed")
    assert run is not None and run.status == "queued" and run.target_id == MODEL
    assert run.stage_table["parent_run_id"] == "run-parent-failed"
    assert job is not None and job.detail["parent_run_id"] == "run-parent-failed"
    copied = job.detail["campaign_config"]
    for key in ("attack_ids", "attack_params", "norm", "eps_grid", "reference_eps", "n_samples", "seed",
                "explain_k", "dataset_id", "dataset_revision", "finding_asr_threshold", "scoring"):
        assert copied[key] == config[key], key
    assert copied["target_snapshot"]["id"] == MODEL and [a["id"] for a in copied["attacks"]] == ["fgsm", "pgd"]
    row = api.campaign_row(run_id)
    assert row is not None and row["parent_run_id"] == "run-parent-failed" and row["kind"] == "attack"
    assert row["config"]["seed"] == config["seed"] == 7
    # Lineage on the chain; the original run and campaign row are untouched.
    events = api.events("attack.run")
    assert len(events) == 1 and events[0].success and events[0].run_id == run_id
    assert events[0].detail["rerun"] is True and events[0].detail["parent_run_id"] == "run-parent-failed"
    assert api.writer.run_existed_at_append == [False]
    assert parent is not None
    assert {"status": parent.status, "stage_table": dict(parent.stage_table), "completed_at": parent.completed_at,
            "created_by": parent.created_by} == parent_before
    assert dict(api.campaign_row("run-parent-failed") or {}) == parent_row_before
    assert api.delay_calls == [job_id]


def test_rerun_of_a_cancelled_parent_is_admitted_too(api: Harness) -> None:
    seed_model(api)
    seed_campaign_run(api, "run-parent-cancelled", status="cancelled")
    response = launch(api, {"parent_run_id": "run-parent-cancelled"})
    assert response.status_code == 202, response.text
    row = api.campaign_row(response.json()["run_id"])
    assert row is not None and row["parent_run_id"] == "run-parent-cancelled"
    assert row["config"]["dataset_id"] == DATASET
