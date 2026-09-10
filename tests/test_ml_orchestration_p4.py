from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker

from redsim.config import RedsimConfig
from redsim.db.models import (
    Artifact,
    Base,
    Finding,
    Job,
    Organization,
    Project,
    Run,
    Target,
)
from redsim.ml.schema import CampaignRecord
from redsim.services.ml_findings import project_campaign_findings

FIXTURE = Path(__file__).parent / "ml" / "fixtures" / "run_record.json"


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type: JSONB, _compiler: Any, **_kwargs: Any) -> str:
    return "JSON"


class _Task:
    id = "celery-task-1"


class _AuditWriter:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.sessions = sessions
        self.events: list[dict[str, Any]] = []

    def append(self, **event: Any) -> None:
        with self.sessions() as session:
            assert session.get(Run, event["run_id"]) is None
        self.events.append(event)


def _campaign_table(engine: Any) -> Table:
    table = Table(
        "ml_campaigns",
        MetaData(),
        Column("run_id", String, primary_key=True),
        Column("project_id", String, nullable=False),
        Column("org_id", String),
        Column("target_id", String, nullable=False),
        Column("kind", String, nullable=False),
        Column("modality", String, nullable=False),
        Column("config", JSON, nullable=False),
        Column("settings_hash", String),
        Column("provenance", JSON),
        Column("score", JSON),
        Column("limitations", JSON, nullable=False),
        Column("parent_run_id", String),
        Column("reviewer_notes", Text),
        Column("created_at", DateTime),
        Column("completed_at", DateTime),
    )
    table.create(engine)
    return table


@pytest.fixture
def orchestration_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    engine = create_engine(f"sqlite:///{tmp_path / 'p4.db'}")
    Base.metadata.create_all(engine)
    campaigns = _campaign_table(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    record = CampaignRecord.model_validate(json.loads(FIXTURE.read_text()))
    record_bytes = record.model_dump_json().encode()
    with sessions.begin() as session:
        org = Organization(id="org-1", name="P4 organization", slug="p4-organization")
        session.add(org)
        session.flush()
        project = Project(id="project-1", org_id=org.id, name="P4 project", slug="p4-project")
        session.add(project)
        session.flush()
        target = Target(
            id=record.config.target_id,
            project_id=project.id,
            kind="ml_model",
            value="bundled://fixture",
            verified=True,
            detail={"modality": "image", "status": "available"},
        )
        baseline = Run(
            id=record.run_id,
            project_id=project.id,
            scanner="attack.run",
            target_id=record.config.target_id,
            status="succeeded",
            stage_table={},
        )
        session.add_all([target, baseline])
        session.flush()
        session.add(Artifact(
            id="artifact-baseline-record",
            run_id=record.run_id,
            project_id=project.id,
            kind="ml.run_record",
            sha256=hashlib.sha256(record_bytes).hexdigest(),
            location="memory://baseline/run_record.json",
            content_type="application/json",
            size_bytes=len(record_bytes),
        ))
        session.execute(
            campaigns.insert().values(
                run_id=record.run_id,
                project_id=project.id,
                target_id=record.config.target_id,
                kind="attack",
                modality="image",
                config=record.config.model_dump(mode="json"),
                settings_hash=record.settings_hash,
                provenance=record.provenance.model_dump(mode="json"),
                score=record.score.model_dump(mode="json") if record.score else None,
                limitations=record.limitations,
            )
        )

    @contextmanager
    def get_session() -> Any:
        with sessions.begin() as session:
            yield session

    monkeypatch.setattr("redsim.db.session.get_session", get_session)
    monkeypatch.setattr(
        "redsim.storage.blobs.open_blob_store",
        lambda: type("_BlobStore", (), {"get": lambda _self, _key: record_bytes})(),
    )
    return {"sessions": sessions, "campaigns": campaigns, "record": record}


def test_p4_routes_are_materialized_in_openapi() -> None:
    from redsim.api.app import create_app

    app = create_app()
    paths = app.openapi()["paths"]
    expected = {
        "/v1/models",
        "/v1/attacks",
        "/v1/datasets",
        "/v1/runs/{run_id}/campaign",
        "/v1/runs/{run_id}/compare",
        "/v1/runs/{run_id}/reviewer-notes",
        "/v1/runs/{run_id}/artifacts",
        "/v1/artifacts/{artifact_id}",
        "/v1/findings/{finding_id}/explain",
        "/v1/findings/{finding_id}/harden",
    }
    assert expected <= paths.keys()


def test_finding_projection_is_idempotent(orchestration_db: dict[str, Any]) -> None:
    record = orchestration_db["record"]
    sessions = orchestration_db["sessions"]

    with sessions.begin() as session:
        first = project_campaign_findings(session, record)
    with sessions.begin() as session:
        second = project_campaign_findings(session, record)

    assert second == first
    with sessions() as session:
        findings = session.query(Finding).order_by(Finding.scanner_finding_id).all()
    assert len(findings) == 2
    assert {item.scanner_finding_id for item in findings} == {"ml.fgsm", "ml.pgd"}
    assert {item.source_tool for item in findings} == {"redsim.ml/fgsm", "redsim.ml/pgd"}
    assert {item.schema_blob["ml"]["attack_id"] for item in findings} == {"fgsm", "pgd"}
    assert all(item.dedup_key.startswith("ml:d0d0d0d0d0d0d0d0:") for item in findings)


@pytest.mark.parametrize(
    ("action", "body", "job_type"),
    [
        ("explain", {"explain_k": 3, "seed": 21}, "explain.run"),
        ("harden", {"llm_narrative": False}, "harden.recommend"),
    ],
)
def test_finding_actions_admit_real_child_campaigns(
    orchestration_db: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    body: dict[str, Any],
    job_type: str,
) -> None:
    from redsim.services.ml_findings import create_finding_action_job

    record = orchestration_db["record"]
    sessions = orchestration_db["sessions"]
    campaigns = orchestration_db["campaigns"]
    with sessions.begin() as session:
        finding_id = project_campaign_findings(session, record)[0]
    writer = _AuditWriter(sessions)
    monkeypatch.setattr("redsim.workers.tasks.ml_campaign.ml_campaign_run.delay", lambda _id: _Task())

    handle = create_finding_action_job(
        finding_id=finding_id,
        action=action,
        body=body,
        actor="reviewer-1",
        config=RedsimConfig(),
        audit_writer=writer,
    )

    with sessions() as session:
        run = session.get(Run, handle.run_id)
        job = session.get(Job, handle.job_ids[0])
        row = session.execute(
            campaigns.select().where(campaigns.c.run_id == handle.run_id)
        ).mappings().one()
    assert run is not None
    assert job is not None
    assert writer.events[0]["action"] == job_type
    assert job.type == job_type
    assert job.celery_task_id == "celery-task-1"
    assert row["parent_run_id"] == record.run_id
    assert row["config"]["attack_ids"] == record.config.attack_ids
    assert row["config"]["eps_grid"] == record.config.eps_grid
    if action == "explain":
        assert row["config"]["explain_k"] == 3
        assert row["config"]["seed"] == 21
    else:
        assert row["config"]["auto_recommend"] is True
        assert row["config"]["llm_narrative"] is False


