"""Review finding F6: a verify run whose score is partial must still finish.

``redsim.ml.scoring.score_run`` can return an ``MRIRecord`` with ``mri=None``
(a subscore such as the explanation shift was unavailable) and the campaign
runner still stamps that record ``succeeded``. ``redsim.ml.scoring.delta``
refuses such a record with ``ValueError``. The worker must not let that refusal
fail the whole verify job: the run and job succeed, the delta is recorded as
unavailable in the run's limitations, the recommendation stays
``validation="not evaluated"``, and the finding outcome follows spec 6.4, where
a partial verify score is ``inconclusive`` (``validation_state="inconclusive"``,
``status="open"``). When both scores are complete the ``MeasuredDelta`` is
written and the outcome comes from the recorded attack measurements.

The task body runs end to end through the real ``task_context`` on a file-backed
sqlite database (one connection per session, as in production). The sandboxed
campaign runner is replaced by a fake that returns a canned verify record built
from the frozen ``run_record.json`` fixture, and the audit writer by a recorder,
so no second connection writes while the body session holds sqlite's write lock.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, Text, create_engine
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
from redsim.ml.schema import CampaignRecord, grade_for_mri
from redsim.services.ml_findings import project_campaign_findings
from redsim.storage import FilesystemBlobStore
from tests.conftest import patch_jsonb_for_sqlite

pytestmark = pytest.mark.integration

FIXTURE = Path(__file__).parent / "ml" / "fixtures" / "run_record.json"
BASELINE_RUN_ID = "run-fixture-0001"
VERIFY_RUN_ID = "run-verify-0001"
VERIFY_JOB_ID = "job-verify-0001"
RECOMMENDATION_ID = "r.R2"
DEFENSE = {
    "id": "feature_squeezing",
    "art_class": "art.defences.preprocessor.FeatureSqueezing",
    "params": {"bit_depth": 4},
}
COMPLETE_VERIFY_MRI = 50
MISSING_SUBSCORE = "S_expl unavailable (no SHAP attributions were produced for the defended copy)"


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
        Column("baseline_run_id", String),
        Column("parent_run_id", String),
        Column("reviewer_notes", Text),
        Column("created_at", DateTime),
        Column("completed_at", DateTime),
    )
    table.create(engine)
    return table


class _RecordingAuditWriter:
    """Stands in for ``PostgresAuditWriter``: keeps the events, writes no rows."""

    events: list[dict[str, Any]] = []

    def __init__(self, session_factory: Any) -> None:
        self.session_factory = session_factory

    def append(self, **event: Any) -> None:
        type(self).events.append(event)


def _baseline_record() -> CampaignRecord:
    return CampaignRecord.model_validate(json.loads(FIXTURE.read_text()))


def _verify_record(*, partial: bool) -> CampaignRecord:
    """A verify child of the fixture campaign: same model, sample and settings."""
    data = json.loads(FIXTURE.read_text())
    data["run_id"] = "run-local-child"
    data["kind"] = "verify"
    data["baseline_run_id"] = BASELINE_RUN_ID
    data["config"]["defense"] = DEFENSE
    data["provenance"]["baseline_run_id"] = BASELINE_RUN_ID
    data["provenance"]["defense"] = DEFENSE
    score = data["score"]
    if partial:
        score["subscores"]["S_expl"] = None
        for per_attack in score["per_attack"].values():
            per_attack["S_expl"] = {"value": None, "n": None, "reason": "explanations unavailable"}
        score.update({
            "mri": None, "grade": None, "completeness": "partial", "reading": None,
            "missing": [MISSING_SUBSCORE],
        })
        data["completeness"] = "partial"
        data["missing"] = [MISSING_SUBSCORE]
    else:
        score.update({"mri": COMPLETE_VERIFY_MRI, "grade": grade_for_mri(COMPLETE_VERIFY_MRI)})
    return CampaignRecord.model_validate(data)


@pytest.fixture
def verify_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Seed a baseline campaign, its finding and an admitted verify job, and wire
    the worker's collaborators (sessions, blobs, config, events) to sqlite and
    ``tmp_path``. Returns the pieces a test needs to run and inspect the job."""
    patch_jsonb_for_sqlite()
    engine = create_engine(f"sqlite:///{tmp_path / 'verify.db'}", future=True)
    Base.metadata.create_all(engine)
    campaigns = _campaign_table(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    @contextmanager
    def get_session() -> Iterator[Session]:
        # Same shape as redsim.db.session.get_session: commit on a clean exit.
        session = sessions()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    store = FilesystemBlobStore(tmp_path / "blobs")

    baseline = _baseline_record()
    baseline_bytes = baseline.model_dump_json().encode()
    baseline_ref = store.put(
        f"project-1/{BASELINE_RUN_ID}/run_record.json", baseline_bytes,
        content_type="application/json",
    )
    verify_config = baseline.config.model_dump(mode="json")
    verify_config["defense"] = DEFENSE

    with get_session() as session:
        org = Organization(id="org-1", name="Review organization", slug="review-organization")
        session.add(org)
        session.flush()
        project = Project(id="project-1", org_id=org.id, name="Review project", slug="review-project")
        session.add(project)
        session.flush()
        session.add(Target(
            id=baseline.config.target_id, project_id=project.id, kind="ml_model",
            value="bundled:tiny", verified=True,
            detail={"modality": "image", "status": "available"},
        ))
        session.add(Run(
            id=BASELINE_RUN_ID, project_id=project.id, scanner="attack.run",
            target_id=baseline.config.target_id, status="succeeded", stage_table={},
        ))
        session.flush()
        session.add(Artifact(
            id="artifact-baseline-record", run_id=BASELINE_RUN_ID, project_id=project.id,
            kind="ml.run_record", sha256=hashlib.sha256(baseline_bytes).hexdigest(),
            location=baseline_ref.location, content_type="application/json",
            size_bytes=len(baseline_bytes),
        ))
        session.execute(campaigns.insert().values(
            run_id=BASELINE_RUN_ID, project_id=project.id,
            target_id=baseline.config.target_id, kind="attack", modality="image",
            config=baseline.config.model_dump(mode="json"),
            settings_hash=baseline.settings_hash,
            provenance=baseline.provenance.model_dump(mode="json") if baseline.provenance else None,
            score=baseline.score.model_dump(mode="json") if baseline.score else None,
            limitations=baseline.limitations,
        ))
        finding_ids = project_campaign_findings(session, baseline)
        findings = [session.get(Finding, finding_id) for finding_id in finding_ids]
        finding = next(f for f in findings if f is not None and f.schema_blob["ml"]["attack_id"] == "fgsm")
        assert any(r["id"] == RECOMMENDATION_ID for r in finding.schema_blob["ml"]["recommendations"])
        finding_id = finding.id

        session.add(Run(
            id=VERIFY_RUN_ID, project_id=project.id, scanner="verify.replay",
            target_id=baseline.config.target_id, status="queued", stage_table={},
            created_by="reviewer-1",
        ))
        session.flush()
        session.add(Job(
            id=VERIFY_JOB_ID, run_id=VERIFY_RUN_ID, project_id=project.id,
            type="verify.replay", status="queued", created_by="reviewer-1",
            detail={
                "finding_id": finding_id,
                "recommendation_id": RECOMMENDATION_ID,
                "baseline_run_id": BASELINE_RUN_ID,
                "campaign_config": verify_config,
            },
        ))
        session.execute(campaigns.insert().values(
            run_id=VERIFY_RUN_ID, project_id=project.id,
            target_id=baseline.config.target_id, kind="verify", modality="image",
            config=verify_config, settings_hash=baseline.settings_hash,
            limitations=[], baseline_run_id=BASELINE_RUN_ID,
        ))

    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.setattr("redsim.db.session.get_session", get_session)
    monkeypatch.setattr("redsim.audit.chain.PostgresAuditWriter", _RecordingAuditWriter)
    monkeypatch.setattr(_RecordingAuditWriter, "events", [])
    monkeypatch.setattr("redsim.storage.open_blob_store", lambda *_a, **_k: store)
    monkeypatch.setattr(
        "redsim.config.load_config",
        lambda *_a, **_k: RedsimConfig(output_dir=str(tmp_path / "out")),
    )
    monkeypatch.setattr("redsim.workers.events._redis_client", lambda: None)

    def install_sandbox(record: CampaignRecord) -> list[str]:
        """Replace the sandboxed runner with one that returns ``record``."""
        stages: list[str] = []

        def fake_run_campaign_sandboxed(config: Any, sink: Any, **kwargs: Any) -> CampaignRecord:
            assert config.defense is not None and config.defense.id == DEFENSE["id"]
            assert kwargs.get("baseline_run_id") == BASELINE_RUN_ID
            on_stage = kwargs.get("on_stage")
            for stage in ("attack", "score", "report"):
                stages.append(stage)
                if on_stage is not None:
                    on_stage(stage)
            sink.put("run_record.json", record.model_dump_json().encode(), "application/json")
            if record.score is not None:
                sink.put("score.json", record.score.model_dump_json().encode(), "application/json")
            return record

        monkeypatch.setattr("redsim.ml.sandbox.run_campaign_sandboxed", fake_run_campaign_sandboxed)
        return stages

    return {
        "sessions": sessions,
        "campaigns": campaigns,
        "store": store,
        "finding_id": finding_id,
        "install_sandbox": install_sandbox,
        "audit_events": _RecordingAuditWriter.events,
    }


def _run_verify_job() -> dict[str, Any]:
    from redsim.workers.tasks.ml_campaign import ml_campaign_run

    result = ml_campaign_run.apply(args=[VERIFY_JOB_ID]).get()
    assert isinstance(result, dict)
    return result


def _persisted_verify_record(harness: dict[str, Any]) -> CampaignRecord:
    with harness["sessions"]() as session:
        artifacts = session.query(Artifact).filter(
            Artifact.run_id == VERIFY_RUN_ID, Artifact.kind == "ml.run_record",
        ).all()
    assert len(artifacts) == 1
    data = harness["store"].get(str(artifacts[0].location))
    assert hashlib.sha256(data).hexdigest() == artifacts[0].sha256
    return CampaignRecord.model_validate_json(data)


def _recommendation(finding: Finding) -> dict[str, Any]:
    return next(
        r for r in finding.schema_blob["ml"]["recommendations"] if r["id"] == RECOMMENDATION_ID
    )


def test_partial_verify_score_finishes_and_projects_the_outcome_without_a_delta(
    verify_harness: dict[str, Any],
) -> None:
    from redsim.workers.tasks.ml_campaign import DELTA_UNAVAILABLE_LIMITATION

    verify_harness["install_sandbox"](_verify_record(partial=True))

    result = _run_verify_job()

    assert result["status"] == "succeeded"
    assert result["run_id"] == VERIFY_RUN_ID
    with verify_harness["sessions"]() as session:
        job = session.get(Job, VERIFY_JOB_ID)
        run = session.get(Run, VERIFY_RUN_ID)
        finding = session.get(Finding, verify_harness["finding_id"])
        campaigns = verify_harness["campaigns"]
        row = session.execute(
            campaigns.select().where(campaigns.c.run_id == VERIFY_RUN_ID)
        ).mappings().one()
    assert job is not None and job.status == "succeeded", job.error if job else None
    assert run is not None and run.status == "succeeded"
    # The verify outcome was audited as ``verify.execute`` (spec 5.11 / 10.5) on the run chain; an
    # inconclusive outcome is a ``success=False`` row naming the reason.
    verify_rows = [
        event for event in verify_harness["audit_events"]
        if event["action"] == "verify.execute" and event["detail"]["job_id"] == VERIFY_JOB_ID
    ]
    assert len(verify_rows) == 1
    assert verify_rows[0]["success"] is False
    assert verify_rows[0]["detail"]["outcome"] == "inconclusive"
    assert "partial" in verify_rows[0]["detail"]["inconclusive_reason"]

    # Spec 6.4: ``score.completeness = "partial"`` on the verify run is ``inconclusive``; the
    # finding stays ``open`` (never ``failed`` or ``fixed`` on a partial verify record).
    assert finding is not None
    verify = finding.schema_blob["ml"]["verify"]
    assert verify["run_id"] == VERIFY_RUN_ID
    assert verify["outcome"] == "inconclusive"
    assert verify["delta"] is None
    assert verify["defense"]["id"] == DEFENSE["id"]
    assert finding.validation_state == "inconclusive"
    assert finding.status == "open"

    # No delta was measured, so the recommendation is not promoted.
    recommendation = _recommendation(finding)
    assert recommendation["validation"] == "not evaluated"
    assert recommendation["measured"] is None

    # The delta is recorded as unavailable, with the reason, on the verify run.
    prefix = DELTA_UNAVAILABLE_LIMITATION.split("{reason}")[0]
    delta_limitations = [item for item in row["limitations"] if item.startswith(prefix)]
    assert len(delta_limitations) == 1
    assert "verify score record is partial" in delta_limitations[0]
    assert MISSING_SUBSCORE in delta_limitations[0]
    assert row["score"]["mri"] is None
    assert row["score"]["delta"] is None

    persisted = _persisted_verify_record(verify_harness)
    assert persisted.run_id == VERIFY_RUN_ID
    assert persisted.status == "succeeded"
    assert persisted.score is not None and persisted.score.delta is None
    assert delta_limitations[0] in persisted.limitations


def test_complete_verify_score_writes_the_measured_delta(
    verify_harness: dict[str, Any],
) -> None:
    from redsim.workers.tasks.ml_campaign import DELTA_UNAVAILABLE_LIMITATION

    baseline = _baseline_record()
    assert baseline.score is not None and baseline.score.mri is not None
    expected_delta = COMPLETE_VERIFY_MRI - baseline.score.mri
    verify_harness["install_sandbox"](_verify_record(partial=False))

    result = _run_verify_job()

    assert result["status"] == "succeeded"
    with verify_harness["sessions"]() as session:
        job = session.get(Job, VERIFY_JOB_ID)
        finding = session.get(Finding, verify_harness["finding_id"])
        campaigns = verify_harness["campaigns"]
        row = session.execute(
            campaigns.select().where(campaigns.c.run_id == VERIFY_RUN_ID)
        ).mappings().one()
    assert job is not None and job.status == "succeeded", job.error if job else None
    assert finding is not None

    verify = finding.schema_blob["ml"]["verify"]
    assert verify["outcome"] == "still_vulnerable"
    assert verify["delta"]["baseline_run_id"] == BASELINE_RUN_ID
    assert verify["delta"]["mri_before"] == baseline.score.mri
    assert verify["delta"]["mri_after"] == COMPLETE_VERIFY_MRI
    assert verify["delta"]["delta"] == expected_delta

    recommendation = _recommendation(finding)
    assert recommendation["validation"] == "measured"
    measured = recommendation["measured"]
    assert measured["verify_run_id"] == VERIFY_RUN_ID
    assert measured["baseline_run_id"] == BASELINE_RUN_ID
    assert measured["defense"]["id"] == DEFENSE["id"]
    assert measured["delta_mri"] == expected_delta
    assert measured["settings_hash"] == baseline.settings_hash
    assert measured["delta_acc_clean"]["before"]["n_correct"] == 172
    assert measured["delta_acc_clean"]["after"]["n_correct"] == 172

    prefix = DELTA_UNAVAILABLE_LIMITATION.split("{reason}")[0]
    assert not any(item.startswith(prefix) for item in row["limitations"])
    assert row["score"]["delta"]["delta"] == expected_delta

    persisted = _persisted_verify_record(verify_harness)
    assert persisted.score is not None and persisted.score.delta is not None
    assert persisted.score.delta.delta == expected_delta


def test_attach_verify_delta_names_a_partial_baseline_too() -> None:
    """The pure helper: a partial baseline is reported, not passed to ``delta``."""
    from redsim.workers.tasks.ml_campaign import _attach_verify_delta

    baseline = _verify_record(partial=True).model_copy(update={"run_id": BASELINE_RUN_ID})
    verify = _verify_record(partial=False).model_copy(update={"run_id": VERIFY_RUN_ID})

    out = _attach_verify_delta(verify, baseline, baseline_run_id=BASELINE_RUN_ID)

    assert out.score is not None and out.score.delta is None
    added = [item for item in out.limitations if item not in verify.limitations]
    assert len(added) == 1
    assert "baseline score record is partial" in added[0]
    assert MISSING_SUBSCORE in added[0]

    # Both complete and compatible: the delta is attached and nothing is added.
    complete_baseline = _baseline_record()
    out = _attach_verify_delta(verify, complete_baseline, baseline_run_id=BASELINE_RUN_ID)
    assert out.score is not None and out.score.delta is not None
    assert out.score.delta.delta == COMPLETE_VERIFY_MRI - 42
    assert out.limitations == verify.limitations
