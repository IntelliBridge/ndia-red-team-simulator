"""Worker task ``redsim.ml_campaign_run`` end to end on sqlite (spec 6.5, 5.8, 10.5, 10.6).

The task body runs through the real ``task_context`` on a file-backed sqlite
database with the sandboxed campaign runner replaced by a fake that returns a
canned record built from the frozen ``tests/ml/fixtures/run_record.json`` and
writes the same artifact names the child would. The audit writer is the JSONL
chain writer rooted in ``tmp_path`` so the rows carry real hashes and
``verify_chain`` can walk them (``tests/ml/test_audit_campaign.py`` reuses this
harness). Nothing here loads a model or touches the network.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

# ``redsim.services.ml_findings`` reaches ``redsim.ml.eval`` (numpy); skip cleanly on the 3.13 lane.
pytest.importorskip("numpy")
from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, Text, create_engine
from sqlalchemy.orm import Session, sessionmaker

from redsim.audit.chain import JsonlAuditWriter
from redsim.config import RedsimConfig
from redsim.db.models import (
    Artifact,
    Base,
    Finding,
    Job,
    LLMUsage,
    Organization,
    Project,
    Run,
    Target,
)
from redsim.ml.errors import SandboxTimeout
from redsim.ml.schema import STAGES, CampaignRecord
from redsim.services.ml_findings import project_campaign_findings
from redsim.storage import FilesystemBlobStore
from tests.conftest import patch_jsonb_for_sqlite

pytestmark = pytest.mark.integration

FIXTURE = Path(__file__).parent / "fixtures" / "run_record.json"
BASELINE_RUN_ID = "run-baseline-0001"
ATTACK_RUN_ID = "run-attack-0001"
ATTACK_JOB_ID = "job-attack-0001"
FOLLOWON_RUN_ID = "run-followon-0001"
FOLLOWON_JOB_ID = "job-followon-0001"
PROJECT_ID = "project-1"
ORG_ID = "org-1"
CREATOR = "user:alice"


# --------------------------------------------------------------------------- records


def fixture_record() -> CampaignRecord:
    return CampaignRecord.model_validate(json.loads(FIXTURE.read_text()))


def _campaign_table(engine: Any) -> Table:
    table = Table(
        "ml_campaigns", MetaData(),
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


# --------------------------------------------------------------------------- harness


class Harness:
    """Sqlite + filesystem blob store + JSONL audit chains wired into the worker's collaborators."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_jsonb_for_sqlite()
        self.tmp_path = tmp_path
        self.engine = create_engine(f"sqlite:///{tmp_path / 'tasks.db'}", future=True)
        Base.metadata.create_all(self.engine)
        self.campaigns = _campaign_table(self.engine)
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.store = FilesystemBlobStore(tmp_path / "blobs")
        self.audit_dir = tmp_path / "audit"
        self.baseline = fixture_record()
        self.config = RedsimConfig(output_dir=str(tmp_path / "out"))
        self.sandbox_calls: list[dict[str, Any]] = []

        @contextmanager
        def get_session() -> Iterator[Session]:
            session = self.sessions()
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

        self.get_session = get_session
        audit_dir = self.audit_dir

        def jsonl_writer(*_a: Any, **_k: Any) -> JsonlAuditWriter:
            return JsonlAuditWriter(audit_dir)

        monkeypatch.delenv("REDSIM_DB_URL", raising=False)
        monkeypatch.delenv("REDSIM_DISABLE_LLM", raising=False)
        monkeypatch.setattr("redsim.db.session.get_session", get_session)
        monkeypatch.setattr("redsim.audit.chain.PostgresAuditWriter", jsonl_writer)
        monkeypatch.setattr("redsim.storage.open_blob_store", lambda *_a, **_k: self.store)
        monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: self.store)
        monkeypatch.setattr("redsim.config.load_config", lambda *_a, **_k: self.config)
        monkeypatch.setattr("redsim.workers.events._redis_client", lambda: None)
        self.monkeypatch = monkeypatch
        self._seed()

    # -- seeding ---------------------------------------------------------------

    def _seed(self) -> None:
        baseline = self.baseline
        with self.get_session() as session:
            session.add(Organization(id=ORG_ID, name="Tasks org", slug="tasks-org"))
            session.flush()
            session.add(Project(id=PROJECT_ID, org_id=ORG_ID, name="Tasks project", slug="tasks-project"))
            session.flush()
            session.add(Target(
                id=baseline.config.target_id, project_id=PROJECT_ID, kind="ml_model_artifact",
                value="bundled:tiny", verified=True,
                detail={"modality": "image", "status": "available", "format": "torch_state_dict",
                        "sha256": baseline.provenance.model_sha256 if baseline.provenance else None,
                        "architecture_id": "small_cnn", "gradients": True},
            ))

    def seed_baseline(self) -> str:
        """A succeeded baseline campaign with its ``ml.run_record`` artifact and projected findings; returns the fgsm finding id."""
        baseline = self.baseline
        baseline_bytes = baseline.model_dump_json().encode()
        ref = self.store.put(f"{PROJECT_ID}/{BASELINE_RUN_ID}/run_record.json", baseline_bytes,
                             content_type="application/json")
        with self.get_session() as session:
            session.add(Run(id=BASELINE_RUN_ID, project_id=PROJECT_ID, scanner="ml.campaign",
                            target_id=baseline.config.target_id, status="succeeded", stage_table={},
                            created_by=CREATOR))
            session.flush()
            session.add(Artifact(
                id="artifact-baseline-record", run_id=BASELINE_RUN_ID, project_id=PROJECT_ID,
                kind="ml.run_record", sha256=hashlib.sha256(baseline_bytes).hexdigest(),
                location=ref.location, content_type="application/json", size_bytes=len(baseline_bytes),
            ))
            session.execute(self.campaigns.insert().values(
                run_id=BASELINE_RUN_ID, project_id=PROJECT_ID, target_id=baseline.config.target_id,
                kind="attack", modality="image", config=baseline.config.model_dump(mode="json"),
                settings_hash=baseline.settings_hash,
                provenance=baseline.provenance.model_dump(mode="json") if baseline.provenance else None,
                score=baseline.score.model_dump(mode="json") if baseline.score else None,
                limitations=baseline.limitations,
            ))
            projected = project_campaign_findings(
                session, baseline.model_copy(update={"run_id": BASELINE_RUN_ID}),
            )
            findings = [session.get(Finding, fid) for fid in projected]
            fgsm = next(f for f in findings if f is not None and f.schema_blob["ml"]["attack_id"] == "fgsm")
            return str(fgsm.id)

    def add_job(self, *, run_id: str, job_id: str, job_type: str, config: dict[str, Any],
                detail: dict[str, Any] | None = None, kind: str = "attack",
                parent_run_id: str | None = None, scanner: str = "ml.campaign") -> None:
        with self.get_session() as session:
            session.add(Run(id=run_id, project_id=PROJECT_ID, scanner=scanner, target_id=config["target_id"],
                            status="queued", stage_table={"stage": None, "stages_done": [], "jobs": {}},
                            created_by=CREATOR))
            session.flush()
            session.add(Job(id=job_id, run_id=run_id, project_id=PROJECT_ID, type=job_type, status="queued",
                            created_by=CREATOR, detail={**(detail or {}), "campaign_config": config}))
            session.execute(self.campaigns.insert().values(
                run_id=run_id, project_id=PROJECT_ID, target_id=config["target_id"], kind=kind,
                modality=config["modality"], config=config, limitations=[],
                parent_run_id=parent_run_id,
            ))

    def add_attack_job(self, *, llm_narrative: bool = False) -> None:
        config = self.baseline.config.model_dump(mode="json")
        config["llm_narrative"] = llm_narrative
        self.add_job(run_id=ATTACK_RUN_ID, job_id=ATTACK_JOB_ID, job_type="attack.run", config=config)

    def add_followon_job(self, finding_id: str, *, job_type: str) -> None:
        config = self.baseline.config.model_dump(mode="json")
        self.add_job(run_id=FOLLOWON_RUN_ID, job_id=FOLLOWON_JOB_ID, job_type=job_type, config=config,
                     detail={"finding_id": finding_id, "parent_run_id": BASELINE_RUN_ID},
                     parent_run_id=BASELINE_RUN_ID, scanner=f"ml.{job_type.split('.', 1)[0]}")

    # -- the fake sandbox ------------------------------------------------------

    def install_sandbox(self, record: CampaignRecord, *, before_return: Callable[[Any], None] | None = None,
                        raise_after: BaseException | None = None, stages: list[str] | None = None) -> None:
        """Replace the sandboxed runner with one that replays ``record`` (or raises ``raise_after``)."""
        calls = self.sandbox_calls

        def fake(config: Any, sink: Any, **kwargs: Any) -> CampaignRecord:
            calls.append({"config": config, "kwargs": kwargs})
            assert kwargs.get("job_id"), "the parent must key the work directory by job_id"
            on_stage = kwargs.get("on_stage")
            for stage in (stages if stages is not None else list(record.stages_done)):
                if on_stage is not None:
                    on_stage(stage)
            if raise_after is not None:
                sink.put("ml/partial/flip_matrix.json", b'{"partial": true}', "application/json")
                sink.put("ml/partial/run_record.json", record.model_dump_json().encode(), "application/json")
                raise raise_after
            for curve in record.curve:
                sink.put(f"curve/{curve.attack_id}.json", curve.model_dump_json().encode(), "application/json")
            sink.put("curve/robustness_curve.png", b"\x89PNG fake", "image/png")
            sink.put("flip_matrix.json", b'{"flipped": {}}', "application/json")
            sink.put("adv_slice/fgsm_eps0.03.npz", b"npz", "application/octet-stream")
            sink.put("obs_000/clean.png", b"png-clean", "image/png")
            sink.put("obs_000/shap_clean.png", b"png-shap", "image/png")
            sink.put("obs_000/shap_meta.json", b"{}", "application/json")
            sink.put("shap_summary.json", b"{}", "application/json")
            sink.put("shap_summary.txt", b"Measurements: m.clean accuracy=172/200 (0.860).\n"
                     b"SHAP attributions describe the model's sensitivity, not the cause of a failure.",
                     "text/plain; charset=utf-8")
            if before_return is not None:
                before_return(sink)
            sink.put("run_record.json", record.model_dump_json().encode(), "application/json")
            if record.score is not None:
                sink.put("score.json", record.score.model_dump_json().encode(), "application/json")
            return record

        self.monkeypatch.setattr("redsim.ml.sandbox.run_campaign_sandboxed", fake)

    # -- running and reading back --------------------------------------------

    @staticmethod
    def run_job(job_id: str) -> dict[str, Any]:
        from redsim.workers.tasks.ml_campaign import ml_campaign_run

        result = ml_campaign_run.apply(args=[job_id]).get()
        assert isinstance(result, dict)
        return result

    def events(self, run_id: str) -> list[dict[str, Any]]:
        return list(JsonlAuditWriter(self.audit_dir).read_chain(f"run:{run_id}"))

    def artifacts(self, run_id: str) -> list[Artifact]:
        with self.sessions() as session:
            return list(session.query(Artifact).filter(Artifact.run_id == run_id).all())

    def persisted_record(self, run_id: str) -> CampaignRecord:
        rows = [a for a in self.artifacts(run_id) if a.kind == "ml.run_record"]
        assert len(rows) == 1
        data = self.store.get(str(rows[0].location))
        raw = data.encode() if isinstance(data, str) else bytes(data)
        assert hashlib.sha256(raw).hexdigest() == rows[0].sha256
        return CampaignRecord.model_validate_json(raw)

    def row(self, model: Any, key: str) -> Any:
        with self.sessions() as session:
            return session.get(model, key)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(tmp_path, monkeypatch)


# --------------------------------------------------------------------------- unit: kinds and stages


def test_artifact_kinds_follow_the_5_8_vocabulary() -> None:
    from redsim.ml import sandbox
    from redsim.workers.tasks.ml_campaign import PARTIAL_PREFIX, artifact_kind

    assert PARTIAL_PREFIX == sandbox.PARTIAL_PREFIX
    expected = {
        "run_record.json": "ml.run_record",
        "score.json": "ml.score",
        "flip_matrix.json": "ml.flip_matrix",
        "validation_report.json": "ml.validation_report",
        "curve/fgsm.json": "ml.curve",
        "curve/robustness_curve.png": "ml.curve",
        "adv_slice/fgsm_eps0.03.npz": "ml.adv_slice",
        "obs_003/clean.png": "ml.input.clean",
        "obs_003/adv.png": "ml.input.adv",
        "obs_003/diff.png": "ml.perturbation",
        "obs_003/shap_clean.png": "ml.shap.image",
        "obs_003/shap_adv.png": "ml.shap.image",
        "obs_003/shap_adv_predclass.png": "ml.shap.image",
        "obs_003/shap_values.npz": "ml.shap.values",
        "obs_003/shap_meta.json": "ml.shap.meta",
        "obs_003/feature_diff.json": "ml.feature_diff",
        "obs_003/shap_force_3.png": "ml.shap.force",
        "shap_bar_clean.png": "ml.shap.bar",
        "shap_beeswarm_adv.png": "ml.shap.beeswarm",
        "shap_summary.json": "ml.shap.summary",
        "shap_summary.txt": "ml.shap.summary_text",
        "harden/prompt.txt": "ml.harden.prompt",
        "harden/completion.txt": "ml.harden.completion",
        "harden/narrative.md": "ml.harden.narrative",
        "report.md": "report.md",
        "report.json": "report.json",
        "report.html": "report.html",
        "ml/partial/run_record.json": "ml.partial.run_record",
        "ml/partial/curve/fgsm.json": "ml.partial.curve",
        "ml/partial/events.jsonl": "ml.partial.events",
        # Phase B (MODALITIES-44): the text modality's word diff and token bars
        # (redsim.ml.explain.shap_text.TEXT_DIFF_NAME / TEXT_PLOT_NAME) and its JSON-lines slices, the detection
        # modality's box record, drawn inputs and scorecard (redsim.ml.runners.detection.BOXES_JSON_NAME /
        # CLEAN_PNG_NAME / ADV_PNG_NAME / SCORECARD_NAME).
        "obs_002/text_diff.json": "ml.text.diff",
        "obs_002/shap_text.png": "ml.shap.text",
        "obs_002/shap_values.npz": "ml.shap.values",
        "adv_slice/word_substitution_eps0.1.jsonl": "ml.adv_slice",
        "obs_001/boxes.json": "ml.detection.boxes",
        "obs_001/clean_boxes.png": "ml.input.clean",
        "obs_001/adv_boxes.png": "ml.input.adv",
        "adv_slice/dpatch_eps0.03.npz": "ml.adv_slice",
        "detection_scorecard.json": "ml.detection.scorecard",
        "ml/partial/obs_001/boxes.json": "ml.partial.detection.boxes",
    }
    for name, kind in expected.items():
        assert artifact_kind(name) == kind, name
        assert len(kind) <= 64


def test_expected_stages_follow_schema_stages_order() -> None:
    from redsim.workers.tasks.ml_campaign import expected_stages

    record = fixture_record()
    stages = expected_stages(record.config)
    assert stages == ["load_target", "sample", "clean_eval", "attack:fgsm", "attack:pgd", "control",
                      "explain", "score", "interpret", "recommend", "report"]
    assert stages == list(record.stages_done)
    # STAGES with the per-attack expansion: the bases, deduplicated, are the frozen tuple in order.
    bases = [s.split(":", 1)[0] for s in stages]
    assert [b for i, b in enumerate(bases) if b not in bases[:i]] == list(STAGES)
    assert "defense_apply" not in stages
    # The optional stages follow the config: no control without the noise control, no explain at
    # explain_k 0, no recommend without auto_recommend. Every other stage is always expected.
    no_control = record.config.model_copy(update={"include_control": False})
    assert expected_stages(no_control) == [s for s in stages if s != "control"]
    no_explain = record.config.model_copy(update={"explain_k": 0})
    assert expected_stages(no_explain) == [s for s in stages if s != "explain"]
    no_recommend = record.config.model_copy(update={"auto_recommend": False})
    assert expected_stages(no_recommend) == [s for s in stages if s != "recommend"]
    one_attack = record.config.model_copy(update={"attack_ids": ["fgsm"]})
    assert expected_stages(one_attack) == [s for s in stages if s != "attack:pgd"]


# --------------------------------------------------------------------------- attack.run


def test_campaign_completes_and_projects_findings(harness: Harness) -> None:
    harness.add_attack_job()
    harness.install_sandbox(fixture_record())

    result = harness.run_job(ATTACK_JOB_ID)

    assert result["status"] == "succeeded" and result["run_id"] == ATTACK_RUN_ID
    assert result["n_findings"] == 2
    job = harness.row(Job, ATTACK_JOB_ID)
    run = harness.row(Run, ATTACK_RUN_ID)
    assert job is not None and job.status == "succeeded", job.error if job else None
    assert run is not None and run.status == "succeeded"
    with harness.sessions() as session:
        findings = session.query(Finding).filter(Finding.run_id == ATTACK_RUN_ID).all()
    assert {f.schema_blob["ml"]["attack_id"] for f in findings} == {"fgsm", "pgd"}
    assert all(f.status == "open" for f in findings)

    # The persisted record carries the platform run id and the child's evidence.
    persisted = harness.persisted_record(ATTACK_RUN_ID)
    assert persisted.run_id == ATTACK_RUN_ID and persisted.status == "succeeded"
    assert all(r.narrative_source == "rules" for r in persisted.recommendations)

    # Spec 5.8 kinds: reports are report.<ext>, the curve JSON and PNG share ml.curve, the SHAP files
    # carry their own kinds and nothing is left on the ml.<basename> fallback.
    kinds = {a.kind for a in harness.artifacts(ATTACK_RUN_ID)}
    assert {"report.md", "report.json", "report.html", "ml.run_record", "ml.score", "ml.curve",
            "ml.flip_matrix", "ml.adv_slice", "ml.input.clean", "ml.shap.image", "ml.shap.meta",
            "ml.shap.summary", "ml.shap.summary_text"} <= kinds
    assert not any(k.startswith("ml.report_") for k in kinds)
    assert all(len(k) <= 64 for k in kinds)
    # unique (run_id, kind, sha256): one row per report format
    with harness.sessions() as session:
        report_rows = session.query(Artifact).filter(Artifact.run_id == ATTACK_RUN_ID,
                                                     Artifact.kind == "report.md").all()
    assert len(report_rows) == 1
    # the sandbox was keyed by job id and given the platform's stage callback
    assert harness.sandbox_calls[0]["kwargs"]["job_id"] == ATTACK_JOB_ID


def test_stage_table_has_the_6_5_shape(harness: Harness) -> None:
    harness.add_attack_job()
    record = fixture_record()
    harness.install_sandbox(record)

    harness.run_job(ATTACK_JOB_ID)

    run = harness.row(Run, ATTACK_RUN_ID)
    assert run is not None
    table = run.stage_table
    assert table["stage"] == "report"
    assert table["stages_done"] == list(record.stages_done)
    assert table["completeness"] == "complete"
    assert table["error"] is None
    stages = table["stages"]
    assert set(record.stages_done) <= set(stages)
    for name in record.stages_done:
        entry = stages[name]
        assert entry["status"] == "succeeded"
        assert entry["job_id"] == ATTACK_JOB_ID
        assert entry["finished_at"] is not None
        assert set(entry) == {"status", "started_at", "finished_at", "job_id"}
    assert stages["load_target"]["started_at"] is not None
    # stages advance monotonically: finished_at is non-decreasing in stage order
    finished = [stages[n]["finished_at"] for n in record.stages_done]
    assert finished == sorted(finished)
    job_entry = table["jobs"][ATTACK_JOB_ID]
    assert job_entry["type"] == "attack.run" and job_entry["status"] == "succeeded"
    assert job_entry["attack_ids"] == ["fgsm", "pgd"]


def test_stage_frames_carry_name_and_status(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    frames: list[dict[str, Any]] = []

    def capture(run_id: str, job_id: str, status: str, **extra: Any) -> None:
        frames.append({"run_id": run_id, "job_id": job_id, "status": status, **extra})

    monkeypatch.setattr("redsim.workers.events.publish_job_event", capture)
    harness.add_attack_job()
    harness.install_sandbox(fixture_record())

    harness.run_job(ATTACK_JOB_ID)

    stage_frames = [f for f in frames if f.get("type") == "stage"]
    assert stage_frames, "stage transitions must be published"
    assert all({"type", "name", "status", "run_id", "job_id"} <= set(f) for f in stage_frames)
    assert {f["status"] for f in stage_frames} >= {"running", "succeeded"}
    succeeded = [f["name"] for f in stage_frames if f["status"] == "succeeded"]
    assert succeeded == list(fixture_record().stages_done)


# --------------------------------------------------------------------------- failure: sandbox timeout


def test_sandbox_timeout_marks_partial(harness: Harness) -> None:
    harness.add_attack_job()
    record = fixture_record()
    harness.install_sandbox(
        record, stages=["load_target", "sample"],
        raise_after=SandboxTimeout("ML sandbox timed out after 1200s; 2 partial file(s) kept under ml/partial/"),
    )

    with pytest.raises(SandboxTimeout):
        harness.run_job(ATTACK_JOB_ID)

    job = harness.row(Job, ATTACK_JOB_ID)
    run = harness.row(Run, ATTACK_RUN_ID)
    assert job is not None and job.status == "failed"
    assert job.error is not None and job.error.startswith("SandboxTimeout:")
    assert run is not None and run.status == "failed"
    table = run.stage_table
    assert table["completeness"] == "partial"
    assert table["stages"]["load_target"]["status"] == "succeeded"
    assert table["stages"]["sample"]["status"] == "succeeded"
    # the stage that was running when the wall clock fired
    assert table["stages"]["clean_eval"]["status"] == "timed_out"
    assert table["stages"]["clean_eval"]["finished_at"] is not None
    assert "SandboxTimeout" in table["error"]
    assert table["jobs"][ATTACK_JOB_ID]["status"] == "failed"
    # what the child had written is kept under ml/partial/ with partial kinds
    kinds = {a.kind for a in harness.artifacts(ATTACK_RUN_ID)}
    assert {"ml.partial.flip_matrix", "ml.partial.run_record"} <= kinds
    assert "ml.run_record" not in kinds and "report.md" not in kinds
    # no finding is created from a partial run
    with harness.sessions() as session:
        assert session.query(Finding).filter(Finding.run_id == ATTACK_RUN_ID).count() == 0
    # audit: model.load succeeded (load_target completed), job.complete failed with the class
    events = harness.events(ATTACK_RUN_ID)
    actions = [e["action"] for e in events]
    assert actions[0] == "model.load" and events[0]["success"] is True
    assert actions[-1] == "job.complete"
    assert events[-1]["success"] is False
    assert events[-1]["detail"]["error_class"] == "SandboxTimeout"
    assert events[-1]["detail"]["completeness"] == "partial"


def test_child_load_refusal_is_a_failed_job_with_refused_model_load(harness: Harness) -> None:
    from redsim.ml.sandbox import partial_campaign_record

    harness.add_attack_job()
    record = fixture_record()
    failed = partial_campaign_record(
        record.config, status="failed", error="ModelLoadRefused: pickle_refused: torch.save object detected",
        stages_done=[], parent_run_id=None,
    )
    harness.install_sandbox(failed, stages=[])

    with pytest.raises(RuntimeError, match="ModelLoadRefused"):
        harness.run_job(ATTACK_JOB_ID)

    job = harness.row(Job, ATTACK_JOB_ID)
    assert job is not None and job.status == "failed"
    events = harness.events(ATTACK_RUN_ID)
    load = next(e for e in events if e["action"] == "model.load")
    assert load["success"] is False and load["detail"]["error_class"] == "ModelLoadRefused"
    assert events[-1]["action"] == "job.complete" and events[-1]["success"] is False
    assert events[-1]["detail"]["error_class"] == "ModelLoadRefused"
    run = harness.row(Run, ATTACK_RUN_ID)
    assert run is not None and run.stage_table["completeness"] == "partial"
    assert run.stage_table["stages"]["load_target"]["status"] == "failed"


# --------------------------------------------------------------------------- explain.run / harden.recommend


def test_followon_writeback_merges_child_results_into_the_parent_finding(harness: Harness) -> None:
    finding_id = harness.seed_baseline()
    harness.add_followon_job(finding_id, job_type="harden.recommend")
    record = fixture_record()
    regenerated = [
        r.model_copy(update={"rationale": f"{r.rationale} (regenerated by harden.recommend)"})
        for r in record.recommendations
    ]
    child = record.model_copy(update={"recommendations": regenerated})
    harness.install_sandbox(child)

    result = harness.run_job(FOLLOWON_JOB_ID)

    assert result["status"] == "succeeded" and result["n_findings"] == 1
    finding = harness.row(Finding, finding_id)
    assert finding is not None
    ml = finding.schema_blob["ml"]
    assert ml["attack_id"] == "fgsm"
    assert ml["recommendations"], "the harden child re-supplied the finding's candidates"
    assert all(r["rationale"].endswith("(regenerated by harden.recommend)") for r in ml["recommendations"])
    # scoped: r.R1 cites pgd rows only and stays off the fgsm finding; r.R2 / r.R3 cite fgsm evidence
    assert {r["id"] for r in ml["recommendations"]} == {"r.R2", "r.R3"}
    # scoped to the finding's attack: clean + control rows and fgsm rows only
    assert {m["attack_id"] for m in ml["measurements"] if m["family"] == "evasion"} == {"fgsm"}
    assert any(m["family"] == "clean" for m in ml["measurements"])
    assert any(m["family"] == "control" for m in ml["measurements"])
    # readable back through the frozen contract
    from redsim.ml.schema import MLFindingDetail

    detail = MLFindingDetail.model_validate(ml)
    assert detail.review.state == "unreviewed"
    assert detail.artifacts["harden.recommend:run_record"]
    # the follow-on run itself projects no new finding rows
    with harness.sessions() as session:
        assert session.query(Finding).filter(Finding.run_id == FOLLOWON_RUN_ID).count() == 0
    # audit vocabulary on the follow-on chain includes harden.execute and job.complete
    actions = [e["action"] for e in harness.events(FOLLOWON_RUN_ID)]
    assert "harden.execute" in actions and actions[-1] == "job.complete"


def test_explain_followon_writes_observations_back(harness: Harness) -> None:
    finding_id = harness.seed_baseline()
    harness.add_followon_job(finding_id, job_type="explain.run")
    record = fixture_record()
    extra = record.observations[0].model_copy(update={"id": "o.900", "sample_index": 900,
                                                      "artifacts": {"shap_clean": "art-o.900-shap-clean"}})
    child = record.model_copy(update={"observations": [*record.observations, extra]})
    harness.install_sandbox(child)

    harness.run_job(FOLLOWON_JOB_ID)

    finding = harness.row(Finding, finding_id)
    assert finding is not None
    ml = finding.schema_blob["ml"]
    assert "o.900" in {o["id"] for o in ml["observations"]}
    assert ml["artifacts"]["shap_clean"] == "art-o.900-shap-clean"
    actions = [e["action"] for e in harness.events(FOLLOWON_RUN_ID)]
    assert "explain.execute" in actions and "campaign.score" in actions


# --------------------------------------------------------------------------- LLMUsage stays empty without a narrative


def test_no_llm_usage_row_without_a_narrative(harness: Harness) -> None:
    harness.add_attack_job()
    harness.install_sandbox(fixture_record())

    harness.run_job(ATTACK_JOB_ID)

    with harness.sessions() as session:
        assert session.query(LLMUsage).count() == 0
    kinds = {a.kind for a in harness.artifacts(ATTACK_RUN_ID)}
    assert not any(k.startswith("ml.harden.") for k in kinds)
