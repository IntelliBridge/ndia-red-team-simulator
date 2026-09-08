"""Review #22 F4: verify admission accepts the defense a rule-generated candidate names.

``redsim.ml.recommend.rules`` cites a defense as a ``defense:<id>`` reference next
to ``<ART class> (Phase A verify loop)`` and the motivating paper, while the frozen
``tests/ml/fixtures/run_record.json`` shape names the bare ART class. The admission
in ``redsim.services.ml_campaigns.create_verify_campaign`` used to test the bare
class for list membership, which never matched rule output and refused every
verify-after-harden request with ``recommendation_defense_mismatch``. It now
resolves the cited defense ids (``rules.defense_configs`` plus the bare-class
shape) and compares them with the requested ``defense_id``, still refusing a
defense the recommendation does not name.
"""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, Text, create_engine
from sqlalchemy.orm import sessionmaker

from redsim.config import RedsimConfig
from redsim.db.models import Artifact, Base, Finding, Job, Organization, Project, Run, Target
from redsim.ml.recommend.rules import recommend
from redsim.ml.schema import CampaignRecord, CandidateRecommendation, Measurement, MLFindingDetail
from redsim.services.ml_campaigns import create_verify_campaign, recommendation_defense_ids
from tests.conftest import patch_jsonb_for_sqlite

FIXTURE = Path(__file__).parent / "ml" / "fixtures" / "run_record.json"
GRID = [0.01, 0.03, 0.1]
N_CLEAN_CORRECT = 80
IMAGE_PREPROCESSORS = {"jpeg_compression", "spatial_smoothing", "feature_squeezing"}
# The fixture's hand-authored r.R2 (bare ART class references), re-labelled so it does not collide with
# the rule layer's own r.R2 when both sit on one finding.
FIXTURE_R2 = "r.fixture.R2"


# --------------------------------------------------------------------------- synthetic evidence

def _m(mid: str, family: str, n_correct: int, *, attack: str | None = None, eps: float | None = None,
       flipped: int | None = None, n: int = 100) -> Measurement:
    extra: dict[str, Any] = {}
    if flipped is not None:
        extra = {"n_flipped_from_clean": flipped, "n_clean_correct": N_CLEAN_CORRECT,
                 "attack_success_rate": round(flipped / N_CLEAN_CORRECT, 4)}
    params = {"eps": eps, "norm": "linf"} if eps is not None else {}
    return Measurement(id=mid, family=family, attack_id=attack, params=params, n=n, n_correct=n_correct,
                       accuracy=n_correct / n, notes=[], **extra)


def _degraded() -> list[Measurement]:
    """Clean 80/100, FGSM and PGD degrade across the grid, noise control flat at eps_ref.

    Triggers R1 (adversarial_training only), R2 (no defense), R6 (the three image preprocessors)
    and R7 (no defense) in ``redsim.ml.recommend.rules.recommend``.
    """
    return [
        _m("m.clean", "clean", 80),
        _m("m.evasion.fgsm.eps0.01", "evasion", 50, attack="fgsm", eps=0.01, flipped=30),
        _m("m.evasion.fgsm.eps0.03", "evasion", 40, attack="fgsm", eps=0.03, flipped=40),
        _m("m.evasion.fgsm.eps0.1", "evasion", 20, attack="fgsm", eps=0.1, flipped=60),
        _m("m.evasion.pgd.eps0.01", "evasion", 30, attack="pgd", eps=0.01, flipped=50),
        _m("m.evasion.pgd.eps0.03", "evasion", 20, attack="pgd", eps=0.03, flipped=60),
        _m("m.evasion.pgd.eps0.1", "evasion", 5, attack="pgd", eps=0.1, flipped=75),
        _m("m.control.noise.eps0.03", "control", 78, attack="noise_control", eps=0.03),
    ]


def _rule_candidates() -> list[CandidateRecommendation]:
    recs = recommend(_degraded(), [], None, modality="image")
    assert {r.id for r in recs} >= {"r.R1", "r.R6", "r.R7"}
    return recs


def _rec(recs: list[CandidateRecommendation], rec_id: str) -> CandidateRecommendation:
    return next(r for r in recs if r.id == rec_id)


# --------------------------------------------------------------------------- reference resolution

@pytest.mark.unit
def test_rule_generated_candidates_resolve_to_catalog_defense_ids() -> None:
    recs = _rule_candidates()
    r6 = _rec(recs, "r.R6")
    # The premise of F4: rule output never lists the bare ART class, so ``art_class in references`` is false.
    assert any(ref.startswith("defense:") for ref in r6.references)
    assert not any(ref.startswith("art.defences.") and " " not in ref for ref in r6.references)
    assert recommendation_defense_ids(r6) == IMAGE_PREPROCESSORS
    assert recommendation_defense_ids(_rec(recs, "r.R1")) == {"adversarial_training"}
    assert recommendation_defense_ids(_rec(recs, "r.R7")) == set()


@pytest.mark.unit
def test_bare_art_class_references_resolve_to_their_catalog_ids() -> None:
    hand_authored = CandidateRecommendation(
        id="r.X", title="t", rationale="r", triggered_by=["m.clean"],
        references=["art.defences.preprocessor.FeatureSqueezing", "art.defences.preprocessor.SpatialSmoothing",
                    "Xu, Evans, Qi 2018"],
    )
    assert recommendation_defense_ids(hand_authored) == {"feature_squeezing", "spatial_smoothing"}
    # The frozen fixture shape (GET /v1/runs/{id}/campaign) is exactly this bare-class form.
    fixture = CampaignRecord.model_validate(json.loads(FIXTURE.read_text()))
    by_id = {r.id: r for r in fixture.recommendations}
    assert recommendation_defense_ids(by_id["r.R2"]) == {"feature_squeezing", "spatial_smoothing"}
    assert recommendation_defense_ids(by_id["r.R3"]) == set()


# --------------------------------------------------------------------------- admission through the service

class _Task:
    id = "celery-task-verify"


class _AuditWriter:
    """Records events and asserts the audited run does not exist yet (audit precedes rows)."""

    def __init__(self, sessions: Any) -> None:
        self.sessions = sessions
        self.events: list[dict[str, Any]] = []

    def append(self, **event: Any) -> None:
        with self.sessions() as session:
            assert session.get(Run, event["run_id"]) is None
        self.events.append(event)


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
        Column("baseline_run_id", String),
        Column("parent_run_id", String),
        Column("reviewer_notes", Text),
        Column("created_at", DateTime),
        Column("completed_at", DateTime),
    )
    table.create(engine)
    return table


@pytest.fixture
def verify_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A succeeded baseline campaign (the frozen fixture record) and one ML finding.

    The finding's recommendations are the real rule output for ``_degraded()`` plus
    the fixture's hand-authored ``r.R2`` (bare ART class references, re-labelled
    ``FIXTURE_R2``), so both reference shapes reach the admission.

    A file-backed sqlite engine, as in ``tests/test_ml_orchestration_p4.py``: the
    service reflects ``ml_campaigns`` through the engine mid-transaction, which the
    shared single-connection in-memory harness cannot host.
    """
    patch_jsonb_for_sqlite()
    engine = create_engine(f"sqlite:///{tmp_path / 'f4.db'}")
    Base.metadata.create_all(engine)
    campaigns = _campaign_table(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    @contextmanager
    def session_cm() -> Any:
        with sessions.begin() as session:
            yield session

    record = CampaignRecord.model_validate(json.loads(FIXTURE.read_text()))
    record_bytes = record.model_dump_json().encode()
    measurements = _degraded()
    recs = _rule_candidates() + [r.model_copy(update={"id": FIXTURE_R2})
                                 for r in record.recommendations if r.id == "r.R2"]
    detail = MLFindingDetail(
        attack_id="fgsm", attack_name="FGSM", norm="linf", eps_grid=GRID, reference_eps=0.03,
        first_success_eps=0.01, asr_at_reference=0.5, threshold=0.2,
        measurements=[m for m in measurements if m.attack_id == "fgsm"], recommendations=recs,
    )
    finding_id = "finding-verify-f4"
    with session_cm() as session:
        session.add(Organization(id="org-1", name="F4 organization", slug="f4-organization"))
        session.flush()
        session.add(Project(id="project-1", org_id="org-1", name="F4 project", slug="f4-project"))
        session.flush()
        session.add_all([
            Target(id=record.config.target_id, project_id="project-1", kind="ml_model",
                   value="bundled://fixture", verified=True, detail={"modality": "image", "status": "available"}),
            Run(id=record.run_id, project_id="project-1", scanner="attack.run", target_id=record.config.target_id,
                status="succeeded", stage_table={}),
        ])
        session.flush()
        session.add(Artifact(
            id="artifact-baseline-record", run_id=record.run_id, project_id="project-1", kind="ml.run_record",
            sha256=hashlib.sha256(record_bytes).hexdigest(), location="memory://baseline/run_record.json",
            content_type="application/json", size_bytes=len(record_bytes),
        ))
        session.add(Finding(
            id=finding_id, scanner_finding_id="ml.fgsm", run_id=record.run_id, project_id="project-1",
            schema_blob={"ml": detail.model_dump(mode="json")}, status="open", severity="high",
            source_tool="redsim.ml/fgsm", validation_state="unvalidated",
        ))
        session.execute(campaigns.insert().values(
            run_id=record.run_id, project_id="project-1", target_id=record.config.target_id, kind="attack",
            modality="image", config=record.config.model_dump(mode="json"), settings_hash=record.settings_hash,
            provenance=record.provenance.model_dump(mode="json") if record.provenance else None,
            score=record.score.model_dump(mode="json") if record.score else None, limitations=record.limitations,
        ))

    monkeypatch.setattr("redsim.db.session.get_session", session_cm)
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store",
                        lambda: type("_BlobStore", (), {"get": lambda _self, _key: record_bytes})())
    monkeypatch.setattr("redsim.workers.tasks.ml_campaign.ml_campaign_run.delay", lambda _id: _Task())
    return {"sessions": sessions, "campaigns": campaigns, "record": record, "finding_id": finding_id}


def _admit(db: dict[str, Any], writer: _AuditWriter, recommendation_id: str, defense_id: str,
           params: dict[str, Any]) -> Any:
    return create_verify_campaign(
        finding_id=db["finding_id"], defense_id=defense_id, params=params, recommendation_id=recommendation_id,
        actor="reviewer-1", config=RedsimConfig(), audit_writer=writer,
    )


@pytest.mark.integration
@pytest.mark.parametrize(
    ("recommendation_id", "defense_id", "params"),
    [
        ("r.R6", "jpeg_compression", {"quality": 60}),       # rule output: defense:<id> references
        ("r.R6", "spatial_smoothing", {"window_size": 3}),
        ("r.R6", "feature_squeezing", {"bit_depth": 4}),
        (FIXTURE_R2, "spatial_smoothing", {}),                # fixture shape: bare ART class references
    ],
)
def test_verify_admission_accepts_the_defense_the_recommendation_names(
    verify_db: dict[str, Any], recommendation_id: str, defense_id: str, params: dict[str, Any],
) -> None:
    sessions = verify_db["sessions"]
    writer = _AuditWriter(sessions)

    handle = _admit(verify_db, writer, recommendation_id, defense_id, params)

    assert writer.events and writer.events[0]["action"] == "verify.replay"
    assert writer.events[0]["detail"]["recommendation_id"] == recommendation_id
    assert writer.events[0]["detail"]["defense"]["id"] == defense_id
    with sessions() as session:
        run = session.get(Run, handle.run_id)
        job = session.get(Job, handle.job_ids[0])
        finding = session.get(Finding, verify_db["finding_id"])
        row = session.execute(
            verify_db["campaigns"].select().where(verify_db["campaigns"].c.run_id == handle.run_id)
        ).mappings().one()
    assert run is not None and run.scanner == "ml.verify" and run.status == "queued"
    assert job is not None and job.type == "verify.replay" and job.celery_task_id == "celery-task-verify"
    assert job.detail["recommendation_id"] == recommendation_id
    assert job.detail["campaign_config"]["defense"]["id"] == defense_id
    assert row["kind"] == "verify" and row["baseline_run_id"] == verify_db["record"].run_id
    assert row["config"]["defense"]["id"] == defense_id
    for name, value in params.items():
        assert row["config"]["defense"]["params"][name] == value
    assert finding is not None and finding.status == "fixing"


@pytest.mark.integration
@pytest.mark.parametrize(
    ("recommendation_id", "defense_id"),
    [
        ("r.R7", "feature_squeezing"),   # names no defense at all
        ("r.R2", "feature_squeezing"),   # rule R2 is evaluation practice, no defense reference
        ("r.R1", "jpeg_compression"),    # names adversarial_training only
        (FIXTURE_R2, "jpeg_compression"),  # fixture shape names FeatureSqueezing and SpatialSmoothing only
    ],
)
def test_verify_admission_still_rejects_a_defense_the_recommendation_does_not_name(
    verify_db: dict[str, Any], recommendation_id: str, defense_id: str,
) -> None:
    sessions = verify_db["sessions"]
    writer = _AuditWriter(sessions)

    with pytest.raises(ValueError, match=r"^recommendation_defense_mismatch: ") as excinfo:
        _admit(verify_db, writer, recommendation_id, defense_id, {})

    assert recommendation_id in str(excinfo.value) and repr(defense_id) in str(excinfo.value)
    # The refusal is explicit and precedes the audit event, the Run/Job rows and the enqueue.
    assert writer.events == []
    with sessions() as session:
        assert session.query(Run).count() == 1          # only the baseline
        assert session.query(Job).count() == 0
        finding = session.get(Finding, verify_db["finding_id"])
    assert finding is not None and finding.status == "open"


@pytest.mark.integration
def test_a_matching_defense_is_not_confused_with_a_rejected_one(verify_db: dict[str, Any]) -> None:
    """An honest end-to-end pass: the mismatch is refused, then the matching defense is admitted."""
    sessions = verify_db["sessions"]
    writer = _AuditWriter(sessions)
    with pytest.raises(ValueError, match=r"^recommendation_defense_mismatch: "):
        _admit(verify_db, writer, "r.R1", "feature_squeezing", {})
    assert writer.events == []
    handle = _admit(verify_db, writer, "r.R6", "jpeg_compression", {})
    assert [e["action"] for e in writer.events] == ["verify.replay"]
    with sessions() as session:
        assert session.get(Run, handle.run_id) is not None
