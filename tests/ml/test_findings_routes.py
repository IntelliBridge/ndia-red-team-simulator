"""ML finding projection, dismissal, reviewer notes, report route and report re-render.

Register rows G-FIND1, G-FIND2, G-FIND3, G-REVNOTES, G-REP2 and G-REPRENDER against
spec 5.7, 5.8, 5.11, 6.4, 7.7, 14.8 and 17.1. Offline: a file-backed sqlite harness
(``ml_campaigns`` created by hand, as the migration owns it), an in-memory blob store
keyed by artifact location, an in-memory audit writer, and FastAPI dependency
overrides for the caller. ``ml_api`` is shared with ``test_compare.py`` and
``test_audit_verify_api.py``.
"""

from __future__ import annotations

import copy
import hashlib
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient
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
from sqlalchemy.orm import Session, sessionmaker

from redsim.api.app import create_app
from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.settings import APISettings
from redsim.audit.chain import InMemoryAuditWriter
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
from redsim.ml.schema import CampaignRecord, MLFindingDetail
from redsim.services.ml_findings import project_campaign_findings
from redsim.storage.blobs import BlobRef
from tests.conftest import patch_jsonb_for_sqlite

pytestmark = pytest.mark.integration

FIXTURE = Path(__file__).parent / "fixtures" / "run_record.json"
PROJECT = "project-1"
OTHER_PROJECT = "project-2"
BASELINE = "run-fixture-0001"
VERIFY = "run-verify-0001"
VERIFY_UNSCORED_DELTA = "run-verify-0002"
VERIFY_HASH_DRIFT = "run-verify-0003"
OTHER_MODEL = "run-other-model"
OTHER_SEED = "run-other-seed"
PARTIAL = "run-partial"
FOREIGN = "run-foreign"
PLAIN = "run-plain"
CREATOR = "user:creator"
SETTINGS_BASE = "f1x7ure000000000000000000000000000000000000000000000000000000000"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


class MemoryBlobStore:
    """Blob store keyed by location; ``put`` records the key as the location."""

    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}

    def put(self, key: str, content: bytes | str, *, content_type: str = "application/octet-stream") -> BlobRef:
        data = content.encode("utf-8") if isinstance(content, str) else content
        self.blobs[key] = data
        return BlobRef(sha256=_sha(data), location=key, size_bytes=len(data), content_type=content_type)

    def get(self, key: str) -> bytes:
        if key not in self.blobs:
            raise FileNotFoundError(key)
        return self.blobs[key]


class UserClient:
    """A ``TestClient`` view bound to one caller: the override reads the holder per request."""

    def __init__(self, client: TestClient, holder: dict[str, CurrentUser], user: CurrentUser) -> None:
        self._client, self._holder, self.user = client, holder, user

    def get(self, url: str, **kwargs: Any) -> Any:
        self._holder["user"] = self.user
        return self._client.get(url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> Any:
        self._holder["user"] = self.user
        return self._client.patch(url, **kwargs)


class RecordingAuditWriter(InMemoryAuditWriter):
    """In-memory writer with a hook so a test can look at the DB when a row is appended."""

    def __init__(self) -> None:
        super().__init__()
        self.on_append: Any = None

    def append(self, **event: Any) -> Any:
        if self.on_append is not None:
            self.on_append(event)
        return super().append(**event)

    def last(self, action: str) -> Any:
        return next(e for e in reversed(self.events) if e.action == action)


def _user(sub: str, role: str, project: str = PROJECT, *, system: bool = False) -> CurrentUser:
    return CurrentUser(sub=sub, email=f"{sub}@example.test", project_memberships={project: role},
                       is_system=system)


def _delta_block(baseline_run_id: str) -> dict[str, Any]:
    return {
        "baseline_run_id": baseline_run_id, "mri_before": 42, "mri_after": 55, "delta": 13,
        "delta_subscores": {"S_acc": 10.0, "S_asr": 20.0, "S_eps": 5.0, "S_conf": 0.0, "S_expl": 1.0},
        "delta_acc_clean": {"before": {"n": 200, "n_correct": 172, "accuracy": 0.86},
                            "after": {"n": 200, "n_correct": 170, "accuracy": 0.85}, "delta": -0.01},
        "delta_families": [{"measurement_id": "m.evasion.fgsm.eps0.03",
                            "before": {"n": 200, "n_correct": 112, "accuracy": 0.56},
                            "after": {"n": 200, "n_correct": 150, "accuracy": 0.75}, "delta": 0.19}],
    }


def _variants(base: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Campaign records derived from the frozen fixture, one per comparison case."""
    defense = {"id": "feature_squeezing", "art_class": "art.defences.preprocessor.FeatureSqueezing",
               "params": {"bit_depth": 4}}

    def verify(run_id: str) -> dict[str, Any]:
        rec = copy.deepcopy(base)
        rec.update({"run_id": run_id, "kind": "verify", "baseline_run_id": BASELINE})
        rec["provenance"]["baseline_run_id"] = BASELINE
        rec["config"]["defense"] = defense
        return rec

    with_delta = verify(VERIFY)
    with_delta["score"].update({"mri": 55, "grade": "D", "delta": _delta_block(BASELINE)})
    no_delta = verify(VERIFY_UNSCORED_DELTA)
    drift = verify(VERIFY_HASH_DRIFT)
    drift["score"]["settings_hash"] = "d" * 64

    other_model = copy.deepcopy(base)
    other_model.update({"run_id": OTHER_MODEL, "settings_hash": "c" * 64})
    other_model["provenance"].update({"model_sha256": "e1" * 32, "settings_hash": "c" * 64})
    other_model["config"]["target_id"] = "tgt-other"
    other_model["score"]["settings_hash"] = "c" * 64

    other_seed = copy.deepcopy(base)
    other_seed.update({"run_id": OTHER_SEED, "settings_hash": "b" * 64})
    other_seed["config"].update({"seed": 7, "n_samples": 100})
    other_seed["provenance"].update({"sample_indices_sha256": "7b" * 32, "settings_hash": "b" * 64})

    partial = copy.deepcopy(base)
    partial.update({"run_id": PARTIAL, "completeness": "partial",
                    "missing": ["S_expl unavailable (explainer failed)"]})
    partial["score"].update({"mri": None, "grade": None, "completeness": "partial",
                             "missing": ["S_expl unavailable (explainer failed)"]})
    partial["score"]["subscores"]["S_expl"] = None

    foreign = copy.deepcopy(base)
    foreign["run_id"] = FOREIGN
    return {BASELINE: base, VERIFY: with_delta, VERIFY_UNSCORED_DELTA: no_delta, VERIFY_HASH_DRIFT: drift,
            OTHER_MODEL: other_model, OTHER_SEED: other_seed, PARTIAL: partial, FOREIGN: foreign}


@pytest.fixture
def ml_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A dev-mode app over sqlite with eight seeded campaigns and an in-memory audit writer."""
    patch_jsonb_for_sqlite()
    engine = create_engine(f"sqlite:///{tmp_path / 'ml_api.db'}")
    Base.metadata.create_all(engine)
    campaigns = _campaign_table(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    @contextmanager
    def get_session() -> Any:
        with sessions.begin() as session:
            yield session

    store = MemoryBlobStore()
    base = json.loads(FIXTURE.read_text())
    records = {run_id: CampaignRecord.model_validate(rec) for run_id, rec in _variants(base).items()}
    with get_session() as session:
        session.add(Organization(id="org-1", name="Org", slug="org"))
        session.flush()
        session.add_all([Project(id=PROJECT, org_id="org-1", name="P1", slug="p1"),
                         Project(id=OTHER_PROJECT, org_id="org-1", name="P2", slug="p2")])
        session.flush()
        target_id = records[BASELINE].config.target_id
        session.add_all([
            Target(id=target_id, project_id=PROJECT, kind="ml_model_artifact", value="bundled:tiny",
                   verified=True, detail={"modality": "image", "status": "available"}),
            Target(id="tgt-other", project_id=PROJECT, kind="ml_model_artifact", value="bundled:tiny-2",
                   verified=True, detail={"modality": "image", "status": "available"}),
        ])
        session.flush()
        for run_id, record in records.items():
            project = OTHER_PROJECT if run_id == FOREIGN else PROJECT
            raw = record.model_dump_json().encode()
            location = f"memory://{project}/{run_id}/run_record.json/{_sha(raw)}"
            store.blobs[location] = raw
            session.add(Run(id=run_id, project_id=project, target_id=record.config.target_id, mode="api",
                            scanner="ml.verify" if record.kind == "verify" else "ml.campaign",
                            status="succeeded", created_by=CREATOR, stage_table={}))
            session.flush()
            session.add(Artifact(id=f"artifact-{run_id}-record", run_id=run_id, project_id=project,
                                 kind="ml.run_record", sha256=_sha(raw), location=location,
                                 content_type="application/json", size_bytes=len(raw)))
            session.execute(campaigns.insert().values(
                run_id=run_id, project_id=project, target_id=record.config.target_id, kind=record.kind,
                modality="image", config=record.config.model_dump(mode="json"),
                settings_hash=record.settings_hash,
                provenance=record.provenance.model_dump(mode="json") if record.provenance else None,
                score=record.score.model_dump(mode="json") if record.score else None,
                limitations=list(record.limitations), baseline_run_id=record.baseline_run_id,
            ))
        # A run that is not a campaign at all.
        session.add(Run(id=PLAIN, project_id=PROJECT, mode="api", status="succeeded", stage_table={}))

    writer = RecordingAuditWriter()
    monkeypatch.setattr("redsim.db.session.get_session", get_session)
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: store)
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _cfg: writer)
    monkeypatch.setattr("redsim.api.v1.ml_findings.resolve_writer", lambda _cfg: writer)

    app = create_app(APISettings(env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"]))
    holder: dict[str, CurrentUser] = {"user": _user("viewer", "viewer")}
    app.dependency_overrides[get_current_user] = lambda: holder["user"]
    client = TestClient(app)

    def as_user(user: CurrentUser) -> UserClient:
        return UserClient(client, holder, user)

    return {"client": client, "as_user": as_user, "sessions": sessions, "get_session": get_session,
            "campaigns": campaigns, "records": records, "store": store, "writer": writer,
            "tmp_path": tmp_path}


def _seed_campaign_artifacts(api: dict[str, Any]) -> dict[str, str]:
    """Curve and campaign SHAP artifact rows the worker sink would have written."""
    files = {
        "curve-fgsm": ("ml.curve", "curve/fgsm.json"),
        "curve-pgd": ("ml.curve", "curve/pgd.json"),
        "curve-png": ("ml.curve", "curve/robustness_curve.png"),
        "shap-summary": ("ml.shap_summary", "shap_summary.txt"),
    }
    with api["get_session"]() as session:
        for artifact_id, (kind, name) in files.items():
            data = artifact_id.encode()
            session.add(Artifact(id=artifact_id, run_id=BASELINE, project_id=PROJECT, kind=kind, sha256=_sha(data),
                                 location=f"memory://{PROJECT}/{BASELINE}/{name}/{_sha(data)}",
                                 content_type="application/octet-stream", size_bytes=len(data)))
    return {artifact_id: name for artifact_id, (_kind, name) in files.items()}


def _project(api: dict[str, Any]) -> dict[str, str]:
    """Project the baseline's findings; returns ``attack_id -> Finding.id``."""
    with api["get_session"]() as session:
        ids = project_campaign_findings(session, api["records"][BASELINE])
        return {session.get(Finding, fid).schema_blob["ml"]["attack_id"]: fid for fid in ids}


def _set_status(api: dict[str, Any], finding_id: str, status: str) -> None:
    with api["get_session"]() as session:
        session.get(Finding, finding_id).status = status


def test_finding_fields_and_dismissal_matrix(ml_api: dict[str, Any]) -> None:
    _seed_campaign_artifacts(ml_api)
    findings = _project(ml_api)
    assert set(findings) == {"fgsm", "pgd"}
    record = ml_api["records"][BASELINE]
    client = ml_api["as_user"](_user("reader", "viewer"))

    # --- spec 5.7 projection (G-FIND1) ---------------------------------------------------
    fgsm = client.get(f"/v1/findings/{findings['fgsm']}").json()
    blob = fgsm["schema_blob"]
    assert blob["finding_type"] == "adversarial_ml"
    assert blob["id"] == "ml.fgsm" and blob["source_tool"] == "redsim.ml/fgsm"
    assert blob["source_run_id"] == BASELINE and blob["status"] == "open"
    assert blob["title"] == "FGSM flips predictions at ε=0.03 (linf; ASR 64/172)"
    assert blob["affected_component"] == record.config.target_id
    assert blob["target"] == "bundled:tiny"
    assert blob["references"] == ["Goodfellow et al. 2015, arXiv:1412.6572"]
    assert blob["artifact_path"] == f"artifact-{BASELINE}-record"
    assert blob["remediation_steps"].startswith("CANDIDATE (not evaluated): ")
    assert "Measured:" in blob["description"] and "LLM" not in blob["description"]
    for cited in ("[m.evasion.fgsm.eps0.03]", "[m.clean]", "[m.control.noise.eps0.03]"):
        assert cited in blob["description"]
    evidence = json.loads(blob["evidence"])
    assert set(evidence) == {"measurements", "observations", "interpretation"}
    assert "m.clean" in evidence["measurements"] and "m.evasion.fgsm.eps0.03" in evidence["measurements"]
    assert not any(m.startswith("m.evasion.pgd") for m in evidence["measurements"])
    assert blob["cvss"] is None and blob["cve"] is None and blob["endpoint"] is None

    # --- MLFindingDetail read back through the frozen schema (G-FIND2) -------------------
    detail = MLFindingDetail.model_validate(blob["ml"])
    families = {m.family for m in detail.measurements}
    assert families == {"clean", "evasion", "control"}
    assert {m.attack_id for m in detail.measurements if m.family == "evasion"} == {"fgsm"}
    assert len([m for m in detail.measurements if m.family == "control"]) == 3
    assert detail.first_success_eps == 0.03 and detail.threshold == 0.2
    # Bare ``o.NNN`` observations belong to the first explained attack (fgsm); pgd has none.
    assert [o.id for o in detail.observations] == ["o.000", "o.001", "o.002", "o.003"]
    assert {i.id for i in detail.interpretation} == {"i.3", "i.4"}
    assert {r.id for r in detail.recommendations} == {"r.R2", "r.R3"}
    assert detail.artifacts["robustness_curve.json"] == "curve-fgsm"
    assert detail.artifacts["robustness_curve.png"] == "curve-png"
    assert detail.artifacts["shap_summary.txt"] == "shap-summary"
    assert "curve-pgd" not in detail.artifacts.values()
    assert detail.artifacts["input_clean"] == "art-o.000-clean"
    assert detail.review.state == "unreviewed"

    pgd = MLFindingDetail.model_validate(client.get(f"/v1/findings/{findings['pgd']}").json()["schema_blob"]["ml"])
    assert pgd.observations == []
    assert {i.id for i in pgd.interpretation} == {"i.1", "i.3", "i.5"}
    assert {r.id for r in pgd.recommendations} == {"r.R1", "r.R2"}
    assert pgd.artifacts["robustness_curve.json"] == "curve-pgd"
    pgd_blob = client.get(f"/v1/findings/{findings['pgd']}").json()["schema_blob"]
    assert pgd_blob["title"] == "PGD flips predictions at ε=0.01 (linf; ASR 36/172)"

    # Projection is idempotent: replaying the record adds nothing.
    assert _project(ml_api) == findings

    # --- dismissal matrix (G-FIND3) ------------------------------------------------------
    writer: RecordingAuditWriter = ml_api["writer"]
    body = {"status": "false_positive", "expected_status": "open", "reason": "measured on a fixture slice"}
    path = f"/v1/findings/{findings['fgsm']}/status"

    assert ml_api["as_user"](_user("reader", "viewer")).patch(path, json=body).status_code == 403
    assert not [e for e in writer.events if e.action == "finding.review"]

    creator = ml_api["as_user"](_user("creator", "approver")).patch(path, json=body)
    assert creator.status_code == 403 and "creator" in creator.json()["detail"]
    refused = writer.last("finding.review")
    assert refused.success is False and refused.detail["refusal"] == "forbidden"
    assert refused.detail["campaign_creator"] == CREATOR and refused.detail["reviewer"] == CREATOR

    system = ml_api["as_user"](_user("worker", "admin", system=True)).patch(path, json=body)
    assert system.status_code == 403 and writer.last("finding.review").success is False

    reviewer = ml_api["as_user"](_user("reviewer", "approver"))
    stale = reviewer.patch(path, json={**body, "expected_status": "fixing"})
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "run_terminal" and stale.json()["detail"]["status"] == "open"
    assert writer.last("finding.review").success is False
    assert writer.last("finding.review").detail["refusal"] == "run_terminal"

    assert reviewer.patch(path, json={**body, "reason": ""}).status_code == 422
    assert reviewer.patch(path, json={**body, "status": "fixed"}).status_code == 422

    def _row_unchanged(event: dict[str, Any]) -> None:
        if event["action"] == "finding.review" and event["success"]:
            with ml_api["sessions"]() as session:
                assert session.get(Finding, findings["fgsm"]).status == "open"

    writer.on_append = _row_unchanged
    ok = reviewer.patch(path, json=body)
    writer.on_append = None
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "false_positive" and ok.json()["from_status"] == "open"
    assert ok.json()["review"]["reviewer"] == "user:reviewer"
    event = writer.last("finding.review")
    assert event.success is True and event.run_id == BASELINE and event.project_id == PROJECT
    assert event.detail["from_status"] == "open" and event.detail["to_status"] == "false_positive"
    assert event.detail["reason"] == body["reason"] and event.detail["reviewer"] == "user:reviewer"
    assert event.detail["campaign_creator"] == CREATOR and event.detail["finding_id"] == findings["fgsm"]
    after = client.get(f"/v1/findings/{findings['fgsm']}").json()
    assert after["status"] == "false_positive" and after["schema_blob"]["status"] == "false_positive"
    review = MLFindingDetail.model_validate(after["schema_blob"]["ml"]).review
    assert review.state == "dismissed" and review.reviewer == "user:reviewer" and review.reason == body["reason"]

    # false_positive is terminal in Phase A.
    terminal = reviewer.patch(path, json={**body, "expected_status": "false_positive"})
    assert terminal.status_code == 409 and terminal.json()["detail"]["code"] == "run_terminal"
    assert terminal.json()["detail"]["allowed_from"] == ["failed", "open"]

    # Only open | failed may be dismissed: fixing is refused, failed is accepted.
    pgd_path = f"/v1/findings/{findings['pgd']}/status"
    _set_status(ml_api, findings["pgd"], "fixing")
    fixing = reviewer.patch(pgd_path, json={**body, "expected_status": "fixing"})
    assert fixing.status_code == 409 and fixing.json()["detail"]["code"] == "run_terminal"
    _set_status(ml_api, findings["pgd"], "failed")
    failed = reviewer.patch(pgd_path, json={**body, "expected_status": "failed"})
    assert failed.status_code == 200 and failed.json()["status"] == "false_positive"
    assert writer.last("finding.review").detail["from_status"] == "failed"
    assert reviewer.patch("/v1/findings/nope/status", json=body).status_code == 404


def test_reviewer_notes_roundtrip_and_audit(ml_api: dict[str, Any]) -> None:
    writer: RecordingAuditWriter = ml_api["writer"]
    notes = "Reviewed the fgsm gallery; the flipped samples are all low-contrast. <b>not html</b>"
    body = {"reviewer_notes": notes}

    # Gate before lookup: a viewer is refused on a campaign and on a plain run alike.
    viewer = ml_api["as_user"](_user("reader", "viewer"))
    assert viewer.patch(f"/v1/runs/{BASELINE}/reviewer-notes", json=body).status_code == 403
    assert viewer.patch(f"/v1/runs/{PLAIN}/reviewer-notes", json=body).status_code == 403
    assert not [e for e in writer.events if e.action == "finding.annotate"]

    remediator = ml_api["as_user"](_user("annotator", "remediator"))
    assert remediator.patch("/v1/runs/missing/reviewer-notes", json=body).status_code == 404
    plain = remediator.patch(f"/v1/runs/{PLAIN}/reviewer-notes", json=body)
    assert plain.status_code == 404 and plain.json()["detail"]["code"] == "campaign_not_found"
    assert remediator.patch(f"/v1/runs/{BASELINE}/reviewer-notes", json={"reviewer_notes": 7}).status_code == 422
    too_long = remediator.patch(f"/v1/runs/{BASELINE}/reviewer-notes", json={"reviewer_notes": "x" * 8193})
    assert too_long.status_code == 422 and too_long.json()["detail"]["code"] == "reviewer_notes_too_long"
    assert not [e for e in writer.events if e.action == "finding.annotate"]

    def _not_written_yet(event: dict[str, Any]) -> None:
        if event["action"] == "finding.annotate":
            with ml_api["sessions"]() as session:
                table = ml_api["campaigns"]
                row = session.execute(table.select().where(table.c.run_id == BASELINE)).mappings().one()
                assert row["reviewer_notes"] is None

    writer.on_append = _not_written_yet
    ok = remediator.patch(f"/v1/runs/{BASELINE}/reviewer-notes", json=body)
    writer.on_append = None
    assert ok.status_code == 200 and ok.json() == {"run_id": BASELINE, "reviewer_notes": notes}

    event = writer.last("finding.annotate")
    assert event.run_id == BASELINE and event.project_id == PROJECT and event.success is True
    encoded = notes.encode("utf-8")
    assert event.detail["sha256"] == _sha(encoded) and event.detail["byte_length"] == len(encoded)
    assert event.detail["length"] == len(notes) and event.detail["author"] == "annotator"
    assert event.detail["run_id"] == BASELINE
    assert "low-contrast" not in json.dumps(event.detail)

    campaign = ml_api["as_user"](_user("reader", "viewer")).get(f"/v1/runs/{BASELINE}/campaign")
    assert campaign.status_code == 200 and campaign.json()["reviewer_notes"] == notes
    # The immutable record is untouched: the overlay comes from ml_campaigns.
    assert json.loads(ml_api["store"].blobs[
        f"memory://{PROJECT}/{BASELINE}/run_record.json/{_sha(ml_api['records'][BASELINE].model_dump_json().encode())}"
    ])["reviewer_notes"] is None

    again = remediator.patch(f"/v1/runs/{BASELINE}/reviewer-notes", json={"reviewer_notes": "second pass"})
    assert again.status_code == 200
    assert ml_api["as_user"](_user("reader", "viewer")).get(
        f"/v1/runs/{BASELINE}/campaign").json()["reviewer_notes"] == "second pass"
    assert len([e for e in writer.events if e.action == "finding.annotate"]) == 2


def _seed_report(api: dict[str, Any], kind: str, data: bytes, *, created_at: datetime,
                 artifact_id: str) -> None:
    location = f"memory://{PROJECT}/{BASELINE}/{kind}/{_sha(data)}"
    api["store"].blobs[location] = data
    with api["get_session"]() as session:
        session.add(Artifact(id=artifact_id, run_id=BASELINE, project_id=PROJECT, kind=kind, sha256=_sha(data),
                             location=location, content_type="text/plain", size_bytes=len(data),
                             created_at=created_at))


def test_report_route_serves_newest_artifact_and_pdf_is_404_until_rendered(ml_api: dict[str, Any]) -> None:
    now = datetime.now(UTC)
    _seed_report(ml_api, "ml.report_md", b"# old report\n", created_at=now - timedelta(hours=1),
                 artifact_id="report-md-old")
    _seed_report(ml_api, "ml.report_md", b"# new report\n", created_at=now, artifact_id="report-md-new")
    _seed_report(ml_api, "ml.report_html", b"<!doctype html><html><body>report</body></html>", created_at=now,
                 artifact_id="report-html")
    _seed_report(ml_api, "report.json", b'{"run_id": "run-fixture-0001"}\n', created_at=now,
                 artifact_id="report-json")

    scanner = ml_api["as_user"](_user("exporter", "scanner"))
    md = scanner.get(f"/v1/runs/{BASELINE}/report.md")
    assert md.status_code == 200 and md.content == b"# new report\n"
    assert md.headers["x-content-type-options"] == "nosniff"
    assert md.headers["content-disposition"].startswith("attachment")
    assert f"redsim-{BASELINE}-report.md" in md.headers["content-disposition"]
    assert md.headers["etag"] == f'"{_sha(b"# new report\n")}"'

    html = scanner.get(f"/v1/runs/{BASELINE}/report.html")
    assert html.status_code == 200 and html.content.startswith(b"<!doctype html>")
    assert html.headers["content-security-policy"].startswith("default-src 'none'")
    assert html.headers["x-content-type-options"] == "nosniff"
    assert html.headers["content-disposition"] == "inline"
    assert html.headers["x-frame-options"] == "DENY"

    as_json = scanner.get(f"/v1/runs/{BASELINE}/report.json")
    assert as_json.status_code == 200 and as_json.json()["run_id"] == BASELINE

    # Phase B: report.pdf is a rendered artifact; with none rendered it is 404, never a filesystem fallback.
    pdf = scanner.get(f"/v1/runs/{BASELINE}/report.pdf")
    assert pdf.status_code == 404, pdf.text
    assert pdf.json()["detail"] == "report not yet rendered"

    assert scanner.get(f"/v1/runs/{BASELINE}/report.txt").status_code == 400
    assert scanner.get("/v1/runs/missing/report.md").status_code == 404
    # REPORT_EXPORT is a scanner-tier gate; a viewer member is refused, PDF included.
    viewer = ml_api["as_user"](_user("reader", "viewer"))
    assert viewer.get(f"/v1/runs/{BASELINE}/report.md").status_code == 403
    assert viewer.get(f"/v1/runs/{BASELINE}/report.pdf").status_code == 403
    # No membership on the run's project: refused before any format decision.
    outsider = ml_api["as_user"](_user("outsider", "admin", project=OTHER_PROJECT))
    assert outsider.get(f"/v1/runs/{BASELINE}/report.pdf").status_code == 403

    # A blob that no longer matches its recorded digest is never served.
    ml_api["store"].blobs[f"memory://{PROJECT}/{BASELINE}/ml.report_md/{_sha(b'# new report\n')}"] = b"tampered"
    tampered = scanner.get(f"/v1/runs/{BASELINE}/report.md")
    assert tampered.status_code == 409
    assert tampered.json()["detail"]["code"] == "report_artifact_digest_mismatch"


def test_ml_report_render_rerenders_from_run_record(ml_api: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("celery")
    from redsim.state import PostgresRunState
    from redsim.workers.tasks.report import report_render

    findings = _project(ml_api)
    _set_status(ml_api, findings["pgd"], "failed")
    with ml_api["get_session"]() as session:
        session.get(Finding, findings["pgd"]).validation_state = "poc_failed"
        table = ml_api["campaigns"]
        session.execute(table.update().where(table.c.run_id == BASELINE).values(
            reviewer_notes="Notes added after the run finished."))
        session.add(Job(id="job-report-1", run_id=BASELINE, project_id=PROJECT, type="report.render",
                        status="queued", created_by="user:reviewer", detail={}))

    writer: RecordingAuditWriter = ml_api["writer"]
    store: MemoryBlobStore = ml_api["store"]
    sessions: sessionmaker[Session] = ml_api["sessions"]

    def _no_report_rows_yet(event: dict[str, Any]) -> None:
        if event["action"] == "report.render":
            with sessions() as check:
                rows = check.query(Artifact).filter(Artifact.run_id == BASELINE,
                                                    Artifact.kind.like("ml.report_%")).count()
                assert rows == 0

    writer.on_append = _no_report_rows_yet

    @contextmanager
    def fake_task_context(job_id: str, task: Any = None) -> Any:
        from redsim.workers.bootstrap import TaskContext

        with sessions.begin() as session:
            run_state = PostgresRunState(session, run_id=BASELINE, project_id=PROJECT,
                                         output_dir=ml_api["tmp_path"], blob_store=store)
            yield TaskContext(job_id=job_id, run_id=BASELINE, project_id=PROJECT, session=session,
                              blob_store=store, run_state=run_state, audit_writer=writer, actor="user:reviewer")

    monkeypatch.setattr("redsim.workers.bootstrap.task_context", fake_task_context)
    result = report_render.apply(args=["job-report-1"]).get()
    writer.on_append = None

    assert result["source"] == "ml.run_record" and result["formats"] == ["md", "json", "html", "pdf"]
    assert result["record_sha256"] == _sha(ml_api["records"][BASELINE].model_dump_json().encode())
    assert result["reviewer_notes_present"] is True
    assert result["finding_states"]["ml.pgd"]["validation_state"] == "poc_failed"
    assert result["finding_states"]["ml.pgd"]["status"] == "failed"
    assert result["markdown_path"] and result["json_path"] and result["html_path"]

    with sessions() as session:
        rows = {row.kind: row for row in session.query(Artifact).filter(
            Artifact.run_id == BASELINE, Artifact.kind.like("ml.report_%")).all()}
    assert set(rows) == {"ml.report_md", "ml.report_json", "ml.report_html", "ml.report_pdf"}
    markdown = store.get(rows["ml.report_md"].location).decode()
    assert "### Reviewer notes" in markdown and "Notes added after the run finished." in markdown
    assert rows["ml.report_md"].sha256 == _sha(markdown.encode()) == result["artifacts"]["md"]["sha256"]
    rendered = json.loads(store.get(rows["ml.report_json"].location))
    assert rendered["run_id"] == BASELINE and rendered["reviewer_notes"] == "Notes added after the run finished."
    assert rendered["score"]["mri"] == 42

    event = writer.last("report.render")
    assert event.run_id == BASELINE and event.project_id == PROJECT and event.success is True
    assert event.detail["formats"] == ["md", "json", "html", "pdf"] and event.detail["source"] == "ml.run_record"
    assert event.detail["finding_states"] == {"ml.fgsm": "unvalidated", "ml.pgd": "poc_failed"}
    assert event.detail["reviewer_notes_sha256"] == _sha(b"Notes added after the run finished.")
    assert "Notes added" not in json.dumps(event.detail)

    # The route now serves what the task wrote.
    served = ml_api["as_user"](_user("exporter", "scanner")).get(f"/v1/runs/{BASELINE}/report.md")
    assert served.status_code == 200 and served.text == markdown
