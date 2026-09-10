"""``POST /v1/models/{id}/attacks`` admission (register G-API-ATTACKS, G-ATK6, G-API-RERUN refusals).

Offline: a file-backed sqlite harness (the admission service reflects
``ml_campaigns`` through the engine mid-transaction, which the shared
in-memory connection cannot host), the real FastAPI app in dev auth with the
user dependency overridden, a recording in-memory audit writer, and
``ml_campaign_run.delay`` replaced by a fake. The harness helpers here are
shared by ``tests/ml/test_admission.py`` and ``tests/ml/test_cancel_terminal.py``.

Pinned here:

* every refusal carries a spec 17.3 code with its table status, writes exactly
  one ``attack.run`` ``success=False`` audit row (ids only, never the body) and
  leaves no ``Run`` / ``Job`` / ``ml_campaigns`` row or enqueue behind;
* the spec 12.3 defaults (norm, ε grid per norm, reference budget, the model's
  bound dataset) are filled at admission and a grid beyond
  ``DEFAULT_MAX_EPS_GRID_MEMBERS`` is refused;
* a missing target status is "not available" (``409 model_load_refused`` with
  ``refusal_reason``), endpoint targets are ``501 not_implemented`` with a
  phase, and an enqueue failure rolls the rows back into ``503 queue_unavailable``.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient
from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, Text, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import HTTP_STATUS
from redsim.audit.chain import InMemoryAuditWriter
from redsim.db.models import Base, Job, Organization, Project, Run, Target
from redsim.ml.scoring import (
    DEFAULT_EPS_GRID_L2,
    DEFAULT_EPS_GRID_LINF,
    DEFAULT_MAX_EPS_GRID_MEMBERS,
    DEFAULT_REFERENCE_EPS,
)
from tests.conftest import patch_jsonb_for_sqlite

pytestmark = pytest.mark.integration

ORG = "org-1"
PROJECT = "project-1"
MODEL = "model-image-1"
DATASET = "fixture/synthetic-shapes"
DATASET_REVISION = "rev-1"
SHA256 = "ab" * 32
ACTOR = "user:dev:admin@test"
CELERY_TASK_ID = "celery-task-routes"


# --------------------------------------------------------------------------- harness

def campaign_table(engine: Engine) -> Table:
    """The migration-owned ``ml_campaigns`` shape (0010_ml_vertical) on sqlite."""
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
        Column("batch_id", String),
        Column("reviewer_notes", Text),
        Column("created_at", DateTime),
        Column("completed_at", DateTime),
    )
    table.create(engine)
    return table


class RecordingAuditWriter(InMemoryAuditWriter):
    """In-memory writer that records, per row, whether the audited run already existed.

    ``run_existed_at_append[i]`` is ``False`` when row ``i`` named a run that did
    not exist yet (the spec 10.5 order: audit before rows) and ``None`` for rows
    without a run id (refusals sit on the project chain).
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        super().__init__()
        self.session_factory = session_factory
        self.run_existed_at_append: list[bool | None] = []

    def append(self, **event: Any) -> Any:
        run_id = event.get("run_id")
        existed: bool | None = None
        if run_id is not None:
            with self.session_factory() as session:
                existed = session.get(Run, run_id) is not None
        self.run_existed_at_append.append(existed)
        return super().append(**event)


@dataclass
class Harness:
    engine: Engine
    Session: sessionmaker[Session]
    campaigns: Table
    writer: RecordingAuditWriter
    delay_calls: list[str]
    client: TestClient | None = None
    user: CurrentUser | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def events(self, action: str) -> list[Any]:
        return [event for event in self.writer.events if event.action == action]

    def counts(self) -> dict[str, int]:
        with self.Session() as session:
            return {
                "runs": session.query(Run).count(),
                "jobs": session.query(Job).count(),
                "campaigns": len(session.execute(self.campaigns.select()).all()),
            }

    def campaign_row(self, run_id: str) -> Any:
        with self.Session() as session:
            return session.execute(
                self.campaigns.select().where(self.campaigns.c.run_id == run_id)
            ).mappings().one_or_none()


def build_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, with_api: bool = True) -> Harness:
    """Seed one org / project, patch the session, audit writer and Celery seams, optionally mount the app."""
    patch_jsonb_for_sqlite()
    engine = create_engine(f"sqlite:///{tmp_path / 'campaign_routes.db'}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    campaigns = campaign_table(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    @contextmanager
    def session_cm() -> Iterator[Session]:
        with session_factory.begin() as session:
            yield session

    with session_factory.begin() as session:
        session.add(Organization(id=ORG, name="Routes organization", slug="routes-organization"))
        session.flush()
        session.add(Project(id=PROJECT, org_id=ORG, name="Routes project", slug="routes-project"))

    monkeypatch.setattr("redsim.db.session.get_session", session_cm)
    writer = RecordingAuditWriter(session_factory)
    for target in ("redsim.audit.chain.resolve_writer", "redsim.api.v1.attacks.resolve_writer",
                   "redsim.api.v1.runs_cancel.resolve_writer"):
        monkeypatch.setattr(target, lambda _config, _writer=writer: _writer)
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.delenv("REDSIM_TEST_AUDIT", raising=False)

    delay_calls: list[str] = []

    class _Task:
        id = CELERY_TASK_ID

    def fake_delay(job_id: str) -> _Task:
        delay_calls.append(job_id)
        return _Task()

    monkeypatch.setattr("redsim.workers.tasks.ml_campaign.ml_campaign_run.delay", fake_delay)

    harness = Harness(engine=engine, Session=session_factory, campaigns=campaigns, writer=writer,
                      delay_calls=delay_calls)
    if with_api:
        from redsim.api.app import create_app
        from redsim.api.settings import APISettings

        app = create_app(APISettings(
            env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
            rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000,
        ))
        user = CurrentUser(sub="dev:admin@test", email="admin@test", project_memberships={PROJECT: "admin"})
        app.dependency_overrides[get_current_user] = lambda: user
        harness.client = TestClient(app)
        harness.user = user
    return harness


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Harness]:
    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    yield build_harness(tmp_path, monkeypatch, with_api=True)
    rl._BUCKETS.clear()


def seed_model(
    harness: Harness,
    model_id: str = MODEL,
    *,
    kind: str = "ml_model_artifact",
    status: str | None = "available",
    modality: str = "image",
    gradients: bool | None = True,
    refusal_reason: str | None = None,
    dataset_id: str | None = DATASET,
) -> str:
    """A registered model target whose ``detail`` carries the manifest copy the API reads."""
    manifest: dict[str, Any] = {"sha256": SHA256, "modality": modality, "name": "seeded model",
                                "format": "onnx", "dataset_revision": DATASET_REVISION}
    if dataset_id is not None:
        manifest["dataset_id"] = dataset_id
    if gradients is not None:
        manifest["gradients"] = gradients
    if status is not None:
        manifest["status"] = status
    if refusal_reason is not None:
        manifest["refusal_reason"] = refusal_reason
    detail = {**manifest, "source": "upload", "manifest": dict(manifest)}
    with harness.Session.begin() as session:
        session.add(Target(id=model_id, project_id=PROJECT, kind=kind, value=f"memory://{model_id}",
                           verified=True, detail=detail))
    return model_id


def parent_config(**overrides: Any) -> dict[str, Any]:
    """A frozen attack-campaign configuration in the ``ml_campaigns.config`` shape.

    ``attack_params`` carry caller overrides only (``eps`` / ``norm_l2`` are the
    runner's, supplied from the grid), the way admission freezes them, so a copy
    made by a rerun is exactly equal to the parent's.
    """
    from redsim.ml.schema import CampaignConfig

    base: dict[str, Any] = {
        "target_id": MODEL, "modality": "image", "attack_ids": ["fgsm", "pgd"],
        "attack_params": {"fgsm": {}, "pgd": {"max_iter": 5, "eps_step_ratio": 0.5}},
        "norm": "linf", "eps_grid": list(DEFAULT_EPS_GRID_LINF), "reference_eps": DEFAULT_REFERENCE_EPS,
        "n_samples": 50, "seed": 7, "explain_k": 4, "dataset_id": DATASET, "dataset_revision": DATASET_REVISION,
        "target_snapshot": {"id": MODEL, "kind": "ml_model_artifact"},
    }
    base.update(overrides)
    return CampaignConfig.model_validate(base).model_dump(mode="json")


def seed_campaign_run(
    harness: Harness, run_id: str, *, status: str, config: dict[str, Any] | None = None,
    kind: str = "attack", target_id: str = MODEL, scanner: str = "ml.campaign",
) -> str:
    """A campaign ``Run`` plus its ``ml_campaigns`` row (the shape a finished admission leaves)."""
    config = config or parent_config(target_id=target_id)
    with harness.Session.begin() as session:
        session.add(Run(id=run_id, project_id=PROJECT, target_id=target_id, mode="api", status=status,
                        scanner=scanner, created_by=ACTOR,
                        stage_table={"stage": "attack", "stages_done": ["load_target"], "jobs": {}}))
        session.flush()
        session.execute(harness.campaigns.insert().values(
            run_id=run_id, project_id=PROJECT, target_id=target_id, kind=kind,
            modality=config["modality"], config=config, settings_hash="0" * 64, limitations=[],
        ))
    return run_id


def launch(harness: Harness, body: dict[str, Any], model_id: str = MODEL) -> Any:
    assert harness.client is not None
    return harness.client.post(f"/v1/models/{model_id}/attacks", json=body)


def assert_refused(harness: Harness, response: Any, code: str, *, audit_rows: int = 1,
                   before: dict[str, int] | None = None) -> dict[str, Any]:
    """The 17.3 envelope, the table status, one failed ``attack.run`` row (ids only) and no new rows.

    ``before`` is the row count the test seeded (a rerun parent, say); by default nothing existed.
    """
    assert response.status_code == HTTP_STATUS[code], response.text
    detail = response.json()["detail"]
    assert detail["code"] == code
    assert detail["message"]
    assert harness.counts() == (before or {"runs": 0, "jobs": 0, "campaigns": 0})
    assert harness.delay_calls == []
    refused = [event for event in harness.events("attack.run") if not event.success]
    assert len(refused) == audit_rows, [event.detail for event in harness.writer.events]
    row = refused[-1]
    assert row.allowlist_check == "n/a" and row.project_id == PROJECT and row.run_id is None
    assert row.detail["code"] == code and row.detail["refused"] is True
    assert row.detail["http_status"] == HTTP_STATUS[code]
    assert "config" not in row.detail and "body" not in row.detail, "refusals carry ids, not the request"
    return dict(detail)


# --------------------------------------------------------------------------- admission

def test_start_campaign_fills_spec_defaults_and_audits_before_rows(api: Harness) -> None:
    seed_model(api)

    response = launch(api, {"attack_ids": ["fgsm"]})

    assert response.status_code == 202, response.text
    body = response.json()
    run_id, (job_id,) = body["run_id"], body["job_ids"]
    assert body["status_url"] == f"/v1/runs/{run_id}"
    with api.Session() as session:
        run = session.get(Run, run_id)
        job = session.get(Job, job_id)
    assert run is not None and run.scanner == "ml.campaign" and run.status == "queued"
    assert run.target_id == MODEL and run.created_by == ACTOR
    assert job is not None and job.type == "attack.run" and job.status == "queued"
    assert job.celery_task_id == CELERY_TASK_ID and api.delay_calls == [job_id]
    config = job.detail["campaign_config"]
    # Spec 12.3 defaults filled at admission (G-ATK6).
    assert config["norm"] == "linf"
    assert config["eps_grid"] == list(DEFAULT_EPS_GRID_LINF)
    assert config["reference_eps"] == DEFAULT_REFERENCE_EPS
    assert config["dataset_id"] == DATASET and config["dataset_revision"] == DATASET_REVISION
    assert config["n_samples"] == 200 and config["finding_asr_threshold"] == 0.2
    assert config["attack_params"] == {"fgsm": {}}, "caller overrides only; eps comes from the grid"
    assert [attack["id"] for attack in config["attacks"]] == ["fgsm"]
    assert config["target_snapshot"]["id"] == MODEL
    row = api.campaign_row(run_id)
    assert row is not None and row["kind"] == "attack" and row["parent_run_id"] is None
    assert row["config"]["eps_grid"] == list(DEFAULT_EPS_GRID_LINF)
    assert isinstance(row["settings_hash"], str) and len(row["settings_hash"]) == 64
    # One success row, written before the Run existed, carrying digests and ids only.
    events = api.events("attack.run")
    assert len(events) == 1 and events[0].success and events[0].run_id == run_id
    assert api.writer.run_existed_at_append == [False]
    detail = events[0].detail
    assert detail["model_sha256"] == SHA256 and detail["settings_hash"] == row["settings_hash"]
    assert detail["attack_ids"] == ["fgsm"] and detail["dataset_id"] == DATASET
    assert detail["rerun"] is False and detail["parent_run_id"] is None
    assert "target_snapshot" not in detail["config"] and "attacks" not in detail["config"]


def test_start_campaign_l2_norm_uses_the_l2_default_grid(api: Harness) -> None:
    # PGD declares ``norm_l2``. This test used to launch ``fgsm`` under ``norm: l2`` and expect 202, which
    # the runner then refused in the sandbox child (FGSM is L-inf only); admission now refuses that pairing
    # with ``params_out_of_range`` (tests/ml/test_admission_followups.py), so the L2 default grid is
    # exercised here with an attack that can run under L2.
    seed_model(api)
    response = launch(api, {"attack_ids": ["pgd"], "norm": "l2"})
    assert response.status_code == 202, response.text
    with api.Session() as session:
        job = session.get(Job, response.json()["job_ids"][0])
    assert job is not None
    config = job.detail["campaign_config"]
    assert config["norm"] == "l2"
    assert config["eps_grid"] == list(DEFAULT_EPS_GRID_L2)
    assert config["reference_eps"] == DEFAULT_EPS_GRID_L2[1], "the spec names no L2 reference; middle member"


def test_start_campaign_explicit_grid_within_the_bound_is_accepted(api: Harness) -> None:
    seed_model(api)
    grid = [0.02, 0.05, 0.2]
    response = launch(api, {"attack_ids": ["fgsm"], "eps_grid": grid, "reference_eps": 0.05})
    assert response.status_code == 202, response.text
    with api.Session() as session:
        job = session.get(Job, response.json()["job_ids"][0])
    assert job is not None
    assert job.detail["campaign_config"]["eps_grid"] == grid
    assert job.detail["campaign_config"]["reference_eps"] == 0.05


_TOO_MANY = [round(0.01 * (i + 1), 2) for i in range(DEFAULT_MAX_EPS_GRID_MEMBERS + 1)]


@pytest.mark.parametrize(
    ("body", "code"),
    [
        pytest.param({}, "params_out_of_range", id="attack_ids_missing"),
        pytest.param({"attack_ids": []}, "params_out_of_range", id="attack_ids_empty"),
        pytest.param({"attack_ids": ["nope"]}, "unknown_attack", id="unknown_attack"),
        pytest.param({"attack_ids": ["fgsm"], "modality": "tabular"}, "attack_modality_mismatch",
                     id="modality_contradicts_model"),
        pytest.param({"attack_ids": ["fgsm"], "eps_grid": [0.1, 0.03]}, "eps_grid_invalid", id="grid_unsorted"),
        pytest.param({"attack_ids": ["fgsm"], "eps_grid": []}, "eps_grid_invalid", id="grid_empty"),
        pytest.param({"attack_ids": ["fgsm"], "eps_grid": [0.0, 0.1]}, "eps_grid_invalid", id="grid_zero"),
        pytest.param({"attack_ids": ["fgsm"], "eps_grid": [0.5, 1.5]}, "eps_grid_invalid", id="grid_above_one"),
        pytest.param({"attack_ids": ["fgsm"], "eps_grid": ["0.1"]}, "eps_grid_invalid", id="grid_not_numeric"),
        pytest.param({"attack_ids": ["fgsm"], "eps_grid": _TOO_MANY, "reference_eps": _TOO_MANY[0]},
                     "eps_grid_invalid", id="grid_exceeds_max_members"),
        pytest.param({"attack_ids": ["fgsm"], "reference_eps": 0.5}, "reference_eps_not_in_grid",
                     id="reference_outside_default_grid"),
        pytest.param({"attack_ids": ["fgsm"], "eps_grid": [0.05, 0.1]}, "reference_eps_not_in_grid",
                     id="default_reference_not_in_custom_grid"),
        pytest.param({"attack_ids": ["fgsm"], "attack_params": {"fgsm": {"nonsense": 1}}},
                     "params_out_of_range", id="unknown_attack_param"),
        pytest.param({"attack_ids": ["fgsm"], "attack_params": {"fgsm": {"batch_size": 0}}},
                     "params_out_of_range", id="attack_param_below_min"),
        pytest.param({"attack_ids": ["fgsm"], "attack_params": {"pgd": {}}}, "params_out_of_range",
                     id="params_for_attack_not_in_set"),
        pytest.param({"attack_ids": ["fgsm"], "n_samples": 5}, "params_out_of_range", id="n_samples_below_min"),
        pytest.param({"attack_ids": ["fgsm"], "explain_k": 64}, "params_out_of_range", id="explain_k_above_max"),
        pytest.param({"attack_ids": ["fgsm"], "norm": "l1"}, "params_out_of_range", id="unknown_norm"),
        pytest.param({"attack_ids": ["fgsm"], "dataset_id": "other/dataset"}, "dataset_incompatible",
                     id="dataset_differs_from_manifest"),
    ],
)
def test_start_campaign_validation_matrix(api: Harness, body: dict[str, Any], code: str) -> None:
    seed_model(api)
    detail = assert_refused(api, launch(api, body), code)
    if code == "eps_grid_invalid":
        assert detail["field"] == "eps_grid" and detail["reasons"]
    if body.get("eps_grid") == _TOO_MANY:
        assert any(f"maximum of {DEFAULT_MAX_EPS_GRID_MEMBERS}" in reason for reason in detail["reasons"])


def test_attack_requires_gradients_422(api: Harness) -> None:
    seed_model(api, gradients=False)
    detail = assert_refused(api, launch(api, {"attack_ids": ["fgsm"]}), "attack_requires_gradients")
    assert "gradients" in detail["message"]


def test_dataset_missing_everywhere_is_dataset_incompatible(api: Harness) -> None:
    seed_model(api, dataset_id=None)
    detail = assert_refused(api, launch(api, {"attack_ids": ["fgsm"]}), "dataset_incompatible")
    assert detail["field"] == "dataset_id"


def test_endpoint_target_501(api: Harness) -> None:
    seed_model(api, kind="ml_model_endpoint", modality="image")
    detail = assert_refused(api, launch(api, {"attack_ids": ["fgsm"]}), "not_implemented")
    assert detail["phase"] == "B"


@pytest.mark.parametrize(
    ("status", "refusal_reason", "expected_status"),
    [
        pytest.param(None, None, "unknown", id="status_missing"),
        pytest.param("registered", None, "registered", id="registered"),
        pytest.param("validating", None, "validating", id="validating"),
        pytest.param("refused", "pickle_refused", "refused", id="refused_with_reason"),
        pytest.param("deleted", None, "deleted", id="soft_deleted"),
    ],
)
def test_model_not_available_409(api: Harness, status: str | None, refusal_reason: str | None,
                                 expected_status: str) -> None:
    seed_model(api, status=status, refusal_reason=refusal_reason)
    detail = assert_refused(api, launch(api, {"attack_ids": ["fgsm"]}), "model_load_refused")
    assert detail["status"] == expected_status
    assert isinstance(detail["refusal_reason"], str) and detail["refusal_reason"]
    if refusal_reason is not None:
        assert detail["refusal_reason"] == refusal_reason


def test_unknown_model_404_keeps_the_string_detail(api: Harness) -> None:
    response = launch(api, {"attack_ids": ["fgsm"]}, model_id="no-such-model")
    assert response.status_code == 404
    assert response.json()["detail"] == "model not found"
    assert api.counts() == {"runs": 0, "jobs": 0, "campaigns": 0}


def test_queue_unavailable_503(api: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    seed_model(api)

    def broken_delay(_job_id: str) -> Any:
        raise ConnectionError("broker unreachable")

    monkeypatch.setattr("redsim.workers.tasks.ml_campaign.ml_campaign_run.delay", broken_delay)

    response = launch(api, {"attack_ids": ["fgsm"]})

    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "queue_unavailable" and detail["reason"] == "ConnectionError"
    assert api.counts() == {"runs": 0, "jobs": 0, "campaigns": 0}, "the admission rows were rolled back"
    events = api.events("attack.run")
    assert [event.success for event in events] == [True, False]
    admitted, rolled_back = events
    assert admitted.run_id is not None and api.writer.run_existed_at_append[0] is False
    assert rolled_back.run_id is None and rolled_back.detail["code"] == "queue_unavailable"
    assert rolled_back.detail["rolled_back_run_id"] == admitted.run_id
    (rolled_back_job,) = rolled_back.detail["rolled_back_job_ids"]
    assert rolled_back_job.startswith("job-")


# --------------------------------------------------------------------------- rerun refusals

def test_rerun_refuses_a_parent_that_is_not_terminal(api: Harness) -> None:
    seed_model(api)
    seed_campaign_run(api, "run-parent-live", status="running")
    detail = assert_refused(api, launch(api, {"parent_run_id": "run-parent-live"}), "campaign_not_terminal",
                            before={"runs": 1, "jobs": 0, "campaigns": 1})
    assert detail["status"] == "running"
    with api.Session() as session:
        assert session.query(Run).count() == 1, "the parent is untouched"


def test_rerun_refuses_a_succeeded_parent(api: Harness) -> None:
    seed_model(api)
    seed_campaign_run(api, "run-parent-ok", status="succeeded")
    response = launch(api, {"parent_run_id": "run-parent-ok"})
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "params_out_of_range" and detail["field"] == "parent_run_id"
    assert detail["status"] == "succeeded"
    refused = [event for event in api.events("attack.run") if not event.success]
    assert len(refused) == 1 and refused[0].detail["parent_run_id"] == "run-parent-ok"


def test_rerun_refuses_a_parent_on_another_model(api: Harness) -> None:
    seed_model(api)
    seed_model(api, "model-image-2")
    seed_campaign_run(api, "run-parent-other", status="failed", target_id="model-image-2",
                      config=parent_config(target_id="model-image-2"))
    response = launch(api, {"parent_run_id": "run-parent-other"})
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "params_out_of_range"
    assert response.json()["detail"]["field"] == "parent_run_id"


def test_rerun_refuses_extra_config(api: Harness) -> None:
    seed_model(api)
    seed_campaign_run(api, "run-parent-failed", status="failed")
    response = launch(api, {"parent_run_id": "run-parent-failed", "attack_ids": ["fgsm"]})
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "params_out_of_range" and detail["field"] == "parent_run_id"
    assert "unexpected field attack_ids" in detail["reasons"]


def test_rerun_unknown_parent_404(api: Harness) -> None:
    seed_model(api)
    response = launch(api, {"parent_run_id": "run-does-not-exist"})
    assert response.status_code == 404, response.text
    assert response.json()["detail"] == "parent run not found: run-does-not-exist"
    refused = [event for event in api.events("attack.run") if not event.success]
    assert len(refused) == 1 and refused[0].detail["code"] == "not_found"
