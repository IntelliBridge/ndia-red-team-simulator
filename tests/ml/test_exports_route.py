"""``GET /v1/exports``: the export inventory the web Exports page reads.

Pinned offline over the shared sqlite harness with the real app in dev auth and
the user dependency overridden:

* one row per campaign or verify run of the caller's projects, newest first;
  follow-up export runs, probe runs and another project's runs never appear;
* the report block names the formats the newest non-archived snapshot holds,
  falls back to the newest artifact row per format, lists what is missing and
  says when a ``report.render`` job is in flight;
* the dataset block is ``exported`` with the manifest digest, file count and
  bytes, ``failed`` with the job's error, ``queued`` / ``running`` while a job
  is active, or ``not_exported`` with the blockers the admission would raise;
* the gates: ``?project=`` on a project the caller is not a member of is 403,
  a viewer reads, a stranger sees only their own project, ``kind`` and
  ``limit`` outside their ranges are ``422 params_out_of_range``;
* no row carries a score of any kind (spec 15.7), and the route writes nothing.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from redsim.api.auth import CurrentUser, get_current_user
from redsim.audit.chain import InMemoryAuditWriter
from redsim.db.models import Artifact, Job, Organization, Project, ReportSnapshot, Run, Target

pytestmark = pytest.mark.integration

PROJECT = "project-1"
OTHER = "project-2"
VIEWER = CurrentUser(sub="dev:viewer@test", email="viewer@test", project_memberships={PROJECT: "viewer"})
ADMIN = CurrentUser(sub="dev:admin@test", email="admin@test", project_memberships={PROJECT: "admin"})
STRANGER = CurrentUser(sub="dev:other@test", email="other@test", project_memberships={OTHER: "admin"})

T0 = datetime(2026, 9, 9, 12, 0, tzinfo=UTC)


def _at(minutes: int) -> datetime:
    return T0 + timedelta(minutes=minutes)


def _artifact(run_id: str, kind: str, *, aid: str, size: int = 10, project: str = PROJECT) -> Artifact:
    return Artifact(id=aid, run_id=run_id, project_id=project, kind=kind, sha256=f"{aid:0>64}"[:64],
                    location=f"runs/{run_id}/{aid}", content_type="application/octet-stream",
                    size_bytes=size, created_at=_at(1))


@pytest.fixture
def api(sqlite_session_factory: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Iterator[SimpleNamespace]:
    """The real app over sqlite with the runs described in the module docstring."""
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings

    with sqlite_session_factory.Session() as sess:
        sess.add(Organization(id="org-1", name="Org", slug="org"))
        sess.add(Project(id=PROJECT, org_id="org-1", name="Project", slug=PROJECT))
        sess.add(Project(id=OTHER, org_id="org-1", name="Other", slug=OTHER))
        sess.flush()
        sess.add(Target(id="tgt-vehicles", project_id=PROJECT, kind="ml_model_artifact", value="bundled:vehicles_cnn",
                        verified=True, detail={"modality": "image", "status": "available", "name": "Vehicles CNN"}))
        sess.add(Target(id="tgt-fixture", project_id=PROJECT, kind="ml_model_artifact", value="bundled:cifar10_smallcnn",
                        verified=True, detail={"modality": "image", "fixture_only": True}))
        sess.add(Target(id="tgt-other", project_id=OTHER, kind="ml_model_artifact", value="bundled:url_trees",
                        verified=True, detail={"modality": "tabular"}))
        sess.add(Target(id="tgt-endpoint", project_id=PROJECT, kind="ml_model_endpoint",
                        value="https://models.example.test:8443/tenants/acme/v1/predict?key=REDACTED-FAKE",
                        verified=True, detail={"modality": "tabular", "endpoint": {"host": "models.example.test:8443"}}))
        sess.flush()
        # run-1: a finished campaign with three report formats in a snapshot, a PDF as a bare
        # artifact, an exported dataset and a render in flight.
        sess.add(Run(id="run-1", project_id=PROJECT, target_id="tgt-vehicles", mode="api", scanner="ml.campaign",
                     status="succeeded", stage_table={}, created_at=_at(1), completed_at=_at(5)))
        # run-2: a verify still running.
        sess.add(Run(id="run-2", project_id=PROJECT, target_id="tgt-vehicles", mode="api", scanner="ml.verify",
                     status="running", stage_table={}, created_at=_at(2)))
        # run-3: a finished campaign whose dataset export failed on its follow-up run.
        sess.add(Run(id="run-3", project_id=PROJECT, target_id="tgt-vehicles", mode="api", scanner="ml.campaign",
                     status="succeeded", stage_table={}, created_at=_at(3), completed_at=_at(6)))
        sess.add(Run(id="run-3-export", project_id=PROJECT, target_id="tgt-vehicles", mode="api",
                     scanner="ml.dataset_export", status="failed", stage_table={}, created_at=_at(7)))
        # run-4: a finished campaign on the CI fixture with no slices.
        sess.add(Run(id="run-4", project_id=PROJECT, target_id="tgt-fixture", mode="api", scanner="ml.campaign",
                     status="succeeded", stage_table={}, created_at=_at(4), completed_at=_at(8)))
        # run-5: a finished campaign against a black-box endpoint (its URL must never leave).
        sess.add(Run(id="run-5", project_id=PROJECT, target_id="tgt-endpoint", mode="api", scanner="ml.campaign",
                     status="succeeded", stage_table={}, created_at=_at(0), completed_at=_at(1)))
        # Not exports of anything: a probe run and another project's campaign.
        sess.add(Run(id="run-probe", project_id=PROJECT, target_id=None, mode="api", scanner="ml.llm_probe",
                     status="succeeded", stage_table={}, created_at=_at(9)))
        sess.add(Run(id="run-other", project_id=OTHER, target_id="tgt-other", mode="api", scanner="ml.campaign",
                     status="succeeded", stage_table={}, created_at=_at(10)))
        sess.flush()
        for kind, aid in (("report.md", "art-md"), ("report.json", "art-json"), ("report.html", "art-html")):
            sess.add(_artifact("run-1", kind, aid=aid))
        sess.add(_artifact("run-1", "report.pdf", aid="art-pdf-bare", size=2048))
        sess.add(_artifact("run-1", "ml.adv_slice", aid="art-slice-1"))
        sess.add(_artifact("run-1", "ml.dataset.manifest", aid="art-manifest", size=100))
        sess.add(_artifact("run-1", "ml.dataset.parquet", aid="art-pq-1", size=1000))
        sess.add(_artifact("run-1", "ml.dataset.parquet", aid="art-pq-2", size=2000))
        sess.add(_artifact("run-1", "ml.dataset.card", aid="art-card", size=50))
        sess.add(_artifact("run-3", "ml.adv_slice", aid="art-slice-3"))
        sess.add(_artifact("run-3", "report.md", aid="art-md-3"))
        sess.flush()
        sess.add(ReportSnapshot(id="snap-1", run_id="run-1", project_id=PROJECT,
                                artifact_ids=["art-md", "art-json", "art-html"], record_sha256="a" * 64,
                                rendered_at=_at(5), archived=False, created_by="worker"))
        sess.add(Job(id="job-render-1", run_id="run-1", project_id=PROJECT, type="report.render", status="queued",
                     created_at=_at(6), detail={"formats": ["pdf"]}))
        sess.add(Job(id="job-export-3", run_id="run-3-export", project_id=PROJECT, type="dataset.export",
                     status="failed", error="projection mismatch", created_at=_at(7),
                     detail={"source_run_id": "run-3"}))
        sess.commit()

    monkeypatch.setattr("redsim.db.session.get_session", sqlite_session_factory.session_cm)
    writer = InMemoryAuditWriter()
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _config: writer)
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)

    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    app = create_app(APISettings(
        env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
        rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000,
    ))
    holder: dict[str, CurrentUser] = {"user": ADMIN}
    app.dependency_overrides[get_current_user] = lambda: holder["user"]
    client = TestClient(app)

    def get(user: CurrentUser, path: str = "/v1/exports") -> Any:
        holder["user"] = user
        return client.get(path)

    yield SimpleNamespace(app=app, get=get, writer=writer, Session=sqlite_session_factory.Session)
    rl._BUCKETS.clear()


def _rows(resp: Any) -> dict[str, dict[str, Any]]:
    assert resp.status_code == 200, resp.text
    return {row["run_id"]: row for row in resp.json()["exports"]}


def test_lists_campaign_and_verify_runs_newest_first_and_nothing_else(api: SimpleNamespace) -> None:
    resp = api.get(ADMIN)
    body = resp.json()
    assert [row["run_id"] for row in body["exports"]] == ["run-4", "run-3", "run-2", "run-1", "run-5"]
    assert body["count"] == 5
    assert body["report_formats"] == ["md", "json", "html", "pdf"]
    assert body["dataset_format"] == "croissant-parquet"
    kinds = {row["run_id"]: row["kind"] for row in body["exports"]}
    assert kinds == {"run-1": "campaign", "run-2": "verify", "run-3": "campaign", "run-4": "campaign",
                     "run-5": "campaign"}


def test_report_block_reads_the_snapshot_then_falls_back_to_bare_artifacts(api: SimpleNamespace) -> None:
    row = _rows(api.get(ADMIN))["run-1"]
    reports = row["reports"]
    assert reports["available"] == ["md", "json", "html", "pdf"]
    assert reports["missing"] == []
    assert reports["formats"]["md"] == {
        "artifact_id": "art-md", "kind": "report.md", "sha256": "art-md".rjust(64, "0"), "size_bytes": 10,
        "source": "snapshot", "snapshot_version": 1,
    }
    # The PDF is not in the snapshot: it comes from the newest artifact row and says so.
    assert reports["formats"]["pdf"]["artifact_id"] == "art-pdf-bare"
    assert reports["formats"]["pdf"]["source"] == "artifact"
    assert "snapshot_version" not in reports["formats"]["pdf"]
    assert reports["snapshot_count"] == 1
    assert reports["latest_snapshot"] == {"id": "snap-1", "version": 1, "rendered_at": _at(5).isoformat(),
                                          "archived": False}
    assert reports["render_in_flight"] is True

    model = row["model"]
    assert model == {"target_id": "tgt-vehicles", "name": "Vehicles CNN", "value": "bundled:vehicles_cnn",
                     "modality": "image", "fixture": False}
    assert row["terminal"] is True
    assert row["completed_at"] == _at(5).isoformat()


def test_dataset_block_exported(api: SimpleNamespace) -> None:
    dataset = _rows(api.get(ADMIN))["run-1"]["dataset"]
    assert dataset["status"] == "exported"
    assert dataset["format"] == "croissant-parquet"
    assert dataset["manifest_artifact_id"] == "art-manifest"
    assert dataset["manifest_sha256"] == "art-manifest".rjust(64, "0")
    assert dataset["files"] == 2
    assert dataset["bytes"] == 100 + 1000 + 2000
    assert dataset["card"] is True
    assert dataset["blockers"] == []


def test_dataset_block_failed_names_the_follow_up_job_and_error(api: SimpleNamespace) -> None:
    dataset = _rows(api.get(ADMIN))["run-3"]["dataset"]
    assert dataset["status"] == "failed"
    assert dataset["job_id"] == "job-export-3"
    assert dataset["follow_up_run_id"] == "run-3-export"
    assert dataset["error"] == "projection mismatch"
    # A failed export can be retried: the run is terminal, non-fixture and kept its slices.
    assert dataset["blockers"] == []
    # The run's one bare report artifact is listed, the rest missing, nothing invented.
    reports = _rows(api.get(ADMIN))["run-3"]["reports"]
    assert reports["available"] == ["md"]
    assert reports["missing"] == ["json", "html", "pdf"]
    assert reports["snapshot_count"] == 0
    assert reports["latest_snapshot"] is None
    assert reports["render_in_flight"] is False


def test_dataset_block_active_job_reports_its_status(api: SimpleNamespace) -> None:
    with api.Session() as sess:
        sess.add(Run(id="run-3-export-2", project_id=PROJECT, target_id="tgt-vehicles", mode="api",
                     scanner="ml.dataset_export", status="queued", stage_table={}, created_at=_at(11)))
        sess.flush()
        sess.add(Job(id="job-export-3b", run_id="run-3-export-2", project_id=PROJECT, type="dataset.export",
                     status="running", created_at=_at(11), detail={"source_run_id": "run-3"}))
        sess.commit()
    dataset = _rows(api.get(ADMIN))["run-3"]["dataset"]
    assert dataset["status"] == "running"
    assert dataset["job_id"] == "job-export-3b"
    assert dataset["error"] is None


def test_dataset_blockers_name_why_an_export_cannot_start(api: SimpleNamespace) -> None:
    rows = _rows(api.get(ADMIN))
    assert rows["run-2"]["dataset"]["status"] == "not_exported"
    assert rows["run-2"]["dataset"]["blockers"] == ["not_terminal", "no_slices"]
    assert rows["run-2"]["terminal"] is False
    assert rows["run-4"]["dataset"]["blockers"] == ["fixture_target", "no_slices"]
    assert rows["run-4"]["model"]["fixture"] is True
    assert rows["run-4"]["model"]["name"] == "cifar10_smallcnn"


def test_kind_filter_and_limit(api: SimpleNamespace) -> None:
    assert list(_rows(api.get(ADMIN, "/v1/exports?kind=verify"))) == ["run-2"]
    assert list(_rows(api.get(ADMIN, "/v1/exports?kind=campaign"))) == ["run-4", "run-3", "run-1", "run-5"]
    assert list(_rows(api.get(ADMIN, "/v1/exports?limit=2"))) == ["run-4", "run-3"]
    for path in ("/v1/exports?kind=probe", "/v1/exports?limit=0", "/v1/exports?limit=501"):
        resp = api.get(ADMIN, path)
        assert resp.status_code == 422, resp.text
        assert resp.json()["detail"]["code"] == "params_out_of_range"


def test_membership_gates(api: SimpleNamespace) -> None:
    # A viewer reads the inventory the way a viewer reads /v1/runs.
    assert list(_rows(api.get(VIEWER))) == ["run-4", "run-3", "run-2", "run-1", "run-5"]
    # A named project the caller is not a member of is refused before any read.
    resp = api.get(ADMIN, f"/v1/exports?project={OTHER}")
    assert resp.status_code == 403, resp.text
    assert isinstance(resp.json()["detail"], str)
    assert api.get(STRANGER, f"/v1/exports?project={PROJECT}").status_code == 403
    # Without a project the listing is scoped to the caller's memberships.
    assert list(_rows(api.get(STRANGER))) == ["run-other"]
    assert list(_rows(api.get(ADMIN, f"/v1/exports?project={PROJECT}"))) == ["run-4", "run-3", "run-2", "run-1",
                                                                             "run-5"]


def test_endpoint_target_shows_its_host_and_never_its_url(api: SimpleNamespace) -> None:
    resp = api.get(ADMIN)
    model = _rows(resp)["run-5"]["model"]
    assert model["value"] == "models.example.test:8443"
    assert model["name"] == "models.example.test:8443"
    text = resp.text
    for leaked in ("https://", "/tenants/acme", "REDACTED-FAKE", "predict"):
        assert leaked not in text, leaked


def test_rows_carry_no_score_and_the_route_writes_nothing(api: SimpleNamespace) -> None:
    with api.Session() as sess:
        before = tuple(sess.execute(select(func.count()).select_from(table)).scalar() for table in (Run, Job, Artifact))
    resp = api.get(ADMIN)
    text = json.dumps(resp.json()).lower()
    for banned in ('"mri"', "grade", "subscore", "readiness"):
        assert banned not in text, banned
    with api.Session() as sess:
        after = tuple(sess.execute(select(func.count()).select_from(table)).scalar() for table in (Run, Job, Artifact))
    assert after == before
    assert api.writer.events == []


def test_openapi_lists_the_route(api: SimpleNamespace) -> None:
    paths = api.app.openapi()["paths"]
    assert "get" in paths["/v1/exports"]
