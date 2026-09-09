"""Phase B route surface: every route wave B0 stubbed is mounted, gated and answers with a real handler.

Register row INTEROP-01 and the wave B0 ``route-stubs`` track of
``docs/plans/12-phase-b-plan.md``: the tree is truthful about Phase B from the
first push. Wave B0 mounted every route as a ``501 not_implemented`` stub; wave
B2 replaced the LLM probe, report.render and snapshot stubs and wave B3 replaced
the rest (interop-contribute / interop-consume: the dataset export and the
consumed-slice admission; atlas-foundry: ATLAS coverage, the roster and the
Foundry push; bulk-service-routes: batch campaigns and bulk verify;
bulk-upload-capacity-cli: bulk upload and the capacity view). ``ROUTES`` is the
B0 stub list kept as the surface pin; nothing here answers ``501
not_implemented`` any more.

Pinned here, offline over the shared sqlite harness with the real app in dev
auth and the user dependency overridden (one project with a finished campaign
run that has no persisted slices, record or ``ml_campaigns`` row, so every write
route is refused after its gates):

* an allowed role reaches the handler on every route and gets its typed
  refusal or read (never ``501 not_implemented``);
* a ``viewer`` gets ``403`` (a plain-string detail) on every gated route and the
  same answer as an admin on the reads its membership admits;
* a non-member is refused before the handler wherever a project can be
  resolved (a run, a model, a finding, a body or query ``project_id``);
* an unknown run, model, finding, dataset or batch is ``404``;
* a batch or bulk body without ``project_id`` is ``422 params_out_of_range``;
* nothing is faked: the refusals create no Run, Job, Target or Finding row and
  every audit row they write is a refusal (``success == False``) or the batch
  admission row that precedes its members' refusals;
* the OpenAPI document lists every Phase B path and method.

No ML library is imported (``numpy`` only because the attack catalog route the
app mounts reads the registry metadata at import).
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("numpy")

from fastapi.testclient import TestClient
from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, Text, func, select

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import Action
from redsim.api.v1 import batches, datasets, integrations, llm
from redsim.audit.chain import InMemoryAuditWriter
from redsim.db.models import Finding, Job, Organization, Project, Run, Target

pytestmark = pytest.mark.integration

PROJECT = "project-1"
OTHER = "project-2"
RUN = "run-phase-b-1"
TARGET = "tgt-phase-b-1"
FINDING = "finding-phase-b-1"
UNKNOWN = "no-such-id"

VIEWER = CurrentUser(sub="dev:viewer@test", email="viewer@test", project_memberships={PROJECT: "viewer"})
ADMIN = CurrentUser(sub="dev:admin@test", email="admin@test", project_memberships={PROJECT: "admin"})
STRANGER = CurrentUser(sub="dev:other@test", email="other@test", project_memberships={OTHER: "admin"})

# (method, path, json body, how the project is resolved, whether a role gate runs, the admin's answer).
# ``resolve`` is one of: run (ensure_run_access), target, finding, project (body project_id),
# query (``?project=``), run-optional (a run with that id when one exists), none (authenticated).
# The admin's answer is ``(status, code)`` with ``code`` the envelope code or None for a read / plain 404.
ROUTES: list[tuple[str, str, dict[str, Any] | None, str, bool, tuple[int, str | None]]] = [
    ("POST", f"/v1/runs/{RUN}/dataset", None, "run", True, (409, "export_unavailable")),
    ("GET", f"/v1/datasets/{RUN}", None, "run-optional", False, (404, None)),
    ("POST", "/v1/datasets", {"project_id": PROJECT}, "project", True, (415, "unsupported_dataset_format")),
    ("GET", f"/v1/runs/{RUN}/atlas-coverage", None, "run", False, (404, None)),
    ("POST", f"/v1/runs/{RUN}/integrations/foundry", None, "run", True, (422, "params_out_of_range")),
    ("GET", "/v1/integrations", None, "none", False, (200, None)),
    ("POST", "/v1/campaigns/batch", {"project_id": PROJECT, "target_ids": [TARGET]}, "project", True,
     (422, "batch_member_refused")),
    ("GET", "/v1/campaigns/batch/batch-1", None, "none", False, (404, None)),
    ("GET", f"/v1/campaigns/batch?project={PROJECT}", None, "query", False, (200, None)),
    ("POST", "/v1/campaigns/batch/batch-1/cancel", None, "none", False, (404, None)),
    ("GET", "/v1/campaigns/batch/batch-1/compare", None, "none", False, (404, None)),
    ("POST", "/v1/models/bulk", {"project_id": PROJECT}, "project", True, (422, "params_out_of_range")),
    # The seeded finding is not an ML finding of a campaign run, so no candidate is verifiable.
    ("POST", f"/v1/findings/{FINDING}/verify/bulk", {}, "finding", True, (422, "params_out_of_range")),
    ("GET", f"/v1/ml/capacity?project={PROJECT}", None, "query", False, (200, None)),
]

#: Every Phase B route as an OpenAPI template path and its method.
OPENAPI_PATHS: list[tuple[str, str]] = [
    ("post", "/v1/runs/{run_id}/dataset"),
    ("get", "/v1/datasets/{dataset_id}"),
    ("post", "/v1/datasets"),
    ("get", "/v1/runs/{run_id}/atlas-coverage"),
    ("post", "/v1/runs/{run_id}/integrations/foundry"),
    ("get", "/v1/integrations"),
    ("get", "/v1/llm/probes"),
    ("post", "/v1/models/{model_id}/probes"),
    ("get", "/v1/runs/{run_id}/llm-scorecard"),
    ("post", "/v1/campaigns/batch"),
    ("get", "/v1/campaigns/batch/{batch_id}"),
    ("get", "/v1/campaigns/batch"),
    ("post", "/v1/campaigns/batch/{batch_id}/cancel"),
    ("get", "/v1/campaigns/batch/{batch_id}/compare"),
    ("post", "/v1/models/bulk"),
    ("post", "/v1/findings/{finding_id}/verify/bulk"),
    ("get", "/v1/ml/capacity"),
    ("post", "/v1/runs/{run_id}/report.render"),
    ("get", "/v1/runs/{run_id}/snapshots"),
]

#: Audit actions a refused call may write with ``success == True``: the batch admission row is written
#: before its members are admitted one by one (spec 17.2), so it precedes the members' refusals.
ADMISSION_ROWS_BEFORE_REFUSAL = {"batch.create"}


def _ids(rows: list[tuple[str, str, Any, str, bool, Any]]) -> list[str]:
    return [f"{method} {path.split('?')[0]}" for method, path, *_ in rows]


def _campaign_mirror(engine: Any) -> None:
    """The migration-owned ``ml_campaigns`` shape (0010 + 0011 ``batch_id``) on sqlite, empty."""
    Table(
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
        Column("batch_id", String),
        Column("reviewer_notes", Text),
        Column("created_at", DateTime),
        Column("completed_at", DateTime),
    ).create(engine)


@pytest.fixture
def api(sqlite_session_factory: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Iterator[SimpleNamespace]:
    """The real app in dev auth over sqlite: one project with a run, a model target and a finding."""
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings

    _campaign_mirror(sqlite_session_factory.engine)
    with sqlite_session_factory.Session() as sess:
        sess.add(Organization(id="org-1", name="Org", slug="org"))
        sess.add(Project(id=PROJECT, org_id="org-1", name="Project", slug=PROJECT))
        sess.add(Project(id=OTHER, org_id="org-1", name="Other", slug=OTHER))
        sess.flush()
        sess.add(Target(id=TARGET, project_id=PROJECT, kind="ml_model_artifact", value="bundled:tiny",
                        verified=True, detail={"modality": "image", "status": "available"}))
        sess.flush()
        sess.add(Run(id=RUN, project_id=PROJECT, target_id=TARGET, mode="api", scanner="ml.campaign",
                     status="succeeded", stage_table={}))
        sess.flush()
        sess.add(Finding(id=FINDING, scanner_finding_id="ml.pgd", run_id=RUN, project_id=PROJECT,
                         schema_blob={"finding_type": "adversarial_ml", "ml": {}}, status="open",
                         severity="high", source_tool="redsim.ml/pgd"))
        sess.commit()

    monkeypatch.setattr("redsim.db.session.get_session", sqlite_session_factory.session_cm)
    writer = InMemoryAuditWriter()
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _config: writer)
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(tmp_path / "no-assets"))
    monkeypatch.delenv("REDSIM_INTEGRATION_FOUNDRY_URL", raising=False)

    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    app = create_app(APISettings(
        env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
        rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000,
    ))
    holder: dict[str, CurrentUser] = {"user": ADMIN}
    app.dependency_overrides[get_current_user] = lambda: holder["user"]
    client = TestClient(app)

    def call(user: CurrentUser, method: str, path: str, body: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        holder["user"] = user
        if body is not None:
            kwargs["json"] = body
        return client.request(method, path, **kwargs)

    yield SimpleNamespace(app=app, client=client, call=call, writer=writer, Session=sqlite_session_factory.Session)
    rl._BUCKETS.clear()


def _assert_answer(resp: Any, expected: tuple[int, str | None]) -> None:
    status_code, code = expected
    assert resp.status_code == status_code, resp.text
    detail = resp.json().get("detail") if status_code >= 400 else None
    if code is not None:
        assert isinstance(detail, dict) and detail["code"] == code, resp.text
    if isinstance(detail, dict):
        # No route on the Phase B surface answers with the wave B0 stub envelope any more.
        assert detail.get("code") != "not_implemented", resp.text


def _assert_plain_403(resp: Any) -> None:
    assert resp.status_code == 403, resp.text
    # The gate speaks first, with FastAPI's plain-string detail, never an envelope.
    assert isinstance(resp.json()["detail"], str)


# --------------------------------------------------------------------------- a real handler for an allowed role


@pytest.mark.parametrize(("method", "path", "body", "_resolve", "_gated", "expected"), ROUTES, ids=_ids(ROUTES))
def test_admin_reaches_the_handler_on_every_route(api: SimpleNamespace, method: str, path: str,
                                                  body: dict[str, Any] | None, _resolve: str, _gated: bool,
                                                  expected: tuple[int, str | None]) -> None:
    _assert_answer(api.call(ADMIN, method, path, body), expected)


def test_report_pdf_is_404_until_rendered(api: SimpleNamespace) -> None:
    """report.pdf is a rendered artifact since wave B2: 404 while none exists, the gate still speaks first."""
    resp = api.call(ADMIN, "GET", f"/v1/runs/{RUN}/report.pdf")
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == "report not yet rendered"
    _assert_plain_403(api.call(VIEWER, "GET", f"/v1/runs/{RUN}/report.pdf"))


# --------------------------------------------------------------------------- gates run before the handler


@pytest.mark.parametrize(("method", "path", "body", "_resolve", "gated", "expected"), ROUTES, ids=_ids(ROUTES))
def test_viewer_is_refused_on_gated_routes_and_admitted_to_reads(
    api: SimpleNamespace, method: str, path: str, body: dict[str, Any] | None, _resolve: str, gated: bool,
    expected: tuple[int, str | None],
) -> None:
    resp = api.call(VIEWER, method, path, body)
    if gated:
        _assert_plain_403(resp)
    else:
        # A membership-only read answers the viewer exactly as it answers the admin.
        _assert_answer(resp, expected)


@pytest.mark.parametrize(
    ("method", "path", "body", "_resolve", "_gated", "_expected"),
    [row for row in ROUTES if row[3] in {"run", "run-optional", "target", "finding", "project", "query"}],
    ids=_ids([row for row in ROUTES if row[3] in {"run", "run-optional", "target", "finding", "project", "query"}]),
)
def test_non_member_is_refused_before_the_handler(api: SimpleNamespace, method: str, path: str,
                                                  body: dict[str, Any] | None, _resolve: str, _gated: bool,
                                                  _expected: Any) -> None:
    _assert_plain_403(api.call(STRANGER, method, path, body))


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", f"/v1/runs/{UNKNOWN}/dataset", None),
        ("GET", f"/v1/runs/{UNKNOWN}/atlas-coverage", None),
        ("POST", f"/v1/runs/{UNKNOWN}/integrations/foundry", None),
        ("GET", f"/v1/runs/{UNKNOWN}/llm-scorecard", None),
        ("POST", f"/v1/runs/{UNKNOWN}/report.render", {}),
        ("GET", f"/v1/runs/{UNKNOWN}/snapshots", None),
        ("POST", f"/v1/models/{UNKNOWN}/probes", {}),
        ("POST", f"/v1/findings/{UNKNOWN}/verify/bulk", {}),
        ("GET", f"/v1/datasets/{UNKNOWN}", None),
        ("GET", f"/v1/campaigns/batch/{UNKNOWN}", None),
        ("POST", f"/v1/campaigns/batch/{UNKNOWN}/cancel", None),
        ("GET", f"/v1/campaigns/batch/{UNKNOWN}/compare", None),
    ],
)
def test_unknown_resource_is_404(api: SimpleNamespace, method: str, path: str, body: dict[str, Any] | None) -> None:
    resp = api.call(ADMIN, method, path, body)
    assert resp.status_code == 404, resp.text


def test_probes_route_refuses_a_non_ml_target(api: SimpleNamespace) -> None:
    with api.Session() as sess:
        sess.add(Target(id="tgt-url", project_id=PROJECT, kind="url", value="http://127.0.0.1:1", verified=False))
        sess.commit()
    assert api.call(ADMIN, "POST", "/v1/models/tgt-url/probes", {}).status_code == 404


@pytest.mark.parametrize("path", ["/v1/datasets", "/v1/campaigns/batch", "/v1/models/bulk"])
def test_missing_project_id_is_422(api: SimpleNamespace, path: str) -> None:
    resp = api.call(ADMIN, "POST", path, {})
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "params_out_of_range"
    assert detail["field"] == "project_id"
    # No body at all, and a body that is not an object, are the same refusal.
    assert api.call(ADMIN, "POST", path).status_code == 422
    assert api.call(ADMIN, "POST", path, content=b"[]",
                    headers={"content-type": "application/json"}).status_code == 422


@pytest.mark.parametrize(
    ("path", "with_file", "query_only"),
    [
        # A fake ONNX part is not Parquet; a query-only call has no file part at all.
        ("/v1/datasets", (415, "unsupported_dataset_format"), (415, "unsupported_dataset_format")),
        # One file without the manifest part; a query-only call has no files part at all.
        ("/v1/models/bulk", (422, "params_out_of_range"), (422, "params_out_of_range")),
    ],
)
def test_form_bodies_and_query_projects_reach_the_gates(api: SimpleNamespace, path: str,
                                                        with_file: tuple[int, str | None],
                                                        query_only: tuple[int, str | None]) -> None:
    """The bulk routes take multipart; the gates run on the form's project_id (or ``?project=``) first."""
    form = {"project_id": PROJECT}
    files = {"file": ("model.onnx", b"\x08\x07", "application/octet-stream")}
    _assert_plain_403(api.call(VIEWER, "POST", path, data=form, files=files))
    _assert_answer(api.call(ADMIN, "POST", path, data=form, files=files), with_file)
    _assert_plain_403(api.call(STRANGER, "POST", f"{path}?project={PROJECT}"))
    _assert_answer(api.call(ADMIN, "POST", f"{path}?project={PROJECT}"), query_only)


def test_list_routes_gate_on_the_named_project_only(api: SimpleNamespace) -> None:
    for path in ("/v1/campaigns/batch", "/v1/ml/capacity"):
        _assert_plain_403(api.call(STRANGER, "GET", f"{path}?project={PROJECT}"))
        # Without a project the list is scoped to the caller's own memberships.
        assert api.call(STRANGER, "GET", path).status_code == 200
        assert api.call(VIEWER, "GET", f"{path}?project={PROJECT}").status_code == 200


# --------------------------------------------------------------------------- nothing is faked


def test_refusals_fake_nothing(api: SimpleNamespace) -> None:
    def counts() -> dict[str, int]:
        with api.Session() as sess:
            return {model.__tablename__: int(sess.execute(select(func.count()).select_from(model)).scalar_one())
                    for model in (Run, Job, Target, Finding)}

    before = counts()
    for method, path, body, _resolve, _gated, expected in ROUTES:
        _assert_answer(api.call(ADMIN, method, path, body), expected)
    assert counts() == before
    # Refusals are audited (success False); the only success rows are admissions that precede their
    # members' refusals. Nothing claims an execution.
    for event in api.writer.events:
        assert event.success is False or event.action in ADMISSION_ROWS_BEFORE_REFUSAL, (event.action, event.success)
    actions = {event.action for event in api.writer.events}
    assert not actions & {"job.complete", "attack.run.execute", "dataset.export.execute", "integration.push.execute"}


def test_openapi_lists_every_route(api: SimpleNamespace) -> None:
    paths = api.app.openapi()["paths"]
    for method, template in OPENAPI_PATHS:
        assert template in paths, template
        assert method in paths[template], f"{method.upper()} {template}"


# --------------------------------------------------------------------------- gate vocabulary


def test_gates_are_the_phase_b_actions_or_their_documented_fallbacks() -> None:
    """Each route gates on the Action the actions-and-codes track adds, or the named Phase A stand-in.

    The fallback pairs are the TODO comments in the route modules; once the members
    exist the first spelling is the one in force and this test keeps passing.
    """
    gates = {
        "DATASET_EXPORT": (integrations.DATASET_EXPORT, "dataset.export", Action.REPORT_EXPORT),
        "INTEGRATION_PUSH": (integrations.INTEGRATION_PUSH, "integration.push", Action.TARGET_MANAGE),
        "DATASET_REGISTER": (datasets.DATASET_REGISTER, "dataset.register", Action.MODEL_REGISTER),
        "LLM_PROBE_RUN": (llm.LLM_PROBE_RUN, "llm.probe.run", Action.ATTACK_RUN),
        "BATCH_RUN": (batches.BATCH_RUN, "batch.run", Action.ATTACK_RUN),
    }
    for name, (in_force, planned_value, fallback) in gates.items():
        member = getattr(Action, name, None)
        if member is not None:
            # The actions-and-codes track has landed: the Phase B member is the gate in force.
            assert in_force is member and in_force.value == planned_value, name
        else:
            assert in_force is fallback, name
    # A member that exists is preferred over the fallback.
    assert integrations.phase_b_action("REPORT_EXPORT", Action.TARGET_MANAGE) is Action.REPORT_EXPORT
    assert integrations.phase_b_action("NO_SUCH_ACTION", Action.TARGET_MANAGE) is Action.TARGET_MANAGE
