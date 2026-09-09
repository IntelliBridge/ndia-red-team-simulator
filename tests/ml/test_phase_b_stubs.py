"""Wave B0 stubs: every Phase B route is mounted, gated and answers ``501 not_implemented`` with ``phase``.

Register row INTEROP-01 and the wave B0 ``route-stubs`` track of
``docs/plans/12-phase-b-plan.md``: the tree is truthful about Phase B from the
first push. Each stub runs the lookup, membership and role gates its real
handler will run and only then raises the spec 17.3 envelope
``{"code": "not_implemented", "message": ..., "phase": "B", "reason": ...}``.

Pinned here, offline over the shared sqlite harness with the real app in dev
auth and the user dependency overridden:

* an allowed role gets ``501`` with ``code``, ``phase == "B"``, a message and a
  ``reason`` on every stub, and ``report.pdf`` still answers the same way;
* a ``viewer`` gets ``403`` (a plain-string detail, never the 501 envelope) on
  every gated stub, and ``501`` on the read stubs its membership admits;
* a non-member is refused before the 501 wherever a project can be resolved
  (a run, a model, a finding, a body or query ``project_id``);
* an unknown run, model or finding is ``404`` before the 501;
* a batch or bulk body without ``project_id`` is ``422 params_out_of_range``;
* nothing is written: no Run, Job, Target, Finding row and no audit event;
* the OpenAPI document lists every stub path and method.

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
from sqlalchemy import func, select

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

# (method, path, json body, how the project is resolved, whether a role gate runs before the 501).
# ``resolve`` is one of: run (ensure_run_access), target, finding, project (body project_id),
# query (``?project=``), run-optional (a run with that id when one exists), none (authenticated).
STUBS: list[tuple[str, str, dict[str, Any] | None, str, bool]] = [
    ("POST", f"/v1/runs/{RUN}/dataset", None, "run", True),
    ("GET", f"/v1/datasets/{RUN}", None, "run-optional", False),
    ("POST", "/v1/datasets", {"project_id": PROJECT}, "project", True),
    ("GET", f"/v1/runs/{RUN}/atlas-coverage", None, "run", False),
    ("POST", f"/v1/runs/{RUN}/integrations/foundry", None, "run", True),
    ("GET", "/v1/integrations", None, "none", False),
    ("GET", "/v1/llm/probes", None, "none", False),
    ("POST", f"/v1/models/{TARGET}/probes", {}, "target", True),
    ("GET", f"/v1/runs/{RUN}/llm-scorecard", None, "run", False),
    ("POST", "/v1/campaigns/batch", {"project_id": PROJECT, "target_ids": [TARGET]}, "project", True),
    ("GET", "/v1/campaigns/batch/batch-1", None, "none", False),
    ("GET", f"/v1/campaigns/batch?project={PROJECT}", None, "query", False),
    ("POST", "/v1/campaigns/batch/batch-1/cancel", None, "none", False),
    ("GET", "/v1/campaigns/batch/batch-1/compare", None, "none", False),
    ("POST", "/v1/models/bulk", {"project_id": PROJECT}, "project", True),
    ("POST", f"/v1/findings/{FINDING}/verify/bulk", {}, "finding", True),
    ("GET", f"/v1/ml/capacity?project={PROJECT}", None, "query", False),
    ("POST", f"/v1/runs/{RUN}/report.render", {}, "run", True),
    ("GET", f"/v1/runs/{RUN}/snapshots", None, "run", False),
]

#: Every stub as an OpenAPI template path and its method.
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


def _ids(rows: list[tuple[str, str, Any, str, bool]]) -> list[str]:
    return [f"{method} {path.split('?')[0]}" for method, path, *_ in rows]


@pytest.fixture
def api(sqlite_session_factory: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Iterator[SimpleNamespace]:
    """The real app in dev auth over sqlite: one project with a run, a model target and a finding."""
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings

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


def _assert_not_implemented(resp: Any) -> dict[str, Any]:
    assert resp.status_code == 501, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "not_implemented"
    assert detail["phase"] == "B"
    assert isinstance(detail["message"], str) and detail["message"]
    assert "docs/plans/12-phase-b-plan.md" in detail["reason"]
    return detail


def _assert_plain_403(resp: Any) -> None:
    assert resp.status_code == 403, resp.text
    # The gate speaks first, with FastAPI's plain-string detail, never the 501 envelope.
    assert isinstance(resp.json()["detail"], str)


# --------------------------------------------------------------------------- 501 for an allowed role


@pytest.mark.parametrize(("method", "path", "body", "_resolve", "_gated"), STUBS, ids=_ids(STUBS))
def test_admin_gets_501_with_phase_on_every_stub(api: SimpleNamespace, method: str, path: str,
                                                  body: dict[str, Any] | None, _resolve: str, _gated: bool) -> None:
    _assert_not_implemented(api.call(ADMIN, method, path, body))


def test_report_pdf_stays_501(api: SimpleNamespace) -> None:
    """The one Phase B refusal that predates wave B0 keeps its envelope (spec 17.4), gates first."""
    resp = api.call(ADMIN, "GET", f"/v1/runs/{RUN}/report.pdf")
    assert resp.status_code == 501, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "not_implemented" and detail["phase"] == "B" and detail["field"] == "ext"
    _assert_plain_403(api.call(VIEWER, "GET", f"/v1/runs/{RUN}/report.pdf"))


# --------------------------------------------------------------------------- gates run before the 501


@pytest.mark.parametrize(("method", "path", "body", "_resolve", "gated"), STUBS, ids=_ids(STUBS))
def test_viewer_is_refused_on_gated_stubs_and_admitted_to_reads(
    api: SimpleNamespace, method: str, path: str, body: dict[str, Any] | None, _resolve: str, gated: bool,
) -> None:
    resp = api.call(VIEWER, method, path, body)
    if gated:
        _assert_plain_403(resp)
    else:
        _assert_not_implemented(resp)


@pytest.mark.parametrize(
    ("method", "path", "body", "_resolve", "_gated"),
    [row for row in STUBS if row[3] in {"run", "run-optional", "target", "finding", "project", "query"}],
    ids=_ids([row for row in STUBS if row[3] in {"run", "run-optional", "target", "finding", "project", "query"}]),
)
def test_non_member_is_refused_before_the_501(api: SimpleNamespace, method: str, path: str,
                                              body: dict[str, Any] | None, _resolve: str, _gated: bool) -> None:
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
    ],
)
def test_unknown_resource_is_404_before_the_501(api: SimpleNamespace, method: str, path: str,
                                                body: dict[str, Any] | None) -> None:
    resp = api.call(ADMIN, method, path, body)
    assert resp.status_code == 404, resp.text


def test_probes_route_refuses_a_non_ml_target(api: SimpleNamespace) -> None:
    with api.Session() as sess:
        sess.add(Target(id="tgt-url", project_id=PROJECT, kind="url", value="http://127.0.0.1:1", verified=False))
        sess.commit()
    assert api.call(ADMIN, "POST", "/v1/models/tgt-url/probes", {}).status_code == 404


def test_dataset_id_without_a_run_is_501_not_404(api: SimpleNamespace) -> None:
    """A consumed slice's id is not resolvable before the dataset store exists, so no false 404."""
    _assert_not_implemented(api.call(ADMIN, "GET", f"/v1/datasets/{UNKNOWN}"))


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


@pytest.mark.parametrize("path", ["/v1/datasets", "/v1/models/bulk"])
def test_form_bodies_and_query_projects_reach_the_gates(api: SimpleNamespace, path: str) -> None:
    """The bulk routes take multipart once built; the stub gates on the form's project_id too."""
    form = {"project_id": PROJECT}
    files = {"file": ("model.onnx", b"\x08\x07", "application/octet-stream")}
    _assert_plain_403(api.call(VIEWER, "POST", path, data=form, files=files))
    _assert_not_implemented(api.call(ADMIN, "POST", path, data=form, files=files))
    _assert_plain_403(api.call(STRANGER, "POST", f"{path}?project={PROJECT}"))
    _assert_not_implemented(api.call(ADMIN, "POST", f"{path}?project={PROJECT}"))


def test_list_routes_gate_on_the_named_project_only(api: SimpleNamespace) -> None:
    for path in ("/v1/campaigns/batch", "/v1/ml/capacity"):
        _assert_plain_403(api.call(STRANGER, "GET", f"{path}?project={PROJECT}"))
        _assert_not_implemented(api.call(STRANGER, "GET", path))
        _assert_not_implemented(api.call(VIEWER, "GET", f"{path}?project={PROJECT}"))


# --------------------------------------------------------------------------- nothing is faked


def test_stubs_write_nothing(api: SimpleNamespace) -> None:
    def counts() -> dict[str, int]:
        with api.Session() as sess:
            return {model.__tablename__: int(sess.execute(select(func.count()).select_from(model)).scalar_one())
                    for model in (Run, Job, Target, Finding)}

    before = counts()
    for method, path, body, _resolve, _gated in STUBS:
        assert api.call(ADMIN, method, path, body).status_code == 501
    assert counts() == before
    assert api.writer.events == []


def test_openapi_lists_every_stub(api: SimpleNamespace) -> None:
    paths = api.app.openapi()["paths"]
    for method, template in OPENAPI_PATHS:
        assert template in paths, template
        assert method in paths[template], f"{method.upper()} {template}"


# --------------------------------------------------------------------------- gate vocabulary


def test_gates_are_the_phase_b_actions_or_their_documented_fallbacks() -> None:
    """Each stub gates on the Action the actions-and-codes track adds, or the named Phase A stand-in.

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
