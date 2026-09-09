"""Probe capacity across projects and concurrent admissions, without a gateway."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from redsim.db.models import Job, Organization, Project, Target
from redsim.services import ml_llm
from redsim.services.auth_profiles import create_auth_profile
from redsim.services.llm_capacity import cap_batch_parallel, count_gateway_active
from redsim.services.ml_capacity import dispatch_deferred
from tests.ml.test_llm_routes import ADMIN, FAKE_KEY, GATEWAY, PERSONA, PROJECT, WorkerHarness
from tests.ml.test_llm_routes import api as api
from tests.ml.test_llm_routes import harness as harness


def admit(harness: WorkerHarness, target_id: str, project_id: str = PROJECT):
    return ml_llm.admit_llm_probe_run(
        project_id=project_id, target_id=target_id,
        body=ml_llm.LLMProbeRequest(probe_ids=["dan.DanInTheWild"], max_prompts_per_probe=5),
        actor="user:capacity", config=harness.config, audit_writer=harness.writer,
    )


def test_third_probe_defers_and_sweep_dispatches_after_completion(harness, monkeypatch):
    sent = []
    monkeypatch.setattr(ml_llm, "_enqueue", lambda job: sent.append(job) or "celery-test")
    targets = [harness.register(model_id=f"test/model-{i}") for i in range(3)]
    handles = [admit(harness, target) for target in targets]
    assert [h.deferred for h in handles] == [False, False, True]
    assert len(sent) == 2
    assert handles[2].to_response()["capacity"]["code"] == "capacity_deferred"
    with harness.get_session() as session:
        session.get(Job, handles[0].job_ids[0]).status = "succeeded"
    with harness.get_session() as session:
        report = dispatch_deferred(session, enqueue=lambda job: sent.append(job) or "celery-next",
                                   audit_writer=harness.writer)
    assert report.n_dispatched == 1 and len(sent) == 3
    assert not harness.row(Job, handles[2].job_ids[0]).detail["deferred"]


def test_gateway_slots_span_projects_and_personas_are_independent(harness, monkeypatch):
    sent = []
    monkeypatch.setattr(ml_llm, "_enqueue", lambda job: sent.append(job) or "celery-test")
    for i in range(2):
        admit(harness, harness.register(model_id=f"test/first-{i}"))
    target_id = harness.register(model_id="test/other-org")
    with harness.get_session() as session:
        session.add(Organization(id="other-org", name="Other", slug="other"))
        session.flush()
        session.add(Project(id="other-project", org_id="other-org", name="Other", slug="other"))
        session.flush()
        profile = create_auth_profile(session, project_id="other-project", name="probe", kind="bearer",
                                      config={}, secret=FAKE_KEY, actor="user:seed", audit_writer=harness.writer)
        target = session.get(Target, target_id)
        target.project_id = "other-project"
        target.detail = {**target.detail, "auth_profile_id": profile.id}
    handle = admit(harness, target_id, "other-project")
    assert handle.deferred and len(sent) == 2
    assert not admit(harness, harness.register(model_id="test/persona", persona="different")).deferred
    with harness.get_session() as session:
        assert count_gateway_active(session, "another-gateway.invalid", PERSONA) == 0
        assert count_gateway_active(session, ml_llm.gateway_host(GATEWAY), PERSONA) == 2


def test_concurrent_admissions_cannot_reserve_more_than_two_slots(harness, monkeypatch):
    sent = []
    monkeypatch.setattr(ml_llm, "_enqueue", lambda job: sent.append(job) or "celery-test")
    targets = [harness.register(model_id=f"test/concurrent-{i}") for i in range(5)]
    with ThreadPoolExecutor(max_workers=5) as pool:
        handles = list(pool.map(lambda target: admit(harness, target), targets))
    assert sum(not handle.deferred for handle in handles) == 2
    assert len(sent) == 2


def test_dispatch_failure_preserves_deferral(harness, monkeypatch):
    monkeypatch.setenv("REDSIM_LLM_PROBE_MAX_CONCURRENT_PER_GATEWAY", "1")
    monkeypatch.setattr(ml_llm, "_enqueue", lambda job: "celery-test")
    first = admit(harness, harness.register(model_id="test/first"))
    second = admit(harness, harness.register(model_id="test/second"))
    with harness.get_session() as session:
        session.get(Job, first.job_ids[0]).status = "succeeded"
    def fail_send(job):
        raise RuntimeError("synthetic broker failure")
    with harness.get_session() as session:
        report = dispatch_deferred(session, enqueue=fail_send, audit_writer=harness.writer)
    assert report.n_dispatched == 0
    assert harness.row(Job, second.job_ids[0]).detail["deferred"] is True


def test_llm_batch_parallel_bound(monkeypatch):
    monkeypatch.setenv("REDSIM_LLM_PROBE_MAX_CONCURRENT_PER_GATEWAY", "2")
    target = SimpleNamespace(detail={"endpoint_kind": "llm"})
    assert cap_batch_parallel(9, [target]) == 2
    assert cap_batch_parallel(None, [target]) == 2
    assert cap_batch_parallel(1, [target]) == 1
    assert cap_batch_parallel(9, [SimpleNamespace(detail={"modality": "image"})]) == 9


def test_capacity_api_exposes_gateway_limit(api, monkeypatch):
    monkeypatch.setenv("REDSIM_LLM_PROBE_MAX_CONCURRENT_PER_GATEWAY", "3")
    response = api.call(ADMIN, "GET", f"/v1/ml/capacity?project={PROJECT}")
    assert response.status_code == 200
    assert response.json()["limits"]["llm_probe_max_concurrent_per_gateway"] == 3


def test_probe_completion_dispatches_waiting_gateway_jobs(harness, monkeypatch):
    from redsim.workers.tasks.capacity import deferred_continuation
    sent = []
    monkeypatch.setattr(ml_llm, "_enqueue", lambda job: sent.append(job) or "celery-test")
    handles = [admit(harness, harness.register(model_id=f"test/hook-{i}")) for i in range(3)]
    with deferred_continuation(handles[0].job_ids[0]):
        with harness.get_session() as session:
            session.get(Job, handles[0].job_ids[0]).status = "succeeded"
    assert len(sent) == 3
    assert not harness.row(Job, handles[2].job_ids[0]).detail["deferred"]
