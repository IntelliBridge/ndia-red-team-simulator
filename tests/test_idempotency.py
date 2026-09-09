"""``Idempotency-Key`` on the mutating ML routes (spec 17.3 Idempotency; F004 US1; REVIEW_REPORTS-31, -32).

Offline over the sqlite harness with the real app in dev auth and the caller
dependency overridden. The probe route is ``POST /v1/runs/{id}/report.render``:
a real audit-first admission that creates one ``Job`` row and needs no worker.

Pinned:

* the same key and body twice: one Job row, one successful admission audit row,
  the second response replays the first body with ``Idempotency-Replayed: true``;
* the same key with a different body: ``409 idempotency_key_reused``, no new Job;
* the same key from another principal, or no key at all: independent admissions;
* the stored row carries a digest, never the raw key, and the request digest;
* a refused admission (4xx) is not stored, so the key can be retried;
* an unknown run passes through to the route's 404 and stores nothing;
* a non-covered route and a read are untouched by the header;
* a key outside 1..255 characters is ``422``; a row older than the TTL is a miss.
"""

from __future__ import annotations

import hashlib
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
from redsim.api.middleware import idempotency as idem
from redsim.audit.chain import InMemoryAuditWriter
from redsim.db.models import IdempotencyKey, Job, Organization, Project, Run

pytestmark = pytest.mark.integration

PROJECT = "project-1"
RUN = "run-idem-1"
LIVE_RUN = "run-idem-live"

SCANNER = CurrentUser(sub="dev:scanner@test", email="scanner@test", project_memberships={PROJECT: "scanner"})
OTHER_SCANNER = CurrentUser(sub="dev:other@test", email="other@test", project_memberships={PROJECT: "scanner"})
VIEWER = CurrentUser(sub="dev:viewer@test", email="viewer@test", project_memberships={PROJECT: "viewer"})
ADMIN = CurrentUser(sub="dev:admin@test", email="admin@test", project_memberships={PROJECT: "admin"})


@pytest.fixture
def api(sqlite_session_factory: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Iterator[SimpleNamespace]:
    """The real app over sqlite with one project, a terminal ML run and a live one."""
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings

    with sqlite_session_factory.Session() as sess:
        sess.add(Organization(id="org-1", name="Org", slug="org"))
        sess.add(Project(id=PROJECT, org_id="org-1", name="Project", slug="p1"))
        sess.flush()
        sess.add(Run(id=RUN, project_id=PROJECT, mode="api", scanner="ml.campaign", status="succeeded",
                     stage_table={}))
        sess.add(Run(id=LIVE_RUN, project_id=PROJECT, mode="api", scanner="ml.campaign", status="running",
                     stage_table={}))
        sess.commit()

    monkeypatch.setattr("redsim.db.session.get_session", sqlite_session_factory.session_cm)
    writer = InMemoryAuditWriter()
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _config: writer)
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    enqueued: list[str] = []
    monkeypatch.setattr("redsim.services.reports._enqueue_report_render",
                        lambda job_id: enqueued.append(job_id) or f"task-{job_id}")

    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    app = create_app(APISettings(
        env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
        rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000,
    ))
    holder: dict[str, CurrentUser] = {"user": SCANNER}
    app.dependency_overrides[get_current_user] = lambda: holder["user"]
    client = TestClient(app)

    def call(user: CurrentUser, method: str, path: str, *, key: str | None = None,
             body: Any = None, **kwargs: Any) -> Any:
        holder["user"] = user
        headers = dict(kwargs.pop("headers", {}))
        if key is not None:
            headers[idem.HEADER] = key
        if body is not None:
            kwargs["json"] = body
        return client.request(method, path, headers=headers, **kwargs)

    def jobs() -> int:
        with sqlite_session_factory.Session() as sess:
            return int(sess.execute(select(func.count()).select_from(Job)).scalar_one())

    def rows() -> list[IdempotencyKey]:
        with sqlite_session_factory.Session() as sess:
            return list(sess.execute(select(IdempotencyKey)).scalars().all())

    yield SimpleNamespace(call=call, jobs=jobs, rows=rows, writer=writer, enqueued=enqueued,
                          Session=sqlite_session_factory.Session)
    rl._BUCKETS.clear()


def _admissions(writer: InMemoryAuditWriter) -> list[Any]:
    return [e for e in writer.events if e.action == "report.render" and e.success]


def test_same_key_and_body_replays_without_a_second_admission(api: SimpleNamespace) -> None:
    first = api.call(SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="key-1", body={})
    assert first.status_code == 202, first.text
    assert idem.REPLAYED_HEADER.lower() not in {k.lower() for k in first.headers}
    assert api.jobs() == 1 and len(_admissions(api.writer)) == 1 and api.enqueued == [first.json()["job_id"]]

    second = api.call(SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="key-1", body={})
    assert second.status_code == 202 and second.json() == first.json(), "the stored response is replayed"
    assert second.headers[idem.REPLAYED_HEADER] == "true"
    assert api.jobs() == 1, "no second Job row"
    assert len(_admissions(api.writer)) == 1, "no second admission audit row"
    assert api.enqueued == [first.json()["job_id"]], "no second enqueue"
    # The same JSON body with keys in another order, or no body, is the same request identity.
    third = api.call(SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="key-1",
                     content=b"{}", headers={"content-type": "application/json"})
    assert third.status_code == 202 and third.headers[idem.REPLAYED_HEADER] == "true"

    stored = api.rows()
    assert len(stored) == 1
    row = stored[0]
    assert row.project_id == PROJECT and row.route == f"POST /v1/runs/{RUN}/report.render"
    assert row.key != "key-1" and len(row.key) == 64, "the raw header value is never stored"
    assert row.key == idem.stored_key(f"sub:{SCANNER.sub}", "key-1")
    assert row.request_sha256 == idem.request_digest("POST", f"/v1/runs/{RUN}/report.render", b"", b"{}")
    assert row.response_status == 202 and row.response_body == first.json()


def test_same_key_different_body_is_refused_and_nothing_new_is_written(api: SimpleNamespace) -> None:
    first = api.call(SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="key-2", body={})
    assert first.status_code == 202, first.text
    events = len(api.writer.events)
    reused = api.call(SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="key-2", body={"formats": ["md"]})
    assert reused.status_code == 409, reused.text
    detail = reused.json()["detail"]
    assert detail["code"] == idem.IDEMPOTENCY_KEY_REUSED and detail["field"] == idem.HEADER
    assert api.jobs() == 1 and len(api.writer.events) == events, "the route never ran"
    # The same key on a different route is a reuse too (the route is part of the identity).
    other_route = api.call(SCANNER, "PATCH", f"/v1/runs/{RUN}/reviewer-notes", key="key-2",
                           body={"reviewer_notes": "x"})
    assert other_route.status_code == 409 and other_route.json()["detail"]["code"] == idem.IDEMPOTENCY_KEY_REUSED


def test_key_is_scoped_by_principal_and_absent_keys_admit_independently(api: SimpleNamespace) -> None:
    a = api.call(SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="shared", body={})
    assert a.status_code == 202, a.text
    # A second principal with the same key is a different identity; the run has a render in
    # flight, so the admission itself refuses (409 job_in_flight) rather than replaying a's job.
    b = api.call(OTHER_SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="shared", body={})
    assert b.status_code == 409 and b.json()["detail"]["code"] == "job_in_flight"
    assert b.headers.get(idem.REPLAYED_HEADER) is None
    assert [r.key for r in api.rows()] == [idem.stored_key(f"sub:{SCANNER.sub}", "shared")], \
        "a refused admission is not stored; the reservation was released"
    # Without a key every request is its own admission (spec 17.3 Phase A behaviour, unchanged).
    with api.Session() as sess:
        sess.get(Job, a.json()["job_id"]).status = "succeeded"
        sess.commit()
    c = api.call(SCANNER, "POST", f"/v1/runs/{RUN}/report.render", body={})
    assert c.status_code == 202 and c.json()["job_id"] != a.json()["job_id"]
    with api.Session() as sess:
        sess.get(Job, c.json()["job_id"]).status = "succeeded"
        sess.commit()
    d = api.call(OTHER_SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="shared", body={})
    assert d.status_code == 202 and d.json()["job_id"] not in {a.json()["job_id"], c.json()["job_id"]}
    assert api.jobs() == 3 and len(api.rows()) == 2
    # And the first principal's replay is still the first response.
    replay = api.call(SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="shared", body={})
    assert replay.json() == a.json() and replay.headers[idem.REPLAYED_HEADER] == "true"


def test_refusals_and_pass_throughs(api: SimpleNamespace) -> None:
    # A refused admission (the run is live) is not stored; the key stays usable.
    live = api.call(SCANNER, "POST", f"/v1/runs/{LIVE_RUN}/report.render", key="key-live", body={})
    assert live.status_code == 409 and live.json()["detail"]["code"] == "campaign_not_terminal"
    assert api.rows() == [] and api.jobs() == 0
    with api.Session() as sess:
        sess.get(Run, LIVE_RUN).status = "succeeded"
        sess.commit()
    retry = api.call(SCANNER, "POST", f"/v1/runs/{LIVE_RUN}/report.render", key="key-live", body={})
    assert retry.status_code == 202 and len(api.rows()) == 1

    # A role refusal (403) is not stored either.
    denied = api.call(VIEWER, "POST", f"/v1/runs/{RUN}/report.render", key="key-viewer", body={})
    assert denied.status_code == 403 and len(api.rows()) == 1

    # An unknown run passes through to the route's 404 and stores nothing.
    missing = api.call(SCANNER, "POST", "/v1/runs/no-such-run/report.render", key="key-missing", body={})
    assert missing.status_code == 404 and len(api.rows()) == 1

    # Reads and non-covered routes ignore the header entirely.
    read = api.call(SCANNER, "GET", f"/v1/runs/{RUN}/snapshots", key="key-read")
    assert read.status_code == 200 and idem.REPLAYED_HEADER.lower() not in {k.lower() for k in read.headers}
    settings = api.call(ADMIN, "PUT", "/v1/projects/p1/ml-scoring", key="key-settings", content=b"null",
                        headers={"content-type": "application/json"})
    assert settings.status_code == 200 and len(api.rows()) == 1
    assert not idem.is_covered("PUT", "/v1/projects/p1/ml-scoring") and idem.is_covered("POST", "/v1/models")
    assert idem.is_covered("POST", "/v1/findings/f/explain") and not idem.is_covered("GET", "/v1/models")

    # Key length bounds.
    too_long = api.call(SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="k" * 256, body={})
    assert too_long.status_code == 422 and too_long.json()["detail"]["code"] == "params_out_of_range"
    assert too_long.json()["detail"]["field"] == idem.HEADER
    assert api.jobs() == 1, "the route did not run"


def test_expired_rows_are_a_miss_and_reservations_block_a_concurrent_twin(api: SimpleNamespace) -> None:
    first = api.call(SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="key-ttl", body={})
    assert first.status_code == 202
    with api.Session() as sess:
        sess.get(Job, first.json()["job_id"]).status = "succeeded"
        row = api.rows()[0]
        stored = sess.get(IdempotencyKey, (row.project_id, row.key))
        stored.created_at = datetime.now(UTC) - idem.IDEMPOTENCY_TTL - timedelta(minutes=1)
        sess.commit()
    fresh = api.call(SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="key-ttl", body={})
    assert fresh.status_code == 202 and fresh.json()["job_id"] != first.json()["job_id"], "an expired row is a miss"
    assert fresh.headers.get(idem.REPLAYED_HEADER) is None
    assert len(api.rows()) == 1 and api.rows()[0].response_body == fresh.json()

    # A reservation whose route has not answered yet refuses its twin with idempotency_conflict.
    with api.Session() as sess:
        sess.get(Job, fresh.json()["job_id"]).status = "succeeded"
        row = api.rows()[0]
        stored = sess.get(IdempotencyKey, (row.project_id, row.key))
        stored.response_status = idem.RESERVED_STATUS
        stored.response_body = None
        sess.commit()
    twin = api.call(SCANNER, "POST", f"/v1/runs/{RUN}/report.render", key="key-ttl", body={})
    assert twin.status_code == 409 and twin.json()["detail"]["code"] == idem.IDEMPOTENCY_CONFLICT
    assert api.jobs() == 2, "the route did not run behind an open reservation"


def test_request_digest_is_canonical() -> None:
    a = idem.request_digest("POST", "/v1/x", b"b=2&a=1", b'{"k": 1, "j": [1, 2]}')
    b = idem.request_digest("post", "/v1/x", b"a=1&b=2", b'{"j":[1,2],"k":1}')
    assert a == b, "query order and JSON key order do not change the identity"
    assert idem.request_digest("POST", "/v1/x", b"", b"{}") != idem.request_digest("POST", "/v1/y", b"", b"{}")
    assert idem.request_digest("POST", "/v1/x", b"", b"{}") != idem.request_digest("POST", "/v1/x", b"", b'{"a":1}')
    assert idem.request_digest("POST", "/v1/x", b"", b"not json") == hashlib.sha256(
        b"POST\x00/v1/x\x00\x00not json\x00").hexdigest()
    assert idem.stored_key("sub:a", "k") != idem.stored_key("sub:b", "k")
