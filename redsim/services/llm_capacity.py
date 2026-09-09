"""Gateway/persona probe slots shared across projects (brief 13 L2).

Postgres advisory transaction locks serialize reservation and commit. A local
lock provides the equivalent for sqlite development. The sole RLS-unscoped
admission query returns a count, never another tenant's jobs or target data;
the original tenant GUC is restored immediately after it.
"""
from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.services.ml_capacity import DispatchReport

MAX_CONCURRENT_ENV = "REDSIM_LLM_PROBE_MAX_CONCURRENT_PER_GATEWAY"
_SQLITE_LOCK = threading.RLock()


def gateway_cap(environ: Mapping[str, str] | None = None) -> int:
    raw = (os.environ if environ is None else environ).get(MAX_CONCURRENT_ENV, "2")
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return 2


def gateway_key(host: str, persona: str | None) -> tuple[str, str]:
    return host.strip().lower(), (persona or "").strip() or "default"


@contextmanager
def gateway_lock(session: Session, host: str, persona: str | None) -> Iterator[None]:
    """The caller must commit the reservation before leaving this scope."""
    from sqlalchemy import text

    if session.get_bind().dialect.name == "postgresql":
        key = "\0".join(gateway_key(host, persona)).encode()
        lock_id = int.from_bytes(hashlib.sha256(key).digest()[:8], "big", signed=True)
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_id})
        yield  # Postgres releases at transaction end, not context exit.
    else:
        with _SQLITE_LOCK:
            yield


def count_gateway_active(session: Session, host: str, persona: str | None,
                         *, exclude_job_ids: Iterable[str] = ()) -> int:
    from sqlalchemy import func, or_, select, text

    from redsim.db.models import Job

    host, persona = gateway_key(host, persona)
    statement = select(func.count()).select_from(Job).where(
        Job.type == "llm.probe", Job.status.in_(("queued", "running")),
        func.lower(Job.detail["gateway_host"].as_string()) == host,
        func.coalesce(func.nullif(Job.detail["persona"].as_string(), ""), "default") == persona,
        or_(Job.status == "running", Job.detail["deferred"].as_boolean().is_not(True)),
        Job.id.not_in(tuple(exclude_job_ids)),
    )
    if session.get_bind().dialect.name != "postgresql":
        return int(session.execute(statement).scalar_one())
    previous = session.execute(text("SELECT current_setting('app.current_tenants', true)")).scalar_one()
    session.execute(text("SELECT set_config('app.current_tenants', '', true)"))
    try:
        return int(session.execute(statement).scalar_one())
    finally:
        session.execute(text("SELECT set_config('app.current_tenants', :value, true)"), {"value": previous or ""})


def capacity_marker(active: int, cap: int) -> dict[str, Any]:
    from redsim.api.errors import CAPACITY_DEFERRED, error_detail
    return error_detail(CAPACITY_DEFERRED, "admitted; waiting for a gateway/persona probe slot",
                        active_runs=active, max_concurrent_runs=cap)


def cap_batch_parallel(value: int | None, targets: Iterable[Any]) -> int | None:
    if any((getattr(target, "detail", None) or {}).get("endpoint_kind") == "llm" for target in targets):
        return min(value, gateway_cap()) if value is not None else gateway_cap()
    return value


def dispatch_gateway_deferred(session: Session, *, report: DispatchReport,
                              enqueue: Callable[[str], str | None] | None = None,
                              exclude_job_ids: Iterable[str] = (),
                              audit_writer: AuditWriter | None = None) -> None:
    """Reserve pending probe slots across projects, then send to the default queue.

    Called in the worker's system scope by the existing capacity sweep. A
    failed broker call restores deferral for the next sweep. No key is loaded.
    """
    from sqlalchemy import select

    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.db.models import Job
    from redsim.services.ml_capacity import _clear_deferred, _restore_deferred, is_deferred
    from redsim.services.ml_llm import _enqueue

    send = enqueue or _enqueue
    candidates = list(session.execute(select(Job.id).where(
        Job.type == "llm.probe", Job.status == "queued",
        Job.detail["deferred"].as_boolean().is_(True),
    ).order_by(Job.created_at, Job.id)).scalars())
    writer = audit_writer
    for job_id in candidates:
        job = session.get(Job, job_id)
        if job is None:
            continue
        detail = dict(job.detail or {})
        host, persona = gateway_key(str(detail.get("gateway_host") or ""), detail.get("persona"))
        with gateway_lock(session, host, persona):
            session.refresh(job)
            if not is_deferred(job):
                session.commit()
                continue
            active = count_gateway_active(session, host, persona, exclude_job_ids=exclude_job_ids)
            cap = gateway_cap()
            project_id = str(job.project_id)
            if active >= cap:
                report.still_deferred[project_id] = report.still_deferred.get(project_id, 0) + 1
                session.commit()
                continue
            writer = writer or resolve_writer(load_config())
            writer.append(action="batch.dispatch", actor="system:capacity", target=None,
                          allowlist_check="n/a", override=False, success=True,
                          run_id=str(job.run_id), project_id=project_id,
                          detail={"job_id": job_id, "job_type": "llm.probe", "gateway_host": host,
                                  "persona": persona, "active_runs": active, "max_concurrent_runs": cap})
            _clear_deferred(session, job, dispatched_at=datetime.now(UTC))
            session.commit()
        try:
            task_id = send(job_id)
        except Exception as exc:  # broker failures leave the reservation queued for the backstop
            writer.append(action="batch.dispatch", actor="system:capacity", target=None,
                          allowlist_check="n/a", override=False, success=False,
                          run_id=str(job.run_id), project_id=project_id,
                          detail={"job_id": job_id, "job_type": "llm.probe", "deferred": True,
                                  "error_class": type(exc).__name__})
            _restore_deferred(session, job_id, type(exc).__name__)
            session.commit()
            report.failed.setdefault(project_id, []).append(job_id)
            continue
        if task_id is not None:
            job.celery_task_id = task_id
            session.commit()
        report.dispatched.setdefault(project_id, []).append(job_id)
