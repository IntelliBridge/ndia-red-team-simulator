"""Per-project ML capacity: concurrency deferral, the daily admission budget, the
continuation dispatcher and the numbers behind ``GET /v1/ml/capacity`` (register
BULK-20..22, plan 12 wave B3 ``bulk-upload-capacity-cli``).

Capacity is data, never broker introspection: every number here is a count over
the ``jobs`` table, so the API, the worker and the beat backstop all read the
same thing and a test can seed it with plain rows.

Two limits, two different postures (owner requirement 5):

* **Concurrency** (``Project.ml_max_concurrent_runs``, default
  ``REDSIM_ML_MAX_CONCURRENT_RUNS_PER_PROJECT`` = 2) never refuses. When the
  project already has that many ML campaign jobs live (``running``, or ``queued``
  and already handed to the broker), a new admission is *deferred*: its Run and
  Job rows are written exactly as usual, the job stays ``queued`` with
  ``detail.deferred = true`` and is not enqueued, and the response carries the
  ``capacity_deferred`` marker (a 202 body field, never a refusal:
  ``redsim.api.errors.MARKER_CODES``). :func:`dispatch_deferred` hands deferred
  jobs to the broker in admission order as slots free up; it runs at the end of
  every ``ml_campaign_run`` (the continuation hook,
  ``redsim.workers.tasks.capacity.continue_deferred``) and every 60 s from beat
  (the backstop, ``redsim.ml_dispatch_deferred``).
* **Daily budget** (``Project.ml_daily_run_budget``, default
  ``REDSIM_ML_DAILY_RUN_BUDGET``, unset = uncapped) counts *admissions* since UTC
  midnight (``attack.run`` and ``verify.replay`` jobs; a cancelled run still
  counts, deliberately). At or over the budget the admission is refused ``429
  daily_budget_exceeded`` with ``budget``, ``used``, ``requested``, ``resets_at``
  and ``retry_after``; the refusal writes its ``success=False`` audit row first
  when the caller hands in the writer.

The admission boundaries call :func:`admit_or_defer` before they write rows;
``redsim.services.ml_batches`` calls it once per member (the whole batch is
refused when the budget cannot take every member: the validate-all rule).

Nothing here imports FastAPI, Celery or an ML library: the API, the worker and
the CLI share it, and ``tests/test_api_process_has_no_ml.py`` keeps passing.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from redsim.api.errors import CAPACITY_DEFERRED, DAILY_BUDGET_EXCEEDED, ApiError, error_detail

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter

logger = logging.getLogger(__name__)

#: Deployment default for ``Project.ml_max_concurrent_runs`` when the column is NULL.
MAX_CONCURRENT_ENV = "REDSIM_ML_MAX_CONCURRENT_RUNS_PER_PROJECT"
DEFAULT_MAX_CONCURRENT_RUNS = 2
#: Deployment default for ``Project.ml_daily_run_budget`` when the column is NULL; unset = uncapped.
#: The register (BULK-20) spelled it ``REDSIM_ML_PROJECT_DAILY_RUN_BUDGET``; both names are read.
DAILY_BUDGET_ENV = "REDSIM_ML_DAILY_RUN_BUDGET"
DAILY_BUDGET_ENV_ALIAS = "REDSIM_ML_PROJECT_DAILY_RUN_BUDGET"

#: Job types that count against the daily budget: the two admission boundaries (BULK-21).
ML_ADMISSION_JOB_TYPES: tuple[str, ...] = ("attack.run", "verify.replay")
#: Job types that occupy a concurrency slot: everything ``redsim.ml_campaign_run`` executes.
ML_CAMPAIGN_JOB_TYPES: tuple[str, ...] = ("attack.run", "verify.replay", "explain.run", "harden.recommend")
#: ``kind`` values :func:`admit_or_defer` accepts, mapped onto the job type they admit.
ADMISSION_KINDS: dict[str, str] = {
    "attack": "attack.run", "campaign": "attack.run", "attack.run": "attack.run",
    "verify": "verify.replay", "verify.replay": "verify.replay",
    "explain": "explain.run", "explain.run": "explain.run",
    "harden": "harden.recommend", "harden.recommend": "harden.recommend",
}

#: ``Job.detail`` / ``Run.stage_table`` key set on a deferred admission.
DEFERRED_KEY = "deferred"
CAPACITY_KEY = "capacity"

#: Audit action of the continuation dispatcher's per-job row (<= 64 chars).
DISPATCH_ACTION = "batch.dispatch"


def _env_int(name: str, default: int | None) -> int | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 0 else default


def default_max_concurrent_runs() -> int:
    """``REDSIM_ML_MAX_CONCURRENT_RUNS_PER_PROJECT`` (default 2; never below 1)."""
    value = _env_int(MAX_CONCURRENT_ENV, DEFAULT_MAX_CONCURRENT_RUNS)
    return max(int(value if value is not None else DEFAULT_MAX_CONCURRENT_RUNS), 1)


def default_daily_run_budget() -> int | None:
    """``REDSIM_ML_DAILY_RUN_BUDGET`` (or the register's alias); ``None`` means uncapped."""
    value = _env_int(DAILY_BUDGET_ENV, None)
    if value is None:
        value = _env_int(DAILY_BUDGET_ENV_ALIAS, None)
    return value


@dataclass(frozen=True)
class CapacityCaps:
    """The effective limits of one project and where each came from (``project`` or ``default``)."""

    max_concurrent_runs: int
    daily_run_budget: int | None
    concurrency_source: str
    budget_source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_concurrent_runs": self.max_concurrent_runs,
            "daily_run_budget": self.daily_run_budget,
            "sources": {"max_concurrent_runs": self.concurrency_source, "daily_run_budget": self.budget_source},
        }


def effective_caps(project: Any) -> CapacityCaps:
    """The project's caps: its own columns when set, else the deployment defaults."""
    raw_cap = getattr(project, "ml_max_concurrent_runs", None)
    raw_budget = getattr(project, "ml_daily_run_budget", None)
    if isinstance(raw_cap, int) and raw_cap >= 1:
        cap, cap_source = raw_cap, "project"
    else:
        cap, cap_source = default_max_concurrent_runs(), "default"
    if isinstance(raw_budget, int) and raw_budget >= 0:
        budget: int | None = raw_budget
        budget_source = "project"
    else:
        budget, budget_source = default_daily_run_budget(), "default"
    return CapacityCaps(max_concurrent_runs=cap, daily_run_budget=budget,
                        concurrency_source=cap_source, budget_source=budget_source)


def utc_midnight(now: datetime | None = None) -> datetime:
    """The start of the current UTC day (the budget window's lower bound)."""
    current = (now or datetime.now(UTC)).astimezone(UTC)
    return current.replace(hour=0, minute=0, second=0, microsecond=0)


def budget_resets_at(now: datetime | None = None) -> datetime:
    """The next UTC midnight: when ``used_today`` drops to zero."""
    return utc_midnight(now) + timedelta(days=1)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _detail(job: Any) -> dict[str, Any]:
    value = getattr(job, "detail", None)
    return dict(value) if isinstance(value, Mapping) else {}


def is_deferred(job: Any) -> bool:
    """A queued job admission left with the broker untouched (``detail.deferred``)."""
    return bool(_detail(job).get(DEFERRED_KEY)) and getattr(job, "status", None) == "queued"


@dataclass
class ActiveCounts:
    """Live ML campaign jobs of one project, split the way the dispatcher needs them."""

    running: int = 0
    dispatched: int = 0        # queued and already enqueued (waiting in the broker)
    deferred: int = 0          # queued, not enqueued: waiting for a slot
    deferred_job_ids: list[str] = field(default_factory=list)

    @property
    def active(self) -> int:
        """Slots in use: running plus queued-and-enqueued jobs."""
        return self.running + self.dispatched

    def as_dict(self) -> dict[str, Any]:
        return {"running_jobs": self.running, "queued_jobs": self.dispatched + self.deferred,
                "deferred_runs": self.deferred, "active_runs": self.active}


def _live_jobs(session: Session, project_id: str) -> list[Any]:
    from sqlalchemy import select

    from redsim.db.models import Job

    return list(session.execute(
        select(Job).where(
            Job.project_id == project_id,
            Job.type.in_(ML_CAMPAIGN_JOB_TYPES),
            Job.status.in_(("queued", "running")),
        ).order_by(Job.created_at, Job.id)
    ).scalars().all())


def count_active(session: Session, project_id: str, *, exclude_job_ids: Iterable[str] = ()) -> ActiveCounts:
    """Running / dispatched / deferred ML campaign jobs of ``project_id`` from the jobs table.

    ``exclude_job_ids`` drops jobs whose terminal write is still in flight (the
    continuation hook runs while the finishing job is committed as ``running``).
    """
    excluded = set(exclude_job_ids)
    counts = ActiveCounts()
    for job in _live_jobs(session, project_id):
        if job.id in excluded:
            continue
        if job.status == "running":
            counts.running += 1
        elif is_deferred(job):
            counts.deferred += 1
            counts.deferred_job_ids.append(str(job.id))
        else:
            counts.dispatched += 1
    return counts


def used_today(session: Session, project_id: str, *, now: datetime | None = None) -> int:
    """Admissions (``attack.run`` + ``verify.replay`` jobs) created in ``project_id`` since UTC midnight."""
    from sqlalchemy import func, select

    from redsim.db.models import Job

    since = utc_midnight(now)
    value = session.execute(
        select(func.count()).select_from(Job).where(
            Job.project_id == project_id,
            Job.type.in_(ML_ADMISSION_JOB_TYPES),
            Job.created_at >= since,
        )
    ).scalar_one()
    return int(value or 0)


@dataclass(frozen=True)
class CapacityDecision:
    """What :func:`admit_or_defer` decided for one admission (never a refusal: those raise)."""

    project_id: str
    kind: str
    job_type: str
    deferred: bool
    active: int
    max_concurrent_runs: int
    used_today: int
    daily_run_budget: int | None
    requested: int
    resets_at: str
    reason: str | None = None

    def marker(self) -> dict[str, Any]:
        """The ``capacity_deferred`` 202 marker for the response body (empty when not deferred)."""
        if not self.deferred:
            return {}
        return error_detail(
            CAPACITY_DEFERRED,
            f"admitted; {self.active} of {self.max_concurrent_runs} concurrent ML runs are in use, dispatch "
            "waits for a free slot",
            active_runs=self.active, max_concurrent_runs=self.max_concurrent_runs,
        )

    def response_fields(self) -> dict[str, Any]:
        """Additive response keys: ``deferred`` plus the marker under ``capacity`` when deferred."""
        out: dict[str, Any] = {"deferred": self.deferred}
        marker = self.marker()
        if marker:
            out["capacity"] = marker
        return out

    def stamp(self) -> dict[str, Any]:
        """What the Run / Job rows record about the decision (counts and timestamps only)."""
        return {
            "deferred": self.deferred, "reason": self.reason, "active_runs": self.active,
            "max_concurrent_runs": self.max_concurrent_runs, "used_today": self.used_today,
            "daily_run_budget": self.daily_run_budget, "decided_at": _iso(datetime.now(UTC)),
        }


def budget_refusal(*, budget: int, used: int, requested: int, now: datetime | None = None) -> ApiError:
    """The ``429 daily_budget_exceeded`` envelope with ``budget``, ``used``, ``requested``, ``resets_at``."""
    resets = budget_resets_at(now)
    current = (now or datetime.now(UTC)).astimezone(UTC)
    retry_after = max(int((resets - current).total_seconds()), 1)
    return ApiError(
        DAILY_BUDGET_EXCEEDED,
        f"the project's daily ML run budget of {budget} admission(s) is spent ({used} used today, {requested} "
        f"requested); it resets at {_iso(resets)}",
        budget=budget, used=used, requested=requested, resets_at=_iso(resets), retry_after=retry_after,
    )


def admit_or_defer(
    session: Session,
    project: Any,
    kind: str,
    *,
    requested: int = 1,
    now: datetime | None = None,
    actor: str | None = None,
    audit_writer: AuditWriter | None = None,
    action: str | None = None,
    exclude_job_ids: Iterable[str] = (),
    **context: Any,
) -> CapacityDecision:
    """Decide whether one admission of ``kind`` may be enqueued now, deferred, or refused.

    ``project`` is the ``Project`` row or its id. ``requested`` is how many
    admissions the caller is about to make against the budget (a batch passes
    its member count once, so the whole batch is refused when the budget cannot
    take it). Raises :class:`ApiError` ``daily_budget_exceeded`` (429) when
    ``used_today + requested`` exceeds the budget; with ``audit_writer`` given the
    ``success=False`` row (``action``, default ``attack.run`` for the kind's
    boundary) is written on the project chain before the raise, carrying ids and
    counts only. Concurrency never refuses: over the cap the decision is
    ``deferred`` and the caller writes its rows with ``enqueue=False`` and calls
    :func:`mark_deferred`.
    """
    from redsim.db.models import Project

    job_type = ADMISSION_KINDS.get(kind)
    if job_type is None:
        raise ValueError(f"unknown admission kind {kind!r}; one of {sorted(ADMISSION_KINDS)}")
    if isinstance(project, str):
        row = session.get(Project, project)
        project_id = project
    else:
        row = project
        project_id = str(getattr(project, "id"))
    caps = effective_caps(row)
    used = used_today(session, project_id, now=now) if job_type in ML_ADMISSION_JOB_TYPES else 0
    resets = budget_resets_at(now)
    if (caps.daily_run_budget is not None and job_type in ML_ADMISSION_JOB_TYPES
            and used + max(int(requested), 1) > caps.daily_run_budget):
        exc = budget_refusal(budget=caps.daily_run_budget, used=used, requested=requested, now=now)
        if audit_writer is not None:
            detail: dict[str, Any] = {
                "refused": True, "code": exc.code, "http_status": exc.status, "reason": str(exc),
                "kind": kind, "job_type": job_type, "budget": caps.daily_run_budget, "used_today": used,
                "requested": requested, "resets_at": _iso(resets), "budget_source": caps.budget_source,
            }
            if actor is not None:
                detail["actor"] = actor
            for key, value in context.items():
                if value is not None:
                    detail[key] = value
            audit_writer.append(
                action=action or job_type, actor=actor or "system:capacity", target=None,
                allowlist_check="n/a", override=False, success=False, detail=detail,
                run_id=None, project_id=project_id,
            )
        raise exc
    counts = count_active(session, project_id, exclude_job_ids=exclude_job_ids)
    deferred = counts.active >= caps.max_concurrent_runs
    reason = (f"{counts.active} of {caps.max_concurrent_runs} concurrent ML runs in use"
              if deferred else None)
    return CapacityDecision(
        project_id=project_id, kind=kind, job_type=job_type, deferred=deferred, active=counts.active,
        max_concurrent_runs=caps.max_concurrent_runs, used_today=used, daily_run_budget=caps.daily_run_budget,
        requested=max(int(requested), 1), resets_at=_iso(resets), reason=reason,
    )


def mark_deferred(session: Session, *, run_id: str, job_id: str, decision: CapacityDecision) -> None:
    """Stamp a queued admission as deferred: ``Job.detail.deferred``, ``Run.stage_table.deferred`` (+ counts)."""
    from redsim.db.models import Job, Run

    stamp = decision.stamp()
    job = session.get(Job, job_id)
    if job is not None:
        detail = _detail(job)
        detail[DEFERRED_KEY] = True
        detail[CAPACITY_KEY] = stamp
        job.detail = detail
    run = session.get(Run, run_id)
    if run is not None:
        table = dict(getattr(run, "stage_table", None) or {})
        table[DEFERRED_KEY] = True
        table[CAPACITY_KEY] = stamp
        run.stage_table = table
    session.flush()


def _clear_deferred(session: Session, job: Any, *, dispatched_at: datetime) -> None:
    from redsim.db.models import Run

    detail = _detail(job)
    detail[DEFERRED_KEY] = False
    capacity = dict(detail.get(CAPACITY_KEY) or {})
    capacity["deferred"] = False
    capacity["dispatched_at"] = _iso(dispatched_at)
    detail[CAPACITY_KEY] = capacity
    job.detail = detail
    run = session.get(Run, job.run_id)
    if run is not None:
        table = dict(getattr(run, "stage_table", None) or {})
        table[DEFERRED_KEY] = False
        run_capacity = dict(table.get(CAPACITY_KEY) or {})
        run_capacity["deferred"] = False
        run_capacity["dispatched_at"] = _iso(dispatched_at)
        table[CAPACITY_KEY] = run_capacity
        run.stage_table = table
    session.flush()


def _restore_deferred(session: Session, job_id: str, error: str) -> None:
    from redsim.db.models import Job, Run

    job = session.get(Job, job_id)
    if job is None:
        return
    detail = _detail(job)
    detail[DEFERRED_KEY] = True
    capacity = dict(detail.get(CAPACITY_KEY) or {})
    capacity["deferred"] = True
    capacity.pop("dispatched_at", None)
    capacity["last_dispatch_error"] = error[:200]
    detail[CAPACITY_KEY] = capacity
    job.detail = detail
    run = session.get(Run, job.run_id)
    if run is not None:
        table = dict(getattr(run, "stage_table", None) or {})
        table[DEFERRED_KEY] = True
        run.stage_table = table
    session.flush()


def default_enqueue(job_id: str) -> str | None:
    """Hand a deferred campaign job to the broker (``redsim.ml_campaign_run``); the Celery task id."""
    from redsim.workers.tasks.ml_campaign import ml_campaign_run

    queued = ml_campaign_run.delay(job_id)
    task_id = getattr(queued, "id", None)
    return str(task_id) if task_id is not None else None


@dataclass
class DispatchReport:
    """What one dispatcher pass did, per project (counts and ids only)."""

    dispatched: dict[str, list[str]] = field(default_factory=dict)
    still_deferred: dict[str, int] = field(default_factory=dict)
    failed: dict[str, list[str]] = field(default_factory=dict)
    active: dict[str, int] = field(default_factory=dict)

    @property
    def n_dispatched(self) -> int:
        return sum(len(ids) for ids in self.dispatched.values())

    def as_dict(self) -> dict[str, Any]:
        return {
            "dispatched": {k: list(v) for k, v in self.dispatched.items()},
            "still_deferred": dict(self.still_deferred),
            "failed": {k: list(v) for k, v in self.failed.items()},
            "active": dict(self.active),
            "n_dispatched": self.n_dispatched,
        }


def projects_with_deferred_jobs(session: Session) -> list[str]:
    """Project ids holding at least one deferred queued campaign job (scanned from the jobs table)."""
    from sqlalchemy import select

    from redsim.db.models import Job

    rows = session.execute(
        select(Job).where(Job.type.in_(ML_CAMPAIGN_JOB_TYPES), Job.status == "queued")
    ).scalars().all()
    return sorted({str(job.project_id) for job in rows if is_deferred(job)})


def dispatch_project(
    session: Session,
    project_id: str,
    *,
    enqueue: Callable[[str], str | None] | None = None,
    exclude_job_ids: Iterable[str] = (),
    audit_writer: AuditWriter | None = None,
    actor: str = "system:capacity",
    report: DispatchReport | None = None,
    now: datetime | None = None,
) -> DispatchReport:
    """Enqueue the project's deferred jobs, oldest first, while a concurrency slot is free.

    Each dispatch clears the deferred flag and commits before the broker call
    (the platform's rows-before-enqueue order); a broker failure restores the
    flag so the backstop retries it. With ``audit_writer`` a ``batch.dispatch``
    row (ids and counts) precedes each enqueue on the job's run chain.
    """
    from redsim.db.models import Job, Project

    report = report or DispatchReport()
    send = enqueue or default_enqueue
    project = session.get(Project, project_id)
    caps = effective_caps(project)
    counts = count_active(session, project_id, exclude_job_ids=exclude_job_ids)
    active = counts.active
    dispatched: list[str] = []
    failed: list[str] = []
    for job_id in counts.deferred_job_ids:
        if active >= caps.max_concurrent_runs:
            break
        job = session.get(Job, job_id)
        if job is None or not is_deferred(job):
            continue
        dispatched_at = now or datetime.now(UTC)
        _clear_deferred(session, job, dispatched_at=dispatched_at)
        if audit_writer is not None:
            audit_writer.append(
                action=DISPATCH_ACTION, actor=actor, target=None, allowlist_check="n/a", override=False,
                success=True, run_id=str(job.run_id), project_id=project_id,
                detail={"actor": actor, "job_id": job_id, "run_id": str(job.run_id), "job_type": str(job.type),
                        "active_runs": active, "max_concurrent_runs": caps.max_concurrent_runs,
                        "dispatched_at": _iso(dispatched_at)},
            )
        session.commit()
        try:
            task_id = send(job_id)
        except Exception as exc:  # noqa: BLE001 - any broker failure leaves the job deferred for the backstop
            logger.warning("capacity: enqueue of deferred job %s failed; kept deferred", job_id, exc_info=True)
            _restore_deferred(session, job_id, f"{type(exc).__name__}: {exc}")
            session.commit()
            failed.append(job_id)
            continue
        if task_id is not None:
            live = session.get(Job, job_id)
            if live is not None:
                live.celery_task_id = task_id
            session.commit()
        dispatched.append(job_id)
        active += 1
    if dispatched:
        report.dispatched[project_id] = dispatched
    if failed:
        report.failed[project_id] = failed
    remaining = count_active(session, project_id, exclude_job_ids=exclude_job_ids)
    report.still_deferred[project_id] = remaining.deferred
    report.active[project_id] = remaining.active
    return report


def dispatch_deferred(
    session: Session,
    *,
    project_id: str | None = None,
    enqueue: Callable[[str], str | None] | None = None,
    exclude_job_ids: Iterable[str] = (),
    audit_writer: AuditWriter | None = None,
    now: datetime | None = None,
) -> DispatchReport:
    """One dispatcher pass over ``project_id`` (or every project holding deferred jobs)."""
    report = DispatchReport()
    targets = [project_id] if project_id is not None else projects_with_deferred_jobs(session)
    for pid in targets:
        dispatch_project(session, pid, enqueue=enqueue, exclude_job_ids=exclude_job_ids,
                         audit_writer=audit_writer, report=report, now=now)
    return report


# ---------------------------------------------------------------------------
# Read side: the capacity view and the gauges
# ---------------------------------------------------------------------------


def project_capacity(session: Session, project: Any, *, now: datetime | None = None) -> dict[str, Any]:
    """The ``project`` block of ``GET /v1/ml/capacity``: caps, live counts, budget use, reset time."""
    from redsim.db.models import Project

    if isinstance(project, str):
        row = session.get(Project, project)
        project_id = project
    else:
        row = project
        project_id = str(getattr(project, "id"))
    caps = effective_caps(row)
    counts = count_active(session, project_id)
    used = used_today(session, project_id, now=now)
    remaining = None if caps.daily_run_budget is None else max(caps.daily_run_budget - used, 0)
    return {
        "project_id": project_id,
        **caps.as_dict(),
        **counts.as_dict(),
        "slots_free": max(caps.max_concurrent_runs - counts.active, 0),
        "used_today": used,
        "budget_remaining": remaining,
        "resets_at": _iso(budget_resets_at(now)),
        "budget_window": "admissions (attack.run + verify.replay jobs) since 00:00 UTC; cancelled runs count",
    }


def global_capacity(session: Session) -> dict[str, Any]:
    """Deployment-wide counts from the jobs table (system callers only; never per tenant)."""
    from sqlalchemy import func, select

    from redsim.db.models import Job

    def _count(*conditions: Any) -> int:
        return int(session.execute(select(func.count()).select_from(Job).where(*conditions)).scalar_one() or 0)

    queued_rows = session.execute(
        select(Job).where(Job.type.in_(ML_CAMPAIGN_JOB_TYPES), Job.status == "queued")
    ).scalars().all()
    deferred = sum(1 for job in queued_rows if is_deferred(job))
    return {
        "running_jobs": _count(Job.status == "running"),
        "queued_jobs": _count(Job.status == "queued"),
        "ml_running_jobs": _count(Job.type.in_(ML_CAMPAIGN_JOB_TYPES), Job.status == "running"),
        "ml_queued_jobs": len(queued_rows),
        "ml_deferred_runs": deferred,
        "workers_hint": "worker pool sizes are not read from the broker; see /metrics and REDSIM_WORKER_CONCURRENCY",
    }


def sample_gauges(session: Session, *, now: datetime | None = None) -> dict[str, Any]:
    """Fill the Prometheus gauges from the jobs table (the dispatcher and the beat backstop call this).

    ``redsim_jobs_active`` = every ``running`` job in the deployment;
    ``redsim_ml_deferred_runs{project}`` and ``redsim_ml_daily_budget_used{project}``
    per project that has any ML campaign job today or live. Never raises.
    """
    from sqlalchemy import select

    from redsim.db.models import Job

    sample: dict[str, Any] = {"jobs_active": 0, "deferred": {}, "budget_used": {}}
    try:
        from sqlalchemy import func

        sample["jobs_active"] = int(session.execute(
            select(func.count()).select_from(Job).where(Job.status == "running")
        ).scalar_one() or 0)
        since = utc_midnight(now)
        rows = session.execute(
            select(Job.project_id).where(
                Job.type.in_(ML_CAMPAIGN_JOB_TYPES),
                (Job.status.in_(("queued", "running"))) | (Job.created_at >= since),
            ).distinct()
        ).scalars().all()
        for project_id in sorted({str(pid) for pid in rows}):
            counts = count_active(session, project_id)
            sample["deferred"][project_id] = counts.deferred
            sample["budget_used"][project_id] = used_today(session, project_id, now=now)
    except Exception:  # noqa: BLE001 - telemetry never breaks the caller
        logger.warning("capacity: gauge sample failed", exc_info=True)
        return sample
    try:
        from redsim.observability import set_capacity_gauges

        set_capacity_gauges(jobs_active=sample["jobs_active"], deferred_by_project=sample["deferred"],
                            budget_used_by_project=sample["budget_used"])
    except Exception:  # noqa: BLE001
        logger.warning("capacity: gauge set failed", exc_info=True)
    return sample


__all__ = [
    "ADMISSION_KINDS",
    "CAPACITY_KEY",
    "DAILY_BUDGET_ENV",
    "DAILY_BUDGET_ENV_ALIAS",
    "DEFAULT_MAX_CONCURRENT_RUNS",
    "DEFERRED_KEY",
    "DISPATCH_ACTION",
    "MAX_CONCURRENT_ENV",
    "ML_ADMISSION_JOB_TYPES",
    "ML_CAMPAIGN_JOB_TYPES",
    "ActiveCounts",
    "CapacityCaps",
    "CapacityDecision",
    "DispatchReport",
    "admit_or_defer",
    "budget_refusal",
    "budget_resets_at",
    "count_active",
    "default_daily_run_budget",
    "default_enqueue",
    "default_max_concurrent_runs",
    "dispatch_deferred",
    "dispatch_project",
    "effective_caps",
    "global_capacity",
    "is_deferred",
    "mark_deferred",
    "project_capacity",
    "projects_with_deferred_jobs",
    "sample_gauges",
    "used_today",
    "utc_midnight",
]
