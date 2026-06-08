"""Scan orchestration service.

Phase 4 v0.3.1 F6 splits this layer into two boundaries:

- **Admission** (``create_scan_job``): authorize → create ``Run`` +
  ``Job`` rows → emit a chained audit event via the supplied
  ``audit_writer`` → enqueue the Celery task. Cheap, synchronous,
  request-scoped. Called from API write routes and the CLI's
  ``--api`` dispatch. The audit row's ``created_at`` precedes the
  worker setting the job's ``celery_task_id``, so the chain remains
  consistent even if the worker crashes mid-task.
- **Execution** (``execute_scan_job`` / ``start_scan``): the long-
  running scanner subprocess + finding persistence. Called from
  Celery workers (and, for backward compat, the CLI's offline path).

The existing ``start_scan`` keeps its v0.3.0 signature so the CLI's
offline ``aegis scan`` flow doesn't break in v0.3.1; F11 will rename
it to ``execute_scan_job`` and wire the worker task body to call it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from aegis.config import AegisConfig
from aegis.safety import authorize
from aegis.schema import AegisFinding

if TYPE_CHECKING:
    from aegis.audit.chain import AuditWriter
    from aegis.state import RunStateAPI

logger = logging.getLogger(__name__)


@dataclass
class ScanOutcome:
    success: bool
    partial_success: bool
    findings: list[AegisFinding]
    scanner: str
    return_code: int | None = None
    error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class JobHandle:
    """Return value of admission services.

    F6 contract: by the time this object exists the chain row is on
    disk / in Postgres, the Run + Job DB rows are flushed, and the
    Celery task has been published (or, if no broker is configured,
    the Job sits in ``queued`` for a later worker pickup). Callers
    can return ``status_url=/v1/runs/{run_id}`` immediately.
    """
    run_id: str
    job_id: str

    def to_response(self) -> dict[str, str]:
        """The admission JSON every job endpoint returns.

        One shared shape across scan / agent / fix / verify so clients get
        the same ``run_id`` + ``job_id`` + pollable ``status_url`` regardless
        of which admission route they hit.
        """
        return {
            "run_id": self.run_id,
            "job_id": self.job_id,
            "status_url": f"/v1/runs/{self.run_id}",
        }


def create_scan_job(
    *,
    target: str,
    scanner: str = "strix",
    project_id: str,
    actor: str,
    instruction: str | None = None,
    config: AegisConfig,
    allowlist: list[str] | None = None,
    audit_writer: AuditWriter,
    override_authorized: bool = False,
    enqueue: bool = True,
) -> JobHandle:
    """Admission boundary for ``scan.start``.

    Order of operations (load-bearing):

    1. ``authorize()`` — emits the chained ``scan.start`` row through
       ``audit_writer``. If the allowlist check fails this raises
       ``AuthorizationError`` *before* any DB row is created.
    2. Insert ``Run`` (flush — FK precedence), insert ``Job``.
    3. Enqueue the Celery task. ``celery_task_id`` is only stamped on
       the Job by the worker on pickup, so the chain row's ``ts``
       precedes the task-id assignment.

    A worker crash anywhere in step 3 leaves a chained audit row + a
    ``queued`` job — never a half-state. Idempotency for re-deliveries
    is the worker's job (F11).
    """
    authorize(
        "scan.start", target,
        allowlist=allowlist if allowlist is not None else config.target_allowlist,
        override_authorized=override_authorized,
        actor=actor, writer=audit_writer,
        project_id=project_id,
        detail={"actor": actor, "scanner": scanner, "target": target,
                "instruction_set": bool(instruction)},
    )

    from aegis.db.models import Job, Run
    from aegis.db.session import get_session

    run_id = f"run-{uuid4().hex[:12]}"
    job_id = f"job-{uuid4().hex[:12]}"
    with get_session() as sess:
        sess.add(Run(
            id=run_id, project_id=project_id, mode="api",
            status="queued", scanner=scanner, created_by=actor,
            stage_table={},
        ))
        sess.flush()
        sess.add(Job(
            id=job_id, run_id=run_id, project_id=project_id,
            type="scan.start", status="queued",
            created_by=actor,
            detail={"target": target, "scanner": scanner,
                    "instruction": instruction,
                    "override_authorized": override_authorized},
        ))
        sess.flush()

    if enqueue:
        try:
            from aegis.workers.tasks.scan import scan_start
            scan_start.delay(job_id)
        except Exception:
            # Broker unreachable: row stays queued, picked up next start.
            logger.warning("enqueue failed for job %s", job_id, exc_info=True)

    return JobHandle(run_id=run_id, job_id=job_id)


def start_scan(
    *,
    run_state: RunStateAPI,
    target: str,
    scanner: str = "strix",
    instruction: str | None = None,
    timeout: int = 1800,
    actor: str,
    config: AegisConfig,
    override_authorized: bool = False,
    use_strix: bool = True,
) -> ScanOutcome:
    """Run a scan against ``target`` and return a structured outcome.

    For Phase 2 / 3 the only live scanner is Strix; ``scanner`` is reserved
    for the M6 registry dispatch. When ``use_strix=False`` and an events
    file is later loaded by the caller, this function is a no-op shell that
    still emits the authorization audit so the chain is honest.
    """
    authorize(
        "scan.start",
        target,
        allowlist=config.target_allowlist,
        run_path=run_state.run_path,
        override_authorized=override_authorized,
        detail={"actor": actor, "scanner": scanner, "target": target,
                "instruction_set": bool(instruction)},
    )

    if not use_strix:
        return ScanOutcome(
            success=True, partial_success=False, findings=[],
            scanner=scanner, return_code=None,
            detail={"mode": "events-only"},
        )

    if scanner == "strix":
        from aegis.runners.strix_runner import run_strix
        result = run_strix(
            target, run_state,
            instruction=instruction,
            timeout=timeout,
            strix_command=getattr(config, "strix_command", None),
            strix_path=config.strix_path,
        )
        run_state.save_findings(result.findings)
        return ScanOutcome(
            success=result.success,
            partial_success=result.partial_success,
            findings=result.findings,
            scanner=scanner,
            return_code=result.return_code,
            error=result.error,
            detail={"command": result.command, "log_path": result.log_path,
                    "events_path": result.events_path},
        )

    from aegis.scanners import ScanOptions, dispatch
    scan_result = dispatch(
        scanner, run_state,
        ScanOptions(target=target, instruction=instruction, timeout=timeout),
    )
    run_state.save_findings(scan_result.findings)
    return ScanOutcome(
        success=(scan_result.exit_code == 0 and not scan_result.error),
        partial_success=bool(scan_result.findings) and scan_result.exit_code not in (0, None),
        findings=scan_result.findings,
        scanner=scanner,
        return_code=scan_result.exit_code,
        error=scan_result.error,
        detail={"command": scan_result.command_str,
                "adapter_version": scan_result.adapter_version,
                "duration_s": scan_result.duration_s},
    )
