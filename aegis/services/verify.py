"""Verification orchestration service.

Phase 4 v0.3.1 F6: split into admission (``create_verify_job``) and
execution (``verify``). The admission entry point is what the API
write route calls; ``verify`` keeps its v0.3.0 signature so the CLI
and worker stay green in v0.3.1.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from aegis.config import AegisConfig
from aegis.safety import authorize
from aegis.schema import AegisFinding
from aegis.services.scans import JobHandle
from aegis.state import RunState
from aegis.verify import verify_finding


def create_verify_job(
    *,
    finding_id: str,
    project_id: str,
    run_id: str,
    actor: str,
    config: AegisConfig,
    audit_writer,
    enqueue: bool = True,
) -> JobHandle:
    """Admission boundary for ``verify.replay``."""
    authorize(
        "verify.replay", None,
        allowlist=config.target_allowlist,
        actor=actor, writer=audit_writer,
        project_id=project_id, run_id=run_id,
        detail={"actor": actor, "finding_id": finding_id},
    )

    from aegis.db.models import Job
    from aegis.db.session import get_session

    job_id = f"job-{uuid4().hex[:12]}"
    with get_session() as sess:
        sess.add(Job(
            id=job_id, run_id=run_id, project_id=project_id,
            type="verify.replay", status="queued", created_by=actor,
            detail={"finding_id": finding_id},
        ))
        sess.flush()

    if enqueue:
        try:
            from aegis.workers.tasks.verify import verify_replay
            verify_replay.delay(job_id)
        except Exception:
            pass

    return JobHandle(run_id=run_id, job_id=job_id)


@dataclass
class VerifyOutcome:
    finding_id: str
    status: str         # "verified" | "still_vulnerable" | "inconclusive"
    strategy: str
    evidence: dict[str, Any]
    notes: str


def verify(
    *,
    run_state: RunState,
    finding: AegisFinding,
    repo_path: Path | None,
    require_rebuilt: bool = True,
    require_source_rebuild: bool = True,
    actor: str,
    config: AegisConfig,
) -> VerifyOutcome:
    authorize(
        "verify.replay",
        finding.target or "localhost",
        allowlist=config.target_allowlist,
        run_path=run_state.run_path,
        detail={"actor": actor, "finding_id": finding.id,
                "require_rebuilt": require_rebuilt,
                "require_source_rebuild": require_source_rebuild},
    )
    result = verify_finding(
        finding,
        run_state=run_state,
        repo_path=repo_path,
        require_rebuilt=require_rebuilt,
        require_source_rebuild=require_source_rebuild,
    )
    return VerifyOutcome(
        finding_id=result.finding_id,
        status=result.status,
        strategy=result.strategy,
        evidence=result.evidence,
        notes=result.notes,
    )
