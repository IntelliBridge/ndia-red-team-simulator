"""Report-rendering orchestration service.

Two branches share the ``redsim.report_render`` task:

* the retained filesystem branch (:func:`render_reports`) renders the
  ``RedsimFinding`` list of a run into ``report.md`` / ``report.json`` /
  ``report.html`` under the run path;
* the adversarial-ML branch (:func:`render_campaign_report_artifacts`,
  spec 14.8, register G-REPRENDER) re-renders a campaign from its authoritative
  ``ml.run_record`` artifact plus the mutable overlays a reviewer can change
  after the run finished (``ml_campaigns.reviewer_notes``) and records the
  reports as ``Artifact`` rows the report route serves. The ``report.render``
  audit row is written before any artifact row.

Phase B (plan 12 wave B2, reports-compare-weights; REVIEW_REPORTS-16, -20, -21,
-22) adds to the ML branch:

* ``report.pdf`` as a fourth format (``redsim.ml.pdf``, imported on the worker only);
* one immutable ``report_snapshots`` row per render (:func:`record_report_snapshot`)
  pointing at the content-addressed ``Artifact`` rows by id and carrying the
  digest of the ``CampaignRecord`` bytes it was projected from and the stamp
  printed in the documents; the bytes live in the artifacts, the row never
  changes except for the ``archived`` soft flag (:func:`set_snapshot_archived`),
  and nothing is ever deleted;
* the audit-first admission of an on-demand render
  (:func:`create_report_render_job`): the ``report.render`` audit row precedes
  the ``Job`` row and the enqueue, refusals go on the chain as ``success=False``
  rows, and a run that is not terminal or already has a render in flight is
  refused with the spec 17.3 codes.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from redsim.api.errors import CAMPAIGN_NOT_TERMINAL, JOB_IN_FLIGHT, PARAMS_OUT_OF_RANGE, ApiError
from redsim.schema import RedsimFinding

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig
    from redsim.state import RunStateAPI
    from redsim.storage.blobs import BlobStore

logger = logging.getLogger(__name__)

# The kind the worker's artifact sink gives a report file, so the route finds
# both a completion-time report and a re-rendered one under the same name.
REPORT_KIND_PREFIX = "ml.report_"
#: Every format a render produces (Phase B adds ``pdf``; REVIEW_REPORTS-16).
REPORT_FORMATS: tuple[str, ...] = ("md", "json", "html", "pdf")
#: Audit action of a snapshot's soft archive flag (spec 5.11 naming style).
SNAPSHOT_ARCHIVE_ACTION = "report.snapshot.archive"
SNAPSHOT_RESTORE_ACTION = "report.snapshot.restore"
#: The admission action; the worker emits the same name when it renders (docs/architecture/audit-chain.md).
REPORT_RENDER_ACTION = "report.render"
REPORT_RENDER_JOB_TYPE = "report.render"
_TERMINAL = frozenset({"succeeded", "failed", "cancelled"})
_ACTIVE_JOB = ("queued", "running")


@dataclass
class ReportOutcome:
    markdown_path: str
    json_path: str
    html_path: str | None


@dataclass
class CampaignReportOutcome:
    """What the ML branch produced: one artifact per format, by extension, and the snapshot row."""

    run_id: str
    record_sha256: str
    formats: list[str]
    artifacts: dict[str, dict[str, Any]] = field(default_factory=dict)
    reviewer_notes_present: bool = False
    finding_states: dict[str, dict[str, Any]] = field(default_factory=dict)
    snapshot_id: str | None = None
    rendered_at: datetime | None = None

    def location(self, ext: str) -> str | None:
        entry = self.artifacts.get(ext)
        return None if entry is None else str(entry.get("location"))


@dataclass(frozen=True)
class ReportRenderHandle:
    """The 202 body of ``POST /v1/runs/{id}/report.render``."""

    run_id: str
    job_id: str
    formats: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "job_id": self.job_id, "job_ids": [self.job_id],
                "formats": list(self.formats), "status": "queued", "type": REPORT_RENDER_JOB_TYPE}


def render_reports(
    *,
    run_state: RunStateAPI,
    findings: list[RedsimFinding],
    html: bool = True,
) -> ReportOutcome:
    from redsim.report import save_reports

    logger.info("render_reports start run_id=%s findings=%d html=%s",
                run_state.run_id, len(findings), html)
    md_path, json_path = save_reports(run_state, findings, html=html)
    html_path = str(run_state.run_path / "report.html") if html else None
    logger.info("render_reports finished run_id=%s markdown=%s json=%s",
                run_state.run_id, md_path, json_path)
    return ReportOutcome(
        markdown_path=md_path,
        json_path=json_path,
        html_path=html_path,
    )


def ml_campaign_row(session: Session, run_id: str) -> dict[str, Any] | None:
    """The ``ml_campaigns`` row of ``run_id`` as a dict, or ``None`` when the run is
    not an ML campaign (or the table cannot be reflected on this connection)."""
    try:
        from sqlalchemy import MetaData, Table

        table = Table("ml_campaigns", MetaData(), autoload_with=session.get_bind())
        row = session.execute(table.select().where(table.c.run_id == run_id)).mappings().one_or_none()
    except Exception:  # noqa: BLE001 - a run without a campaign row is the pentest-era branch
        logger.debug("ml_campaigns lookup failed for run %s", run_id, exc_info=True)
        return None
    if row is None:
        return None
    result = dict(row)
    # A reflected row names its run; anything else is not a campaign row.
    return result if result.get("run_id") == run_id else None


def load_run_record(session: Session, blob_store: BlobStore, run_id: str) -> tuple[dict[str, Any], str]:
    """The newest ``ml.run_record`` artifact of ``run_id`` as parsed JSON plus its digest.

    The bytes are checked against the recorded sha256: a mismatch is a failure,
    never a report rendered from bytes that are not the record.
    """
    from sqlalchemy import select

    from redsim.db.models import Artifact

    row = session.execute(
        select(Artifact).where(Artifact.run_id == run_id, Artifact.kind == "ml.run_record")
        .order_by(Artifact.created_at.desc(), Artifact.id.desc())
    ).scalars().first()
    if row is None:
        raise LookupError(f"run {run_id} has no ml.run_record artifact")
    data = blob_store.get(str(row.location))
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != str(row.sha256):
        raise ValueError(f"ml.run_record bytes for run {run_id} do not match the recorded digest")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError(f"ml.run_record for run {run_id} is not a JSON object")
    return payload, digest


def finding_states(session: Session, run_id: str) -> dict[str, dict[str, Any]]:
    """``scanner_finding_id -> {status, validation_state, validated_at}`` for the run's findings."""
    from sqlalchemy import select

    from redsim.db.models import Finding

    rows = session.execute(select(Finding).where(Finding.run_id == run_id)).scalars().all()

    def _is_llm(row: Finding) -> bool:
        blob = row.schema_blob if isinstance(row.schema_blob, dict) else {}
        return str(blob.get("finding_kind") or blob.get("finding_type") or "") == "adversarial_llm"

    # Validation is the verify-after-harden outcome; an LLM probe finding has no
    # verify loop, so it carries no validation state (owner decision 2026-09-09).
    return {
        str(row.scanner_finding_id): {
            "status": row.status,
            "validation_state": None if _is_llm(row) else row.validation_state,
            "validated_at": None if _is_llm(row) else (row.validated_at.isoformat() if row.validated_at else None),
        }
        for row in rows
    }


# ---------------------------------------------------------------------------
# Snapshots (REVIEW_REPORTS-20, -22)
# ---------------------------------------------------------------------------


def _ext_of_kind(kind: str) -> str | None:
    """``md`` for ``ml.report_md`` or ``report.md``; ``None`` for a non-report kind."""
    if kind.startswith(REPORT_KIND_PREFIX):
        return kind[len(REPORT_KIND_PREFIX):]
    if kind.startswith("report."):
        return kind.split(".", 1)[1]
    return None


def record_report_snapshot(
    session: Session,
    *,
    run_id: str,
    project_id: str,
    artifact_ids: Sequence[str],
    record_sha256: str,
    created_by: str | None,
    rendered_at: datetime | None = None,
) -> Any:
    """Write the immutable ``report_snapshots`` row for one render and return it.

    Called after the report ``Artifact`` rows exist (they are what ``artifact_ids``
    names) and after the ``report.render`` audit row. The worker's completion path
    calls this with the ids its sink recorded; the re-render path below calls it
    itself. The row is content only: no label, no state beyond ``archived``.
    """
    from redsim.db.models import ReportSnapshot

    snapshot = ReportSnapshot(
        id=f"snap-{uuid4().hex[:16]}", run_id=run_id, project_id=project_id,
        artifact_ids=list(artifact_ids), record_sha256=record_sha256,
        rendered_at=rendered_at if rendered_at is not None else datetime.now(UTC),
        archived=False, created_by=created_by,
    )
    session.add(snapshot)
    session.flush()
    return snapshot


def _snapshot_rows(session: Session, run_id: str) -> list[Any]:
    from sqlalchemy import select

    from redsim.db.models import ReportSnapshot

    return list(session.execute(
        select(ReportSnapshot).where(ReportSnapshot.run_id == run_id)
        .order_by(ReportSnapshot.rendered_at.asc(), ReportSnapshot.id.asc())
    ).scalars().all())


def _artifacts_by_id(session: Session, ids: Sequence[str]) -> dict[str, Any]:
    from sqlalchemy import select

    from redsim.db.models import Artifact

    if not ids:
        return {}
    rows = session.execute(select(Artifact).where(Artifact.id.in_(list(ids)))).scalars().all()
    return {str(row.id): row for row in rows}


def snapshot_view(session: Session, snapshot: Any, version: int) -> dict[str, Any]:
    """The API shape of one snapshot row: ids, digests, sizes and the soft flag; never the bytes."""
    artifacts = _artifacts_by_id(session, list(snapshot.artifact_ids or []))
    formats: dict[str, dict[str, Any]] = {}
    for artifact_id in snapshot.artifact_ids or []:
        row = artifacts.get(str(artifact_id))
        if row is None:
            continue
        ext = _ext_of_kind(str(row.kind))
        if ext is None:
            continue
        formats[ext] = {"artifact_id": str(row.id), "kind": str(row.kind), "sha256": str(row.sha256),
                        "size_bytes": int(row.size_bytes or 0), "content_type": str(row.content_type)}
    rendered_at = snapshot.rendered_at
    return {
        "id": str(snapshot.id),
        "version": version,
        "run_id": str(snapshot.run_id),
        "project_id": str(snapshot.project_id),
        "rendered_at": rendered_at.isoformat() if rendered_at is not None else None,
        "record_sha256": str(snapshot.record_sha256),
        "created_by": snapshot.created_by,
        "archived": bool(snapshot.archived),
        "artifact_ids": [str(a) for a in (snapshot.artifact_ids or [])],
        "formats": formats,
    }


def list_snapshots(session: Session, run_id: str) -> list[dict[str, Any]]:
    """Every snapshot of ``run_id``, newest first, ``version`` counting from the first render."""
    rows = _snapshot_rows(session, run_id)
    views = [snapshot_view(session, row, index + 1) for index, row in enumerate(rows)]
    return list(reversed(views))


def resolve_snapshot(session: Session, run_id: str, ref: str) -> tuple[Any, int] | None:
    """The snapshot row named by ``ref`` (its id, or its 1-based chronological version) and its version."""
    rows = _snapshot_rows(session, run_id)
    for index, row in enumerate(rows):
        if str(row.id) == ref:
            return row, index + 1
    if ref.isdigit():
        version = int(ref)
        if 1 <= version <= len(rows):
            return rows[version - 1], version
    return None


def newest_snapshot(session: Session, run_id: str, *, include_archived: bool = False) -> tuple[Any, int] | None:
    rows = _snapshot_rows(session, run_id)
    for index in range(len(rows) - 1, -1, -1):
        row = rows[index]
        if include_archived or not bool(row.archived):
            return row, index + 1
    return None


def snapshot_artifact(session: Session, snapshot: Any, ext: str) -> Any | None:
    """The ``Artifact`` row of format ``ext`` inside ``snapshot``, or ``None``."""
    artifacts = _artifacts_by_id(session, list(snapshot.artifact_ids or []))
    for artifact_id in snapshot.artifact_ids or []:
        row = artifacts.get(str(artifact_id))
        if row is not None and _ext_of_kind(str(row.kind)) == ext:
            return row
    return None


def set_snapshot_archived(session: Session, snapshot: Any, archived: bool) -> bool:
    """Flip the soft flag; returns whether anything changed. Bytes and rows are never deleted."""
    if bool(snapshot.archived) == archived:
        return False
    snapshot.archived = archived
    session.flush()
    return True


# ---------------------------------------------------------------------------
# Render (worker side)
# ---------------------------------------------------------------------------


def render_campaign_report_artifacts(
    *,
    session: Session,
    blob_store: BlobStore,
    run_state: RunStateAPI,
    audit_writer: AuditWriter,
    actor: str,
    run_id: str,
    project_id: str,
    job_id: str,
    campaign: dict[str, Any] | None = None,
    formats: Sequence[str] | None = None,
) -> CampaignReportOutcome:
    """Re-render the campaign reports from the immutable record (spec 14.8) and snapshot them.

    Inputs: the newest ``ml.run_record`` artifact (digest-checked), the campaign
    row's ``reviewer_notes`` (the one field a reviewer changes after completion)
    and the run's finding states (recorded on the audit row and in the outcome;
    the report body itself is a function of the record). The ``report.render``
    audit event goes on the run chain before any artifact row is written; the
    ``report_snapshots`` row is written last, once every artifact row exists.
    """
    from sqlalchemy import select

    from redsim.db.models import Artifact
    from redsim.ml.reporting import render_campaign_reports
    from redsim.ml.schema import CampaignRecord
    from redsim.safety import authorize

    wanted = list(REPORT_FORMATS if formats is None else formats)
    campaign = campaign if campaign is not None else ml_campaign_row(session, run_id)
    payload, record_sha256 = load_run_record(session, blob_store, run_id)
    notes = campaign.get("reviewer_notes") if campaign else None
    if isinstance(notes, str):
        payload["reviewer_notes"] = notes
    record = CampaignRecord.model_validate(payload)
    states = finding_states(session, run_id)
    notes_bytes = notes.encode("utf-8") if isinstance(notes, str) else b""
    rendered_at = datetime.now(UTC)
    detail: dict[str, Any] = {
        "job_id": job_id,
        "formats": wanted,
        "source": "ml.run_record",
        "record_sha256": record_sha256,
        "reviewer_notes_sha256": hashlib.sha256(notes_bytes).hexdigest() if notes_bytes else None,
        "reviewer_notes_length": len(notes) if isinstance(notes, str) else 0,
        "finding_states": {k: v["validation_state"] for k, v in sorted(states.items()) if v["validation_state"] is not None},
        "finding_status": {k: v["status"] for k, v in sorted(states.items())},
        "rendered_at": rendered_at.isoformat(),
    }
    # Audit before the artifact rows exist (spec 10.5).
    authorize(REPORT_RENDER_ACTION, None, allowlist=[], actor=actor, writer=audit_writer,
              project_id=project_id, run_id=run_id, detail=detail)

    outcome = CampaignReportOutcome(
        run_id=run_id, record_sha256=record_sha256, formats=wanted,
        reviewer_notes_present=bool(notes_bytes), finding_states=states, rendered_at=rendered_at,
    )
    artifact_ids: list[str] = []
    for name, data, content_type in render_campaign_reports(record, generated_at=rendered_at, formats=wanted):
        ext = name.rsplit(".", 1)[-1]
        kind = f"{REPORT_KIND_PREFIX}{ext}"
        ref = run_state.record_artifact(kind, data, content_type=content_type)
        row = session.execute(
            select(Artifact).where(Artifact.run_id == run_id, Artifact.kind == kind, Artifact.sha256 == ref.sha256)
            .order_by(Artifact.created_at.desc(), Artifact.id.desc())
        ).scalars().first()
        artifact_id = str(row.id) if row is not None else None
        if artifact_id is not None:
            artifact_ids.append(artifact_id)
        outcome.artifacts[ext] = {
            "kind": kind, "sha256": ref.sha256, "location": ref.location,
            "size_bytes": ref.size_bytes, "content_type": ref.content_type, "artifact_id": artifact_id,
        }
    if artifact_ids:
        snapshot = record_report_snapshot(
            session, run_id=run_id, project_id=project_id, artifact_ids=artifact_ids,
            record_sha256=record_sha256, created_by=actor, rendered_at=rendered_at,
        )
        outcome.snapshot_id = str(snapshot.id)
    else:
        # A run state without Artifact rows (the filesystem backend) has nothing a
        # snapshot could point at; the render still happened, the row is not faked.
        logger.info("render_campaign_report_artifacts run_id=%s wrote no Artifact rows; no snapshot", run_id)
    logger.info("render_campaign_report_artifacts finished run_id=%s formats=%s snapshot=%s",
                run_id, outcome.formats, outcome.snapshot_id)
    return outcome


# ---------------------------------------------------------------------------
# Admission (REVIEW_REPORTS-21): audit first, then the Job row, then the enqueue
# ---------------------------------------------------------------------------


def _refuse_render(audit_writer: AuditWriter, *, actor: str, run_id: str, project_id: str,
                   detail: dict[str, Any], code: str, message: str) -> None:
    """A refused render request is still on the chain, as a ``success=False`` row."""
    audit_writer.append(
        action=REPORT_RENDER_ACTION, actor=actor, target=None, allowlist_check="n/a", override=False,
        success=False, detail={**detail, "refusal": code, "message": message},
        run_id=run_id, project_id=project_id,
    )


def _enqueue_report_render(job_id: str) -> str | None:
    """Enqueue the worker task; returns the celery task id. Imported lazily: the API stays celery-light."""
    from redsim.workers.tasks.report import report_render

    result = report_render.delay(job_id)
    return str(result.id) if result is not None else None


def validate_render_formats(formats: Any) -> list[str]:
    """The formats a render request asks for: ``None`` means every format; a subset must be known."""
    if formats is None:
        return list(REPORT_FORMATS)
    if not isinstance(formats, list) or not formats or not all(isinstance(f, str) for f in formats):
        raise ApiError(PARAMS_OUT_OF_RANGE, "formats must be a non-empty list of format names", field="formats")
    unknown = sorted(set(formats) - set(REPORT_FORMATS))
    if unknown:
        raise ApiError(PARAMS_OUT_OF_RANGE, f"unknown report formats: {unknown}", field="formats",
                       reasons=[f"choose from {list(REPORT_FORMATS)}"])
    return [f for f in REPORT_FORMATS if f in set(formats)]


def create_report_render_job(
    *, run_id: str, actor: str, config: RedsimConfig, audit_writer: AuditWriter,
    formats: Sequence[str] | None = None,
) -> ReportRenderHandle:
    """Admit an on-demand re-render: audit first, then one ``report.render`` Job on the terminal run.

    Order: run lookup (``LookupError`` -> 404), campaign lookup (``LookupError``),
    terminal check (``409 campaign_not_terminal``), in-flight check
    (``409 job_in_flight``), the ``report.render`` audit row, the ``Job`` row, the
    enqueue. Refusals after the lookups append a ``success=False`` row first. The
    run's own status is never touched (spec 6.2): a render is a follow-on job on a
    finished run, never a reopening.
    """
    from sqlalchemy import select

    from redsim.db.models import Job, Run
    from redsim.db.session import get_session
    from redsim.safety import authorize

    wanted = list(REPORT_FORMATS if formats is None else formats)
    job_id = f"job-{uuid4().hex[:12]}"
    with get_session() as session:
        run = session.get(Run, run_id)
        if run is None:
            raise LookupError("run not found")
        project_id = str(run.project_id)
        scanner = getattr(run, "scanner", None)
        campaign = ml_campaign_row(session, run_id)
        if campaign is None and not (isinstance(scanner, str) and scanner.startswith("ml.")):
            raise LookupError("campaign record not found")
        detail: dict[str, Any] = {
            "run_id": run_id, "job_id": job_id, "formats": wanted, "requested_by": actor,
            "run_status": str(run.status),
        }
        if run.status not in _TERMINAL:
            message = "the campaign has not reached a terminal status; reports render at completion"
            _refuse_render(audit_writer, actor=actor, run_id=run_id, project_id=project_id, detail=detail,
                           code=CAMPAIGN_NOT_TERMINAL, message=message)
            raise ApiError(CAMPAIGN_NOT_TERMINAL, message, status=str(run.status))
        in_flight = session.execute(
            select(Job).where(Job.run_id == run_id, Job.type == REPORT_RENDER_JOB_TYPE, Job.status.in_(_ACTIVE_JOB))
        ).scalars().first()
        if in_flight is not None:
            message = "a report.render job is already queued or running for this run"
            _refuse_render(audit_writer, actor=actor, run_id=run_id, project_id=project_id,
                           detail={**detail, "in_flight_job_id": str(in_flight.id)}, code=JOB_IN_FLIGHT,
                           message=message)
            raise ApiError(JOB_IN_FLIGHT, message, job_id=str(in_flight.id))
        # The audit event is intentionally before the durable Job row and the enqueue.
        authorize(REPORT_RENDER_ACTION, None, allowlist=list(config.target_allowlist), actor=actor,
                  writer=audit_writer, project_id=project_id, run_id=run_id,
                  detail={**detail, "phase": "admitted"})
        session.add(Job(id=job_id, run_id=run_id, project_id=project_id, type=REPORT_RENDER_JOB_TYPE,
                        status="queued", created_by=actor,
                        detail={"run_id": run_id, "formats": wanted, "requested_by": actor}))
        session.flush()
    try:
        task_id = _enqueue_report_render(job_id)
        if task_id is not None:
            with get_session() as session:
                job = session.get(Job, job_id)
                if job is not None:
                    job.celery_task_id = task_id
    except Exception:  # durable queued row survives broker outages
        # Durable queued state is intentionally recoverable after broker loss.
        logger.warning("enqueue failed for report.render job %s", job_id, exc_info=True)
    return ReportRenderHandle(run_id=run_id, job_id=job_id, formats=wanted)


__all__ = [
    "REPORT_FORMATS",
    "REPORT_KIND_PREFIX",
    "REPORT_RENDER_ACTION",
    "REPORT_RENDER_JOB_TYPE",
    "SNAPSHOT_ARCHIVE_ACTION",
    "SNAPSHOT_RESTORE_ACTION",
    "CampaignReportOutcome",
    "ReportOutcome",
    "ReportRenderHandle",
    "create_report_render_job",
    "finding_states",
    "list_snapshots",
    "load_run_record",
    "ml_campaign_row",
    "newest_snapshot",
    "record_report_snapshot",
    "render_campaign_report_artifacts",
    "render_reports",
    "resolve_snapshot",
    "set_snapshot_archived",
    "snapshot_artifact",
    "snapshot_view",
    "validate_render_formats",
]
