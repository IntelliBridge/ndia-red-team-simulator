"""Admission for the Croissant/Parquet export of a campaign run (INTEROP-08, -10, -11, -12).

Two functions are the contract the ``interop-consume`` track wires ``POST
/v1/runs/{id}/dataset`` and ``GET /v1/datasets/{id}`` to (imported lazily, so a
tree without this module degrades to ``501``):

* :func:`admit_export` is the audit-first admission boundary. It writes the
  ``dataset.export`` audit row before any durable row and before the enqueue,
  and puts the export job on a **follow-up** ``Run`` (scanner ``ml.dataset_export``)
  so the roll-up never reopens the terminal campaign. It refuses a run that is
  not a terminal, complete adversarial-ML campaign (``export_unavailable``), a
  fixture-only or partial run (``fixture_not_exportable``) and a run whose export
  is already queued or running (``export_in_flight``); a broker outage rolls the
  rows back and answers ``queue_unavailable``. One export per run: a run that
  already has an ``ml.dataset.manifest`` artifact returns that export instead of
  a duplicate job.
* :func:`get_export_manifest` returns the parsed Croissant manifest of an export
  (the ``{id}`` is the source run id), or ``None`` when the run has no export.

Every refusal writes a ``success=False`` ``dataset.export`` row; the audit detail
carries ids, digests and counts only — never a URL, key or model bytes. This
module keeps its imports ML-free so the API process can import it.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NoReturn
from uuid import uuid4

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig
    from redsim.storage import BlobStore

logger = logging.getLogger(__name__)

_TERMINAL: frozenset[str] = frozenset({"succeeded", "failed", "cancelled"})
_SLICE_KINDS = ("ml.adv_slice", "ml.clean_slice", "ml.control_slice")
_MANIFEST_KIND = "ml.dataset.manifest"
_EXPORT_JOB_TYPE = "dataset.export"
_EXPORT_SCANNER = "ml.dataset_export"
#: Public names for the inventory read (``services.ml_exports``); the values above are the contract.
EXPORT_SLICE_KINDS = _SLICE_KINDS
DATASET_EXPORT_JOB_TYPE = _EXPORT_JOB_TYPE
DATASET_EXPORT_SCANNER = _EXPORT_SCANNER


@dataclass
class ExportJobHandle:
    """The result of :func:`admit_export`.

    ``status`` is ``"queued"`` for a fresh export (``run_id``/``job_id`` name the
    follow-up run and job) or ``"exists"`` for the idempotent hit (``manifest_*``
    name the existing export). ``dataset_id`` is always the source run id.
    """

    dataset_id: str
    status: str
    run_id: str | None = None
    job_id: str | None = None
    manifest_artifact_id: str | None = None
    manifest_sha256: str | None = None

    def to_response(self) -> dict[str, Any]:
        body: dict[str, Any] = {"dataset_id": self.dataset_id, "status": self.status,
                                "type": _EXPORT_JOB_TYPE}
        if self.status == "exists":
            body.update({"manifest_artifact_id": self.manifest_artifact_id,
                         "manifest_sha256": self.manifest_sha256})
        else:
            body.update({"run_id": self.run_id, "job_id": self.job_id,
                         "job_ids": [self.job_id] if self.job_id else []})
        return body


# --------------------------------------------------------------------------- reads


def _open_store() -> BlobStore:
    from redsim.storage import open_blob_store

    return open_blob_store()


def _campaign_row(session: Session, run_id: str) -> dict[str, Any] | None:
    from redsim.services.reports import ml_campaign_row

    return ml_campaign_row(session, run_id)


def _is_fixture_target(session: Session, run: Any) -> bool:
    from redsim.db.models import Target

    if not run.target_id:
        return False
    target = session.get(Target, run.target_id)
    detail = getattr(target, "detail", None) if target is not None else None
    if not isinstance(detail, dict):
        return False
    raw_manifest = detail.get("manifest")
    manifest = raw_manifest if isinstance(raw_manifest, dict) else {}
    return bool(detail.get("fixture_only") or manifest.get("fixture_only")
                or detail.get("fixture") or manifest.get("fixture"))


def _has_slices(session: Session, run_id: str) -> bool:
    from sqlalchemy import func, select

    from redsim.db.models import Artifact

    count = session.execute(
        select(func.count()).select_from(Artifact)
        .where(Artifact.run_id == run_id, Artifact.kind.in_(_SLICE_KINDS))
    ).scalar()
    return bool(count)


def _manifest_artifact(session: Session, run_id: str) -> Any:
    from sqlalchemy import select

    from redsim.db.models import Artifact

    return session.execute(
        select(Artifact).where(Artifact.run_id == run_id, Artifact.kind == _MANIFEST_KIND)
        .order_by(Artifact.created_at.desc(), Artifact.id.desc())
    ).scalars().first()


def _export_job_in_flight(session: Session, source_run_id: str) -> bool:
    from sqlalchemy import select

    from redsim.db.models import Job

    jobs = session.execute(
        select(Job).where(Job.type == _EXPORT_JOB_TYPE, Job.status.in_(("queued", "running")))
    ).scalars()
    return any((job.detail or {}).get("source_run_id") == source_run_id for job in jobs)


# --------------------------------------------------------------------------- writes


def _stamp_task_id(job_id: str, task_id: str | None) -> None:
    if task_id is None:
        return
    from redsim.db.models import Job
    from redsim.db.session import get_session

    with get_session() as sess:
        job = sess.get(Job, job_id)
        if job is not None:
            job.celery_task_id = task_id


def _delete_export_rows(run_id: str, job_id: str) -> None:
    from redsim.db.models import Job, Run
    from redsim.db.session import get_session

    with get_session() as sess:
        job = sess.get(Job, job_id)
        if job is not None:
            sess.delete(job)
        run = sess.get(Run, run_id)
        if run is not None:
            sess.delete(run)


def _refuse(audit_writer: AuditWriter, *, actor: str, project_id: str, code: str, message: str,
            source_run_id: str, **context: Any) -> NoReturn:
    from redsim.api.errors import ApiError

    detail: dict[str, Any] = {"actor": actor, "refused": True, "code": code,
                              "source_run_id": source_run_id}
    detail.update({k: v for k, v in context.items() if v is not None})
    audit_writer.append(
        action="dataset.export", actor=actor, target=None, allowlist_check="n/a",
        override=False, success=False, detail=detail, run_id=None, project_id=project_id,
    )
    raise ApiError(code, message)


def admit_export(session: Session, run: Any, actor: str, *, audit_writer: AuditWriter,
                 config: RedsimConfig | None = None, include_card: bool = True,
                 blob_store: BlobStore | None = None) -> ExportJobHandle:
    """Audit-first admission for a dataset export. See the module docstring."""
    from redsim.api.errors import (
        EXPORT_IN_FLIGHT,
        EXPORT_UNAVAILABLE,
        FIXTURE_NOT_EXPORTABLE,
        QUEUE_UNAVAILABLE,
    )
    from redsim.db.models import Job, Run
    from redsim.db.session import get_session
    from redsim.safety import authorize
    from redsim.services.reports import load_run_record

    run_obj = run if hasattr(run, "id") else session.get(Run, run)
    if run_obj is None:
        raise LookupError("run not found")
    source_run_id = str(run_obj.id)
    project_id = str(run_obj.project_id)
    scanner = getattr(run_obj, "scanner", "") or ""

    def refuse(code: str, message: str, **ctx: Any) -> NoReturn:
        _refuse(audit_writer, actor=actor, project_id=project_id, code=code, message=message,
                source_run_id=source_run_id, **ctx)

    campaign = _campaign_row(session, source_run_id)
    if campaign is None and not scanner.startswith("ml."):
        refuse(EXPORT_UNAVAILABLE, "run is not an adversarial-ML campaign")

    status = getattr(run_obj, "status", None)
    if status != "succeeded":
        if status in ("failed", "cancelled"):
            refuse(FIXTURE_NOT_EXPORTABLE, "the run did not complete; a partial run is not exported")
        refuse(EXPORT_UNAVAILABLE, "the campaign has not reached a terminal status")

    if _is_fixture_target(session, run_obj):
        refuse(FIXTURE_NOT_EXPORTABLE, "runs on a CI fixture target are never exported")

    existing = _manifest_artifact(session, source_run_id)
    if existing is not None:
        # One export per run: return the existing export, no duplicate job.
        return ExportJobHandle(dataset_id=source_run_id, status="exists",
                               manifest_artifact_id=str(existing.id),
                               manifest_sha256=str(existing.sha256))

    if not _has_slices(session, source_run_id):
        refuse(EXPORT_UNAVAILABLE, "the run retained no adversarial slices to export")

    store = blob_store or _open_store()
    try:
        record_dict, _ = load_run_record(session, store, source_run_id)
    except Exception:  # noqa: BLE001 - no readable record means there is nothing to export
        refuse(EXPORT_UNAVAILABLE, "the run has no readable record to export")
    if record_dict.get("completeness") == "partial":
        refuse(FIXTURE_NOT_EXPORTABLE, "a partial run is not exported")
    modality = (record_dict.get("config") or {}).get("modality")

    if _export_job_in_flight(session, source_run_id):
        refuse(EXPORT_IN_FLIGHT, "a dataset export for this run is queued or running")

    run_id, job_id = f"run-{uuid4().hex[:12]}", f"job-{uuid4().hex[:12]}"
    allowlist = list(getattr(config, "target_allowlist", None) or [])
    detail = {"source_run_id": source_run_id, "include_card": bool(include_card), "modality": modality}

    with get_session() as sess:
        # Audit-first: the dataset.export row precedes the durable Run/Job rows.
        authorize(
            "dataset.export", None, allowlist=allowlist, actor=actor, writer=audit_writer,
            project_id=project_id, run_id=run_id,
            detail={"actor": actor, "source_run_id": source_run_id, "job_id": job_id,
                    "include_card": bool(include_card), "modality": modality},
        )
        sess.add(Run(id=run_id, project_id=project_id, target_id=run_obj.target_id, mode="api",
                     status="queued", scanner=_EXPORT_SCANNER, created_by=actor,
                     stage_table={"parent_run_id": source_run_id, "jobs": {}}))
        sess.add(Job(id=job_id, run_id=run_id, project_id=project_id, type=_EXPORT_JOB_TYPE,
                     status="queued", created_by=actor, detail=detail))
        sess.flush()

    try:
        from redsim.workers.tasks.dataset_export import dataset_export

        result = dataset_export.apply_async(args=[job_id], queue="scans")
        _stamp_task_id(job_id, getattr(result, "id", None))
    except Exception:  # noqa: BLE001 - broker outage: roll the rows back and answer 503
        logger.warning("enqueue failed for dataset export job %s; rolling back", job_id, exc_info=True)
        _delete_export_rows(run_id, job_id)
        refuse(QUEUE_UNAVAILABLE, "job queue is unavailable", follow_up_run_id=run_id)

    return ExportJobHandle(dataset_id=source_run_id, status="queued", run_id=run_id, job_id=job_id)


def get_export_manifest(session: Session, run_id: str, *, blob_store: BlobStore | None = None,
                        ) -> dict[str, Any] | None:
    """The parsed Croissant manifest of an exported dataset (the ``{id}`` is the source run id).

    ``None`` when the run has no export. The bytes are digest-checked against the
    ``ml.dataset.manifest`` artifact row: a mismatch is a failure, never a manifest
    served from bytes that are not the record.
    """
    row = _manifest_artifact(session, run_id)
    if row is None:
        return None
    store = blob_store or _open_store()
    data = store.get(str(row.location))
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if hashlib.sha256(raw).hexdigest() != str(row.sha256):
        raise ValueError(f"dataset manifest bytes for run {run_id} do not match the recorded digest")
    parsed = json.loads(raw)
    return parsed if isinstance(parsed, dict) else None


__all__ = ["DATASET_EXPORT_JOB_TYPE", "DATASET_EXPORT_SCANNER", "EXPORT_SLICE_KINDS", "ExportJobHandle",
           "admit_export", "get_export_manifest"]
