"""Report-rendering orchestration service.

Two branches share the ``redsim.report_render`` task:

* the retained filesystem branch (:func:`render_reports`) renders the
  ``RedsimFinding`` list of a run into ``report.md`` / ``report.json`` /
  ``report.html`` under the run path;
* the adversarial-ML branch (:func:`render_campaign_report_artifacts`,
  spec 14.8, register G-REPRENDER) re-renders a campaign from its authoritative
  ``ml.run_record`` artifact plus the mutable overlays a reviewer can change
  after the run finished (``ml_campaigns.reviewer_notes``) and records the
  three reports as ``Artifact`` rows the report route serves. The
  ``report.render`` audit row is written before any artifact row.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from redsim.schema import RedsimFinding

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.state import RunStateAPI
    from redsim.storage.blobs import BlobStore

logger = logging.getLogger(__name__)

# The kind the worker's artifact sink gives a report file, so the route finds
# both a completion-time report and a re-rendered one under the same name.
REPORT_KIND_PREFIX = "ml.report_"
REPORT_FORMATS: tuple[str, ...] = ("md", "json", "html")


@dataclass
class ReportOutcome:
    markdown_path: str
    json_path: str
    html_path: str | None


@dataclass
class CampaignReportOutcome:
    """What the ML branch produced: one artifact per format, by extension."""

    run_id: str
    record_sha256: str
    formats: list[str]
    artifacts: dict[str, dict[str, Any]] = field(default_factory=dict)
    reviewer_notes_present: bool = False
    finding_states: dict[str, dict[str, Any]] = field(default_factory=dict)

    def location(self, ext: str) -> str | None:
        entry = self.artifacts.get(ext)
        return None if entry is None else str(entry.get("location"))


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
    return {
        str(row.scanner_finding_id): {
            "status": row.status,
            "validation_state": row.validation_state,
            "validated_at": row.validated_at.isoformat() if row.validated_at else None,
        }
        for row in rows
    }


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
) -> CampaignReportOutcome:
    """Re-render the three campaign reports from the immutable record (spec 14.8).

    Inputs: the newest ``ml.run_record`` artifact (digest-checked), the campaign
    row's ``reviewer_notes`` (the one field a reviewer changes after completion)
    and the run's finding states (recorded on the audit row and in the outcome;
    the report body itself is a function of the record). The ``report.render``
    audit event goes on the run chain before any artifact row is written.
    """
    from redsim.ml.reporting import render_campaign_reports
    from redsim.ml.schema import CampaignRecord
    from redsim.safety import authorize

    campaign = campaign if campaign is not None else ml_campaign_row(session, run_id)
    payload, record_sha256 = load_run_record(session, blob_store, run_id)
    notes = campaign.get("reviewer_notes") if campaign else None
    if isinstance(notes, str):
        payload["reviewer_notes"] = notes
    record = CampaignRecord.model_validate(payload)
    states = finding_states(session, run_id)
    notes_bytes = notes.encode("utf-8") if isinstance(notes, str) else b""
    detail: dict[str, Any] = {
        "job_id": job_id,
        "formats": list(REPORT_FORMATS),
        "source": "ml.run_record",
        "record_sha256": record_sha256,
        "reviewer_notes_sha256": hashlib.sha256(notes_bytes).hexdigest() if notes_bytes else None,
        "reviewer_notes_length": len(notes) if isinstance(notes, str) else 0,
        "finding_states": {k: v["validation_state"] for k, v in sorted(states.items())},
        "finding_status": {k: v["status"] for k, v in sorted(states.items())},
    }
    # Audit before the artifact rows exist (spec 10.5).
    authorize("report.render", None, allowlist=[], actor=actor, writer=audit_writer,
              project_id=project_id, run_id=run_id, detail=detail)

    outcome = CampaignReportOutcome(
        run_id=run_id, record_sha256=record_sha256, formats=list(REPORT_FORMATS),
        reviewer_notes_present=bool(notes_bytes), finding_states=states,
    )
    for name, data, content_type in render_campaign_reports(record):
        ext = name.rsplit(".", 1)[-1]
        kind = f"{REPORT_KIND_PREFIX}{ext}"
        ref = run_state.record_artifact(kind, data, content_type=content_type)
        outcome.artifacts[ext] = {
            "kind": kind, "sha256": ref.sha256, "location": ref.location,
            "size_bytes": ref.size_bytes, "content_type": ref.content_type,
        }
    logger.info("render_campaign_report_artifacts finished run_id=%s formats=%s",
                run_id, outcome.formats)
    return outcome


__all__ = [
    "REPORT_FORMATS",
    "REPORT_KIND_PREFIX",
    "CampaignReportOutcome",
    "ReportOutcome",
    "finding_states",
    "load_run_record",
    "ml_campaign_row",
    "render_campaign_report_artifacts",
    "render_reports",
]
