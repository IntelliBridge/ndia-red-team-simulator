"""ML finding projections and follow-up action admissions.

The campaign record is the evidence authority. Follow-up actions are admitted
as child campaigns so they produce immutable evidence through the same worker.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal
from uuid import uuid4

from redsim.ml.schema import CampaignRecord, FindingReview, MLFindingDetail
from redsim.ml.scoring import finding_inputs
from redsim.safety import authorize
from redsim.schema import RedsimFinding

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig

logger = logging.getLogger(__name__)


_TERMINAL = {"succeeded", "failed", "cancelled"}
_SUPPORTED_MODALITIES = {"image", "tabular"}


class MLFindingAdmissionError(Exception):
    """A stable error returned by the ML finding admission routes."""

    def __init__(self, code: str, message: str, *, phase: str | None = None) -> None:
        super().__init__(message)
        self.code, self.phase = code, phase


@dataclass(frozen=True)
class FindingJobHandle:
    run_id: str
    job_ids: list[str]

    def to_response(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "job_ids": self.job_ids,
                "status_url": f"/v1/runs/{self.run_id}"}


def project_campaign_findings(session: Session, campaign: CampaignRecord) -> list[str]:
    """Project threshold-crossing attacks from a completed campaign once.

    Existing rows are left untouched.  This matters both for retry safety and
    because a later reviewer/verification update must never be overwritten by
    replaying the immutable campaign record.
    """
    from sqlalchemy import select

    from redsim.db.models import Finding, Run

    if campaign.status not in _TERMINAL:
        raise ValueError("only a terminal CampaignRecord can be projected")
    run = session.get(Run, campaign.run_id)
    if run is None:
        raise LookupError(f"campaign run not found: {campaign.run_id}")
    model_sha = (campaign.provenance.model_sha256 if campaign.provenance else None)
    if not model_sha or not campaign.settings_hash:
        raise ValueError("completed campaign lacks model_sha256 or settings_hash")

    attacks = {attack.id: attack for attack in campaign.attacks}
    projected: list[str] = []
    for attack_id in campaign.config.attack_ids:
        inputs = finding_inputs(campaign.config, campaign.measurements, attack_id)
        if not (inputs.crosses_threshold and inputs.denominator_ok and inputs.severity):
            continue
        scanner_id = f"ml.{attack_id}"
        existing = session.execute(
            select(Finding.id).where(Finding.run_id == campaign.run_id,
                                     Finding.scanner_finding_id == scanner_id)
        ).scalar_one_or_none()
        if existing is not None:
            projected.append(existing)
            continue
        info = attacks.get(attack_id)
        attack_name = info.name if info is not None else attack_id
        measurements = [m for m in campaign.measurements if m.attack_id == attack_id]
        measurement_ids = {m.id for m in measurements}
        # Observations do not carry an attack id.  They are campaign evidence
        # emitted by the explainer, so retain them rather than guessing a split.
        observations = list(campaign.observations)
        evidence_ids = measurement_ids | {o.id for o in observations}
        interpretation = [i for i in campaign.interpretation
                          if any(item in evidence_ids for item in i.basis)]
        recommendations = [r for r in campaign.recommendations
                           if any(item in evidence_ids for item in r.triggered_by)]
        artifacts = {name: artifact for o in observations for name, artifact in o.artifacts.items()}
        detail = MLFindingDetail(
            attack_id=attack_id, attack_name=attack_name, norm=campaign.config.norm,
            eps_grid=list(campaign.config.eps_grid),
            reference_eps=campaign.config.reference_eps,
            first_success_eps=inputs.first_success_eps,
            asr_at_reference=inputs.asr_at_reference,
            asr_by_eps=inputs.asr_by_eps, threshold=inputs.threshold,
            measurements=measurements, observations=observations,
            interpretation=interpretation, recommendations=recommendations,
            limitations=list(campaign.limitations), artifacts=artifacts,
        )
        now = datetime.now(UTC).isoformat()
        finding = RedsimFinding(
            id=scanner_id, title=f"{attack_name} adversarial vulnerability",
            severity=inputs.severity, finding_type="config",
            description="Attack measurement crossed the configured finding threshold.",
            source_tool=f"redsim.ml/{attack_id}", source_run_id=campaign.run_id,
            affected_component=campaign.target.id, confidence=inputs.confidence,
            status="open", created_at=now, updated_at=now,
            evidence=None, references=None,
        ).model_dump(mode="json")
        finding["ml"] = detail.model_dump(mode="json")
        row = Finding(
            id=str(uuid4()), scanner_finding_id=scanner_id, run_id=campaign.run_id,
            project_id=run.project_id, schema_blob=finding, status="open",
            severity=inputs.severity, source_tool=f"redsim.ml/{attack_id}",
            validation_state="unvalidated",
            dedup_key=f"ml:{model_sha[:16]}:{attack_id}:{campaign.settings_hash[:16]}",
        )
        session.add(row)
        session.flush()
        projected.append(row.id)
    return projected


def create_finding_action_job(
    *, finding_id: str, action: Literal["explain", "harden"], body: dict[str, Any],
    actor: str, config: RedsimConfig, audit_writer: AuditWriter,
) -> FindingJobHandle:
    """Audit first, then create one immutable follow-up Run and Job."""
    from sqlalchemy import MetaData, Table, select

    from redsim.db.models import Finding, Job, Run, Target
    from redsim.db.session import get_session
    from redsim.ml.schema import CampaignConfig

    job_type = "explain.run" if action == "explain" else "harden.recommend"
    with get_session() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise LookupError("finding not found")
        parent = session.get(Run, finding.run_id)
        if parent is None:
            raise LookupError("campaign run not found")
        if parent.status not in _TERMINAL:
            raise MLFindingAdmissionError("campaign_not_terminal",
                                          "the parent campaign is not terminal")
        target = session.get(Target, parent.target_id) if parent.target_id else None
        raw_manifest = getattr(target, "detail", None)
        manifest: dict[str, Any] = (
            raw_manifest if isinstance(raw_manifest, dict) else {}
        )
        nested_value = manifest.get("manifest")
        nested_manifest: dict[str, Any] = (
            nested_value if isinstance(nested_value, dict) else {}
        )
        modality = manifest.get("modality") or nested_manifest.get("modality")
        if modality not in _SUPPORTED_MODALITIES:
            raise MLFindingAdmissionError(
                "not_implemented", "this finding modality has no Phase A action implementation", phase="B")
        candidates = session.execute(
            select(Job).where(Job.project_id == finding.project_id, Job.type == job_type,
                              Job.status.in_(("queued", "running")))
        ).scalars()
        if any((job.detail or {}).get("finding_id") == finding_id for job in candidates):
            raise MLFindingAdmissionError("job_in_flight",
                                          f"a {job_type} job is already in flight for this finding")
        run_id, job_id = f"run-{uuid4().hex[:12]}", f"job-{uuid4().hex[:12]}"
        campaign_table = Table(
            "ml_campaigns", MetaData(), autoload_with=session.get_bind(),
        )
        parent_campaign = session.execute(
            campaign_table.select().where(campaign_table.c.run_id == parent.id)
        ).mappings().one_or_none()
        if parent_campaign is None:
            raise LookupError("campaign record not found")
        snapshot = dict(parent_campaign["config"])
        if action == "explain":
            requested = body.get("explain_k")
            snapshot["explain_k"] = (
                int(requested)
                if requested is not None
                else max(1, int(snapshot.get("explain_k") or 8))
            )
            if body.get("seed") is not None:
                snapshot["seed"] = int(body["seed"])
        else:
            snapshot["auto_recommend"] = True
            snapshot["llm_narrative"] = bool(body.get("llm_narrative", False))
        frozen = CampaignConfig.model_validate(snapshot).model_dump(mode="json")
        immutable = {
            "finding_id": finding_id,
            "parent_run_id": parent.id,
            "action": action,
            "action_config": dict(body),
            "campaign_config": frozen,
        }
        # The audit event is intentionally before either durable action row.
        authorize(job_type, None, allowlist=config.target_allowlist, actor=actor,
                  writer=audit_writer, project_id=finding.project_id, run_id=run_id,
                  detail={"actor": actor, **immutable})
        session.add(Run(id=run_id, project_id=finding.project_id, target_id=parent.target_id,
                        mode="api", status="queued", scanner=f"ml.{action}",
                        created_by=actor, stage_table={"parent_run_id": parent.id, "jobs": {}}))
        session.add(Job(id=job_id, run_id=run_id, project_id=finding.project_id, type=job_type,
                        status="queued", created_by=actor, detail=immutable))
        session.flush()
        session.execute(campaign_table.insert().values(
            run_id=run_id,
            project_id=finding.project_id,
            target_id=parent.target_id,
            kind="attack",
            modality=frozen["modality"],
            parent_run_id=parent.id,
            config=frozen,
            limitations=[],
        ))
    try:
        from redsim.workers.tasks.ml_campaign import ml_campaign_run

        result = ml_campaign_run.delay(job_id)
        with get_session() as session:
            job = session.get(Job, job_id)
            if job is not None:
                job.celery_task_id = str(result.id)
    except Exception:  # durable queued row survives broker outages
        # Durable queued state is intentionally recoverable after broker loss.
        logger.warning("enqueue failed for finding action job %s", job_id, exc_info=True)
    return FindingJobHandle(run_id, [job_id])


def review_finding(*, finding_id: str, expected_status: str, reason: str, actor: str,
                   config: RedsimConfig, audit_writer: AuditWriter) -> None:
    """Record the only user-owned ML status transition: dismissal."""
    from redsim.db.models import Finding, Run
    from redsim.db.session import get_session

    if not reason.strip():
        raise ValueError("reason is required")
    with get_session() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise LookupError("finding not found")
        parent = session.get(Run, finding.run_id)
        if parent is not None and parent.created_by == actor:
            raise PermissionError("campaign creator cannot review their own finding")
        if finding.status != expected_status:
            raise MLFindingAdmissionError("stale_status", "finding status no longer matches expected_status")
        authorize("finding.review", None, allowlist=config.target_allowlist, actor=actor,
                  writer=audit_writer, project_id=finding.project_id, run_id=finding.run_id,
                  detail={"actor": actor, "finding_id": finding_id, "reason": reason})
        blob = dict(finding.schema_blob)
        ml = dict(blob.get("ml") or {})
        if ml:
            detail = MLFindingDetail.model_validate(ml)
            detail.review = FindingReview(state="dismissed", reviewer=actor, reason=reason,
                                          at=datetime.now(UTC))
            blob["ml"] = detail.model_dump(mode="json")
        finding.schema_blob, finding.status = blob, "false_positive"
        session.flush()


__all__ = ["FindingJobHandle", "MLFindingAdmissionError", "create_finding_action_job",
           "project_campaign_findings", "review_finding"]