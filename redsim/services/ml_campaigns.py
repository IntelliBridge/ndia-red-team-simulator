"""Admission and persistence helpers for adversarial-ML campaigns."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from redsim.ml.schema import CampaignConfig
from redsim.safety import authorize

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CampaignJobHandle:
    """A handle that remains compatible when campaign admission grows jobs."""

    run_id: str
    job_ids: list[str]

    def to_response(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "job_ids": list(self.job_ids),
            "status_url": f"/v1/runs/{self.run_id}",
        }


def _campaign_table(session: Session) -> Any:
    """Reflect the migration-owned table without requiring an ORM model."""
    from sqlalchemy import MetaData, Table

    return Table("ml_campaigns", MetaData(), autoload_with=session.get_bind())


def create_attack_campaign(
    *,
    campaign: CampaignConfig | dict[str, Any],
    project_id: str,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
    enqueue: bool = True,
    run_id: str | None = None,
) -> CampaignJobHandle:
    """Audit first, then atomically admit one whole-campaign ``attack.run`` job."""
    from redsim.db.models import Job, Run, Target
    from redsim.db.session import get_session

    frozen = (campaign if isinstance(campaign, CampaignConfig)
              else CampaignConfig.model_validate(campaign))
    with get_session() as sess:
        target = sess.get(Target, frozen.target_id)
        if target is None or target.project_id != project_id:
            raise LookupError(f"model_not_found: ML target not found in project: {frozen.target_id}")
        detail = getattr(target, "detail", None) or {}
        target_status = detail.get("status") if isinstance(detail, dict) else None
        if target_status != "available":
            raise ValueError(
                f"model_unavailable: ML target {frozen.target_id!r} is not available "
                f"(status={target_status!r})"
            )
        manifest = detail.get("manifest") if isinstance(detail, dict) else {}
        manifest = manifest if isinstance(manifest, dict) else {}
        target_modality = detail.get("modality") or manifest.get("modality")
        if target_modality and target_modality != frozen.modality:
            raise ValueError(
                "modality_mismatch: campaign modality does not match the model manifest"
            )
        model_sha256 = detail.get("sha256") or manifest.get("sha256")
        target_snapshot = {
            "id": target.id,
            "kind": target.kind,
            "value": str(target.value),
            "detail": detail,
        }

    from redsim.ml.attacks.registry import get_attack
    from redsim.ml.scoring import settings_hash

    attack_infos = []
    resolved_params: dict[str, dict[str, float | int | bool]] = {}
    for attack_id in frozen.attack_ids:
        try:
            adapter = get_attack(attack_id)
        except KeyError as exc:
            raise ValueError(f"unknown_attack: unknown attack {attack_id!r}") from exc
        info = adapter.info()
        if info.status != "available":
            raise ValueError(
                f"attack_unavailable: attack {attack_id!r} is not available"
            )
        if info.domain != frozen.modality:
            raise ValueError(
                f"attack_incompatible: attack {attack_id!r} does not support "
                f"{frozen.modality}"
            )
        gradients = detail.get("gradients", manifest.get("gradients"))
        if info.requires_gradients and gradients is False:
            raise ValueError(
                f"gradients_required: attack {attack_id!r} requires model gradients"
            )
        try:
            resolved_params[attack_id] = adapter.resolve_params(
                frozen.attack_params.get(attack_id, {})
            )
        except ValueError as exc:
            raise ValueError(
                f"params_out_of_range: invalid parameters for {attack_id!r}: {exc}"
            ) from exc
        attack_infos.append(info)
    frozen = frozen.model_copy(update={
        "attack_params": resolved_params,
        "attacks": attack_infos,
        "target_snapshot": target_snapshot,
    })
    run_id = run_id or f"run-{uuid4().hex[:12]}"
    job_id = f"job-{uuid4().hex[:12]}"
    snapshot = frozen.model_dump(mode="json")
    frozen_settings_hash = settings_hash(frozen, model_sha256)

    # This must precede all Run/Job/campaign rows. ML campaigns target a
    # registered model rather than an active network location, hence target=None.
    authorize(
        "attack.run", None, allowlist=config.target_allowlist,
        actor=actor, writer=audit_writer, project_id=project_id, run_id=run_id,
        detail={
            "actor": actor, "target_id": frozen.target_id,
            "attack_ids": list(frozen.attack_ids),
            "dataset_id": frozen.dataset_id,
            "dataset_revision": frozen.dataset_revision,
            "model_sha256": model_sha256,
            "settings_hash": frozen_settings_hash,
            "config": snapshot,
        },
    )

    with get_session() as sess:
        target = sess.get(Target, frozen.target_id)
        if target is None or target.project_id != project_id:
            raise LookupError(f"model_not_found: ML target not found in project: {frozen.target_id}")
        sess.add(Run(
            id=run_id, project_id=project_id, target_id=frozen.target_id,
            mode="api", status="queued", scanner="ml.campaign",
            created_by=actor, stage_table={"stage": None, "stages_done": [], "jobs": {}},
        ))
        sess.flush()
        sess.add(Job(
            id=job_id, run_id=run_id, project_id=project_id,
            type="attack.run", status="queued", created_by=actor,
            # Full immutable input, not a pointer to mutable target/config state.
            detail={"campaign_config": snapshot},
        ))
        sess.flush()
        table = _campaign_table(sess)
        sess.execute(table.insert().values(
            run_id=run_id, project_id=project_id, target_id=frozen.target_id,
            kind="attack", modality=frozen.modality, config=snapshot,
            limitations=[],
        ))

    if enqueue:
        try:
            from redsim.workers.tasks.ml_campaign import ml_campaign_run
            ml_campaign_run.delay(job_id)
        except Exception:
            logger.warning("enqueue failed for ML campaign job %s", job_id, exc_info=True)
    return CampaignJobHandle(run_id=run_id, job_ids=[job_id])


def persist_campaign_record(session: Session, run_id: str, record: Any) -> None:
    """Project a completed CampaignRecord onto the queryable campaign row."""
    from sqlalchemy import update

    table = _campaign_table(session)
    session.execute(
        update(table).where(table.c.run_id == run_id).values(
            settings_hash=record.settings_hash,
            provenance=(record.provenance.model_dump(mode="json")
                        if record.provenance is not None else None),
            score=(record.score.model_dump(mode="json") if record.score is not None else None),
            limitations=list(record.limitations),
            completed_at=record.completed_at,
        )
    )


def create_verify_campaign(
    *,
    finding_id: str,
    defense_id: str,
    params: dict[str, Any],
    recommendation_id: str,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
) -> CampaignJobHandle:
    """Audit and admit a defense evaluation as a separate ML campaign."""
    from sqlalchemy import select

    from redsim.db.models import Artifact, Finding, Job, Run
    from redsim.db.session import get_session
    from redsim.ml.defenses import (
        get_defense,
        resolve_defense_params,
    )
    from redsim.ml.schema import MLFindingDetail

    with get_session() as sess:
        finding = sess.get(Finding, finding_id)
        if finding is None:
            raise LookupError("finding not found")
        schema_blob = dict(finding.schema_blob or {})
        ml_detail = MLFindingDetail.model_validate(schema_blob.get("ml") or {})
        recommendation = next(
            (
                item
                for item in ml_detail.recommendations
                if item.id == recommendation_id
            ),
            None,
        )
        if recommendation is None:
            raise ValueError(
                "recommendation_not_found: recommendation does not belong "
                "to this finding"
            )
        baseline = sess.get(Run, finding.run_id)
        if baseline is None:
            raise LookupError("baseline campaign not found")
        if baseline.status != "succeeded":
            raise ValueError("campaign_not_terminal: the baseline campaign is not terminal")
        active = sess.execute(select(Job).where(
            Job.project_id == finding.project_id,
            Job.type == "verify.replay",
            Job.status.in_(["queued", "running"]),
        )).scalars()
        if any((job.detail or {}).get("finding_id") == finding_id for job in active):
            raise ValueError("job_in_flight: a verification job is already active")
        table = _campaign_table(sess)
        baseline_campaign = sess.execute(
            table.select().where(table.c.run_id == baseline.id)
        ).mappings().one_or_none()
        if baseline_campaign is None:
            raise LookupError("baseline campaign record not found")
        baseline_artifact = sess.execute(select(Artifact).where(
            Artifact.run_id == baseline.id,
            Artifact.kind == "ml.run_record",
        )).scalar_one_or_none()
        if baseline_artifact is None:
            raise LookupError("baseline campaign record not found")
        baseline_location = str(baseline_artifact.location)
        baseline_sha256 = str(baseline_artifact.sha256)
        project_id = finding.project_id
        baseline_id = baseline.id

    from redsim.ml.schema import CampaignRecord
    from redsim.storage.blobs import open_blob_store

    baseline_bytes = open_blob_store().get(baseline_location)
    if isinstance(baseline_bytes, str):
        baseline_bytes = baseline_bytes.encode("utf-8")
    if hashlib.sha256(baseline_bytes).hexdigest() != baseline_sha256:
        raise ValueError(
            "campaign_artifact_digest_mismatch: baseline evidence digest mismatch"
        )
    baseline_record = CampaignRecord.model_validate_json(baseline_bytes)
    if baseline_record.run_id != baseline_id or baseline_record.score is None:
        raise ValueError(
            "baseline_evidence_invalid: baseline evidence is incomplete"
        )
    snapshot = baseline_record.config.model_dump(mode="json")
    spec = get_defense(defense_id)
    if spec["art_class"] not in recommendation.references:
        raise ValueError(
            "recommendation_defense_mismatch: the selected recommendation "
            "does not name this defense"
        )
    modality = str(snapshot.get("modality") or "")
    if modality not in spec["domains"]:
        raise ValueError(
            f"defense_modality_mismatch: defense {defense_id!r} "
            f"does not support {modality!r}"
        )
    resolved = resolve_defense_params(defense_id, params)
    snapshot["defense"] = {
        "id": defense_id,
        "art_class": spec["art_class"],
        "params": resolved,
    }
    frozen = CampaignConfig.model_validate(snapshot)
    frozen_json = frozen.model_dump(mode="json")
    run_id = f"run-{uuid4().hex[:12]}"
    job_id = f"job-{uuid4().hex[:12]}"
    target_id = frozen.target_id

    authorize(
        "verify.replay",
        None,
        allowlist=config.target_allowlist,
        actor=actor,
        writer=audit_writer,
        project_id=project_id,
        run_id=run_id,
        detail={
            "actor": actor,
            "finding_id": finding_id,
            "recommendation_id": recommendation_id,
            "baseline_run_id": baseline_id,
            "model_sha256": (
                baseline_record.provenance.model_sha256
                if baseline_record.provenance is not None else None
            ),
            "settings_hash": baseline_record.settings_hash,
            "defense": frozen_json["defense"],
        },
    )
    with get_session() as sess:
        finding = sess.get(Finding, finding_id)
        if finding is None:
            raise LookupError("finding not found")
        finding.status = "fixing"
        sess.add(Run(
            id=run_id,
            project_id=project_id,
            target_id=target_id,
            mode="api",
            status="queued",
            scanner="ml.verify",
            created_by=actor,
            stage_table={
                "stage": None,
                "stages_done": [],
                "baseline_run_id": baseline_id,
                "jobs": {},
            },
        ))
        sess.flush()
        sess.add(Job(
            id=job_id,
            run_id=run_id,
            project_id=project_id,
            type="verify.replay",
            status="queued",
            created_by=actor,
            detail={
                "finding_id": finding_id,
                "recommendation_id": recommendation_id,
                "baseline_run_id": baseline_id,
                "campaign_config": frozen_json,
            },
        ))
        sess.flush()
        table = _campaign_table(sess)
        sess.execute(table.insert().values(
            run_id=run_id,
            project_id=project_id,
            target_id=target_id,
            kind="verify",
            modality=frozen.modality,
            baseline_run_id=baseline_id,
            settings_hash=baseline_record.settings_hash,
            config=frozen_json,
            limitations=[],
        ))
    try:
        from redsim.workers.tasks.ml_campaign import ml_campaign_run

        queued = ml_campaign_run.delay(job_id)
        with get_session() as sess:
            job = sess.get(Job, job_id)
            if job is not None:
                job.celery_task_id = str(queued.id)
    except Exception:
        logger.warning("enqueue failed for ML verify job %s", job_id, exc_info=True)
    return CampaignJobHandle(run_id=run_id, job_ids=[job_id])


__all__ = [
    "CampaignJobHandle", "create_attack_campaign", "create_verify_campaign",
    "persist_campaign_record",
]