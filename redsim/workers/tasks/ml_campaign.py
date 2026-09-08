"""Celery wrapper for one complete adversarial-ML campaign."""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from redsim.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task
    from sqlalchemy.orm import Session

    from redsim.storage import BlobStore

logger = logging.getLogger(__name__)


class DatabaseArtifactSink:
    """ArtifactSink backed by content-addressed BlobStore and Artifact rows."""

    def __init__(self, session: Session, blob_store: BlobStore, *,
                 run_id: str, project_id: str) -> None:
        self.session = session
        self.blob_store = blob_store
        self.run_id = run_id
        self.project_id = project_id
        self._hashes: dict[str, str] = {}
        self.finalizing_run_record = False

    @staticmethod
    def _kind(name: str) -> str:
        if name == "run_record.json":
            return "ml.run_record"
        if name == "score.json":
            return "ml.score"
        if name == "flip_matrix.json":
            return "ml.flip_matrix"
        if name.startswith("curve/"):
            return "ml.curve"
        if name.startswith("adv_slice/"):
            return "ml.adv_slice"
        if name.startswith("report."):
            return f"ml.report_{name.rsplit('.', 1)[-1]}"
        return f"ml.{name.rsplit('/', 1)[-1].rsplit('.', 1)[0]}"

    def put(self, name: str, data: bytes,
            content_type: str = "application/octet-stream") -> str:
        from sqlalchemy import select

        from redsim.db.models import Artifact

        digest = hashlib.sha256(data).hexdigest()
        # The pure runner necessarily creates its own local run id. Defer that
        # one record until the worker replaces it with the authoritative DB id.
        if name == "run_record.json" and not self.finalizing_run_record:
            self._hashes[name] = digest
            return "deferred:ml.run_record"
        kind = self._kind(name)
        existing = self.session.execute(select(Artifact).where(
            Artifact.run_id == self.run_id,
            Artifact.kind == kind,
            Artifact.sha256 == digest,
        )).scalar_one_or_none()
        if existing is None:
            key = f"{self.project_id}/{self.run_id}/{name}/{digest}"
            ref = self.blob_store.put(key, data, content_type=content_type)
            existing = Artifact(
                id=str(uuid4()), run_id=self.run_id, project_id=self.project_id,
                kind=kind, sha256=digest, location=ref.location,
                content_type=content_type, size_bytes=len(data),
            )
            self.session.add(existing)
            self.session.flush()
            # Each artifact is independently durable. If a later ML stage
            # fails, task_context may roll back projections but not evidence
            # already emitted by a completed stage.
            self.session.commit()
        self._hashes[name] = digest
        self._hashes[existing.id] = digest
        return existing.id

    def sha256(self, name: str) -> str:
        return self._hashes[name]


def _publish_stage(run_id: str, job_id: str, stage: str) -> None:
    from redsim.workers.events import publish_job_event

    publish_job_event(
        run_id, job_id, "running", type="stage", stage=stage,
    )


@app.task(name="redsim.ml_campaign_run", bind=True, max_retries=2)
def ml_campaign_run(self: Task, job_id: str) -> dict[str, Any]:
    """Validate frozen input, run the pure campaign, and persist projections."""
    from redsim.db.models import Job, Run, Target
    from redsim.ml.sandbox import run_campaign_sandboxed
    from redsim.ml.schema import CampaignConfig, CampaignRecord
    from redsim.services.ml_campaigns import persist_campaign_record
    from redsim.workers.bootstrap import task_context

    with task_context(job_id, task=self) as ctx:
        if ctx.skip:
            return {"job_id": job_id, "skipped": True}
        audit_writer = ctx.audit_writer
        assert audit_writer is not None
        job = ctx.session.get(Job, job_id)
        if job is None:
            raise RuntimeError(f"job {job_id} disappeared")
        snapshot = dict((job.detail or {}).get("campaign_config") or {})
        config = CampaignConfig.model_validate(snapshot)
        run = ctx.session.get(Run, ctx.run_id)
        if run is None or config.target_id != run.target_id:
            raise RuntimeError("campaign target differs from the admitted Run target")
        target = ctx.session.get(Target, config.target_id)
        if target is None or target.project_id != ctx.project_id:
            raise RuntimeError("campaign target is absent or belongs to another project")
        target_detail = getattr(target, "detail", None) or {}
        target_status = (target_detail.get("status")
                         if isinstance(target_detail, dict) else None)
        if target_status is not None and target_status != "available":
            raise RuntimeError(
                f"campaign target is not available (status={target_status!r})"
            )

        sink = DatabaseArtifactSink(
            ctx.session, ctx.blob_store,
            run_id=ctx.run_id, project_id=ctx.project_id,
        )

        def on_stage(stage: str) -> None:
            live_run = ctx.session.get(Run, ctx.run_id)
            if live_run is not None and live_run.status not in {
                "succeeded", "failed", "cancelled",
            }:
                table = dict(live_run.stage_table or {})
                stages_done = list(table.get("stages_done") or [])
                if stage not in stages_done:
                    stages_done.append(stage)
                jobs = dict(table.get("jobs") or {})
                jobs[job_id] = {
                    "type": "attack.run", "status": "running", "stage": stage,
                }
                table.update({
                    "stage": stage, "stages_done": stages_done, "jobs": jobs,
                })
                live_run.stage_table = table
                ctx.session.commit()
            action = {
                "attack": "attack.run",
                "explain": "explain.run",
                "score": "score.compute",
                "harden": "harden.recommend",
                "report": (
                    "verify.replay"
                    if job.type == "verify.replay"
                    else "report.render"
                ),
            }.get(stage)
            if action is not None:
                audit_writer.append(
                    action=action,
                    actor=ctx.actor,
                    target=None,
                    allowlist_check="pass",
                    override=False,
                    success=True,
                    detail={"job_id": job_id, "stage": stage},
                    project_id=ctx.project_id,
                    run_id=ctx.run_id,
                )
            _publish_stage(ctx.run_id, job_id, stage)

        from sqlalchemy import MetaData, Table, select

        campaign_table = Table(
            "ml_campaigns", MetaData(), autoload_with=ctx.session.get_bind(),
        )
        campaign_row = ctx.session.execute(
            campaign_table.select().where(campaign_table.c.run_id == ctx.run_id)
        ).mappings().one()
        baseline_run_id = campaign_row.get("baseline_run_id")
        parent_run_id = campaign_row.get("parent_run_id")

        def is_cancelled() -> bool:
            from redsim.db.session import get_session

            with get_session() as cancellation_session:
                live_job = cancellation_session.get(Job, job_id)
                live_run = cancellation_session.get(Run, ctx.run_id)
                return (
                    live_job is None
                    or live_run is None
                    or live_job.status == "cancelled"
                    or live_run.status == "cancelled"
                )

        if str(target.value).startswith("bundled:"):
            record = run_campaign_sandboxed(
                config,
                sink,
                on_stage=on_stage,
                is_cancelled=is_cancelled,
                baseline_run_id=baseline_run_id,
                parent_run_id=parent_run_id,
            )
        else:
            from redsim.services.ml_models import uploaded_model_file

            with uploaded_model_file(target, ctx.blob_store) as (
                materialized_path,
                materialized_detail,
            ):
                record = run_campaign_sandboxed(
                    config,
                    sink,
                    target_file=materialized_path,
                    target_detail=materialized_detail,
                    on_stage=on_stage,
                    is_cancelled=is_cancelled,
                    baseline_run_id=baseline_run_id,
                    parent_run_id=parent_run_id,
                )
        # run_campaign is storage-agnostic and allocates a local id. The
        # platform run id is authoritative at this boundary.
        record = record.model_copy(update={"run_id": ctx.run_id})
        if baseline_run_id and record.status == "succeeded" and record.score is not None:
            from redsim.db.models import Artifact
            from redsim.ml.scoring import delta

            baseline_artifact = ctx.session.execute(select(Artifact).where(
                Artifact.run_id == baseline_run_id,
                Artifact.kind == "ml.run_record",
            )).scalar_one_or_none()
            if baseline_artifact is None:
                raise RuntimeError("verify baseline campaign record is missing")
            baseline_bytes = ctx.blob_store.get(str(baseline_artifact.location))
            if isinstance(baseline_bytes, str):
                baseline_bytes = baseline_bytes.encode("utf-8")
            if hashlib.sha256(baseline_bytes).hexdigest() != baseline_artifact.sha256:
                raise RuntimeError("verify baseline ml.run_record digest mismatch")
            baseline_record = CampaignRecord.model_validate_json(baseline_bytes)
            if baseline_record.score is None:
                raise RuntimeError("verify baseline score is unavailable")
            baseline_score = baseline_record.score
            record_score = record.score
            baseline_provenance = baseline_record.provenance
            record_provenance = record.provenance
            mismatch = (
                baseline_provenance is None
                or record_provenance is None
                or baseline_provenance.model_sha256 != record_provenance.model_sha256
                or baseline_provenance.sample_indices_sha256
                != record_provenance.sample_indices_sha256
                or baseline_record.settings_hash != record.settings_hash
            )
            if mismatch:
                failed = record.model_dump(mode="json")
                failed.update({
                    "status": "failed",
                    "error": "verify identity mismatch: model, sample, or settings changed",
                    "score": None,
                    "score_status": {
                        "state": "unavailable",
                        "reason": "verify identity mismatch",
                    },
                    "completeness": "partial",
                    "missing": ["verify model, sample, or settings identity mismatch"],
                })
                record = CampaignRecord.model_validate(failed)
            else:
                measured_delta = delta(
                    baseline_score,
                    record_score,
                    baseline_run_id=str(baseline_run_id),
                    measurements_before=baseline_record.measurements,
                    measurements_after=record.measurements,
                )
                record = record.model_copy(update={
                    "score": record_score.model_copy(update={"delta": measured_delta}),
                })
        from redsim.ml.reporting import render_campaign_reports

        for name, data, content_type in render_campaign_reports(record):
            sink.put(name, data, content_type)
        record_json = record.model_dump_json(indent=2).encode("utf-8")
        sink.finalizing_run_record = True
        sink.put("run_record.json", record_json, "application/json")
        persist_campaign_record(ctx.session, ctx.run_id, record)
        from redsim.services.ml_findings import project_campaign_findings

        if job.type == "attack.run" and record.status == "succeeded":
            project_campaign_findings(ctx.session, record)
        elif job.type == "verify.replay" and record.status == "succeeded":
            from redsim.db.models import Finding
            from redsim.ml.schema import (
                FindingVerify,
                MeasuredDelta,
                MLFindingDetail,
            )
            from redsim.ml.scoring import finding_inputs

            finding = ctx.session.get(Finding, (job.detail or {}).get("finding_id"))
            if finding is None:
                raise RuntimeError("verify finding is missing")
            schema_blob = dict(finding.schema_blob or {})
            ml_detail = MLFindingDetail.model_validate(schema_blob.get("ml") or {})
            inputs = finding_inputs(
                record.config, record.measurements, ml_detail.attack_id,
            )
            outcome = (
                "inconclusive"
                if not inputs.denominator_ok
                else "still_vulnerable"
                if inputs.crosses_threshold
                else "verified"
            )
            ml_detail.verify = FindingVerify(
                run_id=ctx.run_id,
                defense=record.config.defense,
                outcome=outcome,
                delta=record.score.delta if record.score is not None else None,
            )
            if (
                record.score is not None
                and record.score.delta is not None
                and record.config.defense is not None
                and record.settings_hash is not None
            ):
                score_delta = record.score.delta
                measured = MeasuredDelta(
                    verify_run_id=ctx.run_id,
                    baseline_run_id=str(baseline_run_id),
                    defense=record.config.defense,
                    delta_mri=score_delta.delta,
                    delta_subscores=score_delta.delta_subscores,
                    delta_acc_clean=score_delta.delta_acc_clean,
                    settings_hash=record.settings_hash,
                    measured_at=datetime.now(UTC),
                )
                art_class = record.config.defense.art_class
                recommendation_id = str(
                    (job.detail or {}).get("recommendation_id") or ""
                )
                ml_detail.recommendations = [
                    recommendation.model_copy(update={
                        "validation": "measured",
                        "measured": measured,
                    })
                    if (
                        recommendation.id == recommendation_id
                        and art_class in recommendation.references
                    )
                    else recommendation
                    for recommendation in ml_detail.recommendations
                ]
            schema_blob["ml"] = ml_detail.model_dump(mode="json")
            schema_blob["updated_at"] = datetime.now(UTC).isoformat()
            finding.schema_blob = schema_blob
            finding.validation_state = {
                "verified": "poc_passed",
                "still_vulnerable": "poc_failed",
                "inconclusive": "inconclusive",
            }[outcome]
            finding.status = {
                "verified": "fixed",
                "still_vulnerable": "failed",
                "inconclusive": "open",
            }[outcome]
            finding.validated_at = datetime.now(UTC)

        run = ctx.session.get(Run, ctx.run_id)
        stages = list(record.stages_done)
        if record.status == "cancelled" or (
            run is not None and run.status == "cancelled"
        ):
            # Preserve the authoritative partial record and campaign projection.
            # task_context will then observe the committed cancellation and
            # suppress its terminal success write.
            ctx.session.commit()
            return {
                "run_id": ctx.run_id,
                "job_id": job_id,
                "status": "cancelled",
                "stages_done": stages,
            }
        if run is not None and run.status != "cancelled":
            run.stage_table = {
                "stage": record.stage,
                "stages_done": stages,
                "jobs": {
                    job_id: {
                        "type": job.type,
                        "status": "running",
                        "stage": record.stage,
                    }
                },
            }
        if record.status == "failed":
            raise RuntimeError(record.error or "ML campaign failed")
        logger.info("ML campaign completed run=%s job=%s", ctx.run_id, job_id)
        return {"run_id": ctx.run_id, "job_id": job_id,
                "status": record.status, "stages_done": stages}


__all__ = ["DatabaseArtifactSink", "ml_campaign_run"]