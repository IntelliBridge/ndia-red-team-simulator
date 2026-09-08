"""Worker-side deep validation for uploaded model artifacts."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from redsim.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task


def _refusal_reason(message: str) -> str:
    if "pickle_refused" in message:
        return "pickle_refused"
    if "architecture_required" in message:
        return "architecture_missing"
    if "shape_mismatch" in message or "architecture_mismatch" in message:
        return "shape_mismatch"
    if "unsupported_model_format" in message or "format_mismatch" in message:
        return "unsupported_format"
    return "load_failed"


@app.task(name="redsim.ml_model_validate", bind=True, max_retries=2)
def ml_model_validate(self: Task, job_id: str) -> dict[str, Any]:
    """Deserialize and probe an uploaded model only inside a worker."""
    from redsim.db.models import Job, Target
    from redsim.ml.errors import UnsupportedArtifact
    from redsim.ml.sandbox import validate_model_sandboxed
    from redsim.services.ml_models import uploaded_model_file
    from redsim.workers.bootstrap import task_context

    with task_context(job_id, task=self) as ctx:
        if ctx.skip:
            return {"job_id": job_id, "skipped": True}
        assert ctx.audit_writer is not None
        job = ctx.session.get(Job, job_id)
        target_id = str((job.detail or {}).get("target_id") if job else "")
        target = ctx.session.get(Target, target_id)
        if target is None or target.project_id != ctx.project_id:
            raise RuntimeError("uploaded model target is missing or project-mismatched")
        original = dict(target.detail or {})

        def is_cancelled() -> bool:
            from redsim.db.session import get_session

            with get_session() as cancellation_session:
                live_job = cancellation_session.get(Job, job_id)
                return live_job is None or live_job.status == "cancelled"

        try:
            with uploaded_model_file(target, ctx.blob_store) as (
                materialized_path,
                materialized_detail,
            ):
                manifest = validate_model_sandboxed(
                    target.id,
                    materialized_path,
                    materialized_detail,
                    is_cancelled=is_cancelled,
                )
            validation = {
                "detected_format": manifest.get("format"),
                "input_shape": manifest.get("input_shape"),
                "class_count": manifest.get("n_classes"),
                "gradients": manifest.get("gradients"),
                "onnx_torch_argmax_agreement": None,
                "refusal_reason": None,
                "ingest_job_id": job_id,
            }
            target.detail = {
                **original,
                **manifest,
                "status": "available",
                "refusal_reason": None,
                "manifest": manifest,
                "validation": validation,
            }
            success = True
            refusal = None
        except (UnsupportedArtifact, RuntimeError) as exc:
            if "cancelled while sandbox child" in str(exc):
                return {
                    "job_id": job_id,
                    "target_id": target_id,
                    "status": "cancelled",
                    "refusal_reason": None,
                }
            refusal = _refusal_reason(str(exc))
            validation = {
                "detected_format": original.get("format"),
                "input_shape": None,
                "class_count": None,
                "gradients": None,
                "onnx_torch_argmax_agreement": None,
                "refusal_reason": refusal,
                "ingest_job_id": job_id,
            }
            target.detail = {
                **original,
                "status": "refused",
                "refusal_reason": refusal,
                "reason": str(exc),
                "validation": validation,
            }
            success = False
        ctx.audit_writer.append(
            action="model.validate",
            actor=ctx.actor,
            target=None,
            allowlist_check="pass",
            override=False,
            success=success,
            detail={"target_id": target_id, "refusal_reason": refusal},
            project_id=ctx.project_id,
            run_id=ctx.run_id,
        )
        from redsim.workers.tasks.ml_campaign import DatabaseArtifactSink

        report = {
            "target_id": target_id,
            "status": "available" if success else "refused",
            "refusal_reason": refusal,
            "validation": validation,
        }
        DatabaseArtifactSink(
            ctx.session,
            ctx.blob_store,
            run_id=ctx.run_id,
            project_id=ctx.project_id,
        ).put(
            "validation_report.json",
            json.dumps(report, sort_keys=True, separators=(",", ":")).encode(),
            "application/json",
        )
        return {
            "job_id": job_id,
            "target_id": target_id,
            "status": "available" if success else "refused",
            "refusal_reason": refusal,
        }


__all__ = ["ml_model_validate"]