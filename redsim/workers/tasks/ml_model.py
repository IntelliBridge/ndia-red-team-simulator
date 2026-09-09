"""Worker-side deep validation for uploaded model artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redsim.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task

# Structural map from the loader's leading message token (the ``<token>: ...``
# prefix ``redsim.ml.targets.artifact`` always emits) onto the frozen
# ``schema.RefusalReason`` vocabulary. Keying off the token — plus the typed
# exception class the sandbox rebuilds from the child's envelope — is the spec
# 5.11 "structural" refusal mapping, replacing the old substring search over the
# whole message.
_REFUSAL_TOKENS = {
    "pickle_refused": "pickle_refused",
    "architecture_required": "architecture_missing",
    "architecture_not_allowlisted": "architecture_missing",
    "architecture_mismatch": "shape_mismatch",
    "shape_mismatch": "shape_mismatch",
    "unsupported_model_format": "unsupported_format",
    "format_mismatch": "unsupported_format",
    # ``ArtifactDigestMismatch`` ("hash_mismatch: ...") has no dedicated frozen
    # reason; ``load_failed`` is the catch-all the schema offers.
    "hash_mismatch": "load_failed",
}


def _refusal_reason(exc: Exception) -> str:
    """Map a typed loader refusal onto a ``schema.RefusalReason`` literal.

    The sandbox rebuilds the child's ``redsim.ml.errors`` class from the typed
    envelope, so the caller already knows this is a refusal (not an infra
    failure); this only chooses the reason. The loader's messages are shaped
    ``<token>: <detail>``, so the leading token is the structural key; the two
    substring fallbacks cover the free-form architecture messages.
    """
    message = str(exc)
    token = message.split(":", 1)[0].strip().lower()
    if token in _REFUSAL_TOKENS:
        return _REFUSAL_TOKENS[token]
    if token.startswith("architecture"):
        return "architecture_missing"
    if "shape_mismatch" in message or "architecture_mismatch" in message:
        return "shape_mismatch"
    return "load_failed"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@app.task(name="redsim.ml_model_validate", bind=True, max_retries=2)
def ml_model_validate(self: Task, job_id: str) -> dict[str, Any]:
    """Deserialize and probe an uploaded model only inside a worker."""
    from redsim.db.models import Job, Target
    from redsim.ml.errors import ArtifactDigestMismatch, UnsupportedArtifact
    from redsim.ml.sandbox import validate_model_sandboxed
    from redsim.services.ml_models import _delete_blob, uploaded_model_file
    from redsim.workers.bootstrap import task_context
    from redsim.workers.tasks.ml_campaign import DatabaseArtifactSink

    # ``commit_running`` makes the queued->running transition durable (and
    # releases the Job/Run row locks) before the sandbox child starts. The
    # ``is_cancelled`` probe below reads ``Job.status`` from a fresh session,
    # which can only observe a concurrent ``cancel_run`` once that UPDATE is no
    # longer blocked behind this task's own uncommitted transaction.
    with task_context(job_id, task=self, commit_running=True) as ctx:
        if ctx.skip:
            return {"job_id": job_id, "skipped": True}
        assert ctx.audit_writer is not None
        job = ctx.session.get(Job, job_id)
        target_id = str((job.detail or {}).get("target_id") if job else "")
        target = ctx.session.get(Target, target_id)
        if target is None or target.project_id != ctx.project_id:
            raise RuntimeError("uploaded model target is missing or project-mismatched")
        original = dict(target.detail or {})
        registered_manifest = (
            dict(original["manifest"]) if isinstance(original.get("manifest"), dict) else original
        )
        registered_sha = str(
            registered_manifest.get("sha256") or original.get("sha256") or ""
        ).strip().lower()

        def is_cancelled() -> bool:
            from redsim.db.session import get_session

            with get_session() as cancellation_session:
                live_job = cancellation_session.get(Job, job_id)
                return live_job is None or live_job.status == "cancelled"

        # These are set by the refused/available branches below; initialised so
        # the propagation paths (cancel re-raise, SandboxTimeout/SandboxKilled/
        # EnvelopeInvalid, any genuine body error) never touch them.
        success = False
        refusal: str | None = None
        validation: dict[str, Any] = {}
        audit_detail: dict[str, Any] = {}

        try:
            with uploaded_model_file(target, ctx.blob_store) as (
                materialized_path,
                materialized_detail,
            ):
                # G-ASSET12: re-verify the fetched bytes against the registered
                # manifest before spawning the child, so a corrupted/substituted
                # blob is caught in the parent, not deep inside a load.
                if registered_sha:
                    actual = _sha256_file(materialized_path)
                    if actual != registered_sha:
                        raise ArtifactDigestMismatch(
                            f"hash_mismatch: fetched blob sha256 {actual} does not match the "
                            f"registered manifest {registered_sha}"
                        )
                manifest = validate_model_sandboxed(
                    target.id,
                    materialized_path,
                    materialized_detail,
                    is_cancelled=is_cancelled,
                    job_id=job_id,
                )
        except RuntimeError as exc:
            # ``validate_model_sandboxed`` raises RuntimeError only for a
            # cooperative cancel; leave the target status untouched and stop.
            if "cancelled while sandbox child" in str(exc):
                return {
                    "job_id": job_id,
                    "target_id": target_id,
                    "status": "cancelled",
                    "refusal_reason": None,
                }
            raise
        except UnsupportedArtifact as exc:
            # Refusal (pickle/format/shape/architecture and the parent-side
            # ArtifactDigestMismatch, which subclasses UnsupportedArtifact):
            # target -> refused, blob deleted, audit success=False.
            refusal = _refusal_reason(exc)
            validation = {
                "detected_format": original.get("format") or registered_manifest.get("format"),
                "input_shape": None,
                "class_count": None,
                "gradients": None,
                "onnx_torch_argmax_agreement": None,
                "onnx_conversion": None,
                "library_versions": None,
                "refusal_reason": refusal,
                "ingest_job_id": job_id,
            }
            target.detail = {
                **original,
                "status": "refused",
                "refusal_reason": refusal,
                "reason": str(exc)[:1000],
                "validation": validation,
            }
            _delete_blob(ctx.blob_store, str(target.value))
            success = False
            audit_detail = {
                "target_id": target_id,
                "detected_format": original.get("format") or registered_manifest.get("format"),
                "status": "refused",
                "gradients": None,
                "onnx_torch_argmax_agreement": None,
                "onnx_conversion_status": None,
                "library_versions": None,
                "refusal_reason": refusal,
            }
        else:
            # Available: read the argmax agreement and onnx conversion status
            # from the child's manifest rather than hardcoding None.
            agreement = manifest.get("onnx_torch_argmax_agreement")
            onnx_raw = manifest.get("onnx")
            onnx_block = onnx_raw if isinstance(onnx_raw, dict) else {}
            conversion = onnx_block.get("conversion")
            conversion_status = conversion.get("status") if isinstance(conversion, dict) else None
            library_versions = manifest.get("library_versions")
            validation = {
                "detected_format": manifest.get("format"),
                "input_shape": manifest.get("input_shape"),
                "class_count": manifest.get("n_classes"),
                "gradients": manifest.get("gradients"),
                "onnx_torch_argmax_agreement": agreement,
                "onnx_conversion": conversion,
                "library_versions": library_versions,
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
            audit_detail = {
                "target_id": target_id,
                "detected_format": manifest.get("format"),
                "status": "available",
                "gradients": manifest.get("gradients"),
                "onnx_torch_argmax_agreement": agreement,
                "onnx_conversion_status": conversion_status,
                "library_versions": library_versions,
                "refusal_reason": None,
            }

        status = "available" if success else "refused"

        # spec 5.11 ``model.validate``: the validation outcome. ``success`` is
        # the model outcome (available -> True, refused -> False); the target is
        # a in-boundary artifact so ``target=None`` records ``allowlist_check``
        # ``n/a`` (mirrors ``model.register``).
        ctx.audit_writer.append(
            action="model.validate",
            actor=ctx.actor,
            target=None,
            allowlist_check="n/a",
            override=False,
            success=success,
            detail=audit_detail,
            project_id=ctx.project_id,
            run_id=ctx.run_id,
        )

        report = {
            "target_id": target_id,
            "status": status,
            "refusal_reason": refusal,
            "validation": validation,
        }
        report_bytes = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        report_sha = hashlib.sha256(report_bytes).hexdigest()
        DatabaseArtifactSink(
            ctx.session,
            ctx.blob_store,
            run_id=ctx.run_id,
            project_id=ctx.project_id,
        ).put(
            "validation_report.json",
            report_bytes,
            "application/json",
        )

        # spec 5.11 ``job.complete``: the job reached a terminal outcome (a
        # refusal is still a completed job, hence ``success=True`` here; the
        # refusal itself is recorded on the ``model.validate`` row above).
        # SandboxTimeout / SandboxKilled / EnvelopeInvalid never reach this
        # point — they propagate as a job failure that ``task_context`` records.
        ctx.audit_writer.append(
            action="job.complete",
            actor=ctx.actor,
            target=None,
            allowlist_check="n/a",
            override=False,
            success=True,
            detail={
                "job_type": "model.validate",
                "status": "succeeded",
                "validation_status": status,
                "counts": {"findings": 0, "artifacts": 1, "measurements": 0},
                "envelope_sha256": report_sha,
            },
            project_id=ctx.project_id,
            run_id=ctx.run_id,
        )

        return {
            "job_id": job_id,
            "target_id": target_id,
            "status": status,
            "refusal_reason": refusal,
        }


__all__ = ["ml_model_validate"]
