"""Worker-side deep validation for uploaded model artifacts and registered endpoints.

Two variants of the ``model.validate`` job share this task (spec 9.3 step 6, 6.6):

* ``ml_model_artifact`` (uploads): the bytes are fetched from the blob store,
  re-hashed against the registered manifest and loaded only inside the sandbox
  child (``redsim.ml.sandbox.validate_model_sandboxed``). Unchanged.
* ``ml_model_endpoint`` (Phase B, ENDPOINT-09, -19, -29, -30): nothing is
  fetched. The AuthProfile named on ``Job.detail.auth_profile_id`` is decrypted
  here through ``services.auth_profiles.resolve_auth_for_scan`` (the single
  decryption point) and handed to the predict broker in memory; the sandbox
  parent starts the broker, the child binds the bundled evaluation split, sends
  a seeded 8-row probe over the unix socket and checks the answer against the
  ``endpoint-v1`` contract (``redsim.ml.sandbox.probe_endpoint_sandboxed``). The
  credential is never written to ``Job.detail``, the request file, the child's
  environment, an artifact or an audit row. The broker is stopped by the sandbox
  in every exit path.

The outcome vocabulary is the frozen one: ``available`` with ``gradients:
false``, the response fingerprint (*remote model identity*, never a weights
digest), latency, HTTP status and ``onnx_torch_argmax_agreement: null``
(agreement is not applicable to an endpoint); or ``refused`` with
``refusal_reason`` ``shape_mismatch`` (a contract violation) or ``load_failed``
(unreachable, an auth failure, an egress refusal, a binding problem) and the
typed class, code and message under ``detail.validation.probe``. A missing
encryption key on the worker is an infrastructure failure: audited as a
``model.validate`` ``success=False`` row with the error class and re-raised so
the job fails, never degraded to an unauthenticated request. Sandbox timeouts
and dead children propagate as job failures for both variants.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redsim.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task

    from redsim.workers.bootstrap import TaskContext

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

# Typed endpoint failure codes (``redsim.ml.endpoint_broker`` / ``redsim.ml.endpoint_egress``)
# onto the frozen ``RefusalReason`` literals (ENDPOINT-09). A contract violation is a shape
# problem of the remote model's answer; everything else is a failure to load it. The
# fine-grained class and code stay under ``validation.probe`` (ENDPOINT-28 is deferred).
_ENDPOINT_REFUSAL_CODES = {
    "endpoint_schema_mismatch": "shape_mismatch",
    "endpoint_unreachable": "load_failed",
    "endpoint_auth_failed": "load_failed",
    "egress_refused": "load_failed",
    "endpoint_not_allowlisted": "load_failed",
    "endpoint_url_invalid": "load_failed",
    "query_budget_exceeded": "load_failed",
    "endpoint_error": "load_failed",
}

#: ``Target.kind`` of a registered black-box endpoint (mirrors ``services.ml_models.ENDPOINT_KIND``).
ENDPOINT_KIND = "ml_model_endpoint"


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


def _endpoint_refusal_reason(exc: Exception) -> str:
    """The frozen ``RefusalReason`` for a typed endpoint probe failure (class, code, then loader token)."""
    from redsim.ml.errors import UnsupportedArtifact

    if type(exc).__name__ == "EndpointSchemaMismatch":
        return "shape_mismatch"
    code = str(getattr(exc, "code", "") or "")
    if code in _ENDPOINT_REFUSAL_CODES:
        return _ENDPOINT_REFUSAL_CODES[code]
    if isinstance(exc, UnsupportedArtifact):
        # A binding problem the child hit before any request left the worker
        # (``dataset_incompatible: ...`` / ``shape_mismatch: ...``).
        return _refusal_reason(exc)
    return "load_failed"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


@dataclass
class _Outcome:
    """What one validate body established; the task turns it into rows, the audit row and the report."""

    success: bool
    refusal: str | None
    validation: dict[str, Any]
    audit_detail: dict[str, Any]
    audit_target: str | None = None          # the endpoint URL (allowlist verdict on the row); None for uploads
    counts: dict[str, Any] = field(default_factory=dict)   # endpoint rows/requests/bytes for job.complete


# ---------------------------------------------------------------------------
# Endpoint variant (ENDPOINT-09)
# ---------------------------------------------------------------------------


def _validate_endpoint(
    ctx: TaskContext,
    *,
    job_id: str,
    target: Any,
    job_detail: dict[str, Any],
    original: dict[str, Any],
    is_cancelled: Any,
) -> _Outcome | None:
    """Probe a registered endpoint through the broker; ``None`` when the job was cancelled meanwhile.

    The credential is resolved here, passed to ``probe_endpoint_sandboxed`` (which
    hands it to the broker object in memory) and dropped when the call returns.
    Refusals become ``_Outcome(success=False)``; a missing worker key is audited
    and re-raised; sandbox timeouts, dead children and bad envelopes propagate.
    """
    from redsim.config import load_config
    from redsim.ml.errors import EnvelopeInvalid, MLError, SandboxKilled, SandboxTimeout
    from redsim.ml.sandbox import probe_endpoint_sandboxed
    from redsim.security_utils.secrets import AuthProfilesKeyError
    from redsim.services.auth_profiles import resolve_auth_for_scan
    from redsim.services.ml_models import endpoint_auth_profile_id, endpoint_host, endpoint_request_block

    assert ctx.audit_writer is not None
    url = str(target.value)
    host = endpoint_host(url)
    config = load_config()
    allowlist = list(getattr(config, "target_allowlist", None) or [])
    profile_id = endpoint_auth_profile_id(original, job_detail)
    block = endpoint_request_block(url, original, auth_profile_id=profile_id)
    registered_manifest = _as_dict(original.get("manifest")) or original
    registration_sha = str(original.get("sha256") or registered_manifest.get("sha256") or "") or None
    contract = (_as_dict(registered_manifest.get("endpoint")).get("contract_version")
                or _as_dict(original.get("endpoint")).get("contract_version"))
    checked_at = datetime.now(UTC).isoformat()
    probe_base: dict[str, Any] = {"host": host, "auth_profile_id": profile_id, "contract": contract,
                                  "checked_at": checked_at}
    audit_base: dict[str, Any] = {
        "target_id": target.id, "detected_format": "endpoint", "gradients": False,
        "onnx_torch_argmax_agreement": None, "onnx_conversion_status": None, "library_versions": None,
        "host": host, "auth_profile_id": profile_id, "contract": contract,
        "registration_descriptor_sha256": registration_sha,
    }

    def refused(exc: Exception | None, *, reason: str, code: str, error_class: str, message: str) -> _Outcome:
        probe = {**probe_base, "error_class": error_class, "code": code, "reason": message[:1000]}
        validation = {
            "detected_format": "endpoint", "input_shape": registered_manifest.get("input_shape"),
            "class_count": registered_manifest.get("n_classes"), "gradients": False,
            "onnx_torch_argmax_agreement": None, "onnx_conversion": None, "library_versions": None,
            "refusal_reason": reason, "ingest_job_id": job_id,
            "ingest_run_id": _as_dict(original.get("validation")).get("ingest_run_id"),
            "probe": probe, "registration_descriptor_sha256": registration_sha,
        }
        target.detail = {
            **original, "status": "refused", "refusal_reason": reason, "reason": message[:1000],
            "validation": validation,
        }
        return _Outcome(
            success=False, refusal=reason, validation=validation, audit_target=url,
            audit_detail={**audit_base, "status": "refused", "refusal_reason": reason, "error_class": error_class,
                          "code": code, "reason": message[:1000]},
        )

    if not profile_id:
        return refused(None, reason="load_failed", code="auth_profile_required", error_class="LookupError",
                       message="the endpoint registration names no AuthProfile; nothing was queried")
    try:
        auth: dict[str, Any] | None = resolve_auth_for_scan(ctx.session, profile_id)
    except LookupError as exc:
        return refused(exc, reason="load_failed", code="auth_profile_not_found", error_class="LookupError",
                       message=f"auth profile {profile_id!r} is not resolvable on the worker; nothing was queried")
    except AuthProfilesKeyError as exc:
        # Infrastructure failure (spec 10.6): typed, audited, and the job fails. Never an anonymous probe.
        ctx.audit_writer.append(
            action="model.validate", actor=ctx.actor, target=url,
            allowlist_check=_allowlist_check(url, allowlist), override=False, success=False,
            detail={**audit_base, "status": "failed", "error_class": type(exc).__name__,
                    "reason": "the worker cannot decrypt AuthProfile secrets (REDSIM_AUTH_PROFILES_KEY)"},
            project_id=ctx.project_id, run_id=ctx.run_id,
        )
        raise

    try:
        manifest = probe_endpoint_sandboxed(
            target.id, block, auth, endpoint_allowlist=allowlist, is_cancelled=is_cancelled, job_id=job_id,
        )
    except RuntimeError as exc:
        if "cancelled while sandbox child" in str(exc):
            return None
        raise
    except (SandboxTimeout, SandboxKilled, EnvelopeInvalid):
        raise
    except MLError as exc:
        return refused(exc, reason=_endpoint_refusal_reason(exc), code=str(getattr(exc, "code", "") or "ml_error"),
                       error_class=type(exc).__name__, message=str(exc))
    finally:
        auth = None  # the only reference this process held; the broker is already stopped by the sandbox

    probe_block = _as_dict(manifest.get("endpoint_probe"))
    fingerprint = _as_dict(manifest.get("endpoint_fingerprint"))
    broker = _as_dict(manifest.get("endpoint_broker"))
    fingerprint_sha = fingerprint.get("sha256") or broker.get("fingerprint_sha256")
    output_kind = fingerprint.get("output_kind") or probe_block.get("output_kind") or broker.get("output_kind")
    probe = {
        **probe_base,
        "http_status": probe_block.get("http_status"), "latency_ms": probe_block.get("latency_ms"),
        "n_rows": probe_block.get("n_rows"), "output_kind": output_kind,
        "tls_mode": probe_block.get("tls_mode") or broker.get("tls_mode"),
        "checked_at": probe_block.get("checked_at") or checked_at,
        "fingerprint_sha256": fingerprint_sha, "fingerprint_label": fingerprint.get("label"),
        "rows": broker.get("rows"), "requests": broker.get("requests"), "retries": broker.get("retries"),
        "request_bytes": broker.get("request_bytes"), "response_bytes": broker.get("response_bytes"),
        "resolved_addresses": broker.get("resolved_addresses"), "limits": broker.get("limits"),
        "plaintext_loopback": broker.get("plaintext_loopback"),
    }
    validation = {
        "detected_format": "endpoint", "input_shape": manifest.get("input_shape"),
        "class_count": manifest.get("n_classes"), "gradients": False,
        # Agreement is between two loaders of the same bytes; an endpoint has one answer path.
        "onnx_torch_argmax_agreement": None, "onnx_conversion": None,
        "library_versions": manifest.get("library_versions"),
        "refusal_reason": None, "ingest_job_id": job_id,
        "ingest_run_id": _as_dict(original.get("validation")).get("ingest_run_id"),
        "probe": probe, "registration_descriptor_sha256": registration_sha,
    }
    # The child's manifest is authoritative once the endpoint answered (as the loader's is for an
    # upload): its ``sha256`` is the descriptor digest every campaign's provenance will carry, the
    # registration digest stays beside it. Registration-time keys the child does not know
    # (auth_kind, attestation, registration, input_format) survive from ``original``.
    target.detail = {
        **original, **manifest, "status": "available", "refusal_reason": None, "reason": None,
        "manifest": manifest, "validation": validation,
    }
    counts = {"endpoint_rows": broker.get("rows"), "endpoint_requests": broker.get("requests"),
              "endpoint_bytes": (broker.get("request_bytes") or 0) + (broker.get("response_bytes") or 0)}
    return _Outcome(
        success=True, refusal=None, validation=validation, audit_target=url, counts=counts,
        audit_detail={
            **audit_base, "status": "available", "refusal_reason": None, "sha256": manifest.get("sha256"),
            "fingerprint_sha256": fingerprint_sha, "output_kind": output_kind,
            "http_status": probe.get("http_status"), "latency_ms": probe.get("latency_ms"),
            "tls_mode": probe.get("tls_mode"), "n_rows": probe.get("n_rows"),
            "rows": broker.get("rows"), "requests": broker.get("requests"), "retries": broker.get("retries"),
        },
    )


def _allowlist_check(url: str, allowlist: list[str]) -> str:
    from redsim.safety import is_target_allowed

    return "pass" if is_target_allowed(url, allowlist) else "fail"


# ---------------------------------------------------------------------------
# Upload variant (unchanged behaviour)
# ---------------------------------------------------------------------------


def _validate_upload(
    ctx: TaskContext,
    *,
    job_id: str,
    target: Any,
    original: dict[str, Any],
    is_cancelled: Any,
) -> _Outcome | None:
    from redsim.ml.errors import ArtifactDigestMismatch, UnsupportedArtifact
    from redsim.ml.sandbox import validate_model_sandboxed
    from redsim.services.ml_models import _delete_blob, uploaded_model_file

    registered_manifest = (
        dict(original["manifest"]) if isinstance(original.get("manifest"), dict) else original
    )
    registered_sha = str(
        registered_manifest.get("sha256") or original.get("sha256") or ""
    ).strip().lower()
    try:
        with uploaded_model_file(target, ctx.blob_store, session=ctx.session) as (
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
            return None
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
            "ingest_run_id": _as_dict(original.get("validation")).get("ingest_run_id"),
        }
        target.detail = {
            **original,
            "status": "refused",
            "refusal_reason": refusal,
            "reason": str(exc)[:1000],
            "validation": validation,
        }
        _delete_blob(ctx.blob_store, str(target.value))
        return _Outcome(
            success=False, refusal=refusal, validation=validation,
            audit_detail={
                "target_id": target.id,
                "detected_format": original.get("format") or registered_manifest.get("format"),
                "status": "refused",
                "gradients": None,
                "onnx_torch_argmax_agreement": None,
                "onnx_conversion_status": None,
                "library_versions": None,
                "refusal_reason": refusal,
            },
        )
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
        # The registration named the validate Run (spec 9.3); the block keeps naming it after the verdict, as
        # the endpoint path does, so the row points at the chain that carries model.validate + job.complete.
        "ingest_run_id": _as_dict(original.get("validation")).get("ingest_run_id"),
    }
    # The loader describes the bytes it loaded (``source: uploaded``, a manifest built from the loaded model);
    # the row's provenance is registration-time information the child cannot know.
    target.detail = {
        **original,
        **manifest,
        "status": "available",
        "refusal_reason": None,
        "manifest": manifest,
        "validation": validation,
    }
    return _Outcome(
        success=True, refusal=None, validation=validation,
        audit_detail={
            "target_id": target.id,
            "detected_format": manifest.get("format"),
            "status": "available",
            "gradients": manifest.get("gradients"),
            "onnx_torch_argmax_agreement": agreement,
            "onnx_conversion_status": conversion_status,
            "library_versions": library_versions,
            "refusal_reason": None,
        },
    )


# ---------------------------------------------------------------------------
# The task
# ---------------------------------------------------------------------------


@app.task(name="redsim.ml_model_validate", bind=True, max_retries=2)
def ml_model_validate(self: Task, job_id: str) -> dict[str, Any]:
    """Deserialize and probe an uploaded model, or probe a registered endpoint, only inside a worker."""
    from redsim.db.models import Job, Target
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
        job_detail = dict(job.detail or {}) if job is not None else {}
        target_id = str(job_detail.get("target_id") or "")
        target = ctx.session.get(Target, target_id)
        if target is None or target.project_id != ctx.project_id:
            raise RuntimeError("model target is missing or project-mismatched")
        original = dict(target.detail or {})
        endpoint = target.kind == ENDPOINT_KIND

        def is_cancelled() -> bool:
            from redsim.db.session import get_session

            with get_session() as cancellation_session:
                live_job = cancellation_session.get(Job, job_id)
                return live_job is None or live_job.status == "cancelled"

        if endpoint:
            outcome = _validate_endpoint(ctx, job_id=job_id, target=target, job_detail=job_detail,
                                         original=original, is_cancelled=is_cancelled)
        else:
            outcome = _validate_upload(ctx, job_id=job_id, target=target, original=original,
                                       is_cancelled=is_cancelled)
        if outcome is None:
            return {
                "job_id": job_id,
                "target_id": target_id,
                "status": "cancelled",
                "refusal_reason": None,
            }

        status = "available" if outcome.success else "refused"

        # spec 5.11 ``model.validate``: the validation outcome. ``success`` is
        # the model outcome (available -> True, refused -> False). An upload is
        # an in-boundary artifact (``target=None``, ``allowlist_check`` n/a, as
        # ``model.register`` does); an endpoint's row carries the URL as the
        # target so the allowlist verdict is on the chain (ENDPOINT-19).
        if outcome.audit_target is not None:
            from redsim.config import load_config

            allowlist = list(getattr(load_config(), "target_allowlist", None) or [])
            allowlist_check = _allowlist_check(outcome.audit_target, allowlist)
        else:
            allowlist_check = "n/a"
        ctx.audit_writer.append(
            action="model.validate",
            actor=ctx.actor,
            target=outcome.audit_target,
            allowlist_check=allowlist_check,
            override=False,
            success=outcome.success,
            detail=outcome.audit_detail,
            project_id=ctx.project_id,
            run_id=ctx.run_id,
        )

        report = {
            "target_id": target_id,
            "status": status,
            "refusal_reason": outcome.refusal,
            "validation": outcome.validation,
        }
        report_bytes = json.dumps(report, sort_keys=True, separators=(",", ":"), default=str).encode()
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
                "counts": {"findings": 0, "artifacts": 1, "measurements": 0, **outcome.counts},
                "envelope_sha256": report_sha,
            },
            project_id=ctx.project_id,
            run_id=ctx.run_id,
        )

        return {
            "job_id": job_id,
            "target_id": target_id,
            "status": status,
            "refusal_reason": outcome.refusal,
        }


__all__ = ["ENDPOINT_KIND", "ml_model_validate"]
