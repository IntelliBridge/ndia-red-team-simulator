"""Celery task ``redsim.ml_dataset_validate``: parse a consumed slice inside the sandbox child (INTEROP-15).

Plan 12 wave B3, ``interop-consume`` track. ``POST /v1/datasets`` admitted the
slice on static checks and wrote the ``ml_datasets`` row as ``validating``; this
task, on the ``scans`` queue, is the only place the bytes are opened, and it
opens them in a child process, never in the Celery parent:

1. The Job's file list is materialised from the blob store into the job's 0700
   work directory (``redsim.ml.sandbox.job_work_dir``) and re-hashed against
   the digests recorded at admission before any child exists (a substituted
   blob is refused here, never decoded).
2. ``python -m redsim.ml.interop.consume`` runs under the ML sandbox's rlimits
   (``MlSandboxConfig``), in its own process group, with the credential-free
   environment ``redsim.ml.sandbox._ml_child_env`` builds (no ``REDSIM_*``
   setting, no gateway, dataset or cloud credential, no proxy). The request file
   carries the declared schema, the file names and digests and the row cap; the
   child answers with the same typed envelope shape ``sandbox_worker`` uses.
3. The outcome moves the row: ``available`` with the parse report (row count,
   per-class counts, columns, observed value range, digests, revision) or
   ``refused`` with the child's typed reason (``schema_mismatch``,
   ``class_names_mismatch``, ``manifest_digest_mismatch``,
   ``artifact_digest_mismatch``, ``dataset_too_large``,
   ``remote_reference_refused``, ``parse_failed``). A child killed by its
   limits or the wall clock marks the row ``refused`` (``sandbox_killed`` /
   ``sandbox_timeout``: an input the decoder cannot finish inside the budget is
   not admitted) and the job still fails with the infrastructure class so the
   run records it. A malformed envelope is a contract failure and fails the job.
4. Audit: one ``dataset.validate`` row (``success`` is the dataset outcome;
   ids, digests, counts and the reason only), the report as the
   ``ml.dataset_validation_report`` artifact of the ingest run, then
   ``job.complete``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redsim.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task

logger = logging.getLogger(__name__)

#: Task name; routed to ``scans`` through the decorator's ``queue`` option (the pool without credentials).
TASK_NAME = "redsim.ml_dataset_validate"
#: Audit action of the parse outcome (spec 27.4 names the admission event; this is its completion).
VALIDATE_ACTION = "dataset.validate"
#: Artifact name of the report on the ingest run (kind ``ml.dataset_validation_report``).
REPORT_ARTIFACT = "dataset_validation_report.json"
#: Refusal reasons the parent assigns when the child did not answer.
SANDBOX_REASONS = {"timed_out": "sandbox_timeout", "killed": "sandbox_killed"}
_POLL_S = 0.2


class ParseChildFailed(RuntimeError):
    """The child did not finish: ``status`` is ``timed_out`` or ``killed`` (the job fails with this class)."""

    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class ParseOutcome:
    """What one child run produced: ``ok`` with a report, or a typed refusal."""

    ok: bool
    report: dict[str, Any] | None = None
    code: str | None = None
    error_class: str | None = None
    message: str | None = None
    field: str | None = None
    exit_status: int | None = None
    duration_s: float | None = None


@dataclass
class MaterialisedFile:
    name: str
    path: Path
    sha256: str
    role: str
    size_bytes: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- parent-side spawner


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def materialise_files(
    blob_store: Any, files: list[dict[str, Any]], input_dir: Path,
) -> tuple[list[MaterialisedFile], ParseOutcome | None]:
    """Write every recorded blob under ``input_dir`` and re-hash it; a mismatch is a refusal before any child."""
    from redsim.services.ml_datasets import safe_part_name

    input_dir.mkdir(parents=True, exist_ok=True)
    out: list[MaterialisedFile] = []
    for item in files:
        name = safe_part_name(str(item.get("name") or ""), "part")
        location = str(item.get("location") or item.get("key") or "")
        expected = str(item.get("sha256") or "").strip().lower()
        role = str(item.get("role") or "parquet")
        try:
            data = blob_store.get(location)
        except Exception as exc:  # noqa: BLE001 - a missing blob is a refusal, not a crash
            return out, ParseOutcome(ok=False, code="artifact_digest_mismatch", error_class=type(exc).__name__,
                                     message=f"blob for {name!r} is unreadable: {type(exc).__name__}", field="file")
        path = input_dir / name
        path.write_bytes(data)
        actual = _sha256_file(path)
        if expected and actual != expected:
            return out, ParseOutcome(
                ok=False, code="artifact_digest_mismatch", error_class="ArtifactDigestMismatch",
                message=f"blob for {name!r} has sha256 {actual}; admission recorded {expected}", field="file",
            )
        out.append(MaterialisedFile(name=name, path=path, sha256=actual, role=role, size_bytes=len(data)))
    return out, None


def parse_dataset_sandboxed(
    *,
    dataset_id: str,
    schema: dict[str, Any],
    files: list[MaterialisedFile],
    work_dir: Path,
    max_rows: int,
    is_cancelled: Callable[[], bool] | None = None,
) -> ParseOutcome | None:
    """Run ``redsim.ml.interop.consume`` on the materialised files; ``None`` when cancelled meanwhile.

    Raises :class:`ParseChildFailed` for a timed-out or killed child and
    ``EnvelopeInvalid`` for an unreadable request or envelope. The environment,
    rlimits, process group and envelope reader are the ML sandbox's own.
    """
    from redsim.ml.errors import EnvelopeInvalid
    from redsim.ml.sandbox import (
        _EXIT_BAD_REQUEST,
        MlSandboxConfig,
        _assets_dir,
        _ml_child_env,
        _read_envelope,
    )
    from redsim.scanners.sandbox import _kill_process_group, _rlimit_preexec

    cfg = MlSandboxConfig.from_env()
    request = {
        "mode": "dataset_parse",
        "dataset_id": dataset_id,
        "schema": schema,
        "files": [{"name": f.name, "sha256": f.sha256, "role": f.role} for f in files],
        "max_rows": int(max_rows),
    }
    request_path = work_dir / "request.json"
    result_path = work_dir / "result.json"
    result_path.unlink(missing_ok=True)
    request_path.write_text(json.dumps(request, sort_keys=True), encoding="utf-8")
    env = _ml_child_env(cfg, assets=str(_assets_dir()), hash_seed=0, work_dir=work_dir)
    argv = [sys.executable, "-m", "redsim.ml.interop.consume", "--request", str(request_path),
            "--work-dir", str(work_dir)]
    started = time.monotonic()
    proc = subprocess.Popen(
        argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=env,
        preexec_fn=_rlimit_preexec(cfg.rlimits()),  # noqa: PLW1509 - required for POSIX rlimits
        # The working directory is inherited, as ``redsim.ml.sandbox._run_child`` does: ``python -m`` resolves
        # the package from it in a checkout that is not the installed one.
        start_new_session=True,
    )
    forced: str | None = None
    while proc.poll() is None:
        if is_cancelled is not None:
            try:
                cancelled = is_cancelled()
            except Exception:  # noqa: BLE001 - cancellation telemetry cannot fail execution
                logger.debug("dataset parse cancellation probe failed", exc_info=True)
                cancelled = False
            if cancelled:
                forced = "cancelled"
                _kill_process_group(proc)
                break
        if time.monotonic() - started > cfg.timeout_s:
            forced = "timed_out"
            _kill_process_group(proc)
            break
        time.sleep(_POLL_S)
    _, stderr = proc.communicate()
    duration = round(time.monotonic() - started, 3)
    returncode = proc.returncode
    if forced == "cancelled":
        return None
    if forced == "timed_out":
        raise ParseChildFailed("timed_out", f"dataset parse child timed out after {cfg.timeout_s}s")
    if returncode == _EXIT_BAD_REQUEST:
        raise EnvelopeInvalid(f"dataset parse child could not read its request: {(stderr or '').strip()[-1000:]}")
    if returncode != 0:
        detail = (stderr or "").strip()[-1000:]
        message = f"dataset parse child died with status {returncode}"
        raise ParseChildFailed("killed", f"{message}: {detail}" if detail else message)
    if not result_path.is_file():
        raise EnvelopeInvalid("dataset parse child exited 0 without writing result.json")
    envelope = _read_envelope(result_path)
    if envelope["ok"] is False:
        code = envelope.get("code")
        return ParseOutcome(
            ok=False, code=str(code) if isinstance(code, str) and code else "parse_failed",
            error_class=str(envelope.get("error_class")), message=str(envelope.get("error"))[:1000],
            field=str(envelope["field"]) if isinstance(envelope.get("field"), str) else None,
            exit_status=returncode, duration_s=duration,
        )
    report = envelope["result"].get("report")
    if not isinstance(report, dict):
        raise EnvelopeInvalid("dataset parse envelope carries no report object")
    return ParseOutcome(ok=True, report=report, exit_status=returncode, duration_s=duration)


# --------------------------------------------------------------------------- row updates


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _apply_outcome(row: Any, outcome: ParseOutcome, *, job_id: str, checked_at: str) -> dict[str, Any]:
    """Move the ``ml_datasets`` row on ``outcome`` and return the ``validation.parse`` block written."""
    from redsim.services.ml_datasets import STATUS_AVAILABLE, STATUS_REFUSED

    detail = _as_dict(row.detail)
    validation = _as_dict(detail.get("validation"))
    if outcome.ok and outcome.report is not None:
        parse: dict[str, Any] = {**outcome.report, "checked_at": checked_at, "duration_s": outcome.duration_s,
                                 "ingest_job_id": job_id}
        row.status = STATUS_AVAILABLE
        row.refusal_reason = None
        revision = outcome.report.get("revision")
        if isinstance(revision, str) and revision:
            row.manifest_sha256 = revision
        names = outcome.report.get("class_names")
        if isinstance(names, list) and names:
            row.class_names = [str(v) for v in names]
    else:
        parse = {
            "checked_at": checked_at, "duration_s": outcome.duration_s, "ingest_job_id": job_id,
            "refusal_reason": outcome.code, "error_class": outcome.error_class,
            "reason": outcome.message, "field": outcome.field,
        }
        row.status = STATUS_REFUSED
        row.refusal_reason = outcome.code
    row.detail = {**detail, "validation": {**validation, "parse": parse}}
    return parse


def _refuse_on_fresh_session(dataset_id: str, *, code: str, message: str, job_id: str) -> None:
    """Mark the row refused on its own transaction so a job failure's rollback cannot strand it ``validating``."""
    from redsim.db.models import MlDataset
    from redsim.db.session import get_session

    with get_session() as sess:
        row = sess.get(MlDataset, dataset_id)
        if row is None:
            return
        _apply_outcome(row, ParseOutcome(ok=False, code=code, error_class="ParseChildFailed", message=message),
                       job_id=job_id, checked_at=datetime.now(UTC).isoformat())


# --------------------------------------------------------------------------- the task


@app.task(name=TASK_NAME, bind=True, max_retries=2, queue="scans")
def ml_dataset_validate(self: Task, job_id: str) -> dict[str, Any]:
    """Materialise, parse in the sandbox child and move the consumed slice to ``available`` or ``refused``."""
    from redsim.db.models import Job, MlDataset
    from redsim.ml.sandbox import job_work_dir, keep_work_dir
    from redsim.services.ml_datasets import max_rows
    from redsim.workers.bootstrap import task_context
    from redsim.workers.tasks.ml_campaign import DatabaseArtifactSink

    with task_context(job_id, task=self, commit_running=True) as ctx:
        if ctx.skip:
            return {"job_id": job_id, "skipped": True}
        assert ctx.audit_writer is not None
        job = ctx.session.get(Job, job_id)
        job_detail = _as_dict(job.detail if job is not None else None)
        dataset_id = str(job_detail.get("dataset_id") or "")
        row = ctx.session.get(MlDataset, dataset_id)
        if row is None or row.project_id != ctx.project_id:
            raise RuntimeError("dataset row is missing or project-mismatched")
        detail = _as_dict(row.detail)
        schema = _as_dict(detail.get("schema"))
        files_raw = job_detail.get("files") or detail.get("files") or []
        files = [dict(item) for item in files_raw if isinstance(item, dict)]
        checked_at = datetime.now(UTC).isoformat()
        audit_base: dict[str, Any] = {
            "dataset_id": dataset_id, "modality": row.modality, "n_files": len(files),
            "manifest_sha256": job_detail.get("manifest_sha256"), "declared_sha256": job_detail.get("declared_sha256"),
            "sha256s": {str(item.get("name")): item.get("sha256") for item in files},
        }

        def is_cancelled() -> bool:
            from redsim.db.session import get_session

            with get_session() as cancellation_session:
                live_job = cancellation_session.get(Job, job_id)
                return live_job is None or live_job.status == "cancelled"

        work_dir = job_work_dir(job_id)
        outcome: ParseOutcome | None
        try:
            materialised, early = materialise_files(ctx.blob_store, files, work_dir / "input")
            if early is not None:
                outcome = early
            else:
                outcome = parse_dataset_sandboxed(
                    dataset_id=dataset_id, schema=schema, files=materialised, work_dir=work_dir,
                    max_rows=max_rows(), is_cancelled=is_cancelled,
                )
        except ParseChildFailed as exc:
            reason = SANDBOX_REASONS.get(exc.status, "parse_failed")
            # The input did not parse inside the budget: refused on its own transaction, audited, then the
            # job fails with the infrastructure class so the run records what happened (spec 10.6).
            _refuse_on_fresh_session(dataset_id, code=reason, message=str(exc), job_id=job_id)
            ctx.audit_writer.append(
                action=VALIDATE_ACTION, actor=ctx.actor, target=None, allowlist_check="n/a", override=False,
                success=False,
                detail={**audit_base, "status": "refused", "refusal_reason": reason, "error_class": type(exc).__name__,
                        "reason": str(exc)[:1000]},
                project_id=ctx.project_id, run_id=ctx.run_id,
            )
            raise
        finally:
            if keep_work_dir():
                logger.info("dataset parse keeping work directory %s", work_dir)
            else:
                shutil.rmtree(work_dir, ignore_errors=True)

        if outcome is None:
            return {"job_id": job_id, "dataset_id": dataset_id, "status": "cancelled"}

        parse = _apply_outcome(row, outcome, job_id=job_id, checked_at=checked_at)
        ctx.session.add(row)
        ctx.session.flush()
        status = str(row.status)
        report = outcome.report or {}
        audit_detail: dict[str, Any] = {
            **audit_base, "status": status, "refusal_reason": row.refusal_reason,
            "n_rows": report.get("n_rows"), "per_class": report.get("per_class"),
            "empty_classes": report.get("empty_classes"), "revision": row.manifest_sha256,
            "x_shape": report.get("x_shape"), "duration_s": outcome.duration_s,
        }
        if not outcome.ok:
            audit_detail.update({"error_class": outcome.error_class, "code": outcome.code,
                                 "reason": (outcome.message or "")[:1000], "field": outcome.field})
        # spec 5.11: the outcome row. ``success`` is the dataset outcome (available -> True, refused -> False).
        ctx.audit_writer.append(
            action=VALIDATE_ACTION, actor=ctx.actor, target=None, allowlist_check="n/a", override=False,
            success=outcome.ok, detail=audit_detail, project_id=ctx.project_id, run_id=ctx.run_id,
        )

        report_doc = {"dataset_id": dataset_id, "status": status, "refusal_reason": row.refusal_reason,
                      "validation": parse}
        report_bytes = json.dumps(report_doc, sort_keys=True, separators=(",", ":"), default=str).encode()
        report_sha = hashlib.sha256(report_bytes).hexdigest()
        DatabaseArtifactSink(ctx.session, ctx.blob_store, run_id=ctx.run_id, project_id=ctx.project_id).put(
            REPORT_ARTIFACT, report_bytes, "application/json",
        )
        ctx.audit_writer.append(
            action="job.complete", actor=ctx.actor, target=None, allowlist_check="n/a", override=False,
            success=True,
            detail={"job_type": "dataset.validate", "status": "succeeded", "validation_status": status,
                    "counts": {"findings": 0, "artifacts": 1, "measurements": 0, "rows": report.get("n_rows") or 0},
                    "envelope_sha256": report_sha},
            project_id=ctx.project_id, run_id=ctx.run_id,
        )
        return {"job_id": job_id, "dataset_id": dataset_id, "status": status, "refusal_reason": row.refusal_reason}


__all__ = [
    "REPORT_ARTIFACT",
    "TASK_NAME",
    "VALIDATE_ACTION",
    "MaterialisedFile",
    "ParseChildFailed",
    "ParseOutcome",
    "materialise_files",
    "ml_dataset_validate",
    "parse_dataset_sandboxed",
]
