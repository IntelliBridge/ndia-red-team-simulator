"""scan.start — Celery wrapper that delegates to the execution service.

Phase 4 v0.3.1 F11: the worker no longer hand-builds the audit row.
Authorization runs through ``safety.authorize`` against the bootstrap-
supplied ``PostgresAuditWriter``; the row carries the worker actor
(``service:worker:*``, the bootstrap stamps ``actor`` from the Job's
``created_by``) and is correlated with the admission row by ``run_id``.
"""

from __future__ import annotations

from typing import Any

from aegis.workers.celery_app import app


@app.task(name="aegis.scan_start", bind=True, max_retries=2)
def scan_start(self, job_id: str) -> dict[str, Any]:
    from aegis.config import load_config
    from aegis.db.models import Job
    from aegis.safety import authorize
    from aegis.scanners import dispatch
    from aegis.scanners.registry import ScanOptions
    from aegis.workers.bootstrap import task_context

    config = load_config()
    with task_context(job_id) as ctx:
        if ctx.skip or ctx.run_state is None:
            return {"job_id": job_id, "skipped": True}
        job = ctx.session.get(Job, job_id)
        detail = (job.detail if job else {}) or {}
        target = detail["target"]
        scanner = detail.get("scanner", "strix")
        instruction = detail.get("instruction")
        # Carried from admission: an off-allowlist target the caller explicitly
        # authorized must stay authorized through the worker re-check.
        override_authorized = bool(detail.get("override_authorized", False))

        # Worker-side re-check: do not trust the admission allowlist
        # decision blindly. Any drift in config.target_allowlist would
        # surface here before the scanner runs.
        authorize(
            f"scan.execute.{scanner}", target,
            allowlist=config.target_allowlist,
            override_authorized=override_authorized,
            actor=ctx.actor, writer=ctx.audit_writer,
            run_id=ctx.run_id, project_id=ctx.project_id,
            detail={"actor": ctx.actor, "job_id": job_id,
                    "scanner": scanner, "target": target},
        )
        opts: dict[str, Any] = {"target": target, "instruction": instruction}
        if detail.get("timeout") is not None:
            opts["timeout"] = detail["timeout"]
        if detail.get("scan_mode") is not None:
            opts["scan_mode"] = detail["scan_mode"]
        if detail.get("scope_mode") is not None:
            opts["scope_mode"] = detail["scope_mode"]

        # Authenticated DAST: admission stores only the AuthProfile id in
        # Job.detail; the secret is decrypted here, worker-side, and handed
        # to the adapter via ScanOptions.extra["auth"]. It must never be
        # written back to Job.detail, logs, or audit events.
        auth_profile_id = detail.get("auth_profile_id")
        if auth_profile_id:
            from aegis.services.auth_profiles import resolve_auth_for_scan
            try:
                auth = resolve_auth_for_scan(ctx.session, auth_profile_id)
            except Exception as exc:
                # Secret-free by construction: names the profile id and the
                # failure class only. task_context marks the job failed.
                raise RuntimeError(
                    f"failed to resolve auth profile {auth_profile_id!r} "
                    f"for job {job_id}: {type(exc).__name__}"
                ) from exc
            opts["extra"] = {"auth": auth}

        result = dispatch(scanner, ctx.run_state, ScanOptions(**opts))
        ctx.run_state.save_findings(result.findings)
        return {
            "run_id": ctx.run_id, "scanner": scanner,
            "findings": len(result.findings),
            "exit_code": result.exit_code,
        }
