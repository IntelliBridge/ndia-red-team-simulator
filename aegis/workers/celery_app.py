"""Celery app — Redis broker; settings from env."""

from __future__ import annotations

import os

from celery import Celery

from aegis.storage.worm import worm_export_interval

app = Celery(
    "aegis",
    broker=os.environ.get("AEGIS_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.environ.get("AEGIS_RESULT_BACKEND", "redis://localhost:6379/1"),
    include=[
        "aegis.workers.tasks.scan",
        "aegis.workers.tasks.verify",
        "aegis.workers.tasks.report",
        "aegis.workers.tasks.reaper",
        "aegis.workers.tasks.tenant_reconcile",
        "aegis.workers.tasks.worm_export",
    ],
)

app.conf.task_acks_late = True
app.conf.task_track_started = True
app.conf.worker_prefetch_multiplier = 1
app.conf.task_default_retry_delay = 10
app.conf.task_default_max_retries = 3
app.conf.task_soft_time_limit = 1800
app.conf.task_time_limit = 2100

# Queue routing: long-running offensive/remediation work goes on the ``scans``
# queue, fast bookkeeping on ``default``, so a 30-minute scan can't starve a CI
# gate or report behind it. Deploy a dedicated worker pool per queue (see
# deploy/docker-compose.yml). ``parallel_fix`` orchestrates two ``fix_generate``
# children and blocks on their result, so it stays on ``default`` — keeping the
# waiter off the same pool as the work it waits for avoids slot starvation.
app.conf.task_default_queue = "default"
app.conf.task_routes = {
    "aegis.scan_start": {"queue": "scans"},
    "aegis.fix_generate": {"queue": "scans"},
    "aegis.verify_replay": {"queue": "scans"},
    "aegis.agent_run": {"queue": "scans"},
    "aegis.report_render": {"queue": "default"},
    "aegis.vulnfixer_render": {"queue": "default"},
    "aegis.ci_gate": {"queue": "default"},
    "aegis.parallel_fix": {"queue": "default"},
    "aegis.reap_stale_jobs": {"queue": "default"},
    "aegis.verify_tenant_integrity": {"queue": "default"},
}

# Periodic stale-job reaper: a crashed task is left status="running"
# forever (the redelivery guard never re-runs it), so beat sweeps every
# 5 minutes and flips jobs past their TTL to "failed".
app.conf.beat_schedule = {
    "reap-stale-jobs": {
        "task": "aegis.reap_stale_jobs",
        "schedule": 300.0,
    },
    # Periodic tenant-isolation reconciliation: re-derive each scoped row's
    # org_id from its project and flag any drift the 0009 UPDATE trigger
    # couldn't have caught (rows predating it, written out-of-band, restored).
    # Read-only — it logs/audits, never repairs. Hourly is ample for a
    # detective control.
    "verify-tenant-integrity": {
        "task": "aegis.verify_tenant_integrity",
        "schedule": 3600.0,
    },
    # Periodic WORM export of the audit chains to the Object-Lock bucket.
    # The task self-gates on AEGIS_WORM_EXPORT, so this entry is harmless
    # when WORM is disabled; the interval honours AEGIS_WORM_INTERVAL.
    "export-chains-to-worm": {
        "task": "aegis.export_chains_to_worm",
        "schedule": float(worm_export_interval()),
    },
}
