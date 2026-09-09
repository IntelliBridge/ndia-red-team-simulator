"""Celery app — Redis broker; settings from env."""

from __future__ import annotations

import os
from typing import Any

from celery import Celery
from celery.signals import worker_init, worker_process_init

from redsim.storage.worm import worm_export_interval

app = Celery(
    "redsim",
    broker=os.environ.get("REDSIM_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.environ.get("REDSIM_RESULT_BACKEND", "redis://localhost:6379/1"),
    include=[
        "redsim.workers.tasks.scan",
        "redsim.workers.tasks.verify",
        "redsim.workers.tasks.report",
        "redsim.workers.tasks.reaper",
        "redsim.workers.tasks.tenant_reconcile",
        "redsim.workers.tasks.worm_export",
        "redsim.workers.tasks.ml_campaign",
        "redsim.workers.tasks.ml_model",
    ],
)


@worker_init.connect(weak=False)
@worker_process_init.connect(weak=False)
def init_worker_observability(**_kwargs: Any) -> None:
    """Initialise OTel + structlog + the direct log shipper in the worker.

    ``worker_init`` covers the solo/threads pools and the prefork parent;
    ``worker_process_init`` re-runs it in every forked child so exporter
    threads exist post-fork. ``configure_worker_observability`` is idempotent
    per process id and every piece is env-gated (``OTEL_EXPORTER_OTLP_ENDPOINT``,
    ``REDSIM_LOG_INGEST_URL``), so an unconfigured worker is unchanged.
    """
    from redsim.observability import configure_worker_observability

    configure_worker_observability()


app.conf.task_acks_late = True
app.conf.task_track_started = True
app.conf.worker_prefetch_multiplier = 1
app.conf.task_default_retry_delay = 10
app.conf.task_default_max_retries = 3
app.conf.task_soft_time_limit = 1800
app.conf.task_time_limit = 2100

# Queue routing: long-running attack-adapter work (scan dispatch, PoC replay)
# goes on the ``scans`` queue, fast bookkeeping (report rendering, the stale-job
# reaper, tenant reconciliation, WORM export) on ``default``, so a 30-minute
# scan can't starve a report behind it. Deploy a dedicated worker pool per
# queue (see deploy/docker-compose.yml). The pentest fix / agent / CI-gate
# tasks that used to be routed here were removed with the pentest domain.
app.conf.task_default_queue = "default"
app.conf.task_routes = {
    "redsim.scan_start": {"queue": "scans"},
    "redsim.verify_replay": {"queue": "scans"},
    "redsim.ml_campaign_run": {"queue": "scans"},
    "redsim.ml_model_validate": {"queue": "scans"},
    "redsim.report_render": {"queue": "default"},
    "redsim.reap_stale_jobs": {"queue": "default"},
    "redsim.verify_tenant_integrity": {"queue": "default"},
    "redsim.export_chains_to_worm": {"queue": "default"},
}

# Periodic stale-job reaper: a crashed task is left status="running"
# forever (the redelivery guard never re-runs it), so beat sweeps every
# 5 minutes and flips jobs past their TTL to "failed".
app.conf.beat_schedule = {
    "reap-stale-jobs": {
        "task": "redsim.reap_stale_jobs",
        "schedule": 300.0,
    },
    # Periodic tenant-isolation reconciliation: re-derive each scoped row's
    # org_id from its project and flag any drift the 0009 UPDATE trigger
    # couldn't have caught (rows predating it, written out-of-band, restored).
    # Read-only — it logs/audits, never repairs. Hourly is ample for a
    # detective control.
    "verify-tenant-integrity": {
        "task": "redsim.verify_tenant_integrity",
        "schedule": 3600.0,
    },
    # Periodic WORM export of the audit chains to the Object-Lock bucket.
    # The task self-gates on REDSIM_WORM_EXPORT, so this entry is harmless
    # when WORM is disabled; the interval honours REDSIM_WORM_INTERVAL.
    "export-chains-to-worm": {
        "task": "redsim.export_chains_to_worm",
        "schedule": float(worm_export_interval()),
    },
}
