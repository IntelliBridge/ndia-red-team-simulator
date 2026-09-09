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
        "redsim.workers.tasks.ml_llm",
        # Phase B wave B3 (bulk-upload-capacity-cli): the deferred-run dispatcher backstop.
        "redsim.workers.tasks.capacity",
        # Phase B wave B3 interop: the Croissant export and the consumed-slice validation run on
        # ``scans`` (queue set at enqueue / on the decorator), the Foundry push on ``default``.
        "redsim.workers.tasks.dataset_export",
        "redsim.workers.tasks.dataset_validate",
        "redsim.workers.tasks.integration_push",
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
# The LLM probe run (spec 17.4, plan 12 wave B2) is on ``default`` on purpose:
# that pool is the only one with Pythia egress (spec 10.8), the probe child
# talks to the gateway and never loads model bytes, so it does not belong on
# the credential-free ``scans`` pool.
# Phase B wave B3 tasks declare their queue on the ``@app.task`` decorator
# (``redsim.ml_dispatch_deferred`` -> default in redsim/workers/tasks/capacity.py;
# the interop export and integration push tasks likewise), so this table keeps
# the pre-B3 set and ``tests/test_worker_hardening.py`` keeps pinning it.
app.conf.task_default_queue = "default"
app.conf.task_routes = {
    "redsim.scan_start": {"queue": "scans"},
    "redsim.verify_replay": {"queue": "scans"},
    "redsim.ml_campaign_run": {"queue": "scans"},
    "redsim.ml_model_validate": {"queue": "scans"},
    "redsim.ml_llm_probe_run": {"queue": "default"},
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
    # Phase B (BULK-09/-22): the deferred-run dispatcher backstop. A project over
    # its concurrency cap has admissions parked as queued jobs with
    # ``detail.deferred``; the finishing campaign task dispatches the next one
    # (continuation hook) and this sweep catches whatever a crash, broker outage
    # or cancel left behind, refreshing the capacity gauges from the same rows.
    "ml-dispatch-deferred": {
        "task": "redsim.ml_dispatch_deferred",
        "schedule": 60.0,
        "options": {"queue": "default"},
    },
}
