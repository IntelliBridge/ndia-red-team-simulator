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
        "aegis.workers.tasks.fix",
        "aegis.workers.tasks.verify",
        "aegis.workers.tasks.report",
        "aegis.workers.tasks.exports",
        "aegis.workers.tasks.ci_gate",
        "aegis.workers.tasks.parallel_fix",
        "aegis.workers.tasks.reaper",
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

# Periodic stale-job reaper: a crashed task is left status="running"
# forever (the redelivery guard never re-runs it), so beat sweeps every
# 5 minutes and flips jobs past their TTL to "failed".
app.conf.beat_schedule = {
    "reap-stale-jobs": {
        "task": "aegis.reap_stale_jobs",
        "schedule": 300.0,
    },
    # Periodic WORM export of the audit chains to the Object-Lock bucket.
    # The task self-gates on AEGIS_WORM_EXPORT, so this entry is harmless
    # when WORM is disabled; the interval honours AEGIS_WORM_INTERVAL.
    "export-chains-to-worm": {
        "task": "aegis.export_chains_to_worm",
        "schedule": float(worm_export_interval()),
    },
}
