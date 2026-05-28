"""Celery app — Redis broker; settings from env."""

from __future__ import annotations

import os

from celery import Celery

_BROKER = os.environ.get("AEGIS_BROKER_URL", "redis://localhost:6379/0")
_BACKEND = os.environ.get("AEGIS_RESULT_BACKEND", "redis://localhost:6379/1")

app = Celery(
    "aegis",
    broker=_BROKER,
    backend=_BACKEND,
    include=[
        "aegis.workers.tasks.scan",
        "aegis.workers.tasks.fix",
        "aegis.workers.tasks.verify",
        "aegis.workers.tasks.report",
        "aegis.workers.tasks.exports",
        "aegis.workers.tasks.ci_gate",
        "aegis.workers.tasks.parallel_fix",
    ],
)

app.conf.task_acks_late = True
app.conf.task_track_started = True
app.conf.worker_prefetch_multiplier = 1
app.conf.task_default_retry_delay = 10
app.conf.task_default_max_retries = 3
app.conf.task_soft_time_limit = 1800
app.conf.task_time_limit = 2100
