"""Authoritative ``jobs.status`` transition guard.

Every write to ``Job.status`` used to be a bare attribute assignment scattered
across the worker bootstrap, the stale-job reaper, and the run-cancel service.
Nothing enforced that the new value was reachable from the old one, so a logic
bug (or a future caller) could silently flip a ``succeeded`` job back to
``running``, resurrect a ``cancelled`` job, or otherwise corrupt the lifecycle
that the redelivery guard and reaper depend on.

This module centralises that lifecycle as an explicit state machine. The legal
transitions are::

    queued    → running | cancelled
    running   → succeeded | failed | cancelled | queued
    (terminal: succeeded | failed | cancelled) → ∅

``running → queued`` is the **transient-retry requeue**: ``task_context``
(``redsim.workers.bootstrap``) rolls a body back and resets the row to
``queued`` so the redelivery guard lets the retry run, rather than leaving it
``failed`` (which would be skipped). It is the one "backwards" edge and is
deliberately part of the machine, not a bypass.

Terminal states are sinks: once a job is ``succeeded``/``failed``/``cancelled``
no further transition is allowed, which is what makes the redelivery guard
fail-closed — a redelivered terminal job can never be re-run.

All status writes route through :func:`set_job_status`; an illegal transition
raises :class:`IllegalJobTransition` rather than corrupting the row. A
no-op self-transition to the *same* status is permitted (idempotent re-writes
must not blow up); see :func:`set_job_status`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redsim.db.models import Job

#: Legal ``status`` transitions, keyed by current status. A status absent from
#: this map (or mapping to an empty set) is terminal — no transition out of it
#: is permitted. ``running → queued`` is the transient-retry requeue edge.
ALLOWED: dict[str, set[str]] = {
    "queued": {"running", "cancelled"},
    "running": {"succeeded", "failed", "cancelled", "queued"},
    "succeeded": set(),
    "failed": set(),
    "cancelled": set(),
}


class IllegalJobTransition(ValueError):
    """Raised when a ``Job.status`` change is not a legal transition.

    Subclasses :class:`ValueError` so existing ``except ValueError`` handlers
    (and the admission boundaries that surface them) keep working.
    """

    def __init__(self, current: str, new: str) -> None:
        self.current = current
        self.new = new
        super().__init__(
            f"illegal job status transition: {current!r} -> {new!r} "
            f"(allowed from {current!r}: "
            f"{sorted(ALLOWED.get(current, set())) or 'none (terminal)'})"
        )


class _HasStatus(Protocol):
    """Structural type for the subset of ``Job`` this module mutates.

    Declared as a ``Protocol`` so this module carries no hard dependency on the
    SQLAlchemy ORM stack — it stays importable in the minimal (DB-less) env the
    unit CI job runs in, while still type-checking against the real
    :class:`~redsim.db.models.Job`.
    """

    status: str


def set_job_status(job: _HasStatus | Job, new: str) -> None:
    """Set ``job.status`` to ``new``, rejecting illegal transitions.

    The current status is read from ``job.status``. The write is permitted when
    ``new`` is in :data:`ALLOWED` for the current status, or when it is a no-op
    re-write of the same status (idempotent). Any other change raises
    :class:`IllegalJobTransition` and leaves the row untouched.

    Callers remain responsible for the *side* fields that accompany a
    transition (``started_at``, ``completed_at``, ``error``) — this guard owns
    only the ``status`` column.
    """
    current = job.status
    if new == current:
        # Idempotent no-op: re-writing the same status must never raise.
        return
    if new not in ALLOWED.get(current, set()):
        raise IllegalJobTransition(current, new)
    job.status = new
