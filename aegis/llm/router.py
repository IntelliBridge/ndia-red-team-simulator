"""Per-task LLM routing.

The one-pager promises "300+ models, best per task, no vendor lock-in." That
maps to a tiny indirection: every LLM-calling site asks the router for a
model identifier given a ``task`` name. The router reads
``config.task_models`` (an optional dict on ``AegisConfig``), falling back
to ``config.model`` when a task isn't explicitly mapped.

Per-project / per-org budget caps live here too. Today the budget check is
a hook that does nothing when no budget store is provided; Phase 3 M5 wires
in the real ``llm_usage``-table check. Phase 6 (multi-tenancy) adds a per-ORG
monthly cap (enforced *alongside* the project daily cap) and per-tenant
``{task: model}`` routing overrides — both read through the same checker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass
class ModelSpec:
    task: str
    model: str
    budget_remaining_cents: int | None = None


class BudgetExceeded(Exception):
    """Raised when a routed call would exceed the project's LLM budget."""


@runtime_checkable
class BudgetChecker(Protocol):
    def remaining(self, project_id: str | None) -> int | None: ...

    # Phase 6 additions. Declared optional via ``getattr`` at the call site so
    # a legacy checker exposing only ``remaining`` stays a valid BudgetChecker.
    def remaining_org(self, org_id: str | None) -> int | None: ...

    def model_override(self, org_id: str | None, task: str) -> str | None: ...


_DEFAULT_TASKS = {
    "patch", "harden", "verify_replay", "report_summarize",
    "recon", "exploit", "deps_bump",
}


def _resolve_model(task: str, config) -> str:
    task_models = getattr(config, "task_models", None) or {}
    return task_models.get(task) or config.model


def route(
    task: str,
    config,
    *,
    project_id: str | None = None,
    org_id: str | None = None,
    budget_checker: BudgetChecker | None = None,
) -> ModelSpec:
    """Return the model to use for ``task``, gated by budget when supplied.

    Model resolution: a per-tenant override
    (``Organization.llm_model_overrides[task]``, read via the checker) wins;
    otherwise the AegisConfig default (``_resolve_model``). The override is
    only consulted when both ``org_id`` and a checker exposing
    ``model_override`` are supplied — absent a DB it degrades to the config
    default rather than failing.

    Budget gate (only when ``budget_checker`` is supplied): enforces BOTH the
    project's daily cap AND the org's monthly cap. ``BudgetExceeded`` is raised
    if *either* tier is ``<= 0``; the message names the tier without leaking
    spend figures. ``budget_remaining_cents`` reports the tighter (smaller) of
    the two remaining values, treating an unset cap as no constraint.
    """
    model: str | None = None
    if budget_checker is not None and org_id is not None:
        override_fn = getattr(budget_checker, "model_override", None)
        if callable(override_fn):
            model = override_fn(org_id, task)
    if not model:
        model = _resolve_model(task, config)

    remaining: int | None = None
    if budget_checker is not None:
        project_remaining = budget_checker.remaining(project_id)
        if project_remaining is not None and project_remaining <= 0:
            raise BudgetExceeded(
                f"project {project_id!r} has exhausted its daily LLM budget"
            )

        org_remaining: int | None = None
        org_fn = getattr(budget_checker, "remaining_org", None)
        if org_id is not None and callable(org_fn):
            org_remaining = org_fn(org_id)
            if org_remaining is not None and org_remaining <= 0:
                raise BudgetExceeded(
                    f"organization {org_id!r} has exhausted its monthly LLM budget"
                )

        # Report the tighter remaining of the two tiers (None == uncapped).
        candidates = [r for r in (project_remaining, org_remaining) if r is not None]
        remaining = min(candidates) if candidates else None

    return ModelSpec(task=task, model=model, budget_remaining_cents=remaining)


def known_tasks() -> set[str]:
    return set(_DEFAULT_TASKS)
