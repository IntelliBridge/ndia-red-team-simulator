"""Per-task LLM routing.

The one-pager promises "300+ models, best per task, no vendor lock-in." That
maps to a tiny indirection: every LLM-calling site asks the router for a
model identifier given a ``task`` name. The router reads
``config.task_models`` (an optional dict on ``AegisConfig``), falling back
to ``config.model`` when a task isn't explicitly mapped.

Per-project / per-org budget caps live here too. Today the budget check is
a hook that does nothing when no budget store is provided; Phase 3 M5 wires
in the real ``llm_usage``-table check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class ModelSpec:
    task: str
    model: str
    budget_remaining_cents: int | None = None


class BudgetExceeded(Exception):
    """Raised when a routed call would exceed the project's LLM budget."""


class BudgetChecker(Protocol):
    def remaining(self, project_id: str | None) -> int | None: ...


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
    budget_checker: BudgetChecker | None = None,
) -> ModelSpec:
    """Return the model to use for ``task``, gated by budget when supplied."""
    model = _resolve_model(task, config)
    remaining: int | None = None
    if budget_checker is not None:
        remaining = budget_checker.remaining(project_id)
        if remaining is not None and remaining <= 0:
            raise BudgetExceeded(
                f"project {project_id!r} has exhausted its daily LLM budget"
            )
    return ModelSpec(task=task, model=model, budget_remaining_cents=remaining)


def known_tasks() -> set[str]:
    return set(_DEFAULT_TASKS)
