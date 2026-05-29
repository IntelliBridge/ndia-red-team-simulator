"""LLM routing + per-task model selection."""

from aegis.llm.router import BudgetExceeded, ModelSpec, route

__all__ = ["ModelSpec", "BudgetExceeded", "route"]
