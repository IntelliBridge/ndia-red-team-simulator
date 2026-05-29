"""Pluggable CAI-agent registry."""

# Register the built-in CAI adapters.
from aegis.agents.cai import builtins  # noqa: F401
from aegis.agents.registry import (
    AgentAdapter,
    AgentContext,
    AgentResult,
    dispatch,
    get,
    list_agents,
    register,
)

__all__ = [
    "AgentAdapter", "AgentContext", "AgentResult",
    "dispatch", "get", "list_agents", "register",
]
