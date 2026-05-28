"""Pluggable CAI-agent registry."""

from aegis.agents.registry import (
    AgentAdapter,
    AgentContext,
    AgentResult,
    dispatch,
    get,
    list_agents,
    register,
)

# Register the built-in CAI adapters.
from aegis.agents.cai import builtins  # noqa: F401

__all__ = [
    "AgentAdapter", "AgentContext", "AgentResult",
    "dispatch", "get", "list_agents", "register",
]
