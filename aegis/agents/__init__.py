"""Pluggable CAI-agent registry."""

# Register the built-in CAI adapters, then the multi-agent pattern adapters.
from aegis.agents.cai import builtins  # noqa: F401
from aegis.agents.cai import patterns  # noqa: F401
from aegis.agents.registry import (
    AgentAdapter,
    AgentContext,
    AgentResult,
    dispatch,
    get,
    list_agents,
    maybe_load_entry_points,
    register,
)

# Third-party agents (opt-in, AEGIS_PLUGINS=1) load after the built-ins.
maybe_load_entry_points()

__all__ = [
    "AgentAdapter", "AgentContext", "AgentResult",
    "dispatch", "get", "list_agents", "register",
]
