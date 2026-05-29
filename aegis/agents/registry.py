"""Agent adapter Protocol + registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from aegis.registry import Registry

Domain = Literal["offensive", "defensive", "forensic",
                 "recon", "remediation", "audit"]


@dataclass
class AgentContext:
    finding_id: str | None = None
    target: str | None = None
    repo_path: str | None = None
    actor: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    status: str                # "ok" | "not_wired" | "error"
    output: str
    findings: list = field(default_factory=list)
    diff: str | None = None
    agent_version: str | None = None
    error: str | None = None


class AgentAdapter(Protocol):
    name: str
    domain: Domain
    wired: bool

    def invoke(self, prompt: str, context: AgentContext) -> AgentResult: ...


_agent_registry: Registry[AgentAdapter] = Registry("agent")
# Historical public handle; kept as the live backing store (see scanners.registry).
_REGISTRY: dict[str, AgentAdapter] = _agent_registry._items

register = _agent_registry.register
get = _agent_registry.get


def list_agents() -> list[dict[str, Any]]:
    return [
        {"name": a.name, "domain": a.domain, "wired": a.wired}
        for a in _REGISTRY.values()
    ]


def dispatch(name: str, prompt: str,
             context: AgentContext) -> AgentResult:
    return get(name).invoke(prompt, context)


def maybe_load_entry_points() -> None:
    """Third-party agent discovery, gated by AEGIS_PLUGINS=1."""
    _agent_registry.maybe_load_entry_points("aegis.agents")
