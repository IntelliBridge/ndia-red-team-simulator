"""Agent adapter Protocol + registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol


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
    status: str                # "ok" | "not_wired_in_phase_3" | "error"
    output: str
    findings: list = field(default_factory=list)
    diff: str | None = None
    agent_version: str | None = None
    error: str | None = None


class AgentAdapter(Protocol):
    name: str
    domain: Domain
    wired_in_phase_3: bool

    def invoke(self, prompt: str, context: AgentContext) -> AgentResult: ...


_REGISTRY: dict[str, AgentAdapter] = {}


def register(adapter: AgentAdapter) -> None:
    _REGISTRY[adapter.name] = adapter


def get(name: str) -> AgentAdapter:
    if name not in _REGISTRY:
        raise KeyError(f"unknown agent: {name!r}. "
                       f"available: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def list_agents() -> list[dict[str, Any]]:
    return [
        {"name": a.name, "domain": a.domain,
         "wired_in_phase_3": a.wired_in_phase_3}
        for a in _REGISTRY.values()
    ]


def dispatch(name: str, prompt: str,
             context: AgentContext) -> AgentResult:
    return get(name).invoke(prompt, context)
