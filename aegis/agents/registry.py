"""Agent adapter Protocol + registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from aegis.effects import (
    Effect,
    build_action_plan,
    domain_default_effect,
    requires_approval,
)
from aegis.registry import Registry

Domain = Literal["offensive", "defensive", "forensic",
                 "recon", "remediation", "audit"]


@dataclass
class AgentContext:
    finding_id: str | None = None
    target: str | None = None
    repo_path: str | None = None
    actor: str | None = None
    # Human gate: an ``active`` / ``external`` agent only performs its
    # irreversible step when this is True (set by an approver-gated caller).
    # Default False → the agent proposes a plan instead of acting.
    execute: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    status: str                # "ok" | "pending_approval" | "not_wired" | "error"
    output: str
    findings: list = field(default_factory=list)
    diff: str | None = None
    agent_version: str | None = None
    error: str | None = None
    plan: dict | None = None   # set on status == "pending_approval"


class AgentAdapter(Protocol):
    name: str
    domain: Domain
    effect: Effect
    wired: bool

    def invoke(self, prompt: str, context: AgentContext) -> AgentResult: ...


def adapter_effect(adapter: AgentAdapter) -> Effect:
    """Resolve an adapter's effect class, defaulting from its domain.

    Built-ins set ``effect`` explicitly; a third-party agent that omits it
    falls back to the (fail-safe) domain default so it can never be *less*
    gated than its domain implies.
    """
    return getattr(adapter, "effect", None) or domain_default_effect(
        getattr(adapter, "domain", None)
    )


_agent_registry: Registry[AgentAdapter] = Registry("agent")
# Historical public handle; kept as the live backing store (see scanners.registry).
_REGISTRY: dict[str, AgentAdapter] = _agent_registry._items

register = _agent_registry.register
get = _agent_registry.get


def list_agents() -> list[dict[str, Any]]:
    return [
        {"name": a.name, "domain": a.domain,
         "effect": adapter_effect(a), "wired": a.wired}
        for a in _REGISTRY.values()
    ]


def dispatch(name: str, prompt: str,
             context: AgentContext) -> AgentResult:
    """Resolve and invoke an agent through the central human gate.

    This is the single chokepoint every agent invocation passes through, so
    the gate covers built-ins and third-party plugins alike. An ``active`` /
    ``external`` agent invoked without ``context.execute`` returns a
    ``pending_approval`` proposal and the underlying agent is **never run** —
    no exploit fires, no live change lands. ``read`` agents (recon, static
    analysis, diff generation) run unconditionally.
    """
    adapter = get(name)
    effect = adapter_effect(adapter)
    if requires_approval(effect) and not context.execute:
        return AgentResult(
            status="pending_approval",
            output=(f"agent {name!r} ({effect}) requires explicit approval to "
                    f"execute; returning a proposal only"),
            plan=build_action_plan(
                name=name, domain=getattr(adapter, "domain", None),
                effect=effect, target=context.target, intent=prompt,
            ),
        )
    return adapter.invoke(prompt, context)


def maybe_load_entry_points() -> None:
    """Third-party agent discovery, gated by AEGIS_PLUGINS=1."""
    _agent_registry.maybe_load_entry_points("aegis.agents")
