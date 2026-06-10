"""Built-in adapters for CAI multi-agent *patterns*.

CAI ships composite "patterns" that coordinate several agents — a parallel
offensive sweep (``offsec_pattern``), a red-team swarm, and a bug-bounty triage
swarm. They are exposed here as ordinary, **explicitly-dispatchable** registry
entries: a pattern runs only when a caller dispatches it *by name*. Nothing
auto-swarms — a normal single-agent ``dispatch`` never touches this module.

Every pattern is offensive, so its effect class is ``active`` and the unified
human gate (see :mod:`aegis.effects`) applies: a pattern dispatched without
``context.execute`` returns a proposal and no agent is run.
"""

from __future__ import annotations

from aegis.agents.registry import (
    AgentContext,
    AgentResult,
    Domain,
    FunctionAgentAdapter,
    register,
)
from aegis.config import load_config
from aegis.effects import Effect
from aegis.integrations.cai_loader import (
    load_cai,
    load_cai_pattern,
    resolve_cai_agent,
)
from aegis.llm.guardrails import GuardrailViolation, guard_input, guard_output


def _run_agent(bundle, agent, prompt: str, cai_context: dict) -> str:
    result = bundle.Runner.run_sync(
        starting_agent=agent, input=prompt, context=cai_context,
    )
    return str(getattr(result, "final_output", None) or result)


def _invoke_pattern(cai_pattern_name: str, prompt: str, context: AgentContext) -> AgentResult:
    """Resolve a CAI pattern and run its agent(s) through ``Runner.run_sync``.

    A swarm pattern is driven by its entry agent (the handoff network does the
    rest); a parallel pattern resolves each configured agent by name and runs
    them in turn, concatenating their outputs. Either way the irreversible step
    only reaches here once the gate in ``dispatch`` has cleared ``execute``.
    """
    config = load_config()
    try:
        guard_input(prompt, config=config)
    except GuardrailViolation as exc:
        return AgentResult(status="error", output="", error=str(exc))
    bundle = load_cai(config)
    if bundle is None:
        return AgentResult(
            status="error", output="",
            error="CAI library not importable (submodule missing or env not set up)",
        )
    pattern = load_cai_pattern(config, cai_pattern_name)
    if pattern is None:
        return AgentResult(
            status="error", output="",
            error=f"CAI pattern {cai_pattern_name!r} is unavailable",
        )

    cai_context = {
        "finding_id": context.finding_id,
        "target": context.target,
        "repo_path": context.repo_path,
        **context.extra,
    }
    try:
        outputs: list[str] = []
        entry_agent = getattr(pattern, "entry_agent", None)
        if entry_agent is not None:
            # SWARM: the entry agent drives the handoff network.
            outputs.append(_run_agent(bundle, entry_agent, prompt, cai_context))
        else:
            # PARALLEL (and other config-driven types): resolve each configured
            # agent by name and run it.
            for cfg in getattr(pattern, "configs", []) or []:
                agent = resolve_cai_agent(config, cfg.agent_name)
                if agent is not None:
                    outputs.append(_run_agent(bundle, agent, prompt, cai_context))
        if not outputs:
            return AgentResult(
                status="error", output="",
                error=f"pattern {cai_pattern_name!r} resolved no runnable agent",
            )
        return AgentResult(
            status="ok",
            output=guard_output("\n\n".join(outputs), config=config),
            agent_version=bundle.cai_version,
        )
    except Exception as exc:  # pragma: no cover — CAI may not be installed
        return AgentResult(
            status="error", output="", error=f"{type(exc).__name__}: {exc}",
        )


def _pattern_adapter(name: str, domain: Domain, effect: Effect,
                     cai_pattern_name: str) -> FunctionAgentAdapter:
    def invoke(prompt: str, context: AgentContext) -> AgentResult:
        return _invoke_pattern(cai_pattern_name, prompt, context)

    return FunctionAgentAdapter(
        name=name, domain=domain, effect=effect, wired=True, fn=invoke,
    )


# All three are offensive composites → active effect → human-gated. The first
# column is the Aegis registry name; the last is the CAI pattern name resolved
# via ``get_pattern``.
_PATTERNS: list[tuple[str, Domain, Effect, str]] = [
    ("offsec_pattern", "offensive", "active", "offsec_pattern"),
    ("redteam_swarm", "offensive", "active", "redteam_swarm_pattern"),
    ("bb_triage_swarm", "offensive", "active", "bb_triage_swarm_pattern"),
]


for _name, _domain, _effect, _cai_name in _PATTERNS:
    register(_pattern_adapter(_name, _domain, _effect, _cai_name))
