"""Built-in CAI agent adapters.

Wires the CAI agents the one-pager promises (offensive + defensive +
forensic + remediation + audit). Any agent left unwired is registered with
``wired=False`` so the registry stays honest about coverage — invoking it
returns ``status='not_wired'`` instead of silently going missing.
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
from aegis.integrations.cai_loader import load_cai


def _invoke_cai(agent_attr: str, prompt: str, context: AgentContext) -> AgentResult:
    """Run a named CAI agent through ``Runner.run_sync``."""
    bundle = load_cai(load_config())
    if bundle is None:
        return AgentResult(
            status="error", output="",
            error="CAI library not importable (submodule missing or env not set up)",
        )
    agent = getattr(bundle, agent_attr, None)
    if agent is None:
        return AgentResult(
            status="error", output="",
            error=f"CAI bundle has no agent attribute {agent_attr!r}",
        )
    cai_context = {
        "finding_id": context.finding_id,
        "target": context.target,
        "repo_path": context.repo_path,
        **context.extra,
    }
    try:
        result = bundle.Runner.run_sync(
            starting_agent=agent, input=prompt, context=cai_context,
        )
        output = getattr(result, "final_output", None) or str(result)
        return AgentResult(
            status="ok", output=str(output),
            agent_version=bundle.cai_version,
        )
    except Exception as exc:  # pragma: no cover — CAI may not be installed
        return AgentResult(
            status="error", output="",
            error=f"{type(exc).__name__}: {exc}",
        )


def _wired(name: str, domain: Domain, effect: Effect,
           cai_attr: str) -> FunctionAgentAdapter:
    def invoke(prompt: str, context: AgentContext) -> AgentResult:
        return _invoke_cai(cai_attr, prompt, context)

    return FunctionAgentAdapter(
        name=name, domain=domain, effect=effect, wired=True, fn=invoke,
    )


def _not_wired(name: str, domain: Domain,
               effect: Effect) -> FunctionAgentAdapter:
    def invoke(prompt: str, context: AgentContext) -> AgentResult:
        return AgentResult(
            status="not_wired",
            output=f"agent {name!r} is registered but not wired",
        )

    return FunctionAgentAdapter(
        name=name, domain=domain, effect=effect, wired=False, fn=invoke,
    )


# Wired agents: each slot maps to its real CAI agent (no fallbacks). The six
# specialist slots previously fell through to codeagent/blueteam_agent; they now
# resolve to the named upstream agents the loader imports, and recon is composed
# from read-only recon tools. Unavailable agents degrade to None in the loader
# and surface as status="error" at dispatch, never a silent mis-wire.
#
# The 3rd column is the *effect class* (aegis.effects) that drives the human
# gate. It is not a function of the domain: an android-SAST agent is offensive
# by domain but only reads bytecode (read), while the re-tester is audit by
# domain but re-fires exploits to verify a fix (active). Getting this column
# right is what keeps an exploit or a live change from running un-approved.
_WIRED: list[tuple[str, Domain, Effect, str]] = [
    ("codeagent", "remediation", "read", "codeagent"),
    ("blueteam_agent", "defensive", "active", "blueteam_agent"),
    ("bug_bounter", "offensive", "active", "bug_bounter_agent"),
    ("red_teamer", "offensive", "active", "redteam_agent"),
    ("dfir", "forensic", "read", "dfir_agent"),
    ("retester", "audit", "active", "retester_agent"),
    ("reporter", "audit", "read", "reporting_agent"),
    ("web_pentester", "offensive", "active", "web_pentester_agent"),
    ("recon", "recon", "read", "recon_agent"),
    ("memory_analysis", "forensic", "read", "memory_analysis_agent"),
    ("network_traffic_analyzer", "forensic", "read", "network_security_analyzer_agent"),
    ("reverse_engineering", "forensic", "read", "reverse_engineering_agent"),
    ("android_sast_agent", "offensive", "read", "android_sast"),
    ("subghz_sdr_agent", "offensive", "active", "subghz_sdr_agent"),
    ("wifi_security_tester", "offensive", "active", "wifi_security_agent"),
    ("replay_attack_agent", "offensive", "active", "replay_attack_agent"),
]

_NOT_WIRED: list[tuple[str, Domain, Effect]] = []


for name, domain, effect, cai_attr in _WIRED:
    register(_wired(name, domain, effect, cai_attr))

for name, domain, effect in _NOT_WIRED:
    register(_not_wired(name, domain, effect))
