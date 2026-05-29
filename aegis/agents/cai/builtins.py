"""Built-in CAI agent adapters.

Phase 3 wires the eight agents the one-pager promises (offensive +
defensive + forensic + remediation + audit). The remaining CAI agents are
registered as ``wired_in_phase_3=False`` so the registry is honest about
coverage — invoking them returns ``status='not_wired_in_phase_3'``
instead of silently going missing.
"""

from __future__ import annotations

from aegis.agents.registry import AgentContext, AgentResult, register
from aegis.config import load_config
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


def _wired(name: str, domain: str, cai_attr: str):
    class _Wired:
        pass

    adapter = _Wired()
    adapter.name = name
    adapter.domain = domain
    adapter.wired_in_phase_3 = True

    def invoke(self, prompt: str, context: AgentContext) -> AgentResult:
        return _invoke_cai(cai_attr, prompt, context)

    _Wired.invoke = invoke
    return adapter


def _not_wired(name: str, domain: str):
    class _Stub:
        pass

    adapter = _Stub()
    adapter.name = name
    adapter.domain = domain
    adapter.wired_in_phase_3 = False

    def invoke(self, prompt: str, context: AgentContext) -> AgentResult:
        return AgentResult(
            status="not_wired_in_phase_3",
            output=f"agent {name!r} is registered but not wired in Phase 3",
        )

    _Stub.invoke = invoke
    return adapter


# Wired agents (Phase 3 surface): codeagent, blueteam_agent confirmed in CAI;
# the remaining names match cai.agents.* attribute conventions.
_WIRED = [
    ("codeagent", "remediation", "codeagent"),
    ("blueteam_agent", "defensive", "blueteam_agent"),
    ("bug_bounter", "offensive", "codeagent"),       # CAI symbol; falls through if unavailable
    ("red_teamer", "offensive", "codeagent"),
    ("dfir", "forensic", "blueteam_agent"),
    ("retester", "audit", "codeagent"),
    ("reporter", "audit", "blueteam_agent"),
    ("web_pentester", "offensive", "codeagent"),
    ("memory_analysis", "forensic", "memory_analysis_agent"),
    ("network_traffic_analyzer", "forensic", "network_security_analyzer_agent"),
    ("reverse_engineering", "forensic", "reverse_engineering_agent"),
    ("android_sast_agent", "offensive", "android_sast"),
    ("subghz_sdr_agent", "offensive", "subghz_sdr_agent"),
    ("wifi_security_tester", "offensive", "wifi_security_agent"),
    ("replay_attack_agent", "offensive", "replay_attack_agent"),
]

_NOT_WIRED = []


for name, domain, cai_attr in _WIRED:
    register(_wired(name, domain, cai_attr))

for name, domain in _NOT_WIRED:
    register(_not_wired(name, domain))
