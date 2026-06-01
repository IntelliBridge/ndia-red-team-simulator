"""Built-in CAI agent adapters.

Wires the CAI agents the one-pager promises (offensive + defensive +
forensic + remediation + audit). Any agent left unwired is registered with
``wired=False`` so the registry stays honest about coverage — invoking it
returns ``status='not_wired'`` instead of silently going missing.
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
    adapter.wired = True

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
    adapter.wired = False

    def invoke(self, prompt: str, context: AgentContext) -> AgentResult:
        return AgentResult(
            status="not_wired",
            output=f"agent {name!r} is registered but not wired",
        )

    _Stub.invoke = invoke
    return adapter


# Wired agents: each slot maps to its real CAI agent (no fallbacks). The six
# specialist slots previously fell through to codeagent/blueteam_agent; they now
# resolve to the named upstream agents the loader imports, and recon is composed
# from read-only recon tools. Unavailable agents degrade to None in the loader
# and surface as status="error" at dispatch, never a silent mis-wire.
_WIRED = [
    ("codeagent", "remediation", "codeagent"),
    ("blueteam_agent", "defensive", "blueteam_agent"),
    ("bug_bounter", "offensive", "bug_bounter_agent"),
    ("red_teamer", "offensive", "redteam_agent"),
    ("dfir", "forensic", "dfir_agent"),
    ("retester", "audit", "retester_agent"),
    ("reporter", "audit", "reporting_agent"),
    ("web_pentester", "offensive", "web_pentester_agent"),
    ("recon", "recon", "recon_agent"),
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
