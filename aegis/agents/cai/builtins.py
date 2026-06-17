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
from aegis.integrations.cai_loader import load_cai, resolve_cai_agent
from aegis.llm.guardrails import GuardrailViolation, guard_input, guard_output


def _invoke_cai(
    agent_ref: str, prompt: str, context: AgentContext, *, by_name: bool = False,
) -> AgentResult:
    """Run a named CAI agent through ``Runner.run_sync``.

    ``agent_ref`` resolves one of two ways:

    * **bundle attribute** (``by_name=False``, the original 16): the loader's
      :class:`CAIBundle` exposes the agent as a typed field (e.g.
      ``bundle.codeagent``). This path is unchanged.
    * **registry key** (``by_name=True``, the newly-wired breadth): resolved
      generically via :func:`resolve_cai_agent`, which calls CAI's
      ``get_agent_by_name`` on the upstream registry key (e.g. ``one_tool_agent``).
      This lets us wire any CAI agent without adding a ``CAIBundle`` field per
      agent. An unresolvable key surfaces ``status="error"`` at dispatch.
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
    if by_name:
        agent = resolve_cai_agent(config, agent_ref)
        if agent is None:
            return AgentResult(
                status="error", output="",
                error=f"CAI agent {agent_ref!r} could not be resolved by name",
            )
    else:
        agent = getattr(bundle, agent_ref, None)
        if agent is None:
            return AgentResult(
                status="error", output="",
                error=f"CAI bundle has no agent attribute {agent_ref!r}",
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
            status="ok", output=guard_output(str(output), config=config),
            agent_version=bundle.cai_version,
        )
    except Exception as exc:  # pragma: no cover — CAI may not be installed
        return AgentResult(
            status="error", output="",
            error=f"{type(exc).__name__}: {exc}",
        )


def _wired(name: str, domain: Domain, effect: Effect, cai_attr: str,
           *, by_name: bool = False) -> FunctionAgentAdapter:
    def invoke(prompt: str, context: AgentContext) -> AgentResult:
        return _invoke_cai(cai_attr, prompt, context, by_name=by_name)

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
#
# The 5th column is the *resolution mode*. ``False`` (the original 16) resolves
# the agent off a typed ``CAIBundle`` field; ``True`` resolves it generically by
# its upstream registry key via ``resolve_cai_agent`` (CAI's ``get_agent_by_name``)
# — so the breadth agents below need no per-agent ``CAIBundle`` field. The 4th
# column is the bundle field (mode False) OR the upstream registry key (mode True).
_WIRED: list[tuple[str, Domain, Effect, str, bool]] = [
    # --- The original 16, resolved off typed CAIBundle fields (unchanged) ---
    ("codeagent", "remediation", "read", "codeagent", False),
    ("blueteam_agent", "defensive", "active", "blueteam_agent", False),
    ("bug_bounter", "offensive", "active", "bug_bounter_agent", False),
    ("red_teamer", "offensive", "active", "redteam_agent", False),
    ("dfir", "forensic", "read", "dfir_agent", False),
    ("retester", "audit", "active", "retester_agent", False),
    ("reporter", "audit", "read", "reporting_agent", False),
    ("web_pentester", "offensive", "active", "web_pentester_agent", False),
    ("recon", "recon", "read", "recon_agent", False),
    ("memory_analysis", "forensic", "read", "memory_analysis_agent", False),
    ("network_traffic_analyzer", "forensic", "read", "network_security_analyzer_agent", False),
    ("reverse_engineering", "forensic", "read", "reverse_engineering_agent", False),
    ("android_sast_agent", "offensive", "read", "android_sast", False),
    ("subghz_sdr_agent", "offensive", "active", "subghz_sdr_agent", False),
    ("wifi_security_tester", "offensive", "active", "wifi_security_agent", False),
    ("replay_attack_agent", "offensive", "active", "replay_attack_agent", False),
    # --- Breadth: every other genuinely-invocable CAI agent, resolved by name.
    # Effect is classified conservatively (unsure -> active). Agents that run
    # shell / exec tools against a target are ``active``; pure analysis /
    # reasoning / classification is ``read``; DNS/SMTP egress is ``external``.
    # CTF solver — drives generic_linux_command against a challenge host.
    ("ctf_agent", "offensive", "active", "one_tool_agent", True),
    # App-logic mapper — runs generic_linux_command + exec_code to map an app.
    ("app_logic_mapper", "offensive", "active", "app_logic_mapper", True),
    # Email-spoofing assessor — DNS/SMTP lookups + CLI; reaches 3rd-party infra.
    ("dns_smtp_agent", "recon", "external", "dns_smtp_agent", True),
    # CTF flag extractor — analyses prior output to pull a flag; no target action.
    ("flag_discriminator", "audit", "read", "flag_discriminator", True),
    # Prompt-injection classifier — read-only guardrail over supplied text.
    ("prompt_injection_detector", "defensive", "read", "injection_detector_agent", True),
    # Reasoner/planner — proposes next steps via the think tool; no side effects.
    ("thought_agent", "audit", "read", "thought_agent", True),
    # Use-case author — writes cybersecurity case studies; no target action.
    ("usecase_agent", "audit", "read", "use_case_agent", True),
    # Memory query — retrieves historical assessment findings from the store.
    ("memory_query", "forensic", "read", "query_agent", True),
]

# Deliberately NOT wired (not user-invocable agents):
#   semantic_builder / episodic_builder (memory.py) — memory-WRITER helpers used
#     internally by the memory subsystem, not standalone assessment agents.
#   transfer_to_* — handoff thunks, not Agent instances.
#   guardrail/meta internals — infrastructure, not invocable specialists.
_NOT_WIRED: list[tuple[str, Domain, Effect]] = []


for name, domain, effect, cai_attr, by_name in _WIRED:
    register(_wired(name, domain, effect, cai_attr, by_name=by_name))

for name, domain, effect in _NOT_WIRED:
    register(_not_wired(name, domain, effect))
