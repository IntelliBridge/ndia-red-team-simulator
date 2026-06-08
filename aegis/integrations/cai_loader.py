"""Centralized loader for the CAI library.

The Phase 2 ``aegis.remediate.cai_runner`` module mutated ``sys.path`` inside
each function that needed CAI. That's duplicated and obscures the
``cai_path`` dependency. This loader does it once, in one place, returning
a small bundle the rest of the code uses.

The loader is intentionally tolerant: when CAI isn't importable (e.g. the
submodule isn't initialised, or a test environment forces it off), it
returns ``None`` rather than raising — callers decide whether that's a hard
failure or a soft fallback.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.config import AegisConfig


@dataclass
class CAIBundle:
    """Pointers to the CAI primitives a service / worker needs."""
    Runner: Any
    codeagent: Any
    blueteam_agent: Any
    cai_version: str | None
    cai_path: Path
    memory_analysis_agent: Any = None
    network_security_analyzer_agent: Any = None
    reverse_engineering_agent: Any = None
    android_sast: Any = None
    subghz_sdr_agent: Any = None
    wifi_security_agent: Any = None
    replay_attack_agent: Any = None
    bug_bounter_agent: Any = None
    redteam_agent: Any = None
    dfir_agent: Any = None
    retester_agent: Any = None
    reporting_agent: Any = None
    web_pentester_agent: Any = None
    recon_agent: Any = None
    # Count of agents the live Kali MCP server was attached to (0 offline).
    kali_mcp_attached: int = 0


_BUNDLE: CAIBundle | None = None

# Active network-offensive specialists that should reach the live Kali MCP tool
# belt (nmap/sqlmap/hydra/...). The read-only recon agent is deliberately
# excluded: the belt includes active tools, and recon stays read-only.
_KALI_MCP_AGENTS = ("bug_bounter_agent", "redteam_agent", "web_pentester_agent")


def _attach_kali_mcp(agents: dict[str, Any], config: AegisConfig) -> int:
    """Attach an SSE Kali MCP server to the active offensive specialists.

    Lets those agents call the live Kali tool belt at run time. Returns the
    number of agents wired. Degrades to 0 — agents keep their default empty
    ``mcp_servers`` list — when the URL is unset or CAI's MCP client classes
    aren't importable, so the offline path is unaffected.

    Lifecycle: the server object is attached but **not** connected here
    (``connect()`` is async and needs a live server). The worker connects it
    and calls ``cleanup()`` at live-run time; no offline test runs an agent
    live, so an unconnected server is never exercised.
    """
    url = getattr(config, "mcp_kali_url", None)
    if not url:
        return 0
    try:
        from cai.sdk.agents.mcp import MCPServerSse
    except Exception:
        return 0
    try:
        server = MCPServerSse(
            params={"url": url}, cache_tools_list=True, name="kali-mcp",
        )
    except Exception:
        return 0
    attached = 0
    for attr in _KALI_MCP_AGENTS:
        agent = agents.get(attr)
        if agent is None:
            continue
        try:
            agent.mcp_servers = [server]
            attached += 1
        except Exception:
            continue
    return attached


def load_cai_pattern(config: AegisConfig, pattern_name: str) -> Any | None:
    """Resolve a CAI multi-agent pattern by name, or ``None`` when unavailable.

    All ``from cai...`` imports stay funnelled through this loader so the rest
    of the codebase never depends on CAI being importable.
    """
    if load_cai(config) is None:
        return None
    try:
        from cai.agents.patterns import get_pattern

        return get_pattern(pattern_name)
    except Exception:
        return None


def resolve_cai_agent(config: AegisConfig, agent_name: str) -> Any | None:
    """Resolve a CAI agent by its registry name, or ``None`` when unavailable."""
    if load_cai(config) is None:
        return None
    try:
        from cai.agents import get_agent_by_name

        return get_agent_by_name(agent_name)
    except Exception:
        return None


def _git_sha(repo: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True, timeout=5,
        )
        return result.stdout.strip()
    except Exception:
        return None


def load_cai(config: AegisConfig, *, force_reload: bool = False) -> CAIBundle | None:
    """Inject ``<config.cai_path>/src`` onto sys.path once and import CAI.

    Returns the bundle, or ``None`` when CAI can't be imported (caller
    decides how to fall back).
    """
    global _BUNDLE
    if _BUNDLE is not None and not force_reload:
        return _BUNDLE

    cai_path = Path(config.cai_path).resolve()
    cai_src = cai_path / "src"
    if cai_src.is_dir() and str(cai_src) not in sys.path:
        sys.path.insert(0, str(cai_src))

    try:
        from cai.agents.blue_teamer import blueteam_agent
        from cai.agents.codeagent import codeagent
        from cai.sdk.agents import Runner
    except ImportError:
        return None

    # Extended agents degrade to None independently: a failure importing one
    # NEW agent must not regress the working codeagent/blueteam path above.
    try:
        from cai.agents.android_sast_agent import android_sast
        from cai.agents.memory_analysis_agent import memory_analysis_agent
        from cai.agents.network_traffic_analyzer import network_security_analyzer_agent
        from cai.agents.replay_attack_agent import replay_attack_agent
        from cai.agents.reverse_engineering_agent import reverse_engineering_agent
        from cai.agents.subghz_sdr_agent import subghz_sdr_agent
        from cai.agents.wifi_security_tester import wifi_security_agent
    except ImportError:
        android_sast = memory_analysis_agent = network_security_analyzer_agent = None
        replay_attack_agent = reverse_engineering_agent = subghz_sdr_agent = None
        wifi_security_agent = None
    extended = {
        "memory_analysis_agent": memory_analysis_agent,
        "network_security_analyzer_agent": network_security_analyzer_agent,
        "reverse_engineering_agent": reverse_engineering_agent,
        "android_sast": android_sast,
        "subghz_sdr_agent": subghz_sdr_agent,
        "wifi_security_agent": wifi_security_agent,
        "replay_attack_agent": replay_attack_agent,
    }

    # The 6 specialist agents the one-pager names. Like ``extended``, a failure
    # importing one degrades the whole group to None rather than regressing the
    # core codeagent/blueteam path above.
    try:
        from cai.agents.bug_bounter import bug_bounter_agent
        from cai.agents.dfir import dfir_agent
        from cai.agents.red_teamer import redteam_agent
        from cai.agents.reporter import reporting_agent
        from cai.agents.retester import retester_agent
        from cai.agents.web_pentester import web_pentester_agent
    except ImportError:
        bug_bounter_agent = redteam_agent = dfir_agent = None
        retester_agent = reporting_agent = web_pentester_agent = None
    specialists = {
        "bug_bounter_agent": bug_bounter_agent,
        "redteam_agent": redteam_agent,
        "dfir_agent": dfir_agent,
        "retester_agent": retester_agent,
        "reporting_agent": reporting_agent,
        "web_pentester_agent": web_pentester_agent,
    }

    # Compose a read-only recon agent from CAI's safe reconnaissance tools.
    # Recon gets ONLY read/recon tools — never generic_linux_command/exec_code.
    # Broad except: AsyncOpenAI() raises without a key, so offline this degrades
    # to None (the registry tolerates an unavailable recon agent).
    try:
        from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
        from cai.tools.reconnaissance.curl import curl
        from cai.tools.reconnaissance.netcat import netcat
        from cai.tools.reconnaissance.netstat import netstat
        from cai.tools.reconnaissance.nmap import nmap
        from cai.tools.reconnaissance.shodan import (
            shodan_host_info,
            shodan_search,
        )
        from openai import AsyncOpenAI

        recon_agent = Agent(
            name="Recon",
            instructions=(
                "You are a read-only reconnaissance agent. Enumerate hosts, "
                "ports, and services using only the provided recon tools. You "
                "never modify the target, execute arbitrary commands, or write "
                "to disk — you observe and report findings for other agents to "
                "act on."
            ),
            tools=[nmap, shodan_search, shodan_host_info, curl, netcat, netstat],
            model=OpenAIChatCompletionsModel(
                model=os.getenv("CAI_MODEL", "alias1"),
                openai_client=AsyncOpenAI(),
            ),
        )
    except Exception:
        recon_agent = None

    # Wire the live Kali MCP belt onto the active offensive specialists so they
    # can reach it when executed (post-approval). No-op offline.
    mcp_attached = _attach_kali_mcp(specialists, config)

    _BUNDLE = CAIBundle(
        Runner=Runner,
        codeagent=codeagent,
        blueteam_agent=blueteam_agent,
        cai_version=_git_sha(cai_path),
        cai_path=cai_path,
        recon_agent=recon_agent,
        kali_mcp_attached=mcp_attached,
        **extended,
        **specialists,
    )
    return _BUNDLE
