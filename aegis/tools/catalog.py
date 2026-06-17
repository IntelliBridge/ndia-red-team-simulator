"""A single, honest registry of every tool the platform exposes to agents.

Three families make up the roster:

- **Kali tools** (``source="kali"``) — the 10 names the bundled *mcp-kali*
  server actually supports (``aegis.tools.kali_client.ALLOWED_TOOLS``). This is
  a hard cap: mcp-kali only routes those names, so adding more here would mint
  non-functional tools. Breadth therefore does **not** come from inflating the
  Kali allowlist.
- **Scanner adapters** (``source="scanner"``) — the registered adapters from
  ``aegis.scanners.registry.list_scanners()``. Scanners observe a target and
  emit findings, so they are ``read`` — except DAST adapters (zap/nuclei/strix)
  which actively probe a live target and are classified ``active``.
- **CAI function-tools** (``source="cai"``) — the real ``@function_tool``s
  vendored under ``project_repos/cai/src/cai/tools/`` (recon/web/network/crypto/
  misc). These, together with the Camoufox OSINT search (``source="osint"``),
  fill the roster well past the 10-tool Kali ceiling.

Effects are classified conservatively: enumeration/analysis is ``read``; command
execution or active probing is ``active``; anything reaching a third party is
``external``. The catalog is the authoritative owner of every tool's effect;
``aegis.effects.tool_effect`` consults it (falling back to the Kali map).

Several CAI recon tools share a bare name with a Kali tool (e.g. ``nmap``), so
catalog entries for CAI tools are namespaced ``cai_<name>`` to keep names unique
within the single registry. The underlying CAI ``@function_tool`` keeps its own
name when wrapped into an agent toolbelt.

This module is import-light (only ``aegis.effects`` and the two registries) so
it never pulls in CAI at import time; it lists what the platform *can* expose,
independent of whether the optional CAI/Camoufox stacks are installed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from aegis.effects import Effect, kali_tool_effect
from aegis.scanners.registry import list_scanners
from aegis.tools.kali_client import KaliClient
from aegis.tools.osint_search import OSINT_SEARCH_EFFECT

ToolSource = str  # one of: "kali", "scanner", "cai", "osint"
ToolCategory = str  # recon/web/network/crypto/exploitation/forensic/misc/scanner

_VALID_SOURCES: frozenset[str] = frozenset({"kali", "scanner", "cai", "osint"})
_VALID_CATEGORIES: frozenset[str] = frozenset({
    "recon", "web", "network", "crypto", "exploitation",
    "forensic", "misc", "scanner",
})
_VALID_EFFECTS: frozenset[str] = frozenset({"read", "active", "external"})


@dataclass(frozen=True)
class ToolSpec:
    """An honest description of one tool the platform can expose to agents."""

    name: str
    category: ToolCategory
    source: ToolSource
    effect: Effect
    description: str


# --- Kali subset ------------------------------------------------------------
# Categorize the 10 mcp-kali tools; effect comes authoritatively from
# ``aegis.effects.kali_tool_effect`` so the catalog and the gate never drift.
_KALI_CATEGORIES: dict[str, ToolCategory] = {
    "nmap": "recon",
    "nikto": "web",
    "gobuster": "web",
    "dirb": "web",
    "enum4linux": "recon",
    "john": "crypto",
    "sqlmap": "web",
    "hydra": "exploitation",
    "metasploit": "exploitation",
    "wpscan": "web",
}

_KALI_DESCRIPTIONS: dict[str, str] = {
    "nmap": "Network/port/service discovery scan.",
    "nikto": "Web server vulnerability scan.",
    "gobuster": "Brute-force web paths/dirs/dns/vhosts.",
    "dirb": "Discover hidden web content via wordlists.",
    "enum4linux": "Enumerate SMB/Windows share and user info.",
    "john": "Crack a local password-hash file (offline).",
    "sqlmap": "Probe a URL for SQL injection (active).",
    "hydra": "Credential brute-force against a live service.",
    "metasploit": "Run an exploitation module against a host.",
    "wpscan": "Active WordPress vulnerability/enumeration scan.",
}


def _kali_specs() -> list[ToolSpec]:
    specs: list[ToolSpec] = []
    for name in sorted(KaliClient.ALLOWED_TOOLS):
        specs.append(ToolSpec(
            name=name,
            category=_KALI_CATEGORIES.get(name, "misc"),
            source="kali",
            effect=kali_tool_effect(name),
            description=_KALI_DESCRIPTIONS.get(name, f"Kali tool {name}."),
        ))
    return specs


# --- Scanner subset ---------------------------------------------------------
# Scanners observe and report → ``read``. DAST adapters drive live HTTP traffic
# at a running target (active probing) → ``active``.
_ACTIVE_SCANNERS: frozenset[str] = frozenset({"zap", "nuclei", "strix"})


def _scanner_specs() -> list[ToolSpec]:
    specs: list[ToolSpec] = []
    for name in list_scanners():
        effect: Effect = "active" if name in _ACTIVE_SCANNERS else "read"
        kind = "active DAST scanner" if name in _ACTIVE_SCANNERS else "scanner"
        specs.append(ToolSpec(
            name=name,
            category="scanner",
            source="scanner",
            effect=effect,
            description=f"Registered {kind} adapter '{name}'.",
        ))
    return specs


# --- CAI function-tool subset ----------------------------------------------
# The real ``@function_tool``s vendored under cai/tools/. Catalog names are
# namespaced ``cai_*`` to stay unique alongside the Kali ``nmap`` etc.; the
# fourth tuple element records the bare CAI tool name for toolbelt wiring.
@dataclass(frozen=True)
class _CaiEntry:
    catalog_name: str
    cai_name: str
    category: ToolCategory
    effect: Effect
    description: str


# ``read``: enumeration / analysis / third-party-free observation.
# ``active``: command execution or active probing.
# ``external``: reaches a third-party service (e.g. Shodan's API).
_CAI_TOOLS: tuple[_CaiEntry, ...] = (
    # recon
    _CaiEntry("cai_nmap", "nmap", "recon", "read",
              "CAI nmap recon wrapper (enumeration)."),
    _CaiEntry("cai_curl", "curl", "recon", "read",
              "Issue an HTTP request and read the response."),
    _CaiEntry("cai_netcat", "netcat", "network", "read",
              "Connect to a host/port and exchange data (banner grab)."),
    _CaiEntry("cai_netstat", "netstat", "network", "read",
              "Inspect local network connections/sockets."),
    _CaiEntry("cai_wget", "wget", "recon", "read",
              "Download a URL to inspect its contents."),
    _CaiEntry("cai_shodan_search", "shodan_search", "recon", "external",
              "Query the Shodan API for matching hosts (third-party)."),
    _CaiEntry("cai_shodan_host_info", "shodan_host_info", "recon", "external",
              "Fetch Shodan host detail by IP (third-party API)."),
    _CaiEntry("cai_generic_linux_command", "generic_linux_command", "recon",
              "active", "Execute an arbitrary Linux command (active)."),
    _CaiEntry("cai_exec_code", "execute_code", "exploitation", "active",
              "Create and execute a code file in a chosen language (active)."),
    # web
    _CaiEntry("cai_headers", "web_request_framework", "web", "read",
              "Inspect HTTP response headers / web request framework."),
    _CaiEntry("cai_js_surface_mapper", "js_surface_mapper", "web", "read",
              "Map a page's JS/endpoint attack surface (read-only crawl)."),
    # network
    _CaiEntry("cai_capture_traffic", "capture_remote_traffic", "network",
              "active", "Capture network traffic on a remote host over SSH (active)."),
    # crypto
    _CaiEntry("cai_strings", "strings_command", "crypto", "read",
              "Extract printable strings from a local file."),
    _CaiEntry("cai_decode64", "decode64", "crypto", "read",
              "Base64-decode input data."),
    _CaiEntry("cai_decode_hex_bytes", "decode_hex_bytes", "crypto", "read",
              "Decode a hex-byte string."),
    # misc
    _CaiEntry("cai_code_interpreter", "execute_python_code", "misc", "active",
              "Execute Python code in an interpreter (active)."),
    _CaiEntry("cai_reasoning", "thought", "misc", "read",
              "Structured reasoning / scratchpad (no side effects)."),
)


def _cai_specs() -> list[ToolSpec]:
    return [
        ToolSpec(
            name=e.catalog_name,
            category=e.category,
            source="cai",
            effect=e.effect,
            description=e.description,
        )
        for e in _CAI_TOOLS
    ]


def _osint_specs() -> list[ToolSpec]:
    return [ToolSpec(
        name="osint_search",
        category="recon",
        source="osint",
        # "external" — reaches third-party sites. OSINT_SEARCH_EFFECT is typed
        # ``str`` upstream; cast to the Effect literal it is guaranteed to be.
        effect=cast(Effect, OSINT_SEARCH_EFFECT),
        description="Live web OSINT search via the Camoufox anti-detect browser.",
    )]


def _build_catalog() -> list[ToolSpec]:
    specs = _kali_specs() + _scanner_specs() + _cai_specs() + _osint_specs()
    seen: set[str] = set()
    for spec in specs:
        if spec.name in seen:
            raise ValueError(f"duplicate tool name in catalog: {spec.name!r}")
        seen.add(spec.name)
    return specs


#: The single honest tool registry. Order: kali, scanners, cai, osint.
TOOL_CATALOG: list[ToolSpec] = _build_catalog()

#: Fast lookup name → effect, built once from the catalog.
_EFFECT_BY_NAME: dict[str, Effect] = {s.name: s.effect for s in TOOL_CATALOG}

#: Map a catalog ``cai_*`` name to its bare CAI ``@function_tool`` name.
CAI_TOOL_NAMES: dict[str, str] = {e.catalog_name: e.cai_name for e in _CAI_TOOLS}


def list_tools() -> list[ToolSpec]:
    """Return a copy of the full tool catalog."""
    return list(TOOL_CATALOG)


def tool_names() -> list[str]:
    """Return every catalog tool name."""
    return [s.name for s in TOOL_CATALOG]


def tool_effect(name: str) -> Effect:
    """Return the effect for a catalog tool name.

    Unknown names fail *safe* to ``active`` (an unclassified tool is never
    silently treated as harmless), matching ``aegis.effects`` conventions.
    """
    return _EFFECT_BY_NAME.get((name or "").strip(), "active")
