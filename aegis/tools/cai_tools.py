"""CAI function-tool wrappers around the MCP Kali REST client.

CAI is an optional runtime dependency. The toolbelt is built lazily so this
module can be imported without CAI installed; callers see an empty toolbelt
in that case and can fall back to a non-agentic path.

Each tool re-validates the target against the allowlist independently of
whatever the agent decides to send, and emits an audit record per call.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegis.config import AegisConfig
from aegis.safety import AuthorizationError, is_target_allowed
from aegis.tools.kali_client import KaliClient

if TYPE_CHECKING:
    from aegis.audit.chain import AuditWriter


@dataclass
class _Toolbelt:
    tools: list[Any]
    client: KaliClient


def _maybe_import_function_tool():
    """Return cai.sdk.agents.function_tool if available, else None."""
    try:
        from cai.sdk.agents import function_tool
        return function_tool
    except ImportError:
        return None


def build_kali_toolbelt(config: AegisConfig, *,
                       run_path: Path | None = None,
                       caller: str = "cai_tool",
                       audit_writer: AuditWriter | None = None,
                       run_id: str | None = None,
                       project_id: str | None = None) -> _Toolbelt:
    """Construct the CAI toolbelt.

    When CAI isn't importable, ``tools`` is an empty list — the agent
    then runs without these tools (or callers can short-circuit and
    skip CAI).

    Phase 4 v0.3.1 F8: every tool invocation emits an audit-chain event
    via ``audit_writer``. When the caller passes no writer but supplies
    ``run_path``, the underlying KaliClient writes through the safety
    layer's offline shim (a JsonlAuditWriter in single-file mode at
    ``<run_path>/audit.jsonl``) — same chain backend, just the compat
    file naming used by Phase 2. ``tool-calls.jsonl`` is retired.
    """
    if audit_writer is None and run_path is not None:
        # Match the safety layer's compat shim so this client and the
        # services layer write through the same on-disk chain file.
        from aegis.audit.chain import JsonlAuditWriter
        audit_writer = JsonlAuditWriter(run_path, single_file="audit.jsonl")
    client = KaliClient(
        base_url=config.mcp_kali_url,
        target_allowlist=config.target_allowlist,
        caller=caller,
        audit_writer=audit_writer,
        run_id=run_id,
        project_id=project_id,
    )

    function_tool = _maybe_import_function_tool()
    if function_tool is None:
        return _Toolbelt(tools=[], client=client)

    def _check(target: str) -> None:
        if not is_target_allowed(target, config.target_allowlist):
            raise AuthorizationError(
                f"Target '{target}' is not in the allowlist {config.target_allowlist}"
            )

    @function_tool
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str | None = None) -> dict[str, Any]:
        """Run nmap against a target. Target must be in the allowlist."""
        _check(target)
        result = client.run_tool("nmap", {"target": target, "scan_type": scan_type,
                                          **({"ports": ports} if ports else {})})
        return result.__dict__

    @function_tool
    def nikto_scan(target: str) -> dict[str, Any]:
        """Run nikto against a web target. Target must be in the allowlist."""
        _check(target)
        result = client.run_tool("nikto", {"target": target})
        return result.__dict__

    @function_tool
    def sqlmap_test(url: str, data: str | None = None) -> dict[str, Any]:
        """Probe a URL with sqlmap. URL must be in the allowlist."""
        _check(url)
        params = {"url": url}
        if data:
            params["data"] = data
        result = client.run_tool("sqlmap", params)
        return result.__dict__

    @function_tool
    def gobuster_scan(target: str, mode: str = "dir", wordlist: str | None = None) -> dict[str, Any]:
        """Brute-force paths/dirs/dns/vhosts on a target with gobuster. Target must be in the allowlist."""
        _check(target)
        # Coerce any unrecognised mode to the safe default; never forward arbitrary strings.
        if mode not in {"dir", "dns", "vhost", "fuzz"}:
            mode = "dir"
        params = {"url": target, "mode": mode, **({"wordlist": wordlist} if wordlist else {})}
        result = client.run_tool("gobuster", params)
        return result.__dict__

    @function_tool
    def dirb_scan(target: str, wordlist: str | None = None) -> dict[str, Any]:
        """Scan a web target for hidden content with dirb. Target must be in the allowlist."""
        _check(target)
        params = {"url": target, **({"wordlist": wordlist} if wordlist else {})}
        result = client.run_tool("dirb", params)
        return result.__dict__

    @function_tool
    def hydra_attack(target: str, service: str, username: str | None = None,
                     username_file: str | None = None, password: str | None = None,
                     password_file: str | None = None) -> dict[str, Any]:
        """Run a hydra credential attack against a service. Target must be in the allowlist."""
        _check(target)
        params = {"target": target, "service": service}
        if username:
            params["username"] = username
        if username_file:
            params["username_file"] = username_file
        if password:
            params["password"] = password
        if password_file:
            params["password_file"] = password_file
        result = client.run_tool("hydra", params)
        return result.__dict__

    @function_tool
    def wpscan_scan(url: str) -> dict[str, Any]:
        """Scan a WordPress site with wpscan. URL must be in the allowlist."""
        _check(url)
        result = client.run_tool("wpscan", {"url": url})
        return result.__dict__

    @function_tool
    def enum4linux_scan(target: str) -> dict[str, Any]:
        """Enumerate SMB/Windows info on a target with enum4linux. Target must be in the allowlist."""
        _check(target)
        result = client.run_tool("enum4linux", {"target": target})
        return result.__dict__

    @function_tool
    def metasploit_run(module: str, rhosts: str | None = None,
                       options: dict | None = None) -> dict[str, Any]:
        """Run a metasploit module. When rhosts is set it must be in the allowlist."""
        opts = dict(options or {})
        if rhosts:
            _check(rhosts)
            opts["RHOSTS"] = rhosts
        result = client.run_tool("metasploit", {"module": module, "options": opts})
        return result.__dict__

    @function_tool
    def john_crack(hash_file: str, wordlist: str | None = None,
                   format_type: str | None = None) -> dict[str, Any]:
        """Crack a local hash file with john. Operates on local files, no target check."""
        params = {"hash_file": hash_file, **({"wordlist": wordlist} if wordlist else {}),
                  **({"format": format_type} if format_type else {})}
        result = client.run_tool("john", params)
        return result.__dict__

    return _Toolbelt(tools=[nmap_scan, nikto_scan, sqlmap_test, gobuster_scan, dirb_scan,
                            hydra_attack, wpscan_scan, enum4linux_scan, metasploit_run,
                            john_crack], client=client)


@dataclass
class _ExtendedToolbelt:
    """A curated set of CAI function-tools + the OSINT search for agents.

    ``tools`` is the list of importable CAI ``@function_tool`` objects;
    ``names`` records the bare CAI tool names that were successfully loaded
    (useful for tests / introspection). Both are empty when CAI isn't
    importable — callers then compose agents without these tools.
    """

    tools: list[Any]
    names: list[str]


def build_extended_toolbelt() -> _ExtendedToolbelt:
    """Return CAI function-tools for a SAFE-by-default subset + OSINT search.

    The curated set is the read-only / analysis CAI tools that are safe to hand
    an agent without an approval gate, plus the Camoufox OSINT search (whose
    own ``external`` effect is gated downstream). Active CAI tools
    (generic_linux_command, exec_code, code_interpreter, capture_traffic) are
    deliberately *omitted* from the default belt — they remain catalogued as
    ``active`` tools but are not auto-wired here.

    Degrades gracefully: when CAI (or an individual tool module) isn't
    importable, the missing tool is skipped rather than raising. With no CAI at
    all the result is an empty belt.
    """
    function_tool = _maybe_import_function_tool()
    tools: list[Any] = []
    names: list[str] = []
    if function_tool is None:
        # CAI SDK absent → the function_tool-decorated modules can't import
        # either. Return an empty belt so agent composition can skip them.
        return _ExtendedToolbelt(tools=[], names=[])

    # (module path, attribute) for the curated SAFE-by-default CAI tools.
    _SAFE_CAI_TOOLS: tuple[tuple[str, str], ...] = (
        ("cai.tools.reconnaissance.nmap", "nmap"),
        ("cai.tools.reconnaissance.curl", "curl"),
        ("cai.tools.reconnaissance.netcat", "netcat"),
        ("cai.tools.reconnaissance.netstat", "netstat"),
        ("cai.tools.reconnaissance.wget", "wget"),
        ("cai.tools.reconnaissance.shodan", "shodan_search"),
        ("cai.tools.reconnaissance.shodan", "shodan_host_info"),
        ("cai.tools.web.headers", "web_request_framework"),
        ("cai.tools.web.js_surface_mapper", "js_surface_mapper"),
        ("cai.tools.reconnaissance.crypto_tools", "strings_command"),
        ("cai.tools.reconnaissance.crypto_tools", "decode64"),
        ("cai.tools.reconnaissance.crypto_tools", "decode_hex_bytes"),
        ("cai.tools.misc.reasoning", "thought"),
    )

    import importlib

    for module_path, attr in _SAFE_CAI_TOOLS:
        try:
            module = importlib.import_module(module_path)
            tool = getattr(module, attr)
        except Exception:  # noqa: BLE001 - a missing/partial tool is skipped
            continue
        tools.append(tool)
        names.append(attr)

    # The Camoufox OSINT search, wrapped as a CAI function-tool.
    from aegis.tools.osint_search import build_osint_search_tool
    osint_tool = build_osint_search_tool()
    if osint_tool is not None:
        tools.append(osint_tool)
        names.append("osint_search")

    return _ExtendedToolbelt(tools=tools, names=names)
