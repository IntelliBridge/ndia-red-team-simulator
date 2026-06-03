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
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str | None = None) -> dict:
        """Run nmap against a target. Target must be in the allowlist."""
        _check(target)
        result = client.run_tool("nmap", {"target": target, "scan_type": scan_type,
                                          **({"ports": ports} if ports else {})})
        return result.__dict__

    @function_tool
    def nikto_scan(target: str) -> dict:
        """Run nikto against a web target. Target must be in the allowlist."""
        _check(target)
        result = client.run_tool("nikto", {"target": target})
        return result.__dict__

    @function_tool
    def sqlmap_test(url: str, data: str | None = None) -> dict:
        """Probe a URL with sqlmap. URL must be in the allowlist."""
        _check(url)
        params = {"url": url}
        if data:
            params["data"] = data
        result = client.run_tool("sqlmap", params)
        return result.__dict__

    @function_tool
    def gobuster_scan(target: str, mode: str = "dir", wordlist: str | None = None) -> dict:
        """Brute-force paths/dirs/dns/vhosts on a target with gobuster. Target must be in the allowlist."""
        _check(target)
        # Coerce any unrecognised mode to the safe default; never forward arbitrary strings.
        if mode not in {"dir", "dns", "vhost", "fuzz"}:
            mode = "dir"
        params = {"url": target, "mode": mode, **({"wordlist": wordlist} if wordlist else {})}
        result = client.run_tool("gobuster", params)
        return result.__dict__

    @function_tool
    def dirb_scan(target: str, wordlist: str | None = None) -> dict:
        """Scan a web target for hidden content with dirb. Target must be in the allowlist."""
        _check(target)
        params = {"url": target, **({"wordlist": wordlist} if wordlist else {})}
        result = client.run_tool("dirb", params)
        return result.__dict__

    @function_tool
    def hydra_attack(target: str, service: str, username: str | None = None,
                     username_file: str | None = None, password: str | None = None,
                     password_file: str | None = None) -> dict:
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
    def wpscan_scan(url: str) -> dict:
        """Scan a WordPress site with wpscan. URL must be in the allowlist."""
        _check(url)
        result = client.run_tool("wpscan", {"url": url})
        return result.__dict__

    @function_tool
    def enum4linux_scan(target: str) -> dict:
        """Enumerate SMB/Windows info on a target with enum4linux. Target must be in the allowlist."""
        _check(target)
        result = client.run_tool("enum4linux", {"target": target})
        return result.__dict__

    @function_tool
    def metasploit_run(module: str, rhosts: str | None = None,
                       options: dict | None = None) -> dict:
        """Run a metasploit module. When rhosts is set it must be in the allowlist."""
        opts = dict(options or {})
        if rhosts:
            _check(rhosts)
            opts["RHOSTS"] = rhosts
        result = client.run_tool("metasploit", {"module": module, "options": opts})
        return result.__dict__

    @function_tool
    def john_crack(hash_file: str, wordlist: str | None = None,
                   format_type: str | None = None) -> dict:
        """Crack a local hash file with john. Operates on local files, no target check."""
        params = {"hash_file": hash_file, **({"wordlist": wordlist} if wordlist else {}),
                  **({"format": format_type} if format_type else {})}
        result = client.run_tool("john", params)
        return result.__dict__

    return _Toolbelt(tools=[nmap_scan, nikto_scan, sqlmap_test, gobuster_scan, dirb_scan,
                            hydra_attack, wpscan_scan, enum4linux_scan, metasploit_run,
                            john_crack], client=client)
