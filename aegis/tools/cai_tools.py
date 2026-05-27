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
from typing import Any

from aegis.config import AegisConfig
from aegis.safety import AuthorizationError, is_target_allowed
from aegis.tools.kali_client import KaliClient


@dataclass
class _Toolbelt:
    tools: list[Any]
    client: KaliClient


def _maybe_import_function_tool():
    """Return cai.sdk.agents.function_tool if available, else None."""
    try:
        from cai.sdk.agents import function_tool  # type: ignore
        return function_tool
    except ImportError:
        return None


def build_kali_toolbelt(config: AegisConfig, *, run_path: Path | None = None,
                       caller: str = "cai_tool") -> _Toolbelt:
    """Construct the CAI toolbelt.

    When CAI isn't importable, ``tools`` is an empty list — the agent then
    runs without these tools (or callers can short-circuit and skip CAI).
    """
    audit_path = (run_path / "tool-calls.jsonl") if run_path else None
    client = KaliClient(
        base_url=config.mcp_kali_url,
        target_allowlist=config.target_allowlist,
        audit_path=audit_path,
        caller=caller,
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

    return _Toolbelt(tools=[nmap_scan, nikto_scan, sqlmap_test], client=client)
