"""Tool-execution service.

Wraps ``aegis.tools.kali_client.KaliClient`` behind the authorization +
audit boundary so every Kali tool invocation lands on the canonical chain.

Phase 2's KaliClient still maintains a per-call audit file at
``tool-calls.jsonl`` for offline / back-compat. M2 will retire that second
writer and route through the central audit chain via an injected
``AuditWriter``; this service is the entry point that does so.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegis.config import AegisConfig
from aegis.safety import AuthorizationError, authorize
from aegis.state import RunState
from aegis.tools.kali_client import KaliClient, ToolResult


@dataclass
class ToolOutcome:
    success: bool
    tool: str
    return_code: int
    stdout: str
    stderr: str
    error: str | None = None


def run_kali_tool(
    *,
    name: str,
    params: dict[str, Any],
    run_state: RunState,
    actor: str,
    config: AegisConfig,
    override_authorized: bool = False,
    client: KaliClient | None = None,
) -> ToolOutcome:
    """Run a named Kali tool with safety + audit at the service boundary."""
    target = params.get("target") or params.get("url") or ""
    try:
        authorize(
            f"kali.{name}", target or "n/a",
            allowlist=config.target_allowlist,
            run_path=run_state.run_path,
            override_authorized=override_authorized,
            detail={"actor": actor, "tool": name, "params": params},
        )
    except AuthorizationError as exc:
        return ToolOutcome(success=False, tool=name, return_code=-1,
                           stdout="", stderr=str(exc),
                           error="authorization refused")

    if client is None:
        client = KaliClient(
            base_url=config.mcp_kali_url,
            target_allowlist=config.target_allowlist,
            audit_path=run_state.run_path / "tool-calls.jsonl",
            caller=f"service:{actor}",
        )

    result: ToolResult = client.run_tool(name, params)
    return ToolOutcome(
        success=result.success,
        tool=name,
        return_code=result.return_code,
        stdout=result.stdout,
        stderr=result.stderr,
    )
