"""Tool-execution service.

Wraps ``aegis.tools.kali_client.KaliClient`` behind the authorization +
audit boundary so every Kali tool invocation lands on the canonical
hash-chained audit. Phase 4 v0.3.1 F8 retired the side-channel
``tool-calls.jsonl`` file — the KaliClient now requires an
``audit_writer`` and writes through the shared chain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from aegis.config import AegisConfig
from aegis.safety import AuthorizationError, authorize
from aegis.state import RunStateAPI
from aegis.tools.kali_client import KaliClient, ToolResult

if TYPE_CHECKING:
    from aegis.audit.chain import AuditWriter


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
    run_state: RunStateAPI,
    actor: str,
    config: AegisConfig,
    override_authorized: bool = False,
    client: KaliClient | None = None,
    audit_writer: AuditWriter | None = None,
    run_id: str | None = None,
    project_id: str | None = None,
) -> ToolOutcome:
    """Run a named Kali tool with safety + audit at the service boundary.

    ``audit_writer`` (Phase 4 v0.3.1 F8) is the canonical destination
    for both the authorize() event and the tool's per-call audit row.
    When ``None``, the safety layer constructs the offline
    ``JsonlAuditWriter`` compat shim — this fallback is retired by
    F3+F6 once every service caller threads a writer explicitly.
    """
    target = params.get("target") or params.get("url") or ""
    try:
        authorize(
            f"kali.{name}", target or "n/a",
            allowlist=config.target_allowlist,
            run_path=run_state.run_path,
            override_authorized=override_authorized,
            actor=actor, writer=audit_writer,
            run_id=run_id, project_id=project_id,
            detail={"actor": actor, "tool": name, "params": params},
        )
    except AuthorizationError as exc:
        return ToolOutcome(success=False, tool=name, return_code=-1,
                           stdout="", stderr=str(exc),
                           error="authorization refused")

    if client is None:
        # The KaliClient also emits its own per-tool audit row with
        # forensic detail (return code, duration, stdout/stderr digests).
        # We thread the same writer in so all events land on one chain.
        client = KaliClient(
            base_url=config.mcp_kali_url,
            target_allowlist=config.target_allowlist,
            caller=f"service:{actor}",
            audit_writer=audit_writer,
            run_id=run_id,
            project_id=project_id,
        )

    result: ToolResult = client.run_tool(name, params)
    return ToolOutcome(
        success=result.success,
        tool=name,
        return_code=result.return_code,
        stdout=result.stdout,
        stderr=result.stderr,
    )
