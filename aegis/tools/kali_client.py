"""MCP Kali Server HTTP client with safety boundaries.

Phase 4 v0.3.1 F8: ``tool-calls.jsonl`` is retired. Every Kali tool
invocation lands on the canonical hash-chained audit via the injected
``audit_writer``; the forensic detail shape (digests + refs + duration,
no raw stdout/stderr) is built by ``aegis.audit.forensic.tool_detail``.
The legacy ``audit_path`` flat-JSONL fallback has been removed.
"""

from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass

from aegis.audit.forensic import tool_detail
from aegis.safety import AuthorizationError, is_target_allowed


@dataclass
class ToolResult:
    success: bool
    stdout: str
    stderr: str
    return_code: int
    timed_out: bool = False


class KaliClient:
    """HTTP client for MCP Kali Server REST API.

    Safety boundaries:
    - Only targets in allowlist can be scanned
    - Generic shell execution (/api/command) is disabled by default
    - Requires explicit authorization for non-localhost targets
    """

    ALLOWED_TOOLS = {
        "nmap", "gobuster", "dirb", "nikto", "sqlmap",
        "metasploit", "hydra", "john", "wpscan", "enum4linux",
    }

    def __init__(self, base_url: str = "http://127.0.0.1:5000",
                 target_allowlist: list[str] | None = None,
                 allow_generic_command: bool = False,
                 timeout: int = 180,
                 caller: str = "cli",
                 audit_writer=None,
                 run_id: str | None = None,
                 project_id: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.target_allowlist = target_allowlist or ["127.0.0.1", "localhost"]
        self.allow_generic_command = allow_generic_command
        self.timeout = timeout
        self.caller = caller
        self.audit_writer = audit_writer
        self.run_id = run_id
        self.project_id = project_id

    def _check_target_allowed(self, target: str) -> None:
        if not is_target_allowed(target, self.target_allowlist):
            raise AuthorizationError(
                f"Target '{target}' is not in the allowlist {self.target_allowlist}. "
                f"Add it to target_allowlist in aegis.yaml or pass "
                f"--i-understand-this-target-is-authorized."
            )

    def _audit(self, tool: str, params: dict, allowlist_check: str,
               result: ToolResult, duration_ms: int) -> None:
        """Emit one forensic audit row for the tool invocation.

        Phase 4 v0.3.1 F8: when no writer is wired the call is a no-op
        — the safety layer and toolbelt constructors both supply a
        canonical-chain writer; absence here means the caller
        explicitly opted out (e.g. ``health()`` smoke probes).
        """
        if self.audit_writer is None:
            return
        detail = tool_detail(
            tool=tool,
            params=params,
            return_code=result.return_code,
            duration_ms=duration_ms,
            stdout=result.stdout,
            stderr=result.stderr,
        )
        self.audit_writer.append(
            action=f"kali.{tool}",
            actor=self.caller,
            target=params.get("target") or params.get("url"),
            allowlist_check=allowlist_check,
            override=False,
            success=result.success,
            detail=detail,
            run_id=self.run_id,
            project_id=self.project_id,
        )

    def _post(self, path: str, data: dict) -> ToolResult:
        """Make a POST request to the Kali server."""
        url = f"{self.base_url}{path}"
        payload = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode())
                return ToolResult(
                    success=result.get("success", False),
                    stdout=result.get("stdout", result.get("output", "")),
                    stderr=result.get("stderr", ""),
                    return_code=result.get("return_code", 0),
                    timed_out=result.get("timed_out", False),
                )
        except Exception as e:
            return ToolResult(
                success=False, stdout="", stderr=str(e),
                return_code=-1,
            )

    def health(self) -> dict | None:
        """Check server health. Returns health dict or None if unreachable."""
        url = f"{self.base_url}/health"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            return None

    def is_available(self) -> bool:
        """Check if the Kali server is reachable."""
        return self.health() is not None

    def run_tool(self, tool_name: str, params: dict) -> ToolResult:
        """Run a named Kali tool with parameters.

        Two failure surfaces, deliberately asymmetric:

        - **Unknown tool** → returns ``ToolResult(success=False)`` (does
          not raise). An unrecognised tool name is a caller/programming
          error, surfaced as a failed result the caller can branch on.
        - **Disallowed target** → audits an allowlist ``"fail"`` row and
          then **raises** ``AuthorizationError``. A target outside the
          allowlist is a security-boundary violation that must halt the
          call loudly, never be swallowed into a result a caller might
          ignore. Direct callers (the named-tool helpers below, CAI
          agents) rely on this propagating; ``services.tools`` gates the
          same target via ``authorize()`` before reaching here, so for
          that path the raise is belt-and-suspenders.

        On success the tool is POSTed to the Kali server and its
        ``ToolResult`` is returned (with a per-call audit row either way).
        """
        if tool_name not in self.ALLOWED_TOOLS:
            result = ToolResult(
                success=False, stdout="",
                stderr=f"Tool '{tool_name}' is not in the allowed tools list: {self.ALLOWED_TOOLS}",
                return_code=-1,
            )
            self._audit(tool_name, params, "n/a", result, 0)
            return result

        target = params.get("target") or params.get("url") or ""
        allowlist_check = "n/a"
        if target:
            try:
                self._check_target_allowed(target)
                allowlist_check = "pass"
            except AuthorizationError:
                result = ToolResult(success=False, stdout="",
                                    stderr="target not in allowlist", return_code=-1)
                self._audit(tool_name, params, "fail", result, 0)
                raise

        start = time.monotonic()
        result = self._post(f"/api/tools/{tool_name}", params)
        duration_ms = int((time.monotonic() - start) * 1000)
        self._audit(tool_name, params, allowlist_check, result, duration_ms)
        return result

    # The named-tool helpers below are thin parameter builders over
    # ``run_tool``; routing through it (rather than calling ``_post``
    # directly) is what gives them the same allowlist gate *and* the
    # forensic audit row on both invocation and authorization denial.
    def nmap(self, target: str, scan_type: str = "-sV", ports: str | None = None, **kwargs) -> ToolResult:
        params = {"target": target, "scan_type": scan_type}
        if ports:
            params["ports"] = ports
        params.update(kwargs)
        return self.run_tool("nmap", params)

    def nikto(self, target: str, **kwargs) -> ToolResult:
        params = {"target": target}
        params.update(kwargs)
        return self.run_tool("nikto", params)

    def sqlmap(self, url: str, data: str | None = None, **kwargs) -> ToolResult:
        params = {"url": url}
        if data:
            params["data"] = data
        params.update(kwargs)
        return self.run_tool("sqlmap", params)

    def execute_command(self, command: str) -> ToolResult:
        """Execute an arbitrary command. DISABLED by default.

        Must set allow_generic_command=True in constructor.
        """
        if not self.allow_generic_command:
            return ToolResult(
                success=False, stdout="",
                stderr="Generic command execution is disabled. Set allow_generic_command=True to enable.",
                return_code=-1,
            )
        return self._post("/api/command", {"command": command})
