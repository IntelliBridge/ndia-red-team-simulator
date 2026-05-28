"""Small HTTP client used by the CLI when ``--api`` / ``AEGIS_MODE=api``.

Phase 4 v0.3.1 F4: ``--api`` routes write commands (``scan``, ``fix``,
``verify``, ``runs cancel``) through ``AEGIS_API_URL`` instead of the
local admission services. The API itself enforces the same RBAC +
audit pipeline (F6), so this is purely a transport-flip.

Authentication is bearer-only for the CLI — cookie auth is a browser
concept (v0.4.0). The token is read from ``AEGIS_TOKEN`` or from
``~/.config/aegis/token`` (first non-empty line).

This module is deliberately stdlib-only — the offline CLI must not
require ``requests`` or ``httpx`` just to do a single HTTP probe.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ApiError(Exception):
    """Raised when the API returns a non-2xx response."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"API returned {status_code}: {body}")


@dataclass
class ApiClient:
    base_url: str
    token: str | None
    timeout: int = 30

    def _request(self, method: str, path: str,
                 body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}{path}"
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, data=data, method=method,
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = resp.read().decode("utf-8") or "{}"
                return json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            body_bytes = exc.read() if exc.fp else b""
            raise ApiError(exc.code, body_bytes.decode("utf-8", "replace")) from exc

    def health(self) -> dict[str, Any] | None:
        """Return the /health response, or None if unreachable."""
        try:
            return self._request("GET", "/health")
        except (urllib.error.URLError, ApiError):
            return None

    # ----- write endpoints used by the CLI's --api dispatch -----

    def start_scan(self, *, target: str, project_id: str = "default",
                   scanner: str = "strix", instruction: str | None = None,
                   override_authorized: bool = False) -> dict[str, Any]:
        body = {"target": target, "project_id": project_id,
                "scanner": scanner}
        if instruction is not None:
            body["instruction"] = instruction
        if override_authorized:
            body["override_authorized"] = True
        return self._request("POST", "/v1/scans", body=body)

    def fix(self, *, finding_id: str, strategy: str = "patch",
            apply: bool = False, open_pr: bool = False,
            repo: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"strategy": strategy, "apply": apply,
                                "open_pr": open_pr}
        if repo is not None:
            body["repo"] = repo
        return self._request("POST", f"/v1/findings/{finding_id}/fix", body=body)

    def verify(self, *, finding_id: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/findings/{finding_id}/verify")

    def cancel_run(self, *, run_id: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/runs/{run_id}/cancel")


def is_api_mode(args) -> bool:
    """``--api`` flag (set on the parser) OR ``AEGIS_MODE=api`` in env."""
    if getattr(args, "global_api", False):
        return True
    return os.environ.get("AEGIS_MODE", "").lower() == "api"


def load_token() -> str | None:
    """Return the bearer token from env or the on-disk credentials file."""
    tok = os.environ.get("AEGIS_TOKEN")
    if tok:
        return tok.strip()
    path = Path.home() / ".config" / "aegis" / "token"
    if path.is_file():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                return line
    return None


def build_client() -> ApiClient:
    """Construct an ``ApiClient`` from environment defaults.

    Raises ``RuntimeError`` if ``AEGIS_API_URL`` is unset — calling this
    in offline mode is a programming error (callers must check
    ``is_api_mode`` first).
    """
    base_url = os.environ.get("AEGIS_API_URL")
    if not base_url:
        raise RuntimeError(
            "AEGIS_API_URL is not set. Set it (e.g. http://localhost:8000) "
            "or drop --api / AEGIS_MODE to fall back to the offline path."
        )
    return ApiClient(base_url=base_url, token=load_token())
