"""Small HTTP client used by the CLI when ``--api`` / ``REDSIM_MODE=api``.

Phase 4 v0.3.1 F4: ``--api`` routes write commands (``scan``, ``verify``,
``runs cancel``) through ``REDSIM_API_URL`` instead of the local admission
services. The API itself enforces the same RBAC +
audit pipeline (F6), so this is purely a transport-flip.

Authentication is bearer-only for the CLI — cookie auth is a browser
concept (v0.4.0). The token is read from ``REDSIM_TOKEN`` or from
``~/.config/redsim/token`` (first non-empty line).

This module is deliberately stdlib-only — the offline CLI must not
require ``requests`` or ``httpx`` just to do a single HTTP probe.
"""

from __future__ import annotations

import argparse
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

    def start_scan(self, *, target: str, scanner: str,
                   project_id: str = "default", instruction: str | None = None,
                   override_authorized: bool = False) -> dict[str, Any]:
        # ``POST /v1/scans`` was unmounted at M0 (spec section 17.1), so this
        # call answers 404 until the ML campaign client replaces it
        # (``POST /v1/models/{id}/attacks``). ``scanner`` stays required for
        # the offline ``redsim scan`` path that shares this signature.
        body: dict[str, Any] = {"target": target, "project_id": project_id,
                                "scanner": scanner}
        if instruction is not None:
            body["instruction"] = instruction
        if override_authorized:
            body["override_authorized"] = True
        return self._request("POST", "/v1/scans", body=body)

    def verify(self, *, finding_id: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/findings/{finding_id}/verify")

    def cancel_run(self, *, run_id: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/runs/{run_id}/cancel")


def is_api_mode(args: argparse.Namespace) -> bool:
    """``--api`` flag (set on the parser) OR ``REDSIM_MODE=api`` in env."""
    if getattr(args, "global_api", False):
        return True
    return os.environ.get("REDSIM_MODE", "").lower() == "api"


def load_token() -> str | None:
    """Return the bearer token from env or the on-disk credentials file."""
    tok = os.environ.get("REDSIM_TOKEN")
    if tok:
        return tok.strip()
    path = Path.home() / ".config" / "redsim" / "token"
    if path.is_file():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                return line
    return None


def build_client() -> ApiClient:
    """Construct an ``ApiClient`` from environment defaults.

    Raises ``RuntimeError`` if ``REDSIM_API_URL`` is unset — calling this
    in offline mode is a programming error (callers must check
    ``is_api_mode`` first).
    """
    base_url = os.environ.get("REDSIM_API_URL")
    if not base_url:
        raise RuntimeError(
            "REDSIM_API_URL is not set. Set it (e.g. http://localhost:8000) "
            "or drop --api / REDSIM_MODE to fall back to the offline path."
        )
    return ApiClient(base_url=base_url, token=load_token())
