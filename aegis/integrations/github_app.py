"""GitHub App client.

Generates installation tokens (RS256 JWTs + GitHub installation-token
exchange) and exposes the small slice of the REST API Aegis needs:

  - create_pull_request
  - create_check_run
  - list_pr_changed_files (used by webhook PR-scoped scans)

The class is constructed with an installation id; rotating the private
key is a deployment-level concern (env var + restart).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import httpx

GITHUB_API = "https://api.github.com"


@dataclass
class PRInfo:
    number: int
    html_url: str
    head_sha: str
    base_ref: str


def _load_private_key() -> bytes:
    path = os.environ.get("AEGIS_GITHUB_APP_PRIVATE_KEY_PATH")
    if not path:
        raise RuntimeError("AEGIS_GITHUB_APP_PRIVATE_KEY_PATH not set")
    return Path(path).read_bytes()


def _app_jwt(app_id: str) -> str:
    from authlib.jose import jwt
    now = int(time.time())
    header = {"alg": "RS256"}
    payload = {"iat": now - 60, "exp": now + 540, "iss": app_id}
    # authlib's jwt.encode is untyped; .decode() is therefore Any.
    return cast(str, jwt.encode(header, payload, _load_private_key()).decode("ascii"))


class GitHubClient:
    def __init__(self, *, app_id: str | None = None,
                 installation_id: int,
                 user_agent: str = "aegis/0.3"):
        self.app_id = app_id or os.environ["AEGIS_GITHUB_APP_ID"]
        self.installation_id = installation_id
        self._token: str | None = None
        self._token_expiry = 0.0
        self.user_agent = user_agent

    def _installation_token(self) -> str:
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        jwt_token = _app_jwt(self.app_id)
        with httpx.Client(timeout=10) as client:
            resp = client.post(
                f"{GITHUB_API}/app/installations/{self.installation_id}/access_tokens",
                headers={"Authorization": f"Bearer {jwt_token}",
                         "Accept": "application/vnd.github+json",
                         "User-Agent": self.user_agent},
            )
            resp.raise_for_status()
            payload = resp.json()
        self._token = payload["token"]
        # ISO timestamp; rough parse
        from datetime import datetime
        self._token_expiry = datetime.fromisoformat(
            payload["expires_at"].replace("Z", "+00:00")
        ).timestamp()
        return self._token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"token {self._installation_token()}",
            "Accept": "application/vnd.github+json",
            "User-Agent": self.user_agent,
        }

    def create_pull_request(self, repo: str, *, head: str, base: str,
                            title: str, body: str) -> PRInfo:
        with httpx.Client(timeout=10) as client:
            resp = client.post(
                f"{GITHUB_API}/repos/{repo}/pulls",
                json={"title": title, "body": body, "head": head, "base": base},
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()
        return PRInfo(number=data["number"], html_url=data["html_url"],
                      head_sha=data["head"]["sha"], base_ref=data["base"]["ref"])

    def create_check_run(self, repo: str, *, head_sha: str, name: str,
                         conclusion: str, output: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(timeout=10) as client:
            resp = client.post(
                f"{GITHUB_API}/repos/{repo}/check-runs",
                json={"name": name, "head_sha": head_sha,
                      "status": "completed", "conclusion": conclusion,
                      "output": output},
                headers=self._headers(),
            )
            resp.raise_for_status()
            # httpx Response.json() is typed Any; the check-runs endpoint
            # returns a JSON object.
            return cast("dict[str, Any]", resp.json())

    def list_pr_files(self, repo: str, pr_number: int) -> list[dict]:
        with httpx.Client(timeout=10) as client:
            resp = client.get(
                f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}/files",
                headers=self._headers(),
            )
            resp.raise_for_status()
            # httpx Response.json() is typed Any; the files endpoint returns
            # a JSON array of file objects.
            return cast("list[dict[Any, Any]]", resp.json())
