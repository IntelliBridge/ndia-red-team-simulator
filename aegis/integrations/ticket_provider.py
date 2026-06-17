"""Pluggable bidirectional ticket-sync providers.

A ``TicketProvider`` pushes an Aegis finding into an external tracker
(Jira / ServiceNow / Linear) and records/refreshes the resulting external
ticket. The default is :class:`NoneTicketProvider`, a no-op that raises a
clear error — so nothing reaches an external tracker unless an operator has
explicitly configured ``AEGIS_TICKET_PROVIDER`` and the matching creds.

Outbound HTTP mirrors ``aegis.integrations.github_app``: a short-timeout
``httpx.Client`` per call, creds read from the environment via ``from_env``.
Every HTTP failure is wrapped in :class:`TicketProviderError` with a
secret-free message (status code + provider name only, never the body or
the auth header) so a stack trace never leaks a token.

Backend selection mirrors ``aegis.llm.router`` / ``aegis.policy.engine``:
``resolve_ticket_provider`` reads ``AEGIS_TICKET_PROVIDER`` and caches the
result, with ``reset_ticket_provider_cache`` as the test seam.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import httpx

_TIMEOUT = 10.0


@dataclass(frozen=True)
class TicketRef:
    """A reference to an external tracker ticket created/updated for a finding."""

    provider: str
    external_id: str
    url: str | None = None
    status: str | None = None


class TicketProviderError(Exception):
    """Raised when a ticket operation fails.

    The message is deliberately secret-free: it names the provider and (for
    HTTP failures) the status code, never the response body or credentials.
    """


@runtime_checkable
class TicketProvider(Protocol):
    name: str

    def sync_finding(
        self, finding_id: str, schema_blob: dict, *, project_id: str
    ) -> TicketRef:
        """Create-or-update an external ticket from the finding. Returns a ref."""
        ...

    def fetch_status(self, external_id: str) -> str | None:
        """Pull the current external status of a ticket (bidirectional sync)."""
        ...


def _title_for(finding_id: str, schema_blob: dict) -> str:
    title = schema_blob.get("title") or finding_id
    severity = schema_blob.get("severity")
    if severity:
        return f"[{str(severity).upper()}] {title}"
    return str(title)


def _description_for(finding_id: str, schema_blob: dict) -> str:
    parts = [
        f"Aegis finding: {finding_id}",
        f"Severity: {schema_blob.get('severity', 'unknown')}",
    ]
    desc = schema_blob.get("description")
    if desc:
        parts.append("")
        parts.append(str(desc))
    component = schema_blob.get("affected_component")
    if component:
        parts.append(f"Affected component: {component}")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Default no-op provider
# ---------------------------------------------------------------------------


class NoneTicketProvider:
    """Default provider: no external tracker configured.

    Both operations raise :class:`TicketProviderError` with a clear message
    so callers (and the API) can surface a 4xx rather than silently
    succeeding with a phantom ticket.
    """

    name = "none"

    def sync_finding(
        self, finding_id: str, schema_blob: dict, *, project_id: str
    ) -> TicketRef:
        raise TicketProviderError("no ticket provider configured")

    def fetch_status(self, external_id: str) -> str | None:
        raise TicketProviderError("no ticket provider configured")


# ---------------------------------------------------------------------------
# Jira
# ---------------------------------------------------------------------------


class JiraTicketProvider:
    """Jira Cloud/Server REST v2 provider.

    sync_finding -> POST {base}/rest/api/2/issue
    fetch_status -> GET  {base}/rest/api/2/issue/{key}?fields=status
    Auth: HTTP Basic (user + API token), the standard Jira Cloud scheme.
    """

    name = "jira"

    def __init__(self, *, base_url: str, user: str, token: str, project_key: str):
        self.base_url = base_url.rstrip("/")
        self._user = user
        self._token = token
        self.project_key = project_key

    @classmethod
    def from_env(cls) -> JiraTicketProvider:
        try:
            return cls(
                base_url=os.environ["AEGIS_JIRA_URL"],
                user=os.environ["AEGIS_JIRA_USER"],
                token=os.environ["AEGIS_JIRA_TOKEN"],
                project_key=os.environ["AEGIS_JIRA_PROJECT_KEY"],
            )
        except KeyError as exc:
            raise TicketProviderError(
                f"jira provider missing required env var: {exc.args[0]}"
            ) from None

    def sync_finding(
        self, finding_id: str, schema_blob: dict, *, project_id: str
    ) -> TicketRef:
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": _title_for(finding_id, schema_blob),
                "description": _description_for(finding_id, schema_blob),
                "issuetype": {"name": "Bug"},
            }
        }
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                resp = client.post(
                    f"{self.base_url}/rest/api/2/issue",
                    json=payload,
                    auth=(self._user, self._token),
                    headers={"Accept": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            raise _wrap(self.name, exc) from None
        key = data["key"]
        return TicketRef(
            provider=self.name,
            external_id=key,
            url=f"{self.base_url}/browse/{key}",
            status=None,
        )

    def fetch_status(self, external_id: str) -> str | None:
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                resp = client.get(
                    f"{self.base_url}/rest/api/2/issue/{external_id}",
                    params={"fields": "status"},
                    auth=(self._user, self._token),
                    headers={"Accept": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            raise _wrap(self.name, exc) from None
        return (data.get("fields", {}).get("status") or {}).get("name")


# ---------------------------------------------------------------------------
# ServiceNow
# ---------------------------------------------------------------------------


class ServiceNowTicketProvider:
    """ServiceNow Table API provider (incident table).

    sync_finding -> POST {instance}/api/now/table/incident
    fetch_status -> GET  {instance}/api/now/table/incident/{sys_id}
    Auth: Bearer token (OAuth) in the Authorization header.
    """

    name = "servicenow"

    def __init__(self, *, instance_url: str, token: str):
        self.instance_url = instance_url.rstrip("/")
        self._token = token

    @classmethod
    def from_env(cls) -> ServiceNowTicketProvider:
        try:
            return cls(
                instance_url=os.environ["AEGIS_SERVICENOW_INSTANCE"],
                token=os.environ["AEGIS_SERVICENOW_TOKEN"],
            )
        except KeyError as exc:
            raise TicketProviderError(
                f"servicenow provider missing required env var: {exc.args[0]}"
            ) from None

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def sync_finding(
        self, finding_id: str, schema_blob: dict, *, project_id: str
    ) -> TicketRef:
        payload = {
            "short_description": _title_for(finding_id, schema_blob),
            "description": _description_for(finding_id, schema_blob),
            "category": "security",
        }
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                resp = client.post(
                    f"{self.instance_url}/api/now/table/incident",
                    json=payload,
                    headers=self._headers(),
                )
                resp.raise_for_status()
                result = resp.json()["result"]
        except httpx.HTTPError as exc:
            raise _wrap(self.name, exc) from None
        sys_id = result["sys_id"]
        return TicketRef(
            provider=self.name,
            external_id=sys_id,
            url=f"{self.instance_url}/nav_to.do?uri=incident.do?sys_id={sys_id}",
            status=result.get("state"),
        )

    def fetch_status(self, external_id: str) -> str | None:
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                resp = client.get(
                    f"{self.instance_url}/api/now/table/incident/{external_id}",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                result = resp.json()["result"]
        except httpx.HTTPError as exc:
            raise _wrap(self.name, exc) from None
        state: str | None = result.get("state")
        return state


# ---------------------------------------------------------------------------
# Linear
# ---------------------------------------------------------------------------


_LINEAR_API = "https://api.linear.app/graphql"

_LINEAR_CREATE = (
    "mutation IssueCreate($input: IssueCreateInput!) {"
    " issueCreate(input: $input) {"
    " success issue { id identifier url state { name } } } }"
)

_LINEAR_STATUS = (
    "query Issue($id: String!) { issue(id: $id) { state { name } } }"
)


class LinearTicketProvider:
    """Linear GraphQL provider.

    sync_finding -> POST {api} issueCreate mutation
    fetch_status -> POST {api} issue(id) query
    Auth: API key in the Authorization header.
    """

    name = "linear"

    def __init__(self, *, api_key: str, team_id: str):
        self._api_key = api_key
        self.team_id = team_id

    @classmethod
    def from_env(cls) -> LinearTicketProvider:
        try:
            return cls(
                api_key=os.environ["AEGIS_LINEAR_API_KEY"],
                team_id=os.environ["AEGIS_LINEAR_TEAM_ID"],
            )
        except KeyError as exc:
            raise TicketProviderError(
                f"linear provider missing required env var: {exc.args[0]}"
            ) from None

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self._api_key,
            "Content-Type": "application/json",
        }

    def _post(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                resp = client.post(
                    _LINEAR_API,
                    json={"query": query, "variables": variables},
                    headers=self._headers(),
                )
                resp.raise_for_status()
                body = resp.json()
        except httpx.HTTPError as exc:
            raise _wrap(self.name, exc) from None
        if body.get("errors"):
            # GraphQL surfaces errors with a 200; treat as a provider error.
            raise TicketProviderError("linear ticket request returned GraphQL errors")
        data: dict[str, Any] = body["data"]
        return data

    def sync_finding(
        self, finding_id: str, schema_blob: dict, *, project_id: str
    ) -> TicketRef:
        variables = {
            "input": {
                "teamId": self.team_id,
                "title": _title_for(finding_id, schema_blob),
                "description": _description_for(finding_id, schema_blob),
            }
        }
        data = self._post(_LINEAR_CREATE, variables)
        issue = data["issueCreate"]["issue"]
        return TicketRef(
            provider=self.name,
            external_id=issue["id"],
            url=issue.get("url"),
            status=(issue.get("state") or {}).get("name"),
        )

    def fetch_status(self, external_id: str) -> str | None:
        data = self._post(_LINEAR_STATUS, {"id": external_id})
        issue = data.get("issue") or {}
        return (issue.get("state") or {}).get("name")


def _wrap(provider: str, exc: httpx.HTTPError) -> TicketProviderError:
    """Wrap an httpx error in a secret-free TicketProviderError.

    Only the provider name and (for response errors) the HTTP status code
    are included — never the response body, URL, or auth header.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return TicketProviderError(
            f"{provider} ticket request failed with HTTP {exc.response.status_code}"
        )
    return TicketProviderError(f"{provider} ticket request failed: connection error")


# ---------------------------------------------------------------------------
# Backend resolution (mirrors aegis.llm.router / aegis.policy.engine)
# ---------------------------------------------------------------------------


_PROVIDER_CACHE: TicketProvider | None = None


def _build_provider(name: str) -> TicketProvider:
    name = (name or "none").strip().lower()
    if name == "none":
        return NoneTicketProvider()
    if name == "jira":
        return JiraTicketProvider.from_env()
    if name == "servicenow":
        return ServiceNowTicketProvider.from_env()
    if name == "linear":
        return LinearTicketProvider.from_env()
    raise TicketProviderError(f"unknown ticket provider: {name!r}")


def resolve_ticket_provider(config: Any = None) -> TicketProvider:
    """Return the configured ticket provider, cached for the process.

    Selection order: ``AEGIS_TICKET_PROVIDER`` env var wins; else
    ``config.ticket_provider`` if a config object is passed; else ``none``.
    Cache like the other resolvers; ``reset_ticket_provider_cache`` clears it
    for tests.
    """
    global _PROVIDER_CACHE
    if _PROVIDER_CACHE is not None:
        return _PROVIDER_CACHE
    name = os.environ.get("AEGIS_TICKET_PROVIDER")
    if name is None and config is not None:
        name = getattr(config, "ticket_provider", None)
    _PROVIDER_CACHE = _build_provider(name or "none")
    return _PROVIDER_CACHE


def reset_ticket_provider_cache() -> None:
    """Clear the cached provider — test seam (mirrors the other resolvers)."""
    global _PROVIDER_CACHE
    _PROVIDER_CACHE = None
