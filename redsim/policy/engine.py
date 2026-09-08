"""Pluggable authorization policy engine (role-gate seam).

The platform's *role gate* — ``redsim.api.policy.check`` at every mutating
route — historically inlined a static role-rank table. This module lifts
that decision behind a small ``PolicyEngine`` abstraction so an operator
can keep the built-in static rules (the default, behaviour-identical) or
delegate to an external policy service over REST:

- ``StaticPolicyEngine`` — the exact built-in role-rank logic. Default.
- ``OPAPolicyEngine`` — POSTs an ``input`` document to an Open Policy
  Agent data endpoint and reads ``result.allow`` / ``result.reason``.
- ``CedarPolicyEngine`` — POSTs an authorization query to a
  ``cedar-agent``-style REST endpoint and reads its allow/deny decision.

Both external engines **fail closed**: any connection error, non-200
response, or malformed body yields ``PolicyDecision(allowed=False, …)``.

This module deliberately avoids importing FastAPI / SQLAlchemy at module
scope so ``redsim.policy`` stays importable by pure callers (see the
package docstring). The static role tables live in ``redsim.api.policy``
and are imported lazily inside ``StaticPolicyEngine`` only.

Backend selection mirrors ``redsim.storage.blobs.open_blob_store`` and
``redsim.audit.chain.resolve_writer``: read ``REDSIM_POLICY_ENGINE`` from
the environment, construct once per process, expose a reset hook for
tests.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

# httpx ships in the api/worker extras. Only the OPA/Cedar engines reach the
# REST path; keep ``redsim.policy`` importable by pure callers (the static engine
# and CI gate) without it. Tests patch ``redsim.policy.engine.httpx.Client``, so
# the name must stay a module attribute when httpx is installed.
try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover - exercised in the minimal unit env
    httpx = cast("Any", None)

if TYPE_CHECKING:
    from redsim.api.auth import CurrentUser
    from redsim.config import RedsimConfig

logger = logging.getLogger(__name__)

# Short timeout: the role gate is on the hot path of every mutating
# request, so a hung policy service must not stall the API. Failing
# closed on timeout is the safe default.
_HTTP_TIMEOUT = 3.0


@dataclass(frozen=True)
class PolicyDecision:
    """The outcome of evaluating a :class:`PolicyRequest`."""

    allowed: bool
    reason: str | None = None


@dataclass(frozen=True)
class PolicyRequest:
    """A normalized authorization question.

    ``subject`` carries the caller identity (``sub``, ``email``,
    ``project_memberships``, ``is_system``); ``action`` is the
    ``Action`` value string; ``resource`` scopes the question
    (``project_id`` and optional ``target`` / ``run_id`` /
    ``effect_class``); ``context`` carries request-time flags such as
    ``override_authorized``.
    """

    subject: dict[str, Any]
    action: str
    resource: dict[str, Any]
    context: dict[str, Any] = field(default_factory=dict)

    def to_input(self) -> dict[str, Any]:
        """The plain dict external engines embed as their query body."""
        return {
            "subject": self.subject,
            "action": self.action,
            "resource": self.resource,
            "context": self.context,
        }


def build_request(
    user: CurrentUser,
    action: str,
    project_id: str,
    **extra: Any,
) -> PolicyRequest:
    """Construct a :class:`PolicyRequest` from a ``CurrentUser``.

    ``extra`` keys are routed: ``override_authorized`` and any other
    request-time flag land in ``context``; ``target`` / ``run_id`` /
    ``effect_class`` land in ``resource``.
    """
    resource: dict[str, Any] = {"project_id": project_id}
    context: dict[str, Any] = {}
    _RESOURCE_KEYS = {"target", "run_id", "effect_class"}
    for key, value in extra.items():
        if key in _RESOURCE_KEYS:
            resource[key] = value
        else:
            context[key] = value
    return PolicyRequest(
        subject={
            "sub": user.sub,
            "email": user.email,
            "project_memberships": dict(user.project_memberships),
            "is_system": user.is_system,
        },
        action=action,
        resource=resource,
        context=context,
    )


@runtime_checkable
class PolicyEngine(Protocol):
    """A pluggable authorization decision point for the role gate."""

    def evaluate(self, req: PolicyRequest) -> PolicyDecision: ...


# ----------------------------------------------------------------------------
# Static engine — the built-in, behaviour-identical default
# ----------------------------------------------------------------------------


class StaticPolicyEngine:
    """The built-in role-rank rules.

    Reproduces ``redsim.api.policy.check`` exactly: a system principal is
    always allowed; otherwise the caller's role for the request's
    ``project_id`` is resolved from ``project_memberships`` and compared
    against the action's minimum required role using the shared
    ``_ROLE_RANK`` / ``_ACTION_MIN_ROLE`` tables.
    """

    def evaluate(self, req: PolicyRequest) -> PolicyDecision:
        # Imported lazily so importing redsim.policy.engine does not drag in
        # FastAPI for pure (CLI / worker) callers.
        from redsim.api.policy import _ACTION_MIN_ROLE, _ROLE_RANK, Action

        subject = req.subject
        project_id = req.resource.get("project_id", "")
        if subject.get("is_system"):
            return PolicyDecision(allowed=True)

        memberships = subject.get("project_memberships") or {}
        role = memberships.get(project_id)
        if not role:
            return PolicyDecision(
                allowed=False,
                reason=(
                    f"user {subject.get('email')} has no membership on "
                    f"project {project_id}"
                ),
            )

        action = Action(req.action)
        required = _ACTION_MIN_ROLE[action]
        if _ROLE_RANK.get(role, 0) < _ROLE_RANK[required]:
            return PolicyDecision(
                allowed=False,
                reason=(
                    f"role '{role}' cannot perform '{action.value}' on "
                    f"project {project_id}"
                ),
            )
        return PolicyDecision(allowed=True)


# ----------------------------------------------------------------------------
# External engines — OPA + Cedar over REST (fail closed)
# ----------------------------------------------------------------------------


def _post_json(url: str, body: dict[str, Any]) -> dict[str, Any] | None:
    """POST ``body`` as JSON; return parsed JSON or ``None`` on any failure.

    Any transport error, non-2xx status, or non-JSON body is swallowed
    and logged (no request body / secrets are logged) so the caller can
    fail closed. ``None`` means "the policy engine could not give a
    usable answer".
    """
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
            resp = client.post(url, json=body)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        return data
    except httpx.HTTPStatusError as exc:
        logger.warning("policy engine returned %s for %s",
                       exc.response.status_code, url)
        return None
    except httpx.HTTPError as exc:
        logger.warning("policy engine request failed for %s: %s",
                       url, type(exc).__name__)
        return None
    except ValueError as exc:  # malformed / non-JSON body
        logger.warning("policy engine returned malformed JSON for %s: %s",
                       url, type(exc).__name__)
        return None


class OPAPolicyEngine:
    """Delegate to an Open Policy Agent data endpoint.

    POSTs ``{"input": <request>}`` to ``{base_url}{path}`` (default
    ``/v1/data/redsim/authz``) and reads OPA's ``result.allow`` (bool) and
    optional ``result.reason``. Fails closed on any error.
    """

    def __init__(self, base_url: str,
                 path: str = "/v1/data/redsim/authz") -> None:
        self.base_url = base_url.rstrip("/")
        self.path = "/" + path.lstrip("/")
        self.url = f"{self.base_url}{self.path}"

    def evaluate(self, req: PolicyRequest) -> PolicyDecision:
        payload = _post_json(self.url, {"input": req.to_input()})
        if payload is None:
            return PolicyDecision(
                allowed=False,
                reason="policy engine unavailable: OPA request failed",
            )
        result = payload.get("result")
        if not isinstance(result, dict) or not isinstance(
            result.get("allow"), bool
        ):
            logger.warning("OPA response missing result.allow for %s", self.url)
            return PolicyDecision(
                allowed=False,
                reason="policy engine unavailable: malformed OPA result",
            )
        allow = result["allow"]
        reason = result.get("reason")
        return PolicyDecision(
            allowed=allow,
            reason=str(reason) if reason is not None else None,
        )


class CedarPolicyEngine:
    """Delegate to a ``cedar-agent``-style authorization endpoint.

    POSTs the request as ``{"principal", "action", "resource", "context"}``
    to ``{base_url}/v1/is_authorized`` and reads a ``decision`` of
    ``Allow`` / ``Deny`` (case-insensitive) plus an optional ``reason``.
    Fails closed on any error.
    """

    def __init__(self, base_url: str,
                 path: str = "/v1/is_authorized") -> None:
        self.base_url = base_url.rstrip("/")
        self.path = "/" + path.lstrip("/")
        self.url = f"{self.base_url}{self.path}"

    def evaluate(self, req: PolicyRequest) -> PolicyDecision:
        body = {
            "principal": req.subject,
            "action": req.action,
            "resource": req.resource,
            "context": req.context,
        }
        payload = _post_json(self.url, body)
        if payload is None:
            return PolicyDecision(
                allowed=False,
                reason="policy engine unavailable: Cedar request failed",
            )
        decision = payload.get("decision")
        if not isinstance(decision, str):
            logger.warning("Cedar response missing decision for %s", self.url)
            return PolicyDecision(
                allowed=False,
                reason="policy engine unavailable: malformed Cedar result",
            )
        allow = decision.strip().lower() == "allow"
        reason = payload.get("reason")
        return PolicyDecision(
            allowed=allow,
            reason=str(reason) if reason is not None else None,
        )


# ----------------------------------------------------------------------------
# Backend resolution (mirror resolve_writer / open_blob_store)
# ----------------------------------------------------------------------------

_DEFAULT_OPA_URL = "http://localhost:8181"
_DEFAULT_OPA_PATH = "/v1/data/redsim/authz"
_DEFAULT_CEDAR_URL = "http://localhost:8180"

# Module-level lazy singleton: the role gate hits this on every mutating
# request, so we construct the engine once per process. Tests call
# reset_policy_engine() in teardown so engine state can't leak.
_ENGINE: PolicyEngine | None = None


def _build_policy_engine(config: RedsimConfig | None = None) -> PolicyEngine:
    """Construct the engine selected by ``REDSIM_POLICY_ENGINE`` / config.

    Resolution (env wins, falling back to ``config`` then defaults):

    - ``static`` (default) → :class:`StaticPolicyEngine`
    - ``opa`` → :class:`OPAPolicyEngine` over ``REDSIM_OPA_URL`` /
      ``REDSIM_OPA_PATH``
    - ``cedar`` → :class:`CedarPolicyEngine` over ``REDSIM_CEDAR_URL``
    """
    backend = os.environ.get("REDSIM_POLICY_ENGINE")
    if backend is None and config is not None:
        backend = config.policy_engine
    backend = (backend or "static").strip().lower()

    if backend == "opa":
        base_url = os.environ.get("REDSIM_OPA_URL") or (
            config.opa_url if config and config.opa_url else _DEFAULT_OPA_URL
        )
        path = os.environ.get("REDSIM_OPA_PATH") or (
            config.opa_path if config and config.opa_path else _DEFAULT_OPA_PATH
        )
        return OPAPolicyEngine(base_url, path)
    if backend == "cedar":
        base_url = os.environ.get("REDSIM_CEDAR_URL") or (
            config.cedar_url if config and config.cedar_url else _DEFAULT_CEDAR_URL
        )
        return CedarPolicyEngine(base_url)
    if backend != "static":
        logger.warning(
            "unknown REDSIM_POLICY_ENGINE=%r; falling back to static", backend
        )
    return StaticPolicyEngine()


def resolve_policy_engine(config: RedsimConfig | None = None) -> PolicyEngine:
    """Return the process-wide policy engine, constructing it on first use.

    Mirrors ``resolve_writer`` / ``open_blob_store``. The result is cached
    for the process lifetime; ``reset_policy_engine()`` clears the cache
    (tests, or after an env change).
    """
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = _build_policy_engine(config)
    return _ENGINE


def reset_policy_engine() -> None:
    """Drop the cached engine so the next ``resolve_policy_engine`` rebuilds.

    Test seam — call in teardown so engine state never leaks between
    tests, and after changing ``REDSIM_POLICY_ENGINE`` at runtime.
    """
    global _ENGINE
    _ENGINE = None
