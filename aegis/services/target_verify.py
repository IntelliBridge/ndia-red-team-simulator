"""Cloud-target ownership verification.

Before a target is marked ``verified`` we prove the operator actually
controls it:

- **url** targets: a DNS TXT record on the target's host carrying a
  deterministic, per-target token (``aegis-site-verification=<digest>``).
  The token is bound to the project + target value + a server-side secret
  so an operator can't forge it for a host they don't own.
- **github_repo** targets: the configured GitHub App installation must be
  able to access the repo (proves the org installed our App on it).
- **image** targets: not supported (no ownership channel) — callers get a
  clear error.

``dnspython`` is imported lazily so an environment without it degrades to a
clear error rather than failing at import time. No secret is ever returned
to the caller or written to an audit detail.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from urllib.parse import urlparse

# A non-secret dev default so local/dev runs work out of the box; production
# deployments set ``AEGIS_VERIFY_SECRET`` (or ``config.verify_secret``).
_DEV_SECRET = "aegis-dev-verify-secret"

_TXT_PREFIX = "aegis-site-verification="


@dataclass
class VerifyResult:
    verified: bool
    method: str
    detail: str


def _resolve_secret(config=None) -> str:
    """Resolve the verification secret: env > config > dev default."""
    env = os.environ.get("AEGIS_VERIFY_SECRET")
    if env:
        return env
    if config is not None and getattr(config, "verify_secret", None):
        return config.verify_secret
    return _DEV_SECRET


def extract_host(value: str) -> str:
    """Extract the bare hostname from a url-target value.

    Accepts full URLs (``https://app.example.com/path``) and bare hosts
    (``app.example.com``). Strips scheme, port, path, and brackets.
    """
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value.split("/", 1)[0].split(":", 1)[0]
    return host.strip("[]").rstrip(".")


def expected_dns_token(target, *, config=None) -> str:
    """Deterministic TXT verification value bound to the target + project.

    ``aegis-site-verification=<sha256(project_id:value:secret)[:32]>``. Pure
    and testable: same (project, value, secret) always yields the same token;
    a different project or value yields a different one. The secret keeps the
    token unforgeable without server-side knowledge.
    """
    secret = _resolve_secret(config)
    raw = f"{target.project_id}:{target.value}:{secret}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()[:32]
    return f"{_TXT_PREFIX}{digest}"


def verify_dns_txt(domain: str, expected: str) -> tuple[bool, str]:
    """Resolve TXT records for ``domain`` and look for ``expected``.

    ``domain`` may be a full url-target value or a bare host; the hostname is
    extracted either way. Returns ``(matched, detail)``. NXDOMAIN, no TXT
    records, timeouts, and a missing ``dnspython`` all degrade to
    ``(False, reason)`` — never an exception to the caller.
    """
    host = extract_host(domain)
    if not host:
        return False, "could not extract a hostname from the target value"

    try:
        import dns.resolver
    except ImportError:
        return False, (
            "dnspython is not installed; install the 'api' extra "
            "(pip install 'aegis-platform[api]') to enable DNS verification"
        )

    try:
        answers = dns.resolver.resolve(host, "TXT")
    except dns.resolver.NXDOMAIN:
        return False, f"no DNS record exists for {host} (NXDOMAIN)"
    except dns.resolver.NoAnswer:
        return False, f"{host} has no TXT records"
    except dns.resolver.NoNameservers:
        return False, f"no nameservers could answer the query for {host}"
    except dns.resolver.LifetimeTimeout:
        return False, f"DNS lookup for {host} timed out"
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"DNS lookup for {host} failed: {type(exc).__name__}"

    found: list[str] = []
    for rdata in answers:
        # dnspython TXT rdata join their (possibly chunked) byte strings;
        # decode to compare against the expected ASCII token.
        for chunk in getattr(rdata, "strings", []):
            text = chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else str(chunk)
            found.append(text)
        if not getattr(rdata, "strings", None):
            found.append(str(rdata).strip('"'))

    for text in found:
        if text == expected:
            return True, f"matched TXT record on {host}"
    return False, (
        f"{host} has TXT records but none match the expected token "
        f"({len(found)} record(s) checked)"
    )


def verify_github_repo(
    repo_value: str, installation_id: int | None
) -> tuple[bool, str]:
    """Confirm the configured GitHub App installation can access the repo.

    ``repo_value`` is an ``owner/name`` slug (a full GitHub URL is reduced to
    it). Uses ``GitHubClient`` to GET the repo through the installation token:
    a 2xx proves the App is installed on (and can see) the repo. Returns
    ``(True, detail)`` on success, ``(False, reason)`` otherwise. Degrades
    clearly when no ``installation_id`` is set or the App isn't configured.
    """
    repo = _normalise_repo(repo_value)
    if not repo or "/" not in repo:
        return False, (
            "github_repo target value must be an 'owner/name' slug "
            "or a github.com repo URL"
        )
    if installation_id is None:
        return False, (
            "no GitHub App installation is linked to this target; install the "
            "Aegis GitHub App on the repo and set the target's installation_id"
        )

    try:
        import httpx

        from aegis.integrations.github_app import GITHUB_API, GitHubClient
    except (ImportError, KeyError) as exc:
        return False, f"GitHub App is not configured: {type(exc).__name__}"

    try:
        client = GitHubClient(installation_id=installation_id)
    except KeyError:
        return False, (
            "GitHub App is not configured (AEGIS_GITHUB_APP_ID is unset)"
        )
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"could not build a GitHub client: {type(exc).__name__}"

    try:
        with httpx.Client(timeout=10) as http:
            resp = http.get(
                f"{GITHUB_API}/repos/{repo}",
                headers=client._headers(),
            )
    except httpx.HTTPError as exc:
        return False, f"GitHub request failed: {type(exc).__name__}"
    except Exception as exc:  # pragma: no cover - token/JWT exchange failure
        return False, f"GitHub authentication failed: {type(exc).__name__}"

    if resp.status_code == 404:
        return False, (
            f"installation {installation_id} cannot access {repo} "
            "(not found or App not installed on it)"
        )
    if resp.status_code >= 400:
        return False, (
            f"GitHub returned {resp.status_code} for {repo}"
        )
    return True, f"installation {installation_id} can access {repo}"


def _normalise_repo(value: str) -> str:
    """Reduce a github_repo target value to an ``owner/name`` slug."""
    value = value.strip()
    if "github.com" in value:
        # https://github.com/owner/name(.git) or git@github.com:owner/name.git
        tail = value.split("github.com", 1)[1].lstrip(":/")
        slug = tail.rstrip("/")
    else:
        slug = value.rstrip("/")
    if slug.endswith(".git"):
        slug = slug[: -len(".git")]
    return slug
