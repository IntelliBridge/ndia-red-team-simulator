"""Per-event GitHub webhook handlers (Phase 4 v0.4.1 F23a/b/c).

The webhook receiver (``aegis.integrations.github_webhooks``) verifies
HMAC + replay-prunes, then dispatches into these handlers. The scope
of a PR run is a structured ``PRScope`` (not a free-text instruction
string) so scanner adapters can filter results to the PR's
``changed_files`` programmatically.

Fork PRs engage restricted mode: no --apply, no --open-pr, no secrets
mounted, clone depth 1, path allowlist. The Aegis findings still post
back as a Check Run via the installation token so upstream maintainers
see them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PRScope:
    """Structured PR-scoped scan input.

    Lifted out of the webhook payload by ``pr_scope_from_payload``;
    scanner adapters accept ``scope=PRScope`` and filter their reported
    findings to ``changed_files``. Forks engage restricted mode
    (`restricted_mode_for(scope)`).
    """
    repo: str                       # "owner/repo"
    pr_number: int
    base_sha: str
    head_sha: str
    base_ref: str
    head_ref: str
    changed_files: list[str] = field(default_factory=list)
    fork: bool = False              # head repo is in a different account
    installation_id: int | None = None
    head_repo_full_name: str | None = None


@dataclass
class RestrictedMode:
    """Computed policy for a PR run.

    The defaults (no apply / no open_pr / depth-1 clone / secrets off)
    track ``PRScope.fork=True``; merge-PRs in the same org get the
    permissive defaults.
    """
    apply: bool                     # commit + push patches?
    open_pr: bool                   # open a fix-PR after the run?
    clone_depth: int                # 1 for forks; 0 (full) otherwise
    mount_secrets: bool             # mount API keys into the worker?
    path_allowlist: list[str]       # paths the scanner may touch
    reason: str                     # why restricted (audit detail)


def pr_scope_from_payload(payload: dict[str, Any]) -> PRScope:
    """Build a ``PRScope`` from a ``pull_request`` webhook payload.

    ``payload["pull_request"]["head"]["repo"]["full_name"]`` differing
    from the base repo's ``full_name`` is the canonical fork signal —
    GitHub also exposes ``head.repo.fork`` but it isn't reliable on
    cross-fork PRs through forks of forks.
    """
    pr = payload.get("pull_request") or {}
    base = pr.get("base") or {}
    head = pr.get("head") or {}
    base_repo = base.get("repo") or {}
    head_repo = head.get("repo") or {}

    base_full_name = base_repo.get("full_name", "")
    head_full_name = head_repo.get("full_name", "")
    fork = bool(head_full_name) and head_full_name != base_full_name

    installation = payload.get("installation") or {}

    return PRScope(
        repo=base_full_name,
        pr_number=int(pr.get("number") or payload.get("number") or 0),
        base_sha=str(base.get("sha") or ""),
        head_sha=str(head.get("sha") or ""),
        base_ref=str(base.get("ref") or ""),
        head_ref=str(head.get("ref") or ""),
        changed_files=[],  # populated separately via the /files endpoint
        fork=fork,
        installation_id=installation.get("id"),
        head_repo_full_name=head_full_name or None,
    )


def restricted_mode_for(scope: PRScope) -> RestrictedMode:
    """Return the ``RestrictedMode`` that should govern this PR's run.

    Forks: no writes, depth-1 clone, no secrets, narrow path allowlist
    derived from ``changed_files``. Non-forks: permissive defaults.
    """
    if scope.fork:
        return RestrictedMode(
            apply=False,
            open_pr=False,
            clone_depth=1,
            mount_secrets=False,
            path_allowlist=list(scope.changed_files),
            reason="fork.restricted=true",
        )
    return RestrictedMode(
        apply=False,            # default conservative; explicit opt-in via UI
        open_pr=False,
        clone_depth=0,
        mount_secrets=True,
        path_allowlist=[],      # empty == no restriction
        reason="trusted",
    )


def scope_audit_detail(
    scope: PRScope, mode: RestrictedMode,
) -> dict[str, Any]:
    """Forensic audit detail for the scope + mode at admission time."""
    return {
        "repo": scope.repo,
        "pr_number": scope.pr_number,
        "base_sha": scope.base_sha,
        "head_sha": scope.head_sha,
        "fork": scope.fork,
        "head_repo": scope.head_repo_full_name,
        "changed_file_count": len(scope.changed_files),
        "restricted_mode": {
            "apply": mode.apply,
            "open_pr": mode.open_pr,
            "clone_depth": mode.clone_depth,
            "mount_secrets": mode.mount_secrets,
            "path_allowlist": mode.path_allowlist,
            "reason": mode.reason,
        },
    }


# ----- event dispatch ------------------------------------------------------


def on_pull_request_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Top-level dispatcher for ``pull_request`` events.

    Returns the structured handler result so the webhook route can
    surface it for diagnostics; the actual scan + Check Run posting
    happens via the admission service inside the handler.
    """
    action = payload.get("action") or ""
    scope = pr_scope_from_payload(payload)
    mode = restricted_mode_for(scope)
    return {
        "action": action,
        "scope": {
            "repo": scope.repo,
            "pr_number": scope.pr_number,
            "fork": scope.fork,
        },
        "restricted_mode": mode.reason,
    }
