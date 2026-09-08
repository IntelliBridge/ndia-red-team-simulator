"""Effect classification — the spine of the unified human-in-the-loop gate.

Every capability the platform can invoke (a scanner / attack adapter, a tool an
adapter drives, a gated action) has an **effect class** describing its blast
radius:

- ``read``     — no meaningful side effect on the target: recon/enumeration,
                 static analysis, dependency/SBOM scans, generating a diff or a
                 plan, dry-run checks. Safe to run freely (the target allowlist
                 is the only gate).
- ``active``   — attack / state-changing semantics against a live system:
                 exploitation, credential brute-force, running an exploit
                 module, live host hardening. Can compromise, lock out, or
                 disrupt — so it is gated *propose → approve → act*.
- ``external`` — leaves the local sandbox: pushing a branch, opening a PR,
                 egressing a report. Same gate as ``active``.

The gate is one idea applied everywhere: a ``read`` capability runs; an
``active`` / ``external`` one only performs its irreversible step when the
caller explicitly opts in (``execute=true`` / ``apply=true`` / ``open_pr=true``)
**and** the actor holds the ``approver`` role. Otherwise it returns a reviewable
*proposal* (an attack plan, a hardening plan, a diff) for a human to approve.

This module is intentionally dependency-free (no imports from the API or
attack-adapter layers) so any layer can import it without a cycle. The
domain/tool tables below are retained as the classification vocabulary the
ML attack adapters reuse; the pentest agent/Kali registries that once
populated them were removed with the pentest domain.
"""

from __future__ import annotations

from typing import Any, Literal

Effect = Literal["read", "active", "external"]

#: Effects that must clear the human gate (explicit opt-in + approver role).
_GATED: frozenset[Effect] = frozenset({"active", "external"})


def requires_approval(effect: Effect | str) -> bool:
    """True when ``effect`` is state-changing / leaves the sandbox."""
    return effect in _GATED


# --- Domains ----------------------------------------------------------------
# Default effect per capability ``Domain``. Per-capability overrides may narrow
# this (e.g. a re-tester is ``audit`` by domain but re-fires an attack to verify
# a fix → ``active``). An unknown domain is treated as ``active`` so a mis-tagged
# or third-party capability fails *safe* (gated), never open.
_DOMAIN_DEFAULT_EFFECT: dict[str, Effect] = {
    "offensive": "active",
    "defensive": "active",
    "remediation": "read",   # produces a proposal (diff / plan); applying it is the gated step
    "forensic": "read",
    "recon": "read",
    "audit": "read",
}


def domain_default_effect(domain: str | None) -> Effect:
    return _DOMAIN_DEFAULT_EFFECT.get(domain or "", "active")


# --- Tools / adapters -------------------------------------------------------
# Effect per capability *name* (a scanner / attack adapter, or a tool an adapter
# invokes). Scanning / enumeration / local-only work is ``read``; attack or
# state-changing work is ``active``. The table starts empty in this fork — the
# pentest Kali-tool table that populated it was removed with the pentest
# domain — and the adversarial-ML attack adapters register their entries here.
# An unlisted name defaults to ``active`` (fail-safe — an unclassified
# capability is never silently treated as harmless).
_TOOL_EFFECTS: dict[str, Effect] = {}


def tool_effect(name: str | None) -> Effect:
    """Authoritative ``name -> effect`` lookup; unknown or blank fails safe.

    Case-insensitive and whitespace-tolerant. A name with no entry (and an
    empty / ``None`` name) is ``active`` so it stays gated.
    """
    key = (name or "").strip().lower()
    if not key:
        return "active"
    return _TOOL_EFFECTS.get(key, "active")


# --- Proposal plans ---------------------------------------------------------

_EXECUTE_NOTE: dict[str, str] = {
    "offensive": "Executing will run active exploitation / attack tooling against the target.",
    "defensive": "Executing will apply live hardening changes to the target system.",
}


def build_action_plan(
    *,
    name: str,
    domain: str | None,
    effect: Effect | str,
    target: str | None,
    intent: str,
) -> dict[str, Any]:
    """A truthful, deterministic proposal for a gated action.

    No live agent runs to produce this — it states what *would* run, the
    target, the originating intent, and how a human approves it. The detail
    that a richer LLM-generated plan would add is deliberately out of scope:
    the contract here is that the irreversible step has not happened yet.
    """
    return {
        "agent": name,
        "domain": domain,
        "effect": effect,
        "target": target,
        "intent": intent,
        "gated": True,
        "required_role": "approver",
        "to_execute": "re-invoke with execute=true (requires the approver role)",
        "note": _EXECUTE_NOTE.get(
            domain or "",
            "Executing will perform state-changing actions against the target.",
        ),
    }
