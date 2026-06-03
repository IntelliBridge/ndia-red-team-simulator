"""Effect classification — the spine of the unified human-in-the-loop gate.

Every capability the platform can invoke (a scanner, an agent, a Kali tool)
has an **effect class** describing its blast radius:

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

This module is intentionally dependency-free (no imports from ``aegis.agents``
/ ``aegis.api``) so both the agent registry and the tool layer can import it
without a cycle.
"""

from __future__ import annotations

from typing import Any, Literal

Effect = Literal["read", "active", "external"]

#: Effects that must clear the human gate (explicit opt-in + approver role).
_GATED: frozenset[Effect] = frozenset({"active", "external"})


def requires_approval(effect: Effect | str) -> bool:
    """True when ``effect`` is state-changing / leaves the sandbox."""
    return effect in _GATED


# --- Agents -----------------------------------------------------------------
# Default effect per registry ``Domain``. Per-agent overrides live in the
# agent wiring table (e.g. an android-SAST agent is ``offensive`` by domain but
# only reads bytecode → ``read``; a re-tester is ``audit`` by domain but
# re-fires exploits to verify a fix → ``active``). An unknown domain is treated
# as ``active`` so a mis-tagged or third-party agent fails *safe* (gated), never
# open.
_DOMAIN_DEFAULT_EFFECT: dict[str, Effect] = {
    "offensive": "active",
    "defensive": "active",
    "remediation": "read",   # produces a diff proposal; apply is gated in fixes.py
    "forensic": "read",
    "recon": "read",
    "audit": "read",
}


def domain_default_effect(domain: str | None) -> Effect:
    return _DOMAIN_DEFAULT_EFFECT.get(domain or "", "active")


# --- Kali tools -------------------------------------------------------------
# Effect per Kali tool name. Scanning / enumeration / local-only work is
# ``read``; exploitation and credential brute-force are ``active``. An
# unlisted tool defaults to ``active`` (fail-safe — an unclassified tool is
# never silently treated as harmless).
_KALI_TOOL_EFFECTS: dict[str, Effect] = {
    "nmap": "read",
    "nikto": "read",
    "gobuster": "read",
    "dirb": "read",
    "enum4linux": "read",
    "john": "read",
    "sqlmap": "active",
    "hydra": "active",
    "metasploit": "active",
    "wpscan": "active",
}


def kali_tool_effect(name: str) -> Effect:
    return _KALI_TOOL_EFFECTS.get((name or "").strip().lower(), "active")


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
