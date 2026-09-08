"""LLM guardrails: PII/secret scrubbing + prompt-injection detection.

Two fail-safe layers sit around every LLM chokepoint:

1. **Secret scrubbing** (:func:`scrub_secrets` / :func:`filter_output` /
   :func:`guard_diff` / :func:`guard_output`) — regex-redacts credentials and
   tokens out of generated diffs/patches and model outputs before they are
   persisted, surfaced in a PR body, or logged. The token signatures are the
   *same* ones the audit chain already trusts
   (:mod:`redsim.audit.redact`); we reuse them rather than maintain a second
   copy, mapping each to a stable category label.

2. **Prompt-injection detection** (:func:`detect_prompt_injection` /
   :func:`guard_input`) — pattern-matches untrusted finding text for
   instruction-override / role-switch / exfiltration / system-prompt-leak /
   fake-delimiter attempts before it reaches the model, with tiered risk.

Everything is gated by :class:`~redsim.config.RedsimConfig` and is **secret-free
in logs**: only category labels, counts, and risk levels are ever logged or put
into exceptions — never the raw secret material or the offending injected text.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from redsim.audit.redact import _TOKEN_PATTERNS

if TYPE_CHECKING:
    from redsim.config import RedsimConfig

logger = logging.getLogger(__name__)

REDACTION_PLACEHOLDER = "***REDACTED***"


# ---------------------------------------------------------------------------
# Result / verdict / exception types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScrubResult:
    text: str
    categories: list[str] = field(default_factory=list)
    count: int = 0


@dataclass(frozen=True)
class InjectionVerdict:
    detected: bool
    risk: str  # "none" | "low" | "medium" | "high"
    categories: list[str] = field(default_factory=list)


class GuardrailViolation(Exception):
    """Raised when untrusted input is blocked by the injection guard.

    The message is *always* secret-free: it names the risk level and the
    matched category labels only — never the offending injected text.
    """


# ---------------------------------------------------------------------------
# Secret scrubbing
# ---------------------------------------------------------------------------

# The audit-chain token signatures (reused, not duplicated) each map to a
# stable category label. Order matters only for label reporting; the regexes
# are mutually exclusive enough in practice.
_TOKEN_CATEGORY_BY_INDEX: list[str] = [
    "aws_key",        # AKIA...
    "aws_key",        # ASIA...
    "github_pat",     # ghp_
    "github_oauth",   # gho_
    "github_pat",     # ghu_
    "github_pat",     # ghs_
    "github_pat",     # ghr_
    "slack_token",    # xox[abprs]-
    "openai_key",     # sk-
]

# Patterns the audit module only catches as *dict keys*; an LLM diff/output is
# free-form text, so we also catch the inline ``key=value`` / ``key: value``
# forms and PEM private-key blocks here. Conservative — prefer false positives.
_INLINE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
            r".*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    (
        "password",
        re.compile(
            r"""(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*["']?([^\s"']{3,})""",
        ),
    ),
    (
        "api_key",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|"""
            r"""auth[_-]?token|secret)\b\s*[:=]\s*["']?([^\s"']{6,})""",
        ),
    ),
]


def _redact_inline_value(match: re.Match[str]) -> str:
    """Replace only the captured value of a ``key=value`` match, keeping the key."""
    full = match.group(0)
    value = match.group(1)
    # Swap the trailing secret value, preserve the ``key=`` / ``key: `` prefix.
    idx = full.rfind(value)
    return full[:idx] + REDACTION_PLACEHOLDER


def scrub_secrets(text: str) -> ScrubResult:
    """Regex-scrub credentials/tokens out of ``text``.

    Reuses the audit chain's token signatures plus inline ``key=value`` and PEM
    private-key forms. Returns the scrubbed text, the category labels of what
    was removed (never the raw secrets), and the total redaction count.
    """
    if not text:
        return ScrubResult(text=text or "", categories=[], count=0)

    out = text
    categories: list[str] = []
    count = 0

    for idx, pattern in enumerate(_TOKEN_PATTERNS):
        out, n = pattern.subn(REDACTION_PLACEHOLDER, out)
        if n:
            count += n
            label = _TOKEN_CATEGORY_BY_INDEX[idx]
            if label not in categories:
                categories.append(label)

    for label, pattern in _INLINE_PATTERNS:
        if "(" in pattern.pattern and label != "private_key":
            out, n = pattern.subn(_redact_inline_value, out)
        else:
            out, n = pattern.subn(REDACTION_PLACEHOLDER, out)
        if n:
            count += n
            if label not in categories:
                categories.append(label)

    return ScrubResult(text=out, categories=categories, count=count)


def filter_output(text: str) -> ScrubResult:
    """Output-side secret scrub. Composes :func:`scrub_secrets`."""
    return scrub_secrets(text)


# ---------------------------------------------------------------------------
# Prompt-injection detection
# ---------------------------------------------------------------------------

_RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}

# Each rule: (category, risk, compiled pattern). Risk tiers:
#   high   — direct instruction override / exfiltration / tool directives that,
#            if obeyed, subvert the agent immediately.
#   medium — role-switch and system-prompt-leak attempts, fake delimiters.
#   low    — softer "ignore the above"/"forget" phrasings without an explicit
#            instruction verb.
_INJECTION_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    # --- instruction override (high) ---
    (
        "instruction_override", "high",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?"
            r"\b(?:all\s+)?(?:previous|prior|above|earlier|preceding|"
            r"foregoing|system)\b[^.\n]{0,20}?"
            r"\b(?:instruction|prompt|direction|rule|message|context)s?\b",
        ),
    ),
    (
        "instruction_override", "high",
        re.compile(
            r"(?i)\bdisregard\b[^.\n]{0,30}\b(?:the\s+)?above\b",
        ),
    ),
    # --- role switch (medium) ---
    (
        "role_switch", "medium",
        re.compile(
            r"(?i)\byou\s+are\s+now\b|\bact\s+as\s+(?:a|an|the)\b|"
            r"\bpretend\s+(?:to\s+be|you(?:'re| are))\b|"
            r"\bfrom\s+now\s+on\s+you\b|\bnew\s+(?:persona|role|identity)\b|"
            r"\bswitch(?:ing)?\s+(?:to\s+)?(?:a\s+new\s+)?(?:role|persona)\b",
        ),
    ),
    # --- system-prompt leak (medium) ---
    (
        "system_prompt_leak", "medium",
        re.compile(
            r"(?i)\b(?:reveal|show|print|repeat|expose|leak|disclose|reprint)\b"
            r"[^.\n]{0,40}?\b(?:your\s+)?(?:system\s+prompt|initial\s+"
            r"(?:prompt|instruction)s?|instructions|guidelines|rules|"
            r"prompt\s+above|hidden\s+(?:prompt|instructions))\b",
        ),
    ),
    # --- exfiltration / tool directives (high) ---
    (
        "exfiltration", "high",
        re.compile(
            r"(?i)\b(?:exfiltrate|leak|send|post|upload|transmit|email|"
            r"forward)\b[^.\n]{0,50}?\b(?:secret|credential|api[_\s-]?key|"
            r"token|password|env(?:ironment)?\s+var|\.env|private\s+key|"
            r"data)s?\b",
        ),
    ),
    (
        "tool_directive", "high",
        re.compile(
            r"(?i)\b(?:curl|wget|nc|netcat)\b[^.\n]{0,40}?https?://|"
            r"\b(?:run|execute|exec|eval)\b[^.\n]{0,30}?\b(?:the\s+)?"
            r"(?:following\s+)?(?:shell\s+)?(?:command|code|script|payload)\b|"
            r"\b(?:os\.system|subprocess|rm\s+-rf|/etc/passwd)\b",
        ),
    ),
    # --- fake delimiters (medium) ---
    (
        "fake_delimiter", "medium",
        re.compile(
            r"(?i)(?:^|\n)\s*(?:#{0,3}\s*)?(?:\[?(?:system|assistant|user|"
            r"developer)\]?\s*[:>]|<\|?(?:im_start|im_end|system|endoftext)\|?>|"
            r"###\s*(?:system|instruction|new\s+instruction))",
        ),
    ),
    # --- softer override phrasing (low) ---
    (
        "instruction_override", "low",
        re.compile(
            r"(?i)\b(?:ignore|forget|disregard)\b[^.\n]{0,25}?"
            r"\b(?:everything|all\s+of\s+(?:the\s+)?above|what\s+(?:i|you)\s+"
            r"(?:said|told))\b",
        ),
    ),
]


def detect_prompt_injection(text: str) -> InjectionVerdict:
    """Pattern-based prompt-injection detection with tiered risk.

    Scans untrusted text for instruction-override, role-switch,
    system-prompt-leak, exfiltration, tool-directive, and fake-delimiter
    patterns. The reported ``risk`` is the highest tier matched; categories are
    de-duplicated. Benign text — including findings that merely *mention*
    "instructions" or "system" innocuously — returns ``risk="none"``.
    """
    if not text:
        return InjectionVerdict(detected=False, risk="none", categories=[])

    categories: list[str] = []
    top = "none"
    for category, risk, pattern in _INJECTION_RULES:
        if pattern.search(text):
            if category not in categories:
                categories.append(category)
            if _RISK_ORDER[risk] > _RISK_ORDER[top]:
                top = risk

    return InjectionVerdict(
        detected=bool(categories), risk=top, categories=categories,
    )


# ---------------------------------------------------------------------------
# Config-aware high-level helpers (what the call sites use)
# ---------------------------------------------------------------------------

def _resolve_config(config: RedsimConfig | None) -> RedsimConfig:
    if config is not None:
        return config
    from redsim.config import load_config
    return load_config()


def guard_input(text: str, *, config: RedsimConfig | None = None) -> None:
    """Inspect untrusted ``text`` and raise :class:`GuardrailViolation` when it
    is an injection at/above the configured block threshold.

    No-op when guardrails or injection detection are disabled. When the block
    risk is ``"off"`` the verdict is still detected + logged but never blocks.
    The verdict (categories + risk only — never the text) is always logged.
    The raised exception message is secret-free.
    """
    cfg = _resolve_config(config)
    if not getattr(cfg, "llm_guardrails_enabled", True):
        return
    if not getattr(cfg, "llm_detect_injection", True):
        return

    verdict = detect_prompt_injection(text)
    if not verdict.detected:
        return

    logger.info(
        "guardrails: prompt-injection verdict risk=%s categories=%s",
        verdict.risk, verdict.categories,
    )

    block_risk = (getattr(cfg, "llm_injection_block_risk", "high") or "high").lower()
    if block_risk == "off":
        return
    threshold = _RISK_ORDER.get(block_risk, _RISK_ORDER["high"])
    if _RISK_ORDER.get(verdict.risk, 0) >= threshold:
        raise GuardrailViolation(
            "blocked by LLM guardrails: prompt-injection "
            f"risk={verdict.risk} categories={verdict.categories}"
        )


def guard_diff(diff: str, *, config: RedsimConfig | None = None) -> str:
    """Scrub secrets from a generated ``diff`` when enabled (passthrough when
    disabled). Logs the categories + count; returns the scrubbed diff."""
    cfg = _resolve_config(config)
    if not getattr(cfg, "llm_guardrails_enabled", True):
        return diff
    if not getattr(cfg, "llm_scrub_diff_pii", True):
        return diff

    result = scrub_secrets(diff)
    if result.count:
        logger.warning(
            "guardrails: scrubbed %d secret(s) from diff categories=%s",
            result.count, result.categories,
        )
    return result.text


def guard_output(text: str, *, config: RedsimConfig | None = None) -> str:
    """Scrub secrets from an LLM ``output`` when enabled (passthrough when
    disabled). Logs the categories + count; returns the scrubbed output."""
    cfg = _resolve_config(config)
    if not getattr(cfg, "llm_guardrails_enabled", True):
        return text
    if not getattr(cfg, "llm_filter_output", True):
        return text

    result = filter_output(text)
    if result.count:
        logger.warning(
            "guardrails: scrubbed %d secret(s) from LLM output categories=%s",
            result.count, result.categories,
        )
    return result.text
