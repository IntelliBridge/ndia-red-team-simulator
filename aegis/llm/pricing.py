"""LLM cost pricing for budget accounting.

``cost_cents(model, prompt_tokens, completion_tokens)`` returns the integer-cent
cost of a routed call so ``LLMUsage.cost_cents`` is populated and the
``DbBudgetChecker`` daily cap actually binds (Phase 3 M5).

Prices are USD per 1M tokens ``(input, output)``, researched 2026-06 from the
providers' published API rates. Models are matched **by family** on the
litellm-style identifier the router records (e.g. ``gemini/gemini-2.5-flash``,
``anthropic/claude-opus-4-8``, ``openai/gpt-4.1``), so a version/date suffix
still prices. When a model matches no family, we fall back to litellm's own
price map if it is importable (it ships with CAI on the execution path);
failing that the call is recorded uncosted (``0``) rather than mispriced.

Standard (non-batch, non-cached) input/output rates only. Costs round to the
nearest cent, so a sub-cent call records ``0``.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# (input_per_mtok_usd, output_per_mtok_usd), standard-context rates. Ordered
# most-specific family first because matching is substring-based (e.g.
# ``gpt-5`` ⊂ ``gpt-5.5``; ``gpt-4.1`` ⊂ ``gpt-4.1-mini``). o-series reasoning
# models (o3/o4-*) are intentionally left to the litellm fallback — their
# identifiers are too short to family-match here without collisions.
_PRICES_PER_MTOK: list[tuple[str, tuple[float, float]]] = [
    # Google Gemini — 3.x current, 2.5 legacy (the config default is 2.5-flash)
    ("gemini-3.5-flash", (1.50, 9.00)),
    ("gemini-3.1-pro", (2.00, 12.00)),
    ("gemini-3-pro", (2.00, 12.00)),
    ("gemini-2.5-flash", (0.30, 2.50)),
    ("gemini-2.5-pro", (1.25, 10.00)),
    # Anthropic Claude 4.x
    ("claude-opus", (5.00, 25.00)),
    ("claude-sonnet", (3.00, 15.00)),
    ("claude-haiku", (1.00, 5.00)),
    # OpenAI — GPT-5.x current, GPT-4.x legacy (5.5/5.4 before 5; mini before base)
    ("gpt-5.5", (5.00, 30.00)),
    ("gpt-5.4", (2.50, 15.00)),
    ("gpt-5", (1.25, 10.00)),
    ("gpt-4.1-mini", (0.40, 1.60)),
    ("gpt-4.1", (2.00, 8.00)),
    ("gpt-4o-mini", (0.15, 0.60)),
    ("gpt-4o", (2.50, 10.00)),
]


def _static_rate(model: str) -> tuple[float, float] | None:
    name = model.split("/")[-1].lower()
    for family, rate in _PRICES_PER_MTOK:
        if family in name:
            return rate
    return None


def _litellm_usd(model: str, prompt_tokens: int, completion_tokens: int) -> float | None:
    """Authoritative cost via litellm's price map, when importable."""
    try:
        from litellm import cost_per_token
        prompt_cost, completion_cost = cost_per_token(
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
        return float(prompt_cost) + float(completion_cost)
    except Exception:
        return None


def cost_cents(model: str, prompt_tokens: int, completion_tokens: int) -> int:
    """Integer-cent cost of a call; ``0`` when the model cannot be priced."""
    if not model or (prompt_tokens <= 0 and completion_tokens <= 0):
        return 0
    rate = _static_rate(model)
    if rate is None:
        usd = _litellm_usd(model, prompt_tokens, completion_tokens)
        if usd is None:
            logger.debug("no price for model %r; recording cost_cents=0", model)
            return 0
        return round(usd * 100)
    in_rate, out_rate = rate
    usd = (prompt_tokens / 1_000_000) * in_rate + (completion_tokens / 1_000_000) * out_rate
    return round(usd * 100)
