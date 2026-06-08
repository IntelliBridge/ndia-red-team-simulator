"""Unit tests for LLM cost pricing (offline; no litellm, no DB)."""

from __future__ import annotations

import unittest
from unittest import mock

from aegis.llm import pricing
from aegis.llm.pricing import cost_cents


class TestCostCents(unittest.TestCase):
    def test_known_families_per_million(self):
        # 1M input + 1M output → (input_rate + output_rate) USD → cents.
        self.assertEqual(cost_cents("gemini/gemini-2.5-flash", 1_000_000, 1_000_000), 280)
        self.assertEqual(cost_cents("gemini/gemini-2.5-pro", 1_000_000, 1_000_000), 1125)
        self.assertEqual(cost_cents("anthropic/claude-opus-4-8", 1_000_000, 1_000_000), 3000)
        self.assertEqual(cost_cents("anthropic/claude-sonnet-4-6", 1_000_000, 1_000_000), 1800)
        self.assertEqual(cost_cents("anthropic/claude-haiku-4-5", 1_000_000, 1_000_000), 600)
        self.assertEqual(cost_cents("openai/gpt-4.1", 1_000_000, 1_000_000), 1000)
        self.assertEqual(cost_cents("openai/gpt-4o", 1_000_000, 1_000_000), 1250)

    def test_mini_families_not_shadowed_by_base(self):
        # The more-specific mini families must win over gpt-4.1 / gpt-4o.
        self.assertEqual(cost_cents("openai/gpt-4.1-mini", 1_000_000, 1_000_000), 200)
        self.assertEqual(cost_cents("openai/gpt-4o-mini", 1_000_000, 1_000_000), 75)

    def test_prefix_suffix_and_case_normalized(self):
        self.assertEqual(cost_cents("gemini-2.5-flash", 500_000, 0), 15)          # 0.5M * $0.30
        self.assertEqual(cost_cents("anthropic/claude-opus-4-8-20260528", 0, 200_000), 500)  # 0.2M * $25
        self.assertEqual(cost_cents("Gemini/Gemini-2.5-Flash", 1_000_000, 0), 30)

    def test_zero_tokens_is_zero(self):
        self.assertEqual(cost_cents("gemini/gemini-2.5-flash", 0, 0), 0)

    def test_subcent_rounds_to_zero(self):
        self.assertEqual(cost_cents("gemini/gemini-2.5-flash", 1000, 0), 0)       # $0.0003

    def test_empty_model_is_zero(self):
        self.assertEqual(cost_cents("", 1_000_000, 1_000_000), 0)

    def test_unknown_model_without_litellm_is_zero(self):
        with mock.patch.object(pricing, "_litellm_usd", return_value=None):
            self.assertEqual(cost_cents("exotic/unpriced-model", 1_000_000, 1_000_000), 0)

    def test_unknown_model_uses_litellm_fallback(self):
        with mock.patch.object(pricing, "_litellm_usd", return_value=0.05):
            self.assertEqual(cost_cents("exotic/unpriced-model", 10, 10), 5)      # $0.05 → 5¢


if __name__ == "__main__":
    unittest.main()
