"""Phase 4 v0.3.1 F10 — cai_runner uses cai_loader + llm.router.

The runner must:

1. Resolve the LLM model via ``aegis.llm.router.route("patch"/"harden")``
   so per-task overrides + per-project budgets apply.
2. Short-circuit with a structured ``BudgetExceeded`` failure when the
   supplied ``BudgetChecker`` reports zero remaining budget.
3. Inject ``cai_path/src`` onto ``sys.path`` exactly once via
   ``cai_loader.load_cai`` — no per-call sys.path mutation in the runner.
"""

from __future__ import annotations

import sys
import unittest
from unittest.mock import MagicMock, patch as mpatch

from aegis.config import AegisConfig
from aegis.llm.router import BudgetChecker
from aegis.remediate import cai_runner
from aegis.schema import AegisFinding


def _finding() -> AegisFinding:
    return AegisFinding(
        id="vuln-xyz", title="t", severity="high", finding_type="dast",
        description="", source_tool="strix", source_run_id="r",
        affected_component="x", confidence="high", status="open",
        created_at="2026", updated_at="2026",
    )


class _ZeroBudget:
    def remaining(self, project_id):
        return 0


class _UnlimitedBudget:
    def remaining(self, project_id):
        return 10_000


class TestBudgetGate(unittest.TestCase):
    def test_zero_remaining_short_circuits_without_calling_cai(self):
        # When the budget is zero, the runner should return a failure
        # BEFORE load_cai() runs — verified by load_cai being a strict
        # mock that would raise if invoked.
        sentinel = MagicMock(side_effect=AssertionError("load_cai called"))
        with mpatch("aegis.remediate.cai_runner.load_cai", sentinel):
            result = cai_runner.run_code_fix(
                _finding(), config=AegisConfig(),
                project_id="proj-1", budget_checker=_ZeroBudget(),
            )
        self.assertFalse(result.success)
        self.assertIn("BudgetExceeded", result.error or "")
        sentinel.assert_not_called()


class TestRouterPicksTaskModel(unittest.TestCase):
    def test_model_lifted_into_context_per_task(self):
        # Task-specific model wins over config.model.
        config = AegisConfig(model="anthropic/claude-default")
        config.task_models = {"patch": "anthropic/claude-patch-pin",
                              "harden": "anthropic/claude-harden-pin"}

        # Fake bundle so we don't need real CAI installed.
        runner = MagicMock()
        runner.run_sync.return_value = MagicMock(final_output="```diff\n--- a/x\n+++ b/x\n@@ @@\n+ok\n```")
        bundle = MagicMock(Runner=runner,
                           codeagent=MagicMock(), blueteam_agent=MagicMock())

        with mpatch("aegis.remediate.cai_runner.load_cai", return_value=bundle):
            cai_runner.run_code_fix(_finding(), config=config,
                                     project_id="proj-1",
                                     budget_checker=_UnlimitedBudget())
        ctx = runner.run_sync.call_args.kwargs["context"]
        self.assertEqual(ctx["model"], "anthropic/claude-patch-pin")

        with mpatch("aegis.remediate.cai_runner.load_cai", return_value=bundle):
            cai_runner.run_live_hardening(_finding(), config=config,
                                            project_id="proj-1",
                                            budget_checker=_UnlimitedBudget())
        ctx = runner.run_sync.call_args.kwargs["context"]
        self.assertEqual(ctx["model"], "anthropic/claude-harden-pin")


class TestLoaderDeduplicatesSysPath(unittest.TestCase):
    def test_run_code_fix_does_not_mutate_sys_path_directly(self):
        # F10 routes all sys.path injection through cai_loader.load_cai;
        # the runner itself never touches sys.path. We assert the import
        # surface of cai_runner has no ``sys.path`` reference.
        import inspect
        src = inspect.getsource(cai_runner)
        # Allow the import line for sys (it isn't used). What we forbid
        # is direct .path.insert / .append on sys inside this module.
        self.assertNotIn("sys.path.insert", src)
        self.assertNotIn("sys.path.append", src)


if __name__ == "__main__":
    unittest.main()
