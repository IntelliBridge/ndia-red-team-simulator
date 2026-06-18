"""C13 — iterative fix→test→retry remediation loop.

Covers ``aegis.remediate.cai_runner.run_iterative_code_fix`` and the
operator-configured ``aegis.remediate.test_runner``:

1. No test command configured → single-shot ``run_code_fix`` (unchanged path).
2. Loop-on-failure-then-success: the failing test output is fed back to the
   agent, which then produces a passing patch.
3. The loop is bounded by ``config.remediation_max_iters``.
4. A hard agent failure (no diff) stops the loop immediately.
5. ``test_runner`` security: the command is parsed to argv and executed without
   a shell (metacharacters are inert) and a non-zero exit is a failure.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch as mpatch

from aegis.config import AegisConfig
from aegis.remediate import cai_runner
from aegis.remediate.cai_runner import RemediationResult, run_iterative_code_fix
from aegis.remediate.test_runner import (
    parse_test_command,
    run_project_tests,
)
from aegis.schema import AegisFinding
from aegis.services.fixes import generate_fix
from aegis.state import RunState

_DIFF = "--- a/x\n+++ b/x\n@@ -0,0 +1 @@\n+ok\n"


def _finding() -> AegisFinding:
    return AegisFinding(
        id="vuln-loop", title="t", severity="high", finding_type="code",
        description="", source_tool="strix", source_run_id="r",
        affected_component="x", confidence="high", status="open",
        created_at="2026", updated_at="2026",
    )


def _ok_result(diff: str = _DIFF) -> RemediationResult:
    return RemediationResult(
        success=True, action="code_patch", finding_id="vuln-loop",
        output="```diff\n" + diff + "```", diff=diff,
        diff_sha256_hex="deadbeef", source="cai",
    )


class FakeAgent:
    """Records every ``run_code_fix`` call (esp. the ``test_feedback`` it sees)
    and returns a scripted ``RemediationResult`` per attempt."""

    def __init__(self, results: list[RemediationResult]) -> None:
        self._results = results
        self.calls: list[dict] = []

    def __call__(self, finding, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(kwargs)
        idx = min(len(self.calls) - 1, len(self._results) - 1)
        return self._results[idx]


class TestIterativeLoop(unittest.TestCase):
    def test_no_test_command_is_single_shot(self) -> None:
        # With no remediation_test_command configured the loop must delegate to
        # a single run_code_fix and never apply/test.
        config = AegisConfig()  # remediation_test_command defaults to None
        self.assertIsNone(config.remediation_test_command)
        agent = FakeAgent([_ok_result()])
        apply_spy = mpatch("aegis.remediate.cai_runner._apply_and_test",
                           side_effect=AssertionError("must not test"))
        with mpatch("aegis.remediate.cai_runner.run_code_fix", agent), apply_spy:
            result = run_iterative_code_fix(_finding(), repo="/tmp/x",
                                            config=config)
        self.assertTrue(result.success)
        self.assertEqual(result.iterations, 1)
        self.assertIsNone(result.tests_passed)
        self.assertEqual(len(agent.calls), 1)

    def test_loops_on_failure_then_succeeds(self) -> None:
        # tests fail on attempt 1, pass on attempt 2. Assert: two agent calls,
        # the failing output is fed back into the 2nd prompt, final verdict green.
        config = AegisConfig(remediation_test_command="pytest -q",
                             remediation_max_iters=3)
        agent = FakeAgent([_ok_result("--- a/x\n+++ b/x\n@@ @@\n+v1\n"),
                           _ok_result("--- a/x\n+++ b/x\n@@ @@\n+v2\n")])
        outcomes = iter([(False, "AssertionError: boom"), (True, "")])

        def fake_apply_and_test(repo, diff, argv, *, test_timeout):  # type: ignore[no-untyped-def]
            return next(outcomes)

        with mpatch("aegis.remediate.cai_runner.run_code_fix", agent), \
             mpatch("aegis.remediate.cai_runner.is_repo_dirty", return_value=False), \
             mpatch("aegis.remediate.cai_runner._apply_and_test",
                    side_effect=fake_apply_and_test):
            result = run_iterative_code_fix(_finding(), repo="/tmp/x",
                                            config=config)

        self.assertTrue(result.success)
        self.assertTrue(result.tests_passed)
        self.assertEqual(result.iterations, 2)
        self.assertEqual(len(agent.calls), 2)
        # First attempt has no feedback; second carries the failing output.
        self.assertIsNone(agent.calls[0]["test_feedback"])
        self.assertIn("boom", agent.calls[1]["test_feedback"])
        self.assertEqual(result.test_runs,
                         [{"iteration": 1, "passed": False},
                          {"iteration": 2, "passed": True}])

    def test_loop_bounded_by_max_iters(self) -> None:
        # tests never pass → the agent is invoked exactly remediation_max_iters
        # times and the final result reports tests_passed False.
        config = AegisConfig(remediation_test_command="pytest -q",
                             remediation_max_iters=2)
        agent = FakeAgent([_ok_result()])

        with mpatch("aegis.remediate.cai_runner.run_code_fix", agent), \
             mpatch("aegis.remediate.cai_runner.is_repo_dirty", return_value=False), \
             mpatch("aegis.remediate.cai_runner._apply_and_test",
                    return_value=(False, "still red")):
            result = run_iterative_code_fix(_finding(), repo="/tmp/x",
                                            config=config)

        self.assertEqual(len(agent.calls), 2)  # bounded, not infinite
        self.assertEqual(result.iterations, 2)
        self.assertFalse(result.tests_passed)
        self.assertIn("still failing after 2", result.error or "")

    def test_dirty_repo_falls_back_to_single_shot(self) -> None:
        # A dirty working tree must NOT drive the destructive loop (restore_tree
        # would git reset --hard + clean -fd the operator's uncommitted/untracked
        # work). The loop falls back to the safe single-shot path and never
        # applies/tests a candidate diff against the dirty tree.
        config = AegisConfig(remediation_test_command="pytest -q")
        agent = FakeAgent([_ok_result()])
        apply_spy = mpatch("aegis.remediate.cai_runner._apply_and_test",
                           side_effect=AssertionError("must not test a dirty repo"))
        with mpatch("aegis.remediate.cai_runner.run_code_fix", agent), \
             mpatch("aegis.remediate.cai_runner.is_repo_dirty", return_value=True), \
             apply_spy:
            result = run_iterative_code_fix(_finding(), repo="/tmp/x",
                                            config=config)
        self.assertTrue(result.success)
        self.assertIsNone(result.tests_passed)   # loop never ran
        self.assertEqual(len(agent.calls), 1)    # single-shot only

    def test_failing_output_is_secret_scrubbed_before_feedback(self) -> None:
        # Failing-test output routinely contains secrets; they must be scrubbed
        # (guard_output) before being woven into the next agent prompt and
        # shipped to the LLM provider.
        from aegis.llm.guardrails import guard_output

        config = AegisConfig(remediation_test_command="pytest -q",
                             remediation_max_iters=2)
        agent = FakeAgent([_ok_result("--- a/x\n+++ b/x\n@@ @@\n+v1\n"),
                           _ok_result("--- a/x\n+++ b/x\n@@ @@\n+v2\n")])
        raw = "AssertionError: db=postgresql://u:hunter2@h/db api_key=sk-livesecret"
        outcomes = iter([(False, raw), (True, "")])

        def fake_apply_and_test(repo, diff, argv, *, test_timeout):  # type: ignore[no-untyped-def]
            return next(outcomes)

        with mpatch("aegis.remediate.cai_runner.run_code_fix", agent), \
             mpatch("aegis.remediate.cai_runner.is_repo_dirty", return_value=False), \
             mpatch("aegis.remediate.cai_runner._apply_and_test",
                    side_effect=fake_apply_and_test):
            run_iterative_code_fix(_finding(), repo="/tmp/x", config=config)

        # The 2nd-attempt prompt receives the guard_output-scrubbed text, never
        # the raw failing output (proves the scrub is wired into the feedback).
        self.assertEqual(agent.calls[1]["test_feedback"],
                         guard_output(raw, config=config))

    def test_max_iters_floor_of_one(self) -> None:
        # A misconfigured max_iters <= 0 must still run at least once.
        config = AegisConfig(remediation_test_command="pytest -q",
                             remediation_max_iters=0)
        agent = FakeAgent([_ok_result()])
        with mpatch("aegis.remediate.cai_runner.run_code_fix", agent), \
             mpatch("aegis.remediate.cai_runner._apply_and_test",
                    return_value=(False, "red")):
            result = run_iterative_code_fix(_finding(), repo="/tmp/x",
                                            config=config)
        self.assertEqual(len(agent.calls), 1)
        self.assertFalse(result.tests_passed)

    def test_agent_failure_stops_loop_immediately(self) -> None:
        # If the agent can't produce a diff (budget/guardrail/no-parse), there
        # is nothing to test — stop after one attempt without testing.
        config = AegisConfig(remediation_test_command="pytest -q",
                             remediation_max_iters=3)
        fail = RemediationResult(
            success=False, action="code_patch", finding_id="vuln-loop",
            output="", diff=None, error="BudgetExceeded: 0", source="cai",
        )
        agent = FakeAgent([fail])
        apply_spy = mpatch("aegis.remediate.cai_runner._apply_and_test",
                           side_effect=AssertionError("must not test"))
        with mpatch("aegis.remediate.cai_runner.run_code_fix", agent), apply_spy:
            result = run_iterative_code_fix(_finding(), repo="/tmp/x",
                                            config=config)
        self.assertFalse(result.success)
        self.assertEqual(len(agent.calls), 1)
        self.assertIsNone(result.tests_passed)
        self.assertIn("BudgetExceeded", result.error or "")


class TestApplyAndTestReplay(unittest.TestCase):
    """``_apply_and_test`` against a real git repo: apply → test → rollback,
    reusing the patch_workflow replay machinery."""

    def _init_repo(self, repo: Path) -> None:
        def g(*args: str) -> None:
            subprocess.run(["git", "-C", str(repo), *args],
                           check=True, capture_output=True, text=True)
        repo.mkdir(parents=True, exist_ok=True)
        g("init", "-q")
        g("config", "user.email", "t@example.invalid")
        g("config", "user.name", "T")
        (repo / "value.txt").write_text("0\n")
        g("add", "-A")
        g("commit", "-q", "-m", "init")

    def test_apply_runs_tests_then_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            self._init_repo(repo)
            diff = ("--- a/value.txt\n+++ b/value.txt\n"
                    "@@ -1 +1 @@\n-0\n+1\n")
            # A test command (argv) that passes iff value.txt contains "1".
            argv = ["grep", "-q", "1", "value.txt"]
            passed, feedback = cai_runner._apply_and_test(
                repo, diff, argv, test_timeout=30,
            )
            self.assertTrue(passed)
            self.assertEqual(feedback, "")
            # Rolled back: the working tree is clean and unchanged.
            status = subprocess.run(
                ["git", "-C", str(repo), "status", "--porcelain"],
                capture_output=True, text=True, check=True).stdout
            self.assertEqual(status.strip(), "")
            self.assertEqual((repo / "value.txt").read_text(), "0\n")

    def test_unappldiff_returns_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            self._init_repo(repo)
            bad = ("--- a/value.txt\n+++ b/value.txt\n"
                   "@@ -1 +1 @@\n-NOPE\n+1\n")  # context doesn't match
            passed, feedback = cai_runner._apply_and_test(
                repo, bad, ["true"], test_timeout=30,
            )
            self.assertFalse(passed)
            self.assertIn("did not apply", feedback)

    def test_added_file_is_cleaned_up_on_rollback(self) -> None:
        # A patch that ADDS a new file must leave a pristine tree afterward —
        # ``git reset --hard`` alone leaves untracked files, so restore_tree's
        # ``git clean`` matters here.
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            self._init_repo(repo)
            add = ("--- /dev/null\n+++ b/new.txt\n"
                   "@@ -0,0 +1 @@\n+added\n")
            passed, _ = cai_runner._apply_and_test(
                repo, add, ["true"], test_timeout=30,
            )
            self.assertTrue(passed)
            self.assertFalse((repo / "new.txt").exists())
            status = subprocess.run(
                ["git", "-C", str(repo), "status", "--porcelain"],
                capture_output=True, text=True, check=True).stdout
            self.assertEqual(status.strip(), "")


class TestTestRunner(unittest.TestCase):
    def test_parse_test_command(self) -> None:
        self.assertIsNone(parse_test_command(None))
        self.assertIsNone(parse_test_command(""))
        self.assertIsNone(parse_test_command("   "))
        self.assertEqual(parse_test_command("pytest -q tests/"),
                         ["pytest", "-q", "tests/"])
        # Quoted args survive shlex splitting.
        self.assertEqual(parse_test_command('make "unit tests"'),
                         ["make", "unit tests"])
        # Unbalanced quote → unparseable → None (not an exception).
        self.assertIsNone(parse_test_command('pytest "'))

    def test_run_project_tests_passes_on_zero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            res = run_project_tests(Path(td), ["true"], timeout=30)
            self.assertTrue(res.ran)
            self.assertTrue(res.passed)
            self.assertEqual(res.returncode, 0)

    def test_run_project_tests_fails_on_nonzero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            res = run_project_tests(Path(td), ["false"], timeout=30)
            self.assertTrue(res.ran)
            self.assertFalse(res.passed)
            self.assertNotEqual(res.returncode, 0)

    def test_missing_command_is_nonraising_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            res = run_project_tests(
                Path(td), ["definitely-not-a-real-binary-xyz"], timeout=30)
            self.assertFalse(res.ran)
            self.assertFalse(res.passed)
            self.assertIn("not found", res.error or "")

    def test_no_shell_metacharacters_are_interpreted(self) -> None:
        # SECURITY: argv execution must NOT spawn a shell. We echo a literal
        # string containing shell metacharacters; if a shell ran, the `;` /
        # `$(...)` would be interpreted. With list-argv they are inert literals.
        payload = "safe; echo PWNED $(id)"
        with tempfile.TemporaryDirectory() as td:
            res = run_project_tests(Path(td), ["echo", payload], timeout=30)
            self.assertTrue(res.passed)
            self.assertIn(payload, res.stdout)
            self.assertNotIn("PWNED\n", res.stdout)  # never executed a 2nd cmd

    def test_combined_output_tail_truncates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            big = "A" * 50_000
            res = run_project_tests(Path(td), ["echo", big], timeout=30)
            self.assertTrue(res.passed)
            self.assertLess(len(res.combined_output), 50_000)
            self.assertIn("truncated", res.combined_output)


class TestGenerateFixDrivesLoop(unittest.TestCase):
    """End-to-end: ``generate_fix(strategy='patch')`` runs the loop, commits the
    *validated* diff, and records the iteration verdict on the outcome."""

    def _seed(self, repo: Path) -> None:
        def g(*args: str) -> None:
            subprocess.run(["git", "-C", str(repo), *args],
                           check=True, capture_output=True, text=True)
        repo.mkdir(parents=True, exist_ok=True)
        g("init", "-q")
        g("config", "user.email", "t@example.invalid")
        g("config", "user.name", "T")
        (repo / "value.txt").write_text("0\n")
        g("add", "-A")
        g("commit", "-q", "-m", "seed")

    def test_loop_then_commit_records_iterations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rloop")
            repo = Path(tmp) / "repo"
            self._seed(repo)

            # Both diffs apply to the pristine tree (the loop rolls back between
            # attempts). v1 fails the test command; v2 passes it.
            bad = _ok_result("--- a/value.txt\n+++ b/value.txt\n@@ -1 +1 @@\n-0\n+bad\n")
            good = _ok_result("--- a/value.txt\n+++ b/value.txt\n@@ -1 +1 @@\n-0\n+1\n")
            agent = FakeAgent([bad, good])

            config = AegisConfig(
                output_dir=tmp,
                # Operator-configured, shell-free argv source: passes iff
                # value.txt is exactly "1".
                remediation_test_command="grep -qx 1 value.txt",
                remediation_max_iters=3,
                # Keep the agent prompt out of the guardrail path noise: the
                # fake agent never reaches real CAI anyway.
                llm_guardrails_enabled=False,
            )
            # Patch the agent seam *inside* the loop (cai_runner namespace).
            with mpatch("aegis.remediate.cai_runner.run_code_fix", agent):
                outcome = generate_fix(
                    run_state=state, finding=_finding(),
                    strategy="patch", repo=str(repo),
                    apply=True, open_pr=False, branch=None,
                    allow_dirty=False, push=False, use_golden_patch=False,
                    actor="cli:test", config=config,
                )

            self.assertTrue(outcome.success, msg=outcome.error)
            self.assertEqual(outcome.status, "fixed")
            self.assertEqual(len(agent.calls), 2)  # looped once on failure
            self.assertEqual(outcome.detail.get("remediation_iterations"), 2)
            self.assertTrue(outcome.detail.get("remediation_tests_passed"))
            # The committed file reflects the *validated* (v2) diff.
            committed = subprocess.run(
                ["git", "-C", str(repo), "show", f"{outcome.branch}:value.txt"],
                capture_output=True, text=True, check=True).stdout
            self.assertEqual(committed.strip(), "1")


if __name__ == "__main__":
    unittest.main()
