"""Agentic remediation: the vuln-fixer runner + the gated ``agentic``/``live``
fix strategies.

Fully offline: the runner's subprocess + node lookup are mocked, and the
strategy tests mock the engine so no Node/driver/network is needed. The point
of these tests is the **human gate**: propose by default, act only on explicit
opt-in, and (per the platform's design) let the engine open the human-reviewed
PR when approved — the PR review is the gate.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from aegis.config import AegisConfig
from aegis.remediate.cai_runner import RemediationResult
from aegis.runners import vulnfixer_runner
from aegis.runners.vulnfixer_runner import run_agentic_fix
from aegis.schema import AegisFinding
from aegis.services.fixes import generate_fix
from aegis.state import RunState

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN_DIFF = (FIXTURES / "juice_shop_login.diff").read_text()


def _dep_finding() -> AegisFinding:
    return AegisFinding(
        id="vuln-dep-001", title="CVE-2024-1234 in lodash", severity="high",
        finding_type="dependency", description="Prototype pollution",
        source_tool="strix", source_run_id="test-run-001",
        affected_component="lodash", confidence="high", status="open",
        created_at="2026-05-27T10:30:00Z", updated_at="2026-05-27T10:30:00Z",
        cve="CVE-2024-1234", cvss=7.5, package_name="lodash",
        installed_version="4.17.20", fixed_version="4.17.21",
    )


def _appsec_finding() -> AegisFinding:
    with open(FIXTURES / "aegis_finding_expected.json") as f:
        return AegisFinding.from_dict(json.load(f))


def _config_with_driver(tmp: str) -> AegisConfig:
    drv = Path(tmp, "scripts", "aegis_remediate.mjs")
    drv.parent.mkdir(parents=True, exist_ok=True)
    drv.write_text("// stub driver")
    return AegisConfig(output_dir=tmp, vulnfixer_path=tmp)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True).stdout


def _seed_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "T")
    (repo / "routes").mkdir()
    (repo / "routes" / "login.js").write_text(
        "module.exports = function login () {\n"
        "  return (req, res, next) => {\n"
        "    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${hash}'`)\n"
        "  }\n"
        "}\n"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "seed")


class TestRunAgenticFixRunner(unittest.TestCase):
    def test_requires_repo(self):
        res = run_agentic_fix(_dep_finding(), repo_path=None, config=AegisConfig())
        self.assertFalse(res.success)
        self.assertIn("repo", res.error)

    def test_degrades_when_node_absent(self):
        with patch.object(vulnfixer_runner.shutil, "which", return_value=None):
            res = run_agentic_fix(_dep_finding(), repo_path="/x",
                                  config=AegisConfig())
        self.assertFalse(res.success)
        self.assertIn("node", res.error)

    def test_degrades_when_driver_missing(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(vulnfixer_runner.shutil, "which",
                          return_value="/usr/bin/node"):
            res = run_agentic_fix(_dep_finding(), repo_path=tmp,
                                  config=AegisConfig(vulnfixer_path=tmp))
        self.assertFalse(res.success)
        self.assertIn("driver not found", res.error)

    def test_propose_returns_diff_no_push_no_pr(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _config_with_driver(tmp)
            proc = MagicMock(returncode=0, stdout=f"```diff\n{GOLDEN_DIFF}```\n",
                             stderr="")
            with patch.object(vulnfixer_runner.shutil, "which",
                              return_value="/usr/bin/node"), \
                 patch.object(vulnfixer_runner.subprocess, "run",
                              return_value=proc) as run_mock:
                res = run_agentic_fix(_dep_finding(), repo_path=tmp, config=cfg)
        self.assertTrue(res.success, res.error)
        self.assertIsNotNone(res.diff)
        self.assertEqual(res.source, "vulnfixer")
        cmd = run_mock.call_args.args[0]
        self.assertIn("--no-push", cmd)
        self.assertIn("--no-pr", cmd)
        self.assertNotIn("--open-pr", cmd)

    def test_propose_no_diff_degrades(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _config_with_driver(tmp)
            proc = MagicMock(returncode=0, stdout="nothing useful", stderr="")
            with patch.object(vulnfixer_runner.shutil, "which",
                              return_value="/usr/bin/node"), \
                 patch.object(vulnfixer_runner.subprocess, "run",
                              return_value=proc):
                res = run_agentic_fix(_dep_finding(), repo_path=tmp, config=cfg)
        self.assertFalse(res.success)
        self.assertIn("no parseable", res.error)

    def test_nonzero_exit_degrades(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _config_with_driver(tmp)
            proc = MagicMock(returncode=2, stdout="", stderr="boom")
            with patch.object(vulnfixer_runner.shutil, "which",
                              return_value="/usr/bin/node"), \
                 patch.object(vulnfixer_runner.subprocess, "run",
                              return_value=proc):
                res = run_agentic_fix(_dep_finding(), repo_path=tmp, config=cfg)
        self.assertFalse(res.success)
        self.assertIn("exited 2", res.error)

    def test_timeout_degrades(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _config_with_driver(tmp)
            with patch.object(vulnfixer_runner.shutil, "which",
                              return_value="/usr/bin/node"), \
                 patch.object(vulnfixer_runner.subprocess, "run",
                              side_effect=subprocess.TimeoutExpired("node", 1)):
                res = run_agentic_fix(_dep_finding(), repo_path=tmp, config=cfg)
        self.assertFalse(res.success)
        self.assertIn("failed to run", res.error)

    def test_pr_mode_requires_github_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _config_with_driver(tmp)
            with patch.object(vulnfixer_runner.shutil, "which",
                              return_value="/usr/bin/node"), \
                 patch.dict(os.environ, clear=False):
                os.environ.pop("GITHUB_TOKEN", None)
                res = run_agentic_fix(_dep_finding(), repo_path=tmp,
                                      open_pr=True, config=cfg)
        self.assertFalse(res.success)
        self.assertIn("GITHUB_TOKEN", res.error)

    def test_pr_mode_success_and_token_never_in_argv(self):
        marker = ('AEGIS_RESULT {"pr_url": "https://github.com/o/r/pull/7", '
                  '"branch": "aegis/fix/x"}')
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _config_with_driver(tmp)
            proc = MagicMock(returncode=0, stdout=f"working...\n{marker}\n",
                             stderr="")
            with patch.object(vulnfixer_runner.shutil, "which",
                              return_value="/usr/bin/node"), \
                 patch.object(vulnfixer_runner.subprocess, "run",
                              return_value=proc) as run_mock, \
                 patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_secrettoken"},
                            clear=False):
                res = run_agentic_fix(_dep_finding(), repo_path=tmp,
                                      open_pr=True, config=cfg)
        self.assertTrue(res.success, res.error)
        self.assertEqual(res.plan["pr_url"], "https://github.com/o/r/pull/7")
        self.assertEqual(res.plan["branch"], "aegis/fix/x")
        cmd = run_mock.call_args.args[0]
        self.assertIn("--open-pr", cmd)
        self.assertNotIn("ghp_secrettoken", " ".join(cmd))

    def test_pr_mode_no_result_marker_degrades(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _config_with_driver(tmp)
            proc = MagicMock(returncode=0, stdout="did work but no marker",
                             stderr="")
            with patch.object(vulnfixer_runner.shutil, "which",
                              return_value="/usr/bin/node"), \
                 patch.object(vulnfixer_runner.subprocess, "run",
                              return_value=proc), \
                 patch.dict(os.environ, {"GITHUB_TOKEN": "x"}, clear=False):
                res = run_agentic_fix(_dep_finding(), repo_path=tmp,
                                      open_pr=True, config=cfg)
        self.assertFalse(res.success)
        self.assertIn("no PR", res.error)


class TestAgenticStrategyGate(unittest.TestCase):
    def _diff_result(self) -> RemediationResult:
        return RemediationResult(
            success=True, action="code_patch", finding_id="vuln-0001",
            output="o", diff=GOLDEN_DIFF, diff_sha256_hex="x",
            source="vulnfixer",
        )

    def test_propose_by_default_no_commit_no_pr(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "ra1")
            repo = Path(tmp) / "repo"
            _seed_repo(repo)
            with patch("aegis.services.fixes.run_agentic_fix",
                       return_value=self._diff_result()) as raf:
                outcome = generate_fix(
                    run_state=state, finding=_appsec_finding(),
                    strategy="agentic", repo=str(repo),
                    apply=False, open_pr=False, branch=None,
                    allow_dirty=False, push=False, use_golden_patch=False,
                    actor="cli:test", config=AegisConfig(output_dir=tmp),
                )
            # repo left untouched — vulnerable interpolation still present
            login_js = (repo / "routes" / "login.js").read_text()
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.status, "pending_apply")
        self.assertIsNone(outcome.pr_url)
        self.assertIsNone(outcome.commit_hash)
        self.assertFalse(raf.call_args.kwargs["open_pr"])
        self.assertIn("'${req.body.email}'", login_js)

    def test_apply_commits_locally_without_pr(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "ra2")
            repo = Path(tmp) / "repo"
            _seed_repo(repo)
            with patch("aegis.services.fixes.run_agentic_fix",
                       return_value=self._diff_result()) as raf:
                outcome = generate_fix(
                    run_state=state, finding=_appsec_finding(),
                    strategy="agentic", repo=str(repo),
                    apply=True, open_pr=False, branch=None,
                    allow_dirty=False, push=False, use_golden_patch=False,
                    actor="cli:test", config=AegisConfig(output_dir=tmp),
                )
        self.assertTrue(outcome.success, outcome.error)
        self.assertEqual(outcome.status, "fixed")
        self.assertIsNotNone(outcome.commit_hash)
        self.assertIsNone(outcome.pr_url)
        self.assertFalse(raf.call_args.kwargs["open_pr"])

    def test_open_pr_lets_engine_open_the_pr(self):
        pr_result = RemediationResult(
            success=True, action="code_patch", finding_id="vuln-0001",
            output="o", source="vulnfixer",
            plan={"pr_url": "https://github.com/o/r/pull/9",
                  "branch": "aegis/fix/vuln-0001"},
        )
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "ra3")
            repo = Path(tmp) / "repo"
            _seed_repo(repo)
            with patch("aegis.services.fixes.run_agentic_fix",
                       return_value=pr_result) as raf:
                outcome = generate_fix(
                    run_state=state, finding=_appsec_finding(),
                    strategy="agentic", repo=str(repo),
                    apply=True, open_pr=True, branch=None,
                    allow_dirty=False, push=True, use_golden_patch=False,
                    actor="cli:test", config=AegisConfig(output_dir=tmp),
                )
        self.assertTrue(outcome.success, outcome.error)
        self.assertEqual(outcome.status, "fixed")
        self.assertEqual(outcome.pr_url, "https://github.com/o/r/pull/9")
        self.assertEqual(outcome.branch, "aegis/fix/vuln-0001")
        self.assertTrue(raf.call_args.kwargs["open_pr"])

    def test_open_pr_without_apply_falls_through_to_propose(self):
        # open_pr=True with apply=False is not approved to act → propose only.
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "ra4")
            repo = Path(tmp) / "repo"
            _seed_repo(repo)
            with patch("aegis.services.fixes.run_agentic_fix",
                       return_value=self._diff_result()) as raf:
                outcome = generate_fix(
                    run_state=state, finding=_appsec_finding(),
                    strategy="agentic", repo=str(repo),
                    apply=False, open_pr=True, branch=None,
                    allow_dirty=False, push=False, use_golden_patch=False,
                    actor="cli:test", config=AegisConfig(output_dir=tmp),
                )
        self.assertEqual(outcome.status, "pending_apply")
        self.assertIsNone(outcome.pr_url)
        self.assertFalse(raf.call_args.kwargs["open_pr"])


class TestLiveHardeningGate(unittest.TestCase):
    def test_propose_returns_plan_and_never_invokes_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rl1")
            with patch("aegis.services.fixes.run_live_hardening") as rlh:
                outcome = generate_fix(
                    run_state=state, finding=_appsec_finding(),
                    strategy="live", repo=None,
                    apply=False, open_pr=False, branch=None,
                    allow_dirty=False, push=False, use_golden_patch=False,
                    actor="cli:test", config=AegisConfig(output_dir=tmp),
                )
        self.assertEqual(outcome.status, "pending_approval")
        self.assertIn("plan", outcome.detail)
        self.assertEqual(outcome.detail["plan"]["required_role"], "approver")
        rlh.assert_not_called()

    def test_apply_runs_hardening(self):
        hardening = RemediationResult(
            success=True, action="live_hardening", finding_id="vuln-0001",
            output="hardened", source="cai",
        )
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rl2")
            with patch("aegis.services.fixes.run_live_hardening",
                       return_value=hardening) as rlh:
                outcome = generate_fix(
                    run_state=state, finding=_appsec_finding(),
                    strategy="live", repo=None,
                    apply=True, open_pr=False, branch=None,
                    allow_dirty=False, push=False, use_golden_patch=False,
                    actor="cli:test", config=AegisConfig(output_dir=tmp),
                    override_authorized=True,
                )
        self.assertEqual(outcome.status, "fixed")
        rlh.assert_called_once()


if __name__ == "__main__":
    unittest.main()
