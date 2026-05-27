"""Test the fixture-assisted end-to-end demo path."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from aegis.config import AegisConfig
from aegis.demo import run_demo


_SEED_LOGIN_JS = (
    "module.exports = function login () {\n"
    "  return (req, res, next) => {\n"
    "    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${hash}'`)\n"
    "  }\n"
    "}\n"
)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
    ).stdout


def _init_juice_shop_clone(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "demo@example.invalid")
    _git(repo, "config", "user.name", "Demo")
    (repo / "routes").mkdir()
    (repo / "routes" / "login.js").write_text(_SEED_LOGIN_JS)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "seed juice-shop clone")


class TestFixtureAssistedDemoDryRunDefault(unittest.TestCase):
    """Default fixture-assisted demo must NOT mutate the supplied repo."""

    def test_default_is_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "aegis_output"
            repo = Path(tmp) / "juice-shop"
            _init_juice_shop_clone(repo)
            initial_branch = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            initial_commit = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()

            config = AegisConfig(output_dir=str(output_dir))
            outcome = run_demo(config, repo_path=repo,
                               live_strix=False, live_llm=False)
            run_path = Path(outcome.run_path)

            # Diff was persisted as evidence
            self.assertTrue((run_path / "artifacts" / "patches" / "vuln-0001.diff").exists())
            # ... but the working tree is unchanged
            self.assertEqual((repo / "routes" / "login.js").read_text(), _SEED_LOGIN_JS)
            # ... and we're still on the original branch
            branch_now = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            self.assertEqual(branch_now, initial_branch)
            commit_now = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            self.assertEqual(commit_now, initial_commit)

            # The remediate stage label includes "+dry-run"
            remediate = next(s for s in outcome.stages if s.name == "remediate")
            self.assertIn("dry-run", remediate.mode)


class TestFixtureAssistedDemoApply(unittest.TestCase):
    """`apply=True` opts in to branch + commit + rebuild + verify."""

    def test_end_to_end_with_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "aegis_output"
            repo = Path(tmp) / "juice-shop"
            _init_juice_shop_clone(repo)

            config = AegisConfig(output_dir=str(output_dir))
            outcome = run_demo(config, repo_path=repo,
                               live_strix=False, live_llm=False, apply=True)
            run_path = Path(outcome.run_path)

            stage_names = {s.name for s in outcome.stages}
            for name in ("target.up", "discover", "remediate", "rebuild",
                         "verify", "report"):
                self.assertIn(name, stage_names)

            for stage in outcome.stages:
                if stage.name == "teardown":
                    continue  # no live container to tear down
                self.assertTrue(stage.success,
                                msg=f"{stage.name} failed: {stage.detail}")

            # Patch landed on the deterministic branch
            current_branch = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            self.assertEqual(current_branch, "aegis/fix/vuln-0001")

            # Source ref reflects rebuild
            runtime = json.loads((run_path / "target" / "runtime.json").read_text())
            self.assertIsNotNone(runtime["last_rebuild_at"])

            # Audit log has the active events
            audit_lines = [
                json.loads(l) for l in (run_path / "audit.jsonl").read_text().splitlines()
            ]
            actions = {e["action"] for e in audit_lines}
            self.assertIn("patch.commit", actions)
            self.assertIn("verify.replay", actions)

            # Report files emitted
            self.assertTrue((run_path / "report.html").exists())
            html = (run_path / "report.html").read_text()
            self.assertIn("Stage Provenance", html)


if __name__ == "__main__":
    unittest.main()
