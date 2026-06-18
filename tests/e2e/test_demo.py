"""End-to-end demo test.

Skipped unless ``AEGIS_E2E=1``. Variants:

  AEGIS_E2E=1 AEGIS_DISABLE_LLM=1   -> deterministic, no Docker / LLM / network.
                                       Runs the fixture-assisted demo path.
  AEGIS_E2E_LIVE=1                  -> manual, full live path. Requires Docker,
                                       network, and provider credentials. Not
                                       enabled in CI.

The deterministic variant is what the CI workflow exercises via
``workflow_dispatch``.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from aegis.config import AegisConfig
from aegis.demo import run_demo

E2E_ENABLED = os.environ.get("AEGIS_E2E") == "1"
E2E_LIVE = os.environ.get("AEGIS_E2E_LIVE") == "1"


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


def _seed_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "e2e@example.invalid")
    _git(repo, "config", "user.name", "E2E")
    (repo / "routes").mkdir()
    (repo / "routes" / "login.js").write_text(_SEED_LOGIN_JS)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "seed")


@unittest.skipUnless(E2E_ENABLED, "AEGIS_E2E not set")
class E2EDemoFixtureAssisted(unittest.TestCase):
    """Deterministic fixture-assisted demo end-to-end.

    Asserts the full six-link evidence chain from PLAN.md §9.3:
      1. Discovered  — findings.json has the seeded SQLi
      2. Normalized  — Aegis schema fields populated
      3. Remediated  — patch diff persisted, committed to branch
      4. Rebuilt     — target/runtime.json shows last_rebuild_at
      5. Verified    — verify/<id>.json has status != still_vulnerable
      6. Reported    — report.html with stage table
    """

    def test_fixture_assisted_demo(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "aegis_output"
            repo = Path(tmp) / "juice-shop"
            _seed_repo(repo)
            config = AegisConfig(output_dir=str(output_dir))

            outcome = run_demo(
                config, repo_path=repo,
                live_strix=False, live_llm=False, apply=True,
            )
            run_path = Path(outcome.run_path)

            # Link 1: Discovered
            findings = json.loads((run_path / "findings.json").read_text())
            self.assertTrue(any(f["id"] == "vuln-0001" for f in findings), "discover")

            # Link 2: Normalized
            seeded = next(f for f in findings if f["id"] == "vuln-0001")
            self.assertEqual(seeded["affected_component"], "/rest/user/login")
            self.assertEqual(seeded["source_tool"], "strix")

            # Link 3: Remediated — diff persisted, branch+commit recorded
            patch = run_path / "artifacts" / "patches" / "vuln-0001.diff"
            self.assertTrue(patch.exists(), "patch persisted")
            self.assertIn("models.sequelize.query", patch.read_text())
            current_branch = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            self.assertEqual(current_branch, "aegis/fix/vuln-0001")

            # Link 4: Rebuilt — runtime metadata records last_rebuild_at
            runtime = json.loads((run_path / "target" / "runtime.json").read_text())
            self.assertIsNotNone(runtime.get("last_rebuild_at"), "rebuild")

            # Link 5: Verified
            verify = json.loads((run_path / "verify" / "vuln-0001.json").read_text())
            self.assertNotEqual(verify["status"], "still_vulnerable",
                                msg=f"verify result: {verify}")

            # Link 6: Reported
            html = (run_path / "report.html").read_text()
            self.assertIn("Stage Provenance", html)
            self.assertIn("Aegis Security Assessment Report", html)

            # Audit log records every active op
            audit = (run_path / "audit.jsonl").read_text().splitlines()
            actions = {json.loads(line)["action"] for line in audit}
            for needed in ("patch.commit", "verify.replay"):
                self.assertIn(needed, actions, f"missing audit action: {needed}")


@unittest.skipUnless(E2E_LIVE, "AEGIS_E2E_LIVE not set (manual-only demo)")
class E2EDemoLive(unittest.TestCase):
    """Live demo path. Requires Docker, network, and provider credentials.

    Not run in CI; intended for one-off manual demos. Will fail loudly if any
    of those are missing.
    """

    def test_live_demo(self):  # pragma: no cover — manual
        repo = Path(os.environ.get("AEGIS_E2E_REPO", "/tmp/juice-shop"))
        self.assertTrue(repo.is_dir(),
                        f"set AEGIS_E2E_REPO to a Juice Shop clone (got {repo})")
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "aegis_output"
            config = AegisConfig(output_dir=str(output_dir))
            outcome = run_demo(
                config, repo_path=repo,
                live_strix=True, live_llm=True,
            )
            run_path = Path(outcome.run_path)
            self.assertTrue((run_path / "report.html").exists())


if __name__ == "__main__":
    unittest.main()
