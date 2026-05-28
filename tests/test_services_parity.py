"""Sanity: the new service layer produces the same artifacts the CLI did."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.config import AegisConfig
from aegis.remediate.cai_runner import RemediationResult
from aegis.schema import AegisFinding
from aegis.services.fixes import generate_fix
from aegis.services.scans import start_scan
from aegis.services.verify import verify as verify_svc
from aegis.state import RunState


FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN_DIFF = (FIXTURES / "juice_shop_login.diff").read_text()


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


def _finding() -> AegisFinding:
    with open(FIXTURES / "aegis_finding_expected.json") as f:
        return AegisFinding.from_dict(json.load(f))


class TestGenerateFixPatchDryRun(unittest.TestCase):
    def test_dry_run_does_not_mutate_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r1")
            repo = Path(tmp) / "repo"
            _seed_repo(repo)

            result = RemediationResult(
                success=True, action="code_patch",
                finding_id="vuln-0001", output="patch output",
                diff=GOLDEN_DIFF, diff_sha256_hex="x",
                source="golden_fixture",
            )
            with patch("aegis.services.fixes.run_code_fix",
                       return_value=result):
                outcome = generate_fix(
                    run_state=state, finding=_finding(),
                    strategy="patch", repo=str(repo),
                    apply=False, open_pr=False, branch=None,
                    allow_dirty=False, push=False, use_golden_patch=False,
                    actor="cli:test", config=AegisConfig(output_dir=tmp),
                )
            self.assertTrue(outcome.success)
            self.assertEqual(outcome.status, "pending_apply")
            # Diff was persisted
            self.assertTrue(Path(outcome.diff_path).exists())
            # Repo was NOT mutated — original vulnerable interpolation remains
            self.assertIn("'${req.body.email}'",
                          (repo / "routes" / "login.js").read_text())


class TestGenerateFixPatchApply(unittest.TestCase):
    def test_apply_commits_on_deterministic_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r2")
            repo = Path(tmp) / "repo"
            _seed_repo(repo)

            result = RemediationResult(
                success=True, action="code_patch",
                finding_id="vuln-0001", output="patch output",
                diff=GOLDEN_DIFF, diff_sha256_hex="x",
                source="golden_fixture",
            )
            with patch("aegis.services.fixes.run_code_fix",
                       return_value=result):
                outcome = generate_fix(
                    run_state=state, finding=_finding(),
                    strategy="patch", repo=str(repo),
                    apply=True, open_pr=False, branch=None,
                    allow_dirty=False, push=False, use_golden_patch=False,
                    actor="cli:test", config=AegisConfig(output_dir=tmp),
                )
            self.assertTrue(outcome.success, msg=outcome.error)
            self.assertEqual(outcome.status, "fixed")
            self.assertEqual(outcome.branch, "aegis/fix/vuln-0001")
            self.assertIsNotNone(outcome.commit_hash)


class TestStartScanAuthorizes(unittest.TestCase):
    def test_audit_event_emitted_before_strix_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r3")
            with patch("aegis.adapters.strix_runner.run_strix") as mock_strix:
                mock_strix.return_value = type("R", (), {
                    "success": True, "partial_success": False,
                    "findings": [], "return_code": 0,
                    "command": ["strix"], "log_path": "/tmp/x",
                    "events_path": "/tmp/y", "error": None,
                })()
                outcome = start_scan(
                    run_state=state, target="http://localhost:3000",
                    actor="cli:test", config=AegisConfig(output_dir=tmp),
                )
            self.assertTrue(outcome.success)
            audit = (state.run_path / "audit.jsonl").read_text().strip().splitlines()
            actions = [json.loads(l)["action"] for l in audit]
            self.assertIn("scan.start", actions)


if __name__ == "__main__":
    unittest.main()
