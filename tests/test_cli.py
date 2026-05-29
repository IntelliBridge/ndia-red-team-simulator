import json
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from aegis.cli import cmd_fix, main
from aegis.config import AegisConfig
from aegis.remediate.cai_runner import RemediationResult
from aegis.schema import AegisFinding
from aegis.state import RunState

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN_DIFF = (FIXTURES / "juice_shop_login.diff").read_text()


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
    ).stdout


def _fix_args(**overrides):
    base = dict(
        finding_id="vuln-0001",
        run="test-run",
        repo=None,
        patch=False, live=False, deps=False,
        apply=False, branch=None,
        push=False, open_pr=False,
        rollback=False, ref_before=None,
        use_golden_patch=False, allow_dirty=False,
        override_authorized=False,
    )
    base.update(overrides)
    return Namespace(**base)


class TestRunCodeFixDiffRequired(unittest.TestCase):
    """run_code_fix must fail when CodeAgent returns no parseable diff."""

    def test_no_diff_returns_failure(self):
        # F10: cai_runner now routes through cai_loader.load_cai, which
        # also imports the blueteam agent. The test mocks the entire CAI
        # surface load_cai touches so the bundle is non-None.
        from unittest.mock import MagicMock
        from unittest.mock import patch as mpatch

        from aegis.remediate.cai_runner import run_code_fix

        finding = AegisFinding(
            id="vuln-xyz", title="t", severity="high", finding_type="dast",
            description="", source_tool="strix", source_run_id="r",
            affected_component="x", confidence="high", status="open",
            created_at="2026", updated_at="2026",
        )
        fake_runner = MagicMock()
        fake_runner.Runner.run_sync.return_value = MagicMock(final_output="No diff here.")
        codeagent_mod = MagicMock()
        codeagent_mod.codeagent = MagicMock()
        blueteam_mod = MagicMock()
        blueteam_mod.blueteam_agent = MagicMock()
        with mpatch.dict("sys.modules", {
            "cai": MagicMock(),
            "cai.agents": MagicMock(),
            "cai.agents.codeagent": codeagent_mod,
            "cai.agents.blue_teamer": blueteam_mod,
            "cai.sdk": MagicMock(),
            "cai.sdk.agents": fake_runner,
        }), mpatch("aegis.integrations.cai_loader._BUNDLE", None):
            result = run_code_fix(finding)
        self.assertFalse(result.success)
        self.assertIsNone(result.diff)
        self.assertIn("no parseable unified diff", (result.error or "").lower())


class TestCliFixStatusSemantics(unittest.TestCase):
    """The status logic must reflect whether the repo was actually mutated."""

    def _seed_run_with_finding(self, tmp: Path) -> tuple[AegisConfig, RunState, AegisFinding]:
        config = AegisConfig(output_dir=str(tmp))
        state = RunState(str(tmp), "test-run")
        with open(FIXTURES / "aegis_finding_expected.json") as f:
            finding = AegisFinding.from_dict(json.load(f))
        state.save_findings([finding])
        return config, state, finding

    def test_patch_dry_run_does_not_mark_fixed(self):
        """--patch without --apply must leave the finding NOT fixed."""
        with tempfile.TemporaryDirectory() as tmp:
            config, state, _ = self._seed_run_with_finding(Path(tmp))
            # Set up a real git repo so --check has somewhere to run, but
            # use a tree the golden patch does NOT apply to — we only care
            # that the status doesn't become "fixed" in dry-run.
            repo = Path(tmp) / "repo"
            repo.mkdir()
            _git(repo, "init", "-q")
            _git(repo, "config", "user.email", "t@example.invalid")
            _git(repo, "config", "user.name", "T")
            (repo / "x").write_text("x\n")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "-m", "init")

            result = RemediationResult(
                success=True, action="code_patch",
                finding_id="vuln-0001", output="patch output",
                diff=GOLDEN_DIFF, diff_sha256_hex="deadbeef",
                source="golden_fixture",
            )
            args = _fix_args(patch=True, apply=False, repo=str(repo))
            # F3: cmd_fix routes through services.fixes; patch the symbol
            # where it is *looked up*, not where it is defined.
            with patch("aegis.services.fixes.run_code_fix", return_value=result):
                cmd_fix(args, config)

            findings = state.load_findings()
            self.assertNotEqual(findings[0]["status"], "fixed",
                                "dry-run --patch must NOT mark a finding fixed")
            # And we communicate it explicitly via a non-"fixed" status
            self.assertIn(findings[0]["status"], {"failed", "pending_apply", "open"})

    def test_patch_apply_marks_fixed_only_after_commit_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, state, _ = self._seed_run_with_finding(Path(tmp))
            # Real git repo whose tree matches the golden patch's input
            repo = Path(tmp) / "repo"
            repo.mkdir()
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

            result = RemediationResult(
                success=True, action="code_patch",
                finding_id="vuln-0001", output="patch output",
                diff=GOLDEN_DIFF, diff_sha256_hex="deadbeef",
                source="golden_fixture",
            )
            args = _fix_args(patch=True, apply=True, repo=str(repo))
            # F3: cmd_fix routes through services.fixes; patch the symbol
            # where it is *looked up*, not where it is defined.
            with patch("aegis.services.fixes.run_code_fix", return_value=result):
                cmd_fix(args, config)

            findings = state.load_findings()
            self.assertEqual(findings[0]["status"], "fixed")


class TestCliDepsStatusNotOverwritten(unittest.TestCase):
    """`aegis fix <cve> --deps --apply` must stay 'fixed' after bump commit."""

    def test_deps_apply_keeps_fixed_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = AegisConfig(output_dir=str(tmp))
            state = RunState(str(tmp), "test-run-deps")

            # Build a Node repo with a known-vulnerable lodash
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "package.json").write_text(json.dumps({
                "name": "demo",
                "dependencies": {"lodash": "4.17.20"},
            }, indent=2) + "\n")
            _git(repo, "init", "-q")
            _git(repo, "config", "user.email", "t@example.invalid")
            _git(repo, "config", "user.name", "T")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "-m", "seed")

            dep_finding_id = "CVE-2024-1111@lodash"
            # Pre-seed the dependency finding so cmd_fix can find it by id
            # without us needing a real Trivy binary.
            dep_finding = AegisFinding(
                id=dep_finding_id,
                title="lodash vuln", severity="high",
                finding_type="dependency",
                description="...", source_tool="trivy",
                source_run_id="test-run-deps",
                affected_component="lodash (package-lock.json)",
                confidence="high", status="open",
                created_at="2026", updated_at="2026",
                cve="CVE-2024-1111", package_name="lodash",
                installed_version="4.17.20", fixed_version="4.17.21",
            )
            state.save_findings([dep_finding])

            from aegis.adapters.trivy_runner import TrivyRunResult
            fake_trivy = TrivyRunResult(
                success=True, return_code=0, findings=[dep_finding],
                raw_json_path=None,
            )

            args = _fix_args(
                finding_id=dep_finding_id, run="test-run-deps",
                repo=str(repo), deps=True, apply=True,
            )
            with patch("aegis.adapters.trivy_runner.run_trivy", return_value=fake_trivy):
                cmd_fix(args, config)

            findings = state.load_findings()
            updated = next(f for f in findings if f["id"] == dep_finding_id)
            self.assertEqual(updated["status"], "fixed",
                             "deps bump must leave the finding 'fixed' and "
                             "must not be overwritten by the generic update")

            # And the bump actually landed on the deterministic branch
            current_branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
            self.assertEqual(current_branch,
                             f"aegis/fix/{dep_finding_id}")


class TestGlobalDryRunBlocksDocker(unittest.TestCase):
    """`aegis --dry-run targets up` must refuse to run Docker."""

    def test_dry_run_targets_up_aborts_before_docker(self):
        """The parser/main must refuse without ever invoking docker."""
        with patch("aegis.targets.subprocess.run") as docker_mock:
            try:
                main(["--dry-run", "targets", "up", "juice-shop"])
            except SystemExit as exc:
                self.assertEqual(exc.code, 2)
            else:
                self.fail("expected SystemExit(2) under --dry-run")
            docker_mock.assert_not_called()

    def test_dry_run_targets_down_aborts(self):
        with patch("aegis.targets.subprocess.run") as docker_mock:
            try:
                main(["--dry-run", "targets", "down", "juice-shop"])
            except SystemExit as exc:
                self.assertEqual(exc.code, 2)
            docker_mock.assert_not_called()

    def test_targets_list_still_allowed_under_dry_run(self):
        """`targets list` is read-only — must not be blocked."""
        try:
            main(["--dry-run", "targets", "list"])
        except SystemExit as exc:
            # main() doesn't exit on success; targets list prints and returns.
            self.fail(f"--dry-run targets list should not exit: {exc}")


if __name__ == "__main__":
    unittest.main()