import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from aegis.remediate.deps_workflow import build_version_bump_diff
from aegis.remediate.patch_workflow import apply_patch, commit_patch
from aegis.schema import AegisFinding


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
    ).stdout


def _dep_finding(pkg, installed, fixed, fid=None):
    return AegisFinding(
        id=fid or f"CVE-X@{pkg}",
        title=f"{pkg} vuln", severity="high", finding_type="dependency",
        description="...", source_tool="trivy", source_run_id="r",
        affected_component=f"{pkg}", confidence="high", status="open",
        created_at="2026-01-01", updated_at="2026-01-01",
        package_name=pkg, installed_version=installed, fixed_version=fixed,
    )


class TestNpmBump(unittest.TestCase):
    def test_bumps_package_json_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            pkg_json = repo / "package.json"
            pkg_json.write_text(json.dumps({
                "name": "demo",
                "dependencies": {
                    "lodash": "4.17.20",
                    "express": "^4.17.1",
                },
            }, indent=2) + "\n")
            _git(repo, "init", "-q")
            _git(repo, "config", "user.email", "t@example.invalid")
            _git(repo, "config", "user.name", "T")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "-m", "init")

            finding = _dep_finding("lodash", "4.17.20", "4.17.21")
            bump = build_version_bump_diff(finding, repo)

            self.assertIsNotNone(bump.diff, msg=bump.error)
            self.assertEqual(bump.rel_path, "package.json")

            # The diff applies cleanly via git apply
            applied = apply_patch(repo, bump.diff, dry_run=True)
            self.assertTrue(applied.success, msg=applied.stderr)

            # Commit path also works end-to-end
            commit = commit_patch(repo, finding, bump.diff)
            self.assertTrue(commit.success, msg=commit.error)

    def test_refuses_when_spec_does_not_include_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "package.json").write_text(json.dumps({
                "name": "demo",
                "dependencies": {"lodash": "5.0.0"},
            }, indent=2) + "\n")
            finding = _dep_finding("lodash", "4.17.20", "4.17.21")
            bump = build_version_bump_diff(finding, repo)
            self.assertIsNone(bump.diff)
            self.assertIn("does not include installed", bump.error or "")


class TestRequirementsBump(unittest.TestCase):
    def test_bumps_requirements_txt(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "requirements.txt").write_text(
                "requests==2.28.1\nPyYAML>=6.0\n"
            )
            _git(repo, "init", "-q")
            _git(repo, "config", "user.email", "t@example.invalid")
            _git(repo, "config", "user.name", "T")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "-m", "init")

            finding = _dep_finding("requests", "2.28.1", "2.31.0")
            bump = build_version_bump_diff(finding, repo)
            self.assertIsNotNone(bump.diff, msg=bump.error)
            self.assertEqual(bump.rel_path, "requirements.txt")

            applied = apply_patch(repo, bump.diff, dry_run=True)
            self.assertTrue(applied.success, msg=applied.stderr)

    def test_case_insensitive_package_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "requirements.txt").write_text("PyYAML==6.0\n")
            finding = _dep_finding("pyyaml", "6.0", "6.0.1")
            bump = build_version_bump_diff(finding, repo)
            self.assertIsNotNone(bump.diff)


class TestNoManifest(unittest.TestCase):
    def test_returns_error_when_no_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            finding = _dep_finding("anything", "1.0", "1.1")
            bump = build_version_bump_diff(finding, Path(tmp))
            self.assertIsNone(bump.diff)
            self.assertIsNotNone(bump.error)

    def test_missing_fixed_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = _dep_finding("p", "1.0", "")  # empty fixed_version
            bump = build_version_bump_diff(f, Path(tmp))
            self.assertIsNone(bump.diff)


if __name__ == "__main__":
    unittest.main()
