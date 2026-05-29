import subprocess
import tempfile
import unittest
from pathlib import Path

from aegis.remediate.patch_workflow import (
    apply_patch,
    commit_patch,
    deterministic_branch,
    diff_sha256,
    extract_unified_diff,
    is_repo_dirty,
    load_golden_patch,
    rollback,
)
from aegis.schema import AegisFinding

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN_DIFF = (FIXTURES / "juice_shop_login.diff").read_text()


def _git(repo: Path, *args: str, **kwargs) -> str:
    kwargs.setdefault("check", True)
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    return subprocess.run(["git", "-C", str(repo), *args], **kwargs).stdout


def _init_repo(repo: Path, seed_content: str) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    (repo / "routes").mkdir()
    (repo / "routes" / "login.js").write_text(seed_content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")


_SEED_LOGIN_JS = (
    "module.exports = function login () {\n"
    "  return (req, res, next) => {\n"
    "    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${hash}'`)\n"
    "  }\n"
    "}\n"
)


class TestExtractDiff(unittest.TestCase):
    def test_extracts_from_diff_fence(self):
        agent_response = (FIXTURES / "cai_codeagent_response.txt").read_text()
        diff = extract_unified_diff(agent_response)
        self.assertIsNotNone(diff)
        self.assertIn("--- a/routes/login.js", diff)
        self.assertIn("+++ b/routes/login.js", diff)
        self.assertIn("replacements: [req.body.email, hash]", diff)

    def test_extracts_from_patch_fence(self):
        text = "Here you go:\n```patch\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n```\nDone."
        diff = extract_unified_diff(text)
        self.assertIsNotNone(diff)
        self.assertIn("--- a/x", diff)

    def test_extracts_naked_diff(self):
        text = "blah blah\n--- a/foo.py\n+++ b/foo.py\n@@ -1 +1 @@\n-old\n+new\n"
        diff = extract_unified_diff(text)
        self.assertIsNotNone(diff)
        self.assertTrue(diff.startswith("--- a/foo.py"))

    def test_returns_none_for_no_diff(self):
        self.assertIsNone(extract_unified_diff("Just plain text."))
        self.assertIsNone(extract_unified_diff(None))


class TestApplyPatch(unittest.TestCase):
    def test_dry_run_does_not_modify(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo, _SEED_LOGIN_JS)
            result = apply_patch(repo, GOLDEN_DIFF, dry_run=True)
            self.assertTrue(result.success)
            self.assertTrue(result.dry_run)
            self.assertEqual((repo / "routes" / "login.js").read_text(), _SEED_LOGIN_JS)

    def test_apply_modifies_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo, _SEED_LOGIN_JS)
            result = apply_patch(repo, GOLDEN_DIFF, dry_run=False)
            self.assertTrue(result.success)
            self.assertFalse(result.dry_run)
            modified = (repo / "routes" / "login.js").read_text()
            self.assertIn("'SELECT * FROM Users WHERE email = ? AND password = ?'", modified)
            self.assertNotIn("`${req.body.email}`", modified)

    def test_check_fails_on_unmatching_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo, "totally different content\n")
            result = apply_patch(repo, GOLDEN_DIFF, dry_run=True)
            self.assertFalse(result.success)


class TestCommitPatch(unittest.TestCase):
    def _finding(self) -> AegisFinding:
        return AegisFinding(
            id="vuln-0001", title="SQL Injection in Login Form",
            severity="critical", finding_type="dast",
            description="...", source_tool="strix", source_run_id="r",
            affected_component="/rest/user/login", confidence="high",
            status="open", created_at="2026-01-01", updated_at="2026-01-01",
        )

    def test_commit_creates_branch_and_records_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo, _SEED_LOGIN_JS)
            result = commit_patch(repo, self._finding(), GOLDEN_DIFF)
            self.assertTrue(result.success, msg=result.error)
            self.assertEqual(result.branch, "aegis/fix/vuln-0001")
            self.assertIsNotNone(result.commit_hash)
            self.assertEqual(result.diff_sha256, diff_sha256(GOLDEN_DIFF))
            self.assertIsNotNone(result.ref_before)

            # On the new branch
            current_branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
            self.assertEqual(current_branch, "aegis/fix/vuln-0001")

            # Commit message contains diff sha
            msg = _git(repo, "log", "-1", "--pretty=%B")
            self.assertIn(result.diff_sha256, msg)

    def test_refuses_dirty_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo, _SEED_LOGIN_JS)
            (repo / "dirty.txt").write_text("uncommitted")
            result = commit_patch(repo, self._finding(), GOLDEN_DIFF)
            self.assertFalse(result.success)
            self.assertIn("uncommitted", result.error or "")

    def test_rollback_returns_to_ref_before(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo, _SEED_LOGIN_JS)
            result = commit_patch(repo, self._finding(), GOLDEN_DIFF)
            self.assertTrue(result.success)
            assert result.ref_before  # for type checker
            self.assertTrue(rollback(repo, result.ref_before))
            self.assertEqual((repo / "routes" / "login.js").read_text(), _SEED_LOGIN_JS)

    def test_branch_first_does_not_mutate_current_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo, _SEED_LOGIN_JS)
            initial_branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
            initial_commit = _git(repo, "rev-parse", initial_branch).strip()
            commit_patch(repo, self._finding(), GOLDEN_DIFF)
            # The original branch's tip is unchanged
            self.assertEqual(_git(repo, "rev-parse", initial_branch).strip(), initial_commit)
            # The file on the original branch still has the vulnerable content
            file_on_orig = _git(repo, "show", f"{initial_branch}:routes/login.js")
            self.assertIn("`SELECT * FROM Users WHERE email = '${req.body.email}'", file_on_orig)

    def test_rolls_back_when_apply_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo, "totally different content\n")
            initial_branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
            initial_commit = _git(repo, "rev-parse", "HEAD").strip()
            result = commit_patch(repo, self._finding(), GOLDEN_DIFF)
            self.assertFalse(result.success)
            self.assertIn("apply", (result.error or "").lower())
            # Working tree is clean and we're back on the original branch
            self.assertFalse(is_repo_dirty(repo))
            self.assertEqual(
                _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip(), initial_branch
            )
            self.assertEqual(_git(repo, "rev-parse", "HEAD").strip(), initial_commit)
            # The orphan branch must NOT remain (we deleted it on rollback)
            branches = _git(repo, "branch", "--list", "aegis/fix/vuln-0001").strip()
            self.assertEqual(branches, "")

    def test_rolls_back_when_commit_fails(self):
        """When git commit itself fails, the tree returns to ref_before."""
        from unittest.mock import patch as mpatch

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo, _SEED_LOGIN_JS)
            initial_branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
            initial_commit = _git(repo, "rev-parse", "HEAD").strip()

            real_git = __import__("aegis.remediate.patch_workflow", fromlist=["_git"])._git

            def flaky_git(repo_arg, args, **kwargs):
                # Inject failure only on the actual commit step
                if len(args) >= 4 and args[0] == "-c" and "commit" in args:
                    return subprocess.CompletedProcess(
                        ["git", "commit"], 1, stdout="",
                        stderr="simulated commit failure",
                    )
                return real_git(repo_arg, args, **kwargs)

            with mpatch("aegis.remediate.patch_workflow._git", side_effect=flaky_git):
                result = commit_patch(repo, self._finding(), GOLDEN_DIFF)

            self.assertFalse(result.success)
            self.assertIn("commit", (result.error or "").lower())
            self.assertFalse(is_repo_dirty(repo))
            self.assertEqual(
                _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip(), initial_branch
            )
            self.assertEqual(_git(repo, "rev-parse", "HEAD").strip(), initial_commit)


class TestGoldenPatch(unittest.TestCase):
    def test_load_golden_patch_for_seeded_id(self):
        diff = load_golden_patch("vuln-0001")
        self.assertIsNotNone(diff)
        self.assertIn("--- a/routes/login.js", diff)

    def test_load_returns_none_for_unknown(self):
        self.assertIsNone(load_golden_patch("definitely-not-a-real-id"))


class TestBranchNaming(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(deterministic_branch("vuln-0001"), "aegis/fix/vuln-0001")


class TestIsRepoDirty(unittest.TestCase):
    def test_clean_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo, _SEED_LOGIN_JS)
            self.assertFalse(is_repo_dirty(repo))

    def test_dirty_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo, _SEED_LOGIN_JS)
            (repo / "extra.txt").write_text("x")
            self.assertTrue(is_repo_dirty(repo))


if __name__ == "__main__":
    unittest.main()
