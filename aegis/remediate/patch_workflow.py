"""Patch lifecycle: extract from agent output -> apply -> commit -> branch -> PR -> rollback."""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aegis.schema import AegisFinding

_FENCE_RE = re.compile(
    r"```(?:diff|patch)\s*\n(.*?)```", re.DOTALL | re.IGNORECASE
)
_HUNK_HEADER_RE = re.compile(r"^---\s+a/.+\n\+\+\+\s+b/.+", re.MULTILINE)


@dataclass
class ApplyResult:
    success: bool
    dry_run: bool
    stdout: str
    stderr: str


@dataclass
class CommitResult:
    success: bool
    branch: str
    commit_hash: str | None
    ref_before: str | None
    diff_sha256: str
    error: str | None = None


def extract_unified_diff(agent_output: str | None) -> str | None:
    """Extract a unified diff from CAI agent output.

    Strategy:
      1. ``` diff / ``` patch fenced block.
      2. First ``` block that looks like a unified diff.
      3. Naked --- a/... / +++ b/... block.
    """
    if not agent_output:
        return None

    for match in _FENCE_RE.finditer(agent_output):
        candidate = match.group(1).strip()
        if "---" in candidate and "+++" in candidate:
            return candidate + "\n" if not candidate.endswith("\n") else candidate

    # Fall back: naked diff outside fences.
    m = _HUNK_HEADER_RE.search(agent_output)
    if m:
        return agent_output[m.start():].rstrip() + "\n"

    return None


def diff_sha256(diff: str) -> str:
    return hashlib.sha256(diff.encode("utf-8")).hexdigest()


def _git(repo: Path, args: list[str], *, check: bool = True,
         input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        input=input_text,
        check=check,
    )


def _ref_before(repo: Path) -> str | None:
    try:
        return _git(repo, ["rev-parse", "HEAD"]).stdout.strip()
    except subprocess.CalledProcessError:
        return None


def is_repo_dirty(repo: Path) -> bool:
    try:
        result = _git(repo, ["status", "--porcelain"])
    except subprocess.CalledProcessError:
        return True
    return bool(result.stdout.strip())


def apply_patch(repo_path: Path | str, diff: str, *, dry_run: bool = True) -> ApplyResult:
    repo = Path(repo_path)
    if not diff.endswith("\n"):
        diff = diff + "\n"
    try:
        check = _git(repo, ["apply", "--check"], input_text=diff, check=False)
    except FileNotFoundError as exc:
        return ApplyResult(False, dry_run, "", f"git not found: {exc}")
    if check.returncode != 0:
        return ApplyResult(False, dry_run, check.stdout, check.stderr or "git apply --check failed")
    if dry_run:
        return ApplyResult(True, True, check.stdout, "")
    result = _git(repo, ["apply"], input_text=diff, check=False)
    return ApplyResult(result.returncode == 0, False, result.stdout, result.stderr)


def deterministic_branch(finding_id: str) -> str:
    return f"aegis/fix/{finding_id}"


def commit_patch(
    repo_path: Path | str,
    finding: AegisFinding,
    diff: str,
    *,
    branch: str | None = None,
    allow_dirty: bool = False,
    author_name: str = "Aegis",
    author_email: str = "aegis@example.invalid",
) -> CommitResult:
    """Branch-first, apply, commit — with automatic rollback on any failure.

    Order is critical for safety: we never mutate the working tree on the
    current branch. On any failure the repo is reset to its pre-call state.

    1. Capture ``ref_before`` and refuse to proceed when dirty unless
       ``allow_dirty=True``.
    2. Create / check out the deterministic branch.
    3. ``git apply --check`` against the new branch.
    4. ``git apply`` to mutate the tree.
    5. ``git add -A && git commit``.
    6. On any failure after the branch is created, ``git reset --hard
       ref_before`` so the repo never lingers in a half-applied state.
    """
    repo = Path(repo_path)
    branch_name = branch or deterministic_branch(finding.id)
    ref_before = _ref_before(repo)
    digest = diff_sha256(diff)

    if not diff.endswith("\n"):
        diff = diff + "\n"

    if ref_before is None:
        return CommitResult(
            success=False, branch=branch_name, commit_hash=None,
            ref_before=None, diff_sha256=digest,
            error="repository has no HEAD (initialize and make an initial commit first)",
        )

    # Remember the symbolic branch the user was on so we can restore it
    # on rollback. ``--abbrev-ref HEAD`` returns "HEAD" in detached state.
    initial_branch_run = _git(repo, ["rev-parse", "--abbrev-ref", "HEAD"], check=False)
    initial_branch = initial_branch_run.stdout.strip()

    if is_repo_dirty(repo) and not allow_dirty:
        return CommitResult(
            success=False, branch=branch_name, commit_hash=None,
            ref_before=ref_before, diff_sha256=digest,
            error="repository has uncommitted changes (pass allow_dirty=True to override)",
        )

    branch_created = False

    def _rollback() -> None:
        # Drop any in-progress tree changes, hop back to the user's branch,
        # then delete the throwaway branch we created.
        _git(repo, ["reset", "--hard", "HEAD"], check=False)
        if initial_branch and initial_branch != "HEAD":
            _git(repo, ["checkout", initial_branch], check=False)
        else:
            _git(repo, ["checkout", "--detach", ref_before], check=False)
        if branch_created:
            _git(repo, ["branch", "-D", branch_name], check=False)

    # Step 2: branch first — never mutate the current branch.
    checkout_result = _git(repo, ["checkout", "-B", branch_name, ref_before], check=False)
    if checkout_result.returncode != 0:
        return CommitResult(
            success=False, branch=branch_name, commit_hash=None,
            ref_before=ref_before, diff_sha256=digest,
            error=checkout_result.stderr or "git checkout failed",
        )
    branch_created = True

    # Step 3: dry-run apply against the new branch.
    check = _git(repo, ["apply", "--check"], input_text=diff, check=False)
    if check.returncode != 0:
        _rollback()
        return CommitResult(
            success=False, branch=branch_name, commit_hash=None,
            ref_before=ref_before, diff_sha256=digest,
            error=check.stderr or "git apply --check failed",
        )

    # Step 4: real apply.
    apply_real = _git(repo, ["apply"], input_text=diff, check=False)
    if apply_real.returncode != 0:
        _rollback()
        return CommitResult(
            success=False, branch=branch_name, commit_hash=None,
            ref_before=ref_before, diff_sha256=digest,
            error=apply_real.stderr or "git apply failed",
        )

    # Step 5: commit.
    message = f"Aegis fix: {finding.id} {finding.title}\n\ndiff-sha256: {digest}\n"
    commit_args = [
        "-c", f"user.name={author_name}",
        "-c", f"user.email={author_email}",
        "commit", "-a", "-m", message,
    ]
    commit_run = _git(repo, commit_args, check=False)
    if commit_run.returncode != 0:
        _rollback()
        return CommitResult(
            success=False, branch=branch_name, commit_hash=None,
            ref_before=ref_before, diff_sha256=digest,
            error=commit_run.stderr or "git commit failed",
        )

    commit_hash = _git(repo, ["rev-parse", "HEAD"], check=False).stdout.strip()
    return CommitResult(
        success=True, branch=branch_name, commit_hash=commit_hash,
        ref_before=ref_before, diff_sha256=digest, error=None,
    )


def rollback(repo_path: Path | str, ref_before: str) -> bool:
    """Hard-reset the working tree to the pre-patch ref."""
    repo = Path(repo_path)
    try:
        _git(repo, ["reset", "--hard", ref_before])
        return True
    except subprocess.CalledProcessError:
        return False


def open_pull_request(
    repo_path: Path | str,
    branch: str,
    *,
    title: str,
    body: str,
    base: str = "main",
    push: bool = True,
) -> tuple[bool, str]:
    """Push the branch and create a PR via the gh CLI.

    Returns (success, pr_url_or_error). Requires gh to be authenticated.
    """
    repo = Path(repo_path)
    if push:
        push_result = subprocess.run(
            ["git", "-C", str(repo), "push", "-u", "origin", branch],
            capture_output=True, text=True, check=False,
        )
        if push_result.returncode != 0:
            return False, push_result.stderr or "git push failed"
    pr_result = subprocess.run(
        ["gh", "pr", "create",
         "--title", title,
         "--body", body,
         "--base", base,
         "--head", branch],
        capture_output=True, text=True, check=False, cwd=str(repo),
    )
    if pr_result.returncode != 0:
        return False, pr_result.stderr or "gh pr create failed"
    url = pr_result.stdout.strip().splitlines()[-1] if pr_result.stdout else ""
    return True, url


# ---------------------------------------------------------------------------
# Golden patch fixture loader (for AEGIS_DISABLE_LLM / --use-golden-patch)
# ---------------------------------------------------------------------------

_GOLDEN_DIR = Path(__file__).resolve().parents[2] / "tests" / "fixtures"


def load_golden_patch(finding_id: str) -> str | None:
    """Return the bundled golden patch for a finding id, if available."""
    candidate = _GOLDEN_DIR / f"{finding_id}.diff"
    if candidate.exists():
        return candidate.read_text()
    # Fall back to the demo SQLi golden patch when finding_id is the seeded vuln.
    sqli = _GOLDEN_DIR / "juice_shop_login.diff"
    if finding_id == "vuln-0001" and sqli.exists():
        return sqli.read_text()
    return None
