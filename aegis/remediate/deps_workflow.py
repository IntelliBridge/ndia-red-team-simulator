"""Deterministic version-bump patch generation for dependency findings.

When Trivy emits a finding with both ``installed_version`` and
``fixed_version`` and the repo contains a recognizable manifest entry
(npm ``package.json``, Python ``requirements.txt`` / ``pyproject.toml``),
we can synthesize a one-line unified diff without an LLM. That's the path
this module implements.

If no manifest entry can be matched, we return None so the caller can fall
back to a CAI prompt (or report the failure cleanly).
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from pathlib import Path

from aegis.schema import AegisFinding


@dataclass
class BumpResult:
    diff: str | None
    rel_path: str | None
    error: str | None = None


_NPM_LINE_RE = re.compile(
    r'^(?P<indent>\s*)"(?P<pkg>[^"]+)"\s*:\s*"(?P<spec>[\^~><=]*\s*\d[^"]*)"(?P<suffix>,?\s*)$'
)
_REQS_LINE_RE = re.compile(
    r"^(?P<pkg>[A-Za-z0-9_.\-]+)\s*(?P<op>==|>=|~=|<=)\s*(?P<ver>[^\s;#]+)(?P<rest>.*)$"
)


def _make_unified_diff(rel_path: str, old_lines: list[str], new_lines: list[str]) -> str:
    """Compose a proper unified diff via difflib (with context lines)."""
    diff = difflib.unified_diff(
        old_lines, new_lines,
        fromfile=f"a/{rel_path}", tofile=f"b/{rel_path}",
        n=3,
    )
    return "".join(diff)


def _replace_line(content: str, line_index: int, new_line: str) -> tuple[list[str], list[str]]:
    """Return (old_lines, new_lines) where line at line_index (0-based) is replaced."""
    old_lines = content.splitlines(keepends=True)
    new_lines = list(old_lines)
    suffix = "\n" if (line_index < len(old_lines) and old_lines[line_index].endswith("\n")) else ""
    new_lines[line_index] = new_line + suffix
    return old_lines, new_lines


def _bump_npm(repo: Path, pkg: str, current: str, fixed: str) -> BumpResult:
    pkg_json = repo / "package.json"
    if not pkg_json.exists():
        return BumpResult(None, None, "package.json not found")
    content = pkg_json.read_text()
    for idx, raw in enumerate(content.splitlines(keepends=True)):
        line = raw.rstrip("\n")
        m = _NPM_LINE_RE.match(line)
        if not m:
            continue
        if m.group("pkg") != pkg:
            continue
        if current not in m.group("spec"):
            return BumpResult(
                None, "package.json",
                f"found '{pkg}' but spec '{m.group('spec')}' does not include installed '{current}'",
            )
        new_spec = m.group("spec").replace(current, fixed)
        new_line = f'{m.group("indent")}"{pkg}": "{new_spec}"{m.group("suffix")}'
        old_lines, new_lines = _replace_line(content, idx, new_line)
        return BumpResult(
            diff=_make_unified_diff("package.json", old_lines, new_lines),
            rel_path="package.json",
        )
    return BumpResult(None, "package.json", f"package '{pkg}' not listed")


def _bump_requirements(repo: Path, pkg: str, current: str, fixed: str) -> BumpResult:
    req = repo / "requirements.txt"
    if not req.exists():
        return BumpResult(None, None, "requirements.txt not found")
    content = req.read_text()
    for idx, raw in enumerate(content.splitlines(keepends=True)):
        line = raw.rstrip("\n")
        m = _REQS_LINE_RE.match(line)
        if not m:
            continue
        if m.group("pkg").lower() != pkg.lower():
            continue
        if m.group("ver") != current:
            return BumpResult(
                None, "requirements.txt",
                f"found '{pkg}' but version '{m.group('ver')}' != installed '{current}'",
            )
        new_line = f"{m.group('pkg')}{m.group('op')}{fixed}{m.group('rest')}"
        old_lines, new_lines = _replace_line(content, idx, new_line)
        return BumpResult(
            diff=_make_unified_diff("requirements.txt", old_lines, new_lines),
            rel_path="requirements.txt",
        )
    return BumpResult(None, "requirements.txt", f"package '{pkg}' not listed")


def build_version_bump_diff(finding: AegisFinding, repo_path: Path | str) -> BumpResult:
    """Synthesize a single-line bump diff for a dependency finding."""
    repo = Path(repo_path)
    pkg = finding.package_name
    current = finding.installed_version
    fixed = finding.fixed_version
    if not pkg or not current or not fixed or fixed == "N/A":
        return BumpResult(None, None, "finding lacks package_name / installed_version / fixed_version")

    npm = _bump_npm(repo, pkg, current, fixed)
    if npm.diff is not None:
        return npm
    py = _bump_requirements(repo, pkg, current, fixed)
    if py.diff is not None:
        return py

    # Both failed — surface the most informative error
    reason = npm.error or py.error or "no recognizable manifest matched"
    return BumpResult(None, None, reason)
