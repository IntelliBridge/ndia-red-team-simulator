"""mkdocs build hook: rewrite links that escape ``docs/`` to GitHub URLs.

Pages under ``docs/`` link to repo-root files (``../CONTRIBUTING.md``,
``../SECURITY.md``, ``../deploy/...``) with relative paths. Those paths are
correct on GitHub, but the files are not part of the mkdocs site, so
``mkdocs build --strict`` rejects every one of them as "target is not found
among documentation files".

This hook runs on every page. For each relative markdown link whose target
resolves *outside* ``docs_dir`` it checks that the target exists in the
repository and, when it does, rewrites the link to an absolute
``{repo_url}/blob/main/<path>`` URL (``tree`` for directories). A link whose
target does not exist anywhere is left untouched so strict validation still
flags it. Links that are already absolute (any URL scheme, ``mailto:``,
``#anchor``) and links that stay inside ``docs/`` are never modified.

``hooks/readme_as_index.py`` does the same job for the README rendered as
``index.md``. Both hooks are registered in ``mkdocs.yml``.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path

# ``](target)`` or ``](target "title")``. The target has no whitespace and no
# closing paren, which is how every link in this tree is written.
_LINK = re.compile(r"\]\((?P<target>[^)\s<>]+)(?P<title>\s+\"[^\"]*\")?\)")
_HAS_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _rewrite_target(target: str, page_dir: str, docs_dir: Path, repo_root: Path, repo_url: str) -> str | None:
    """Return the absolute GitHub URL for ``target`` or ``None`` to leave it alone."""
    if not target or target.startswith("#") or target.startswith("/") or _HAS_SCHEME.match(target):
        return None
    path, _sep, anchor = target.partition("#")
    if not path:
        return None

    resolved = (docs_dir / page_dir / path).resolve()
    try:
        resolved.relative_to(docs_dir)
        return None  # stays inside the docs tree: mkdocs validates it
    except ValueError:
        pass

    try:
        rel = resolved.relative_to(repo_root)
    except ValueError:
        return None  # escapes the repository entirely: leave for validation
    if not resolved.exists():
        return None  # genuinely broken: leave so --strict reports it

    kind = "tree" if resolved.is_dir() else "blob"
    url = f"{repo_url}/{kind}/main/{rel.as_posix()}"
    return f"{url}#{anchor}" if anchor else url


def on_page_markdown(markdown, page, config, files):  # noqa: ARG001
    repo_url = (config.get("repo_url") or "").rstrip("/")
    if not repo_url:
        return markdown

    docs_dir = Path(config["docs_dir"]).resolve()
    repo_root = docs_dir.parent
    page_dir = posixpath.dirname(page.file.src_uri)

    def _sub(match: re.Match[str]) -> str:
        new = _rewrite_target(match.group("target"), page_dir, docs_dir, repo_root, repo_url)
        if new is None:
            return match.group(0)
        return f"]({new}{match.group('title') or ''})"

    return _LINK.sub(_sub, markdown)
