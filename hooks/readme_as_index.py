"""mkdocs build hook: serve the repo-root README as docs/index.md.

The README ships in two contexts:
- GitHub's repo browser (where relative paths like ``docs/foo.md`` and
  ``CONTRIBUTING.md`` resolve correctly).
- The mkdocs site (where pages render relative to ``docs/`` and the
  cross-tree files aren't part of the site at all).

This hook reads ``README.md`` at build time, normalises the links so
they work in the mkdocs context, and returns the rewritten markdown
for ``index.md``. Result: one canonical README that renders correctly
in both places.

Rewrites:
- ``](docs/X)`` → ``](X)`` so links to docs/-internal pages resolve
  against the mkdocs serve root.
- ``](CONTRIBUTING.md|SECURITY.md|CHANGELOG.md|CLAUDE.md|specs/…|
  .specify/…|examples/…|.github/…)`` → absolute GitHub URL using
  ``repo_url`` from mkdocs.yml (repo-root files the docs site does not own).
"""

from __future__ import annotations

import re
from pathlib import Path


# Cross-tree paths that live outside ``docs/`` and must be rewritten
# to absolute GitHub URLs in the docs-site rendering.
_CROSS_TREE = re.compile(
    r"\]\((CONTRIBUTING\.md|SECURITY\.md|CHANGELOG\.md|CLAUDE\.md|"
    r"specs/[^)]+|\.specify/[^)]+|examples/[^)]+|\.github/[^)]+)\)"
)


def on_page_markdown(markdown, page, config, files):  # noqa: ARG001
    if page.file.src_uri != "index.md":
        return markdown

    repo_root = Path(config["docs_dir"]).parent
    readme = repo_root / "README.md"
    if not readme.exists():
        return markdown

    md = readme.read_text(encoding="utf-8")

    # docs-internal: strip the leading ``docs/`` so paths resolve from
    # the mkdocs serve root. Handles both file links (docs/x.md) and
    # directory links (docs/adr/).
    md = re.sub(r"\]\(docs/", "](", md)

    # Cross-tree files: rewrite to absolute GitHub URLs so they at
    # least navigate from the docs site (mkdocs doesn't own them).
    repo_url = config.get("repo_url", "").rstrip("/")
    if repo_url:
        gh_blob = f"{repo_url}/blob/main"
        md = _CROSS_TREE.sub(rf"]({gh_blob}/\1)", md)

    return md
