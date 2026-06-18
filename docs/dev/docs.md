# Editing the docs

The docs you're reading are rendered from markdown files under
`docs/`. The build uses [MkDocs Material](https://squidfunk.github.io/mkdocs-material/)
with native mermaid support. Markdown stays the authoritative
authoring format; the rendered HTML is build output.

## Run the site locally

```bash
pip install -e ".[docs]"
mkdocs serve            # http://localhost:8001
```

`mkdocs serve` watches the tree and rebuilds on save. To produce the
static output without serving:

```bash
mkdocs build            # output: ./site/
```

Both targets are wired into the deploy Makefile too:

```bash
cd deploy
make docs-serve         # equivalent to mkdocs serve
make docs-build         # equivalent to mkdocs build
```

## Conventions

- **Authoring format is markdown.** Every page under `docs/` is
  rendered both by the docs site and by GitHub's repo browser; keep
  the markdown idiomatic so both render cleanly.
- **Mermaid diagrams** go in `\`\`\`mermaid` fenced blocks. The
  build's `pymdownx.superfences` extension renders them natively;
  GitHub renders the same blocks on its side.
- **Internal links** use relative paths within `docs/` (e.g.
  `[auth](../architecture/auth.md)`). Cross-tree links (to
  `project_repos/`, `deploy/`, root-level `CONTRIBUTING.md` etc.)
  use absolute GitHub URLs so they work in both the docs site and
  GitHub's repo browser.
- **Code samples** that show shell commands prefer `bash`. Python /
  TS samples use their respective language tags so Pygments
  highlights them.
- **Admonitions** (`!!! note`, `!!! warning`) are available via
  `pymdownx.details`. Don't overuse them — most prose works without.

## Adding a new page

1. Write the page under the appropriate directory (`docs/architecture/`,
   `docs/api/`, `docs/ops/`, `docs/dev/`, `docs/security/`, or
   `docs/adr/`).
2. Add it to the `nav:` block in [`mkdocs.yml`](https://github.com/IntelliBridge/aegis/blob/main/mkdocs.yml)
   under the section it belongs to. Pages **not** referenced in
   `nav` will surface a build warning unless they live under
   `architecture/legacy/`.
3. Cross-link from at least one neighbouring page so the nav isn't
   the only entry point.
4. Run `mkdocs build --strict` locally before opening the PR — CI
   runs the same check.

## ADRs

Architectural Decision Records live under `docs/adr/`. Number them
sequentially (`0001-…`, `0002-…`). The
[vendored-submodules ADR](../adr/0001-vendored-submodules.md) is the
template — keep the same section structure (Context → Decision →
Consequences → Bumps log when applicable).

## Strict-mode build

CI runs `mkdocs build --strict` so broken cross-references fail the
build. Locally:

```bash
mkdocs build --strict
```

Strict mode treats these as errors:

- Pages in `docs/` that aren't in `nav`.
- Links to files mkdocs can't find.
- References to anchors that don't exist on the target page.

The exception is `docs/architecture/legacy/` — those files are
intentionally archived and excluded from nav. The
[`legacy/README.md`](../architecture/legacy/README.md) explains
what each archived file is.

## Theming + behaviour

The Material theme + extensions are configured in `mkdocs.yml`:

- Dark / light mode toggle in the header.
- Sticky top tabs for the major sections; sidebar for deeper nav.
- Code blocks render with copy buttons and line annotations.
- Full-text search with suggestions.
- "Edit this page" link in the page header points at the source
  file on GitHub.

Theming changes that touch more than one variable should land as an
ADR. Day-to-day tweaks (palette, feature flag, plugin add) can ship
in a regular commit.

## Hosting

The site builds on every PR via
[`.github/workflows/docs.yml`](https://github.com/IntelliBridge/aegis/blob/main/.github/workflows/docs.yml).
Pushes to `main` deploy to GitHub Pages.
