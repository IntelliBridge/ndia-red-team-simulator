# Editing the docs

The docs you are reading are rendered from markdown files under `docs/`. The
build uses [MkDocs Material](https://squidfunk.github.io/mkdocs-material/)
with native mermaid support. Markdown is the authoring format, the rendered
HTML is build output.

## Run the site locally

`mkdocs` and Material come from the `docs` extra, which `make install` does
not include by default:

```bash
uv pip install --native-tls -e ".[docs]"
MKDOCS=.venv/bin/mkdocs make docs-serve          # http://localhost:8001
MKDOCS=.venv/bin/mkdocs make docs-build          # output: ./site/
MKDOCS=.venv/bin/mkdocs make docs-build-strict   # what CI runs
```

The root `Makefile` targets call `mkdocs` from `PATH`, so either activate the
venv or pass `MKDOCS=…` as above. `.venv/bin/python -m mkdocs build --strict`
is the equivalent direct call. `deploy/Makefile` has no docs targets.

## Build hooks

Two hooks in `hooks/` are registered in `mkdocs.yml` and keep the strict build
green without editing content for the build:

- `readme_as_index.py` renders the root `README.md` as the site landing page
  (`docs/index.md` is a stub). It strips the leading `docs/` from links so
  they resolve from the site root, and rewrites links to `CONTRIBUTING.md`,
  `SECURITY.md`, `CHANGELOG.md`, `CLAUDE.md`, `specs/…`, `.specify/…` and
  `.github/…` to absolute GitHub URLs.
- `cross_tree_links.py` runs on every page and rewrites relative links that
  escape `docs/` (for example `../specs/README.md`) to absolute GitHub URLs
  when the target exists in the repository. A link to a file that exists
  nowhere is left alone so strict mode still reports it.

## Conventions

- **Markdown renders in two places**, the docs site and GitHub's repo browser.
  Keep it idiomatic so both render cleanly.
- **Mermaid diagrams** go in ```` ```mermaid ```` fenced blocks
  (`pymdownx.superfences`). The interactive HTML diagrams under
  `docs/architecture/diagrams/` are static files that mkdocs copies as-is.
- **Internal links** use relative paths within `docs/`
  (`[auth](../architecture/auth.md)`). Cross-tree links (to `deploy/`,
  `specs/`, root files) may be written as relative paths, the hook rewrites
  them, or as absolute GitHub URLs.
- **Code samples** use `bash`, `python`, `ts`, `yaml` or `jsonc` fences so
  Pygments highlights them.
- **Admonitions** (`!!! note`, `!!! warning`, `!!! danger`) are available.
  Most prose works without them.
- **Prose** avoids em dashes and semicolons. Use `aegis` only for the
  upstream project and its history, everything that describes this code says
  redsim.
- **Do not describe unmerged code as existing.** Mark it as "PR #n" or
  "planned (WSn)".

## Adding a new page

1. Write the page under `docs/architecture/`, `docs/api/`, `docs/ops/`,
   `docs/dev/`, `docs/security/`, `docs/plans/` or `docs/adr/`.
2. Add it to the `nav:` block in `mkdocs.yml` under the section it belongs
   to. A page that exists but is not in the nav is only an INFO message
   today, but readers cannot find it from the sidebar (`docs/ops/pythia.md`
   and `docs/workstreams/pythia-access.md` are in that state on 2026-09-08).
3. Cross-link from at least one neighbouring page.
4. Run the strict build locally before opening the PR.

## ADRs

Architectural Decision Records live under `docs/adr/`, numbered sequentially.
[`0001-vendored-submodules.md`](../adr/0001-vendored-submodules.md) is the
template (Context, Decision, Consequences, Bumps log when applicable). ADRs
0001, 0002 and 0004 were written for the pentest platform and are kept as
history.

## Strict mode

CI runs `mkdocs build --strict`, which turns these into errors:

- Links to files mkdocs cannot find.
- References to anchors that do not exist on the target page.

Pages outside the nav and unknown anchors inside one page are INFO only. The
build passed on `main` at `4320740` in about 2 s.

## Theming and behaviour

The Material theme and extensions are configured in `mkdocs.yml`: dark and
light toggle, sticky top tabs plus sidebar, copy buttons on code blocks,
full-text search, and an "Edit this page" link to the source on GitHub.
Theming changes that touch more than one variable should land as an ADR.

## Hosting

`.github/workflows/docs.yml` builds the site on every PR and push that
touches `docs/`, `mkdocs.yml`, `hooks/`, `pyproject.toml` or the root
markdown files. The GitHub Pages deploy job is dormant behind the repo
variable `ENABLE_PAGES`: Pages is off because the repository is private and
the plan offers only public Pages. To turn it on, enable Pages with source
"GitHub Actions" and set `ENABLE_PAGES=true`.
