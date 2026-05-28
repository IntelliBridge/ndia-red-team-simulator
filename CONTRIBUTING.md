# Contributing to Aegis

Welcome. This guide covers the dev setup, the conventions every PR is
expected to follow, and the gates a change has to pass before merge.

## Dev setup

```bash
git clone --recurse-submodules <repo-url>
cd Pentest
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[test,dev]"              # Phase 2 offline CLI
pip install -e ".[test,dev,api,worker]"   # full stack (Phase 3+)
```

Python 3.12 or 3.13 is required. The default macOS `python3` (3.9)
won't work — use Homebrew's `python3.12` or `python3.13`.

For frontend work, the repo is a pnpm workspace:

```bash
pnpm install --frozen-lockfile          # honours web/pnpm-lock.yaml
pnpm --filter @aegis/web dev            # next dev -p 3000
pnpm --filter @aegis/web typecheck
pnpm --filter @aegis/web build
pnpm --filter @aegis/web storybook      # design-system stories
```

See [`docs/dev/frontend.md`](docs/dev/frontend.md) for the design-
system + Storybook conventions.

## Run the test suite

```bash
pytest -q                                          # default 237 + 3 skipped
pytest -m "not slow"                                # excludes long-running
pytest -m "integration" tests/integration/         # integration suite (Postgres / Redis required)
AEGIS_E2E=1 AEGIS_DISABLE_LLM=1 pytest -q tests/e2e/   # deterministic E2E
```

Markers (defined in `pyproject.toml`):

| Marker            | What it gates                                                  |
|-------------------|----------------------------------------------------------------|
| `unit`            | Pure-Python; runs by default.                                  |
| `integration`     | May hit Postgres / Redis; runs by default but needs services.  |
| `docker`          | Needs Docker (gated to `workflow_dispatch` in CI).             |
| `e2e`             | Live stack; opt-in via `AEGIS_E2E=1`.                          |
| `slow`            | Long-running; excluded by default.                             |
| `auth_required`   | Needs Keycloak / cookie flow; skipped by default.              |

The Phase 2 offline path is sacred — every PR must keep
`pytest -q` green and pass the deterministic E2E run.

## Code style

- Python 3.12, type hints expected on public APIs.
- `ruff check aegis tests` — non-blocking but encouraged.
- Tests use `unittest`; fixtures via `unittest.mock`.
- Frontend: TypeScript strict mode; Tailwind via `cn()` from
  `@aegis/design-system`. No inline scripts (CSP).
- Don't add error handling for impossible cases — boundary code
  validates, internal code trusts framework guarantees.

## Pull request flow

1. Branch off `main`. Use `aegis/<topic>` for features;
   `aegis/fix/<finding_id>` is reserved for Aegis-generated fix PRs.
2. Write tests with the change. Don't ship behaviour without coverage.
3. Keep `pytest -q` green at every commit. Run the deterministic E2E
   if your change touches the demo path.
4. Update `CHANGELOG.md` under `## [Unreleased]` if your change is
   user-visible.
5. CI gates that must pass:
   - `pytest -q` on Python 3.12 + 3.13.
   - `uv lock --check` — no drift in `uv.lock`.
   - `pnpm install --frozen-lockfile` — no drift in
     `web/pnpm-lock.yaml`.
   - `pnpm --filter @aegis/web typecheck && build`.

## Service-layer contract (v0.3.1+)

From v0.3.1 F6 onward, **API write routes call admission services
only** (`services.scans.create_scan_job`,
`services.fixes.create_fix_job`, etc.) and **Celery tasks call
execution services only**. A grep gate fails any new
`add_route(..., methods=["POST"|"PUT"|"PATCH"|"DELETE"], ...)` whose
handler doesn't go through `aegis.services.*`. See
[`docs/architecture/overview.md`](docs/architecture/overview.md) §
"Layered service architecture."

Audit-before-enqueue is the load-bearing invariant:
`safety.authorize()` runs (and emits the chain row) **before** the
Run + Job DB rows are inserted and **before** Celery is touched. A
worker crash mid-enqueue must never produce a DB row without a
matching chain event.

## Submodule discipline

Every entry under `project_repos/` is pinned at a specific SHA in
[`project_repos/AEGIS_VENDORED.md`](project_repos/AEGIS_VENDORED.md).
Bumping a pointer is an explicit operation — see
[`docs/adr/0001-vendored-submodules.md`](docs/adr/0001-vendored-submodules.md)
for the full policy. CI verifies the pinned SHAs match what's
checked in.

## Security

Found a vulnerability in Aegis itself? See
[`SECURITY.md`](SECURITY.md). Do not file a public issue.

For changes to the auth / audit / cookie / CSRF / WS path, the PR
description should reference the relevant section of
[`docs/architecture/auth.md`](docs/architecture/auth.md) or
[`docs/architecture/audit-chain.md`](docs/architecture/audit-chain.md)
so reviewers can confirm the invariant the change preserves.

## Where to ask questions

- **Architecture / design** — open a discussion thread, or draft an
  ADR under `docs/adr/`.
- **Behaviour bug** — open an issue with a reproducer (or a failing
  test, even better).
- **Process / contributing** — this doc + the docs it links to.
