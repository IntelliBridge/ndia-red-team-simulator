# Testing

For the contributor workflow (how to install extras and what must stay green
on every PR), see
[`CONTRIBUTING.md`](https://github.com/IntelliBridge/ndia-red-team-simulator/blob/main/CONTRIBUTING.md)
§ "Run the test suite". This page documents the shared test plumbing.

## Shared fixtures (`tests/conftest.py`)

The top-level `tests/conftest.py` provides the fixtures most DB-touching tests
need, so individual tests stop hand-rolling an in-memory database:

- **`sqlite_session_factory`** — a session factory bound to a fresh in-memory
  SQLite engine with the schema created (a session-scoped, isolated database).
- **`db_session`** — a ready-to-use `Session` from that factory, rolled back
  and disposed at the end of the test for isolation between cases.

Use `db_session` for a single unit-style test that just needs a working
session; reach for `sqlite_session_factory` when a test needs to mint several
sessions itself.

## The `integration` marker

Markers are declared in `pyproject.toml` (the full table is in
`CONTRIBUTING.md`). The one to know here is **`integration`**: a test marked
`@pytest.mark.integration` may hit **Postgres / Redis**, so it needs those
services running. Pure-Python tests are `unit` and need nothing.

```python
import pytest


@pytest.mark.integration
def test_rls_blocks_cross_org_reads(...):
    ...  # needs a real Postgres (RLS / FORCE is a no-op on SQLite)
```

## CI unit-vs-integration split

CI runs the two tiers separately:

- The **Unit** job installs a minimal env (`pip install -e ".[test,dev]"` — no
  `api`/`worker` extras) and runs the default suite. Keeping it minimal is
  deliberate: it catches import-guard regressions and missing-extra failures
  that a full `.venv` would hide. Reproduce it in a throwaway venv before
  pushing if you touch import boundaries.
- The **integration** job stands up **Postgres + Redis** as services and runs
  `pytest -m "integration"` — this is where the RLS / `FORCE ROW LEVEL
  SECURITY` and tenant-integrity guards are actually exercised (they're no-ops
  on the SQLite path).

The Phase 2 offline path stays sacred: the default `pytest -q` must be green
with no services and no live LLM.
