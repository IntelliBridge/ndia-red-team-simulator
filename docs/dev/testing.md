# Testing

For the contributor workflow (how to install extras and what must stay green
on every PR), see
[`CONTRIBUTING.md`](https://github.com/IntelliBridge/ndia-red-team-simulator/blob/main/CONTRIBUTING.md)
under "Run the test suite". This page documents the shared test plumbing and
the CI split. The test plan for the ML vertical is section 22 of the
[product spec](../superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md).

## Running

```bash
.venv/bin/python -m pytest -q                              # 900 passed, 30 skipped on main 4320740, about 19 s
.venv/bin/python -m pytest -q -m ml                        # only the ml-marked tests
.venv/bin/python -m pytest -q --cov=redsim --cov-report=term | tail -5
```

The venv was created with uv and has no `pip`, so always run through
`.venv/bin/python -m …`. The default `-m` from `addopts` in `pyproject.toml`
excludes `docker`, `e2e`, `slow` and `auth_required`.

## Shared fixtures (`tests/conftest.py`)

- **`sqlite_session_factory`**: a session factory bound to a fresh in-memory
  SQLite engine with the schema created.
- **`db_session`**: a ready-to-use `Session` from that factory, rolled back
  and disposed at the end of the test.

Use `db_session` for a single test that needs a working session, reach for
`sqlite_session_factory` when a test needs to mint several sessions itself.
`tests/conftest.py` stamps DB-touching tests with the `integration` marker so
CI can route them to the Postgres-equipped jobs.

## Markers

| Marker | What it gates |
|---|---|
| `unit` | Pure-Python. Runs everywhere. |
| `integration` | May hit Postgres / Redis. Runs on the sqlite harness locally, against real services in the `Coverage gate` and `API integration` jobs. RLS, `FORCE ROW LEVEL SECURITY` and the tenant-drift guards are no-ops on SQLite, so those guarantees are only exercised in CI. |
| `ml` | Needs the `ml` extra (torch, ART, SHAP, onnxruntime). Deselected on the Python 3.13 lane and in the API integration job. |
| `docker`, `e2e`, `slow`, `auth_required` | Opt-in. |

Deselection happens after collection, so an `ml` test module must still
import cleanly without the extra. Put `pytest.importorskip("torch")` at module
top, or place the module under a directory whose `conftest.py` skips when the
extra is absent. A bare `import torch` in a test module fails collection on
3.13 regardless of the marker.

## ML test doubles and fixtures (`tests/ml/`)

- `fakes.py::TinyTarget`: a random-weight 1-conv net on 8×8×3 inputs with
  three synthetic classes. Exercises the `Target` and `AttackAdapter`
  protocols with no download.
- `fixtures/run_record.json`: the frozen `GET /v1/runs/{id}/campaign` shape
  with a full `score` block. `test_fixture.py` validates it against the
  schema, and any P0 contract change has to update it through the change
  protocol in `docs/plans/01`, section 8.
- `test_schema.py` and `test_cli_ml.py` pin the frozen schema and the
  `redsim ml build-assets` skeleton (`not_implemented`, writes nothing).
- Planned with the ML PRs: a committed stratified sample of the malicious-URLs
  dataset (`fixtures/malicious_urls_sample.csv`) and a pinned CIFAR-10 slice
  as CI fixtures. Fixture data never appears in the demo catalog or as a
  result.

## Guard tests worth knowing

- `test_api_process_has_no_ml.py`: builds the app in a subprocess with
  `torch`, `torchvision`, `art`, `onnx`, `onnxruntime`, `shap`, `sklearn` and
  `xgboost` blocked in `sys.modules`, serves `/health`, and asserts
  `POST /v1/scans` answers 404.
- `test_admission_audit_before_enqueue.py`: the chain row exists before the
  `Run` and `Job` rows and before Celery.
- `test_migration_0010.py`: `0010_ml_vertical` is the single head above
  `0009` and applies and reverses cleanly.
- `test_policy_ml_actions.py`: the seven ML `Action` members, their minimum
  roles and the `viewer` rank.
- `test_llm_pythia.py` and `test_pythia_check.py`: the Pythia client and the
  connectivity check against an `httpx.MockTransport`, including `.env`
  discovery isolated from a developer's real `.env`.
- The engine-unavailable paths (`test_cli_commands_coverage.py`,
  `test_m6_dispatch.py`, `test_api_routes_coverage.py`, `test_doctor.py`) pin
  the explicit failure of the removed pentest seams, so a faked empty result
  fails the suite.

## CI split

The full description is [CI pipeline](ci.md).

- `Unit tests (py3.12)` and `(py3.13)`: install `.[api,worker,test,dev]`
  (plus `ml` with CPU torch on 3.12), run ruff and mypy, then pytest with
  `not integration and not docker and not e2e and not slow and not
  auth_required` (3.13 adds `and not ml`). No Postgres or Redis.
- `Coverage gate`: the full default suite against Postgres 16 and Redis 7,
  `alembic upgrade head` first, `--cov-fail-under=81`.
- `API integration (Postgres + Redis)`: `.[api,worker,test]`, migrations,
  then `pytest -m "not e2e and not docker and not slow and not auth_required
  and not ml" tests/`.
- `Stack E2E (Playwright)`: only via `workflow_dispatch` with `run_e2e=true`,
  brings the compose stack up and runs `web/tests`.

The default `pytest -q` stays green with no services and no live LLM.
