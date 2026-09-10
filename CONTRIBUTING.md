# Contributing to redsim

This guide covers the dev setup, the branch and merge rules, and the gates a
change has to pass. The README describes the product, and the pages under
`docs/` describe the architecture, the API and the operations.

## Dev setup

Python 3.12. The venv is created with uv and has no `pip` module, so install
with uv and run tools through the venv interpreter.

```bash
make install                                   # .venv, uv pip install -e ".[api,worker,test,dev,ml]", pnpm install
# or by hand
uv venv --python 3.12 .venv
uv pip install --native-tls -e ".[api,worker,test,dev,ml]"
pnpm install
```

`--native-tls` is needed behind a corporate TLS proxy. Extras: `api`,
`worker`, `test`, `dev`, `security`, `docs`, `ml` (torch, ART, SHAP, ONNX,
scikit-learn), `llm` (the optional private `pythia-sdk`) and `garak` (the LLM
probe domain, pinned `garak>=0.16,<0.17`). Never call `.venv/bin/pip`.

The web side is one pnpm 10 workspace rooted at the repo (`web/` and
`packages/design-system/`) with a single root `pnpm-lock.yaml`:

```bash
pnpm install --frozen-lockfile
pnpm --filter @redsim/web dev            # next dev -p 3000
pnpm --filter @redsim/web typecheck
pnpm --filter @redsim/web test           # vitest
pnpm --filter @redsim/web build
pnpm --filter @redsim/design-system typecheck
```

See [`docs/dev/local-stack.md`](docs/dev/local-stack.md) for the compose
stack and [`docs/dev/frontend.md`](docs/dev/frontend.md) for the design
system conventions.

## Branches and merges

- Branch off `main` for every change. Never commit to `main` directly.
- Branch names are `type/topic`, matching the commit prefix: `feat/ml-core`,
  `fix/worker-queue-routing`, `docs/refresh`.
- The repository allows squash merges only and deletes the branch on merge.
  Write the PR title as the squashed commit subject.
- Commits and PR titles are `type(topic): description` (`feat`, `fix`,
  `docs`, `test`, `ci`, `build`, `style`, `refactor`, `chore`).
- Prose in docs, commit bodies and comments avoids em dashes and semicolons.

## Run the test suite

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider                 # default tier: unit and sqlite-backed integration
.venv/bin/python -m pytest -q -p no:cacheprovider -m ml           # the tests that need the ml extra
.venv/bin/python -m pytest -q -p no:cacheprovider -m garak tests  # the LLM probe tier (needs the garak extra)
REDSIM_E2E=1 .venv/bin/python -m pytest -q -p no:cacheprovider -m e2e tests/e2e   # end to end: real API, worker, sandbox child, CLI
.venv/bin/python -m pytest -q --cov=redsim --cov-report=term | tail -5
```

The tiers are described in [`docs/dev/testing.md`](docs/dev/testing.md). From
a git worktree export `PYTHONPATH=<worktree>` before the e2e tier so the
sandbox child imports the tree under test.

Markers (defined in `pyproject.toml`):

| Marker | What it gates |
|---|---|
| `unit` | Pure Python. Runs by default. |
| `integration` | May hit Postgres or Redis. Runs by default on the sqlite harness in `tests/conftest.py`, against real services in CI. |
| `ml` | Needs the `ml` extra. Deselected on the Python 3.13 CI lane. Guard heavy imports with `pytest.importorskip` so collection survives without the extra. |
| `garak` | Needs the `garak` extra and is skipped without it. Runs in the `garak offline` CI job against an in-process fake gateway. |
| `e2e` | `tests/e2e/`: the real API, admission, eager Celery, the real sandbox child and the CLI over sqlite on a synthetic asset tree. Opt in with `REDSIM_E2E=1`. `REDSIM_E2E_POSTGRES_URL` (a migrated database) turns the row-level-security lane on. |
| `docker`, `slow`, `auth_required` | Opt in. Excluded by default. |

The default `pytest -q` must stay green with no services and no live LLM.
Nothing under `redsim/ml/` may be presented as working until it runs, and no
fixture (`TinyTarget`, the CIFAR-10 slice, the committed URL sample) may be
presented as a result.

## Code style

- `ruff check --select E4,E7,E9,F,I redsim tests` is the lint contract. A
  bare `ruff check` applies a much larger default set and is not the gate.
- `mypy redsim` runs strict and blocks merge, so new code is fully annotated.
- `make check` runs lint, typecheck and the default tier in one command.
- Frontend: TypeScript strict mode, Tailwind through `cn()` from
  `@redsim/design-system`, no inline scripts (CSP).
- Boundary code validates, internal code trusts framework guarantees. Do not
  add error handling for impossible cases.

## CI gates

`.github/workflows/redsim-ci.yml` runs on every PR and push to `main`. The
full description is [`docs/dev/ci.md`](docs/dev/ci.md).

- `Unit tests (py3.12)` and `(py3.13)`: ruff, mypy, then pytest without the
  `integration` tier. 3.12 installs the `ml` extra with CPU torch, 3.13
  deselects `ml`.
- `Coverage gate`: the full default suite against Postgres 16 and Redis 7
  with a coverage floor. Do not lower the floor without recording why in
  `docs/dev/ci.md`.
- `API integration (Postgres + Redis)`, `SAST (semgrep + bandit)`,
  `Dependency CVEs (pip-audit + trivy)`, `Helm chart lints + templates`,
  `OTel Collector config is valid`, `Secret scan (trufflehog)`,
  `redsim_output is not committed`.
- `E2E tier (python, eager Celery)`: the e2e tier against a migrated service
  Postgres, with the `garak` extra installed for the LLM probe cases.
- `garak offline`: the `garak` tier with no gateway variable in the
  environment. It fails when nothing was collected or no test passed.
- `Next.js build (pnpm, frozen lockfile)`: design-system and web typecheck,
  vitest, `next build`. When you change a `package.json`, regenerate the root
  `pnpm-lock.yaml` in the same commit.
- `Build images (no push)`: the `deploy/Dockerfile.*` images.
- `Docs` (`docs.yml`): `mkdocs build --strict`. Every page under `docs/`
  belongs in the `nav`.

`deploy-host.yml` deploys every push to `main` to the EC2 demo host over SSM.
It does not run the gates.

## Frozen contracts

These are shared contracts. Change them additively, with a default value, and
say so in the PR:

- every field name and type in `redsim/ml/schema.py`
  (`tests/ml/test_schema_compat.py` pins the frozen fixture and refuses a
  removed or retyped property),
- the migration head and the `ml_campaigns` column set,
- the `Action` values in `redsim/api/policy.py` and their minimum roles,
  mirrored in `deploy/opa/redsim-authz.rego` and
  `deploy/cedar/redsim-policy.cedar` (`tests/test_policy_ml_actions.py`
  asserts the three agree),
- the error codes in `redsim/api/errors.py` (`tests/ml/test_error_codes.py`
  is the table),
- the `GET /v1/runs/{id}/campaign` response shape in
  `tests/ml/fixtures/run_record.json`.

A schema change ships with its Alembic migration and its test update in the
same PR.

## Service-layer contract

API write routes call admission services only (`redsim/services/`), and
Celery tasks call execution services only. See
[`docs/architecture/overview.md`](docs/architecture/overview.md) under
"Layered service architecture".

Audit-before-enqueue is the load-bearing invariant: `safety.authorize()` runs
and emits the chain row before the `Run` and `Job` rows are inserted and
before Celery is touched. `tests/test_admission_audit_before_enqueue.py`
asserts the order.

Two more rules for the ML vertical:

- The API process never imports torch, ART, onnxruntime, SHAP, scikit-learn,
  garak, openai, litellm, reportlab, pyarrow or mlcroissant.
  `tests/test_api_process_has_no_ml.py` builds the app with those modules
  blocked. Model bytes, inference calls and dataset parsing happen only on
  the worker, inside the sandbox child, or in the worker parent for the
  endpoint predict broker.
- Measurements, observations, interpretation and candidate recommendations
  stay separate fields and separate panels. The `Literal` labels in
  `redsim/ml/schema.py` are part of the contract.

## Secrets

`.env` is gitignored and dockerignored. Never commit a credential, and never
add a real one to make a test pass. Some test fixtures carry deliberately fake
secrets for the redaction tests.

## Security

Found a vulnerability in redsim itself? See [`SECURITY.md`](SECURITY.md). Do
not file a public issue.

For changes to the auth, audit, cookie, CSRF or WebSocket path, the PR
description should reference the relevant section of
[`docs/architecture/auth.md`](docs/architecture/auth.md) or
[`docs/architecture/audit-chain.md`](docs/architecture/audit-chain.md) so
reviewers can confirm the invariant the change preserves.
