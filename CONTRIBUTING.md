# Contributing to redsim

This guide covers the dev setup, the branch and merge rules, the gates a
change has to pass, and the spec-first workflow the team follows. The
authoritative product documents are listed in [`CLAUDE.md`](CLAUDE.md) and
the README.

## Dev setup

Python 3.12 only. The venv is created with uv and has no `pip` module, so
install with uv and run tools through the venv interpreter.

```bash
make install                                   # .venv, uv pip install -e ".[api,worker,test,dev,ml]", pnpm install
# or by hand
uv venv --python 3.12 .venv
uv pip install --native-tls -e ".[api,worker,test,dev,ml]"
pnpm install
```

`--native-tls` is required behind the corporate TLS proxy. Extras:
`api`, `worker`, `test`, `dev`, `security`, `docs`, `ml`, `llm` (optional
private `pythia-sdk`), `garak` (Phase B LLM domain, pinned `garak>=0.16,<0.17`,
installed by the `garak offline` CI lane and by nobody else yet). `pydantic>=2.7`
and `PyYAML` are the only base dependencies. Never call `.venv/bin/pip`, and do not install
packages into a venv that other agents or worktrees share.

The web side is one pnpm 10 workspace rooted at the repo (`web/` and
`packages/design-system/`), with a single root `pnpm-lock.yaml`:

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
  `fix/worker-queue-routing`, `docs/refresh`, `ci/aws-deploy`. Dependabot
  and agent branches keep their own prefixes.
- The repository allows **squash merges only** and deletes the branch on
  merge. Rebase and merge commits are disabled. Write the PR title as the
  squashed commit subject.
- Commits and PR titles are `type(topic): description` (`feat`, `fix`,
  `docs`, `test`, `ci`, `build`, `style`, `refactor`, `chore`). Every commit
  ends with the trailer
  `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Git worktrees are the normal way to work on several branches at once. Stay
  inside your ownership list when other writers edit the same worktree.
- Prose in docs, commit bodies and comments avoids em dashes and semicolons.

## Run the test suite

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider                 # default tier: 2081 passed, 35 skipped, 1 deselected at main 29db42c (106 s with the ml extra)
.venv/bin/python -m pytest -q -p no:cacheprovider -m ml           # only the tests that need the ml extra
.venv/bin/python -m pytest -q -p no:cacheprovider -m integration  # sqlite-backed integration tests
REDSIM_E2E=1 .venv/bin/python -m pytest -q -p no:cacheprovider -m e2e tests/e2e   # 22 passed at 29db42c (136 s)
.venv/bin/python -m pytest -q -p no:cacheprovider -m garak tests  # exit 5 (nothing collected) until a garak-marked test exists
.venv/bin/python -m pytest -q --cov=redsim --cov-report=term | tail -5
```

The counts are the wave B0 integration run at `29db42c` (2026-09-09), local,
not CI; they move with every wave, so re-run before quoting them. The four
tiers (default, `ml`, `e2e`, `garak`) are described in
[`docs/dev/testing.md`](docs/dev/testing.md).

Markers (defined in `pyproject.toml`):

| Marker | What it gates |
|---|---|
| `unit` | Pure-Python. Runs by default. |
| `integration` | May hit Postgres / Redis. Runs by default on the sqlite harness in `tests/conftest.py`, runs against real services in CI. |
| `ml` | Needs the `ml` extra (torch, ART, SHAP). Deselected on the Python 3.13 CI lane. Guard heavy imports with `pytest.importorskip` so collection survives without the extra. |
| `docker` | Needs Docker. Opt-in. |
| `e2e` | `tests/e2e/`: the real API, admission, eager Celery, the real sandbox child and the CLI over sqlite on a synthetic asset tree. Opt-in via `REDSIM_E2E=1`; `REDSIM_E2E_POSTGRES_URL` (a migrated database) turns the RLS lane on. Runs in CI on every PR since wave B0 (`E2E tier (python, eager Celery)`). |
| `garak` | Needs the `garak` extra; skipped when absent (wave B0). Deselected by `addopts` and by every other lane, so `garak`-marked tests run only in the `garak offline` job. Stamp it, and `importorskip("garak")`, on every test that imports garak. |
| `slow` | Long-running. Excluded by default. |
| `auth_required` | Needs the Keycloak cookie flow. Skipped by default. |

The default `pytest -q` must stay green with no services and no live LLM.
Nothing under `redsim/ml/` may be presented as working until it runs, and no
fixture (`TinyTarget`, the CIFAR-10 slice, the committed URL sample) may be
presented as a result.

## Code style

- `ruff check --select E4,E7,E9,F,I redsim tests`. That explicit selection
  is the CI gate. `pyproject.toml` only declares `extend-select = ["I"]`, and
  a bare `ruff check` applies ruff 0.16's much larger default set, which is
  not the contract.
- `mypy redsim` runs strict (`disallow_untyped_defs`,
  `disallow_incomplete_defs`, `warn_return_any`, `warn_unused_ignores`) and
  blocks merge, so new code is fully annotated. Note that
  `warn_unused_ignores` together with `ignore_missing_imports` makes a
  `# type: ignore[import-not-found]` on an optional import an error.
- Run the local gate before pushing: `make check` (lint, typecheck, test),
  or `make typecheck` while iterating. `make lint-web` prints a skip line
  while `web/` has no ESLint config.
- Frontend: TypeScript strict mode, Tailwind via `cn()` from
  `@redsim/design-system`, no inline scripts (CSP).
- Boundary code validates, internal code trusts framework guarantees. Do not
  add error handling for impossible cases.

## CI gates

`.github/workflows/redsim-ci.yml` runs on every PR and push to `main`. The
full description is [`docs/dev/ci.md`](docs/dev/ci.md).

- `Unit tests (py3.12)` and `(py3.13)`: ruff (CI selection), mypy, then
  pytest without the `integration` tier. 3.12 installs the `ml` extra with
  CPU torch, 3.13 deselects `ml`.
- `Coverage gate`: the full default suite against Postgres 16 and Redis 7
  with `--cov-fail-under=81`. The floor is the local measurement minus 2.
  Raise it in the PR that merges each ML phase. Do not lower it without
  recording the reason in `docs/dev/ci.md`.
- `API integration (Postgres + Redis)`, `SAST (semgrep + bandit)`,
  `Dependency CVEs (pip-audit + trivy)`, `Helm chart lints + templates`,
  `OTel Collector config is valid`, `Secret scan (trufflehog)`,
  `redsim_output is not committed`.
- `E2E tier (python, eager Celery)` (job `e2e-python`, wave B0 of the Phase B
  plan): `REDSIM_E2E=1 pytest -m e2e tests/e2e` against a migrated service
  Postgres so the RLS lane runs, 20 minute timeout, harness directory
  uploaded on failure.
- `garak offline` (job `garak-offline`, wave B0): installs the `garak` extra
  on CPU torch, imports garak, runs `pytest -m garak tests` with no gateway
  variable in the environment. Exit 5 (nothing collected) counts as success
  until the LLM tracks land their `garak`-marked tests; any other non-zero
  exit fails the job.
- `Next.js build (pnpm, frozen lockfile)`: `pnpm install --frozen-lockfile`,
  design-system and web typecheck, vitest, `next build`. When you change a
  `package.json`, regenerate the root `pnpm-lock.yaml` in the same commit.
- `Build images (no push)`: the four `deploy/Dockerfile.*`.
- `Docs` (`docs.yml`): `mkdocs build --strict` when docs, the root markdown
  files, `mkdocs.yml`, `hooks/` or `pyproject.toml` change. Every page under
  `docs/` belongs in the `nav`. GitHub Pages publishing is off.

`deploy-aws.yml` builds images under GitHub OIDC and rolls ECS services. It
does not run the gates. Since the `58461cc` push the AssumeRole step succeeds
and the three images are built and pushed; the deploy job is skipped while the
repo variable `ECS_CLUSTER` is unset.

## Spec-first workflow

Every change traces to the product spec or a feature file. The process is
[`docs/spec-driven-workflow.md`](docs/spec-driven-workflow.md), the feature
layer is [`specs/README.md`](specs/README.md) (F001 to F008 with `spec.md`,
`plan.md`, `tasks.md`) and the readiness checklist in `specs/_shared/`. Where
a feature file and the product spec conflict, the product spec wins. A
changed requirement updates the spec before implementation continues.

Workstream ownership and status are in
[`docs/plans/00-master-plan.md`](docs/plans/00-master-plan.md) section 4.
Start work on a workstream only when its gate in section 7 is open.

## Changing what P0 froze

Milestone M0 (plan P0, PR #18) froze the shared contracts so parallel
workstreams cannot break each other. Treat these as locked:

- every field name and type in `redsim/ml/schema.py`, old and new
  (`CampaignConfig`, `MRIRecord`, `MLModelManifest` and `MLFindingDetail`
  are the shared contracts),
- the migration head and the `ml_campaigns` column set. The head moved once
  under the protocol, from `0010_ml_vertical` to `0011_phase_b_platform`
  (wave B0 of the Phase B plan, additive, announced in master plan section 5;
  `ml_campaigns` gained only the nullable `batch_id`),
- the `Action` values in `redsim/api/policy.py` and their minimum roles, and
  the `viewer` rank,
- the `GET /v1/runs/{id}/campaign` response shape encoded by
  `tests/ml/fixtures/run_record.json`,
- the environment variable name `REDSIM_ML_LLM_MODEL`.

The change protocol (section 8 of
[`docs/plans/01-p0-contracts-api-skeleton.md`](docs/plans/01-p0-contracts-api-skeleton.md)):

1. Do not rename a schema field, a column, an `Action` value or a response
   key silently.
2. Announce any change as a one-line note in master plan section 5, plus a
   heads-up to the team.
3. Prefer an additive, default-valued field over a change to an existing
   one. Additive fields do not break a parallel slice, renames and type
   changes do.

A schema change ships with its Alembic migration, its test update and the
master-plan note in the same PR.

Wave B0 of [`docs/plans/12-phase-b-plan.md`](docs/plans/12-phase-b-plan.md)
exercised the protocol once (2026-09-09): every Phase B field of its section 3
landed in `redsim/ml/schema.py` additive and default-valued, announced in
master plan sections 0 and 5, with the frozen fixture validating
byte-identical. `tests/ml/test_schema_compat.py` is the tripwire that keeps it
so: it pins the fixture's sha256, requires every property added since P0 to
have a default, and refuses a removed or retyped P0 property or a narrowed
vocabulary. Any further change to `redsim/ml/schema.py` has to keep that test
green, and the docs writer for the wave records it in master plan section 0.

## Service-layer contract

API write routes call admission services only (`services.scans`,
`services.verify`, `services.targets`, `services.auth_profiles`,
`services.ml_models`, `services.ml_campaigns`, `services.ml_findings`, and
in Phase B waves B2 and B3 the planned `services.ml_llm`,
`services.finding_review`, `services.ml_batches`, `services.ml_datasets`,
`services.ml_capacity`), and Celery tasks call execution services only. The
Phase B routes that wave B0 mounted are `501 not_implemented` stubs that call
no service and write nothing until their wave replaces them. See
[`docs/architecture/overview.md`](docs/architecture/overview.md) under
"Layered service architecture".

Audit-before-enqueue is the load-bearing invariant: `safety.authorize()` runs
and emits the chain row **before** the `Run` and `Job` rows are inserted and
**before** Celery is touched. `tests/test_admission_audit_before_enqueue.py`
asserts the order. A worker crash mid-enqueue must never produce a DB row
without a matching chain event.

Two more rules for the ML vertical:

- The API process never imports torch, ART, onnxruntime, SHAP, scikit-learn,
  garak, openai, litellm, reportlab, pyarrow or mlcroissant.
  `tests/test_api_process_has_no_ml.py` builds the app with those modules
  blocked. Model bytes, inference calls and dataset parsing happen only on the
  worker: inside the sandbox child, or in the worker parent for the endpoint
  predict broker, which is the only outbound HTTP of the vertical.
- Measurements, observations, interpretation and candidate recommendations
  stay separate fields and separate panels. The `Literal` labels in
  `redsim/ml/schema.py` are part of the contract.

## Pre-commit hook (Aikido)

`git config core.hooksPath` points at `~/.git-hooks`, whose `pre-commit` runs
the Aikido secret scanner. Some restored test fixtures carry deliberately fake
secrets and trip it. Use `AIKIDO_SKIP_PRE_COMMIT=1` only for commits that touch
those fixtures, say so in the commit message, and never add a real credential
to make a test pass. `.env` is gitignored and dockerignored.

## Security

Found a vulnerability in redsim itself? See [`SECURITY.md`](SECURITY.md). Do
not file a public issue.

For changes to the auth, audit, cookie, CSRF or WebSocket path, the PR
description should reference the relevant section of
[`docs/architecture/auth.md`](docs/architecture/auth.md) or
[`docs/architecture/audit-chain.md`](docs/architecture/audit-chain.md) so
reviewers can confirm the invariant the change preserves. For changes to
model loading, the sandbox or the upload path, reference section 9 of the
product spec.

## Where to ask questions

- Architecture or design: open a discussion thread, or draft an ADR under
  `docs/adr/`.
- Behaviour bug: open an issue with a reproducer (or a failing test, even
  better).
- Process: this doc and the docs it links to.
