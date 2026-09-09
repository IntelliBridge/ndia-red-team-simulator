# CI pipeline

Every pull request and every push to `main` runs the workflows under
`.github/workflows/`. This page says what each job checks, why the gates are
set where they are, how to reproduce a failure locally, and what the state of
CI was when the page was written. For the test plumbing itself (fixtures,
markers) see [Testing](testing.md), and for running the stack and the e2e tier see
[Local stack](local-stack.md).

## Workflows

| Workflow | File | Runs on |
|---|---|---|
| Redsim CI | `redsim-ci.yml` | every PR and push to `main`, plus `workflow_dispatch` (with an opt-in E2E toggle) |
| Docs | `docs.yml` | PRs and pushes that touch `docs/`, `mkdocs.yml`, `hooks/`, `pyproject.toml`, the root markdown files or the workflow itself. `mkdocs build --strict` only. The Pages deploy job is dormant behind the repo variable `ENABLE_PAGES` (Pages is off: the repository is private and the plan has no private Pages) |
| Release sign | `release-sign.yml` | `v*` tags only. Builds, pushes, cosign-signs and SBOM-attests the four images |
| Deploy to AWS | `deploy-aws.yml` | pushes to `main` that touch runtime paths. Builds api, worker and web images for ECR under GitHub OIDC and rolls whichever `ECS_SERVICE_*` variables are set. Since the `58461cc` push the AssumeRole step succeeds and the images are built and pushed; the deploy job is skipped while the repo variable `ECS_CLUSTER` is unset. It runs none of the test gates. The Fargate runtime itself is the remaining-work brief's package E (`docs/plans/10-remaining-work-brief.md`), not a Phase B wave |

## Redsim CI jobs

| Job | What it checks | Python | Extras installed |
|---|---|---|---|
| Unit tests (py3.12) | ruff, mypy, then `pytest -q -m "not integration and not docker and not e2e and not slow and not auth_required and not garak"` | 3.12 | `api,worker,test,dev` plus `ml` (CPU torch first) |
| Unit tests (py3.13) | same, with `and not ml` appended to the marker expression | 3.13 | `api,worker,test,dev` |
| Coverage gate | the full default suite (the `addopts` marker expression) against Postgres 16 and Redis 7 after `alembic upgrade head`, then `--cov-fail-under=$COV_FAIL_UNDER` | 3.12 | `api,worker,test,dev,ml` |
| API integration (Postgres + Redis) | `tests/` with `-m "not e2e and not docker and not slow and not auth_required and not ml and not garak"` after `alembic upgrade head` | 3.12 | `api,worker,test` |
| E2E tier (python, eager Celery) | `scripts/phase_b_gate.sh --only e2e` (the gate's e2e step: `REDSIM_E2E=1 pytest -q -p no:cacheprovider -rs -m e2e tests/e2e` with `REDSIM_E2E_POSTGRES_URL` set after `alembic upgrade head`, so the Postgres RLS lane runs rather than skips and the step fails if the harness still reports the lane off), then `scripts/phase_b_gate.sh --only docs-consistency` (`tests/test_docs_phase_b_consistency.py`). 30 minute timeout (wave B4; the tier grew by seven files), the pytest `--basetemp` (the harness directory) uploaded as an artifact on failure. See "The Python e2e job" and "Phase B gate" | 3.12 | `api,worker,test,dev,ml,garak` (the `garak` extra since wave B4, for the e2e-gated `tests/e2e/test_ml_llm.py`) |
| garak offline | `python -c "import garak"`, then `scripts/phase_b_gate.sh --only garak` (`pytest -q -p no:cacheprovider -m garak tests`; the lane collects the 12 `garak`-marked tests under `tests/ml`; since wave B4 the step fails on exit code 5, on a run in which no test passed and on a missing extra). No gateway variable in the environment, the script removes every `PYTHIA_*` variable on top, garak's XDG directories under the runner temp. See "The garak offline job" and "Phase B gate" | 3.12 | `api,worker,test,dev,garak` (CPU torch first) |
| SAST (semgrep + bandit) | `p/python` + `p/security-audit` at ERROR plus `.semgrep.yml`, bandit `-ll -ii` with `.bandit` | 3.12 | `security` |
| Dependency CVEs (pip-audit + trivy) | pip-audit over the resolved `api,worker,security` env, trivy `fs` at HIGH,CRITICAL | 3.12 | `api,worker,security` |
| Helm chart lints + templates | `helm lint` and the `helm template` renders including the prod-secret guard | n/a | n/a |
| OTel Collector config is valid | pipeline references resolve, forward-looking components stay commented | 3.12 | pyyaml |
| Secret scan (trufflehog, verified only) | verified secrets in the tree | n/a | n/a |
| redsim_output is not committed | `git ls-files redsim_output` is empty | n/a | n/a |
| Next.js build (pnpm, frozen lockfile) | typecheck design-system and web, vitest, `next build` | Node 20 | pnpm |
| Build images (no push) | the four `deploy/Dockerfile.*` build | n/a | n/a |
| Stack E2E (Playwright, fixture-assisted) | only via `workflow_dispatch` with `run_e2e=true`: compose up, Playwright against the web app with `REDSIM_E2E_STACK=1` and `REDSIM_DISABLE_LLM=1`, compose down | 3.12, Node 20 | `api,worker,test` |

API integration, the Python e2e tier, the garak lane, the Next.js build and
the image builds depend on the unit job, so a lint or type failure skips them.
The Playwright stack job depends on API integration and the web build and is
excluded from this completion pass (it is never run automatically).

### Test tiers and where they run

| Tier | Selected by | Runs in |
|---|---|---|
| unit and ML unit | default (`-m` from `addopts`), and `ml`-marked tests need the extra | both unit lanes (3.13 without `ml`), Coverage gate |
| integration (sqlite harness locally, real Postgres and Redis in CI) | `integration` marker, stamped automatically on DB-touching tests | Coverage gate, API integration |
| e2e (Python) | `tests/e2e/`, marked `e2e` by its `conftest.py`, skipped unless `REDSIM_E2E` is set. The Postgres RLS lane needs `REDSIM_E2E_POSTGRES_URL` | E2E tier (python, eager Celery), on every PR and push, with the Postgres lane on. Locally as described in [Local stack](local-stack.md#tests-including-the-e2e-tier) |
| garak (Phase B) | `garak` marker: needs the `garak` extra, skipped when absent. Deselected by `addopts` and by every other lane's marker expression except `e2e-python`. 12 tests under `tests/ml` (`test_llm_core.py`, `test_llm_routes.py`) plus the four e2e-gated cases of `tests/e2e/test_ml_llm.py`, real garak against an in-process fake gateway | garak offline (`tests/ml`), E2E tier (the e2e file) |
| browser e2e (Playwright) | `workflow_dispatch` with `run_e2e=true` | Stack E2E job, on demand only, excluded from this pass |

### The `ml` extra and the Python matrix

The ml stack (torch, torchvision, ART, SHAP, onnxruntime, onnx2torch,
scikit-learn) is installed and exercised on Python 3.12 only. It is the
interpreter the ml stack is validated on, and it keeps the 3.13 lane a fast
pure-platform check. The deploy images no longer pin 3.12: the dependabot
docker bump `ff24944` (#13) moved `deploy/Dockerfile.api` and
`deploy/Dockerfile.worker` to `python:3.14-slim`, and the image builds were
green on that base in the last green run (`ea39f97`). CI installs CPU-only
torch first from `https://download.pytorch.org/whl/cpu`, exactly as the
worker Dockerfile does, so the extra resolves against it instead of pulling
the multi-GB CUDA wheels.

The 3.13 lane and the API integration job deselect the `ml` marker.
Deselection happens after collection, so an ML test module must still import
cleanly without the extra. Guard heavy imports with
`pytest.importorskip("torch")` at module top, or put the module under a
directory whose `conftest.py` skips when the extra is absent. A bare
`import torch` in a test module fails collection on 3.13 regardless of the
marker. The same applies to `mypy redsim` on the 3.13 lane: a function whose
return type is only known with torch or `truststore` installed needs an
explicit annotation (`d4804d1` and `d5e0bc9` fixed two such cases in
`redsim/ml/datasets/image_hub.py` and `redsim/ml/assets/train_cnn.py`).

The same rule holds for the order in which `redsim.ml` packages are imported.
Without the extra, the `ml`-marked modules skip at the top and never import
`redsim.ml.targets`, so the first ML import the 3.13 lane performs is whatever
the first un-marked module needs: at `bb43bd7` that was
`redsim.ml.datasets.cifar10` (from `tests/ml/test_cifar10_fixture.py`), and
`redsim.ml.datasets.sampling` imported `Sample` from `redsim.ml.targets.base`,
which runs the targets package `__init__` (it registers every target) and
reaches back into the half-initialised `sampling` module. The layering is now
one-way: `Sample` is defined in `redsim.ml.datasets.sampling` and re-exported
by `redsim.ml.targets.base` and `redsim.ml.targets`, the datasets package
imports nothing from the targets package, and
`tests/ml/test_import_order.py` imports the two packages in a fresh
interpreter with torch, ART, SHAP and scikit-learn blocked in three orders
(datasets first as on 3.13, `sampling` first, targets first) and fails on the
first cycle. Run that file after touching either package's imports.

### The Python e2e job

`E2E tier (python, eager Celery)` (job id `e2e-python`, plan 12 wave B0,
TESTS_DOCS-04) runs `tests/e2e` on every PR and push. It is the completion
gate for every Phase A criterion and every Phase B path that the tier proves:
a real FastAPI app, real admission, Celery in eager mode, the real
credential-free sandbox child, the CLI, all over a file-backed sqlite of the
harness's own. It installs `api,worker,test,dev` plus `ml` with CPU torch
first, exactly as the Coverage gate does, and since wave B4 the `garak` extra
as well, because `tests/e2e/test_ml_llm.py` is `garak`-marked and
`tests/conftest.py` would otherwise skip its four cases at collection, so the
LLM probe evidence (register LLM-30) would run in no lane. It sets nothing
else that the harness does not set itself. No network, no Kaggle, no Docker: the harness
mocks the Pythia gateway in the worker parent and builds a tiny asset tree.

Postgres 16 and Redis 7 are attached as services, copied from the Coverage
gate. The harness scrubs `REDSIM_DB_URL` from the process, so Postgres serves
one purpose: the RLS lane. The job runs `alembic upgrade head` against the
service database and passes its URL as `REDSIM_E2E_POSTGRES_URL`, so the
`postgres_url` fixture returns it and the `-k postgres` items run instead of
skipping. That fixture fails, rather than skips, when the URL points at an
unmigrated database, which is why the migrate step comes first. The RLS test
provisions its own non-superuser role from the container's `redsim` superuser
(`tests/e2e/test_ml_governance.py`), matching this service.

`--basetemp="$RUNNER_TEMP/redsim-e2e"` pins the pytest temp root, and with it
the harness directory (assets, sqlite file, blobs, sandbox work dirs, CLI
output), to a known path. On failure the job uploads that directory as the
`e2e-python-harness` artifact (7 days). `--durations=15` prints the slowest
items so a tier creeping towards the 20 minute job timeout is visible in the
log. `REDSIM_ML_KEEP_WORK_DIR` is not set: the harness scrubs it and keeps its
work directories under the harness root itself. The job timeout is 30
minutes since wave B4 (the tier grew from four files to eleven). The
checkout in CI is the tree the editable install points at, so the
`PYTHONPATH` the gate sets for a git-worktree run is not needed there (the
script detects that and sets nothing).

Reproduce locally with the venv interpreter:

```bash
REDSIM_E2E=1 .venv/bin/python -m pytest -q -p no:cacheprovider -m e2e tests/e2e --durations=15
# with the Postgres lane (a migrated database, see tests/e2e/README.md "Postgres lane")
REDSIM_DB_URL=postgresql+psycopg://redsim:redsim@localhost:5432/redsim_e2e .venv/bin/alembic upgrade head
REDSIM_E2E=1 REDSIM_E2E_POSTGRES_URL=postgresql+psycopg://redsim:redsim@localhost:5432/redsim_e2e \
  .venv/bin/python -m pytest -q -p no:cacheprovider -m e2e tests/e2e
```

### The garak offline job

`garak offline` (job id `garak-offline`, plan 12 wave B0, TESTS_DOCS-02) is
the lane for the Phase B LLM domain. It installs `api,worker,test,dev` plus
the `garak` extra, pinned to `garak>=0.16,<0.17` in `pyproject.toml`, with
CPU-only torch first because garak pulls torch and transformers. It then
imports garak and runs `pytest -q -p no:cacheprovider -m garak tests`.

Two things about this lane are deliberate:

- **Nothing is claimed that is not there.** From wave B0 to wave B1 the step
  mapped a pytest exit code of 5 (no tests collected) to success with a
  `::notice::` line, because no garak test existed. Since wave B2 the lane
  collects 12 `garak`-marked tests (ten in `tests/ml/test_llm_core.py`, two
  in `tests/ml/test_llm_routes.py`) that drive garak 0.16.0 through
  `PythiaGenerator` against `tests/ml/fake_openai_server.py` on the loopback
  interface: the generator's headers and body, one real probe child run with
  its counts, the credential boundary, the scorecard, a version mismatch, the
  offline detector policy, the wall-clock kill, the committed catalog against
  a fresh regeneration, and the route-to-worker case. Since wave B4 the
  mapping is gone from the script and the workflow: the step fails on exit 5
  (a marker or collection regression, never an empty tier), on a run in which
  no test passed (every item skipped) and on a missing extra (checked with
  `find_spec` before pytest runs, so the extra's absence cannot read as a
  pass), and `tests/test_docs_phase_b_consistency.py` drives the step with a
  fake interpreter to prove each of those. The 12 passed locally at `703f8f6`
  (35 s with the extra installed); whether they pass on the runner is proven
  by a run after the B4 push, which has not been read.
- **Offline by construction.** The job exports no `PYTHIA_*` variable and no
  provider key (garak installs the openai and litellm clients, redsim
  configures neither, `tests/test_api_process_has_no_ml.py` blocks both in the
  API process, and `assert_no_litellm` checks the generator's MRO). A probe
  that reaches for a real gateway therefore fails loudly; the tests point
  the generator at the fake server with a low-entropy fake token.
  `XDG_DATA_HOME`, `XDG_CONFIG_HOME` and `XDG_CACHE_HOME` point under the
  runner temp so garak's run reports and plugin cache never land in the
  checkout; the probe child pins the same variables under its work directory
  itself.

The `garak` marker means "needs the garak extra; skipped when absent".
`tests/conftest.py` enforces the second half: when `garak` is not importable,
every `garak`-marked item is skipped at collection, so `pytest -m garak` on an
interpreter without the extra reports skips, not errors. The default tier
deselects the marker through `addopts`, and every other lane's `-m`
expression restates `not garak`, so garak tests run only here. Reproduce
locally, on a venv that has the extra, with:

```bash
XDG_DATA_HOME=$(mktemp -d) .venv/bin/python -m pytest -q -p no:cacheprovider -m garak tests
```

### Lint and type gates

`ruff check --select E4,E7,E9,F,I redsim tests`. The explicit `--select` is
deliberate. ruff 0.16 enables a much larger default rule set than the
E4/E7/E9/F default this tree was written against, and `pyproject.toml` only
declares `extend-select = ["I"]`. Without the explicit selection the same ruff
reports hundreds of findings (UP, BLE, SIM, RUF, B, S and friends) that were
never part of the contract. The durable fix is to pin `lint.select` in
`pyproject.toml` and drop the flag from the workflow. Run the same command
locally before pushing.

`mypy redsim` runs with the settings in `pyproject.toml`
(`disallow_untyped_defs`, `warn_return_any`, `warn_unused_ignores`,
`ignore_missing_imports`). Note that `warn_unused_ignores` together with
`ignore_missing_imports` makes a `# type: ignore[import-not-found]` on an
optional import an error, not a no-op.

### Coverage gate

`Coverage gate` runs the full default suite against real Postgres and Redis,
then applies `--cov-fail-under=$COV_FAIL_UNDER`. The value lives in the job
`env` block of `redsim-ci.yml`, in one place.

The floor is **81%**, set on 2026-09-08 after the pentest-domain removal and
the redsim rename as the local measurement minus 2, rounded down, so a
contributor without Postgres can still predict the CI result. The measurements
recorded when it was set (83% locally on SQLite, 86.26% in the Coverage gate
job on `main`) predate the ML PRs and the completion waves. The Coverage gate
job itself measured 89.09% on `bb43bd7` and 88.89% on `58461cc` (it printed
"Required test coverage of 81% reached" before failing on the 23 upload tests
described below, so the measurement stands even though the job was red). The
target is **90** as the ML vertical settles: the owner of a merged phase raises
`COV_FAIL_UNDER` to the new measured value minus 2 in the same PR. Do not lower
it again without recording the reason here.

Measure locally with:

```bash
.venv/bin/python -m pytest -q --cov=redsim --cov-report=term | tail -5
```

### Dependency CVEs

`pip-audit --skip-editable` audits the resolved `api,worker,security`
environment. `--skip-editable` drops the local editable `redsim-platform`
distribution, which has no PyPI advisory record. Advisory IDs with no fixed
release go in `.github/pip-audit-ignores.txt`, one per line with the reason.
The list was empty and the audit clean on 2026-09-08. When an advisory
appears, bump the pin in `pyproject.toml` if a fixed release exists within the
same major, otherwise add the ignore with a one-line justification.

The ml extra is not part of the audited environment (the job stays lean and
the `+cpu` torch wheels have no PyPI advisory record). The release workflow's
Syft SBOM covers the shipped worker image.

`trivy fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed` scans the
whole checkout, which in practice means `pnpm-lock.yaml`. The trivy release is
pinned by `TRIVY_VERSION` in the workflow so a scanner behaviour change cannot
flip the gate on its own. Dependabot cannot bump a curl-installed binary, so
raise the pin by hand when a new release is out. `.trivyignore` carries the
documented baseline of Next.js 14 advisories whose fix is in a later major, and
they go away together with the Next upgrade owned by the web workstream. The
baseline grew by one advisory on 2026-09-09: `CVE-2026-75604` and its alias
`GHSA-2xp9-vwfh-vxw4` (Next 14.2.35, fixed only in 15.5.24 / 16.3.3) describe an
unauthenticated RCE in the Image Optimization API on windows-hosted servers;
`deploy/Dockerfile.web` is a Linux container, so the affected path is not
reachable as deployed, and the entry says so. A new Next.js advisory with a
fix only in 15+ goes in the same block with the same justification; anything
else needs its own reason or a pin bump.

### Dependabot

`.github/dependabot.yml` groups weekly updates per ecosystem: pip, npm
(`/web`), GitHub Actions and the Docker base images under `deploy/`. Treat a
Docker base-image bump as a runtime change, not a routine one: it moves the
interpreter the `ml` extra is validated on, and the 2026-09-08 bump to
`node:26` broke the web image until #21 installed pnpm explicitly.

## Phase B gate

`make check-phase-b` runs `scripts/phase_b_gate.sh`, the Phase B definition of
done (plan 12 section 6, register row TESTS_DOCS-36). It runs the checks below
in order, stops at the first failure and prints the spec 26 criterion that step
is the evidence for, so a red gate says which completion criterion is not met
rather than which command exited non-zero. `make check` keeps its Phase A
meaning (lint, typecheck, test). The script needs the venv interpreter (`PY` or
`VENV`, default `.venv/bin/python`) with the `api`, `worker`, `test`, `dev`,
`ml` and `docs` extras, plus `garak` for a non-vacuous garak step.

| Step | Command | Spec 26 criterion | A failure means |
|---|---|---|---|
| `ruff` | `ruff check --select E4,E7,E9,F,I redsim tests` | 26.27 | the lint contract of the unit lanes is broken |
| `mypy` | `mypy redsim` | 26.27 | the type contract is broken |
| `unit` | `pytest -q -p no:cacheprovider --ignore=tests/e2e` | 26.27 | the default tier (unit and sqlite integration) is red |
| `ml` | `pytest -q -p no:cacheprovider -m ml tests/ml` | 26.27 | the `ml` tier is red |
| `garak` | `pytest -q -p no:cacheprovider -m garak tests` | 26.20 | a garak-marked test failed, nothing was collected (exit 5), no test passed (every item skipped) or the `garak` extra is not installed for `PY`; each is a `FAIL` naming 26.20, never a vacuous pass |
| `e2e` | `REDSIM_E2E=1 pytest -q -p no:cacheprovider -rs -m e2e tests/e2e` (with `PYTHONPATH=<checkout>` first when `PY` imports `redsim` from another tree, a git worktree) | 26.2 to 26.24 | a completion-criteria file under `tests/e2e` is red, or `REDSIM_E2E_POSTGRES_URL` is set and the harness still skipped its Postgres lane |
| `docs` | `mkdocs build --strict` (into a temporary site directory) | 26.11 | a broken link or reference in the docs |
| `docs-consistency` | `pytest -q -p no:cacheprovider tests/test_docs_phase_b_consistency.py` | 26.11, 26.24 | a document disagrees with the tree (see below) |
| `probes` | HTTP probes against `REDSIM_API_URL`, then `redsim audit verify --all` | 26.9, 26.17, 26.22, 26.24 | the running stack does not have Phase B built, or its audit chain does not verify |

`scripts/phase_b_gate.sh --list` prints the table, `--only <step>` runs one
step and `--help` prints the header. Steps `unit`, `ml`, `garak`, `e2e` and
`docs-consistency` run with `REDSIM_DB_URL`, the broker variables,
`REDSIM_API_URL`, `REDSIM_API_TOKEN` and every `PYTHIA_*` and LLM-model
variable removed from the environment, exactly as the CI lanes run them: the
tiers are offline by contract and a database or gateway variable left in a
developer shell must not change what they prove. `REDSIM_E2E_POSTGRES_URL` is
the one variable the e2e step passes through.

The e2e step is one pytest invocation. When `REDSIM_E2E_POSTGRES_URL` names a
migrated database the harness's `postgres_url` fixture turns the RLS lane on
inside that run, and the step fails if the `-rs` summary still carries the
"Postgres lane is off" skip reason. The step also resolves `redsim` from a
neutral directory first: when the editable install points at another
checkout (a git worktree) it prints a notice and runs pytest with
`PYTHONPATH=<this checkout>` first, so the sandbox child and the CLI
subprocess run the tree under test; from the main checkout nothing is set. Running the tier a second time with the
variable set would double a tier that is sized for a laptop, and pytest's `-k`
cannot select the lane (its tests are selected by a fixture, not a name), so
the tripwire on the skip reason is what proves the lane ran.

### The stack probes

The `probes` step runs only when `REDSIM_API_URL` and `REDSIM_API_TOKEN` are
both set. Without them the step prints `SKIPPED` and the final line reads
`PASS (partial)`, so a gate run without a stack never reads as the full
completion check. Against `make up`, export the API URL, a token the stack
accepts (`REDSIM_AUTH_MODE=dev` accepts `dev:<email>`, admin on project
`default`) and the stack's database URL:

```bash
export REDSIM_API_URL=http://localhost:8000
export REDSIM_API_TOKEN=dev:admin@example.com
export REDSIM_DB_URL=postgresql+psycopg://redsim:redsim@localhost:5432/redsim
make check-phase-b                       # or: scripts/phase_b_gate.sh --only probes
```

The probe program is the Python block between the `PHASE_B_PROBES` markers in
the script (standard library only). In order, stopping at the first failure:

| Probe | Holds when | Criterion |
|---|---|---|
| `capabilities` | `GET /v1/ml/capabilities` reports `modalities.text`, `modalities.detection`, `modalities.llm` and `endpoint_connector` with `status: available` | 26.24 |
| `attacks-text` | `GET /v1/attacks?modality=text` lists `word_substitution` | 26.24 |
| `endpoint-registration` | `POST /v1/models` with `{"source": "endpoint", "project_id": ...}` and no URL is refused with `422` (never `501`). The project is `REDSIM_API_PROJECT`, else the first project `GET /v1/projects` lists, else `default`; the token must be admin on it (`target.manage`) | 26.17, 26.24 |
| `report-pdf` | `GET /v1/runs/{id}/report.pdf` answers `200` with a body starting `%PDF-` for `REDSIM_API_RUN_ID`, else for the newest succeeded run that has a rendered PDF (`GET /v1/runs?limit=25`). A stack with no rendered PDF fails this probe: render one with `POST /v1/runs/{id}/report.render` first | 26.9, 26.24 |
| `integrations` | `GET /v1/integrations` shows `lattice` as `not_implemented` with a reason (D3, text only) | 26.24 |
| `audit-verify` | `redsim audit verify --all` exits 0 and verified at least one chain. `REDSIM_DB_URL` must be set: without it the CLI would read an empty local JSONL directory and exit 0 having verified nothing about the stack, so the step fails instead | 26.22 |

The probes are read-only with one exception: the endpoint probe's invalid body
is an audited refusal, so it leaves one `success=False` `model.register` row on
the project chain (spec 9.3 step 2). A `401` or `403` is reported as a token or
role problem, not as a missing route.

### What `tests/test_docs_phase_b_consistency.py` asserts

The file is the docs half of the gate and runs in the default tier as well
(its one app-building test carries `integration`, so the unit lanes skip it and
the Coverage gate, API integration and the e2e-python job's docs-consistency
step run it). Every failure is prefixed with the file that owns the fix in
square brackets, for example `[docs track: docs/api/v1.md] ...`:

- every `tests/...py` file named in the spec section 22 addendum and every
  test file `docs/dev/testing.md` names exists (26.11);
- every route in the Phase B table of `docs/api/v1.md` is mounted, compared
  with the app's OpenAPI document, and its status column says "landed"
  exactly when an admin member reaches a real handler rather than a wave B0
  `501 not_implemented` stub (26.24). The check calls each documented route
  on the real app over an in-memory sqlite seeded with one project, an
  available model, a succeeded run and a finding, with Celery's
  `Task.apply_async` replaced so no broker is needed;
- the README "Open items" section names the web UI, the owner decisions and
  the remaining-work brief (26.11);
- no page under `docs/`, nor `README.md`, `CLAUDE.md`, `SECURITY.md` or
  `CONTRIBUTING.md`, still describes PR #23 as open (it merged as `10650da`)
  or marks one of the four landed Phase B waves as not yet begun (26.11). The dated registers
  `docs/plans/09-*`, `10-*` and `11-*` quote those phrases as work items and
  are excluded, and the test says so;
- the mkdocs nav lists plans 10, 11 and 12;
- the gate is discriminating: the probe program, run against a fake HTTP layer
  whose Phase B routes still answer `501` for an allowed role (or fake a
  result, or serve a non-PDF as `report.pdf`, or list Lattice as available),
  fails on that probe, names the spec 26 criterion and stops there; the
  script parses and lists the nine steps in the order above; the Makefile
  target and the two CI jobs call the script.

### How CI uses the script

`e2e-python` runs `scripts/phase_b_gate.sh --only e2e` (with
`PHASE_B_PYTEST_ARGS` carrying `--durations=15` and the `--basetemp` the
artifact upload reads) and then `--only docs-consistency`; `garak-offline`
runs `--only garak`. `docs.yml` runs `mkdocs build --strict` on its own, the
unit lanes run ruff, mypy and the default tier, and the Coverage gate runs the
`ml`-marked tests, so every step of the gate except the stack probes runs in
CI on every push, and the local `make check-phase-b` runs the same commands.

### State at the wave B4 push (`703f8f6` plus wave B4, 2026-09-09)

Read from the B4 tree before this documentation pass; re-run and replace this
paragraph rather than carrying it forward. The wave B4 gate track measured the
gate in its worktree (`cb1e559` plus the B4 tracks): the docs-consistency
step failed on the five stale-docs facts it was written to catch (the Phase B
table saying "501 until built" on 20 rows, no spec 22 addendum, the README
open items, PR #23 described as open in nine places, the nav), the `capabilities` probe
failed against a stack built from that tree (`text`, `detection`, `llm` and
`endpoint_connector` still `not_implemented`), and `--only unit` carried 17
`tests/ml` seam failures. The fix pass closed the roster (`redsim/api/v1/ml_capabilities.py`
reads every Phase B block from the tree), the assembler added the nav rows,
and this documentation pass closed the docs facts:
`scripts/phase_b_gate.sh --only docs-consistency` passes on the B4 tree.

What the gate reports on the B4 tree now: `ruff` and `mypy` pass; `unit`
carries one stale pin (`tests/ml/test_audit_campaign.py:113`, the
`report.render` `formats` now include `pdf`); `ml` was 433 passed at
`703f8f6` and the B4 tree's count is the assembler's; `garak` passes with the
extra installed (12 passed, 4 skipped without `REDSIM_E2E`, 35 s) and fails
without it by design; `e2e` is not green: the B4 files fail by attribution on
the product defects listed in the README's open items (the unscaled endpoint
probe, no training slice exposed to the child, the worker-parent
consumed-slice call, `architecture_kwargs` for `state_dict` uploads) and two
report pins are stale (`tests/e2e/test_ml_verify_upload_reports.py`,
`tests/e2e/test_ml_review_reports.py`); `docs` passes; `probes` has not been
run against `make up` (brief package A). The CI runs for `29db42c`,
`1439f92`, `57da31f`, `703f8f6` and the B4 push have not been read.

## State of `main` at `1439f92` and the wave B3 push (2026-09-09)

Written together with the wave B3 push, which follows the B2 push below.
Facts, in order:

- Wave B3 (five track commits plus `fix: integrate Phase B wave B3 tracks`)
  was written in the worktree `wt/waveb3` on the B2 integration commit and
  rebased onto it. The B3 assembler's checks in that worktree (head
  `a780d88`, before the atlas-foundry and integration commits and the
  rebase): `ruff check --select E4,E7,E9,F,I redsim tests` clean, `mypy
  redsim` clean (253 source files), the six writers' test files together 140
  passed and 1 skipped, the rewritten `tests/ml/test_phase_b_stubs.py` 61
  passed, the e2e smoke file 8 passed through the real child. Final counts
  at the B3 integration on the rebased tree (the reconcile pass, run from the repository root): `ruff check --select E4,E7,E9,F,I redsim tests` clean, `mypy redsim` clean (253 source files), the default tier `pytest -q -p no:cacheprovider --ignore=tests/e2e` 2634 passed, 35 skipped, 13 deselected (the `test_campaign_golden` artifact pin now excludes the Phase B export slices, `test_cli_ml` pins the `l2` default `pgd`; the `test_campaign` harden-hook and `test_datasets` synonyms failures of the B2 tree are not present), the `ml` tier 433 passed and 1 skipped, the `garak` tier 12 passed, the `e2e` tier against the compose Postgres 22 passed, `mkdocs build --strict` exit 0. The Coverage gate and the `Unit tests (py3.12)` lane
  have nothing known-red to expect from this push.
- The wave B3 tests need `pyarrow` (ml extra) for the export and consume
  cases, which are `ml`-marked and skip on the 3.13 lane, and PyYAML (a core
  dependency) for the CLI matrix. No new extra was declared. The B3 task
  modules are registered through the Celery `include` list, so the
  `tests/test_worker_hardening.py` routed-set pin is unchanged.
- The Aikido pre-commit hook passed every B3 commit; the JWT-shaped fake
  token of `tests/ml/fake_foundry_server.py` is assembled from three segments
  at import so no JWT literal sits in the source. The trufflehog job scans
  verified secrets only and has nothing to find there.
- `mkdocs build --strict` passed for this documentation pass with the new
  `docs/interop.md` in the nav.
- The Redsim CI runs for `29db42c`, `1439f92`, `57da31f` and `703f8f6` had
  not been read when this page was written. Nothing is claimed green.

## State of `main` at `1439f92` and the wave B2 push (2026-09-09)

Written after the wave B1 push (`29db42c..1439f92`, twelve commits) and
together with the wave B2 push that follows it. Facts, in order:

- The wave B1 integration commit `1439f92` re-ran the tiers on the rebased
  tree, the last full run recorded on `main`: default tier
  `pytest -q -x -p no:cacheprovider --ignore=tests/e2e` 2257 passed, 35
  skipped, 1 deselected (2:03); `pytest -q -m ml tests/ml` 418 passed, 1
  skipped, 753 deselected (1:12); e2e with the Postgres lane at
  `localhost:5433` 22 passed (2:30); `ruff check --select E4,E7,E9,F,I redsim
  tests` clean; `mypy redsim` clean (220 source files); `mkdocs build
  --strict` exit 0. Two passes, the tree green before the push.
- Wave B2 was written in a worktree on `b404eb8`, a base that predates the B1
  integration commit, and rebased onto `1439f92`. Its assembler's checks in
  that worktree: ruff clean, `mypy redsim` clean (236 source files), the
  writers' ten test files 251 passed and 1 xfailed, the full default tier
  without `-x` 2431 passed, 36 skipped, 12 deselected, 1 xfailed and 17
  failed, the 17 verified present at the base in a scratch worktree
  (`tests/ml/test_endpoint_target.py` x10 on the broker defect the B1
  integration fixed, `test_campaign`, `test_campaign_golden`,
  `test_datasets`, `test_detection_modality` x2, `test_text_modality` x2) and
  none added by B2; one genuine B2 regression found and fixed in the
  integration commit (`redsim/llm/pricing.py`: litellm's import ran
  `dotenv.load_dotenv()` and seeded the process from the developer's `.env`,
  making `tests/ml/test_narrative.py` order-dependent). The B2 integration pass (`fix: integrate Phase B wave B2`, pushed with the B2 commits) re-ran every tier on the rebased tree from the venv: ruff (CI selection) and `mypy redsim` (236 files) clean, the default tier 2480 passed, 35 skipped, 13 deselected, the `ml` tier 420 passed, 1 skipped, the 12 `garak`-marked tests green against the fake gateway, the e2e tier 22 passed against Postgres with the sandbox child, `mkdocs build --strict` exit 0.
- The B2 integration commit moved the e2e pins that B2 made stale
  (`tests/e2e/test_ml_governance.py`: `report.pdf` is `404 report not yet
  rendered` and an endpoint body without a profile is `422
  auth_profile_required`; `tests/e2e/test_ml_verify_upload_reports.py::test_reports_sections_and_pdf_404`:
  the same `404`, and the projection's weights keys beside the record), so
  the `e2e-python` job has nothing known-red.
- The wave B2 tests need `reportlab` and `pillow` (worker extra) and `pypdf`
  (test extra), declared in `pyproject.toml` by B2; every lane installs
  `worker` and `test`, and `redsim/ml/pdf_fonts/` ships as package data.
- The Redsim CI runs for `29db42c` (the first with `e2e-python` and
  `garak-offline`) and `1439f92` (wave B1) had not been read when this page
  was written, and the B2 push had not happened. Nothing is claimed green.

## State of `main` at `29db42c` and the wave B1 push (2026-09-09)

Written after the wave B0 push (`git push origin redsim-implementation:main`,
`6cbb661..29db42c`) and together with the wave B1 push that follows it. Facts,
in order:

- Wave 4 landed on `main` before Phase B (`3dda572..e73dea0`, integration
  commit `e73dea0`) with the three CI fixes the previous section describes:
  `python-multipart` in the `api` extra, the `Sample` move that breaks the
  `datasets` / `targets` import cycle, the `.trivyignore` baseline for the
  `next` advisory, and the lazy torch imports behind `redsim ml build-assets`
  (`d8a9f15`). PR #23 (the Fargate runtime) merged as `10650da`, PR #24 and
  PR #25 (web) followed.
- Wave B0 (`934838e..29db42c`, seven track commits plus the integration
  commit) added the two jobs `e2e-python` and `garak-offline` to
  `redsim-ci.yml` (validated with PyYAML: 14 jobs) and `not garak` to every
  lane's marker expression. The `29db42c` push is therefore the first run of
  both jobs on `main`. **That run had not been read when this page was
  written**: whether the Postgres RLS lane of `e2e-python` passes on the
  service database, and whether `garak>=0.16,<0.17` resolves next to the
  platform extras on the runner, is proven by that run and by nothing on this
  page. The last run this documentation has read is `58461cc` (red on the
  three jobs below, all three causes fixed in wave 4). Nothing is claimed
  green.
- Local checks at `29db42c` with the venv interpreter (Python 3.12, `ml`
  extra), from the wave B0 integration: `ruff check --select E4,E7,E9,F,I
  redsim tests` clean, `mypy redsim` clean (197 source files), the default
  tier `pytest -q -p no:cacheprovider --ignore=tests/e2e` 2081 passed, 35
  skipped, 1 deselected (106 s), the e2e tier with the Postgres lane at
  `localhost:5433` 22 passed (136 s), `mkdocs build --strict` exit 0, the
  frozen fixture `tests/ml/fixtures/run_record.json` unchanged (sha256
  `e5266f18…` matching the tripwire pin). The Postgres-gated cases of
  `tests/test_migration_0011.py` and `tests/test_tenant_rls.py` skip without
  `REDSIM_DB_URL` and were not run locally; the Coverage gate is where they
  run.
- Wave B1 was written in an isolated worktree on `7706950` (before B0) and
  rebased onto `29db42c`. Its own checks before the rebase: ruff clean,
  `mypy redsim` clean (213 source files), the seven writers' test files 206
  passed, the default tier 1840 passed and 31 skipped (that worktree did not
  yet carry B0's tests). The B1 integration commit `1439f92` re-ran the tiers
  on the rebased tree; its counts are in the section above.

Reading order for the rest of this section: the `58461cc` history below is
kept because it explains why the three fixes exist.

## State of `main` at `58461cc` (2026-09-09, before wave 4 landed)

Redsim CI on `main` has been red on every push since `ea39f97` (the last
green run, before the ML PRs landed). Do not read this page as a claim of a
green pipeline: the fixes below are in the tree, and the next push to `main`
is what shows whether they hold. What the failed runs said, read from the job
logs of `bb43bd7` (run 34299574164) and `58461cc` (run 34307513075; the #23
merge `10650da`, run 34308071046, failed the same three jobs):

| Job | What was red | What changed in this tree |
|---|---|---|
| Coverage gate | 23 tests in `tests/ml/test_models_routes.py` and `tests/test_review22_models.py` failed with `AssertionError: The python-multipart library must be installed to use form parsing`: `POST /v1/models` with `source="upload"` reads a multipart form and no extra declared the parser. Coverage itself was 89.09% / 88.89%, above the 81% floor | `python-multipart>=0.0.9` is in the `api` extra in `pyproject.toml`. The Coverage gate, API integration and both unit lanes install `api`; `deploy/Dockerfile.api` installs `.[api,worker]`, so the image picks it up too |
| Unit tests (py3.13) at `bb43bd7` | collection `ImportError: cannot import name 'as_model_input' from partially initialized module 'redsim.ml.datasets.sampling'`: the datasets -> targets -> datasets import cycle described under "The `ml` extra and the Python matrix" | `Sample` moved to `redsim.ml.datasets.sampling`, re-exported unchanged from `redsim.ml.targets.base`; `tests/ml/test_import_order.py` reproduces the 3.13 import order in a fresh interpreter and fails on a cycle |
| Unit tests (py3.13) at `58461cc` | collection got past the cycle by luck of module order and ran 1090 tests; two failed: `tests/ml/test_cli_ml.py::test_build_options_come_from_args_and_the_cache_env` and `::test_bad_options_exit_2` raise `ModuleNotFoundError: No module named 'torch'` because `redsim/cli/ml.py` imports `redsim.ml.assets.build`, which imports `redsim.ml.assets.train_cnn` (`import torch` at module level) even to validate options | Fixed at integration: `redsim/ml/assets/build.py` imports `train_cnn`, `train_url_classifier` and `targets.architectures` inside the functions that train (alias resolution in `BuildOptions` tolerates a missing extra; canonical ids still validate), and `train_url_classifier.py` imports `classification_metrics` lazily. Verified by running the two tests with torch and the other ml libraries blocked in `sys.modules`: 2 passed |
| Dependency CVEs (pip-audit + trivy) | pip-audit clean; trivy reported CRITICAL `CVE-2026-75604` / `GHSA-2xp9-vwfh-vxw4` on `next 14.2.35` in `pnpm-lock.yaml`, fixed only in 15.5.24 / 16.3.3 | both IDs baselined in `.trivyignore` under the existing Next 14 -> 15 policy, with the windows-only reachability note (see "Dependency CVEs") |

API integration, the Next.js build and the image builds carry `needs: unit`, so
they were skipped on every one of these runs, not passed. They start running
as soon as both unit lanes are green (with the `test_cli_ml.py` fix above the
py3.13 lane has no known remaining failure). What to expect from them, measured from
this tree on 2026-09-09 rather than assumed:

- **API integration**: the job's selection (`-m "not e2e and not docker and not
  slow and not auth_required and not ml"`, no `ml` extra) run locally on the
  sqlite harness with torch, ART, SHAP and scikit-learn blocked failed only the
  same two `test_cli_ml.py` tests before the lazy-import fix above, and nothing
  else attributable to this tree. Postgres-specific behaviour is not covered by
  that local run.
- **Next.js build**: `pnpm --filter @redsim/design-system run typecheck` passes.
  Before the `#23` merge (`10650da`) `pnpm --filter @redsim/web typecheck` failed
  (`web/src/__fixtures__/typed.ts:6`, TS2352: the `campaign.json` fixture did not
  overlap the `Campaign` type) and `pnpm --filter @redsim/web test` failed 11 of
  274 tests in 3 files (the run page read `campaign.target.metadata.framework_versions`
  and the fixture's `target` had no `metadata`). `#23` fixed the fixture:
  measured after rebasing onto `8e3083a`, `typecheck` passes and `test` fails 1
  of 274 (`src/app/findings/[id]/page.test.tsx` "submits selected defense and
  editable params": the page only enables Verify when a candidate
  recommendation references the selected defense's `art_class` and passes the
  recommendation id as a fourth argument, while the test's `useDefenses` mock
  has no `art_class` and expects a three-argument call). Expect this job red
  on that one test until the test and page agree; `next build` was not reached.
- **Build images**: not run locally. The four Dockerfiles last built green at
  `ea39f97` on the same `python:3.14-slim` / `node:26` bases; the only new
  runtime dependency since then that the api image installs is
  `python-multipart`, a pure-Python wheel.

Local results from the wave 4 working tree with the venv interpreter
(Python 3.12, `ml` extra installed), 2026-09-09, before wave 4 was integrated
(the `29db42c` numbers above supersede them):

| Check | Result |
|---|---|
| `pytest -q -p no:cacheprovider tests/ml/test_import_order.py` | 4 passed (3 of 4 failed before the `Sample` move) |
| `pytest -q -p no:cacheprovider --ignore=tests/e2e` | 1680 passed, 30 skipped (92 s with the `ml` extra). An earlier run during the same pass had two failures in files another writer was editing concurrently (`tests/ml/test_campaign_routes.py`, `tests/test_plugin_marketplace.py`); both passed once those edits settled |
| `ruff check --select E4,E7,E9,F,I redsim tests` | clean |
| `mypy redsim` | clean (190 source files) |

`Docs` builds on every docs change and its Pages deploy stays off.
`Deploy to AWS` built and pushed the three images under OIDC on the `58461cc`
push and skips its deploy job while `ECS_CLUSTER` is unset. The CI state is
recorded here as of the commits named. Re-run the workflow and update this
section rather than carrying a statement forward.

## Docs build

`mkdocs build --strict` fails on any warning. Two hooks in `hooks/` keep it
green without editing content for the build:

- `readme_as_index.py` renders the root `README.md` as the site landing page
  and rewrites its `docs/` paths.
- `cross_tree_links.py` rewrites relative links that escape `docs/` (for
  example `../specs/README.md` from `project-brief.md`) to absolute GitHub
  URLs when the target exists in the repository. Links to files that exist
  nowhere are left alone and still fail strict mode, which is the point of
  strict mode.

Every page under `docs/` should appear in the `nav` in `mkdocs.yml`. A page
that exists but is not in the nav is only an INFO message, but readers cannot
find it. As of this commit the gap register, the ops Pythia page, the three
workstream pages, the remaining-work brief, the Phase B register and plan,
the endpoint predict contract page (`docs/api/endpoint-contract.md`) and the
wave B3 interoperability page (`docs/interop.md`) are in the nav.

## Reproduce locally

The dev venv lives at `.venv/` and was created with uv. It has no `pip`
module, so install with uv and run tools through the venv interpreter.
`mkdocs` needs the `docs` extra (`uv pip install --native-tls -e ".[docs]"`):

```bash
V=.venv/bin/python
$V -m ruff check --select E4,E7,E9,F,I redsim tests
$V -m mypy redsim
$V -m pytest -q --cov=redsim --cov-report=term | tail -5
REDSIM_E2E=1 $V -m pytest -q -p no:cacheprovider -m e2e tests/e2e
$V -m pytest -q -p no:cacheprovider -m garak tests   # the 12 garak-marked tests under tests/ml (needs the garak extra); REDSIM_E2E=1 adds the 4 of tests/e2e/test_ml_llm.py
$V -m pytest -q -p no:cacheprovider tests/ml/test_schema_compat.py   # the P0 schema tripwire
$V -m mkdocs build --strict
$V -c 'import yaml,sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]' .github/workflows/*.yml
make check-phase-b        # every step above in the gate's order, stopping at the first miss (see "Phase B gate")
```

To reproduce the Coverage gate or API integration job exactly, point
`REDSIM_DB_URL` at a migrated Postgres (the compose one from `make up` works,
after `alembic upgrade head`) and `REDSIM_BROKER_URL` at Redis before running
pytest. The sqlite harness is what the default invocation uses otherwise.

Behind a TLS-inspecting proxy, `uv` needs `--native-tls` and Python HTTP
clients need the system trust store through `truststore.inject_into_ssl()`
(the `truststore` package is installed in the venv). pip-audit can be run the
same way against a freeze:

```bash
uv pip freeze --python $V | grep -v redsim-platform > /tmp/freeze.txt
$V -c 'import sys,truststore; truststore.inject_into_ssl(); from pip_audit._cli import audit; sys.argv=["pip-audit","-r","/tmp/freeze.txt","--no-deps"]; audit()'
```
