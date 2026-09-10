# CI pipeline

Every pull request and every push to `main` runs the workflows under
`.github/workflows/`. This page says what each job checks, why the gates are
set where they are and how to reproduce a failure locally. For the test
plumbing itself (fixtures, markers) see [Testing](testing.md), and for running
the stack and the e2e tier see [Local stack](local-stack.md).

## Workflows

| Workflow | File | Runs on |
|---|---|---|
| Redsim CI | `redsim-ci.yml` | every PR and push to `main`, plus `workflow_dispatch` (with an opt-in E2E toggle) |
| Docs | `docs.yml` | PRs and pushes that touch `docs/`, `mkdocs.yml`, `hooks/`, `pyproject.toml`, the root markdown files or the workflow itself. `mkdocs build --strict` only. The Pages deploy job is dormant behind the repo variable `ENABLE_PAGES` (Pages is off: the repository is private and the plan has no private Pages) |
| Release sign | `release-sign.yml` | `v*` tags only. Builds, pushes, cosign-signs and SBOM-attests the four images |
| Deploy to the EC2 host | `deploy-host.yml` | every push to `main`. One SSM command on the demo host runs `redsim-deploy`, which fast-forwards the checkout, reinstalls what the diff touched, restarts the units and requires `/health` 200. It runs none of the test gates. The host is described in [`deploy/ec2/README.md`](../../deploy/ec2/README.md) |

## Redsim CI jobs

| Job | What it checks | Python | Extras installed |
|---|---|---|---|
| Unit tests (py3.12) | ruff, mypy, then `pytest -q -m "not integration and not docker and not e2e and not slow and not auth_required and not garak"` | 3.12 | `api,worker,test,dev` plus `ml` (CPU torch first) |
| Unit tests (py3.13) | same, with `and not ml` appended to the marker expression | 3.13 | `api,worker,test,dev` |
| ML tier (py3.12, ml extra) | `pytest -q -p no:cacheprovider -m ml tests --durations=15`, offline (`HF_HUB_OFFLINE`, `HF_DATASETS_OFFLINE`, `REDSIM_DISABLE_LLM` set, no gateway variable). The CPU torch and torchvision wheels are restored from `actions/cache` keyed by the version `pip index versions` reads from the CPU index, downloaded only on a miss, and installed with `--no-index` from the cache directory. See "The ML tier job" | 3.12 | `api,worker,test,dev` plus `ml` (cached CPU torch) |
| Coverage gate | the full default suite (the `addopts` marker expression) against Postgres 16 and Redis 7 after `alembic upgrade head`, then `--cov-fail-under=$COV_FAIL_UNDER` | 3.12 | `api,worker,test,dev,ml` |
| API integration (Postgres + Redis) | `tests/` with `-m "not e2e and not docker and not slow and not auth_required and not ml and not garak"` after `alembic upgrade head` | 3.12 | `api,worker,test` |
| E2E tier (python, eager Celery) | `REDSIM_E2E=1 pytest -q -p no:cacheprovider -rs -m e2e tests/e2e` with `REDSIM_E2E_POSTGRES_URL` set after `alembic upgrade head`, so the Postgres RLS lane runs rather than skips. The step fails if the log still reports "Postgres lane is off". 30 minute timeout, the pytest `--basetemp` (the harness directory) uploaded as an artifact on failure. See "The Python e2e job" | 3.12 | `api,worker,test,dev,ml,garak` (the `garak` extra for the e2e-gated `tests/e2e/test_ml_llm.py`) |
| garak offline | `python -c "import garak"`, then `pytest -q -p no:cacheprovider -m garak tests`. The step fails on pytest exit code 5 (nothing collected) and on a run in which no test passed. No gateway variable in the environment, garak's XDG directories under the runner temp. See "The garak offline job" | 3.12 | `api,worker,test,dev,garak` (CPU torch first) |
| SAST (semgrep + bandit) | `p/python` + `p/security-audit` at ERROR plus `.semgrep.yml`, bandit `-ll -ii` with `.bandit` | 3.12 | `security` |
| Dependency CVEs (pip-audit + trivy) | pip-audit over the resolved `api,worker,security` env, trivy `fs` at HIGH,CRITICAL | 3.12 | `api,worker,security` |
| Helm chart lints + templates | `helm lint` and the `helm template` renders including the prod-secret guard | n/a | n/a |
| OTel Collector config is valid | pipeline references resolve, forward-looking components stay commented | 3.12 | pyyaml |
| Secret scan (trufflehog, verified only) | verified secrets in the tree | n/a | n/a |
| redsim_output is not committed | `git ls-files redsim_output` is empty | n/a | n/a |
| Next.js build (pnpm, frozen lockfile) | lint, typecheck design-system and web, vitest, `next build` | Node 20 | pnpm |
| Build images (no push) | the four `deploy/Dockerfile.*` build | n/a | n/a |
| Stack E2E (Playwright, fixture-assisted) | only via `workflow_dispatch` with `run_e2e=true`: compose up, Playwright against the web app with `REDSIM_E2E_STACK=1` and `REDSIM_DISABLE_LLM=1`, compose down | 3.12, Node 20 | `api,worker,test` |

API integration, the Python e2e tier, the garak lane, the Next.js build and
the image builds depend on the unit job, so a lint or type failure skips them.
The Playwright stack job depends on API integration and the web build and
runs on demand only.

### Test tiers and where they run

| Tier | Selected by | Runs in |
|---|---|---|
| unit and ML unit | default (`-m` from `addopts`), and `ml`-marked tests need the extra | both unit lanes (3.13 without `ml`), Coverage gate, and the `ml`-marked tests alone in the ML tier job |
| integration (sqlite harness locally, real Postgres and Redis in CI) | `integration` marker, stamped automatically on DB-touching tests | Coverage gate, API integration |
| e2e (Python) | `tests/e2e/`, marked `e2e` by its `conftest.py`, skipped unless `REDSIM_E2E` is set. The Postgres RLS lane needs `REDSIM_E2E_POSTGRES_URL` | E2E tier (python, eager Celery), on every PR and push, with the Postgres lane on. Locally as described in [Local stack](local-stack.md#tests-including-the-e2e-tier) |
| garak | `garak` marker: needs the `garak` extra, skipped when absent. Deselected by `addopts` and by every other lane's marker expression except `e2e-python`. The tests under `tests/ml` (`test_llm_core.py`, `test_llm_routes.py`) plus the e2e-gated cases of `tests/e2e/test_ml_llm.py`, real garak against an in-process fake gateway | garak offline (`tests/ml`), E2E tier (the e2e file) |
| browser e2e (Playwright) | `workflow_dispatch` with `run_e2e=true` | Stack E2E job, on demand only |

### The `ml` extra and the Python matrix

The ml stack (torch, torchvision, ART, SHAP, onnxruntime, onnx2torch,
scikit-learn) is installed and exercised on Python 3.12 only. It is the
interpreter the ml stack is validated on, and it keeps the 3.13 lane a fast
pure-platform check. The deploy images do not pin 3.12: `deploy/Dockerfile.api`
and `deploy/Dockerfile.worker` build on `python:3.14-slim`. CI installs
CPU-only torch first from `https://download.pytorch.org/whl/cpu`, exactly as
the worker Dockerfile does, so the extra resolves against it instead of
pulling the multi-GB CUDA wheels.

The 3.13 lane and the API integration job deselect the `ml` marker.
Deselection happens after collection, so an ML test module must still import
cleanly without the extra. Guard heavy imports with
`pytest.importorskip("torch")` at module top, or put the module under a
directory whose `conftest.py` skips when the extra is absent. A bare
`import torch` in a test module fails collection on 3.13 regardless of the
marker. The same applies to `mypy redsim` on the 3.13 lane: a function whose
return type is only known with torch or `truststore` installed needs an
explicit annotation.

The same rule holds for the order in which `redsim.ml` packages are imported.
Without the extra, the `ml`-marked modules skip at the top and never import
`redsim.ml.targets`, so the first ML import the 3.13 lane performs is whatever
the first un-marked module needs. The layering is one-way: `Sample` is defined
in `redsim.ml.datasets.sampling` and re-exported by `redsim.ml.targets.base`
and `redsim.ml.targets`, the datasets package imports nothing from the targets
package, and `tests/ml/test_import_order.py` imports the two packages in a
fresh interpreter with torch, ART, SHAP and scikit-learn blocked in three
orders (datasets first as on 3.13, `sampling` first, targets first) and fails
on the first cycle. Run that file after touching either package's imports.

### The Python e2e job

`E2E tier (python, eager Celery)` (job id `e2e-python`) runs `tests/e2e` on
every PR and push: a real FastAPI app, real admission, Celery in eager mode,
the real credential-free sandbox child, the CLI, all over a file-backed sqlite
of the harness's own. It installs `api,worker,test,dev` plus `ml` with CPU
torch first, exactly as the Coverage gate does, and the `garak` extra as well,
because `tests/e2e/test_ml_llm.py` is `garak`-marked and `tests/conftest.py`
would otherwise skip its cases at collection. It sets nothing else that the
harness does not set itself. No network, no Kaggle, no Docker: the harness
mocks the Pythia gateway in the worker parent and builds a tiny asset tree.

Postgres 16 and Redis 7 are attached as services, copied from the Coverage
gate. The harness scrubs `REDSIM_DB_URL` from the process, so Postgres serves
one purpose: the RLS lane. The job runs `alembic upgrade head` against the
service database and passes its URL as `REDSIM_E2E_POSTGRES_URL`, so the
`postgres_url` fixture returns it and the `-k postgres` items run instead of
skipping. That fixture fails, rather than skips, when the URL points at an
unmigrated database, which is why the migrate step comes first. The RLS test
provisions its own non-superuser role from the container's `redsim` superuser
(`tests/e2e/test_ml_governance.py`), matching this service. The step greps
the pytest log for the skip reason "Postgres lane is off" and fails when it
appears, so a lane that silently skipped can never read as a pass.

`--basetemp="$RUNNER_TEMP/redsim-e2e"` pins the pytest temp root, and with it
the harness directory (assets, sqlite file, blobs, sandbox work dirs, CLI
output), to a known path. On failure the job uploads that directory as the
`e2e-python-harness` artifact (7 days). `--durations=15` prints the slowest
items so a tier creeping towards the 30 minute job timeout is visible in the
log. `REDSIM_ML_KEEP_WORK_DIR` is not set: the harness scrubs it and keeps its
work directories under the harness root itself. The checkout in CI is the
tree the editable install points at, so no `PYTHONPATH` is needed there. From
a git worktree on a laptop, export `PYTHONPATH=<worktree>` first (see
`tests/e2e/README.md`).

Reproduce locally with the venv interpreter:

```bash
REDSIM_E2E=1 .venv/bin/python -m pytest -q -p no:cacheprovider -rs -m e2e tests/e2e --durations=15
# with the Postgres lane (a migrated database, see tests/e2e/README.md "Postgres lane")
REDSIM_DB_URL=postgresql+psycopg://redsim:redsim@localhost:5432/redsim_e2e .venv/bin/alembic upgrade head
REDSIM_E2E=1 REDSIM_E2E_POSTGRES_URL=postgresql+psycopg://redsim:redsim@localhost:5432/redsim_e2e \
  .venv/bin/python -m pytest -q -p no:cacheprovider -rs -m e2e tests/e2e
```

### The ML tier job

`ML tier (py3.12, ml extra)` (job id `ml-tier`) runs the `ml`-marked tests
alone: `pytest -q -p no:cacheprovider -m ml tests --durations=15`. The unit
py3.12 lane and the Coverage gate still run those tests inside the default
tier, so this job does not add coverage. It adds a check whose name fails only
on the ml stack. It has no dependency on the unit job, so it starts with it
and its result is visible even while a lint finding skips the downstream jobs.

The CPU torch wheels are cached. `pip index versions torch --index-url
https://download.pytorch.org/whl/cpu` reads the current version from the
index page without downloading a wheel, the cache key is
`ml-tier-<os>-py3.12-torch-<version>`, `pip download` fills the directory
only on a miss, and `pip install --no-index --find-links` installs torch and
torchvision from it before `.[ml]` resolves the rest against them. A second
run at the same torch version restores the directory and skips the download
step. When the index read fails the key falls back to a hash of
`pyproject.toml` so the job still runs, with a fresh download.

The job is offline by construction: `HF_HUB_OFFLINE=1`,
`HF_DATASETS_OFFLINE=1` and `REDSIM_DISABLE_LLM=1` are set and no
`PYTHIA_*` variable exists in the environment, so a test that reaches for a
hub, a dataset or a gateway fails loudly. Making the job a required status
check is a repository setting (`gh api -X PUT
repos/<owner>/<repo>/branches/main/protection` with
`ML tier (py3.12, ml extra)` in `required_status_checks.contexts`).

Reproduce locally with `.venv/bin/python -m pytest -q -p no:cacheprovider -m
ml tests`.

### The garak offline job

`garak offline` (job id `garak-offline`) is the lane for the LLM domain. It
installs `api,worker,test,dev` plus the `garak` extra, pinned to
`garak>=0.16,<0.17` in `pyproject.toml`, with CPU-only torch first because
garak pulls torch and transformers. It then imports garak and runs
`pytest -q -p no:cacheprovider -m garak tests`.

Two things about this lane are deliberate:

- **Nothing is claimed that is not there.** The lane collects the
  `garak`-marked tests under `tests/ml` (`test_llm_core.py`,
  `test_llm_routes.py`), which drive garak through `PythiaGenerator` against
  `tests/ml/fake_openai_server.py` on the loopback interface: the generator's
  headers and body, one real probe child run with its counts, the credential
  boundary, the scorecard, a version mismatch, the offline detector policy,
  the wall-clock kill, the committed catalog against a fresh regeneration, and
  the route-to-worker case. The step fails on pytest exit 5 (a marker or
  collection regression, never an empty tier) and on a run in which no test
  passed (every item skipped), so a missing extra cannot read as a pass.
- **Offline by construction.** The job exports no `PYTHIA_*` variable and no
  provider key (garak installs the openai and litellm clients, redsim
  configures neither, `tests/test_api_process_has_no_ml.py` blocks both in the
  API process, and `assert_no_litellm` checks the generator's MRO). A probe
  that reaches for a real gateway therefore fails loudly. The tests point
  the generator at the fake server with a low-entropy fake token.
  `XDG_DATA_HOME`, `XDG_CONFIG_HOME` and `XDG_CACHE_HOME` point under the
  runner temp so garak's run reports and plugin cache never land in the
  checkout. The probe child pins the same variables under its work directory
  itself. They are set on the two garak steps, not on the job: the `runner`
  context is not available in a job-level `env`, and a workflow that puts
  `${{ runner.temp }}` there fails at parse.

The `garak` marker means "needs the garak extra; skipped when absent".
`tests/conftest.py` enforces the second half: when `garak` is not importable,
every `garak`-marked item is skipped at collection, so `pytest -m garak` on an
interpreter without the extra reports skips, not errors. The default tier
deselects the marker through `addopts`, and every other lane's `-m`
expression restates `not garak`, so garak tests run only here and in the e2e
job. Reproduce locally, on a venv that has the extra, with:

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

The floor is **81%**, set as the local measurement minus 2, rounded down, so a
contributor without Postgres can still predict the CI result. The target is
**90** as the ML vertical settles: the owner of a merged phase raises
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
When an advisory appears, bump the pin in `pyproject.toml` if a fixed release
exists within the same major, otherwise add the ignore with a one-line
justification.

The ml extra is not part of the audited environment (the job stays lean and
the `+cpu` torch wheels have no PyPI advisory record). The release workflow's
Syft SBOM covers the shipped worker image.

`trivy fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed` scans the
whole checkout, which in practice means `pnpm-lock.yaml`. The trivy release is
pinned by `TRIVY_VERSION` in the workflow so a scanner behaviour change cannot
flip the gate on its own. Dependabot cannot bump a curl-installed binary, so
raise the pin by hand when a new release is out. `.trivyignore` carries the
documented baseline of Next.js 14 advisories whose fix is in a later major, and
they go away together with the Next upgrade owned by the web workstream.
`CVE-2026-75604` and its alias `GHSA-2xp9-vwfh-vxw4` (Next 14.2.35, fixed only
in 15.5.24 / 16.3.3) describe an unauthenticated RCE in the Image Optimization
API on windows-hosted servers. `deploy/Dockerfile.web` is a Linux container,
so the affected path is not reachable as deployed, and the entry says so. A
new Next.js advisory with a fix only in 15+ goes in the same block with the
same justification. Anything else needs its own reason or a pin bump.

### Dependabot

`.github/dependabot.yml` groups weekly updates per ecosystem: pip, npm
(`/web`), GitHub Actions and the Docker base images under `deploy/`. Treat a
Docker base-image bump as a runtime change, not a routine one: it moves the
interpreter the `ml` extra is validated on, and a Node base bump once broke
the web image until pnpm was installed explicitly.

## Docs build

`mkdocs build --strict` fails on any warning. Two hooks in `hooks/` keep it
green without editing content for the build:

- `readme_as_index.py` renders the root `README.md` as the site landing page
  and rewrites its `docs/` paths.
- `cross_tree_links.py` rewrites relative links that escape `docs/` (for
  example `../CONTRIBUTING.md`) to absolute GitHub URLs when the target exists
  in the repository. Links to files that exist nowhere are left alone and
  still fail strict mode, which is the point of strict mode.

Every page under `docs/` should appear in the `nav` in `mkdocs.yml`. A page
that exists but is not in the nav is only an INFO message, but readers cannot
find it. See [Editing the docs](docs.md).

## Reproduce locally

The dev venv lives at `.venv/` and was created with uv. It has no `pip`
module, so install with uv and run tools through the venv interpreter.
`mkdocs` needs the `docs` extra (`uv pip install --native-tls -e ".[docs]"`):

```bash
V=.venv/bin/python
$V -m ruff check --select E4,E7,E9,F,I redsim tests
$V -m mypy redsim
$V -m pytest -q --cov=redsim --cov-report=term | tail -5
REDSIM_E2E=1 $V -m pytest -q -p no:cacheprovider -rs -m e2e tests/e2e
$V -m pytest -q -p no:cacheprovider -m garak tests   # the garak-marked tests under tests/ml (needs the garak extra); REDSIM_E2E=1 adds those of tests/e2e/test_ml_llm.py
$V -m pytest -q -p no:cacheprovider tests/ml/test_schema_compat.py   # the schema tripwire
$V -m mkdocs build --strict
$V -m pytest -q -p no:cacheprovider -m ml tests   # the ML tier job
$V -c 'import yaml,sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]' .github/workflows/*.yml
```

`make check` runs the same gates in one command: ruff with the CI selection,
`mypy redsim`, the Python default tier, then the web typecheck and vitest.
It needs `pnpm install --frozen-lockfile` first. The YAML load above proves
only that the workflow parses as YAML. A GitHub expression error such as an
unavailable context is caught only by GitHub or by `actionlint`
(`docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:latest`).

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
