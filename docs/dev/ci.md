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
| Deploy to AWS | `deploy-aws.yml` | pushes to `main` that touch runtime paths. Builds api, worker and web images for ECR under GitHub OIDC and rolls whichever `ECS_SERVICE_*` variables are set. It fails at "Configure AWS credentials" (the AssumeRole is refused account-side) and runs none of the test gates. Applying the Fargate deployment is excluded from this completion pass |

## Redsim CI jobs

| Job | What it checks | Python | Extras installed |
|---|---|---|---|
| Unit tests (py3.12) | ruff, mypy, then `pytest -q -m "not integration and not docker and not e2e and not slow and not auth_required"` | 3.12 | `api,worker,test,dev` plus `ml` (CPU torch first) |
| Unit tests (py3.13) | same, with `and not ml` appended to the marker expression | 3.13 | `api,worker,test,dev` |
| Coverage gate | the full default suite (the `addopts` marker expression) against Postgres 16 and Redis 7 after `alembic upgrade head`, then `--cov-fail-under=$COV_FAIL_UNDER` | 3.12 | `api,worker,test,dev,ml` |
| API integration (Postgres + Redis) | `tests/` with `-m "not e2e and not docker and not slow and not auth_required and not ml"` after `alembic upgrade head` | 3.12 | `api,worker,test` |
| SAST (semgrep + bandit) | `p/python` + `p/security-audit` at ERROR plus `.semgrep.yml`, bandit `-ll -ii` with `.bandit` | 3.12 | `security` |
| Dependency CVEs (pip-audit + trivy) | pip-audit over the resolved `api,worker,security` env, trivy `fs` at HIGH,CRITICAL | 3.12 | `api,worker,security` |
| Helm chart lints + templates | `helm lint` and the `helm template` renders including the prod-secret guard | n/a | n/a |
| OTel Collector config is valid | pipeline references resolve, forward-looking components stay commented | 3.12 | pyyaml |
| Secret scan (trufflehog, verified only) | verified secrets in the tree | n/a | n/a |
| redsim_output is not committed | `git ls-files redsim_output` is empty | n/a | n/a |
| Next.js build (pnpm, frozen lockfile) | typecheck design-system and web, vitest, `next build` | Node 20 | pnpm |
| Build images (no push) | the four `deploy/Dockerfile.*` build | n/a | n/a |
| Stack E2E (Playwright, fixture-assisted) | only via `workflow_dispatch` with `run_e2e=true`: compose up, Playwright against the web app with `REDSIM_E2E_STACK=1` and `REDSIM_DISABLE_LLM=1`, compose down | 3.12, Node 20 | `api,worker,test` |

API integration, the Next.js build and the image builds depend on the unit
job, so a lint or type failure skips them. The Playwright stack job depends on
API integration and the web build and is excluded from this completion pass
(it is never run automatically).

### Test tiers and where they run

| Tier | Selected by | Runs in |
|---|---|---|
| unit and ML unit | default (`-m` from `addopts`), and `ml`-marked tests need the extra | both unit lanes (3.13 without `ml`), Coverage gate |
| integration (sqlite harness locally, real Postgres and Redis in CI) | `integration` marker, stamped automatically on DB-touching tests | Coverage gate, API integration |
| e2e (wave 3, landing 2026-09-09) | `tests/e2e/`, marked `e2e` by its `conftest.py`, skipped unless `REDSIM_E2E` is set. The Postgres RLS lane needs `REDSIM_E2E_POSTGRES_URL` | not in any CI job yet. Run it locally as described in [Local stack](local-stack.md#tests-including-the-e2e-tier) |
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

## State of `main` at the time of writing (2026-09-09, after `58461cc`)

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

Local results from this tree with the venv interpreter (Python 3.12, `ml`
extra installed), 2026-09-09:

| Check | Result |
|---|---|
| `pytest -q -p no:cacheprovider tests/ml/test_import_order.py` | 4 passed (3 of 4 failed before the `Sample` move) |
| `pytest -q -p no:cacheprovider --ignore=tests/e2e` | 1680 passed, 30 skipped (92 s with the `ml` extra). An earlier run during the same pass had two failures in files another writer was editing concurrently (`tests/ml/test_campaign_routes.py`, `tests/test_plugin_marketplace.py`); both passed once those edits settled |
| `ruff check --select E4,E7,E9,F,I redsim tests` | clean |
| `mypy redsim` | clean (190 source files) |

`Docs` builds on every docs change and its Pages deploy stays off.
`Deploy to AWS` built and pushed the three images under OIDC on the `58461cc`
push and skips its deploy job while `ECS_CLUSTER` is unset. The CI state is recorded here as
of this commit. Re-run the workflow and update this section rather than
carrying the statement forward.

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
find it. As of this commit the gap register, the ops Pythia page and the three
workstream pages are in the nav.

## Reproduce locally

The dev venv lives at `.venv/` and was created with uv. It has no `pip`
module, so install with uv and run tools through the venv interpreter.
`mkdocs` needs the `docs` extra (`uv pip install --native-tls -e ".[docs]"`):

```bash
V=.venv/bin/python
$V -m ruff check --select E4,E7,E9,F,I redsim tests
$V -m mypy redsim
$V -m pytest -q --cov=redsim --cov-report=term | tail -5
$V -m mkdocs build --strict
$V -c 'import yaml,sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]' .github/workflows/*.yml
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
