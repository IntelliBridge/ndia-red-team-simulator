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
scikit-learn) is installed and exercised on Python 3.12 only. That is the
interpreter the deploy images pin (`deploy/Dockerfile.api`,
`deploy/Dockerfile.worker`), and it keeps the 3.13 lane a fast pure-platform
check. CI installs CPU-only torch first from
`https://download.pytorch.org/whl/cpu`, exactly as the worker Dockerfile does,
so the extra resolves against it instead of pulling the multi-GB CUDA wheels.

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
job on `main`) predate the ML PRs and the completion waves and have not been
re-measured on `bb43bd7`, so measure before quoting. The target is **90** as the
ML vertical settles: the owner of a merged phase raises `COV_FAIL_UNDER` to
the new measured value minus 2 in the same PR. Do not lower it again without
recording the reason here.

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
they go away together with the Next upgrade owned by the web workstream.

### Dependabot

`.github/dependabot.yml` groups weekly updates per ecosystem: pip, npm
(`/web`), GitHub Actions and the Docker base images under `deploy/`. Treat a
Docker base-image bump as a runtime change, not a routine one: it moves the
interpreter the `ml` extra is validated on, and the 2026-09-08 bump to
`node:26` broke the web image until #21 installed pnpm explicitly.

## State of `main` at the time of writing (2026-09-08, `bb43bd7`)

Redsim CI on `main` is red and the cause is being investigated. Do not read
this page as a claim of a green pipeline. What is known from this tree:

| Check | Result on `bb43bd7`, run locally with the venv interpreter |
|---|---|
| `pytest -q -p no:cacheprovider --ignore=tests/e2e` | 1594 passed, 30 skipped (78 s with the `ml` extra) |
| `ruff check --select E4,E7,E9,F,I redsim tests` | clean (as reported by the wave 2 assembler) |
| `mypy redsim` | clean (as reported by the wave 2 assembler, from a venv that has `truststore` and `torch`) |
| `mkdocs build --strict` | clean |

`Docs` builds on every docs change and its Pages deploy stays off.
`Deploy to AWS` fails at the AssumeRole step. The CI state is recorded here as
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
