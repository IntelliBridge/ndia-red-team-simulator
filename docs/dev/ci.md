# CI pipeline

Every pull request and every push to `main` runs the workflows under
`.github/workflows/`. This page says what each job checks, why the gates are
set where they are, and how to reproduce a failure locally. For the test
plumbing itself (fixtures, markers) see [Testing](testing.md).

## Workflows

| Workflow | File | Runs on |
|---|---|---|
| Redsim CI | `redsim-ci.yml` | every PR and push to `main`, plus `workflow_dispatch` (with an opt-in E2E toggle) |
| Docs | `docs.yml` | PRs and pushes that touch `docs/`, `mkdocs.yml`, `hooks/`, `pyproject.toml` or the root markdown files. `main` also deploys to GitHub Pages |
| Release sign | `release-sign.yml` | `v*` tags only. Builds, pushes, cosign-signs and SBOM-attests the four images |
| Deploy to AWS | `deploy-aws.yml` | pushes to `main` that touch runtime paths. Needs the repo variables and the OIDC role described at the top of the file, otherwise it fails at "Configure AWS credentials" |

## Redsim CI jobs

| Job | What it checks | Python | Extras installed |
|---|---|---|---|
| Unit tests (py3.12) | ruff, mypy, then `pytest -m "not integration ..."` | 3.12 | `api,worker,test,dev` plus `ml` (CPU torch) |
| Unit tests (py3.13) | same, with `and not ml` in the marker expression | 3.13 | `api,worker,test,dev` |
| Coverage gate | full default suite against Postgres 16 + Redis 7, `--cov-fail-under` | 3.12 | `api,worker,test,dev,ml` |
| API integration (Postgres + Redis) | `tests/` with `-m "not e2e and not docker and not slow and not auth_required and not ml"` | 3.12 | `api,worker,test` |
| SAST (semgrep + bandit) | `p/python` + `p/security-audit` at ERROR plus `.semgrep.yml`, bandit `-ll -ii` with `.bandit` | 3.12 | `security` |
| Dependency CVEs (pip-audit + trivy) | pip-audit over the resolved `api,worker` env, trivy `fs` at HIGH,CRITICAL | 3.12 | `api,worker,security` |
| Helm chart lints + templates | `helm lint` and six `helm template` renders including the prod-secret guard | n/a | n/a |
| OTel Collector config is valid | pipeline references resolve, forward-looking components stay commented | 3.12 | pyyaml |
| Secret scan (trufflehog, verified only) | verified secrets in the tree | n/a | n/a |
| redsim_output is not committed | `git ls-files redsim_output` is empty | n/a | n/a |
| Next.js build (pnpm, frozen lockfile) | typecheck design-system and web, vitest, `next build` | Node 20 | pnpm 10 |
| Build images (no push) | the four `deploy/Dockerfile.*` build | n/a | n/a |
| Stack E2E (Playwright) | only via `workflow_dispatch` with `run_e2e=true` | 3.12 | `api,worker,test` |

The last three depend on the unit job, so a lint failure skips them.

### The `ml` extra and the Python matrix

The ml stack (torch, torchvision, ART, SHAP, onnxruntime, scikit-learn) is
installed and exercised on Python 3.12 only. That is the interpreter the deploy
images pin (`deploy/Dockerfile.api`, `deploy/Dockerfile.worker`), and it keeps
the 3.13 lane a fast pure-platform check. CI installs CPU-only torch first from
`https://download.pytorch.org/whl/cpu`, exactly as the worker Dockerfile does,
so the extra resolves against it instead of pulling the multi-GB CUDA wheels.

The 3.13 lane and the API integration job deselect the `ml` marker. Deselection
happens after collection, so an ML test module must still import cleanly
without the extra. Guard heavy imports with `pytest.importorskip("torch")` at
module top, or put the module under a directory whose `conftest.py` skips when
the extra is absent. A bare `import torch` in a test module fails collection on
3.13 regardless of the marker.

### Lint and type gates

`ruff check --select E4,E7,E9,F,I redsim tests`. The explicit `--select` is
deliberate. ruff 0.16 enables a much larger default rule set (413 rules) than
the E4/E7/E9/F default this tree was written against, and `pyproject.toml` only
declares `extend-select = ["I"]`. Without the explicit selection the same ruff
reports 361 findings (UP, BLE, SIM, RUF, B, S and friends) that were never part
of the contract. The durable fix is to pin `lint.select` in `pyproject.toml`
and drop the flag from the workflow. Run the same command locally before
pushing.

`mypy redsim` runs with the settings in `pyproject.toml` (`disallow_untyped_defs`,
`warn_return_any`, `warn_unused_ignores`, `ignore_missing_imports`). Note that
`warn_unused_ignores` together with `ignore_missing_imports` makes a
`# type: ignore[import-not-found]` on an optional import an error, not a no-op.

### Coverage gate

`Coverage gate` runs the full default suite (the `addopts` marker expression in
`pyproject.toml`) against real Postgres and Redis, then applies
`--cov-fail-under=$COV_FAIL_UNDER`. The value lives in the job `env` block of
`redsim-ci.yml`, in one place.

The floor is **81%** as of 2026-09-08. That is a truthful floor for the tree
after the pentest-domain removal and the redsim rename, not the target:

| Measurement (2026-09-08) | Coverage |
|---|---|
| local, `pytest -q --cov=redsim` (SQLite only, 28 integration tests skipped) | 83% |
| `Coverage gate` job on `main` (Postgres + Redis) | 86.26% |
| `Coverage gate` job on `feat/ml-core` | 84.70% |

The floor is the local measurement minus 2, rounded down, so a contributor
without Postgres can still predict the CI result. The target returns to **90**
as the ML vertical lands: each merged phase (P1 targets and assets, P2 attacks
and scoring, P3 explain and recommend, P4 orchestration) ships pure modules
with unit tests, and the owner of that phase raises `COV_FAIL_UNDER` to the new
measured value minus 2 in the same PR. Do not lower it again without recording
the reason here.

Measure locally with:

```bash
.venv/bin/python -m pytest -q --cov=redsim --cov-report=term | tail -5
```

### Dependency CVEs

`pip-audit --skip-editable` audits the resolved `api,worker,security`
environment. `--skip-editable` drops the local editable `redsim-platform`
distribution, which has no PyPI advisory record. Advisory IDs with no fixed
release go in `.github/pip-audit-ignores.txt`, one per line with the reason.
The list is empty and the audit was clean on 2026-09-08 (CI run and a local run
against a freeze of the dev venv). When an advisory does appear, bump the pin
in `pyproject.toml` if a fixed release exists within the same major, otherwise
add the ignore with a one-line justification.

The ml extra is not part of the audited environment yet (the job stays lean
and the `+cpu` torch wheels have no PyPI advisory record). The release
workflow's Syft SBOM covers the shipped worker image.

`trivy fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed` scans the
whole checkout, which in practice means `pnpm-lock.yaml`. The trivy release is
pinned by `TRIVY_VERSION` in the workflow so a scanner behaviour change cannot
flip the gate on its own. Dependabot cannot bump a curl-installed binary, so
raise the pin by hand when a new release is out. `.trivyignore` carries the
documented baseline. Every current entry is a Next.js 14 advisory whose fix is
in Next 15 or 16, or the postcss 8.4.31 copy that `next@14.2.35` pins exactly.
They go away together with the Next upgrade owned by the web workstream
(dependabot PR #15 proposes Next 16 + React 19).

### Dependabot

`.github/dependabot.yml` groups weekly updates per ecosystem: pip, npm (`/web`),
GitHub Actions and the Docker base images under `deploy/`. Two open groups on
2026-09-08 are the actions bump (#14, checkout v7, setup-python v7 and friends,
which also clears the Node 20 deprecation warnings) and the docker bump (#13,
which moves the Python images from 3.12 to 3.14, Postgres 16 to 18 and Node 20
to 26). Neither touches the CI-owned files edited for this page, but #13 moves
the interpreter the ml extra is validated on, so treat it as a runtime change,
not a routine bump.

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
that exists but is not in the nav is only an INFO message today, but readers
cannot find it.

## Reproduce locally

The dev venv lives at `.venv/` and was created with uv. It has no `pip`
module, so install with uv and run tools through the venv interpreter:

```bash
V=.venv/bin/python
$V -m ruff check --select E4,E7,E9,F,I redsim tests
$V -m mypy redsim
$V -m pytest -q --cov=redsim --cov-report=term | tail -5
$V -m mkdocs build --strict
$V -c 'import yaml,sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]' .github/workflows/*.yml
```

Behind a TLS-inspecting proxy, `uv` needs `--native-tls` and Python HTTP
clients need the system trust store (`import truststore;
truststore.inject_into_ssl()`, already installed in the venv). pip-audit can be
run the same way against a freeze:

```bash
uv pip freeze --python $V | grep -v redsim-platform > /tmp/freeze.txt
$V -c 'import sys,truststore; truststore.inject_into_ssl(); from pip_audit._cli import audit; sys.argv=["pip-audit","-r","/tmp/freeze.txt","--no-deps"]; audit()'
```
