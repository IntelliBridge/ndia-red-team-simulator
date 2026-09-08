# redsim (Adversarial ML Red-Team Simulator)

Non-operational proof of concept that evaluates and hardens the robustness of
ML classifiers under adversarial evasion attacks: ART attacks with a benign
noise control and an epsilon sweep, SHAP as supporting evidence, a per-campaign
Model Robustness Index, candidate hardening recommendations, and a
verify-after-harden loop that reports a measured delta. Open, unclassified,
public data only. It never trains, optimizes or deploys targeting or weapons
models and connects to no mission system.

The repository is a fork of IntelliBridge's `aegis` security platform. The
product owner decided on 2026-09-08 to keep the FULL aegis platform (FastAPI,
Celery, Postgres + Alembic, Redis, S3/MinIO, Keycloak/NextAuth, RBAC and
Postgres RLS, hash-chained audit log, per-task LLM routing, observability) and
add one vertical under `redsim/ml/`. The pentest domain (14 scanner adapters,
Kali, CAI agents, GitHub remediation, ticketing, CI gate) is deleted for good.
The earlier lean "strip aegis down to a `redsim` package" design is retired.

## Authoritative docs, in order

1. `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`. The
   consolidated product spec, 27 sections. Section 8 is the architecture,
   section 17 the API surface, section 18 the web UI, section 20 deployment,
   section 22 testing, section 23 milestones, section 26 completion criteria.
2. `docs/project-brief.md`. Governance brief. Its reporting principles are
   design constraints. "Decisions taken (2026-09-08)" records every decision
   and every knowing divergence from the brief and the constitution.
3. `specs/README.md` and `specs/00N-*/` (F001 to F008) with
   `specs/_shared/` (decision register, shared architecture, readiness
   checklist). Feature layer beneath the product spec. Where a feature file
   and the product spec conflict, the product spec wins.
4. `docs/architecture/*`. redsim platform docs (inherited from aegis), still
   accurate for the platform.

Superseded, history only: `docs/adversarial-ml-redteam-spec.md` (and `.html`)
and `docs/superpowers/specs/2026-09-08-redsim-design.md`. Do not build against
them.

## Naming

- Product and UI name: redsim, long form "Adversarial ML Red-Team Simulator".
- Python namespace: `redsim`. Import as `redsim.…`. The console script is
  `redsim`, environment variables are `REDSIM_*`, the API title is "Redsim
  API", the session cookie is `redsim_api_session`, the CSRF cookie and header
  are `redsim_csrf` and `X-Redsim-CSRF`, the config file is `redsim.yaml`.
  Decision D7 was amended by the product owner on 2026-09-08 (commit
  `b39d933`): the earlier "Python stays aegis" position is superseded, and
  `aegis` survives only as the name of the upstream fork.
- Web workspace packages: `@redsim/web` (in `web/`) and
  `@redsim/design-system` (in `packages/design-system/`). Web environment
  variables are `NEXT_PUBLIC_REDSIM_*`.
- Compose services and images are `redsim-*`, the Helm chart is
  `deploy/helm/redsim`, the CI workflow is `.github/workflows/redsim-ci.yml`.
- Mentions of `aegis` that refer to the upstream project or to history (fork
  provenance, "restored from the aegis head", the ADRs) are correct and stay.
  Anything that describes this package, its paths, env vars, CLI, services,
  cookies or chart says redsim.

## What exists and what is not written yet

Exists and importable (verified with `.venv/bin/python`):

- `redsim.api.app:create_app()` builds and mounts 21 routes: `health`,
  `runs`, `runs_cancel`, `findings`, `audit`, `reports`,
  `scanners`, `verify`, `targets`, `auth_profiles`, `projects`, `logs`,
  `org_cost`, the WebSocket `runs/{id}/events` and `/v1/__settings`.
  `POST /v1/scans` was unmounted at M0 and answers 404.
- `redsim.workers.celery_app` loads with tasks `scan`, `verify`, `report`,
  `reaper`, `tenant_reconcile`, `worm_export` on queues `scans` and
  `default`.
- `redsim/db` models plus Alembic migrations `0001` to `0009`,
  `redsim/audit` (chain, forensic, redaction), `redsim/api/policy.py` RBAC and
  `redsim/policy` engines, `redsim/api/middleware` (tenant GUC for RLS, CSRF,
  rate limit), `redsim/llm` (router, budget, pricing, guardrails, `pythia.py`),
  `redsim/storage` (filesystem, S3, WORM), `redsim/state`, `redsim/services`,
  `redsim/scanners` (registry, capability vocabulary, sandbox), `redsim/cli`,
  `redsim/log_ingest`, `redsim/observability.py`.
- `redsim/ml/`: `schema.py` (the evidence model: `TargetInfo`, `AttackInfo`,
  `RunConfig`, `Provenance`, `Measurement`, `Observation`, `Interpretation`,
  `CandidateRecommendation`, `RunRecord`, `RunSummary`, `STAGES`,
  `STANDING_LIMITATIONS`), `targets/base.py` (`Target` protocol, `Sample`),
  `attacks/base.py` (`AttackAdapter`, `AttackOutput`). `explain/` and
  `recommend/` are empty packages. `tests/ml/fakes.py` holds `TinyTarget`.
- Web `@redsim/web` pages: `/`, `/login`, `/dashboard`, `/runs`,
  `/runs/[id]`, `/findings`, `/findings/[id]`, `/projects`,
  `/projects/[slug]/settings`, `/targets`, `/auth-profiles`, `/logs`,
  `/audit`, `/cost`. `web/src/lib/api.ts` defaults to
  `http://localhost:8000`, overridable with `NEXT_PUBLIC_REDSIM_API_URL`.
- `deploy/docker-compose.yml`: postgres, redis, keycloak, minio, redsim-api,
  redsim-worker (`-Q scans`), redsim-worker-default (`-Q default`),
  redsim-beat, redsim-web, redsim-log-ingest, plus opt-in profiles for opa,
  otel-collector, loki, jaeger, elasticsearch, kibana. `deploy/helm/redsim`.

Not written yet (every item is an assigned location in the spec, not a file):

- ML loaders and the sandboxed loader subprocess (`redsim/ml/targets/
  {bundled,artifact,architectures,tabular,endpoint}.py`, `redsim/ml/sandbox.py`,
  `redsim/ml/sandbox_worker.py`).
- Attack adapters and registry (`redsim/ml/attacks/{fgsm,pgd,noise_control,
  hopskipjump,registry}.py`), `redsim/ml/campaign.py`, `redsim/ml/eval.py`,
  `redsim/ml/scoring.py` (MRI), `redsim/ml/defenses.py`, `redsim/ml/datasets/`,
  `redsim/ml/errors.py`.
- SHAP explainers (`redsim/ml/explain/{shap_image,shap_tabular,stability,
  summary}.py`) and the recommendation layer (`redsim/ml/recommend/
  {interpret,rules,narrative}.py`).
- Celery tasks `model.validate`, `attack.run`, `explain.run`,
  `harden.recommend` and the ML branch of `verify.replay`
  (`redsim/workers/tasks/{model_validate,attack,explain,harden}.py`).
- Admission services `redsim/services/{ml_models,ml_campaigns,ml_findings}.py`
  and routes `redsim/api/v1/{models,attacks,datasets,defenses,
  ml_capabilities,artifacts,compare,ml_findings}.py` (`/v1/models`,
  `/v1/models/{id}/attacks`, `/v1/attacks`, `/v1/datasets`, `/v1/defenses`,
  `/v1/ml/capabilities`, `/v1/runs/{id}/campaign`, `/v1/runs/{id}/artifacts`,
  `/v1/artifacts/{id}`, `/v1/runs/{id}/compare`, explain and harden on
  findings).
- Alembic migration `0010_ml_vertical` (`targets.detail`, `ml_campaigns`).
- `redsim/cli/ml.py` (`redsim ml build-assets`, `redsim ml attack`).
- Web pages `/models`, `/models/[id]`, the MRI scorecard and panels on
  `/runs/[id]`, the three-pane body of `/findings/[id]`, the `/targets`
  redirect.
- Bundled models and datasets. Nothing is fetched or trained yet.

## How to run things

- Python 3.12 only. The venv is `.venv`, created with uv, and it has NO `pip`
  module. Run Python as `.venv/bin/python`. Install with uv:
  `uv pip install --native-tls -e ".[api,worker,test,dev,ml]"`. uv is at
  `/opt/homebrew/bin/uv` and needs `--native-tls` behind the corporate TLS
  proxy. Never call `.venv/bin/pip`.
- Extras in `pyproject.toml`: `api`, `worker`, `test`, `dev`, `security`,
  `docs`, `ml` (torch, torchvision, onnx, onnxruntime, scikit-learn, ART,
  SHAP, matplotlib, pyarrow, httpx), `llm` (optional private `pythia-sdk`,
  `redsim/llm/pythia.py` falls back to httpx), `garak` (Phase B only).
- Tests: `.venv/bin/python -m pytest -q`. The default `-m` from `addopts`
  excludes `docker`, `e2e`, `slow` and `auth_required`. `pytest -m ml` runs
  the tests that need the `ml` extra, `pytest -m integration` the sqlite or
  Postgres-backed ones.
- Lint and types: `.venv/bin/ruff check redsim tests`, `.venv/bin/mypy redsim`.
- Web: pnpm 10 workspace at the repo root. `pnpm --filter @redsim/web dev`
  (:3000), `pnpm --filter @redsim/web typecheck`, `pnpm --filter @redsim/web
  test` (vitest), `pnpm --filter @redsim/design-system typecheck`.
- Make targets: `install` (venv, then `uv pip install --native-tls
  --python .venv/bin/python -e ".[$(EXTRAS)]"` with `EXTRAS` defaulting to
  `api,worker,test,dev,ml`, pip fallback, `pnpm install`),
  `require-install`, `dev` (pytest, then `dev-api` + `dev-web` under
  `make -j`), `dev-api` (`uvicorn redsim.api.app:create_app --factory
  --reload --port 8000`, boots without Postgres or Redis but only `/health`,
  `/docs` and `/metrics` work until they are up), `dev-web`, `dev-worker`
  (`celery -A redsim.workers.celery_app worker -Q scans,default`, needs Redis,
  Postgres and the `ml` extra, deliberately not on the `dev` line), `test`,
  `test-cov` (`--cov=redsim`), `lint`, `lint-py`, `lint-web`, `typecheck`,
  `typecheck-py`, `typecheck-web`, `check` (lint, typecheck, test), `up`
  (`docker compose -f deploy/docker-compose.yml up -d --build`), `down`,
  `docs-serve`, `docs-build`, `docs-build-strict`, `docs-clean` (call
  `mkdocs` from `PATH`, need the `docs` extra and an activated venv or
  `MKDOCS=.venv/bin/mkdocs`).
- Full stack: `make up` at the root runs compose directly. `deploy/Makefile`
  has the finer helpers (`cd deploy && make seed`, `token-for`, `whoami`,
  `psql`, `logs`, `rebuild`, `down`, `down-clean`, `up-obs`). `redsim-api`
  runs `alembic upgrade head` on start. Ports: web 3300, API 8000, Keycloak
  8080, Postgres 5432, Redis 6379, MinIO 9100/9101, log ingest 4319.
  `REDSIM_AUTH_MODE=dev` dev tokens (`Bearer dev:<email>`) are allowed for
  the demo.
- Environment names are in `.env.example` (`REDSIM_DB_URL`, `REDSIM_BROKER_URL`,
  `REDSIM_RESULT_BACKEND`, `REDSIM_BLOB_BACKEND`, `REDSIM_S3_*`,
  `REDSIM_AUTH_MODE`, `REDSIM_OIDC_*`, `REDSIM_CORS_ORIGINS`,
  `REDSIM_PLUGINS_SANDBOX`, `REDSIM_DISABLE_LLM`, `REDSIM_LLM_BUDGET_STRICT`).

## LLM access: Pythia only

Every LLM call goes through Pythia (`redsim/llm/pythia.py`). redsim's per-task
router and budget caps stay the policy layer, Pythia is the only transport.
No litellm, no direct provider keys. The `OPENAI_API_KEY`-style entries still
in `.env.example` are aegis leftovers and are unused by the ML vertical.

| Variable | Meaning |
|---|---|
| `PYTHIA_BASE_URL` | Gateway base URL, posts go to `{PYTHIA_BASE_URL}/v1/chat/completions`. |
| `PYTHIA_API_KEY` | `pk_...` key sent as `Authorization: Bearer`. |
| `PYTHIA_PERSONA` | Optional, sent as `X-Pythia-Persona`. |
| `PYTHIA_TIMEOUT_S` | Optional, default 60. |
| `REDSIM_ML_LLM_MODEL` | Canonical model id (`<vendor>/<model>` or `pythia/auto`). Renamed from `REDSIM_LLM_MODEL` at M0 in `redsim/llm/pythia.py`, the `redsim/ml/schema.py` comment and `tests/test_llm_pythia.py`. The spec text still says `AEGIS_ML_LLM_MODEL`, the namespace rename made it `REDSIM_*`. |

If any required variable is missing, `PythiaSettings.from_env()` returns
`None`, the recommendation keeps `narrative = None` and
`narrative_source = "rules"`, and the UI says "Narrative unavailable". Never
fake a narrative. The writer receives metrics and a SHAP text summary only,
never images, model bytes or dataset rows.

Behind the corporate TLS proxy (Zscaler) the gateway is reached through an
inspecting proxy. The Python client must trust the system store: inject
`truststore` (installed in the venv: `import truststore;
truststore.inject_into_ssl()`) or set `SSL_CERT_FILE` to a bundle containing
the proxy root, otherwise httpx fails with `CERTIFICATE_VERIFY_FAILED` while
`curl` succeeds (it uses the macOS keychain). The Pythia access workstream
(PR #11) adds `python -m redsim.llm.pythia_check`, which lists `/v1/models`
and runs one chat completion. Run it to prove the gateway is reachable before
debugging the narrative code. Until it merges, `curl` against
`{PYTHIA_BASE_URL}/v1/models` with the bearer key is the equivalent check.

## Pre-commit hook (Aikido)

`git config core.hooksPath` points at `~/.git-hooks`, whose `pre-commit` runs
`aikido-local-scanner pre-commit-scan` on the repo. The restored aegis
redaction and guardrail test fixtures (for example `tests/test_otel_redaction.py`,
`tests/test_llm_guardrails.py`, `tests/test_audit_chain.py`,
`tests/test_evidence_pack.py`) contain deliberately fake secrets and trip the
scanner. Use `AIKIDO_SKIP_PRE_COMMIT=1 git commit ...` only for commits that
touch those fixtures, and say so in the commit message. Do not skip the hook
for anything else, and never add a real credential to make a test pass.

## Known broken (verified 2026-09-08, while the code fix-up is still editing)

Counts below come from running the commands, not from memory. Re-run them
before quoting them, the fix-up agent is changing `redsim/`, `tests/`,
`deploy/` and `web/` concurrently.

- `.venv/bin/python -m ruff check redsim tests`: 361 errors, 195 fixable with
  `--fix`. The bulk is import sorting and modernisation rules across the
  restored platform, not the ML vertical.
- `.venv/bin/python -m pytest -q`: `tests/test_effects.py` fails collection
  (`ImportError: cannot import name 'kali_tool_effect' from 'redsim.effects'`,
  a pentest leftover). With that file ignored: 763 passed, 20 failed, 28
  skipped in about 19 s. The failures are in `tests/test_cli_commands_coverage.py`
  (8), `tests/test_doctor.py` (4, Gemini and OpenAI key checks),
  `tests/test_api_client.py` (3), `tests/test_worker_hardening.py` (2, queue
  routing), `tests/test_m6_dispatch.py`, `tests/test_rate_limit.py` (webhook
  path) and `tests/test_worker_tasks_coverage.py` (default scanner `strix`).
  All are pentest-era expectations the fix-up is removing or rewriting.
- `make lint-web` is guarded. `web/` has no ESLint config and no `eslint` dev
  dependency, and `next lint` without a config drops into Next's interactive
  setup prompt, so the target prints a skip line and exits 0 until
  `web/.eslintrc.json` or `web/eslint.config.mjs` exists. Fixing it for real
  means adding `eslint` and `eslint-config-next` plus a config, or replacing
  the `lint` script. `make lint` and `make check` pass through the skip.
- `mkdocs` is not installed in `.venv` (the `docs` extra is not part of the
  default install), so `make docs-*` fails until
  `uv pip install --native-tls -e ".[docs]"`.
- `deploy/Dockerfile.api` now copies `redsim/` and `alembic.ini`, installs
  `.[api,worker,ml]` and runs `alembic upgrade head` before uvicorn.
  Installing `ml` in the API image diverges from spec section 8.4 (the API
  image should never carry torch, ART, onnxruntime or SHAP, and section 22
  plans a test for it). Resolve that before the M0 test lands.
  `deploy/Dockerfile.worker` now installs `.[worker,ml]` after the CPU-only
  torch wheels. `deploy-aws.yml` builds api, worker and web images and rolls
  the ECS services that are configured. None of the three images has been
  built end to end on the restored tree yet.
- `docs/api/v1.md` still documents removed routes (tickets, agents, fix,
  `tools/kali`, GitHub webhooks). `CONTRIBUTING.md` still describes the aegis
  submodule checkout. `docs/dev/local-stack.md` still lists `kali` and
  `git submodule update`. `CHANGELOG.md` is aegis release history.
- `.github/workflows/redsim-ci.yml` still runs the redsim lint, mypy, pytest,
  coverage (`--cov-fail-under=90`), SAST and web-build jobs against this
  tree, so it is red until the items above are fixed.

## Working rules for this codebase

- Read a file immediately before editing it and make surgical edits. Another
  agent may have touched it since your last read.
- Nothing under `redsim/ml/` may be presented as working until it runs. Show
  unimplemented paths as `not_implemented` with a reason, never with
  placeholder results. Fixture data (CIFAR-10 slice, `TinyTarget`) is for
  tests only.
- The API process never imports torch, ART, onnxruntime or SHAP. Model bytes
  are opened only on the worker inside the sandbox child.
- Every mutating route appends its audit event before writing `Run`/`Job`
  rows and before touching Celery (`tests/test_admission_audit_before_enqueue.py`
  asserts the order).
- Measurements, observations, interpretation and candidate recommendations
  stay separate fields and separate panels. The `Literal` labels in
  `redsim/ml/schema.py` (`candidate`, `not evaluated`, `inferred`,
  `heuristic`) are part of the contract.
- The MRI is per campaign and never shown without its subscores, the
  per-family table with denominators and the epsilon curve. No expected gain
  on a recommendation until verify measures it.

## Conventions

Commits are `type(topic): description`. Branch before committing, never commit
to `main` directly. Prose in docs and comments avoids em dashes and semicolons.
