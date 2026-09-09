# Remaining-work brief: leftover Phase A, infrastructure completion, data-poisoning evaluation

Written 2026-09-09 as a brief for an agent (or a teammate running one). It covers
the work that the Phase A waves did not pick up, the completion of the deployed
infrastructure, and the data-poisoning evaluation module added to scope on
2026-09-09. Phase B proper (endpoint connector, LLM red-teaming, new modalities
and attacks, review workflow, PDF, interoperability, bulk operations) continues
in the redsim workflow waves and is only cross-referenced in section G.

## 0. Your task

You are completing redsim, an adversarial-ML red-team simulator built on the
aegis platform (Python package `redsim`; product and code name both `redsim`;
`aegis` appears only as upstream provenance). Work through packages A to F
below. Each item has an id, the requirement with its spec citation, the files it
lives in, the state found on 2026-09-09, an acceptance check you can run, and a
size. Verify the state yourself before changing anything; where an item is
already done, close it with the file and line as evidence instead of redoing it.
Where a check needs credentials or access you do not have (AWS, the live
Keycloak console), produce the code, the validated plan and a precise runbook,
and mark the apply step as open for the account owner.

## 1. State of the tree

`origin/main` is at `60a6c41` or later. On it:

- PR #22 (Metz): P4 campaign orchestration, compare and reports, web contract
  alignment, with the eight review findings fixed before the squash.
- Waves 1 to 3 (2026-09-08 to 2026-09-09): libraries reconciled with the
  build-assets manifest; the worker on the spec 10.5 audit vocabulary with the
  Pythia narrative in the worker parent; every ML route on the spec 17.3 error
  codes; `redsim ml attack` (offline, verifiable audit chain) and
  `redsim ml seed`; the ml-campaign scanner adapter; the doctor rewritten around
  Pythia; the `tests/e2e` harness with an eight-case smoke through the real
  sandbox child (image and tabular campaigns, audit verify and tamper, mocked
  narrative on and off).
- PR #23 (William): public HTTPS Fargate demo runtime at
  `https://redsim.ndia.agiledefense.xyz`, applied by its author; two review
  fixes landed on it (deploy workflow API-URL guard, Keycloak project-role
  mapper).
- Wave 4 is landing: the three end-to-end completion-criteria test files under
  `tests/e2e`, three CI fixes for `main` (B1), admission follow-ups, and the
  documentation refresh. Rebase onto `main` before you start.

Local suite at wave 3: 1663 passed, 30 skipped; ruff and mypy clean. Local
assets (gitignored, `assets/MANIFEST.json`): vehicles model now ResNet-18 at
0.7687 clean accuracy on 1,621 test images (illustrative, local build), URL
classifier 0.9087, CIFAR-10 fixture 0.6872 (fixture only).

## 2. Ground rules that apply to every item

- `redsim/ml/schema.py` is P0-frozen. Any field you need goes through the
  protocol in `docs/plans/01-p0-contracts-api-skeleton.md` section 8: additive,
  default-valued, announced in `docs/plans/00-master-plan.md` section 0.
- Nothing unimplemented is faked. An unbuilt path returns `501 not_implemented`
  with a reason (codes in `redsim/api/errors.py`) or records `unavailable`; it
  never returns an empty success.
- Every mutating action writes its audit row before the rows it mutates and
  before any job is enqueued (`safety.authorize` / the audit writer). Audit
  detail carries ids, digests and counts, never secrets, raw payloads or model
  bytes; `redsim/audit/redact.py` blanks any key containing `token`.
- The MRI is per campaign, travels with its five subscores and denominators,
  and never aggregates across modalities or with poisoning or LLM results (D9).
- Models load only in the sandbox child (`redsim/ml/sandbox.py`); the API
  process never imports torch, ART, SHAP, onnxruntime or sklearn
  (`tests/test_api_process_has_no_ml.py`). Pythia is the only LLM transport and
  is called only from the worker parent on the default pool.
- URL strings are data and are never fetched. Fixture data (the CIFAR-10 slice,
  `TinyTarget`, `TinyTabularTarget`) is never served as a result.
- Datasets are open, unclassified, public, with a recorded licence, and live in
  the public repository `https://github.com/IntelliBridge/ai-red-teaming-data`.
  The D3 bounds hold: no operational data, no targeting or weapons model is
  trained, no mission-system connection.
- No readiness, fielding, deployment or certification wording. Illustrative
  numbers are labelled illustrative.

## 3. Working conventions and commands

- Branch from `main`, open a PR to `main`, squash merge only (merge and rebase
  are disabled). The `codex-pr-review` skill runs on PRs; fix its findings on
  the branch before the squash. Direct docs-only pushes to `main` are the
  convention for plan updates.
- CI must stay green, including the torch-less py3.13 lane: ML tests carry the
  `ml` marker and skip when torch is absent.
- The Aikido pre-commit secret scan blocks anything key-shaped. Use low-entropy
  fakes in tests (`"kagglefakekagglefakekagglefake00"` passes;
  `"0123456789abcdef..."` does not). Never bypass the hook.
- Python environment: `.venv` created with `uv` behind a corporate TLS proxy
  (`UV_NATIVE_TLS=1 uv pip install ...`; `truststore` for Python TLS).
- Local checks (root `Makefile`): `make lint`, `make typecheck`, `make test`,
  `make check`, `make docs-build-strict`. Ruff selection in CI is
  `--select E4,E7,E9,F,I`; type check is `mypy redsim`.
- Test tiers: `pytest -q` (default), `pytest -q -m ml`, the Postgres integration
  lane, and `REDSIM_E2E=1 pytest -q -m e2e tests/e2e` with
  `REDSIM_E2E_POSTGRES_URL` for the RLS cases (a stock `postgres:16` on
  `localhost:5433`, user/password/db `redsim`, works; the compose Postgres image
  does not build behind the proxy, see A1).
- Compose stack (`deploy/Makefile`): `make up`, `make up-obs`, `make seed`,
  `make token-for`, `make psql`, `make logs`, `make down`.
- Terraform 1.15 is installed; `deploy/terraform/validate.sh` runs the mocked
  plans. There are no AWS credentials on the development machine.

## 4. Suggested order

B (CI parity) first because everything else is checked by it; then D (residual
rows, mostly verification); then F (poisoning module, the largest new build);
then A (compose operations) and E (infrastructure completion, code and runbook);
then C (process documents). Run A and E's live checks only where you have the
stack or the account.

## A. Compose-stack operations

Spec sections 20, 22.5 and 26.1. Files: `deploy/docker-compose.yml`,
`deploy/Dockerfile.postgres`, `deploy/Dockerfile.worker`, `deploy/Makefile`,
root `Makefile`, `deploy/helm/redsim`, `docs/dev/local-stack.md`, `README.md`.

| Id | Requirement | State on 2026-09-09 | Acceptance check | Size |
|---|---|---|---|---|
| A1 | `deploy/Dockerfile.postgres` (postgres:16 + pgaudit) fails to build behind a corporate TLS proxy: `apt-get install postgresql-16-pgaudit` exits 100. Make the build proxy-tolerant (system CA bundle, or a pinned pgaudit package with a checksum) or document a supported fallback to the stock `postgres:16` image with pgaudit off, selected through a compose variable. | Missing. The stock image works for tests; nothing documents the fallback. | `docker compose -f deploy/docker-compose.yml build postgres` succeeds on a proxied machine, or `POSTGRES_IMAGE=postgres:16 docker compose up -d postgres` is documented and starts. | S |
| A2 | `make up` brings up postgres, redis, keycloak, minio, redsim-api, redsim-worker (`-Q scans`), redsim-worker-default, redsim-beat, redsim-web and redsim-log-ingest, and the API answers `/health`. | Unverified end to end since the ML vertical landed. | `make up` then `curl -f localhost:8000/health`; `docker compose ps` shows every service healthy. | M |
| A3 | The worker image installs `.[worker,ml]` with the CPU torch wheel, `onnx2torch` and `safetensors`; `python -m redsim.ml.sandbox_worker --help` runs inside it. | Unverified after wave 1 added `onnx2torch`. | `docker compose run --rm redsim-worker python -c "import torch, art, shap, onnx2torch, safetensors"` exits 0. | S |
| A4 | The assets directory (`REDSIM_ML_ASSETS_DIR`) and the dataset cache (`REDSIM_ML_DATASET_CACHE`) are mounted into the worker; `redsim ml seed` registers the bundled models against the compose database; a campaign runs on the stack. | Partial. Volumes exist for the older layout; names must match what `redsim/ml/targets/bundled.py` reads. | `docker compose exec redsim-api redsim ml seed` registers `vehicles_cnn` and `url_trees`; a campaign started through the API reaches `succeeded`. | M |
| A5 | Pythia environment split: `redsim-worker-default` receives `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`, `REDSIM_ML_LLM_MODEL` with `REDSIM_DISABLE_LLM` unset; the `scans` pool has `REDSIM_DISABLE_LLM=1` and no Pythia variables; the sandbox child sees neither. | Partial. Check the compose `environment` blocks against `redsim/workers/celery_app.py`. | `docker compose exec redsim-worker env \| grep -c PYTHIA` prints 0; the default worker prints 3 or more. | S |
| A6 | Queue topology matches `redsim/workers/celery_app.py`: `redsim.ml_campaign_run` and `redsim.ml_model_validate` on `scans`; narrative-bearing follow-ons and `redsim.report_render` where the routes put them. | Unverified. | A campaign on the compose stack shows its job on the `scans` worker log and the narrative attempt on the default worker log. | S |
| A7 | MinIO bootstrap creates the primary bucket and the WORM bucket at stack start. | Unverified since the WORM export task landed. | `docker compose exec minio mc ls local/` lists both buckets after `make up`. | S |
| A8 | `make seed` creates the default org, project `default` and the admin user; `make token-for` mints a dev bearer token. | Present in `deploy/Makefile`; verify against the current ORM (org, project and membership tables changed under P0). | `make seed`, then `make token-for EMAIL=admin@example.com`, then `curl -H "Authorization: Bearer <token>" localhost:8000/v1/projects` returns the project. | S |
| A9 | A `make e2e` (or `make smoke`) target runs the completion flow against the live compose stack. `tests/e2e` runs in-process with eager Celery through `tests/e2e/harness.py`; a live mode needs an API URL and token environment (`REDSIM_E2E_API_URL`, `REDSIM_E2E_TOKEN`), polling of real Celery runs, and the worker having the assets (A4). | Missing. | `make e2e` exits 0 against `make up` with the image and tabular campaigns, verify, reports and `redsim audit verify --all`. | L |
| A10 | Helm chart `deploy/helm/redsim` current for the ML services: worker `-Q scans` and default pools, the spec 20.3 ML variables, the assets volume, the Pythia secret on the default pool only. | Unverified since wave 2. | `helm lint deploy/helm/redsim` and `helm template` show the ML variables; the CI job "Helm chart lints + templates" stays green. | M |
| A11 | Clone-to-first-run measurement (spec 26.1 item 1): time a fresh clone to a finished bundled-image FGSM and PGD campaign on the compose stack and record it in `README.md` with date and machine class. | Missing. | `README.md` carries the measured figure. | S |

## B. CI parity

Spec section 22.5. Files: `.github/workflows/redsim-ci.yml`, root `Makefile`,
`docs/dev/ci.md`.

| Id | Requirement | State on 2026-09-09 | Acceptance check | Size |
|---|---|---|---|---|
| B1 | Do not redo the three `main` fixes wave 4 lands: `python-multipart` in the `api` extra (coverage job), the `redsim.ml.datasets.sampling` to `redsim.ml.targets` import cycle on the torch-less lane, and the Next.js advisory baseline in `.trivyignore`. Confirm `main` is green after wave 4 before B2. | Landing in wave 4. | `gh run list --branch main --workflow redsim-ci.yml --limit 1` shows success. | S |
| B2 | A dedicated `ml` CI job: installs `.[test,dev,ml]` with the CPU torch wheel cached (`actions/cache` keyed by the torch version), runs `pytest -q -m ml` offline, and is a required check. Today the py3.12 unit job installs torch inline and runs the ml tests with the default tier. | Partial. | A job named `ML tier (py3.12, ml extra)` passes and its torch install hits the cache on the second run. | M |
| B3 | `make check` mirrors CI: `ruff check --select E4,E7,E9,F,I redsim tests`, `mypy redsim`, `pytest -q`, and `pnpm --filter @redsim/web typecheck && pnpm --filter @redsim/web test`. | Partial. `make check` runs ruff, mypy and pytest; confirm the web half is included and documented. | `make check` exits 0 on a clean checkout with pnpm installed and fails when a vitest test fails. | S |
| B4 | `docs/dev/ci.md` describes the lanes, what gates the downstream jobs (API integration, Next.js build, image build, Playwright), and the honest current state. | Wave 4 rewrites the state paragraph; keep it current after B2. | The page matches the workflow file. | S |

## C. Process-gate documents

Spec section 26.6 (items 25 to 29) and 26.2 item 11. Files:
`specs/_shared/readiness-checklist.md`, `specs/001-project-access` to
`specs/008-audit-governance`, `specs/_shared/decisions.md`,
`.specify/memory/constitution.md`, `SECURITY.md`, `docs/project-brief.md`. Only
signatures need people; the artifacts are ours to produce, with every box
unchecked and every reviewer name blank.

| Id | Requirement | State on 2026-09-09 | Acceptance check | Size |
|---|---|---|---|---|
| C1 | Each `specs/00N-*` gets `checklists/readiness-checklist.md` copied from `specs/_shared/readiness-checklist.md`: Specify, Clarify, Plan and Tasks sections present, all boxes unchecked, reviewer names blank. Boxes are checked only by the named reviewers, never by generation. | Missing (no `checklists/` directories). | `ls specs/00*/checklists/readiness-checklist.md` lists eight files; `grep -c '\[x\]'` prints 0 for each. | S |
| C2 | Each feature gets `checklists/approval.md`: product owner, engineering reviewer, security or data reviewer where relevant, dates blank, remaining non-blocking limitations listed, decision `Draft`. D006 and D007 stay open with no invented owners. | Missing. | Eight files exist; each reads `Decision: Draft`. | S |
| C3 | Each feature gets `checklists/evidence.md` mapping every success criterion in its `spec.md` to the test ids that prove it (unit, integration, `ml`, `e2e`) or to "no automated evidence" where true. "Done" is recorded separately from approval. | Missing. | Every `SC-` id in the eight `spec.md` files appears in the matching evidence file. | M |
| C4 | `specs/_shared/decisions.md` carries RESOLVED rows D001 to D005 in its own format with approver `product owner (hackathon), 2026-09-08`; D006 and D007 open; a new row D014 for the poisoning decision (see F1). | Partial. | The five rows read RESOLVED with that approver; D006 and D007 read OPEN; D014 present. | S |
| C5 | `.specify/memory/constitution.md` carries "Amendment proposals (2026-09-08)" with status `proposed, pending named approval`; ratification is not claimed anywhere. | Unverified. | `grep -n "Amendment proposals (2026-09-08)" .specify/memory/constitution.md` matches; no line claims ratification. | S |
| C6 | `docs/project-brief.md` is the single brief (D13). Every reference to `docs/brief.md` under `docs/`, `specs/` and `.specify/` is updated; references remaining in code or `README.md` are reported in the master plan, not silently edited. | Unverified. | `grep -rn "docs/brief.md" docs specs .specify` prints nothing. | S |
| C7 | `SECURITY.md` "Known gaps" is current: the Next.js advisories baselined in `.trivyignore` (including CVE-2026-75604 and GHSA-2xp9-vwfh-vxw4 added in wave 4) with the tracked Next 15 upgrade, and the sandbox and upload status after waves 1 to 3 (typed sandbox config, rlimits, no network jail, ONNX and state_dict only, pickles refused). | Partial. | The section names every `.trivyignore` id and describes the sandbox as `redsim/ml/sandbox.py` implements it. | S |
| C8 | Illustrative numbers labelled illustrative everywhere (spec 26.2 item 11): local asset accuracies (0.7687, 0.9087, 0.6872) and demo-script figures. Wave 4 labels README and docs; sweep `specs/` and `docs/plans/06` to `08`. | Partial. | `grep -rn "0\.7687\|0\.9087\|0\.5151" docs specs README.md` shows "illustrative" in the same paragraph for every hit. | S |
| C9 | A scripted walkthrough of the spec 24 demo (no UI): a shell script or `make demo` target that seeds, registers the bundled models, starts the image campaign, waits, starts verify, downloads the report and runs `redsim audit verify --all`, printing the ids at each step. | Missing. | `make demo` (or `scripts/demo.sh`) exits 0 against `make up` and prints the run id, finding id, verify run id and report path. | M |

## D. Residual Phase A rows

Verify each against the tree and close it, or record the divergence under the
plan-01 section 8 protocol in `docs/plans/00-master-plan.md` section 0.

| Id | Requirement | State on 2026-09-09 | Acceptance check | Size |
|---|---|---|---|---|
| D1 | Full adversarial slice per (attack, eps) stored as Artifact kind `ml.adv_slice` up to `REDSIM_ML_MAX_ADV_ARTIFACT_MB` (spec 12.8) and listed by `GET /v1/runs/{id}/artifacts`. | Done in code: `redsim/ml/campaign.py` writes `adv_slice/<attack>_<eps>.npz`; `redsim/workers/tasks/ml_campaign.py` maps the prefix to `ml.adv_slice`. Verify the listing and the cap with a test. | A test asserts the kind appears in the listing after a campaign and is absent, with a limitation recorded, when the cap is exceeded. | S |
| D2 | Resource bounds at admission (spec 12): `max_iter <= 50`, `max_eval <= 5000`, `n_samples <= 1000`, eps grid at most 3 members by default. | Partial. Wave 3 added the grid cap (`DEFAULT_MAX_EPS_GRID_MEMBERS` in `redsim/services/ml_campaigns.py`); HopSkipJump caps `max_eval` in `redsim/ml/attacks/hopskipjump.py`. Confirm `max_iter` and `n_samples` are enforced at admission, not only in adapters. | Route tests: 422 `params_out_of_range` for each bound. | S |
| D3 | 403 role-check denials logged to `application_logs` with the request id (spec 7, 21; `redsim/api/policy.py`). | Unverified. | A test asserts a denied request produces one application log row with `request_id` and the action name, and no audit chain row. | S |
| D4 | Blob keys prefixed `{project_id}/models/{target_id}` for uploads and `{project_id}/runs/{run_id}/...` for evidence (spec 5, 21; `redsim/services/ml_models.py`, `redsim/workers/tasks/ml_campaign.py`). | Unverified. | A test asserts the stored keys for an upload and a campaign artifact. | S |
| D5 | Broker unreachable at enqueue. Spec 10 says rows stay `queued` with the audit row written; wave 2 shipped `503 queue_unavailable` with the rows rolled back. Decide one behaviour and record it as a divergence or change it. | Divergence, unrecorded. | Master plan section 0 lists the divergence, or the service matches spec 10 and its test changes accordingly. | S |
| D6 | WORM export covers ML evidence on the beat schedule and the exported chain re-verifies (spec 26.5 item 23; `redsim/workers/tasks/worm_export.py`). | Partial. Confirm the export includes the `run:<id>` chains and the ML artifact references, and that `redsim audit verify` passes on the export. | An integration test runs the export task after a campaign and verifies the exported chain. | M |
| D7 | Spambase all-continuous fixture (spec 11.3.6) vendored under `tests/ml/fixtures/` with a manifest sidecar, never registered as a demo target. | Missing. | The fixture and sidecar exist; a test asserts no API path serves it. | S |
| D8 | UNSW-NB15 fallback (spec 11) recorded honestly as not built; the Kaggle malicious-URLs dataset is the tabular dataset. | Missing statement. | `grep -n "UNSW" README.md docs/plans/00-master-plan.md` shows the "not built" statement. | S |
| D9 | Every report carries a coverage header (dataset id and revision, split, `n_samples`, seed, selection method) and `generated_at`, the Run id, the `settings_hash` and the model sha (spec 14; `redsim/ml/reporting.py`). | Partial. Wave 1 rewrote the renderer to six sections; confirm every header field in all three formats. | `tests/ml/test_report.py` asserts each field in md, json and html. | S |
| D10 | `GET /v1/__settings` (`redsim/api/app.py`) hidden in production mode. | Unverified. | A test asserts 404 in production mode and 200 in dev. | S |
| D11 | `docs/api/v1.md`: stale pentest-era routes pruned; every mounted ML route documented with its codes. | Wave 4 documents the ML routes; prune remaining pentest rows. | The page lists no route `redsim/api/app.py` does not mount. | S |

## E. Infrastructure completion

Spec sections 20 and 26; `docs/plans/08-p7-infra-cd.md`;
`deploy/runtime/README.md` (William's deployment sequence, limitations and cost
estimate); `deploy/terraform/HANDOFF.md`; `.github/workflows/deploy-aws.yml`.
The runtime is applied and serving: health, login and OIDC discovery return 200,
unauthenticated API calls return 401, migrations are through `0010`. Workers are
at zero and automatic rollout is disabled. Classify each item as code-and-plan
(you can finish it) or apply (the account owner runs it from your runbook).

| Id | Requirement | State on 2026-09-09 | Acceptance check | Size |
|---|---|---|---|---|
| E1 | Keycloak project-role claim on the live realm. PR #23's fix added an `oidc-usermodel-attribute-mapper` for `redsim_project_roles` and the user-profile attribute to `deploy/runtime/identity/realm.json`, but `--import-realm` skips an existing realm, so the applied realm lacks them. Runbook: admin console steps (client `redsim-web`, dedicated scope, add mapper by configuration, user attribute `redsim_project_roles`, JSON type, ID token + access token + userinfo; realm settings, user profile, attribute with admin-only view and edit) or a realm re-import before demo users exist. | Apply. Procedure documented in `deploy/runtime/README.md` "Project membership claim". | A test login produces a session cookie whose `redsim_project_roles` map equals the user attribute `{"<project_id>": "approver"}`. | S |
| E2 | Pinned asset bundle: build the bundle from the local assets (vehicles ResNet-18, `url_trees`, manifests) with `deploy/runtime/scripts/upload_assets.py`, upload it, and pin its digest in the worker task definition so workers can start. | Code exists (`upload_assets.py`, `load_assets.py`, `deploy/runtime/tests/test_assets.py`); the bundle is not built or uploaded. Code-and-plan for the bundle build; apply for the upload and pin. | The worker task starts with the bundle mounted and `redsim ml seed` registers both bundled models against the live database. | M |
| E3 | Worker desired count above zero with the ml image on the `scans` pool and a default pool with the Pythia secret; the beat service running. | Apply (Terraform variable and task definitions in `deploy/runtime/tasks.tf`). | ECS shows running tasks for `redsim-worker`, `redsim-worker-default` and `redsim-beat`; a live campaign reaches `succeeded`. | M |
| E4 | CI-driven rollout: `deploy-aws.yml` builds immutable images and advances pinned task definitions and runs the migration task after a guarded build; the API-URL guard from PR #23 stays; a manual approval environment before apply. | Partial (workflow builds and pushes; rollout disabled by design). Code-and-plan. | A dry run of the workflow on a branch shows the plan and the pinned digests; the owner approves the first rollout. | M |
| E5 | OIDC deploy role trust for GitHub Actions (account-side) and the repository variables and secrets the workflow needs, documented with names only. | Apply. | The workflow's role assumption step succeeds on `main`. | S |
| E6 | Demo users and project memberships: a seed script or `redsim` command that creates the demo org, project, users at each role and their `redsim_project_roles` attributes through the Keycloak admin API, idempotent, with secrets from Secrets Manager, never in Git. | Missing. Code-and-plan for the script; apply for running it. | Running the script twice is a no-op the second time; each role can sign in and hits the expected 403s. | M |
| E7 | WORM export on the beat schedule in Fargate against the Object-Lock bucket and re-verification (spec 26.5 item 23). | Partial (task and bucket exist; the schedule and IAM on the runtime unverified). Code-and-plan. | The export runs on schedule, and `redsim audit verify` passes on the exported chain read back from the bucket. | M |
| E8 | API-level smoke against the live URL: health, OIDC discovery, 401 unauthenticated, then an authenticated campaign when a service credential exists; runnable as `make smoke-live` with the URL and token from the environment. | Missing. Code-and-plan. | `make smoke-live` exits 0 against the runtime. | S |
| E9 | `deploy/Dockerfile.web` keeps `ARG NEXT_PUBLIC_REDSIM_API_URL=http://localhost:8000` as a local default that the workflow no longer relies on; either drop the default or make the local build pass it explicitly, so no image can carry a localhost API URL by accident. | Partial. Code-and-plan. | Building the web image without the arg fails with a clear message, or the arg has no default and `make up` passes it. | S |
| E10 | Cost and teardown: the roughly $200/month core estimate, what to scale to zero between demos, and a `terraform destroy` order for bootstrap and runtime, in `deploy/runtime/README.md`. | Partial (estimate present). Code-and-plan. | The README carries the teardown section and the scale-to-zero commands. | S |
| E11 | Terraform hygiene: `deploy/terraform/validate.sh` (18 foundation plans, 11 scope-guard tests) and `deploy/runtime/tests/runtime.tftest.hcl` pass on `main`; the Helm chart and compose stay consistent with the runtime's environment variables. | Unverified since the merges. | `bash deploy/terraform/validate.sh` and `terraform test` in `deploy/runtime` pass. | S |

## F. Data-poisoning evaluation module

Decision D14 (owner, 2026-09-09): the brief and the original use case name data
poisoning as a vulnerability class, so the spec 3.3 non-goal "a training-data
poisoning pipeline" is narrowed. redsim evaluates a classifier's exposure to
training-data poisoning on the bundled datasets and small bundled models; it is
still not a training platform, not a poisoning pipeline for real data, and
nothing here touches operational data or the D3 bounds. Poisoning results are
never an MRI input; they get their own Poisoning Exposure card with k/n
denominators.

Files: new package `redsim/ml/poisoning/`, `redsim/workers/tasks/ml_poisoning.py`,
`redsim/services/ml_poisoning.py`, `redsim/api/v1/poisoning.py`, additive
fields in `redsim/ml/schema.py` under the protocol, `redsim/api/policy.py`
(new `Action`), `redsim/ml/reporting.py`, tests, docs, the spec and brief.

| Id | Requirement | State on 2026-09-09 | Acceptance check | Size |
|---|---|---|---|---|
| F1 | Record D14: replace the non-goal sentence in spec section 3.3 and reconciliation row 46, add item D14 to `docs/project-brief.md` "Decisions taken", add row D014 to `specs/_shared/decisions.md`, and announce the additive schema fields in `docs/plans/00-master-plan.md` section 0. | Missing. | The four documents carry the D14 text; `mkdocs build --strict` passes. | S |
| F2 | Schema, additive and default-valued (plan-01 section 8): a `poisoning` campaign kind literal; measurement families `poison_clean_retrain`, `poison_poisoned_retrain`, `poison_backdoor_asr`, `poison_defense_detection`; a `PoisoningExposure` record (poison fraction, trigger description, per-family measurements with denominators, defense detections with precision and recall against the known poisoned indices, limitations) referenced from the run record as an optional field; an `AttackInfo` family value `poisoning`. Nothing existing changes meaning. | Missing. | `tests/ml/test_schema.py` round-trips the new record; existing records still validate unchanged. | S |
| F3 | Library `redsim/ml/poisoning/`: attacks wrapping ART's `PoisoningAttackBackdoor` (pattern and single-pixel perturbations) and `PoisoningAttackCleanLabelBackdoor` for image targets, and an in-repo seeded label-flip poisoning for the tabular tree ensemble with the stated limitation that ART's poisoning attacks target neural networks and SVMs; `FeatureCollisionAttack`, `HiddenTriggerBackdoor` and `BullseyePolytope` registered as `not_implemented` with a reason. Defenses wrapping ART's `ActivationDefence` and `SpectralSignatureDefense`; `STRIP` and `NeuralCleanse` registered as `not_implemented`. Each attack declares its modality and parameter schema with bounds (poison fraction at most 0.2, trigger size bounded, seed required). | Missing. | `tests/ml/test_poisoning.py` on `TinyTarget` (8x8x3, 2x2 trigger, seconds): the poisoned retrain flips triggered inputs at a measurable rate, the clean retrain does not, and the defenses return indices with precision and recall computed against the known poisoned set. | L |
| F4 | Retrain recipe inside the sandbox child: two short seeded retrains (clean and poisoned) of a reduced model on a subsampled training split (for vehicles: `small_cnn` at 64 px, or a linear head on cached ResNet-18 features; for `url_trees`: the sklearn ensemble on the subsample), both finishing within `REDSIM_ML_SANDBOX_TIMEOUT_S`; the evaluation slice is never poisoned; the trigger is applied only to test copies for the ASR measurement. Record the recipe, the subsample indices and their digest in provenance. | Missing. | A `TinyTarget` run completes in seconds; a bundled `vehicles_cnn` run completes within the timeout on a laptop CPU, with both retrains, the subsample digest and the recipe in provenance. | L |
| F5 | Measurements and card: clean accuracy of the clean-retrained and poisoned-retrained models (k/n, per class), backdoor attack success rate on triggered test inputs (k/n), defense detection precision and recall (k/n against the known poisoned indices), observations (flagged training indices, SHAP on triggered inputs as supporting evidence labelled heuristic), interpretation labelled inferred, candidate recommendations (the defenses and data-provenance controls as candidates with no numeric gain), limitations (bundled datasets only, subsampled retrain, evaluation slice never poisoned, not a poisoning pipeline for real data, D3 bounds). The card is separate from the MRI and refuses aggregation with it. | Missing. | The run record carries the card; a test asserts the MRI code path rejects poisoning families and the card is absent from `MRIRecord`. | M |
| F6 | Worker and service: `redsim.ml_poisoning_run` on the `scans` pool through the sandbox child, admission service with audit-first `poison.run` row, stage events (`poison.execute.<attack>`, `poison.defend.<defense>`, `job.complete`), findings projection (finding type `adversarial_ml_poisoning`), report section rendered by `redsim/ml/reporting.py` with the card and denominators, artifacts (poisoned sample indices, trigger image, defense scores) with digests. | Missing. | Eager-Celery test: a poisoning run on `TinyTarget` completes, its chain passes `redsim audit verify --run`, the finding carries the card, the report has the section. | L |
| F7 | Routes: `POST /v1/models/{id}/poisoning` (body: attack id, defense ids, poison fraction, trigger, subsample size, seed; 202 with the run id; 501 with reason for endpoint targets and unbuilt attacks; 422 for bounds), `GET /v1/runs/{id}/poisoning` (the card), catalog rows on `GET /v1/attacks?family=poisoning` and `GET /v1/defenses?family=poisoning`; a new `Action` `POISON_RUN` at the `scanner` rank in `redsim/api/policy.py` (platform code, not the frozen ML schema) with tests; the spec 17.3 codes reused. | Missing. | Route tests for 202, 501, 422, 403 (viewer) and the card shape. | M |
| F8 | End-to-end and docs: `tests/e2e/test_ml_poisoning.py` on the harness (image poisoning run on the tiny bundled CNN with backdoor attack and both defenses, ASR and detection measurements with denominators, card present, MRI absent, audit chain verified); `docs/api/v1.md`, `docs/architecture/ml-vertical.md`, `README.md` (the module, its limits, the D14 decision) and `CLAUDE.md` updated; the public data repository unchanged (bundled datasets only). | Missing. | `REDSIM_E2E=1 pytest -q -m e2e tests/e2e/test_ml_poisoning.py` passes; `mkdocs build --strict` passes. | M |

## G. Cross-references, not in this brief

- Phase B proper continues in the redsim workflow waves (plan at
  `docs/plans/11-phase-b-plan.md` when published): black-box endpoint
  connector, LLM red-teaming through Pythia with garak, text and detection
  modalities, Carlini-Wagner, DeepFool, ZOO and patch attacks, KernelSHAP,
  adversarial training and distillation with measured deltas, the full review
  states, PDF export, snapshots, N-run comparison, per-project weights,
  idempotency keys, interoperability (dataset export and consume, ATLAS tags
  and coverage, the Foundry push; the Lattice push stays text-only pending an
  owner decision), and bulk operations (batch campaigns, bulk upload, bulk
  verify, CLI matrix).
- The web UI is deferred by the owner. API contracts for every page exist.

## 7. How to report back

Open one PR per package (A to F), or one per large item (A9, F3, F4, F6). In the
PR description list the item ids closed and paste the acceptance-check output
for each. Where an item is already done, close it in this document with the
file and line as evidence by changing its state column. Where an item is an
apply step, leave it open here with the runbook reference and say who runs it.
