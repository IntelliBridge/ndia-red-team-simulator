# Handoff to John Sasser: leftover Phase A items

Date: 2026-09-09. Owner: Noah Behrick (product owner). Assignee: John Sasser.

This document lists the Phase A items that no implementation wave picked up. The
product owner decided they go to you rather than to the workflow waves, which
continue with Phase B (see section E). Everything here is small or medium, is
code or documentation, and has an acceptance check you can run locally. Nothing
here needs AWS access or a browser.

## 1. State of the tree

`origin/main` is at `10650da` or later. On it:

- PR #22 (Metz): P4 campaign orchestration, compare and reports, web contract
  alignment, with the eight review findings fixed before the squash.
- Waves 1 to 3 (2026-09-08 to 2026-09-09): libraries reconciled with the
  build-assets manifest, the worker on the spec 10.5 audit vocabulary with the
  Pythia narrative in the worker parent, every ML route on the spec 17.3 error
  codes, `redsim ml attack` and `redsim ml seed`, the ml-campaign scanner
  adapter, the doctor rewritten around Pythia, and the `tests/e2e` harness with
  an eight-case smoke through the real sandbox child.
- PR #23 (William): public HTTPS Fargate demo runtime, applied by its author.
- Wave 4 is landing as you read this: the three end-to-end completion-criteria
  test files, the three CI fixes for `main` (see B1), admission follow-ups, and
  the documentation refresh. Rebase onto `main` before you start.

Local suite at wave 3: 1663 passed, 30 skipped; ruff and mypy clean. CI on
`main` was red at the time of writing for the three reasons wave 4 fixes.

## 2. Ground rules that apply to every item

- `redsim/ml/schema.py` is P0-frozen. Any field you need goes through the
  protocol in `docs/plans/01-p0-contracts-api-skeleton.md` section 8: additive,
  default-valued, announced in the master plan.
- Nothing unimplemented is faked. An unbuilt path returns `501 not_implemented`
  with a reason or records `unavailable`; it never returns an empty success.
- Every mutating action writes its audit row before the rows it mutates and
  before any job is enqueued. Audit detail carries ids, digests and counts, never
  secrets, raw payloads or model bytes.
- URL strings are data and are never fetched. Fixture data (the CIFAR-10 slice,
  `TinyTarget`, `TinyTabularTarget`) is never served as a result.
- No readiness, fielding, deployment or certification wording anywhere.
- Illustrative numbers are labelled illustrative.

## 3. Working conventions

- Branch from `main`, open a PR to `main`, squash merge only (merge and rebase
  are disabled on the repository). The `codex-pr-review` skill runs on PRs and
  its findings get fixed on the branch before the squash.
- CI must stay green, including the torch-less py3.13 lane: ML tests carry the
  `ml` marker and skip when torch is absent.
- The Aikido pre-commit secret scan blocks anything that looks like a key. Use
  low-entropy fakes in tests (`"kagglefakekagglefakekagglefake00"` passed;
  `"0123456789abcdef..."` did not). Never bypass the hook.
- Local checks (root `Makefile`): `make lint`, `make typecheck`, `make test`,
  `make check`, `make docs-build-strict`. Ruff selection in CI is
  `--select E4,E7,E9,F,I`. The e2e tier is
  `REDSIM_E2E=1 pytest -q -m e2e tests/e2e`, with
  `REDSIM_E2E_POSTGRES_URL` for the RLS lane.
- Compose stack (`deploy/Makefile`): `make up`, `make up-obs`, `make seed`,
  `make token-for`, `make psql`, `make logs`, `make down`.

## 4. Suggested order

B (CI parity) first because everything else is checked by it, then D (residual
rows, mostly verification), then A (compose operations), then C (process
documents).

## A. Compose-stack operations

Spec sections 20, 22.5 and 26.1. Files: `deploy/docker-compose.yml`,
`deploy/Dockerfile.postgres`, `deploy/Dockerfile.worker`, `deploy/Makefile`,
root `Makefile`, `deploy/helm/redsim`, `docs/dev/local-stack.md`, `README.md`.

| Id | Requirement | State on 2026-09-09 | Acceptance check | Size |
|---|---|---|---|---|
| A1 | `deploy/Dockerfile.postgres` (postgres:16 + pgaudit) fails to build behind a corporate TLS proxy: `apt-get install postgresql-16-pgaudit` exits 100. Either make the build proxy-tolerant (system CA bundle, or a pinned pgaudit package fetched at build time with a checksum) or document a supported fallback to the stock `postgres:16` image with pgaudit off, and have compose honour it through a variable. | Missing. The stock image works for tests; nothing documents the fallback. | `docker compose -f deploy/docker-compose.yml build postgres` succeeds on a proxied machine, or `POSTGRES_IMAGE=postgres:16 docker compose up -d postgres` is documented and starts. | S |
| A2 | `make up` brings up postgres, redis, keycloak, minio, redsim-api, redsim-worker (`-Q scans`), redsim-worker-default, redsim-beat, redsim-web and redsim-log-ingest, and the API answers `/health` within the documented time. | Unverified end to end since the ML vertical landed. | `make up` then `curl -f localhost:8000/health`; `docker compose ps` shows every service healthy. | M |
| A3 | The worker image installs `.[worker,ml]` with the CPU torch wheel, `onnx2torch` and `safetensors`, and `python -m redsim.ml.sandbox_worker --help` runs inside it. | Unverified after wave 1 added `onnx2torch` use. | `docker compose run --rm redsim-worker python -c "import torch, art, shap, onnx2torch, safetensors"` exits 0. | S |
| A4 | The assets directory (`REDSIM_ML_ASSETS_DIR`) and the dataset cache (`REDSIM_ML_DATASET_CACHE`) are mounted into the worker so a bundled campaign can run on the compose stack; `redsim ml seed` registers the bundled models against the compose database. | Partial. Volumes exist in compose for the older layout; the mount names must match what `redsim/ml/targets/bundled.py` reads. | With assets built locally: `docker compose exec redsim-api redsim ml seed` registers `vehicles_cnn` and `url_trees`; a campaign started through the API reaches `succeeded`. | M |
| A5 | Pythia environment split: `redsim-worker-default` receives `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`, `REDSIM_ML_LLM_MODEL` with `REDSIM_DISABLE_LLM` unset; the `scans` pool has `REDSIM_DISABLE_LLM=1` and no Pythia variables. The sandbox child never sees either. | Partial. Check the compose `environment` blocks against `redsim/workers/celery_app.py` task routes. | `docker compose exec redsim-worker env | grep -c PYTHIA` prints 0; the default worker prints 3 or more. | S |
| A6 | Queue topology matches `redsim/workers/celery_app.py`: `redsim.ml_campaign_run` and `redsim.ml_model_validate` on `scans`, the narrative-bearing follow-ons and `redsim.report_render` where the spec puts them. | Unverified. | A campaign on the compose stack shows its job on the `scans` worker log and the narrative attempt on the default worker log. | S |
| A7 | MinIO bootstrap creates the primary bucket and the WORM bucket at stack start. | Unverified since the WORM export task landed. | `docker compose exec minio mc ls local/` lists both buckets after `make up`. | S |
| A8 | `make seed` creates the default org, project `default` and the admin user; `make token-for` mints a dev bearer token. | Present in `deploy/Makefile`; verify against the current ORM (org/project/membership tables changed under P0). | `make seed` then `make token-for EMAIL=admin@example.com` and `curl -H "Authorization: Bearer <token>" localhost:8000/v1/projects` returns the project. | S |
| A9 | A `make e2e` (or `make smoke`) target runs the completion flow against the live compose stack. Today `tests/e2e` runs in-process with eager Celery through `tests/e2e/harness.py`. A live mode needs: an API URL and token environment (`REDSIM_E2E_API_URL`, `REDSIM_E2E_TOKEN`), polling of real Celery runs instead of eager returns, and the worker having the assets (A4). | Missing. | `make e2e` exits 0 against `make up` with the image and tabular campaigns, verify, reports and `redsim audit verify --all`. | L |
| A10 | Helm chart `deploy/helm/redsim` current for the ML services: worker `-Q scans` and default pools, the ML environment variables of spec 20.3, the assets volume, the Pythia secret on the default pool only. | Unverified since wave 2. | `helm lint deploy/helm/redsim` and `helm template` show the ML variables; the CI job "Helm chart lints + templates" stays green. | M |
| A11 | Clone-to-first-run measurement (spec 26.1 item 1): time a teammate from clone to a finished bundled-image FGSM and PGD campaign on the compose stack and record it in `README.md`. | Missing. | `README.md` carries the measured figure with date and machine class. | S |

## B. CI parity

Spec section 22.5. Files: `.github/workflows/redsim-ci.yml`, root `Makefile`,
`docs/dev/ci.md`.

| Id | Requirement | State on 2026-09-09 | Acceptance check | Size |
|---|---|---|---|---|
| B1 | Do not redo the three `main` fixes wave 4 lands: `python-multipart` in the `api` extra (coverage job), the `redsim.ml.datasets.sampling` to `redsim.ml.targets` import cycle on the torch-less lane, and the Next.js advisory baseline in `.trivyignore`. Confirm `main` is green after wave 4 before starting B2. | Landing in wave 4. | `gh run list --branch main --workflow redsim-ci.yml --limit 1` shows success. | S |
| B2 | A dedicated `ml` CI job: installs `.[test,dev,ml]` with the CPU torch wheel cached (`actions/cache` on the pip cache keyed by the torch version), runs `pytest -q -m ml` offline, and is a required check. Today the py3.12 unit job installs torch inline and runs the ml tests together with the default tier. | Partial (folded into the py3.12 unit job). | The workflow shows a job named `ML tier (py3.12, ml extra)` that passes and whose torch install hits the cache on the second run. | M |
| B3 | `make check` mirrors CI: `ruff check --select E4,E7,E9,F,I redsim tests`, `mypy redsim`, `pytest -q`, and `pnpm --filter @redsim/web typecheck && pnpm --filter @redsim/web test`. | Partial. `make check` runs ruff, mypy and pytest; confirm the web half is included and documented. | `make check` exits 0 on a clean checkout with pnpm installed and fails when a vitest test fails. | S |
| B4 | `docs/dev/ci.md` describes the lanes, what gates the downstream jobs (API integration, Next.js build, image build, Playwright), and the honest current state. | Wave 4 rewrites the state paragraph; keep it current after B2. | The page matches the workflow file. | S |

## C. Process-gate documents

Spec section 26.6 (items 25 to 29) and 26.2 item 11. Files: `specs/_shared/readiness-checklist.md`,
`specs/001-project-access` to `specs/008-audit-governance`,
`specs/_shared/decisions.md`, `.specify/memory/constitution.md`, `SECURITY.md`,
`docs/project-brief.md`. Only signatures need people; the artifacts are ours to
produce, with every box unchecked and every reviewer name blank.

| Id | Requirement | State on 2026-09-09 | Acceptance check | Size |
|---|---|---|---|---|
| C1 | Each feature directory `specs/00N-*` gets a `checklists/` directory with `readiness-checklist.md` copied from `specs/_shared/readiness-checklist.md`, its Specify, Clarify, Plan and Tasks sections present, all boxes unchecked, reviewer names blank. Boxes are checked only by the named reviewers, never by generation. | Missing (no `checklists/` directories exist). | `ls specs/00*/checklists/readiness-checklist.md` lists eight files; `grep -c '\[x\]'` on each prints 0. | S |
| C2 | Each feature gets `checklists/approval.md`: product owner, engineering reviewer, security or data reviewer (where relevant), dates blank, remaining non-blocking limitations listed, decision `Draft`. D006 and D007 stay open with no invented owners. | Missing. | Eight files exist; each reads `Decision: Draft`. | S |
| C3 | Each feature gets `checklists/evidence.md` mapping every success criterion in its `spec.md` to the test ids that prove it (unit, integration, `ml`, `e2e`) or to "no automated evidence" where that is true. "Done" is recorded separately from approval. | Missing. | Every `SC-` id in the eight `spec.md` files appears in the matching evidence file. | M |
| C4 | `specs/_shared/decisions.md` carries RESOLVED rows D001 to D005 in its own format with approver `product owner (hackathon), 2026-09-08`; D006 and D007 remain open. | Partial (check the rows and approver text). | The five rows read RESOLVED with that approver; D006 and D007 read OPEN. | S |
| C5 | `.specify/memory/constitution.md` carries the section "Amendment proposals (2026-09-08)" with status `proposed, pending named approval`; ratification is not claimed anywhere. | Unverified. | `grep -n "Amendment proposals (2026-09-08)" .specify/memory/constitution.md` matches; no line claims ratification. | S |
| C6 | `docs/project-brief.md` is the single brief (D13). Every reference to `docs/brief.md` under `docs/`, `specs/` and `.specify/` is updated; references remaining in code or `README.md` are reported in the master plan, not silently edited. | Unverified. | `grep -rn "docs/brief.md" docs specs .specify` prints nothing. | S |
| C7 | `SECURITY.md` "Known gaps" is current: the Next.js advisories baselined in `.trivyignore` (including CVE-2026-75604 and GHSA-2xp9-vwfh-vxw4 added in wave 4) with the tracked Next 15 upgrade, and the sandbox and upload status after waves 1 to 3 (typed sandbox config, rlimits, no network jail, ONNX and state_dict only, pickles refused). | Partial. | The section names every `.trivyignore` id and describes the sandbox as it is in `redsim/ml/sandbox.py`. | S |
| C8 | Illustrative numbers are labelled illustrative everywhere (spec 26.2 item 11): the local asset accuracies (vehicles ResNet-18 0.7687, URL classifier 0.9087, CIFAR-10 fixture 0.6872) and any demo-script figures. | Wave 4 labels them in README and docs; sweep `specs/` and `docs/plans/06` to `08`. | `grep -rn "0\.7687\|0\.9087\|0\.5151" docs specs README.md` shows "illustrative" on the same line or in the same paragraph for every hit. | S |
| C9 | A scripted walkthrough of the spec 24 demo (no UI): a shell script or `make demo` target that seeds, registers the bundled models, starts the image campaign, waits, starts verify, downloads the report and runs `redsim audit verify --all`, printing the ids at each step. | Missing. | `make demo` (or `scripts/demo.sh`) exits 0 against `make up` and prints the run id, finding id, verify run id and report path. | M |

## D. Residual Phase A rows

Verify each against the tree and close it or record the divergence under the
plan-01 section 8 protocol in `docs/plans/00-master-plan.md`.

| Id | Requirement | State on 2026-09-09 | Acceptance check | Size |
|---|---|---|---|---|
| D1 | Full adversarial slice per (attack, eps) stored as Artifact kind `ml.adv_slice` up to `REDSIM_ML_MAX_ADV_ARTIFACT_MB` (spec 12.8) and listed by `GET /v1/runs/{id}/artifacts`. | Done in code: `redsim/ml/campaign.py` writes `adv_slice/<attack>_<eps>.npz` and `redsim/workers/tasks/ml_campaign.py` maps the prefix to `ml.adv_slice`. Verify the listing and the size cap with a test. | A test asserts the kind appears in the artifacts listing after a campaign and is absent when the cap is exceeded, with the limitation recorded. | S |
| D2 | Resource bounds at admission (spec 12): `max_iter <= 50`, `max_eval <= 5000`, `n_samples <= 1000`, eps grid at most 3 members by default. | Partial. Wave 3 added the eps-grid cap (`DEFAULT_MAX_EPS_GRID_MEMBERS` in `redsim/services/ml_campaigns.py`); HopSkipJump caps `max_eval` at 5000 in `redsim/ml/attacks/hopskipjump.py`. Confirm `max_iter` and `n_samples` bounds are enforced at admission, not only in the adapters. | Route tests: 422 `params_out_of_range` for each bound. | S |
| D3 | 403 role-check denials are logged to `application_logs` with the request id (spec 7, 21). | Unverified (`redsim/api/policy.py`). | A test asserts a denied request produces one application log row with `request_id` and the action name, and no audit chain row. | S |
| D4 | Blob keys are prefixed `{project_id}/models/{target_id}` for uploads and `{project_id}/runs/{run_id}/...` for evidence (spec 5, 21). | Unverified (`redsim/services/ml_models.py`, `redsim/workers/tasks/ml_campaign.py`). | A test asserts the stored keys for an upload and a campaign artifact. | S |
| D5 | Broker unreachable at enqueue. Spec 10 says the rows stay `queued` with the audit row already written, for later pickup; wave 2 shipped `503 queue_unavailable` with the rows rolled back. Decide one behaviour and record it as a divergence or change it. | Divergence, unrecorded. | The master plan section 0 lists the divergence under the plan-01 section 8 protocol, or the service matches spec 10 and its test changes accordingly. | S |
| D6 | WORM export covers ML evidence on the beat schedule and the exported chain re-verifies (spec 26.5 item 23; `redsim/workers/tasks/worm_export.py`). | Partial. The task exists from the platform; confirm it exports the `run:<id>` chains and the ML artifact references and that `redsim audit verify` passes on the export. | An integration test runs the export task after a campaign and verifies the exported chain. | M |
| D7 | Spambase all-continuous fixture (spec 11.3.6) vendored under `tests/ml/fixtures/` with a manifest sidecar, never registered as a demo target. | Missing (no reference on the tree). | The fixture file and sidecar exist; a test asserts no API path serves it. | S |
| D8 | UNSW-NB15 fallback (spec 11) recorded honestly: not built. The README and the master plan say the Kaggle malicious-URLs dataset is the tabular dataset and the fallback was not needed. | Missing statement. | `grep -n "UNSW" README.md docs/plans/00-master-plan.md` shows the "not built" statement. | S |
| D9 | Every report carries a coverage header (dataset id and revision, split, `n_samples`, seed, selection method) and `generated_at`, the Run id, the `settings_hash` and the model sha (spec 14; `redsim/ml/reporting.py`). | Partial. Wave 1 rewrote the renderer to the six sections; confirm every header field. | `tests/ml/test_report.py` asserts each field in all three formats. | S |
| D10 | `GET /v1/__settings` (in `redsim/api/app.py`) is hidden in production mode. | Unverified. | A test asserts 404 with `REDSIM_ENV=production` (or the mode flag the app uses) and 200 in dev. | S |
| D11 | `docs/api/v1.md`: stale pentest routes pruned; every mounted ML route documented with its codes. | Wave 4 documents the ML routes; prune any remaining pentest-era rows. | The page lists no route that `redsim/api/app.py` does not mount. | S |

## E. Cross-references, not in this handoff

- Phase B runs in the workflow waves: black-box endpoint connector, LLM
  red-teaming through Pythia with garak, text and detection modalities,
  Carlini-Wagner, DeepFool, ZOO and patch attacks, KernelSHAP, adversarial
  training and distillation with measured deltas, the full review states, PDF
  export, snapshots, N-run comparison, per-project weights, idempotency keys,
  interoperability (dataset export and consume, ATLAS tags and coverage, the
  Foundry push), bulk operations, and a data-poisoning evaluation module added
  to scope by the owner on 2026-09-09 because the brief names poisoning. Its
  plan will appear as `docs/plans/11-phase-b-plan.md`.
- William's live Fargate runtime follow-ups are in `deploy/runtime/README.md`:
  the `redsim_project_roles` mapper on the already-applied Keycloak realm, the
  pinned asset bundle, demo users and memberships, worker count above zero, and
  automatic rollout.
- The web UI is deferred by the owner.

## 6. How to report back

Open one PR per group (or one per item for A9 and C3) against `main`. In the PR
description list the item ids closed and paste the acceptance-check output for
each. Where an item turns out to be already done, say so with the file and line
and close it in this document by changing its state column.
