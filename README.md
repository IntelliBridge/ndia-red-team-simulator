# redsim (Adversarial ML Red-Team Simulator)

redsim stress-tests a machine-learning classifier under adversarial evasion
attacks before anyone relies on it. A user picks a model (a bundled sample or
an uploaded ONNX or PyTorch `state_dict` artifact), launches an attack campaign
(ART attacks such as FGSM, PGD and HopSkipJump across an epsilon sweep, each
paired with a benign random-noise control), and reads the SHAP explanation and
the candidate hardening recommendations side by side, with every step recorded
on a hash-chained audit log. A verify campaign re-runs the same settings with
an ART preprocessing defense in front of an evaluation copy and reports the
measured change in the Model Robustness Index.

What it does not do. It is a non-operational proof of concept on open,
unclassified, public data. It evaluates and hardens the robustness of a
classifier and nothing else: it never trains, optimizes or deploys targeting or
weapons models, it connects to no mission system, it applies defenses only to
an evaluation copy inside a campaign, and no score or grade it produces is a
safety, readiness or certification statement. Measurements, per-sample
observations, inferred interpretation and candidate recommendations are kept
in separate fields and separate UI panels, every succeeded run carries its
limitations, and a recommendation carries no expected gain until a verify run
measures one. Fixture data is never served as a result, and unsupported paths
answer `not_implemented` with a reason instead of a placeholder.

The product is built as one vertical, `redsim/ml/`, inside the redsim
platform. This repository is a fork of IntelliBridge's aegis security platform
with the penetration-testing domain removed and, since 2026-09-08, every
identifier renamed to redsim (see Provenance).

## Status

As of 2026-09-09, `main` is at `29db42c`: the four Phase A completion waves
(wave 4, the end-to-end completion-criteria files and the CI fixes, integrated
by `e73dea0`) and Phase B wave B0 (contracts, tripwires, stubs, datasets,
`934838e..29db42c`). Phase B wave B1, the library layer (eight commits from
`refactor(ml): split run_campaign into a frame plus modality runners` to
`fix: integrate Phase B wave B1 tracks`), is pushed to `main` together with
this documentation pass. The decisions behind this table are in
[`docs/project-brief.md`](docs/project-brief.md) under "Decisions taken", the
target design is the
[product spec](docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md),
the Phase A spec-versus-tree register is
[`docs/plans/09-gap-register-2026-09-08.md`](docs/plans/09-gap-register-2026-09-08.md),
and Phase B is planned in
[`docs/plans/12-phase-b-plan.md`](docs/plans/12-phase-b-plan.md) over the
register [`docs/plans/11-phase-b-register-2026-09-09.md`](docs/plans/11-phase-b-register-2026-09-09.md).
Anything that does not hold on a running stack is listed under "Open items
and not implemented", never simulated in the UI.

| Area | State on `main` |
|---|---|
| redsim platform (inherited from aegis): FastAPI `/v1` API, Celery workers, Postgres with Alembic migrations `0001` to `0011`, Redis, S3/MinIO blob store, Keycloak/NextAuth auth, RBAC and Postgres RLS, hash-chained audit log with WORM export, per-task LLM routing and budgets, OTel observability and `redsim-log-ingest` | Restored. `create_app()` mounts 58 HTTP routes under `/v1` (39 Phase A routes plus the 19 Phase B routes wave B0 mounted as gated `501` stubs) plus `/health`, `/metrics` and the run-events WebSocket. At `29db42c` the default suite is 2081 passed, 35 skipped, 1 deselected and the e2e tier 22 passed through the real sandbox child with the Postgres RLS lane on (local runs from the wave B0 integration). Ruff (CI selection) and mypy are clean from the venv. The Redsim CI run for `29db42c` had not been read when this README was written (see Open items and [`docs/dev/ci.md`](docs/dev/ci.md)). |
| Pentest domain (14 scanner adapters, Kali, CAI agents, GitHub remediation, ticketing, CI gate) | Deleted for good. The seams fail explicitly: `POST /v1/scans` is unmounted (404), `redsim scan --scanner X` exits 1 when no adapter of that name is registered, the web Start scan button is disabled behind a notice, and target ownership verification answers 501. `GET /v1/scanners` lists the one adapter that exists, `ml-campaign` (`3ab9de7`), whose health check probes the `ml` extra and the sandbox child and never a model. |
| ML contracts (P0, extended once by Phase B wave B0) | `redsim/ml/schema.py` frozen, the `Target` and `AttackAdapter` protocols, migration `0010_ml_vertical` (`targets.detail`, `ml_campaigns` with RLS parity), the seven ML `Action` members and the `viewer` role, the spec 17.3 error-code table in `redsim/api/errors.py`, the spec 10.6 failure classes in `redsim/ml/errors.py`, and a test that the API process imports no ML library. Wave B0 (`29db42c`) added, under the plan-01 section 8 protocol and announced in master plan section 0: the Phase B schema fields (`text` and `detection` modalities, `edit` and `patch_area` norms, detection and text measurement and observation blocks, the `endpoint` and `derived_from` manifest blocks, the widened review states, `schema_version`, the `defense_apply` stage), all additive and default-valued with the frozen fixture validating byte-identical (`tests/ml/test_schema_compat.py`); migration `0011_phase_b_platform` (`report_snapshots`, `idempotency_keys`, `ml_batches`, `ml_datasets` with RLS parity, `projects.ml_*` columns, `ml_campaigns.batch_id`); seven Phase B `Action` members with OPA and Cedar mirrors; 23 spec 17.3 codes in a dated addendum; the `endpoint-v1` predict contract and egress policy ([`docs/api/endpoint-contract.md`](docs/api/endpoint-contract.md)). |
| ML libraries (waves 1 and 2, then Phase B wave B1): loaders, sandbox child, attacks, scoring, explain, recommend, reports, modality runners, hardening, endpoint broker | On main. Loaders read the `build-assets` manifest, onnx2torch conversion with argmax agreement, `small_cnn` and `resnet18` architectures, tabular target `url_trees` (alias `url_classifier`), surrogate-transfer PGD with per-feature eps and ART mask, HopSkipJump, the noise control, the binomial `control_preserves_accuracy` predicate, `FamilyDelta`, typed delta refusal, `not_run` handling, curve PNG, dataset caveats and `subject_centered`, the `PartitionExplainer` fallback and explanation cache, the six-section report renderer, the typed `MlSandboxConfig` and envelopes. Wave B1 adds the frame-plus-`ModalityRunner` split of `run_campaign` (golden-tested against the pre-refactor function), the `text` modality (`sms_tfidf_lr`, `word_substitution` with its text control, SHAP text), the `detection` modality (`assets_frcnn_mnv3`, `dpatch` with `patch_noise_control`, a detection scorecard and never an MRI), `cw_l2`, `deepfool` and `zoo`, KernelSHAP for predict-only tabular targets with endpoint query caps, `EndpointTarget` with the worker-parent `PredictBroker`, and the training defenses `adversarial_training` and `defensive_distillation` as the `defense_apply` stage. Registered targets: `vehicles_cnn`, `url_trees`, `cifar10_smallcnn` (fixture only), `endpoint_stub` (not implemented), `assets_frcnn_mnv3` (detection, `not_implemented` until built), `sms_tfidf_lr` (text, when `redsim.ml.targets.text` is imported). Attacks: `fgsm`, `pgd`, `hopskipjump`, `noise_control`, `cw_l2`, `deepfool`, `zoo`, `word_substitution`, `dpatch`, `patch_noise_control`. Defenses: `feature_squeezing`, `spatial_smoothing`, `jpeg_compression` (preprocessing), `adversarial_training`, `defensive_distillation` (training, admitted by the verify route in wave B2). Library only: nothing of B1 is admitted through the API until wave B2. Details in [`docs/architecture/ml-vertical.md`](docs/architecture/ml-vertical.md). |
| ML orchestration and API (PR #22 plus wave 2; Phase B stubs in wave B0) | On main. Tasks `redsim.ml_campaign_run` (one job per campaign) and `redsim.ml_model_validate` on the `scans` queue. The spec 10.5 audit vocabulary and 6.5 stage table (with `defense_apply` for a training defense since the B1 integration). The Pythia narrative in the worker parent through `route("ml.harden_narrative")` with `DbBudgetChecker` and `LLMUsage` rows. Routes `/v1/ml/capabilities`, `/v1/attacks`, `/v1/datasets`, `/v1/defenses`, `/v1/models` (per-project bundled ids, upload refusal codes with audited refusals, audited soft delete), `POST /v1/models/{id}/attacks` (with reruns), `/v1/runs/{id}/campaign`, `/v1/runs/{id}/compare` (variable-level incompatibility, `verify_delta`), `/v1/runs/{id}/artifacts`, `/v1/artifacts/{id}`, `/v1/runs/{id}/report.{md,json,html}` (`report.pdf` answers 501), finding explain / harden / verify / status (dismissal rules), `GET /v1/audit/verify?all=1`. Since wave B0 the 19 Phase B routes (LLM probes, batch, bulk, capacity, `report.render`, snapshots, dataset export and consume, ATLAS coverage, Foundry) are mounted behind their real gates and answer `501 not_implemented` with the wave and track that builds each ("Phase B, 501 until built", [`docs/api/v1.md`](docs/api/v1.md#phase-b-routes)). The full list is in [`CLAUDE.md`](CLAUDE.md). |
| Offline CLI, seeding, adapter, e2e harness, doctor and config (wave 3, `7556b22..58461cc`) | On main. `redsim ml attack` (`3ab9de7`), `redsim ml seed` (`3ab9de7`, `98a8733`), the `ml-campaign` scanner adapter and opt-in `redsim.ml.attacks` plugin discovery (`3ab9de7`), the `tests/e2e` harness and its 8-case smoke file (`35e71c7`, `a45a787`), `redsim doctor --worker-mode` rewritten around Pythia with Pythia-only `redsim.yaml` and `.env.example` (`7556b22`, `c3868e5`), `redsim audit verify --run-dir` with canonical audit timestamps (`aa9674e`), the `resnet18` fine-tune recipe (`39126ce`), and the defect fixes: `eps` and `norm_l2` no longer frozen into `attack_params` and applicability by capability tag (`dd2bbd4`), PGD by surrogate transfer admitted on `url_trees` (`58461cc`), the sandbox child pinned to an absent `.env` with `REDSIM_DISABLE_LLM=1` and attack plugins on `GET /v1/attacks` (`c3868e5`). |
| Pythia LLM transport (`redsim/llm/pythia.py`, `python -m redsim.llm.pythia_check`) | Merged (#11) and reached from behind the corporate proxy on 2026-09-08. Reads `REDSIM_ML_LLM_MODEL`. The narrative is optional and degrades to rule text with `narrative_source = "rules"`. See [`docs/ops/pythia.md`](docs/ops/pythia.md). |
| Web app `@redsim/web` (Next.js 14) and `@redsim/design-system` | Pages `/`, `/login`, `/dashboard`, `/runs`, `/runs/[id]`, `/findings`, `/findings/[id]`, `/projects`, `/projects/[slug]/settings`, `/targets`, `/auth-profiles`, `/logs`, `/audit`, `/cost`, `/models`, `/models/[id]`, with the MRI scorecard and evidence panels. PR #22 aligned the web contract with the mounted routes, PR #24 (`b93d9a9`) added tRPC and env management and PR #25 (`6cbb661`) the design reference. Wiring beyond that has not been exercised in a browser against a running stack with real campaign data; the web UI is the one deferral of the Phase B plan (open item). |
| Deployment: `deploy/docker-compose.yml`, `deploy/helm/redsim`, `deploy/Dockerfile.*`, `deploy/terraform/`, `deploy/bootstrap/`, `deploy/runtime/`, `deploy-aws.yml` | Compose (postgres, redis, keycloak, minio, redsim-api, redsim-worker, redsim-worker-default, redsim-beat, redsim-web, redsim-log-ingest, optional opa / otel-collector / loki / jaeger / elasticsearch / kibana) and the Helm chart are named `redsim-*`. `Dockerfile.api` installs `.[api,worker]` and runs `alembic upgrade head`, `Dockerfile.worker` installs CPU torch then `.[worker,ml]`. `deploy/terraform/` (#19) is the Fargate foundation with mocked-plan tests; PR #23 (`10650da`, merged) adds `deploy/bootstrap/` and `deploy/runtime/`, a public HTTPS Fargate demo runtime at https://redsim.ndia.agiledefense.xyz that its author reports applied to the AWS account with workers at zero tasks, demo users and real assets outstanding (its completion is package E of [`docs/plans/10-remaining-work-brief.md`](docs/plans/10-remaining-work-brief.md), not a Phase B wave). The compose stack was not brought up end to end as part of these passes (package A of the brief). `deploy-aws.yml` builds and pushes the three images under OIDC and skips its deploy job while `ECS_CLUSTER` is unset. No campaign has been run on a deployed stack. |
| Demo data | Decided and buildable. `redsim ml build-assets --dataset all` fetches the datasets by pinned revision and trains the bundled models on CPU (image, tabular, CIFAR-10 fixture and, since the B1 integration, the SMS spam text classifier; the detector is built only when `--dataset detection` is named because its input is the published subset). Everything it writes under `assets/` is gitignored, so a fresh clone has none until it runs the build. Clean accuracy per model is recorded in the asset manifest (see Datasets for the illustrative local numbers). Wave B0 published the Phase B datasets (SMS Spam Collection, the military-assets subset pending owner review) and the WordNet, ATLAS and garak reference entries to the public data repository at head `4048a209`. |
| Docs site (`mkdocs.yml`, `make docs-*`) | `mkdocs build --strict` passes locally. GitHub Pages publishing is off (the plan has no private Pages). |
| Phase B waves B2 (services, workers, routes), B3 (interoperability, bulk), B4 (e2e evidence, gate, docs) | Not started. Every route they build is one of the 19 stubs, "Phase B, 501 until built"; what each replaces is listed in [`docs/architecture/ml-vertical.md`](docs/architecture/ml-vertical.md#what-waves-b2-to-b4-replace). |

## Architecture at a glance

Three layers, described in full in
[section 8 of the product spec](docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md#8-architecture)
and in [`docs/architecture/ml-vertical.md`](docs/architecture/ml-vertical.md).
The diagrams live under `docs/architecture/diagrams/` and open as pages on the
docs site:

- [`redsim-platform.architecture.html`](docs/architecture/diagrams/redsim-platform.architecture.html):
  the deployed services and the data plane.
- [`attack-campaign.sequence.html`](docs/architecture/diagrams/attack-campaign.sequence.html):
  one campaign from `POST /v1/models/{id}/attacks` through the worker, the
  sandbox child and Pythia.
- [`campaign-run.lifecycle.html`](docs/architecture/diagrams/campaign-run.lifecycle.html):
  run, job and finding states and the stage progression.

1. **redsim platform.** Browser to `@redsim/web` (Next.js, NextAuth against
   Keycloak, dev-token mode allowed for the demo) to `redsim-api` (FastAPI
   `/v1`, RBAC through `redsim/api/policy.py`, tenant GUC for Postgres RLS,
   CSRF, rate limit, request-id correlation). Every mutating call appends a
   hash-chained audit event before it writes `Run` and `Job` rows and before it
   touches Celery, and every refusal carries a spec 17.3 code. Postgres holds
   runs, jobs, findings, artifacts, campaign records and the audit chain,
   S3/MinIO holds bytes, Redis is the Celery broker and the live-event channel
   behind `/v1/runs/{id}/events`.
2. **`redsim/ml/` vertical.** Runs only on the worker. One Celery job per
   campaign (`redsim.ml_campaign_run`) loads the model inside a sandboxed
   child process (separate process, rlimits, wall-clock kill, no network
   configuration, no secrets), runs the ART attacks and the noise control at
   every eps on one seeded slice, explains with SHAP, computes the MRI per
   campaign, derives interpretation and candidate recommendations from rules,
   and hands back a typed envelope. The worker parent writes `Artifact` rows,
   the stage table, the spec 10.5 audit rows and the findings, and runs the
   optional Pythia narrative. `redsim.ml_model_validate` validates uploads the
   same way. The API process never imports torch, ART, onnxruntime or SHAP (a
   test enforces it).
3. **Pythia.** The only LLM transport. The worker parent sends metrics, rule
   outputs, limitations and a SHAP text summary, never images or model bytes,
   to `{PYTHIA_BASE_URL}/v1/chat/completions` under redsim's per-task routing
   and budget caps. No provider key exists anywhere in the deployment.

## Quickstart

### Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Python | 3.12.x | `pyproject.toml` requires 3.12 or newer. `torch` and `adversarial-robustness-toolbox` wheels lag newer interpreters, so 3.12 is the working choice and the one the images pin. |
| uv | any recent | `/opt/homebrew/bin/uv` on the team laptops. The local `.venv` is created by uv and has no `pip` module, so use `uv pip ...` or `.venv/bin/python -m ...`, never `.venv/bin/pip`. |
| Node.js | 20 or newer | Only for the web app. |
| pnpm | 10 | Workspaces are declared in `pnpm-workspace.yaml` (`web`, `packages/design-system`). The lockfile is the root `pnpm-lock.yaml`. |
| Docker | 24 or newer, Compose v2 | Only for Postgres, Redis and the full stack (`make up`). |

Behind a corporate TLS proxy (Zscaler and similar), uv needs the system trust
store: pass `--native-tls` to every `uv` command. The Dockerfiles under
`deploy/` copy any `.pem` / `.crt` files from `deploy/certs/` into the image
trust store for the same reason, and the Pythia client trusts the OS store by
default.

### 1. Install

```bash
git clone https://github.com/IntelliBridge/ndia-red-team-simulator.git
cd ndia-red-team-simulator
uv venv --python 3.12 .venv
uv pip install --native-tls -e ".[api,worker,test,dev,ml]"
pnpm install                       # only if you want the web app
```

`make install` does the same (venv from pyenv's newest 3.12.x, then
`python3.12`, then `python3`. `uv pip install --native-tls` when uv is on
`PATH`, `ensurepip` plus pip otherwise. `pnpm install`), with the extras in
`EXTRAS` (default `api,worker,test,dev,ml`). The extras are `api`, `worker`,
`test`, `dev`, `security`, `docs`, `ml` (numpy, torch, torchvision, onnx,
onnxruntime, scikit-learn, ART, onnx2torch, safetensors, SHAP, matplotlib,
pillow, pyarrow, httpx), `llm` (the optional private `pythia-sdk`, not needed
because `redsim/llm/pythia.py` falls back to an in-repo httpx client) and
`garak` (the Phase B LLM domain, pinned `garak>=0.16,<0.17`, installed only by
the `garak offline` CI lane until waves B2 and B4 land their tests).

Check the environment:

```bash
.venv/bin/redsim doctor                   # dev laptop
.venv/bin/redsim doctor --worker-mode     # requires the ml extra, the sandbox child and the asset manifest
```

`redsim doctor` (`7556b22`, `c3868e5`) prints the mode, an informational
Pythia block (key redacted to prefix and length, the routed model, a note when
the model came from a deprecated alias), the `ml` extra with versions, a
launch of the sandbox child with `--help` under the real child environment,
the asset manifest verification and whether the `ml-campaign` adapter is on
the roster. The three ML checks are required with `--worker-mode` (or
`REDSIM_DOCTOR_WORKER_MODE=1`) and informational otherwise. `--api-mode` adds
the Postgres, blob and OIDC probes. No provider key is checked anywhere.

### 2. Build the bundled ML assets

```bash
.venv/bin/redsim ml build-assets --dataset all --arch resnet18
```

Fetches the datasets of spec section 11 by pinned revision, trains the
bundled image models, the URL classifier and (since the B1 integration) the
SMS spam text classifier `sms_tfidf_lr` on CPU with a fixed seed, writes the
training slice a training defense fine-tunes on next to each image model, and
writes `assets/MANIFEST.json` on `MLModelManifest` with the dataset caveats.
`--dataset detection` builds the military-assets detector `assets_frcnn_mnv3`
from the published subset under `<assets>/cache/military_assets_subset` and is
never part of `--dataset all`, because the build cannot fetch that input
itself (`redsim ml build-assets --help` lists every dataset choice).
Everything under `assets/` except its README is gitignored, so each clone
builds its own. The Kaggle download reads `KAGGLE_API_TOKEN` from the
environment or from `.env` (`REDSIM_ENV_FILE`), or the older
`KAGGLE_USERNAME` / `KAGGLE_KEY` pair, and falls back to the committed CI
sample (marking the result `fixture_only`) when neither is set.
`--dataset cifar10` needs no token. `--arch small_cnn` (the default) or
`resnet18` (ImageNet weights only from the local torch hub cache, else random
init, recorded in the manifest), `--epochs` (default 3), `--only <model_id>`,
`--out`, `--cache-dir`, `--seed`, `--image-size`, `--max-train` / `--max-eval`
(smoke builds) are the other knobs. `--fixture` regenerates
`tests/ml/fixtures/cifar10_test_500.npz` from local files only. Network access
happens only in this command, never in the worker or the tests. Clean accuracy
per model is recorded in the manifest and read from there by the UI and the
reports.

### 3. Run one campaign offline

```bash
.venv/bin/redsim ml attack vehicles_cnn --out ./redsim_output
.venv/bin/redsim ml attack url_trees --attacks pgd,hopskipjump --out ./redsim_output
.venv/bin/redsim audit verify --run <run_id>            # or --run-dir ./redsim_output/<run_id>
```

`redsim ml attack` builds a frozen `CampaignConfig` for a bundled target from
`REDSIM_ML_ASSETS_DIR` or `./assets` (`vehicles_cnn`, `url_trees`, and once
built `sms_tfidf_lr` with `--norm edit` and `assets_frcnn_mnv3` with
`--norm patch_area`), runs the attacks in the credential-free
sandbox child with no network and no Pythia, and writes
`<out>/<run_id>/run_record.json`, `report.md`, `report.json`, `report.html`,
the robustness curve PNG and `audit.jsonl`, a single-file hash chain
(`run:<run_id>`) that `redsim audit verify --run <run_id>` walks. Defaults:
attacks `fgsm,pgd` (the noise control runs automatically, `--no-control`
skips it), the spec 12.3 eps grid for the norm with reference eps `0.03`,
`--n-samples 200`, `--seed 0`, `--explain-k 8`. `endpoint_stub` is refused
with `not_implemented` and fixture-only targets with `fixture_only` before
anything is written. Every recommendation stays `narrative_source=rules`.

### 4. Run the API and the worker locally

```bash
docker compose -f deploy/docker-compose.yml up -d postgres redis
cp .env.example .env               # fill in what you need; .env is gitignored
set -a; source .env; set +a        # REDSIM_DB_URL, REDSIM_BROKER_URL, REDSIM_RESULT_BACKEND, REDSIM_AUTH_MODE=dev
.venv/bin/alembic upgrade head
make dev-api                       # uvicorn on :8000, /docs and /health
make dev-worker                    # second terminal: celery -Q scans,default, needs the ml extra
make dev-web                       # optional, third terminal: Next.js on :3000
```

With no `REDSIM_DB_URL` the API still boots and `/health` reports
`db_configured=false`, but every database-backed route raises until Postgres
and Redis are up. `REDSIM_AUTH_MODE=dev` accepts `Authorization: Bearer
dev:<email>` as an admin of project `default` (refused when
`REDSIM_ENV=prod`). Create the default organisation, project and user, then
register the bundled models and launch a campaign:

```bash
cd deploy && make seed && cd ..                        # default-org, project default, user admin (compose stack)
.venv/bin/redsim ml seed --project default             # bundled models into the project (audit-first, one commit per model)
TOKEN="Bearer dev:admin@redsim.local"
curl -s -H "Authorization: $TOKEN" localhost:8000/v1/models | jq '.models[] | {id, status, modality}'
curl -s -X POST -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
     -d '{"attack_ids": ["fgsm", "pgd"]}' localhost:8000/v1/models/<model_id>/attacks
curl -s -H "Authorization: $TOKEN" localhost:8000/v1/runs/<run_id>/campaign | jq '.score'
curl -s -H "Authorization: $TOKEN" "localhost:8000/v1/audit/verify?run=<run_id>"
```

`deploy/Makefile`'s `seed` runs inside the compose `redsim-api` container.
Without the compose API, seed the rows with the same Python snippet against
your `REDSIM_DB_URL`. Admission fills `modality`, `eps_grid` (the spec 12.3
default for the norm), `reference_eps` and `dataset_id` from the model's
manifest when the body omits them, and refuses anything it cannot admit with
a spec 17.3 code before any row is written. Without a bundled registration
`POST /v1/models` with `{"source": "bundled", "project_id": "default",
"bundled_id": "vehicles_cnn"}` does the same as `redsim ml seed` for one
model.

Full stack in containers:

```bash
make up          # docker compose -f deploy/docker-compose.yml up -d --build
make down
```

`redsim-api` runs `alembic upgrade head` on start. Ports: web `3300`, API
`8000`, Keycloak `8080`, Postgres `5432`, Redis `6379`, MinIO `9100` / `9101`,
log ingest `4319`. `docker compose --profile obs up -d` adds OTel Collector,
Loki and Jaeger. The worker image installs `.[worker,ml]` (CPU-only torch
wheels first), so expect it to be the slowest to build. The compose worker
anchor sets `REDSIM_DISABLE_LLM=1`. Unset it on `redsim-worker-default`
before expecting a narrative. Bringing the compose stack up end to end was
not part of the completion pass (see Open items).

### 5. Run the tests

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider               # default tier: 2081 passed, 35 skipped, 1 deselected at 29db42c
.venv/bin/python -m pytest -q -p no:cacheprovider -m ml         # only the tests that need the ml extra
REDSIM_E2E=1 .venv/bin/python -m pytest -q -p no:cacheprovider -m e2e tests/e2e     # end-to-end tier, sqlite lane
REDSIM_E2E=1 REDSIM_E2E_POSTGRES_URL=postgresql+psycopg://redsim:redsim@localhost:5432/redsim_e2e \
  .venv/bin/python -m pytest -q -p no:cacheprovider -m e2e tests/e2e                # adds the Postgres RLS lane: 22 passed at 29db42c
.venv/bin/python -m pytest -q -p no:cacheprovider -m garak tests   # garak tier: exit 5 (nothing collected) until a garak-marked test exists
.venv/bin/ruff check --select E4,E7,E9,F,I redsim tests         # lint, exactly as CI
.venv/bin/mypy redsim                                           # types
pnpm --filter @redsim/web typecheck                             # tsc --noEmit
pnpm --filter @redsim/web test                                  # vitest
```

The counts are local runs from the wave B0 integration at `29db42c`
(2026-09-09), not CI results; they move with every wave, so re-run before
quoting them. Wave B1's own checks before its rebase (ruff and mypy clean, 206
passed in its writers' test files) are in its integration commit.

Markers are declared in `pyproject.toml`. `unit` and `integration` run by
default. The `integration` tests use the shared sqlite harness in
`tests/conftest.py` and need no running services. `docker`, `e2e`, `slow`,
`auth_required` and (since wave B0) `garak` are opt-in with `-m`; `garak`
means "needs the garak extra, skipped when absent" and runs only in the
`garak offline` CI job. The e2e tier (`35e71c7`, `a45a787`)
stamps every item under `tests/e2e` as `e2e` and skips it unless `REDSIM_E2E`
is set. It drives the real API, admission services, eager Celery task bodies,
the real sandbox child and the real CLI over sqlite against a tiny synthetic
asset tree, needs the `api`, `worker` and `ml` extras, no network and no
Docker. `REDSIM_E2E_SANDBOX=inprocess` runs the campaign in process for
debugging (the default `child` exercises the process boundary),
`REDSIM_E2E_POSTGRES_URL=postgresql+psycopg://...` (a migrated database)
enables the RLS lane, which skips when unset and fails when the database is
not migrated. The files are `tests/e2e/test_harness_smoke.py` (wave 3, 8
cases: asset build, bundled registration, role gates, an image campaign and
two tabular campaigns through the real child, `audit verify --all` clean then
broken, the mocked narrative) and the completion-criteria evidence of wave 4
(on `main` since `e73dea0`): `tests/e2e/test_ml_campaigns.py` (spec 26.4 to
26.9 and 26.12 to 26.15, an image and a tabular campaign each with its own
scorecard, the narrative on and off), `tests/e2e/test_ml_verify_upload_reports.py`
(26.15 measured ΔMRI through `compare`, 26.17 ONNX accepted and pickle
refused with the audit row, the six report sections and `report.pdf` as 501)
and `tests/e2e/test_ml_governance.py` (26.21 and 26.22: the RBAC negative
matrix, the RLS negatives on the Postgres lane, `audit verify --all` passing
then failing after a mutation, no Pythia secret in the capabilities body), 22
cases in all. Since wave B0 the tier runs on every PR and push in the
`E2E tier (python, eager Celery)` CI job with the Postgres lane on. Every
number an e2e run produces is a harness measurement on a test double, never a
demo result. See
[`tests/e2e/README.md`](https://github.com/IntelliBridge/ndia-red-team-simulator/blob/main/tests/e2e/README.md).
The web vitest suite was last recorded at 274 passed (`7240220`) and was not
re-run for this revision.

### Pythia

Every LLM call goes through Pythia. Set these on the worker (the `default`
pool in compose) when the narrative should run:

| Variable | Meaning |
|---|---|
| `PYTHIA_BASE_URL` | Gateway base URL. The client posts to `{PYTHIA_BASE_URL}/v1/chat/completions`. |
| `PYTHIA_API_KEY` | `pk_...` gateway key, sent as `Authorization: Bearer`. The only LLM credential anywhere. |
| `PYTHIA_PERSONA` | Optional, sent as `X-Pythia-Persona`. |
| `PYTHIA_TIMEOUT_S` | Optional request timeout, default 60. |
| `REDSIM_ML_LLM_MODEL` | Canonical model id, `<vendor>/<model>` or `pythia/auto`, for the hardening narrative. `AEGIS_ML_LLM_MODEL` and `REDSIM_LLM_MODEL` are read as deprecated aliases. |
| `REDSIM_DISABLE_LLM` | Truthy skips the narrative (rules only). |

When any required variable is missing the narrative is skipped, not faked:
recommendations render from the rule layer with `narrative_source = "rules"`
and the UI says so. The narrative runs in the worker parent after the sandbox
child returns, through `redsim.llm.router.route("ml.harden_narrative")` with
the database budget checker. The prompt and completion are stored as
artifacts with their digests on the `harden.execute` audit row, and one
`LLMUsage` row is written per call. The child holds no Pythia variables: the
sandbox parent points it at an absent `.env` (`REDSIM_ENV_FILE`) and sets
`REDSIM_DISABLE_LLM=1` (`c3868e5`). There are no provider keys: since
`7556b22` `.env.example` names `PYTHIA_API_KEY` as the only LLM credential
and documents every spec 20.3 ML variable with empty values. The values live
in `.env` at the repo root, which is gitignored and dockerignored, and the
Aikido pre-commit hook scans staged files for secrets.

Behind the corporate TLS proxy the client verifies against the OS trust store
by default (`REDSIM_TLS_TRUSTSTORE=1` through the `truststore` package), or
against `REDSIM_CA_BUNDLE` / `SSL_CERT_FILE` when that is turned off. Prove
the gateway is reachable before debugging narrative code:

```bash
.venv/bin/python -m redsim.llm.pythia_check              # lists /v1/models, runs one chat completion
.venv/bin/python -m redsim.llm.pythia_check --skip-chat  # only GET /v1/models
```

The full runbook is [`docs/ops/pythia.md`](docs/ops/pythia.md).

## Datasets

Every dataset is open, unclassified, publicly available and carries a license
stated on its distribution page (spec section 11). Nothing is committed except
the CI fixtures under `tests/ml/fixtures/`: the one-off `redsim ml
build-assets` run fetches the datasets and trains the bundled models locally.

Other teams obtain the data from the public GitHub repository
[IntelliBridge/ai-red-teaming-data](https://github.com/IntelliBridge/ai-red-teaming-data)
(head `4048a209` on 2026-09-09; CC BY 4.0 for the repository's own contents,
upstream licenses kept per file). Phase A: the military vehicles parquet
(9,444 JPEGs as bytes, MIT), the full malicious-URLs CSV (651,191 rows, CC0)
and its 128,224-row seeded eval split. Phase B (wave B0, commits `a9ba6ba3`
and `4048a209`): the UCI SMS Spam Collection verbatim with a seeded 20 percent
eval split (CC BY 4.0), the 300-image military-assets subset (CC BY 4.0,
published for owner review), the `data/garak/` copy of garak 0.16.0's
probe corpora with a reference entry recording the licence per subset, a
WordNet 3.0 reference entry (not republished) and an ATLAS release record,
every file with an `INDEX.csv` row (bytes, sha256, source, licence,
attribution) and a `MANIFEST.json` entry. No models and no CIFAR-10 are
published. The public URL CSVs are redacted copies: credential-shaped
query-parameter values are replaced with the literal `REDACTED` in 2,346 of
651,191 rows (406 of 128,224 in the eval split), with row count, order and
labels unchanged. The private build trains on the unredacted Kaggle file, so
metrics re-derived from the public copy differ slightly on those 0.36 percent
of rows (spec section 11.7). The SMS corpus was published without redaction
(owner default MODALITIES-12, reason recorded in the public `MANIFEST.json`),
so its public copy hashes to the loader's pin.

| Role | Dataset | Modality | License | Notes |
|---|---|---|---|---|
| Demo image dataset | `leibnitz-lab/military_vehicles` (HuggingFace), coarse 7-class task | image | MIT (dataset card) | Ground-level photographs, not aerial imagery. Photo copyright is not cleared by the MIT tag, so images are not redistributed in public releases or reports. Bundled model `vehicles_cnn`. |
| Image CI fixture | `uoft-cs/cifar10` (HuggingFace), test split, pinned 500-image subset committed as `tests/ml/fixtures/cifar10_test_500.npz` | image | CIFAR-10 terms | Tests only, never a demo dataset or a result. Bundled model `cifar10_smallcnn` is `fixture_only` and cannot be registered or attacked. |
| Demo tabular dataset | Kaggle `sid321axn/malicious-urls-dataset` (`malicious_phish.csv`) | tabular | CC0 (Kaggle metadata) | Lexical URL features only. URL strings are data and are never fetched, resolved or rendered as links. The download needs a Kaggle API token for the one `redsim ml build-assets` run (`KAGGLE_API_TOKEN`, or the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair), never on the API, web, steady-state worker or CI. A committed stratified sample under `tests/ml/fixtures/` serves CI. Bundled model `url_trees`. |
| Tabular fallback | `lacg030175/UNSW-NB15` (HuggingFace), config `standard` | tabular | CC-BY-4.0 | Named in the spec as the fallback if the Kaggle download cannot be completed. Not built, not wired (open item). |
| Demo text dataset (Phase B) | UCI SMS Spam Collection (`archive.ics.uci.edu/dataset/228`, Almeida and Gomez Hidalgo 2011) | text | CC BY 4.0 (UCI page) | 5,574 messages, 4,827 ham and 747 spam, zip and corpus pinned by sha256. Published verbatim to the public repository (`data/sms_spam_collection.tsv`, `data/sms_spam_eval_split.tsv`). A committed 300-row sample serves CI. Bundled model `sms_tfidf_lr` (TF-IDF word 1-2 grams plus logistic regression, `build-assets --dataset text`). Caveats recorded: 2011-era, English only, class imbalance, phone numbers present. |
| Synonym lexicon (Phase B) | WordNet 3.0 (`nltk/nltk_data` gh-pages `550b6625`, `wordnet.zip` sha256 `cbda5ea6…`) | text | WordNet 3.0 license (Princeton, BSD-style) | Fetched by `build-assets` into the gitignored asset cache for the `word_substitution` attack; not republished (reference entry only). A 47-entry JSON fixture serves CI. |
| Demo detection dataset (Phase B, pending owner review) | Kaggle `rawsi18/military-assets-dataset-12-classes-yolo8-format`, a capped seeded subset of 300 images and 607 boxes in 4 classes (`military_tank`, `military_truck`, `military_vehicle`, `military_aircraft`) | detection | CC BY 4.0 (Kaggle metadata) | Published as `data/military_assets_subset/` (52 MB) for the owner to confirm under plan 12 decision MODALITIES-27, removable in one commit. Person and weapon classes excluded by construction. The full 4.1 GB archive is cached locally only; Kaggle throttles per-file downloads. Bundled model `assets_frcnn_mnv3` (`build-assets --dataset detection`, named explicitly). |
| ATLAS technique data (Phase B) | `mitre-atlas/atlas-data` release `v2026.08` | reference | Apache-2.0 | Vendored as constants in `redsim/ml/atlas_data.py` with the data file's sha256 and the licence text; finding stamping is wave B3. |
| LLM probe corpora (Phase B) | garak 0.16.0 `garak/data` | text | Apache-2.0 (garak packaging), upstream terms per subset | Loaded by garak itself, never re-packaged by redsim; the public repository carries a copy and a reference entry with the per-subset licences (owner decision TESTS_DOCS-33). Probing is waves B2 and B4. |
| Unit-test doubles | `TinyTarget` and `TinyTabularTarget` in `tests/ml/fakes.py`, `TinyTextTarget` in `tests/ml/fakes_text.py`, `TinyDetector` in `tests/ml/fakes_detection.py`, `TinyEndpointServer` in `tests/ml/tiny_endpoint_server.py` | image, tabular, text, detection, endpoint | in-repo | Random-weight or synthetic models, no download. |

Illustrative numbers from one local build (2026-09-09, one laptop CPU), read
from that build's `assets/MANIFEST.json` and not a product claim: `url_trees`
(scikit-learn HistGradientBoosting on 16 lexical features) reached clean
accuracy 0.9087 on the 128,224-row eval split, with the PGD surrogate agreeing
with the ensemble on 0.7891 of it. `vehicles_cnn` built with `--arch resnet18`
(ImageNet init from the local torch hub cache, fine-tuned 12 epochs at lr 3e-4
with a cosine schedule and flip / crop augmentation) reached 0.7687 on the
1,621-image `test_coarse` split, where the earlier `small_cnn` build reached
0.5151. `cifar10_smallcnn` reached 0.6872 on the 10,000-image test split and
is a fixture only. Your build's manifest is the only source for your numbers.

## Demo path

The demo script is section 24 of the product spec, and every number in it is
illustrative: the live values are what is shown and said. In outline, with the
stack up and the bundled models registered:

1. `/models`: the bundled targets show as `available` with dataset, license,
   pinned revision, model sha256 and the clean accuracy read from the
   manifest, under the bounds banner (open, unclassified data, robustness
   evaluation only).
2. Run attack on the vehicle CNN: FGSM and PGD, eps grid `{0.01, 0.03, 0.1}`
   with reference `0.03`, the noise control on. The admission writes the audit
   row before the job is queued.
3. `/runs/[id]`: the stage timeline, then the MRI scorecard together with its
   five subscores, the per-family table with denominators and the robustness
   curve. The grade describes robustness under these attacks at this grid on
   this slice and is not a readiness statement.
4. The finding: clean versus adversarial versus control image, SHAP clean
   versus adversarial with the heuristic and inferred labels, and the
   candidate recommendations with no expected gain.
5. Verify fix with a preprocessing defense: the same settings re-run, the
   measured ΔMRI shown as measured whether it is positive, zero or negative.
6. The tabular campaign on `url_trees` (PGD by surrogate transfer plus
   HopSkipJump): its own MRI, never combined with the image campaign's, with
   the realizability caveat on every row.
7. Honest edges: the endpoint connector, the LLM domain and the text and
   detection campaigns shown as not implemented with their reason (the
   library is on `main`, admission is wave B2), the Phase B routes answering
   501 with the wave that builds them. A dismissal by a second identity that
   the campaign creator cannot perform.
8. `/audit` and `redsim audit verify --all` on the chain.
9. The Markdown or HTML report with configuration and provenance,
   measurements by family, observations, interpretation, candidates, the
   score and the limitations.

The offline equivalent for a laptop without the stack is step 3 of the
Quickstart (`redsim ml attack`, `3ab9de7`).

## Make targets

| Target | What it runs |
|---|---|
| `make install` | Venv, `uv pip install --native-tls -e ".[$(EXTRAS)]"` (or pip), `pnpm install` |
| `make require-install` | Fails fast with one clear line when `.venv` or `node_modules` is missing. |
| `make dev` | pytest, then `dev-api` and `dev-web` under `make -j` |
| `make dev-api` | `uvicorn redsim.api.app:create_app --factory --reload --port 8000` |
| `make dev-web` | `pnpm --filter @redsim/web dev` on :3000 |
| `make dev-worker` | `celery -A redsim.workers.celery_app worker -Q scans,default`. Not on the `dev` line, needs Redis and Postgres first. |
| `make test` | `pytest -q` plus `pnpm --filter @redsim/web test` |
| `make test-cov` | pytest with `--cov=redsim --cov-report=term-missing` |
| `make lint` | `lint-py` (bare `ruff check redsim tests`, wider than CI's selection) then `lint-web` (printed as a skip line while `web/` has no ESLint config) |
| `make typecheck` | `typecheck-py` (`mypy redsim`) then `typecheck-web` (`tsc --noEmit`) |
| `make check` | lint, typecheck, test |
| `make up` / `make down` | `docker compose -f deploy/docker-compose.yml up -d --build` / `down` |
| `make docs-serve` / `docs-build` / `docs-build-strict` / `docs-clean` | MkDocs Material on :8001. The recipes call `mkdocs` from `PATH`, so activate the venv or pass `MKDOCS=.venv/bin/mkdocs`. |

The CI contract is in [`docs/dev/ci.md`](docs/dev/ci.md).

## Layout

```
redsim/                 Python package (renamed from aegis on 2026-09-08)
  api/                  FastAPI app factory, /v1 routers, middleware, auth, policy, errors.py (spec 17.3 codes)
  audit/                hash-chained audit log: chain, writers, forensic export, redaction
  cli/                  `redsim` console script: doctor, audit verify/export, plugins, ml build-assets / attack / seed, ...
  db/                   SQLAlchemy models, session, Alembic migrations 0001-0011
  llm/                  per-task routing, budgets, pricing, guardrails, Pythia transport and check
  log_ingest/           OTLP logs to Postgres mirror service
  migrate/              filesystem to Postgres migration helpers
  ml/                   the adversarial-ML vertical: frozen schema, targets (bundled image, tabular, text, detection,
                        endpoint), attacks, defenses, harden/ (training defenses), eval, scoring, the campaign frame and
                        runners/ (one per modality), explain, recommend, reporting, sandbox parent and child, the endpoint
                        predict broker and egress policy, assets builder and datasets, atlas_data
  policy/               static / OPA / Cedar policy engines behind the RBAC check
  scanners/             registry, capability vocabulary, out-of-process plugin sandbox
  services/             admission services (audit event, Run/Job rows, enqueue): ml_models, ml_campaigns, ml_findings, ...
  state/                run-state facade: filesystem and Postgres backends
  storage/              blob store: filesystem, S3/MinIO, WORM export
  supply_chain/         plugin signing
  workers/              Celery app, job state machine, tasks/ (ml_campaign, ml_model, reaper, report, ...)
web/                    Next.js 14 app (@redsim/web): app router pages, NextAuth, api() client
packages/design-system/ @redsim/design-system: curated components over shadcn primitives
tests/                  pytest suite (unit, integration, ml, garak markers), tests/ml/ for the vertical, tests/e2e/ the end-to-end tier (harness, smoke file, three wave-4 files)
assets/                 bundled models, datasets and MANIFEST.json written by `redsim ml build-assets` (gitignored)
deploy/                 docker-compose.yml, Dockerfile.{api,worker,web,postgres,log_ingest}, helm, terraform, keycloak, opa, cedar, otel, loki, certs
docs/                   product spec, project brief, plans and gap register, architecture docs and diagrams, ADRs, ops and dev guides
specs/                  Spec Kit feature layer: F001-F008 plus _shared/ (decisions, architecture, readiness)
.specify/               Spec Kit constitution and templates
.github/                redsim-ci.yml, deploy-aws.yml, docs.yml, release-sign.yml, dependabot
hooks/                  mkdocs build hooks (README as the docs index, cross-tree links)
exports/                ai-assurance-spec-pack.zip (spec pack export)
alembic.ini             Alembic entry point for redsim/db/migrations
redsim.yaml             default runtime configuration read by redsim/config.py
mkdocs.yml              docs site configuration
pyproject.toml          package metadata, extras, pytest markers, ruff and mypy settings
pnpm-workspace.yaml     web and packages/design-system workspaces
```

## Documentation

Read in this order. Where two documents disagree, the earlier one in this list
wins.

| Doc | What it is |
|---|---|
| [`docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`](docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md) | The consolidated product spec, 27 sections: scope and phasing, domain model, architecture, model loading and isolation, job and worker flow, datasets, attacks, SHAP, MRI scoring, recommendations, API surface, web UI, deployment, testing, demo script, completion criteria, Phase B2 interoperability. |
| [`docs/project-brief.md`](docs/project-brief.md) | Governance brief. Its reporting principles are design constraints, and its "Decisions taken (2026-09-08)" section records the product owner's decisions and every knowing divergence. |
| [`specs/README.md`](specs/README.md) and `specs/00N-*/` | Spec Kit feature layer beneath the product spec: F001 project access through F008 audit and governance, each with `spec.md`, `plan.md`, `tasks.md`. `specs/_shared/` holds the decision register (D006 and D007 open), the shared architecture and the readiness checklist. |
| [`docs/plans/00-master-plan.md`](docs/plans/00-master-plan.md), `docs/plans/01` to `08`, [`docs/plans/09-gap-register-2026-09-08.md`](docs/plans/09-gap-register-2026-09-08.md) | The coordination plan (workstreams, corrected shared contracts, integration waves), one phase file per plan step, and the spec-versus-tree gap register that orders the completion waves. Section 8 of [`01-p0-contracts-api-skeleton.md`](docs/plans/01-p0-contracts-api-skeleton.md) is the change protocol for everything P0 froze and where accepted divergences are recorded. |
| [`docs/plans/10-remaining-work-brief.md`](docs/plans/10-remaining-work-brief.md), [`docs/plans/11-phase-b-register-2026-09-09.md`](docs/plans/11-phase-b-register-2026-09-09.md), [`docs/plans/12-phase-b-plan.md`](docs/plans/12-phase-b-plan.md) | The remaining-work brief (packages A to F: compose operations, CI parity, process-gate documents, residual Phase A rows, infrastructure completion, the data-poisoning module), the 309-item Phase B register, and the Phase B execution plan (owner decisions with defaults, the schema additions, the datasets, waves B0 to B4 with a dated status line per wave). |
| [`docs/spec-driven-workflow.md`](docs/spec-driven-workflow.md) | How the team works spec-first with Spec Kit's stages. The Spec Kit CLI is not installed. |
| [`docs/architecture/ml-vertical.md`](docs/architecture/ml-vertical.md) and [`docs/architecture/diagrams/`](docs/architecture/diagrams/README.md) | The vertical as built and the current pictures: platform architecture, attack-campaign sequence, campaign-run lifecycle. |
| [`docs/architecture/overview.md`](docs/architecture/overview.md), [`auth.md`](docs/architecture/auth.md), [`audit-chain.md`](docs/architecture/audit-chain.md), [`multi-tenancy.md`](docs/architecture/multi-tenancy.md), [`observability.md`](docs/architecture/observability.md) | Platform architecture inherited from aegis. `auth`, `audit-chain`, `multi-tenancy` and `observability` still hold. `overview.md` still carries pentest-era sections that no longer exist. |
| [`docs/api/v1.md`](docs/api/v1.md), [`docs/api/endpoint-contract.md`](docs/api/endpoint-contract.md) | The `/v1` routes with their gates, error codes and the "Phase B, 501 until built" table, and the `endpoint-v1` predict contract a black-box inference endpoint has to speak. |
| [`docs/dev/local-stack.md`](docs/dev/local-stack.md), [`testing.md`](docs/dev/testing.md), [`ci.md`](docs/dev/ci.md), [`frontend.md`](docs/dev/frontend.md), [`extending.md`](docs/dev/extending.md), [`docs.md`](docs/dev/docs.md) | Developer guides: the compose stack, test plumbing, the CI contract, the web workspace, the extension points (registries, `Target` and `AttackAdapter`, defenses, plugins), the docs build. |
| [`docs/ops/deploy.md`](docs/ops/deploy.md), [`kubernetes.md`](docs/ops/kubernetes.md), [`pythia.md`](docs/ops/pythia.md), [`compliance-evidence.md`](docs/ops/compliance-evidence.md) | Operator guides: production env vars, keys and rotation, the Helm chart, the LLM gateway, the evidence pack. |
| [`docs/adr/0002-registry-seam-and-runners.md`](docs/adr/0002-registry-seam-and-runners.md), [`docs/adr/0004-unified-effect-class-gate.md`](docs/adr/0004-unified-effect-class-gate.md) | The two seams the ML attack adapters reuse: the registry and the effect-class gate. Written for the pentest domain, kept as history. The other ADRs ([`0001`](docs/adr/0001-vendored-submodules.md), [`0005`](docs/adr/0005-worker-autoscaling-and-dr.md), [`0008`](docs/adr/0008-nix-reproducible-builds.md)) record platform decisions. |
| [`CLAUDE.md`](CLAUDE.md) | The working guide for the tree: routes, tasks, CLI, environment variables, test tiers, accepted divergences, verified state and the rules for changing anything. |
| [`SECURITY.md`](SECURITY.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), [`CHANGELOG.md`](CHANGELOG.md) | Security model and boundaries, contribution rules and gates. `CHANGELOG.md` is the aegis release history up to the fork. |

Superseded and kept for history only: `docs/adversarial-ml-redteam-spec.md`
(and its `.html`) and `docs/superpowers/specs/2026-09-08-redsim-design.md`.

## Open items and not implemented

Everything in this list is open. None of it is done, approved or waived, and
nothing in the UI, the CLI or the reports pretends otherwise. Waves B0 and B1
closed the items they built (the Phase B contracts, stubs, datasets and the
library layer), and those are no longer listed here.

- **Web UI.** The one deferral of the Phase B plan. PR #22 aligned
  `@redsim/web` with the mounted routes, #24 and #25 added tRPC, env
  management and the design reference, and the pages render
  `not_implemented` states honestly, but the pages have not been exercised in
  a browser against a running stack with real campaign data, the upload
  dialog stays disabled (spec 26.18, below), no page exists for the Phase B
  modalities, endpoints, probes, batches or review states, and the Playwright
  stack e2e (`workflow_dispatch` with `run_e2e=true`) has not been run. The
  `tests/e2e` tier covers the API, worker, sandbox and CLI, not a browser.
- **Phase B waves B2 to B4** (`docs/plans/12-phase-b-plan.md` section 5).
  Not started. Until they land: `POST /v1/models` with `source: endpoint`,
  campaigns on `text`, `detection` and endpoint targets, the `edit` and
  `patch_area` norms, verify with `adversarial_training` or
  `defensive_distillation`, LLM probing through Pythia, review transitions
  beyond dismissal, `report.pdf`, snapshots, N-run compare, per-project
  scoring weights, `Idempotency-Key`, Croissant export and consume, ATLAS
  stamping and coverage, the Foundry push, batch campaigns, bulk upload, bulk
  verify and capacity all answer `501 not_implemented` with `phase: "B"` and
  the wave that builds them. The library behind the B2 items is on `main`
  (wave B1) and is exercised by the `ml` tier only.
- **Owner decisions** (plan 12 section 2, each with the recommended default
  the code follows until the owner rules otherwise): ENDPOINT-26 (no DNS-TXT
  ownership check for endpoints; egress allowlist plus admin registration
  plus attestation), LLM-08 (HarmBench excluded), LLM-26 (a separate Pythia
  persona and key for probe traffic), MODALITIES-12 (SMS corpus published
  verbatim, applied), MODALITIES-27 (the 300-image military-assets subset is
  published for review and removable in one commit), MODALITIES-36
  (detection carries a scorecard, never an MRI), REVIEW_REPORTS-13 (no
  `reviewer` role), REVIEW_REPORTS-33 (no pickle override),
  REVIEW_REPORTS-35, -36, -41, -42 (membership administration and retention
  purge deferred to the platform team), INTEROP-26 (Foundry tested against a
  fake endpoint), INTEROP-27 / TESTS_DOCS-41 (Lattice as text only),
  INTEROP-30 (B2 deployment posture as a runbook item), INTEROP-34 (imagery
  exports stay in the artifacts bucket), BULK-16 (one defended run projected
  onto N findings), TESTS_DOCS-33 (the public `data/garak/` publication
  recorded with per-subset licences). Two smaller confirmations from wave B0:
  `dataset.export` gates at `scanner` (the brief) where the register said
  `remediator`, and five stub paths follow the brief rather than the
  register.
- **The remaining-work brief** (`docs/plans/10-remaining-work-brief.md`),
  executed outside the Phase B waves: package A compose-stack operations
  (the stack has not been brought up end to end and spec 26.1's
  clone-to-first-run time is unrecorded), B CI parity, C the process-gate
  documents that need named human reviewers (spec 26.18 upload sign-off, so
  the upload dialog stays disabled and says why; 26.25 readiness checklists;
  26.26 approval records; 26.27 the separate "done" record; D006 and D007 stay
  OPEN in `specs/_shared/decisions.md` with no owner invented), D residual
  Phase A rows, E infrastructure completion (the #23 runtime's pinned asset
  bundle, demo users and memberships, real assets, automatic rollout, Helm
  install; no campaign has been run on it) and F the data-poisoning
  evaluation module (decision D14).
- **Recorded non-builds**: `adv_patch` (MODALITIES-32; `dpatch` is the
  detection attack), KernelSHAP for images (ATTACKS_HARDEN-08;
  `PartitionExplainer` stays), ART's `DefensiveDistillation` (a native torch
  distillation is used and the ART class cited), connection IP pinning in the
  predict broker (the resolve-once session pin exists, the pinned-connect
  transport does not), the fallback datasets `lacg030175/UNSW-NB15` and the
  aircraft image fallback of spec 11.3.2, and the query-budget codes
  `auth_profile_required`, `auth_profile_in_use`, `query_budget_exceeded`
  and the bulk and idempotency codes the register names but the brief did
  not (added with their wave, one `errors.py` row plus one spec addendum row
  together).
- **CI.** The Redsim CI run for the `29db42c` push, the first with the
  `e2e-python` and `garak-offline` jobs, had not been read when this README
  was written; the last run read is `58461cc` (red on three jobs whose causes
  wave 4 fixed). Nothing is claimed green until a run on `main` is read. The
  counts in this README are local runs from the wave B0 integration.

## Team conventions

- Commits are `type(topic): description` with the trailer
  `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Branch before committing. Never commit to `main` directly. The repository
  allows squash merges only and deletes the branch on merge.
- Work spec-first: a changed requirement updates the spec before
  implementation continues. See
  [`docs/spec-driven-workflow.md`](docs/spec-driven-workflow.md) and the
  readiness checklist in `specs/_shared/`.
- Anything P0 froze (schema fields, migration head, `Action` values, the
  campaign response shape, `REDSIM_ML_LLM_MODEL`) changes only through the
  protocol in section 8 of `docs/plans/01-p0-contracts-api-skeleton.md`, which
  also records the accepted divergences listed in [`CLAUDE.md`](CLAUDE.md).
  Phase B wave B0 used it once (additive schema fields, the head moved to
  `0011`, seven new `Action` members), announced in master plan section 0 and
  guarded by `tests/ml/test_schema_compat.py`.
- Prose in docs and comments avoids em dashes and semicolons.
- No fixture data is ever presented as a result, illustrative numbers are
  labelled illustrative, and unimplemented paths are shown as unavailable with
  a reason, never faked.

## Provenance

This repository is `IntelliBridge/ndia-red-team-simulator`, forked from
`IntelliBridge/aegis` (restored from aegis head `5eb24ca` and then pruned).

Removed for good: the 14 pentest scanner adapters, `aegis/agents`,
`aegis/tools`, `aegis/integrations`, `aegis/remediate`, `aegis/runners`, the
Kali image, the CAI agents, the GitHub App and webhooks, ticketing, the CI
gate, demo and vendor tooling, every git submodule, and the `agents` and
`tools` web pages.

Names: on 2026-09-08 the product owner amended decision D7 and every
identifier was renamed to redsim (commit `b39d933`). The Python namespace is
`redsim` (`import redsim...`), the console script is `redsim`, environment
variables are `REDSIM_*`, the API title is "Redsim API", the session and CSRF
cookies are `redsim_api_session` and `redsim_csrf` with the `X-Redsim-CSRF`
header, the compose services, images and Helm chart are `redsim-*` and
`deploy/helm/redsim`, the web workspace packages are `@redsim/web` and
`@redsim/design-system`, the config file is `redsim.yaml`, and the product and
UI name is redsim. `aegis` survives only as the name of the upstream fork.

License: Apache-2.0.

Proof of concept on open, unclassified public data. Results are evidence for
human review, not a safety, readiness, or certification determination.
