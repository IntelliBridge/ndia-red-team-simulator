# redsim (Adversarial ML Red-Team Simulator)

redsim stress-tests machine-learning models before anyone relies on them. A
user picks a model, launches a test, and reads the evidence: how the model
behaved under attack, why (SHAP), what a reviewer could try next, and a
hash-chained audit trail of every step. Every run is a measurement in its own
right, and every result is written for human review.

Live demo: https://redsim.ndia.agiledefense.xyz (sign-in required).

## What it does

- **Adversarial evasion campaigns against classifiers.** ART attacks (FGSM,
  PGD, Carlini-Wagner L2, DeepFool, HopSkipJump, ZOO) across an epsilon sweep,
  each paired with a benign random-noise control so a drop in accuracy is
  attributed to the attack and not to noise. Image, tabular, text
  (word substitution) and object-detection (DPatch) modalities.
- **A Model Robustness Index (MRI) per campaign.** Five subscores, a
  per-family table with denominators and the epsilon curve. The MRI is never
  shown without them, and a grade always carries the sentence that it
  describes measured behaviour under the declared attacks and nothing more.
- **SHAP as supporting evidence.** Per-modality explainers with an
  explanation-stability signal, kept in a separate panel from the
  measurements.
- **Candidate hardening recommendations.** Rule-based candidates, with an
  optional LLM narrative through the Pythia gateway. Every recommendation is
  labelled `candidate` and carries no expected gain, because the product has
  not evaluated it against the model.
- **LLM probes.** NVIDIA garak probes (a committed catalog of 103, 76 in the
  offline core set) run against an LLM target through Pythia, scored as
  hits over evaluated replies, never as an MRI.
- **Black-box endpoints.** Register a remote predict endpoint under the
  `endpoint-v1` contract and attack it through a worker-side broker with a
  request budget. Credentials live in encrypted auth profiles and never reach
  the sandbox.
- **Bring your own model.** Upload an ONNX or PyTorch `state_dict` artifact,
  or fetch open-weights checkpoints from Hugging Face through the same path.
  Uploads are statically checked in the API and opened only inside the worker
  sandbox. Pickle is refused.
- **Findings with a review workflow.** Attack and probe results project into
  findings that a reviewer confirms, dismisses, reopens or resolves.
  Independence is enforced by identity. A finding chat drawer answers
  questions from the recorded evidence and can propose the next campaign,
  which the analyst runs with one click.
- **Reports, snapshots and evidence packs.** Markdown, JSON, HTML and PDF
  reports, immutable report snapshots, and a signed, offline-verifiable
  evidence pack per run (`redsim evidence verify` needs no server).
- **Interoperability.** Croissant and Parquet dataset export of a campaign's
  slices, ATLAS technique coverage per run, batch campaigns, bulk upload, and
  an optional push of the scorecard to a Palantir Foundry dataset.
- **Platform.** Multi-tenant projects with RBAC and Postgres row-level
  security, a hash-chained audit log with WORM export, per-task LLM routing
  and budgets, OpenTelemetry, and a web app with a dashboard, models, runs,
  tests, findings, exports and audit pages.

## What it does not do

redsim is a non-operational proof of concept on open, unclassified, public
data. It never trains, optimizes or deploys targeting or weapons models, it
connects to no mission system, and it applies no defense to any model. No
score, grade or finding it produces is a safety, readiness or certification
statement. The product enforces this: a banned-vocabulary check refuses
readiness words in every score, report and export payload, and the web footer,
the reports and the chat drawer repeat the boundary. Unsupported paths answer
`not_implemented` with a reason instead of a placeholder.

## Architecture

```
browser ── Next.js web (login, dashboard, evidence panels, chat drawer)
              │  cookie session + CSRF
              ▼
         FastAPI /v1 ──── Postgres (RLS, audit chain, Alembic) ─── Redis ─── S3/MinIO
              │  audit row first, then Run + Job, then enqueue
              ▼
         Celery workers ── sandbox child (rlimits, no secrets, no network)
              │                 └── torch / ART / SHAP / ONNX: the only place model bytes open
              ├── endpoint broker (the only outbound HTTP of the vertical)
              └── Pythia gateway (narrative, garak probes)
```

- **API process** (`redsim/api/`): admission only. It validates, writes the
  audit row, creates the `Run` and `Job` rows and enqueues. It never imports
  torch, ART, ONNX, SHAP, garak or pyarrow (a test builds the app with them
  blocked).
- **Workers** (`redsim/workers/`): one Celery job per campaign, run inside a
  credential-free sandbox child with CPU, memory, thread and wall-clock
  limits. The worker parent turns the child's envelope into artifacts,
  findings, reports and audit rows.
- **ML vertical** (`redsim/ml/`): targets, attacks, scoring, explainers,
  recommendations, reports, the modality runners, the endpoint broker, the
  garak integration and the interop modules. `redsim/ml/schema.py` is the
  frozen contract every record follows.
- **Web** (`web/`, `packages/design-system/`): Next.js 14 with tRPC, an
  email-and-password login against Keycloak from the server, and evidence
  panels that keep measurements, observations, interpretation and candidate
  recommendations apart.

Details: [`docs/architecture/overview.md`](docs/architecture/overview.md),
[`docs/architecture/ml-vertical.md`](docs/architecture/ml-vertical.md),
[`docs/api/v1.md`](docs/api/v1.md) and the diagrams under
`docs/architecture/diagrams/`.

## Quickstart

### Prerequisites

- Python 3.12 and [uv](https://github.com/astral-sh/uv).
- Node 22+ and pnpm 10 for the web app.
- Docker with Compose v2 for the full stack.

### 1. Install

```bash
make install            # .venv with the api, worker, test, dev and ml extras, then pnpm install
.venv/bin/redsim doctor # checks the environment; --worker-mode also checks the ML extra and the sandbox
```

### 2. Build the bundled models

A fresh clone has no models. The build fetches the open datasets by pinned
revision and trains the bundled models on CPU. Everything it writes under
`assets/` is gitignored.

```bash
.venv/bin/redsim ml build-assets --dataset all               # image, tabular, CIFAR-10 fixture and text
.venv/bin/redsim ml build-assets --dataset cifar10 --fixture  # the small CI slice only
```

The tabular download needs a Kaggle token (`KAGGLE_API_TOKEN` in the
environment or `.env`). Without one the build falls back to the committed
sample and marks the model `fixture_only`.

### 3. Run one campaign offline

No database, no network, no LLM. The run writes the record, the reports, the
curve and a hash-chained audit log under `redsim_output/<run_id>/`.

```bash
.venv/bin/redsim ml attack url_trees --attacks fgsm,pgd --n-samples 200
.venv/bin/redsim audit verify --run <run_id>
```

### 4. Run the full stack

```bash
make up                 # postgres, redis, keycloak, minio, api :8000, workers, beat, web :3300
```

Open http://localhost:3300 and sign in with the local realm's admin,
`admin@redsim.local` / `adminpass` (a development credential shipped in
`deploy/keycloak/realm-export.json` for the local stack only). Register a
bundled model on the Models page, launch a campaign, and follow the run on the
Runs page. The compose stack mounts `./assets` into the API and the workers.
[`docs/dev/local-stack.md`](docs/dev/local-stack.md) covers the profiles,
the observability stack and the CLI in API mode.

### 5. Run the tests

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider              # default tier, no services needed
.venv/bin/python -m pytest -q -p no:cacheprovider -m ml        # the tests that need the ml extra
REDSIM_E2E=1 .venv/bin/python -m pytest -q -m e2e tests/e2e    # real API, worker, sandbox child and CLI
make check                                                    # ruff, mypy, pytest, web typecheck and vitest
```

### LLM access

Every LLM call goes through the Pythia gateway. Set `PYTHIA_BASE_URL`,
`PYTHIA_API_KEY` and `REDSIM_ML_LLM_MODEL` in `.env` for the hardening
narrative and the finding chat. LLM probes use a separate probe key held in an
auth profile. Without a gateway the recommendations render from the rule
layer alone and the UI says so. See
[`docs/ops/pythia.md`](docs/ops/pythia.md).

## Datasets and models

| Bundled target | Modality | Data | Licence |
|---|---|---|---|
| `vehicles_cnn` (ResNet-18) | image | `leibnitz-lab/military_vehicles` (Hugging Face), coarse 7-class task | MIT |
| `url_trees` (gradient-boosted trees) | tabular | Kaggle `sid321axn/malicious-urls-dataset`, lexical URL features only | CC0 |
| `sms_tfidf_lr` (TF-IDF + logistic regression) | text | UCI SMS Spam Collection | CC BY 4.0 |
| `assets_frcnn_mnv3` (Faster R-CNN) | detection | a 300-image subset of Kaggle `rawsi18/military-assets-dataset-12-classes-yolo8-format`, vehicle and aircraft classes only | CC BY 4.0 |
| `cifar10_smallcnn` | image | `uoft-cs/cifar10` | fixture for CI only, never served |

Clean accuracy and per-class counts are recorded in `assets/MANIFEST.json`
by the build in hand and read from there by the UI and the reports. The
datasets are also published for other teams at
https://github.com/IntelliBridge/ai-red-teaming-data. ATLAS technique ids
come from a vendored copy of MITRE ATLAS.

## Layout

```
redsim/            the Python package: api/, workers/, services/, db/, audit/, llm/, ml/, cli/
redsim/ml/         targets, attacks, scoring, explain, recommend, runners, llm (garak), interop, sandbox
web/               @redsim/web (Next.js 14)          packages/design-system/  @redsim/design-system
tests/             default tier, tests/ml (ml extra), tests/e2e (real API, worker, sandbox, CLI)
deploy/            docker-compose.yml, Dockerfile.*, helm/redsim, ec2/ (the demo host), keycloak/, opa/, cedar/
docs/              architecture, API reference, operations, development, security (mkdocs site)
scripts/           demo.sh, smoke_live.sh, hf_open_weights_fetch.sh, hf_open_weights_demo.py, verify-release.sh
```

## Documentation

| Where | What |
|---|---|
| [`docs/architecture/overview.md`](docs/architecture/overview.md) | The platform: layers, tenancy, audit chain, auth, observability |
| [`docs/architecture/ml-vertical.md`](docs/architecture/ml-vertical.md) | The ML vertical end to end: admission, sandbox, attacks, scoring, explain, reports, accepted divergences |
| [`docs/api/v1.md`](docs/api/v1.md), [`docs/api/endpoint-contract.md`](docs/api/endpoint-contract.md) | Every `/v1` route with its refusal codes, and the `endpoint-v1` predict contract |
| [`docs/interop.md`](docs/interop.md) | Croissant export, consumed datasets, ATLAS coverage, the Foundry push |
| [`docs/ops/pythia.md`](docs/ops/pythia.md), [`docs/ops/deploy.md`](docs/ops/deploy.md), [`deploy/ec2/README.md`](deploy/ec2/README.md) | The LLM gateway, production deployment, the demo host |
| [`docs/dev/testing.md`](docs/dev/testing.md), [`docs/dev/ci.md`](docs/dev/ci.md) | Test tiers and the CI contract |
| [`SECURITY.md`](SECURITY.md), [`CONTRIBUTING.md`](CONTRIBUTING.md) | Security model and boundaries, contribution rules |

`make docs-serve` renders the docs site with MkDocs Material.

## Known limitations

- The web UI has been exercised against the compose stack and the demo host
  by hand. There is no browser end-to-end suite in CI.
- The finding chat writes no audit or usage row per turn, and its system
  prompt carries the reporting rules as instructions rather than as an
  enforced check. The evidence panels remain the record.
- The detection modality carries a scorecard, never an MRI, and has no
  explainer.
- The PDF renderer cannot typeset a very wide measurement table. The run then
  keeps the Markdown, JSON and HTML reports and records `pdf_unavailable`.
- Endpoint targets are admitted by an egress allowlist and an audited
  attestation. There is no DNS ownership check.
- The Foundry push has been proven against a fake server in CI and against a
  developer-tier Foundry instance by hand.
- Numbers in the docs are illustrative unless they come from the manifest or
  the record in hand.

## Provenance

redsim is a fork of IntelliBridge's `aegis` security platform. The
penetration-testing domain was removed and the adversarial-ML vertical added
in September 2026. The `aegis` name survives only where it refers to the
upstream project.

Built for the NDIA hackathon.
