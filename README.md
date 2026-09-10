# redsim (Adversarial ML Red-Team Simulator)

redsim stress-tests a machine-learning classifier under adversarial evasion
attacks before anyone relies on it. A user picks a model (a bundled sample or
an uploaded ONNX or PyTorch `state_dict` artifact), launches an attack campaign
(ART attacks such as FGSM, PGD and HopSkipJump across an epsilon sweep, each
paired with a benign random-noise control), and reads the SHAP explanation and
the candidate hardening recommendations side by side, with every step recorded
on a hash-chained audit log. Every run is a measurement in its own right. Two
compatible campaigns can be compared side by side, variable by variable, and
findings close by reviewer decision (product owner decision of 2026-09-09,
`docs/project-brief.md` item 16).

What it does not do. It is a non-operational proof of concept on open,
unclassified, public data. It evaluates the robustness of a classifier and
nothing else: it never trains, optimizes or deploys targeting or weapons
models, it connects to no mission system, it applies no defense to any model,
and no score or grade it produces is a safety, readiness or certification
statement. Measurements, per-sample observations, inferred interpretation and
candidate recommendations are kept in separate fields and separate UI panels,
every succeeded run carries its limitations, and every recommendation is a
candidate that the product has not evaluated against the model. Fixture data
is never served as a result, and unsupported paths answer `not_implemented`
with a reason instead of a placeholder.

The product is built as one vertical, `redsim/ml/`, inside the redsim
platform. This repository is a fork of IntelliBridge's aegis security platform
with the penetration-testing domain removed and, since 2026-09-08, every
identifier renamed to redsim (see Provenance).

## Status

As of 2026-09-09, `main` is at `703f8f6`: the four Phase A completion waves
(wave 4, the end-to-end completion-criteria files and the CI fixes, integrated
by `e73dea0`) and Phase B waves B0 (contracts, tripwires, stubs, datasets,
`934838e..29db42c`), B1 (the library layer, integrated by `1439f92`), B2 (the
services, workers and routes over that library, integrated by `57da31f`) and
B3 (interoperability and bulk operations, integrated by `703f8f6`). Phase B
wave B4 (the end-to-end evidence for everything B2 and B3 built, the `make
check-phase-b` gate with the docs-consistency test, the fix pass those files
demanded and this documentation pass) is pushed to `main` together with this
README; every statement below marked "wave B4" was verified from that tree
(routers, services, tasks and tests), not from the writers' reports. The
decisions behind this table are in
[`docs/project-brief.md`](docs/project-brief.md) under "Decisions taken", the
target design is the
[product spec](docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md)
(its 3.2, 17.4, 22.6 and 26.7 addenda record the Phase B status), the Phase A
spec-versus-tree register is
[`docs/plans/09-gap-register-2026-09-08.md`](docs/plans/09-gap-register-2026-09-08.md),
and Phase B is planned in
[`docs/plans/12-phase-b-plan.md`](docs/plans/12-phase-b-plan.md) over the
register [`docs/plans/11-phase-b-register-2026-09-09.md`](docs/plans/11-phase-b-register-2026-09-09.md),
with a dated status line per wave. Anything that does not hold on a running
stack is listed under "Open items and not implemented", never simulated in
the UI.

| Area | State on `main` |
|---|---|
| redsim platform (inherited from aegis): FastAPI `/v1` API, Celery workers, Postgres with Alembic migrations `0001` to `0011`, Redis, S3/MinIO blob store, Keycloak auth behind the app's own login page, RBAC and Postgres RLS, hash-chained audit log with WORM export, per-task LLM routing and budgets, OTel observability and `redsim-log-ingest` | Restored. `create_app()` mounts 69 HTTP routes under `/v1` (the 39 Phase A routes, the 16 wave B2 built: five former stubs replaced and eleven new paths, and the 14 wave B3 built in place of the last B0 stubs; no route is a `501` stub) plus `/health`, `/metrics` and the run-events WebSocket, read from the app's OpenAPI document. The last counts labelled with their commit are the B3 integration's on `main` at `703f8f6`: the default tier 2634 passed, 35 skipped, 13 deselected; the `ml` tier 433 passed, 1 skipped; the `garak` tier 12 passed; the e2e tier 22 passed through the real sandbox child with the Postgres RLS lane on; ruff (CI selection) and `mypy redsim` (253 files) clean from the venv. The wave B4 tree adds the seven e2e files and the gate; its counts are the B4 assembler's to record with its commit, and neither the e2e tier nor the default tier is claimed green at the B4 push (the attributed defects and the stale pins are under Open items). No Redsim CI run on `main` after `58461cc` has been read (see Open items and [`docs/dev/ci.md`](docs/dev/ci.md)). |
| Pentest domain (14 scanner adapters, Kali, CAI agents, GitHub remediation, ticketing, CI gate) | Deleted for good. The seams fail explicitly: `POST /v1/scans` is unmounted (404), `redsim scan --scanner X` exits 1 when no adapter of that name is registered, the web Start scan button is disabled behind a notice, and target ownership verification answers 501. `GET /v1/scanners` lists the one adapter that exists, `ml-campaign` (`3ab9de7`), whose health check probes the `ml` extra and the sandbox child and never a model. |
| ML contracts (P0, extended once by Phase B wave B0) | `redsim/ml/schema.py` frozen, the `Target` and `AttackAdapter` protocols, migration `0010_ml_vertical` (`targets.detail`, `ml_campaigns` with RLS parity), the seven ML `Action` members and the `viewer` role, the spec 17.3 error-code table in `redsim/api/errors.py`, the spec 10.6 failure classes in `redsim/ml/errors.py`, and a test that the API process imports no ML library. Wave B0 (`29db42c`) added, under the plan-01 section 8 protocol and announced in master plan section 0: the Phase B schema fields (`text` and `detection` modalities, `edit` and `patch_area` norms, detection and text measurement and observation blocks, the `endpoint` manifest block, the widened review states, `schema_version`), all additive and default-valued with the frozen fixture validating byte-identical (`tests/ml/test_schema_compat.py`); migration `0011_phase_b_platform` (`report_snapshots`, `idempotency_keys`, `ml_batches`, `ml_datasets` with RLS parity, `projects.ml_*` columns, `ml_campaigns.batch_id`); seven Phase B `Action` members with OPA and Cedar mirrors; 23 spec 17.3 codes in a dated addendum; the `endpoint-v1` predict contract and egress policy ([`docs/api/endpoint-contract.md`](docs/api/endpoint-contract.md)). Wave B2 (`api: add thirteen Phase B error codes; dataset.export to remediator`) added the 13 codes the register named and B0 left out (`reviewer_not_independent` 403; `auth_profile_in_use`, `idempotency_key_reused`, `idempotency_conflict`, `review_state_conflict`, `snapshot_archived` 409; `bulk_too_large` 413; `auth_profile_required`, `probe_key_required`, `batch_member_refused`, `bulk_too_many_files`, `fixture_not_exportable` 422; `query_budget_exceeded` 429) in a second dated addendum table, and moved `dataset.export` to `remediator` in `redsim/api/policy.py` and both policy mirrors (spec 17.4 and 27.4, closing the B0 divergence). Wave B3 changed no frozen contract; every one of the seven Phase B `Action` members gates a real handler. Wave B4's fix pass added, under the same protocol, the ten codes the B2 routes had resolved by `getattr` (`attestation_required`, `scoring_weights_invalid`, `model_id_invalid`, `model_not_chat`, `gateway_url_required`, `unknown_probe`, `probe_excluded`, `probe_detector_unavailable` 422; `llm_probe_quota_exceeded` 429; `endpoint_auth_failed` 502) in a third dated 17.3 addendum, corrected the `endpoint_schema_mismatch` row to the `endpoint-v1` name, and widened `redsim/schema.py` `FindingType` additively with `adversarial_llm` and `adversarial_ml_manual`. On 2026-09-09 the verify paradigm was removed under the same protocol (`docs/project-brief.md` item 16, master plan section 5): the verify and defense models and fields left `redsim/ml/schema.py` (`CampaignKind = attack \| ingest`, `RunKind = attack \| ingest \| llm_probe`, `STAGES` the P0 tuple), the frozen fixture was regenerated (sha256 `25be404f…`, `tests/ml/test_schema_compat.py`), the `Action` set lost its verify member (20 members, the OPA and Cedar mirrors in step), the 17.3 table lost its two defense codes, and the head moved to `0012_remove_verify_paradigm`, which drops `findings.validation_state`, `findings.validated_at` and `ml_campaigns.baseline_run_id`. |
| ML libraries (waves 1 and 2, then Phase B waves B1 and B2): loaders, sandbox child, attacks, scoring, explain, recommend, reports, modality runners, endpoint broker, the garak probe core, PDF and N-run compare | On main. Loaders read the `build-assets` manifest, onnx2torch conversion with argmax agreement, `small_cnn` and `resnet18` architectures, tabular target `url_trees` (alias `url_classifier`), surrogate-transfer PGD with per-feature eps and ART mask, HopSkipJump, the noise control, the binomial `control_preserves_accuracy` predicate, `not_run` handling, curve PNG, dataset caveats and `subject_centered`, the `PartitionExplainer` fallback and explanation cache, the six-section report renderer, the typed `MlSandboxConfig` and envelopes. Wave B1 adds the frame-plus-`ModalityRunner` split of `run_campaign` (golden-tested against the pre-refactor function), the `text` modality (`sms_tfidf_lr`, `word_substitution` with its text control, SHAP text), the `detection` modality (`assets_frcnn_mnv3`, `dpatch` with `patch_noise_control`, a detection scorecard and never an MRI), `cw_l2`, `deepfool` and `zoo`, KernelSHAP for predict-only tabular targets with endpoint query caps, and `EndpointTarget` with the worker-parent `PredictBroker`. Registered targets on `import redsim.ml.targets`: `vehicles_cnn`, `url_trees`, `cifar10_smallcnn` (fixture only), `endpoint_stub` (not implemented), `assets_frcnn_mnv3` (detection, `not_implemented` until its asset is built) and `sms_tfidf_lr` (text). Attacks: `fgsm`, `pgd`, `hopskipjump`, `noise_control`, `cw_l2`, `deepfool`, `zoo`, `word_substitution`, `dpatch`, `patch_noise_control`. There is no defense catalog: the product applies no defense (2026-09-09). Wave B2 adds three library modules: `redsim/ml/llm/` (garak 0.16.0 through the Pythia gateway: the committed probe catalog of 103 probes with the offline `redsim-core` set of 76, `PythiaGenerator`, the credential-minimised probe child and its runner, the k/n `LLMProbeScorecard` whose validator refuses every MRI, grade or subscore key, the rule layer and the report section), `redsim/ml/pdf.py` (the report as reportlab flowables with bundled DejaVu subsets) and `redsim/ml/compare.py` (the N-run comparison table with no mean or rank). Wave B3 adds `redsim/ml/interop/` (`parquet.py`, `croissant.py`, `card.py` for the export: deterministic Parquet shards on one nullable schema, the Croissant 1.0 manifest whose own sha256 is the dataset version, the projection-equality guard against the flip matrix, the D9 manifest validator and the template-only card; `consume.py`, the sandbox child that parses a consumed slice; pyarrow imported inside functions only), `redsim/ml/atlas.py` (the per-attack ATLAS stamp checked against `atlas_data` at import, `technique_for_attack`, the catalog block and the number-free `coverage` view) and `comparability_groups` in `redsim/ml/compare.py` (batch grouping, no aggregate). Details in [`docs/architecture/ml-vertical.md`](docs/architecture/ml-vertical.md) and [`docs/interop.md`](docs/interop.md). |
| ML orchestration and API (PR #22 plus wave 2; Phase B stubs in wave B0; Phase B services, workers and routes in wave B2) | On main. Tasks `redsim.ml_campaign_run` (one job per campaign) and `redsim.ml_model_validate` on the `scans` queue and, since wave B2, `redsim.ml_llm_probe_run` on `default` (the only Pythia-egress pool). The spec 10.5 audit vocabulary and 6.5 stage table. The Pythia narrative in the worker parent through `route("ml.harden_narrative")` with `DbBudgetChecker` and `LLMUsage` rows. Phase A routes `/v1/ml/capabilities`, `/v1/attacks`, `/v1/datasets`, `/v1/models` (per-project bundled ids, upload refusal codes with audited refusals, audited soft delete), `POST /v1/models/{id}/attacks` (with reruns), `/v1/runs/{id}/campaign`, `/v1/runs/{id}/compare` (variable-level incompatibility, `side_by_side`), `/v1/runs/{id}/artifacts`, `/v1/artifacts/{id}`, `/v1/runs/{id}/report.{md,json,html}`, finding explain / harden / status, `GET /v1/audit/verify?all=1`. Wave B2 built, verified from the tree: `POST /v1/models` with `source: endpoint` (admin, static egress checks, the `model.register` row with the allowlist verdict, validation through the worker-parent broker, credential-free projections; `endpoint_kind: llm` registers an LLM target with a probe `AuthProfile`); campaigns on `text`, `detection` and endpoint targets with the `edit` and `patch_area` norms, the endpoint query budget (`429 query_budget_exceeded`) and the per-project scoring weights; `GET /v1/llm/probes`, `POST /v1/models/{id}/probes`, `GET /v1/runs/{id}/llm-scorecard`; the review workflow (`POST /v1/findings/{id}/review[/{transition}]`, analyst drafts `POST /v1/findings` and `PATCH /v1/findings/{id}/draft`); `POST /v1/runs/{id}/report.render` with `report.pdf`, immutable snapshots (`GET /v1/runs/{id}/snapshots[/{ref}]`, archive and restore), `GET /v1/runs/compare?ids=` (2 to 10 runs), `GET`/`PUT /v1/projects/{slug}/ml-scoring` and the `Idempotency-Key` header on the mutating ML routes. Wave B3 built, verified from the tree, the last 14: `POST /v1/runs/{id}/dataset` (the Croissant export as an audit-first follow-up job on `redsim.dataset_export`, one export per run, `409 export_unavailable` / `export_in_flight`, `422 fixture_not_exportable`) and `GET /v1/datasets/{id}` (a run's manifest as `application/ld+json`, or a consumed record); `POST /v1/datasets` (a Parquet slice with an optional Croissant manifest, static checks in the API and the parse only in the sandbox child of `redsim.ml_dataset_validate`; `413`, `415`, `422 remote_reference_refused` / `license_required` / `schema_undeclared`, `501` for `text` and `detection` slices); `GET /v1/runs/{id}/atlas-coverage` (a membership view with no numeric field) with the ATLAS technique stamped on every new finding and exposed on `GET /v1/attacks`; `GET /v1/integrations` (the roster: Foundry `disabled` by default, Lattice text only) and `POST /v1/runs/{id}/integrations/foundry` (admin, `501 integration_disabled` until an operator configures an attested, allowlisted Foundry host; the scorecard push through a D9 payload guard on `redsim.integration_push`, proven against a fake server only); `POST`/`GET /v1/campaigns/batch`, `GET .../{id}`, `GET .../{id}/compare`, `POST .../{id}/cancel` (batch campaigns reusing the single-run boundary per member, a roll-up with no aggregate score, grouped compare with no delta or rank); `POST /v1/models/bulk` (`201` / `207` / `422 batch_member_refused`); `GET /v1/ml/capacity` with per-project deferral and the audited `429 daily_budget_exceeded` on batch members ([`docs/api/v1.md`](docs/api/v1.md#phase-b-routes), [`docs/interop.md`](docs/interop.md)). Wave B4 (the fix pass, verified from the tree): `GET /v1/ml/capabilities` reads every Phase B block from the tree (`text`, `detection` and `llm` `available` with their runner, attacks and probe sets, the endpoint connector with the `endpoint-v1` contract summary, the explainer roster, an `interop` block, and the non-builds named `not_implemented` with a reason); `GET /v1/attacks?modality=` filters on the adapters' capability tags, the rule admission applies; `GET /v1/runs/{id}/campaign` carries `batch_id`; `DELETE /v1/auth-profiles/{id}` answers `409 auth_profile_in_use` while a live endpoint or LLM target names the profile; the single-run admission (`POST /v1/models/{id}/attacks`) consults the capacity service (deferral with the `capacity_deferred` marker, `429 daily_budget_exceeded`); the campaign completion path renders `md`, `json`, `html` and `pdf` and records the run's first snapshot; the text and detection runners write self-describing export slices. On 2026-09-09 the verify paradigm was removed (`docs/project-brief.md` item 16): the verify routes, the defense catalog and the finding validation state are gone, 68 routes remain under `/v1`, `GET /v1/exports` has no kind filter, the compare routes answer `side_by_side` with no delta, and a finding resolves once a reviewer has confirmed it. The full list is in [`CLAUDE.md`](CLAUDE.md). |
| Offline CLI, seeding, adapter, e2e harness, doctor and config (wave 3, `7556b22..58461cc`) | On main. `redsim ml attack` (`3ab9de7`), `redsim ml seed` (`3ab9de7`, `98a8733`), the `ml-campaign` scanner adapter and opt-in `redsim.ml.attacks` plugin discovery (`3ab9de7`), the `tests/e2e` harness and its 8-case smoke file (`35e71c7`, `a45a787`), `redsim doctor --worker-mode` rewritten around Pythia with Pythia-only `redsim.yaml` and `.env.example` (`7556b22`, `c3868e5`), `redsim audit verify --run-dir` with canonical audit timestamps (`aa9674e`), the `resnet18` fine-tune recipe (`39126ce`), and the defect fixes: `eps` and `norm_l2` no longer frozen into `attack_params` and applicability by capability tag (`dd2bbd4`), PGD by surrogate transfer admitted on `url_trees` (`58461cc`), the sandbox child pinned to an absent `.env` with `REDSIM_DISABLE_LLM=1` and attack plugins on `GET /v1/attacks` (`c3868e5`). |
| Pythia LLM transport (`redsim/llm/pythia.py`, `python -m redsim.llm.pythia_check`) | Merged (#11) and reached from behind the corporate proxy on 2026-09-08. Reads `REDSIM_ML_LLM_MODEL`. The narrative is optional and degrades to rule text with `narrative_source = "rules"`. Since wave B2 the LLM probe traffic also goes through Pythia: garak's `PythiaGenerator` posts to `{gateway}/v1/chat/completions` with a probe key held in a bearer `AuthProfile` and a persona declared per target (owner default LLM-26: a separate persona and key, never the narrative writer's), and the worker checks the key's entitlement to the model before any probe is sent. No probe run against the live gateway has been recorded; the tests drive a fake OpenAI-compatible server. See [`docs/ops/pythia.md`](docs/ops/pythia.md). |
| Web app `@redsim/web` (Next.js 14) and `@redsim/design-system` | Pages `/`, `/login`, `/dashboard`, `/runs`, `/runs/[id]`, `/findings`, `/findings/[id]`, `/projects`, `/projects/[slug]/settings`, `/targets`, `/auth-profiles`, `/logs`, `/audit`, `/cost`, `/models`, `/models/[id]`, with the MRI scorecard and evidence panels. PR #22 aligned the web contract with the mounted routes, PR #24 (`b93d9a9`) added tRPC and env management and PR #25 (`6cbb661`) the design reference. Wiring beyond that has not been exercised in a browser against a running stack with real campaign data; the web UI is the one deferral of the Phase B plan (open item). |
| Deployment: `deploy/docker-compose.yml`, `deploy/helm/redsim`, `deploy/Dockerfile.*`, `deploy/terraform/`, `deploy/bootstrap/`, `deploy/runtime/`, `deploy-aws.yml` | Compose (postgres, redis, keycloak, minio, redsim-api, redsim-worker, redsim-worker-default, redsim-beat, redsim-web, redsim-log-ingest, optional opa / otel-collector / loki / jaeger / elasticsearch / kibana) and the Helm chart are named `redsim-*`. `Dockerfile.api` installs `.[api,worker]` and runs `alembic upgrade head`, `Dockerfile.worker` installs CPU torch then `.[api,worker,ml]`. `deploy/terraform/` (#19) is the Fargate foundation with mocked-plan tests; PR #23 (`10650da`, merged) adds `deploy/bootstrap/` and `deploy/runtime/`, a public HTTPS Fargate demo runtime at https://redsim.ndia.agiledefense.xyz that its author reports applied to the AWS account with workers at zero tasks, demo users and real assets outstanding (its completion is package E of [`docs/plans/10-remaining-work-brief.md`](docs/plans/10-remaining-work-brief.md), not a Phase B wave). The compose stack was brought up end to end on 2026-09-10 (login, seed, a registered bundled model, a campaign; [`docs/dev/local-stack.md`](docs/dev/local-stack.md)). `deploy-aws.yml` builds and pushes the three images under OIDC and skips its deploy job while `ECS_CLUSTER` is unset. No campaign has been run on a deployed stack. |
| Demo data | Decided and buildable. `redsim ml build-assets --dataset all` fetches the datasets by pinned revision and trains the bundled models on CPU (image, tabular, CIFAR-10 fixture and, since the B1 integration, the SMS spam text classifier; the detector is built only when `--dataset detection` is named because its input is the published subset). Everything it writes under `assets/` is gitignored, so a fresh clone has none until it runs the build. Clean accuracy per model is recorded in the asset manifest (see Datasets for the illustrative local numbers). Wave B0 published the Phase B datasets (SMS Spam Collection, the military-assets subset pending owner review) and the WordNet, ATLAS and garak reference entries to the public data repository at `4048a209`; wave B3 added the first Croissant export built with the new modules from a real offline `url_trees` PGD campaign (`data/exports/url_trees_sample/`, 3 Parquet shards, 600 rows of 16-feature vectors, no URL strings) at head `0dababc`. |
| Docs site (`mkdocs.yml`, `make docs-*`) | `mkdocs build --strict` passes locally. GitHub Pages publishing is off (the plan has no private Pages). |
| Phase B wave B2 (services, workers and routes over the B1 library) | Landed (integration `57da31f`): eight track commits plus `fix: integrate Phase B wave B2 tracks` (the endpoint connector, the Phase B admission rules, the worker's broker lifecycle, the LLM probe core and routes, the review workflow, reports with PDF, snapshots, N-run compare, weights and idempotency, the 13 codes). Its dedicated e2e evidence landed in wave B4 (`tests/e2e/test_ml_endpoint.py`, `test_ml_llm.py`, `test_ml_review_reports.py`, `test_ml_attacks_harden.py`). |
| Phase B wave B3 (interoperability and bulk operations) | Landed (integration `703f8f6`): five track commits plus `fix: integrate Phase B wave B3 tracks` (the Croissant/Parquet export with its projection-equality guard and template card, the consumed-slice admission with the sandboxed parse, ATLAS stamping and the coverage view, the Foundry push behind the admin gate and a payload validator with Lattice text only, batch campaigns with roll-up, grouped compare and cancel, bulk upload, per-project capacity with deferral, the daily budget, the gauges and `GET /v1/ml/capacity`, the `redsim ml attack` matrix). No frozen contract changed. The gaps the tracks could not close inside their file sets were closed by the wave B4 fix pass except the worker-parent materialisation of a consumed slice ([`docs/architecture/ml-vertical.md`](docs/architecture/ml-vertical.md#what-wave-b4-closed-and-what-stays-open)); the narrative is [`docs/interop.md`](docs/interop.md) and the e2e evidence `tests/e2e/test_ml_interop.py` and `test_ml_bulk.py`. |
| Phase B wave B4 (e2e evidence, gate, docs) | Landed with this push: four track commits (`e2e(endpoint,llm)`, `e2e(text,detection,attacks,harden)`, `e2e(review,reports,interop,bulk)`, `ci(phase-b-gate)`) rebased onto `703f8f6`, the seven e2e files above on the shared harness, `scripts/phase_b_gate.sh` behind `make check-phase-b` (nine steps, the first failure naming its spec 26 criterion; the garak step fails on an empty collection), `tests/test_docs_phase_b_consistency.py`, the `e2e-python` and `garak-offline` jobs calling the script, then the fix pass the e2e files demanded (three tracks closing the carried B2 and B3 items) and this documentation pass. The e2e files report product defects by attribution rather than weakening an assertion; what they left open is under Open items. |

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

1. **redsim platform.** Browser to `@redsim/web` (Next.js; a branded email
   and password page that signs in against Keycloak from the server, no dev
   login) to `redsim-api` (FastAPI
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
`garak` (the Phase B LLM domain, pinned `garak>=0.16,<0.17`, needed on the
worker for probe runs; no deploy image installs it yet, the `garak offline`
CI lane installs it for the 12 `garak`-marked tests under `tests/ml` and,
since wave B4, the `e2e-python` lane installs it for the e2e-gated
`tests/e2e/test_ml_llm.py`). The worker extra carries `reportlab` (the PDF
projection) since wave B2 and the test extra `pypdf`.

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
SMS spam text classifier `sms_tfidf_lr` on CPU with a fixed seed, and writes
`assets/MANIFEST.json` on `MLModelManifest` with the dataset caveats.
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
.venv/bin/redsim ml attack vehicles_cnn url_trees --out ./redsim_output      # wave B3: one run and one chain per target
.venv/bin/redsim ml attack --matrix grid.yaml --fail-fast --out ./redsim_output   # wave B3: models x attack_sets x eps_grids x seeds
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
Since wave B3 the command takes several target ids, or `--matrix FILE.yaml`
(`models`, `attack_sets`, `eps_grids`, `seeds`, and optional `norm`,
`reference_eps`, `n_samples`, `explain_k`, `include_control`, `name`; the
schema is printed by `redsim ml attack --help`), and runs one offline campaign
per cell with its own run directory and hash-chained `audit.jsonl` (each
verified with `verify_chain`), prints a per-cell summary table with no mean or
rank, writes `<out>/matrix-<id>/summary.json`, stops at the first refused or
failed cell with `--fail-fast` and exits 1 when any cell was refused or
failed. The single-target path is unchanged.

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
cd deploy && make seed && cd ..                        # default-org and project default (compose stack; rows only)
.venv/bin/redsim ml seed --project default             # bundled models into the project (audit-first, one commit per model)
TOKEN="Bearer dev:admin@redsim.local"
curl -s -H "Authorization: $TOKEN" localhost:8000/v1/models | jq '.models[] | {id, status, modality}'
curl -s -X POST -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
     -d '{"attack_ids": ["fgsm", "pgd"]}' localhost:8000/v1/models/<model_id>/attacks
curl -s -H "Authorization: $TOKEN" localhost:8000/v1/runs/<run_id>/campaign | jq '.score'
curl -s -H "Authorization: $TOKEN" "localhost:8000/v1/audit/verify?run=<run_id>"
```

`deploy/Makefile`'s `seed` feeds `deploy/runtime/scripts/seed_project.py`
to the compose `redsim-api` container and creates only the organisation and
project rows; memberships are read from the `redsim_project_roles` token
claim (the dev bearer is admin on `default`, and the realm's admin user
carries the attribute). Without the compose API, run `python
deploy/runtime/scripts/seed_project.py default-org default Default` with
`REDSIM_DB_URL` exported. Admission fills `modality`, `eps_grid` (the spec 12.3
default for the norm), `reference_eps` and `dataset_id` from the model's
manifest when the body omits them, and refuses anything it cannot admit with
a spec 17.3 code before any row is written. Without a bundled registration
`POST /v1/models` with `{"source": "bundled", "project_id": "default",
"bundled_id": "vehicles_cnn"}` does the same as `redsim ml seed` for one
model. Since wave B2 an admin can also register a black-box predict endpoint
(`{"source": "endpoint", "url": "https://…", "auth_profile_id": "…",
"modality": "image", "input_shape": [3, 128, 128], "class_names": […],
"dataset_id": "…", "license_statement": "…", "evaluation_instance_attestation":
true, …}`, validated through the worker-parent broker; the contract is
[`docs/api/endpoint-contract.md`](docs/api/endpoint-contract.md)) or an LLM
target (`{"source": "endpoint", "endpoint_kind": "llm", "model_id":
"<vendor>/<model>", "persona": "…", "guardrail_mode": "permission_gate_only",
"auth_profile_id": "…"}`) and launch garak probes against the latter with
`POST /v1/models/{id}/probes`; the rules for each are in
[`docs/api/v1.md`](docs/api/v1.md).

Full stack in containers:

```bash
make up                  # the session keypair, then docker compose -f deploy/docker-compose.yml up -d --build
cd deploy && make seed   # organisation default-org and project default
make down
```

`make up` generates the RSA keypair the web app signs the `redsim_api_session`
cookie with into `deploy/certs/` on the first run (gitignored) and exports
both halves to compose on every run, mounts the repo's `assets/` read-only
into `redsim-api` and both worker pools as `REDSIM_ML_ASSETS_DIR`, and
`redsim-api` runs `alembic upgrade head` on start. Sign in at
`http://localhost:3300` as `admin@redsim.local` / `adminpass`; the realm
user carries `redsim_project_roles = {"default": "admin"}`, so the default
project shows with the admin role once `make seed` has created it. Ports: web
`3300`, API `8000`, Keycloak `8080`, Postgres `5432`, Redis `6379`, MinIO
`9100` / `9101`, log ingest `4319`. `docker compose --profile obs up -d` adds
OTel Collector, Loki and Jaeger. The worker image installs
`.[api,worker,ml]` (CPU-only torch wheels first; the `api` extra because the
campaign task imports `redsim.api.errors`), so expect it to be the slowest to
build. The
compose worker anchor sets `REDSIM_DISABLE_LLM=1`. Unset it on
`redsim-worker-default` before expecting a narrative. The stack, the sign-in
and a campaign were brought up end to end on 2026-09-10
([`docs/dev/local-stack.md`](docs/dev/local-stack.md)).

### 5. Run the tests

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider               # default tier: 2634 passed, 35 skipped, 13 deselected at 703f8f6
.venv/bin/python -m pytest -q -p no:cacheprovider -m ml         # only the tests that need the ml extra: 433 passed, 1 skipped at 703f8f6
REDSIM_E2E=1 .venv/bin/python -m pytest -q -p no:cacheprovider -m e2e tests/e2e     # end-to-end tier, sqlite lane
REDSIM_E2E=1 REDSIM_E2E_POSTGRES_URL=postgresql+psycopg://redsim:redsim@localhost:5432/redsim_e2e \
  .venv/bin/python -m pytest -q -p no:cacheprovider -m e2e tests/e2e                # adds the Postgres RLS lane: 22 passed at 703f8f6 (before the wave B4 files)
.venv/bin/python -m pytest -q -p no:cacheprovider -m garak tests   # garak tier: 12 passed at 703f8f6 (needs the garak extra, skipped without it)
.venv/bin/ruff check --select E4,E7,E9,F,I redsim tests         # lint, exactly as CI
.venv/bin/mypy redsim                                           # types
make check-phase-b                                              # the Phase B gate: every step above in order, then mkdocs, the docs-consistency test and the stack probes
pnpm --filter @redsim/web typecheck                             # tsc --noEmit
pnpm --filter @redsim/web test                                  # vitest
```

The counts are local runs from the wave B3 integration on `main` at `703f8f6`
(2026-09-09, the reconcile pass run from the repository root), not CI results;
they move with every wave, so re-run before quoting them. Wave B4 adds the
seven e2e files under `tests/e2e/` and the gate; its counts are the B4
assembler's to record with its commit. At the B4 push the e2e tier is not
green: the B4 files fail by attribution on the product defects listed under
Open items, and two report-format pins the completion render made stale are
still to be moved (`tests/ml/test_audit_campaign.py`,
`tests/e2e/test_ml_review_reports.py`). Every other tier was green at
`703f8f6`. The verify paradigm removal of 2026-09-09 deleted the verify tests
and rewrote the mixed ones. Its counts, run on branch
`refactor/remove-verify-paradigm` after the merge of `main` at `776c74b`: the
default tier 2588 passed, 36 skipped, 25 deselected; the `ml` tier 400 passed,
1 skipped; the e2e tier through the real sandbox child 54 passed, 5 skipped
(the Postgres lane and the garak-gated cases); ruff and `mypy redsim` (246
files) clean; `mkdocs build --strict` exit 0; web typechecks clean and vitest
502 passed. The `garak` tier was not run: its extra is not installed in that
venv.

Markers are declared in `pyproject.toml`. `unit` and `integration` run by
default. The `integration` tests use the shared sqlite harness in
`tests/conftest.py` and need no running services. `docker`, `e2e`, `slow`,
`auth_required` and (since wave B0) `garak` are opt-in with `-m`; `garak`
means "needs the garak extra, skipped when absent" and runs only in the
`garak offline` CI job. It holds the 12 tests of
`tests/ml/test_llm_core.py` and `tests/ml/test_llm_routes.py` (wave B2 and
its integration) and, since wave B4, the four e2e-gated cases of
`tests/e2e/test_ml_llm.py`, all running real garak 0.16.0 probes through
`PythiaGenerator` against an in-process fake OpenAI-compatible server on the
loopback interface, with the key file, the child environment and every
written file checked for the low-entropy fake key. Since wave B4 the gate's
garak step fails on pytest exit 5 (nothing collected), on an all-skipped run
and on a missing extra. The e2e tier (`35e71c7`, `a45a787`)
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
scorecard, the narrative on and off), `tests/e2e/test_ml_upload_reports.py`
(26.17 ONNX accepted and pickle refused with the audit row, the six report
sections and the report formats) and `tests/e2e/test_ml_governance.py` (26.21 and 26.22: the RBAC negative
matrix, the RLS negatives on the Postgres lane, `audit verify --all` passing
then failing after a mutation, the capabilities body secret-free and, since
wave B4, reporting the Phase B rows from the tree), 22 cases in all at
`703f8f6` and 22 passed there (fewer since the verify cases were deleted on
2026-09-09, re-run before quoting), and the wave B4 files `tests/e2e/test_ml_endpoint.py`,
`test_ml_llm.py`, `test_ml_text_detection.py`, `test_ml_attacks_harden.py`,
`test_ml_review_reports.py`, `test_ml_interop.py` and `test_ml_bulk.py` (the
endpoint connector through the tiny server, garak probes through the fake
gateway, text and detection campaigns, norm tags and ZOO, the review workflow
with PDF, snapshots, N-run compare and idempotency, the Croissant round trip
with ATLAS and the Foundry push, and batches, bulk upload and capacity;
`tests/e2e/README.md` "Phase B
wave B4 files"). Since wave B0 the tier runs on every PR and push in the
`E2E tier (python, eager Celery)` CI job with the Postgres lane on, through
`scripts/phase_b_gate.sh --only e2e` since wave B4. Every
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

Probe traffic (wave B2) is the second Pythia consumer and is kept apart from
the narrative writer: an LLM target names its Pythia model id, a persona and a
bearer `AuthProfile` holding the probe key (`probe_key_required` otherwise),
`PYTHIA_BASE_URL` is only the default gateway for a registration that names
no `gateway_url`, and the worker's `redsim.ml_llm_probe_run` task resolves the
key at pickup, checks the model is entitled through `GET /v1/models`, writes
it to a 0600 file the garak child reads and deletes, and never puts it in an
environment variable, a garak config, a log or an audit row. The knobs are
`REDSIM_LLM_PROBE_MAX_PROMPTS_PER_PROBE` (64), `REDSIM_LLM_PROBE_MAX_RUNS_PER_PROJECT_PER_DAY`
(10), `REDSIM_LLM_PROBE_HF_DETECTORS` (opt in to the Hugging Face detector
probes), `REDSIM_LLM_PROBE_TIMEOUT_S` (1500) and `REDSIM_DISABLE_LLM`, which
refuses probe runs as it skips the narrative.

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
(head `0dababc` on 2026-09-09; CC BY 4.0 for the repository's own contents,
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
so its public copy hashes to the loader's pin. Wave B3 (`0dababc`) added the
first export the platform produced with its own modules,
`data/exports/url_trees_sample/` (see the row below and
[`docs/interop.md`](docs/interop.md)).

| Role | Dataset | Modality | License | Notes |
|---|---|---|---|---|
| Demo image dataset | `leibnitz-lab/military_vehicles` (HuggingFace), coarse 7-class task | image | MIT (dataset card) | Ground-level photographs, not aerial imagery. Photo copyright is not cleared by the MIT tag, so images are not redistributed in public releases or reports. Bundled model `vehicles_cnn`. |
| Image CI fixture | `uoft-cs/cifar10` (HuggingFace), test split, pinned 500-image subset committed as `tests/ml/fixtures/cifar10_test_500.npz` | image | CIFAR-10 terms | Tests only, never a demo dataset or a result. Bundled model `cifar10_smallcnn` is `fixture_only` and cannot be registered or attacked. |
| Demo tabular dataset | Kaggle `sid321axn/malicious-urls-dataset` (`malicious_phish.csv`) | tabular | CC0 (Kaggle metadata) | Lexical URL features only. URL strings are data and are never fetched, resolved or rendered as links. The download needs a Kaggle API token for the one `redsim ml build-assets` run (`KAGGLE_API_TOKEN`, or the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair), never on the API, web, steady-state worker or CI. A committed stratified sample under `tests/ml/fixtures/` serves CI. Bundled model `url_trees`. |
| Tabular fallback | `lacg030175/UNSW-NB15` (HuggingFace), config `standard` | tabular | CC-BY-4.0 | Named in the spec as the fallback if the Kaggle download cannot be completed. Not built, not wired (open item). |
| Demo text dataset (Phase B) | UCI SMS Spam Collection (`archive.ics.uci.edu/dataset/228`, Almeida and Gomez Hidalgo 2011) | text | CC BY 4.0 (UCI page) | 5,574 messages, 4,827 ham and 747 spam, zip and corpus pinned by sha256. Published verbatim to the public repository (`data/sms_spam_collection.tsv`, `data/sms_spam_eval_split.tsv`). A committed 300-row sample serves CI. Bundled model `sms_tfidf_lr` (TF-IDF word 1-2 grams plus logistic regression, `build-assets --dataset text`). Caveats recorded: 2011-era, English only, class imbalance, phone numbers present. |
| Synonym lexicon (Phase B) | WordNet 3.0 (`nltk/nltk_data` gh-pages `550b6625`, `wordnet.zip` sha256 `cbda5ea6…`) | text | WordNet 3.0 license (Princeton, BSD-style) | Fetched by `build-assets` into the gitignored asset cache for the `word_substitution` attack; not republished (reference entry only). A 47-entry JSON fixture serves CI. |
| Demo detection dataset (Phase B, pending owner review) | Kaggle `rawsi18/military-assets-dataset-12-classes-yolo8-format`, a capped seeded subset of 300 images and 607 boxes in 4 classes (`military_tank`, `military_truck`, `military_vehicle`, `military_aircraft`) | detection | CC BY 4.0 (Kaggle metadata) | Published as `data/military_assets_subset/` (52 MB) for the owner to confirm under plan 12 decision MODALITIES-27, removable in one commit. Person and weapon classes excluded by construction. The full 4.1 GB archive is cached locally only; Kaggle throttles per-file downloads. Bundled model `assets_frcnn_mnv3` (`build-assets --dataset detection`, named explicitly). |
| ATLAS technique data (Phase B) | `mitre-atlas/atlas-data` release `v2026.08` | reference | Apache-2.0 | Vendored as constants in `redsim/ml/atlas_data.py` with the data file's sha256 and the licence text. Since wave B3 `redsim/ml/atlas.py` stamps the technique on every new finding (`AML.T0043` for the gradient and text and patch attacks, `AML.T0040` for the query-based ones, `None` for controls), exposes it on `GET /v1/attacks` and serves the number-free coverage view. |
| Adversarial-dataset export sample (Phase B wave B3) | `data/exports/url_trees_sample/` in the public repository at `0dababc`: `croissant.json`, `README.md` and three Parquet shards (`pgd_eps0.01`, `pgd_eps0.03`, `pgd_eps0.1`) from offline run `run-dce555487e2b` against the bundled `url_trees` | tabular (derived) | CC0-derived feature vectors; the repository's CC BY 4.0 for the manifest and card | 600 rows of 16 lexical features, no URL strings; the manifest sha256 `8a4a5dfa…` is the dataset version; the adversarial family only (the source run retained no clean or control slices) with the realizability caveat in the card. Built by `redsim.ml.interop` and published by hand; the platform never pushes to this repository. |
| LLM probe corpora (Phase B) | garak 0.16.0 `garak/data` | text | Apache-2.0 (garak packaging), upstream terms per subset | Loaded by garak itself, never re-packaged by redsim; the public repository carries a copy and a reference entry with the per-subset licences (owner decision TESTS_DOCS-33). Probing landed in wave B2 (`redsim/ml/llm/`, 103 catalogued probes, the offline `redsim-core` set of 76) and its end-to-end evidence in wave B4 (`tests/e2e/test_ml_llm.py`, against the fake gateway); the spec 11.6 and brief item 14 addenda record the publication. |
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
   candidate recommendations, each labelled candidate and none evaluated
   against this model.
5. Two compatible campaigns compared side by side
   (`GET /v1/runs/{id}/compare?with=`), variable by variable, with no delta
   and no claim of improvement.
6. The tabular campaign on `url_trees` (PGD by surrogate transfer plus
   HopSkipJump): its own MRI, never combined with the image campaign's, with
   the realizability caveat on every row.
7. Honest edges: `GET /v1/integrations` reporting Foundry `disabled` and
   Lattice text only, a Foundry push answering `501 integration_disabled`
   until an operator configures an attested host, `GET /v1/ml/capabilities`
   reporting the Phase B rows from the tree (`text`, `detection`, `llm` and
   the endpoint connector `available`, the detection explainer, endpoint
   ownership verification and Lattice `not_implemented` with their reasons),
   a dismissal by a second identity that the
   campaign creator cannot perform, and a `resolve` refused with
   `409 resolution_blocked` until an independent reviewer has confirmed the
   finding.
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
| `make dev` | `dev-api` and `dev-web` under `make -j`. Runs no tests: use `make test`. |
| `make dev-api` | `uvicorn redsim.api.app:create_app --factory --reload --port 8000` |
| `make dev-web` | `pnpm --filter @redsim/web dev` on :3000 |
| `make dev-worker` | `celery -A redsim.workers.celery_app worker -Q scans,default`. Not on the `dev` line, needs Redis and Postgres first. |
| `make test` | `pytest -q` plus `pnpm --filter @redsim/web test` |
| `make test-cov` | pytest with `--cov=redsim --cov-report=term-missing` |
| `make lint` | `lint-py` (`ruff check --select E4,E7,E9,F,I redsim tests`, the CI selection) then `lint-web` (printed as a skip line while `web/` has no ESLint config) |
| `make typecheck` | `typecheck-py` (`mypy redsim`) then `typecheck-web` (`tsc --noEmit`) |
| `make check` | lint, typecheck, test |
| `make up` / `make down` | `deploy/scripts/with-session-keypair.sh docker compose -f deploy/docker-compose.yml up -d --build` (the session keypair generated under `deploy/certs/` on first run and exported, the built `assets/` mounted into the api and workers) / `down` |
| `make docs-serve` / `docs-build` / `docs-build-strict` / `docs-clean` | MkDocs Material on :8001. The recipes call `mkdocs` from `PATH`, so activate the venv or pass `MKDOCS=.venv/bin/mkdocs`. |

The CI contract is in [`docs/dev/ci.md`](docs/dev/ci.md).

## Layout

```
redsim/                 Python package (renamed from aegis on 2026-09-08)
  api/                  FastAPI app factory, /v1 routers, middleware (tenant, CSRF, rate limit, Idempotency-Key), auth,
                        policy, errors.py (spec 17.3 codes and both Phase B addenda)
  audit/                hash-chained audit log: chain, writers, forensic export, redaction
  cli/                  `redsim` console script: doctor, audit verify/export, plugins, ml build-assets / attack / seed, ...
  db/                   SQLAlchemy models, session, Alembic migrations 0001-0012
  llm/                  per-task routing, budgets, pricing, guardrails, Pythia transport and check
  log_ingest/           OTLP logs to Postgres mirror service
  migrate/              filesystem to Postgres migration helpers
  integrations/         wave B3: the Foundry scorecard push (settings, roster, payload builder and D9 guard, Datasets v2
                        client) and the admission boundary; Lattice as text only
  ml/                   the adversarial-ML vertical: frozen schema, targets (bundled image, tabular, text, detection,
                        endpoint), attacks, eval, scoring, the campaign frame and
                        runners/ (one per modality), explain, recommend, reporting, pdf (reportlab, pdf_fonts/), compare
                        (N-run table, batch grouping), llm/ (garak through Pythia: catalog, generator, probe child, runner,
                        scorecard, rules, report section), interop/ (wave B3: Parquet shards, the Croissant manifest and
                        guard, the dataset card, the consumed-slice parse child), atlas (the technique stamp and coverage
                        view), sandbox parent and child, the endpoint predict broker and egress policy, assets builder and
                        datasets, atlas_data
  policy/               static / OPA / Cedar policy engines behind the RBAC check
  scanners/             registry, capability vocabulary, out-of-process plugin sandbox
  services/             admission services (audit event, Run/Job rows, enqueue): ml_models, ml_campaigns, ml_findings,
                        ml_llm, finding_review, reports (snapshots, render jobs), and since wave B3 ml_datasets (consume),
                        ml_datasets_export, ml_batches, ml_capacity
  state/                run-state facade: filesystem and Postgres backends
  storage/              blob store: filesystem, S3/MinIO, WORM export
  supply_chain/         plugin signing
  workers/              Celery app, job state machine, tasks/ (ml_campaign, ml_model, ml_llm, reaper, report, and since
                        wave B3 dataset_export, dataset_validate, integration_push, capacity)
web/                    Next.js 14 app (@redsim/web): app router pages, login route, api() client
packages/design-system/ @redsim/design-system: curated components over shadcn primitives
tests/                  pytest suite (unit, integration, ml, garak markers), tests/ml/ for the vertical (with the wave B3
                        files test_interop_export, test_interop_consume, test_atlas_foundry, test_batches,
                        test_bulk_upload_capacity, test_cli_matrix and the fake Foundry server), tests/e2e/ the end-to-end
                        tier (harness, smoke file, three wave-4 files, seven wave B4 files);
                        test_docs_phase_b_consistency.py the docs half of the Phase B gate
scripts/                phase_b_gate.sh (make check-phase-b, the Phase B definition of done), verify-release.sh
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
| [`docs/plans/00-master-plan.md`](docs/plans/00-master-plan.md), `docs/plans/01` to `08`, [`docs/plans/09-gap-register-2026-09-08.md`](docs/plans/09-gap-register-2026-09-08.md), [`docs/plans/EXECUTION-CONTEXT.md`](docs/plans/EXECUTION-CONTEXT.md) | The coordination plan (v2.8: a change note per Phase B wave, the waves in section 4.1, the divergences recorded under the plan-01 section 8 protocol), one phase file per plan step ([`07`](docs/plans/07-p6-interoperability.md) rewritten in wave B4 onto spec section 27 as built; `08` under a status banner), the spec-versus-tree gap register that ordered the Phase A completion waves, and the cold-start guide refreshed for the B4 tree. Section 8 of [`01-p0-contracts-api-skeleton.md`](docs/plans/01-p0-contracts-api-skeleton.md) is the change protocol for everything P0 froze. |
| [`docs/plans/10-remaining-work-brief.md`](docs/plans/10-remaining-work-brief.md), [`docs/plans/11-phase-b-register-2026-09-09.md`](docs/plans/11-phase-b-register-2026-09-09.md), [`docs/plans/12-phase-b-plan.md`](docs/plans/12-phase-b-plan.md) | The remaining-work brief (packages A to F: compose operations, CI parity, process-gate documents, residual Phase A rows, infrastructure completion, the data-poisoning module), the 309-item Phase B register, and the Phase B execution plan (owner decisions with defaults, the schema additions, the datasets, waves B0 to B4 with a dated status line per wave). |
| [`docs/spec-driven-workflow.md`](docs/spec-driven-workflow.md) | How the team works spec-first with Spec Kit's stages. The Spec Kit CLI is not installed. |
| [`docs/architecture/ml-vertical.md`](docs/architecture/ml-vertical.md) and [`docs/architecture/diagrams/`](docs/architecture/diagrams/README.md) | The vertical as built and the current pictures: platform architecture, attack-campaign sequence, campaign-run lifecycle. |
| [`docs/architecture/overview.md`](docs/architecture/overview.md), [`auth.md`](docs/architecture/auth.md), [`audit-chain.md`](docs/architecture/audit-chain.md), [`multi-tenancy.md`](docs/architecture/multi-tenancy.md), [`observability.md`](docs/architecture/observability.md) | Platform architecture inherited from aegis. `auth`, `audit-chain`, `multi-tenancy` and `observability` still hold. `overview.md` still carries pentest-era sections that no longer exist. |
| [`docs/api/v1.md`](docs/api/v1.md), [`docs/api/endpoint-contract.md`](docs/api/endpoint-contract.md) | The `/v1` routes checked against the app's OpenAPI document with their gates, the error codes (the spec 17.3 table and the three Phase B addenda) and the Phase B route table with an honest status per row (`tests/test_docs_phase_b_consistency.py` compares it with the app), and the `endpoint-v1` predict contract a black-box inference endpoint has to speak, with its status table. |
| [`docs/interop.md`](docs/interop.md) | Interoperability as built (wave B3, closed out in B4): what leaves (the Croissant export, its guard and card, the published sample at `0dababc`), what enters (the consumed-slice admission and the sandboxed parse, the contribute-a-model walkthrough), ATLAS stamping and coverage, the Foundry push and its payload guard, Lattice as text, the rules both directions obey, and what stays open. |
| [`docs/dev/local-stack.md`](docs/dev/local-stack.md), [`testing.md`](docs/dev/testing.md), [`ci.md`](docs/dev/ci.md), [`frontend.md`](docs/dev/frontend.md), [`extending.md`](docs/dev/extending.md), [`docs.md`](docs/dev/docs.md) | Developer guides: the compose stack, test plumbing, the CI contract, the web workspace, the extension points (registries, `Target` and `AttackAdapter`, explainers, rules, plugins), the docs build. |
| [`docs/ops/deploy.md`](docs/ops/deploy.md), [`kubernetes.md`](docs/ops/kubernetes.md), [`pythia.md`](docs/ops/pythia.md), [`compliance-evidence.md`](docs/ops/compliance-evidence.md) | Operator guides: production env vars, keys and rotation, the Helm chart, the LLM gateway, the evidence pack. |
| [`docs/adr/0002-registry-seam-and-runners.md`](docs/adr/0002-registry-seam-and-runners.md), [`docs/adr/0004-unified-effect-class-gate.md`](docs/adr/0004-unified-effect-class-gate.md) | The two seams the ML attack adapters reuse: the registry and the effect-class gate. Written for the pentest domain, kept as history. The other ADRs ([`0001`](docs/adr/0001-vendored-submodules.md), [`0005`](docs/adr/0005-worker-autoscaling-and-dr.md), [`0008`](docs/adr/0008-nix-reproducible-builds.md)) record platform decisions. |
| [`CLAUDE.md`](CLAUDE.md) | The working guide for the tree: routes, tasks, CLI, environment variables, test tiers, accepted divergences, verified state and the rules for changing anything. |
| [`SECURITY.md`](SECURITY.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), [`CHANGELOG.md`](CHANGELOG.md) | Security model and boundaries, contribution rules and gates. `CHANGELOG.md` is the aegis release history up to the fork. |

Superseded and kept for history only: `docs/adversarial-ml-redteam-spec.md`
(and its `.html`) and `docs/superpowers/specs/2026-09-08-redsim-design.md`.

## Open items and not implemented

Everything in this list is open. None of it is done, approved or waived, and
nothing in the UI, the CLI or the reports pretends otherwise. Waves B0 to B4
closed the items they built and the wave B4 fix pass closed the carried B2
and B3 follow-ups (the capabilities roster, the attacks filter, the third
17.3 addendum, the `FindingType` literals, `auth_profile_in_use`, the
completion render and snapshot, the text and detection export slices, the
consumed-slice upload binding and loader, the JWT redaction pattern, the ATLAS
stamp on drafts, the `.env.example` and compose pass-through, the `batch_id`
overlay, the single-run capacity admissions); those are no longer listed
here. The items that concerned only the verify loop (the training slice, the
training defenses, the verify report pin) left with it on 2026-09-09.

- **Web UI.** The one deferral of the Phase B plan. PR #22 aligned
  `@redsim/web` with the mounted routes, #24 and #25 added tRPC, env
  management and the design reference, and the pages render
  `not_implemented` states honestly, but the pages have not been exercised in
  a browser against a running stack with real campaign data, the upload
  dialog stays disabled (spec 26.18, below), no page exists for the Phase B
  modalities, endpoints, probes, review states, snapshots or batches, and the
  Playwright stack e2e (`workflow_dispatch` with `run_e2e=true`) has not been
  run. The `tests/e2e` tier covers the API, worker, sandbox and CLI, not a
  browser.
- **Finding chat** (2026-09-09, the `Chat` drawer on `/findings/[id]`,
  through Pythia from the Next server; `docs/ops/pythia.md` "Finding chat
  (web)"): no audit row and no `LLMUsage` row is written per turn, so the
  chain and the org cost view do not see chat traffic; no per-user rate
  limit beyond the gateway's own; the system prompt carries the brief's
  reporting rules as instructions and cannot enforce them, so the panel's
  standing caveat and the evidence panels remain the record; the drawer has
  been exercised in vitest against a fake gateway only, not in a browser
  against a live gateway.
- **Phase B items the wave B4 e2e files found and left open by attribution**
  (each a `pytest.fail` naming the module; the fixers' notes are quoted):
  - `redsim/ml/targets/endpoint.py:228`: `EndpointTarget.load` "sends
    `x[probe_idx]` as float32 without the `as_model_input` scaling that
    `sample()` applies", so the 8-row probe of a uint8 image split is refused
    by the `float32_nchw` rule and no endpoint reaches `available` through the
    tiny server; the three campaign-path cases of `tests/e2e/test_ml_endpoint.py`
    fail on it. The fix is one `as_model_input(...)` call before
    `encode_request`.
  - INTEROP-16 remainder: the upload admission and the target loader bind a
    consumed `ds-…` slice since B4, but "the consumed-slice path needs one
    call in the worker parent (`redsim/workers/tasks/ml_model.py`
    `_validate_upload` and `redsim/workers/tasks/ml_campaign.py` where
    `target_detail` is built): put `materialize_consumed_slice(...)` at
    `target_detail["consumed_slice"]`", so a campaign on a consumed-bound
    model does not run end to end (`tests/e2e/test_ml_interop.py`).
  - Bulk `state_dict` upload (spec 9.2, 26.4 item 17): "neither `POST
    /v1/models` nor `POST /v1/models/bulk` accepts or derives
    `architecture_kwargs`" from the dataset binding, so a `small_cnn`
    `state_dict` for a dataset with other than 10 classes is refused at
    validation with `shape_mismatch` (`tests/e2e/test_ml_bulk.py`).
  - `redsim/ml/pdf.py`: reportlab raises `LayoutError` on a 13-column
    measurement table (observed on the text campaign and the tabular ZOO
    campaign); the completion path degrades to
    `md`/`json`/`html` with `pdf_unavailable` on the `report.render` row, but
    `POST /v1/runs/{id}/report.render` still raises on such a record.
  - Two stale pins the completion render made stale, to be moved by their
    owners: `tests/ml/test_audit_campaign.py:113` (`formats` now includes
    `pdf`; the one default-tier failure on the B4 tree) and
    `tests/e2e/test_ml_review_reports.py` (the completion snapshot is version
    1, the on-demand render version 2).
  - Endpoint seams recorded, not failing: the frozen `query_budget.limits`
    fold `batch_rows`/`timeout_s` from the registration while the broker runs
    with the validate-time defaults; the broker's `by_purpose` split is
    `{probe, predict}` because the classification runner never enters
    `EndpointTarget.purpose(...)`; `Job.detail` of an endpoint `attack.run`
    carries no `auth_profile_id` (ENDPOINT-29); `/campaign` and `/compare`
    answer `404 campaign_not_found` for an LLM probe run rather than `409
    llm_target_required`; ENDPOINT-30's typed transport-failure mapping in the
    campaign task is not built.
  - INTEROP-07 (regenerate-in-child: `export_unavailable` instead, never
    fabricated), INTEROP-23 (the dataset push to Foundry: `PUSH_PAYLOADS` is
    `("scorecard",)`), INTEROP-26 closed on 2026-09-10 (the push reached a
    developer-tier instance through `tests/e2e/test_ml_foundry_live.py`,
    which skips in CI without operator-supplied `REDSIM_FOUNDRY_LIVE_*`
    variables), `tests/ml/fixtures/public_index.csv` snapshots the public
    `INDEX.csv` at `4048a209`, before the export rows.
- **Owner decisions** (plan 12 section 2, each with the recommended default
  the code follows until the owner rules otherwise): ENDPOINT-26 (no DNS-TXT
  ownership check for endpoints; egress allowlist plus admin registration
  plus the audited attestation, applied in B2), LLM-08 (HarmBench excluded:
  `fitd.FITD` is an excluded catalog row with its reason), LLM-26 (a separate
  Pythia persona and key for probe traffic, declared as `guardrail_mode` on
  the target and required by the registration), MODALITIES-12 (SMS corpus
  published verbatim, applied), MODALITIES-27 (the 300-image military-assets
  subset is published for review and removable in one commit),
  MODALITIES-36 (detection carries a scorecard, never an MRI; the admission
  table sets `mri=False`), REVIEW_REPORTS-13 (no `reviewer` role;
  independence is identity, never rank), REVIEW_REPORTS-33 (no pickle
  override), REVIEW_REPORTS-35, -36, -41, -42 (membership administration and
  retention purge deferred to the platform team), INTEROP-26 (Foundry tested
  against `tests/ml/fake_foundry_server.py` in CI and, since 2026-09-10,
  against a real developer-tier instance by the live lane), INTEROP-27 / TESTS_DOCS-41 (Lattice as text
  only: the roster entry and no code), INTEROP-30 (B2 deployment posture as a
  runbook item of brief package E), INTEROP-34 (imagery exports stay in the
  artifacts bucket), BULK-16 (one defended run projected onto N findings,
  applied at admission in B3 and in the worker in B4), TESTS_DOCS-33 (the
  public `data/garak/` publication recorded with per-subset licences in the
  spec 11.6 and brief item 14 addenda). B3 added one design choice for the
  owner: the Foundry switch is the URL plus the attestation variable
  `REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL=1`, droppable if the owner
  prefers the bare URL switch. Five stub paths follow the brief rather than
  the register; the `dataset.export` role question is closed (`remediator`
  since B2).
- **The remaining-work brief** (`docs/plans/10-remaining-work-brief.md`),
  executed outside the Phase B waves: package A compose-stack operations
  (the stack has not been brought up end to end, spec 26.1's
  clone-to-first-run time is unrecorded, and `make check-phase-b` has not
  been run against `make up`), B CI parity (no CI run on `main` after
  `58461cc` has been read), C the process-gate documents that need named
  human reviewers (spec 26.18 upload sign-off, so the upload dialog stays
  disabled and says why; 26.25 readiness checklists; 26.26 approval records;
  26.27 the separate "done" record; D006 and D007 stay OPEN in
  `specs/_shared/decisions.md` with no owner invented), D residual Phase A
  rows, E infrastructure completion (the #23 runtime's pinned asset bundle,
  demo users and memberships, real assets, the `0011` and `0012` migrations, automatic
  rollout, Helm install; no campaign has been run on it) and F the
  data-poisoning evaluation module (decision D14).
- **Recorded non-builds**: `adv_patch` (MODALITIES-32; `dpatch` is the
  detection attack), KernelSHAP for images (ATTACKS_HARDEN-08;
  `PartitionExplainer` stays), a SHAP explainer for object detectors (the
  detection runner records box evidence and never an MRI), connection IP pinning in the predict broker (the resolve-once
  session pin exists, the pinned-connect transport does not), the fallback
  datasets `lacg030175/UNSW-NB15` and the aircraft image fallback of spec
  11.3.2, garak's `dan.AutoDAN` and `grandma.GrandmaIntent` and the uncapped
  `*Full` corpus variants (excluded catalog rows with their reasons), an LLM
  narrative for probe results (rule text only, `NARRATIVE_NOT_OFFERED_REASON`),
  `text` and `detection` consumed slices (`501` on `POST /v1/datasets` with
  the reason), the Lattice integration (text only by decision D3), the
  `mlcroissant` library (the manifest is built and validated in pure Python;
  the package stays blocked in the API tripwire), and no deploy image installs
  the `garak` extra (the two CI lanes and an opted-in venv do).
- **CI.** No Redsim CI run on `main` after `58461cc` (red on three jobs whose
  causes wave 4 fixed) has been read: not the runs for `e73dea0`, `29db42c`
  (the first with the `e2e-python` and `garak-offline` jobs), `1439f92`,
  `57da31f`, `703f8f6`, nor the wave B4 push. Nothing is claimed green until a
  run on `main` is read. The counts in this README are the local runs of the
  B3 integration at `703f8f6`; the B4 tree's counts are the assembler's to
  record.

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
  guarded by `tests/ml/test_schema_compat.py`. Waves B1, B2 and B3 changed
  no frozen contract; B2's one role change (`dataset.export` to `remediator`)
  edited the three policy files together, B3 added no error code, action,
  field or migration, and B4 added ten codes in a third dated 17.3 addendum
  (`tests/ml/test_error_codes.py` parses all three) and widened the platform
  `FindingType` additively, leaving `redsim/ml/schema.py` untouched.
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
