# ML vertical

Status as of 2026-09-09: `main` at `703f8f6` (the Phase A completion waves 1
to 4 and Phase B waves B0 to B3), with Phase B wave B4 (the end-to-end
evidence for everything B2 and B3 built, the `make check-phase-b` gate, the
fix pass those files demanded and this documentation pass) pushed to `main`
together and verified from that tree. This page describes the adversarial-ML
vertical as it runs from this tree: the flow from admission to report, the
stage table, the artifact and audit vocabularies, the verify loop, what each
Phase B wave put on `main`, what wave B4 closed and what stays open, and the
places where the tree knowingly departs from the spec. The interoperability narrative has
its own page, [Interoperability](../interop.md). The authoritative
design is the
[product spec](../superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md),
the coordination plan is the [master plan](../plans/00-master-plan.md), the
spec-versus-tree audit that drove the Phase A completion waves is the
[gap register](../plans/09-gap-register-2026-09-08.md), and the Phase B
execution plan with its register is
[`12-phase-b-plan.md`](../plans/12-phase-b-plan.md) over
[`11-phase-b-register-2026-09-09.md`](../plans/11-phase-b-register-2026-09-09.md).
Where this page and the spec disagree and the divergence is not listed below,
the spec wins and this page is stale.

## What the vertical does

One campaign takes one classifier (a bundled sample or an uploaded ONNX or
PyTorch `state_dict` artifact), one modality (`image` or `tabular`), a
declared attack set, an ε grid and a reference budget. The worker runs the
attacks from the Adversarial Robustness Toolbox (ART) at every ε on one seeded
slice, pairs them with a benign random-noise control, explains flipped and
unflipped samples with SHAP, scores the campaign with the Model Robustness
Index (MRI), derives interpretation and candidate hardening recommendations
from deterministic rules, and optionally rewrites the rule output into prose
through Pythia. A verify campaign re-runs the same settings with an ART
preprocessing defense in front of an evaluation copy and reports the measured
ΔMRI. Nothing is ever applied to the stored model. The tool is a
non-operational proof of concept on open, unclassified public data, and no
score or grade it produces is a safety, readiness or certification statement.

Platform pieces the vertical reuses unchanged: the FastAPI app and RBAC
([auth](auth.md)), the Celery workers and the job state machine, Postgres
with row-level security ([multi-tenancy](multi-tenancy.md)), the blob store,
the hash-chained audit log ([audit chain](audit-chain.md)), per-task LLM
routing with budgets, and the Pythia transport.

Since Phase B waves B0 and B1 the library under `redsim/ml/` also carries a
`text` modality (a bundled TF-IDF plus logistic-regression SMS spam
classifier, a word-substitution attack under an edit budget, SHAP text
attributions), a `detection` modality (a bundled torchvision detector on a
capped open subset, ART DPatch under a patch-area budget, a detection
scorecard and never an MRI), the Carlini-Wagner L2, DeepFool and ZOO attacks,
KernelSHAP for predict-only tabular targets, an `EndpointTarget` that reaches
a black-box inference endpoint only through a worker-parent predict broker,
and adversarial training and defensive distillation as a `defense_apply`
stage. Since wave B2 it is reachable through the API: campaign admission
covers all four modalities and endpoint targets, `POST /v1/models` registers
predict endpoints and LLM targets, the verify route admits the training
defenses and the worker registers the derived model, garak probes run
through the Pythia gateway (`redsim/ml/llm/`), the review workflow, PDF
reports, snapshots, N-run compare, per-project weights and `Idempotency-Key`
exist. Since wave B3 a terminal run exports its adversarial examples as a
Croissant dataset over Parquet shards, another team's Parquet slice is
admitted with static checks and parsed only in the sandbox child, every new
finding carries its ATLAS technique and a campaign has a coverage view, a
scorecard can be pushed to a configured Foundry instance (off by default,
proven against a fake server only), campaigns run as batches with a roll-up
and grouped compare, models upload in bulk, verifies run in bulk, and
per-project capacity defers or refuses admissions; the 14 wave B0 stubs are
gone. Since wave B4 the seven e2e files under `tests/e2e/` drive every one of
those paths through the real API, worker and sandbox child, `make
check-phase-b` runs the Phase B definition of done, and the carried B2 and B3
follow-ups are closed except the ones listed under
[What wave B4 closed and what stays open](#what-wave-b4-closed-and-what-stays-open).
See [Phase B on `main`](#phase-b-on-main-waves-b0-to-b3).

## Where things stand

| Piece | State at `703f8f6` plus wave B4 |
|---|---|
| Frozen contracts: `redsim/ml/schema.py`, `redsim/ml/targets/base.py`, `redsim/ml/attacks/base.py`, migrations `0010_ml_vertical` and `0011_phase_b_platform`, the seven ML `Action` members and the seven Phase B members | on `main`, frozen by P0 and extended once under the plan-01 section 8 protocol by wave B0 (`934838e`: every plan 12 section 3 field additive and default-valued, the frozen fixture validating byte-identical, `tests/ml/test_schema_compat.py` as the tripwire; `7b1f2fa`: the head moved `0010` to `0011`; `3cd3362`: seven `Action` members and 23 error codes with their policy mirrors and spec addenda). `redsim/ml/errors.py` carries the spec 10.6 failure classes (`ModelLoadRefused`, `ArtifactDigestMismatch`, `SandboxTimeout`, `SandboxKilled`, `EnvelopeInvalid`, `DatasetUnavailable`, `MlExtraUnavailable`, `ExplainerUnavailable`) and since B1 the endpoint classes, each with a stable `code` |
| Targets, attacks, eval, scoring, campaign runner, SHAP, rules, narrative writer (`redsim/ml/`) | on `main` (#8, #9, then wave 1 `f8693c2..a99d9cc`; Phase B library in wave B1). Registered targets `cifar10_smallcnn` (fixture only), `url_trees` (alias `url_classifier`), `vehicles_cnn`, `endpoint_stub`, since B1 `assets_frcnn_mnv3` (detection, `not_implemented` until its asset is built) and `sms_tfidf_lr` (text; both register on `import redsim.ml.targets` since the B2 integration); attacks `fgsm`, `pgd`, `hopskipjump`, `noise_control` and since B1 `cw_l2`, `deepfool`, `zoo`, `word_substitution`, `dpatch`, `patch_noise_control`. Loaders read the build-assets manifest shape, ONNX uploads are converted with onnx2torch and their argmax agreement recorded, `pgd` on a tree ensemble runs by surrogate transfer with per-feature ε scaling and an ART mask for frozen features, attacks that cannot run are recorded `not_run` and dropped from the scored set, the robustness curve is rendered to PNG, the control check is a binomial predicate, an image target without a torch module falls back to `PartitionExplainer`, a predict-only tabular target to `KernelExplainer`, explanations are cached per (model, sample, attack, ε, explainer, seed), and the report renderer writes the six sections of spec 14.8. `run_campaign` is a frame plus one `ModalityRunner` per `Modality` since B1, proven byte-for-byte against the pre-refactor function by `tests/ml/test_campaign_golden.py` |
| Sandbox child (`redsim/ml/sandbox.py`, `redsim/ml/sandbox_worker.py`) | on `main`. Typed `MlSandboxConfig` from `REDSIM_ML_SANDBOX_*`, per-job work directory, typed result envelope, `SandboxTimeout` / `SandboxKilled` / `EnvelopeInvalid` distinct from a model refusal. Since B1 the parent can start a `PredictBroker` on a unix socket in the 0700 work directory for an endpoint target (`run_campaign_sandboxed(..., target_endpoint=, endpoint_auth=, endpoint_allowlist=)`, `probe_endpoint_sandboxed`), the child talks to it over `SocketPredictTransport` with no URL and no credential, and the envelope carries the typed endpoint failures with their structured `detail` |
| Worker (`redsim.ml_campaign_run`, `redsim.ml_model_validate`, since wave B2 `redsim.ml_llm_probe_run`, ML branch of `redsim.report_render`; since wave B3 `redsim.dataset_export`, `redsim.ml_dataset_validate`, `redsim.integration_push`, `redsim.ml_dispatch_deferred`) | on `main` (wave 2 `055bdee..bb43bd7`). Spec 10.5 audit vocabulary, spec 6.5 stage table, Pythia narrative in the worker parent, typed validate envelope with a parent-side digest check, observability init, stage spans and the run roll-up in the reaper. The B1 integration teaches `expected_stages` the `defense_apply` stage (only when the campaign's defense is a `kind: training` row) and the sink the text, detection and derived-model artifact kinds. Wave B2 (`worker: endpoint broker lifecycle, derived-target registration, retests (Phase B B2)`, `feat(ml): endpoint registration, validate via broker, projections`, `feat(llm): probe routes, admission, worker, scorecard and findings`) adds the broker start and stop around an endpoint campaign with the credential resolved at run time, the `ml.clean_slice` / `ml.control_slice` kinds, the registration of a derived model as a new target with `derived_from` lineage, the `retests` list on every verify, the endpoint variant of validate through `probe_endpoint_sandboxed`, and the probe task on the `default` queue. Wave B3 adds the Croissant export task and the consumed-slice validation task on `scans`, the Foundry push task on `default` (the egress pool) and the deferred-run dispatcher on beat every 60 s (thirteen tasks in all). Since wave B4 the completion path renders all four formats and records the run's first `report_snapshots` row (a PDF the renderer cannot typeset degrades to the text formats with `pdf_unavailable` recorded), a bulk verify projects its one record onto every finding in `Job.detail.finding_ids`, the stage table is closed from the returned record, and `ml_campaign_run` enters `deferred_continuation` so a finishing run dispatches the project's deferred jobs |
| API admission and routes | on `main` (#22, then wave 2, then waves B2 and B3). Every ML route of spec 17.2 is mounted and uses the spec 17.3 codes from `redsim/api/errors.py`: 39 Phase A routes, the 16 routes wave B2 built (five former stubs and eleven new paths) and the 14 routes wave B3 built in place of the last B0 stubs, 69 under `/v1` in all, none a `501` stub. Since wave B2 (`admission(ml): modality table, norm checks, endpoint budget, project scoring`) admission covers `image`, `tabular`, `text` and `detection` through `SUPPORTED_MODALITIES` with per-modality norms, default grids and caps, refuses a norm the adapter does not declare, admits endpoint targets with a query budget, applies the project scoring override, and admits the training defenses on verify. Since wave B3 the batch, bulk, export, consume, coverage, roster and push routes are real ([Phase B on `main`](#phase-b-on-main-waves-b0-to-b3)). Since wave B4 `GET /v1/ml/capabilities` reads every Phase B block from the tree (the modalities, the endpoint connector with the `endpoint-v1` summary, the explainer roster, an `interop` block, the non-builds named with a reason), `GET /v1/attacks?modality=` filters on the capability tags admission uses, `GET /v1/runs/{id}/campaign` carries `batch_id`, `DELETE /v1/auth-profiles/{id}` emits `409 auth_profile_in_use`, and every single-run admission consults the capacity service; `GET /v1/defenses` reads `phase` and `status` from the catalog row since the B2 integration. See the [API reference](../api/v1.md) |
| Offline CLI `redsim ml attack`, `redsim ml seed`, the `ml-campaign` scanner adapter, `redsim.ml.attacks` plugin discovery, the `tests/e2e` harness, the Pythia-centred `redsim doctor`, Pythia-only `redsim.yaml` and `.env.example` | on `main` (wave 3, `7556b22..58461cc`). `redsim ml` has `build-assets`, `attack` and `seed` (`3ab9de7`, `98a8733`), `GET /v1/scanners` lists `ml-campaign` (`3ab9de7`), `GET /v1/attacks` loads plugins and reports them under `plugins` (`c3868e5`), `tests/e2e/` holds the harness and the 8-case smoke file (`35e71c7`, `a45a787`), `redsim doctor` checks no provider key and gained `--worker-mode` (`7556b22`, `c3868e5`), audit timestamps are canonical and `audit verify` has `--run-dir` (`aa9674e`), admission strips grid-owned params and decides by capability tag (`dd2bbd4`) and admits PGD by surrogate on tabular (`58461cc`), the sandbox child is pinned to an absent `.env` with `REDSIM_DISABLE_LLM=1` (`c3868e5`), `resnet18` has the `39126ce` fine-tune recipe |
| End-to-end completion criteria: `tests/e2e/test_ml_campaigns.py`, `tests/e2e/test_ml_verify_upload_reports.py`, `tests/e2e/test_ml_governance.py` | on `main` since wave 4 (`3dda572`, `35662e4`, `6a8a534`, integrated by `e73dea0`) on the wave-3 harness: 22 e2e cases in all with the 8-case smoke file, 22 passed at `29db42c` with the Postgres RLS lane on, and run on every PR by the `e2e-python` CI job since wave B0 |
| Web pages `/models`, `/models/[id]`, MRI panels on `/runs/[id]`, three-pane `/findings/[id]` | on `main` (#16). #22 aligned the web contract with the mounted routes, #24 (`b93d9a9`) added tRPC and env management, #25 (`6cbb661`) the design reference. Wiring beyond that against a running stack with real campaign data, and the Playwright browser e2e, are the one deferral of the Phase B plan |
| ECS Fargate deployment | Terraform foundation (#19, `deploy/terraform/`) and the runtime of #23 (`10650da`, `deploy/bootstrap/`, `deploy/runtime/`) on `main`. The runtime is reported applied at https://redsim.ndia.agiledefense.xyz (health, login and OIDC discovery 200, unauthenticated API 401, migrated through `0010` at the time of the PR) with workers at zero, demo users and real assets outstanding. Its completion is package E of the [remaining-work brief](../plans/10-remaining-work-brief.md), outside the Phase B waves; no campaign has been run on it |
| Phase B contracts and stubs (wave B0, `934838e..29db42c`) | on `main` at `29db42c`. Schema additions, migration `0011`, seven actions and 23 codes, the 19 stubs, the schema-compat tripwire, the `garak` marker and pin, the `e2e-python` and `garak-offline` CI jobs, the datasets (SMS Spam Collection, WordNet 3.0, the military-assets subset, the `vehicles_cnn` training slice, the ATLAS `v2026.08` constant, the garak reference entry), the `endpoint-v1` contract and the egress policy |
| Phase B library layer (wave B1) | on `main` at `1439f92` (eight commits, `refactor(ml): split run_campaign into a frame plus modality runners` through `fix: integrate Phase B wave B1 tracks`). Modality runners, text and detection modalities, `cw_l2` / `deepfool` / `zoo`, KernelSHAP for predict-only tabular targets and the endpoint explain caps, `EndpointTarget` and `PredictBroker`, adversarial training and distillation. At `1439f92`: default tier 2257 passed, 35 skipped, 1 deselected; `ml` tier 418 passed, 1 skipped; e2e 22 passed |
| Phase B services, workers and routes (wave B2) | on `main` at `57da31f` (eight track commits plus `fix: integrate Phase B wave B2 tracks` and the integration `fix: integrate Phase B wave B2`). The endpoint connector, the Phase B admission rules, the worker's broker lifecycle and derived-target registration, the garak probe core and routes, the review workflow, reports with PDF, snapshots, N-run compare, weights and idempotency, the 13 codes and the `dataset.export` role. Its checks before the rebase (a worktree on `b404eb8`): ruff and mypy (236 files) clean, 251 passed and 1 xfailed in the writers' ten test files, the default tier 2431 passed with 17 failures all present at that base and fixed on `main` by the B1 integration; The B2 integration pass re-ran every tier on the rebased tree (default 2480 passed, 35 skipped; `ml` 420 passed, 1 skipped; garak 12; e2e 22; mypy 236 files; ruff clean). Details under [Phase B on `main`](#phase-b-on-main-waves-b0-to-b3) |
| Phase B interoperability and bulk operations (wave B3) | on `main` at `703f8f6` (five track commits plus `fix: integrate Phase B wave B3 tracks`, the reconcile commits and the integration `fix: integrate Phase B wave B3`). The Croissant export and the consumed-slice admission with the sandboxed parse, ATLAS stamping and the coverage view, the integrations roster and the Foundry push (off by default), batch campaigns with roll-up, grouped compare, cancel and bulk verify, bulk upload, per-project capacity with deferral and the daily budget, `GET /v1/ml/capacity`, the filled gauges and the `redsim ml attack` matrix; the last 14 B0 stubs replaced. The B3 assembler's checks in its worktree (before the rebase): ruff and `mypy redsim` (253 files) clean, the six writers' test files 140 passed and 1 skipped, the rewritten `tests/ml/test_phase_b_stubs.py` 61 passed, then at the integration on the rebased tree the default tier 2634 passed, 35 skipped, 13 deselected, `ml` 433 passed, 1 skipped, `garak` 12, `e2e` 22 ([testing.md](../dev/testing.md)). Details under [Phase B on `main`](#phase-b-on-main-waves-b0-to-b3) and [Interoperability](../interop.md) |
| Phase B wave B4 (e2e evidence, gate, docs) | pushed to `main` with this pass: four track commits (`e2e(endpoint,llm)`, `e2e(text,detection,attacks,harden)`, `e2e(review,reports,interop,bulk)`, `ci(phase-b-gate)`) rebased onto `703f8f6`, the seven e2e files, `scripts/phase_b_gate.sh` behind `make check-phase-b`, `tests/test_docs_phase_b_consistency.py`, the fix pass (`fix-api-services`, `fix-worker-runners`, `fix-gate-ci`) and this documentation pass. The e2e files report product defects by attribution; what they left open is under [What wave B4 closed and what stays open](#what-wave-b4-closed-and-what-stays-open) and in the README |

The bundled assets were built locally with `redsim ml build-assets` on
2026-09-09. They are gitignored under `assets/`, so a fresh clone builds its
own. The numbers below are illustrative local build figures read from that
manifest, not results and not product claims:

| Asset | Recipe | Clean accuracy (illustrative, local build) |
|---|---|---|
| `url_trees` | scikit-learn `HistGradientBoosting` on lexical URL features, with a build-time PGD surrogate | 0.9087 on `n = 128224` (Kaggle malicious-URLs eval split), surrogate clean agreement 0.7891 |
| `vehicles_cnn` | `resnet18` with the `39126ce` recipe: ImageNet initialisation from the local torch hub cache, fine-tune at lr 3e-4 with cosine decay, random flip and reflect-pad crop augmentation, best epoch by a per-class 10 percent validation slice held out of the training split, so the evaluation split is never used for selection | 0.7687 on `n = 1621` (`test_coarse`). The earlier `small_cnn` recipe reached 0.5151 on the same split |
| `cifar10_smallcnn` | `small_cnn`, CI fixture only, never a demo target | 0.6872 on the CIFAR-10 test split |

## Orchestration

One API-launched campaign is one job. The flow at `58461cc`:

1. **Admission** (`POST /v1/models/{id}/attacks`, `redsim/services/ml_campaigns.py::create_attack_campaign`).
   The route checks membership and `attack.run`. The service resolves the
   target (status must be `available`), fills defaults (norm `linf`, the
   default ε grid for the norm, `reference_eps`, the dataset the manifest
   binds), validates every attack against the registry (applicability by
   the adapter's `modality:<domain>` capability tag, the gradients check
   waived for a `surrogate_transfer` adapter on a target with a declared
   surrogate, the grid-owned `eps` and `norm_l2` stripped so that only the
   caller's keys are frozen into `attack_params`), freezes a
   `CampaignConfig` with the target snapshot and the attack infos, and
   computes `settings_hash`. Every refusal is an `ApiError` with a spec 17.3
   code and writes an `attack.run` audit row with `success=False`.
2. **Audit row, then rows** (spec 10.5). `redsim.safety.authorize("attack.run", …)`
   appends to the project chain with the frozen config (minus the snapshot)
   in `detail`. Only then are the `Run` (`scanner = "ml.campaign"`,
   `status = "queued"`), the `Job` (`type = "attack.run"`, the frozen config
   in `detail`) and the `ml_campaigns` row (`kind = "attack"`, config,
   `settings_hash`, `parent_run_id` for a rerun) written.
3. **Enqueue** on `redsim.ml_campaign_run`, routed to the `scans` queue. A
   broker failure deletes the three rows and answers `503 queue_unavailable`.
   Otherwise the Celery task id is stamped on the job and the JobHandle
   `{run_id, job_ids, status_url}` is returned with `202`.
4. **Worker parent** (`redsim/workers/tasks/ml_campaign.py`). `task_context`
   guards redelivery and cancellation, binds the log context, opens the
   `job.run` span and moves the job to `running`. The task re-validates the
   frozen config against the `Run` and `Target` rows, refuses a target that
   is not `available`, and creates the `DatabaseArtifactSink`, the
   `_StageTracker` and the `_AuditEmitter` (actor `worker:<job type>`, the
   requesting principal in `detail.requested_by`).
5. **Sandbox child** (`redsim/ml/sandbox.py::run_campaign_sandboxed`). The
   parent writes a request file and starts
   `python -m redsim.ml.sandbox_worker` in its own process group with POSIX
   rlimits from `MlSandboxConfig` (`REDSIM_ML_SANDBOX_TIMEOUT_S` 1200,
   `CPU_SECONDS` 900, `MEMORY_MB` 4096, `FILESIZE_MB` 1024, `THREADS` 2) in a
   0700 work directory under `REDSIM_ML_WORK_DIR/<job_id>`. The child
   environment is built from an empty dict: the interpreter allowlist plus
   `PYTHONHASHSEED = config.seed`, thread caps, `MPLBACKEND=Agg`, the
   Hugging Face offline flags, `REDSIM_ML_ASSETS_DIR`, `REDSIM_ENV_FILE`
   pinned to the absent `<work_dir>/no-env` and `REDSIM_DISABLE_LLM=1`
   (`c3868e5`). No `REDSIM_*` secret, no `PYTHIA_*` value and no proxy
   variable reaches it, the child cannot fall back to a checkout's `.env`,
   and it scrubs the LLM variables again itself. Bundled targets load from the asset
   tree. An uploaded model is materialised from the blob store by the parent,
   which re-checks its sha256 against the registered manifest before the
   child starts. The child runs `redsim.ml.campaign.run_campaign`, reports
   each finished stage back through a file the parent polls, writes artifacts
   through the sink, and ends with one typed envelope
   (`{"ok": true, "result": {"record": <CampaignRecord>}}` or
   `{"ok": false, "error_class", "error", "code"}`).
6. **Envelope handling.** Exit 0 means an envelope was written (success or a
   structured refusal). A wall-clock overrun is `SandboxTimeout`, any other
   death `SandboxKilled`, an unreadable envelope `EnvelopeInvalid`. In those
   three cases the files the child had written are kept as `ml.partial.*`
   artifacts, a partial `ml.run_record` is persisted, the running stage is
   marked `timed_out` or `failed`, `job.complete` is written with
   `success=False` and the error class, and the job fails. Cancellation
   observed by the parent's `is_cancelled` poll kills the process group and
   returns a `cancelled` partial record.
7. **Parent narrative** (`_parent_narrative`, spec 10.8). Only after the child
   returns, only on a succeeded `attack.run` or `harden.recommend` job, and
   only when `llm_narrative` was requested: `redsim.llm.router.route("ml.harden_narrative")`
   with `DbBudgetChecker` picks the model under the project daily and
   organisation monthly caps, `redsim.llm.pythia.chat_text` sends one
   non-streaming completion, the prompt and completion are stored as
   `ml.harden.prompt` and `ml.harden.completion` artifacts, one `LLMUsage`
   row with `task = "ml.harden_narrative"` is written, and their digests go on
   the `harden.execute` row. Any failure (not configured,
   `REDSIM_DISABLE_LLM=1`, budget exceeded, transport error, guardrail block,
   post-check rejection) leaves the rule text standing with
   `narrative_source = "rules"` and the reason as a limitation. A verify job
   never narrates.
8. **Reports, record, audit, findings.** `render_campaign_reports` writes
   `report.md`, `report.json` and `report.html`. The run record is written as
   `ml.run_record` and mirrored into `ml_campaigns`, and `_emit_record_audit`
   writes the rows the record justifies in spec 10.5 order. `attack.run`
   projects one `Finding` per attack whose ASR at `reference_eps` crosses
   `finding_asr_threshold`, `explain.run` and `harden.recommend` merge the
   child's observations, interpretation and candidates back into the parent
   finding's `schema_blob["ml"]`, and `verify.replay` attaches the
   `MeasuredDelta` and projects the outcome. `report.render` (with the format
   list and artifact ids) and `job.complete` close the trail.

Follow-up actions (`POST /v1/findings/{id}/explain` and `/harden`) and the
verify loop (`POST /v1/findings/{id}/verify`) are admitted by the same
pattern as child campaigns of the parent run (`scanner` `ml.explain`,
`ml.harden`, `ml.verify`, and the `ml_campaigns` row carries `parent_run_id` or
`baseline_run_id`) and run on the same task. Reruns of a failed or cancelled
campaign pass `parent_run_id` to `POST /v1/models/{id}/attacks` and copy the
parent's configuration. The original rows are never touched.

Upload validation is the second task: `POST /v1/models` (multipart) writes a
`model.register` row, the `Target` (`status = "validating"`), an `ml.ingest`
`Run` and a `model.validate` `Job`, and enqueues `redsim.ml_model_validate`,
which re-verifies the blob digest in the parent, loads the model in the
sandbox child (`validate_model_sandboxed`), and moves the target to
`available` or `refused` (deleting the blob) with a `model.validate` row
carrying format, status, gradients, ONNX agreement and library versions, a
`validation_report.json` artifact and `job.complete`.

The offline path (`redsim ml attack <target_id>`, `3ab9de7`) runs the same
`run_campaign_sandboxed` without the database: the `attack.run` row goes
first to a `JsonlAuditWriter` at `<out>/<run_id>/audit.jsonl` (chain
`run:<run_id>`), then `run_record.json`, `report.md/json/html` and the curve
land under `<out>/<run_id>/`, stage events and `job.complete` join the same
chain, `llm_narrative` stays off and the command prints
`narrative_source=rules`. `endpoint_stub` and fixture-only targets are
refused before anything is written. `redsim audit verify --run <run_id>`
finds that chain through the `<output_dir>/<run_id>/audit.jsonl` fallback,
or `--run-dir <out>/<run_id>` names it (`aa9674e`).

## Phase B on `main` (waves B0 to B3)

Plan 12 runs Phase B as five waves. B0 landed every frozen-contract change
once and made the tree truthful with stubs and data; B1 built the library
layer under `redsim/ml/` against those contracts; B2 built the services,
workers and routes over that library and replaced five of the stubs; B3
built interoperability and the bulk operations and replaced the last 14
([Phase B routes](../api/v1.md#phase-b-routes)); B4 added the end-to-end
evidence, the gate, the fix pass that closed the carried B2 and B3 follow-ups,
and the documentation.

### Contracts (wave B0)

- **Schema** (`934838e`): the additive fields listed under
  [the frozen schema](#the-frozen-schema) and in master plan section 0.
  `tests/ml/test_schema_compat.py` pins the frozen fixture's sha256 and
  refuses any removed, retyped or narrowed P0 property.
- **Migration `0011_phase_b_platform`** (`7b1f2fa`): `report_snapshots`,
  `idempotency_keys`, `ml_batches`, `ml_datasets` with `0010`'s RLS parity,
  `projects.ml_scoring` / `ml_max_concurrent_runs` / `ml_daily_run_budget`,
  `ml_campaigns.batch_id`. See [multi-tenancy](multi-tenancy.md).
- **Actions and codes** (`3cd3362`): `llm.probe.run` (remediator),
  `dataset.register` (remediator), `dataset.export` (scanner),
  `integration.push` (admin), `batch.run` (scanner), `report.render`
  (scanner), `finding.author` (remediator), mirrored in the OPA and Cedar
  bundles; 23 spec 17.3 codes in a dated addendum, listed in the
  [API reference](../api/v1.md#error-codes-spec-173).
- **Stubs** (`0b0981b`): 19 routes behind their real gates.
- **Tripwires and CI** (`a625583`): the schema-compat test, the extended
  API-process import block (garak, openai, litellm, reportlab, pyarrow,
  mlcroissant), the child-env credential check, the `garak` marker and
  `garak>=0.16,<0.17` pin, the `e2e-python` and `garak-offline` jobs.
- **Endpoint contract and egress** (`622d741`): `endpoint-v1`, see
  [the contract page](../api/endpoint-contract.md).
- **Datasets** (`ff9e658`): see [Datasets and handling rules](#datasets-and-handling-rules).

### Modality runners (wave B1, `runner-refactor`)

`redsim/ml/campaign.py` is the shared frame: target and defense resolution,
attack-set resolution and the norm check (`attack_supports_norm`), stage
bookkeeping, the evidence lists, the curve and flip-matrix artifacts, the
explain gate, score, interpret, recommend, the narrative deferral, report,
provenance and the `CampaignRecord`. Everything that depends on what a sample
is lives in a `ModalityRunner` (`redsim/ml/runners/base.py`):
`run_<modality>(config, target, *, frame) -> ModalityResult` performs
`sample`, `clean_eval`, `attack:<id>`, `control` and hands back an explain
closure. `MODALITY_RUNNERS` maps every `schema.Modality` literal to a
`"module:attribute"` string (`image` and `tabular` to
`runners.classification:run_classification`, `text` to
`runners.text:run_text`, `detection` to `runners.detection:run_detection`),
resolved lazily so the API never imports a runner; a missing module is the
typed `ModalityRunnerUnavailable` before any stage. The frame pins `NLTK_DATA`
(`<REDSIM_ML_ASSETS_DIR>/lexicons/nltk_data`) and `TORCH_HOME`
(`<work_dir>/torch`) offline for the run's duration when unset. The golden
test `tests/ml/test_campaign_golden.py` runs four scenarios (image FGSM and
PGD with explain, tabular PGD by surrogate, tabular all `not_run`, image
verify with `feature_squeezing`) through the refactored frame and the frozen
pre-refactor copy `tests/ml/_campaign_pre_refactor.py` (sha256 asserted) and
asserts deep equality of every non-volatile field; HopSkipJump is excluded
because ART draws its initial point from an unseeded `RandomState`, which the
adapter records.

### Text modality (wave B1, `text-modality`)

- `redsim/ml/datasets/sms_spam.py`: the tokenizer contract shared by the
  model, the SHAP masker and the attack (`TOKEN_PATTERN` `(?u)\w+`,
  `MASKER_SPLIT_PATTERN` `\W+`, asserted equal), the UCI corpus constants
  (`uci:sms-spam-collection`, CC BY 4.0, classes `ham` and `spam`), the TSV
  reader with digest check and the bundled `eval.jsonl` writer.
- `redsim/ml/assets/train_text_classifier.py`: a scikit-learn `Pipeline` of
  `TfidfVectorizer` (word 1-2 grams, lowercase) and `LogisticRegression`
  trained on a seeded stratified split after exact-string dedupe, macro-F1
  beside accuracy because the prior is 87 percent ham, saved as
  `model.joblib`, `build_text_asset` writing the `ModelEntry` (`sms_tfidf_lr`,
  format `sklearn_joblib`, `gradients: false`, `TextModelSpec` block).
- `redsim/ml/targets/text.py`: `BundledTextTarget` on the tabular pattern.
  `joblib.load` runs only after the manifest digest matched (the spec 9.2
  exception, as for `url_trees`), `predict_proba` over strings, `sample()` a
  seeded stratified array of strings, `art_classifier()` raises
  `AttackNotApplicable` (ART has no text estimator), the synonym lexicon
  resolved from `<assets>/lexicons/synonyms.json` or the WordNet `nltk_data`
  tree.
- `redsim/ml/attacks/word_substitution.py`: `word_substitution` (text,
  evasion, black-box, `norms {edit}`, `takes_eps`): leave-one-out importance
  ranking (one predict call per message), greedy synonym substitution from a
  `SynonymLexicon` (JSON table or offline WordNet through nltk's reader,
  sha256 recorded), stop at the first flip or the budget
  `ceil(eps * n_words) >= 1`, case preserved, one `\w+` token for one so the
  token count is kept, queries counted as predict rows (the HopSkipJump
  denominator convention), deviations from TextFooler stated in the
  description and on every row, `linf` and `l2` recorded `nan`. Default grid
  `{0.1, 0.2, 0.3}`, reference `0.2`. `text_noise_control` swaps random words
  from the slice vocabulary at the same budget with zero model queries and is
  run by the runner, not listed in the catalog. Without a lexicon the attack
  is `LexiconUnavailable` and recorded `not_run`.
- `redsim/ml/explain/shap_text.py`: `shap.Explainer(predict_proba,
  Text(r"\W+"), algorithm="partition")` on the first `k` flipped and `k`
  unflipped messages, clean, adversarial and control, `expl_shift` by cosine
  over positional token attributions with the noise floor from the control,
  `text_diff.json` / `shap_text.png` / `shap_values.npz` per sample, an
  `Observation.text` block and a campaign `shap_summary.json` with counts,
  ranks and shifts only.
- `redsim/ml/runners/text.py`: `run_text` with `Measurement.edit_fraction_mean`
  on every attack row, `pert_first_success` over realised edit fractions, the
  `adv_slice` JSON lines, the MODALITIES-23 limitations (including a
  correction of the standing white-box sentence for a black-box text attack)
  and the flip-matrix extras (budget label, per-message edit fractions, word
  counts). A non-`edit` norm is refused before any stage.

### Detection modality (wave B1, `detection-modality`)

- `redsim/ml/datasets/military_assets.py`: reads the capped subset the
  datasets step publishes under `<assets>/cache/military_assets_subset`
  (YOLOv8 layout: `images/<split>`, `labels/<split>`, a `*.yaml`). Boxes of the
  person and weapon classes (`camouflage_soldier`, `weapon`, `civilian`,
  `soldier`) are dropped at load time under the D3 bound, images left without
  boxes are dropped, the exclusion and seed are recorded on the split. Images
  are stretched to a square with boxes scaled the same way (a stated caveat).
- `redsim/ml/targets/detection.py`: greedy IoU matching, recall with box
  denominators, per-class counts, all-point-interpolated AP averaged over
  classes with ground truth (`map50`, the interpolation convention stated on
  every row), the torchvision `fasterrcnn_mobilenet_v3_large_320_fpn` factory
  (COCO checkpoint from the local torch hub cache only, random init recorded
  otherwise), `BundledDetectionTarget` `assets_frcnn_mnv3` (digest-checked
  `state_dict`, packed `eval_det.npz`, `DetectionModelSpec` block; `predict()`
  returns boxes, labels and scores, `predict_proba` raises
  `AttackNotApplicable`, `art_estimator()` is one `PyTorchFasterRCNN`).
- `redsim/ml/attacks/dpatch.py`: `dpatch` (detection, white-box, `norms
  {patch_area}`) wraps ART DPatch untargeted against the ground-truth boxes:
  `eps` is the patch area share, side `round(sqrt(eps * H * W))`, one universal
  patch per slice and `eps` pasted at a seeded location per image, the
  realised share, side, universal / replacement / digital-patch notes and the
  nondeterminism recorded. `patch_noise_control` pastes a uniform-noise patch
  of the same side at the same seeded locations with no model access.
- `redsim/ml/assets/train_detector.py`: seeded SGD fine-tuning with bounded
  epochs and cosine decay, per-epoch measured recall and `map50`, last-epoch
  metrics (the evaluation split is never used for selection).
- `redsim/ml/runners/detection.py`: `run_detection` rows count ground-truth
  boxes as `n`, matched boxes at IoU >= threshold as `n_correct`, `accuracy`
  is recall (said in `notes`), `attack_success_rate` is the suppression rate,
  `conf_gap` is `None` with an "undefined for detection" note,
  `Measurement.detection` filled beside scalar `det_*` params. The explain
  closure records `ExplainerUnavailable` ("no SHAP explainer for object
  detectors") per attack plus a limitation and writes box evidence
  (`clean_boxes.png`, `adv_boxes.png` with the patch drawn, `boxes.json`).
  `mri=False`: the frame records `ScoreStatus` unavailable and never computes
  an MRI; a `DetectionScorecard` per attack (worst-case recall ratio,
  suppression rate at the reference patch area, recall AUC over the grid,
  `map50`, all with denominators) is written as `detection_scorecard.json`
  and validated to carry no MRI key (owner default MODALITIES-36).
  Detection-worded interpretations and recommendations (patch-aware
  adversarial training, occlusion detection, multi-frame consistency, with
  references) are exposed for the rule layer. A detection config with a
  defense raises `AttackNotApplicable` (`defense_modality_mismatch`) rather
  than faking a verify; wave B2 built no detection defense (MODALITIES-39 /
  -40), and admission refuses one with `422 defense_modality_mismatch`
  because no catalog row declares `detection`.

### Phase B attacks (wave B1, `attacks`)

`cw_l2` (Carlini-Wagner L2 over ART `CarliniL2Method`), `deepfool`
(`DeepFool`) and `zoo` (`ZooAttack`) are described in the
[attack catalog](../api/v1.md#attack-catalog). Shared registry additions:
`KNOWN_NORMS` `{linf, l2, edit, patch_area}`, `attack_norms(adapter)` and
`attack_supports_norm(adapter, norm)` (the frame refuses an adapter in a
norm it does not declare and records it `not_run`; since wave B2 admission
refuses the same case first with `422 params_out_of_range` on `norm`),
`norm:<n>` capability tags, `attack_domain_defaults` /
`apply_domain_defaults` for per-modality cost defaults (image HopSkipJump
`IMAGE_DEFAULTS`), the shared `queries_summary` / `achieved_norm_note` /
`require_class_gradients` helpers, `ATLAS_TECHNIQUES` entries for the new
evasion adapters, and a catalog check that the registered ids match the
declared list (`adv_patch`, MODALITIES-32, recorded as not built with its
reason). ZOO re-imposes frozen tabular features through `TabularScaling`,
keeps the exact clean value on coordinates it did not move, and uses
`learning_rate` 0.1 and `variable_h` 0.05 instead of ART's image defaults,
which moved nothing on the tree ensembles (recorded in the module docstring).

**Measured CPU budgets** (ATTACKS_HARDEN-22 / -24; a CPU-only Apple silicon
laptop, Python 3.12.13, torch 2.14.0 pinned to 2 threads as in the sandbox
child, ART 1.20.1, seed 0, the real bundled models, 2026-09-09). These are
budgets for choosing `n_samples` and defaults, never accuracy or robustness
claims about the models:

| Target | Attack, parameters | n | Wall time | Per sample | Observed |
|---|---|---|---|---|---|
| `vehicles_cnn` (resnet18 at 128 px, 7 classes) | forward pass, batch 64 | | | 7.1 ms per row | |
| `vehicles_cnn` | `hopskipjump`, `IMAGE_DEFAULTS` (`max_iter` 10, `max_eval` 250, `init_eval` 50, `init_size` 50) | 8 | 63.3 s | 7.9 s | 6 of 8 flipped, `queries_mean` 1393.0 (8358 predict rows in 1670 calls). n = 64 is about 8.5 min; n = 200 does not fit the 1200 s sandbox wall clock. Hence the B2 cap of 64 |
| `vehicles_cnn` | `cw_l2` defaults (`binary_search_steps` 5, `max_iter` 10, `initial_const` 0.01) | 8 | 48.2 s | 6.0 s | 6 of 8 changed, median achieved L2 0.27, max 0.47. `initial_const` 0.1: 50.2 s, median 0.24; 1.0: 50.3 s, median 0.29 (defaults kept) |
| `vehicles_cnn` | `deepfool` defaults (`max_iter` 20) | 8 | 10.4 s | 1.3 s | 8 of 8 changed, 4 of 8 flipped from the clean prediction, median L2 0.22, max 0.52 |
| `url_trees` (HistGB, 16 features) | `zoo` defaults (`learning_rate` 0.1, `variable_h` 0.05) | 16 | 90.9 s | 5.7 s | 11 of 16 flipped, `queries_mean` 100.4 (1104 single-row predict calls: ART's `BlackBoxClassifier` batches at ZOO's `batch_size` 1). `variable_h` 0.1 / `learning_rate` 0.2: same counts, 90.1 s |

The rows live in `hopskipjump.MEASUREMENT` and in the body of the attacks
commit. Spec 12.2 named image HopSkipJump as a Phase B adapter; the tree
serves it through the Phase A adapter with image defaults (`phase: "A"`),
recorded under [accepted divergences](#accepted-divergences).

### Black-box explanation (wave B1, `explain-blackbox`)

`redsim/ml/explain/shap_tabular.py` gains an `explainer` choice (`auto`,
`TreeExplainer`, `KernelExplainer`): `auto` takes `TreeExplainer` when a tree
model is reachable and falls back to `KernelExplainer` (the tree failure
recorded in `explainers_tried`), an explicit choice never falls back, the
image explainer names are refused. `KernelExplainer` uses a seeded 100-row
background drawn outside the explained rows (`KERNEL_BACKGROUND_ROWS`), the
explainer family lands on every `Observation.metric_note`, `feature_diff.json`
and the summary, every `predict_proba` call is counted with an upper bound
beside it, and the calls run inside `target.purpose("explain")` when the
target offers it. `redsim/ml/explain/base.py` (no heavy imports, so the API
may import it) carries `EXPLAINER_KINDS`, `ExplainQueryCaps` and
`EXPLAIN_QUERY_CAPS = (20 background rows, 200 nsamples, explain_k 8)` for
endpoint targets (detected through `metadata["access"] ==
"black-box-endpoint"`), `estimate_kernel_explain_rows` (the ENDPOINT-08
admission estimate) and `EXPLAINER_ROSTER` for the capabilities route, which
carries it since wave B4 as `explainer_roster` (the admission service reads
`EXPLAIN_QUERY_CAPS` directly since wave B2).
KernelSHAP for images is not built (about 100k predict calls per
3x128x128 sample); `PartitionExplainer` stays the black-box image explainer
(ATTACKS_HARDEN-08, recorded under accepted divergences).

### Endpoint target and predict broker (wave B1, `endpoint-target`)

Described in full on [the contract page](../api/endpoint-contract.md):
`EndpointTarget` (`redsim/ml/targets/endpoint.py`) implements the `Target`
protocol over ART's `BlackBoxClassifier` with `gradients: false` and
`metadata["access"] = "black-box-endpoint"`; the worker-parent
`PredictBroker` (`redsim/ml/endpoint_broker.py`) is the only outbound HTTP of
the vertical, enforces the egress policy, a token-bucket rate limit and the
row and request budgets from `REDSIM_ML_ENDPOINT_*`, retries 5xx twice, and
records `BrokerStats` into `Provenance.model_manifest["endpoint_broker"]`;
the sandbox child reaches it over a unix socket in the 0700 work directory
with no URL and no credential. Registration, admission and the worker wiring
landed in wave B2 (the sections below).

### Training defenses (wave B1, `hardening`)

`redsim/ml/defenses.py` rows carry `kind` (`preprocessing` or `training`) and
`phase`; `DEFENSES` stays the preprocessing tuple the Phase A verify admission
treats as runnable, `TRAINING_DEFENSES` and `ALL_DEFENSES` are new, and
`apply_defense` refuses a training id with a pointer to
`redsim.ml.harden.apply.apply_training_defense`. That hook is the
`defense_apply` stage: it fine-tunes a deep copy of the target's torch module
on the bundled training slice (`bundled/<model>/train_slice.npz`, written by
the image builds since the B1 integration; ATTACKS_HARDEN-11) and returns a
`DerivedTorchTarget` whose `manifest()` keeps the parent's digest keys so
`Provenance.model_sha256` stays the parent's identity (spec 15.6), with the
`TrainingRecord` (resolved params, `n_train`, epochs run, wall time, parent
and derived weight digests, loss per epoch, clean correct before and after,
library versions) as `Provenance.defense` and as `training_report.json`.
`adversarial_training` drives ART `AdversarialTrainer` one epoch at a time
with PGD (or FGSM when `pgd_iters` is 0) at the campaign's reference eps in
the campaign norm; `defensive_distillation` is native torch (frozen teacher,
soft labels at temperature `T`, KL times `T^2`, student evaluated at `T = 1`).
Both are bounded by `epochs`, `train_n` and `wall_budget_s`, keep the backbone
frozen by default and are deterministic under the seed. A target without a
torch module (the tabular tree ensembles) or without a slice is the typed
`TrainingDefenseUnavailable` (`training_defense_unavailable`, ATTACKS_HARDEN-20):
the frame records the defense unavailable, runs the rows on the undefended
model and withholds the score so the verify is `inconclusive`, and nothing is
faked. Record and limitation texts avoid the banned word "hardened".

### Endpoint connector (wave B2, `endpoint-admission`)

`POST /v1/models` with `source: endpoint` is real: gated on `target.manage`
before any field is read, the body validated as `EndpointRegistration`, the
static egress check, the `AuthProfile` resolved without decrypting it, the
dataset bound, the `model.register` row with the allowlist verdict, a
`Target` of kind `ml_model_endpoint` (`value` the normalised URL, detail
host-only, `format: "endpoint"`, `gradients: false`, the descriptor digest as
`sha256`, `status: validating`), then `redsim.ml_model_validate`, whose
endpoint variant resolves the credential at pickup, hands it only to
`probe_endpoint_sandboxed` and records the probe (response fingerprint,
latency, `tls_mode`, rows, requests, resolved addresses) or the frozen
`refusal_reason` with the typed class beside it. `endpoint_kind: llm` hands
off to the LLM registration below. Projections carry a credential-free
`endpoint` block and `available_attacks`; the URL, the secret and the
ciphertext never appear. The route table and the codes are on the
[contract page](../api/endpoint-contract.md) and in the
[API reference](../api/v1.md#register-an-endpoint).

### Phase B admission (wave B2, `admission-phase-b`)

`redsim/services/ml_campaigns.py` (`tests/ml/test_admission_phase_b.py`):
`SUPPORTED_MODALITIES` maps `image`, `tabular`, `text` and `detection` to a
`ModalitySpec` (admitted norms, default grid and reference per norm from
`redsim.ml.scoring`, `word_substitution` and `dpatch`, the `n_samples`
default and cap, the endpoint flag, the `mri` flag: detection is
`mri=False`); `llm` is `NOT_IMPLEMENTED_MODALITIES` pointing at the probe
route. `check_norm_for_modality` and `attack_supports_norm` refuse a norm the
modality or the adapter does not take with `422 params_out_of_range` on
`norm`; `apply_domain_defaults` is applied for validation only, so only the
caller's keys are frozen. Detection campaigns default to 50 samples and are
capped at 200 (`DETECTION_N_SAMPLES_CAP`). An endpoint target is admitted
with gradients forced `false` (every white-box attack
`attack_requires_gradients`), image and tabular only, `explain_k` capped at
`EXPLAIN_QUERY_CAPS.explain_k`, and its worst-case query estimate compared
with `EndpointLimits.from_env(modality)` merged with the binding limits
(`429 query_budget_exceeded` with `estimate` and `cap`); the frozen config's
`target_snapshot` becomes `endpoint:<host>` with URL, auth and allowlist keys
scrubbed. The scoring block is the rerun parent's, else the project's
`ml_scoring` override, else `ScoringConfig()`, validated without
renormalising; `scoring_source`, `scoring_weights` and `non_default_weights`
travel on the response and the audit row (`is_default_weights` is the spec
15.3 predicate). On verify the runnable catalog is `ALL_DEFENSES`: a training
defense is admitted for the modalities its row declares on a model whose
manifest gradients are not `false`, tabular is `422 defense_modality_mismatch`
with `TREE_ENSEMBLE_REASON`, a gradient-free target `422 params_out_of_range`
with `training_defense_unavailable`.

### Endpoint campaigns (wave B2)

`redsim/workers/tasks/ml_campaign.py` (`worker-campaign-phase-b`,
`tests/ml/test_tasks_phase_b.py`) detects an `ml_model_endpoint` target,
resolves the `AuthProfile` credential at run time
(`services.auth_profiles.resolve_auth_for_scan`), builds the credential-free
`target_endpoint` block (the URL read from `Target.value`, host-only detail
accepted) and dispatches `run_campaign_sandboxed(..., target_endpoint=,
endpoint_auth=, endpoint_allowlist=)`. The broker is started in the worker
parent and stopped by the sandbox in every exit path; the secret reaches only
the broker, never the child, a `job.detail`, a log or an audit row. The
parent-side tally (rows, requests, by purpose, budget, fingerprint) is read
from `provenance.model_manifest["endpoint_broker"]` and recorded on the run
record and on the `attack.execute`, `campaign.score` and `job.complete` rows;
for endpoint runs the `attack.execute` rows are written after the record so
they carry the counts. The typed transport-failure mapping of ENDPOINT-30 in
this task is not built (open item, README). Two more endpoint seams are
recorded by `tests/e2e/test_ml_endpoint.py` and not fixed: the frozen
`query_budget.limits` fold the registration's `batch_rows` and `timeout_s`
while the broker runs with the validate-time defaults, and the broker's
`by_purpose` split is `{probe, predict}` because the classification runner
never enters `EndpointTarget.purpose(...)`. The campaign path itself is
blocked at the B4 push by the unscaled 8-row probe in
`redsim/ml/targets/endpoint.py:228` (no endpoint reaches `available` through
the tiny server), the one defect the three failing endpoint e2e cases name.

### Training verifies and retests (wave B2)

After a verify whose `provenance.defense.kind == "training"`, the same task
registers the derived weights the child wrote (`derived_model/weights.pt`)
as a NEW `Target` of kind `ml_model_artifact`, source `derived`, with
`MLModelManifest.derived_from = DerivedFrom(parent_target_id, parent_sha256,
defense_id, training_budget)` through the register-then-validate path
(`status: validating`, a validate `Run`, a `model.validate` `Job`, the
`model.register` row on the validate run's chain before the enqueue,
`ml_model_validate.delay` best-effort so a durable queued `Job` survives a
broker outage). No derived weights means no registration and never a faked
one, and the verify job never fails on it. `verify.execute` and the
`RemediationAttempt` summary carry `derived_sha256`, `derived_target_id`,
`parent_sha256` and `training_budget` (the frozen `MeasuredDelta` keeps its
shape; the digest lives in the surrounding context). Every verify appends a
`FindingVerify` with `settings_hash` and `baseline_run_id` to
`MLFindingDetail.retests`, keeping `verify == retests[-1]`, which is what
the review workflow's `resolve` gate reads.

### LLM probes through Pythia (wave B2, `llm-core` and `llm-api`)

`redsim/ml/llm/` is a self-contained package imported by the worker and the
tests only (a fresh-interpreter test proves the API imports none of it with
garak, openai, litellm, torch, transformers, shap, sklearn, ART and
onnxruntime blocked). `catalog.py` and the committed `catalog.json` (regenerated
from garak 0.16.0 by `build_catalog_from_garak()`, read with json and pydantic
only, a `garak`-marked test asserts the committed JSON equals a fresh
regeneration): 103 probes across thirteen modules, the `redsim-core` set of 76
probes whose primary detector is a string, trigger or regex matcher, the
opt-in `redsim-extended` set of 85 (the core plus the nine probes whose
primary detector is a Hugging Face classifier), and 18 excluded rows with
visible reasons (`fitd.FITD` for HarmBench, owner default LLM-08;
`dan.AutoDAN`, which drives a red-team model; `grandma.GrandmaIntent`, whose
detectors are intent-routed; every uncapped `*Full` / `RepeatExtended` corpus
variant whose capped sibling exists). Each `ProbeInfo` carries a `short_id`
so `llm.probe.<module>.<short_id>` fits the 64-character audit action column.
`generator.py`: `PythiaGenerator(OpenAICompatible)` with `uri` the gateway's
`/v1/`, `X-Pythia-Persona` as a default header, TLS from
`redsim.llm.pythia.tls_verify`, OpenAI client `max_retries=0` and a bounded
retry loop in place of garak's uncapped backoff, a body of exactly `model`,
`messages`, `temperature`, `max_tokens`, the key caller-supplied (an
`api_key=` or a 0600 `key_file=`, never the environment, never garak's
`_config`, which garak dumps into `report.jsonl`), a `UsageLedger` (requests,
statuses, retries, tokens, wall time, the model ids the gateway answered
with, `tls_mode`) and `assert_no_litellm`. `probe_child.py` (`python -m
redsim.ml.llm.probe_child --spec <json>`): pins the XDG and Hugging Face
offline variables before importing garak, reads and deletes the key file,
refuses a garak version other than the catalog's (exit 3), writes a
`garak.yaml` (no deprecated argv flags), validates every probe against the
live registry and the detector policy (`unknown_probe`, `probe_excluded`,
`detector_model_unavailable_offline` become `not_run` rows), enforces the
hard prompt cap on every probe through a wrapper around
`garak._plugins.load_plugin` (garak's soft cap is honoured by only some
probes), reads `report.jsonl` for counts only, raises the openai, httpx and
httpcore loggers so `garak.log` carries no request headers, and scrubs every
written file for the key. `runner.py`: a 0700 work directory, the 0600 key
file, the child environment from the plugin sandbox's interpreter allowlist
with network on and `PYTHIA_*`, `AWS_*`, `KAGGLE*`, `OPENAI*`, `HF_TOKEN`,
`HUGGING_FACE*`, `GOOGLE_`/`AZURE_`/`ANTHROPIC_` and every other `REDSIM_*`
swept (`assert_child_env_minimal`), rlimits (`REDSIM_LLM_PROBE_TIMEOUT_S`
1500 s, CPU 1200 s, 4096 MB, 1024 MB files, 64 processes), cancellation
polling, process-group kill, the key file deleted in `finally`, and a typed
`ChildOutcome`. `scorecard.py`: `DetectorResult` (`llm.<probe>.<detector>`,
`n_evaluated`, `n_hits`, `n_passed`, `n_none`, `hit_rate` `None` exactly when
`n_evaluated` is 0 and otherwise validated equal to k/n, garak's CI),
`ProbeResult`, `ProbeFamilyResult` (probe counts, deliberately no family
rate), `UsageSummary`, `LLMProbeScorecard` (`kind llm_probe`, `completeness`,
`limitations`, artifact digests) with a validator that walks the dump against
`FORBIDDEN_KEY_RE` (mri, grade, subscore, `S_*`, `robustness_index`,
weights) and requires the D9 sentence; `assert_no_mri` is the reusable guard.
`rules.py`: `interpret()` and `recommend()` (`r.L1` to `r.L7`, every
candidate `not evaluated`, `narrative_source rules`,
`NARRATIVE_NOT_OFFERED_REASON`). `report_section.py` renders the seven-section
probe report and the fragment `redsim.ml.reporting` embeds between sections
2 and 3, guarded by `check_llm_report_text` (no banned score word, no MRI or
grade wording outside D9).

`redsim/services/ml_llm.py` (API-light, no garak, openai or ML import) holds
the vocabulary (`ml.llm_probe` scanner, `llm.probe` job type,
`redsim.ml_llm_probe_run` task, `ml.llm_probe` usage task,
`ml.llm.scorecard` kind, the guardrail modes, the default set), the
`LLMProbeRequest` model, `register_llm_target`, the catalog reader,
`resolve_probes`, `admit_llm_probe_run` (audit-first, `Run` and `Job`, the
enqueue on `default`, no `ml_campaigns` row), `read_llm_scorecard` and the
`is_llm_probe_run` / `refuse_llm_probe_run` guards `/campaign` and `/compare`
use. `redsim/api/v1/llm.py` replaces the three B0 stubs.
`redsim/workers/tasks/ml_llm.py` is the task described in the
[API reference](../api/v1.md#llm-probes): refusals before any gateway
request, the entitlement check, the child, per-probe stages and
`llm.probe.execute.<short_id>` rows, the `ml.llm.*` artifacts never parsed
for text, the scorecard with its `llm.probe.score` row, one `LLMUsage` row,
findings through `services.ml_findings.project_llm_findings` with hit-rate
severity labelled as such, rule candidates, the reports, `report.render` and
`job.complete`. `tests/ml/fake_openai_server.py` is the OpenAI-compatible
stdlib server the tests drive garak against; no probe run against the live
gateway has been recorded.

### Review workflow (wave B2, `review-workflow`)

`redsim/services/finding_review.py` (`tests/ml/test_review_workflow.py`) is
one transition table over (`Finding.status`, `schema_blob.<ml|llm>.review.state`)
with six decisions (`submit`, `confirm`, `request_changes`, `dismiss`,
`reopen`, `resolve`), independence by identity (campaign creator, latest
revision author, retest requester, system principals; `403
reviewer_not_independent`), compare-and-set on `expected_status` and
`expected_review_state` (`409 review_state_conflict`), `resolve` judged by
`resolution_conditions()` (`poc_passed`, `fixed`, `confirmed`, a linked
retest at the baseline's `settings_hash` and `baseline_run_id` with outcome
`verified`; else `409 resolution_blocked` with the unmet list), every
decision audited through `authorize()` before the write, history appended
instead of replaced, `list_retests()` with compatibility per retest, and
analyst drafts (`create_draft_finding`, `revise_draft`) whose evidence ids
are checked against the digest-verified run record. The routes are in the
[API reference](../api/v1.md#review-workflow). The Phase A dismissal route
keeps its rules, codes and plain-string `forbidden` byte for byte.

### Reports, snapshots, compare and weights (wave B2, `reports-compare-weights`)

`redsim/ml/pdf.py` renders the report Markdown into reportlab flowables
(imported inside the function, so the API tripwire holds), byte-identical
for the same record and stamp, with DejaVu Sans subsets under
`redsim/ml/pdf_fonts/` (Bitstream Vera licence, the subset command in its
README), `REDSIM_PDF_FONT_DIR` as the override and a `PdfFontsUnavailable`
refusal rather than a Latin-1 fallback; text extraction confirms the six spec
14.8 headings and the ε and Δ glyphs. `redsim/ml/reporting.py` gains the
`schema_version` and licence lines, the **Non-default weights** badge, the
derived-model lineage in the delta block, the open-D006 sentence, `formats=`
and the LLM section hook. `redsim/services/reports.py` writes one
`report_snapshots` row per render (`snap-<hex>`, `artifact_ids`,
`record_sha256`, `rendered_at`, `created_by`), admits `report.render` jobs
audit-first and serves, resolves, archives and restores snapshots;
`redsim/api/v1/reports.py` serves `report.pdf`, `?snapshot=`, the render
route and the snapshot routes ([API reference](../api/v1.md#reports)).
`redsim/ml/compare.py` is the pure comparison module: compatibility per
config field plus `sample_indices_sha256` with the scoring block compared per
sub-key, `comparison_table` over 2 to 10 runs in request order with a delta
only on a verify row whose baseline is in the set, `assert_no_aggregate_keys`;
`GET /v1/runs/compare?ids=` is the thin route over it. `GET`/`PUT
/v1/projects/{slug}/ml-scoring` store the full `ScoringConfig` or `null`,
never filled in or renormalised, audited as `project.settings`.
`redsim/api/middleware/idempotency.py` honours `Idempotency-Key` on the
mutating ML routes ([API reference](../api/v1.md#idempotency-key)). Since
wave B4 the campaign task's completion path renders `md`, `json`, `html` and
`pdf`, lists what it wrote on the `report.render` row and records the run's
first `report_snapshots` row over those artifact rows
(REVIEW_REPORTS-16/-20); `POST /v1/runs/{id}/report.render` adds further
snapshots (version 2 onwards). A record whose measurement table is too wide
for the PDF renderer (reportlab `LayoutError`, observed on a 13-column table)
degrades to the three text formats with `pdf_unavailable` on the row and the
job completes; the on-demand render route still raises on such a record
(open item, `redsim/ml/pdf.py`).

### Croissant export (wave B3, `interop-contribute`)

`redsim/ml/interop/` (pyarrow imported inside functions only, so the API
tripwire holds): `parquet.py` builds one deterministic Parquet shard per
(attack, ε) for the adversarial family, plus the control family and the clean
slice when the run persisted them, on one fixed nullable Arrow schema
(`family`, `attack`, `eps`, `norm`, `sample_index`, `true_label`, `flipped`,
`y_pred_clean`, `y_pred_adv`, `conf_clean`, `conf_adv`, `input`,
`dataset_id`, `dataset_revision`, `run_id`), rows sorted by `sample_index`, a
pinned writer so the bytes are byte-identical and the shard sha256 is its
content id, `input` always a numeric vector or flattened tensor and never a
URL string. `croissant.py` builds the MLCommons Croissant 1.0 manifest with a
`redsim:provenance` block (model and settings digests, dataset identity and
licence with the coverage caveat, the frozen campaign configuration, the
limitations verbatim, the ATLAS technique per attack, the release,
`baseline_run_id` for a verify run); the manifest's own sha256 is the dataset
version; `check_projection` is the projection-equality guard (every
adversarial row's `flipped` equals the run's `ml.flip_matrix`, cross-checked
from retained predictions when present, `ExportMismatch` otherwise) and
`croissant_validate` the structural gate that also refuses model file names,
`reviewer_notes`, credential environment names and any bare MRI (D9).
`card.py` renders the dataset card from a template, never by the LLM.
`redsim/services/ml_datasets_export.py::admit_export` is the audit-first
admission (`dataset.export` row, follow-up `Run` with scanner
`ml.dataset_export` and `Job` of type `dataset.export`, enqueue on `scans`;
`409 export_unavailable` / `export_in_flight`, `422 fixture_not_exportable`,
`503 queue_unavailable` with the rows rolled back; one export per run, a
second call answers the existing manifest) and `get_export_manifest` the
digest-checked read. `redsim/workers/tasks/dataset_export.py`
(`redsim.dataset_export`) loads the slices and the flip matrix, guards,
writes `datasets/<source-run-id>/` as `ml.dataset.manifest`,
`ml.dataset.parquet` and `ml.dataset.card` rows on the source run, and the
`dataset.export.execute` and `job.complete` rows; a mismatch or an invalid
manifest is a `success=False` execute row and a failed job with nothing
written. Since the B3 reconcile pass the classification runner writes
self-describing `clean_slice.npz`, `adv_slice/<attack>_<eps>.npz` and
`control_slice/<eps>.npz` with the per-sample prediction keys (INTEROP-04
closed for image and tabular), and the exporter labels each slice from the
`family` / `attack` / `eps` keys embedded in its bytes, so a live export of a
classification run carries clean, adversarial and control shards with
populated prediction columns; a non-npz slice (the text runner's JSON lines)
is skipped with a caveat, and an all-unlabelled run is a refusal, never a
guess. `tests/ml/test_interop_export.py` proves it end to end on a real
campaign through the filesystem blob store.
The published sample and the rules are in
[Interoperability](../interop.md#contribute-a-runs-adversarial-examples-as-a-croissant-dataset).

### Consumed slices (wave B3, `interop-consume`)

`POST /v1/datasets` (`redsim/api/v1/datasets.py`, multipart only) runs the
static checks of `redsim/services/ml_datasets.py` (stdlib only): the length
cap, the project and gate, Parquet magic at both ends and no pickle-shaped
name, a Croissant `Dataset` with a `distribution` list when a manifest is
sent, every `contentUrl` a bare file name present in the upload (nothing is
ever fetched), a licence, and the declared schema (`modality` `image` or
`tabular`, `class_names`, `label_column`, tabular `features` or the manifest's
`recordSet`, image `input_shape`, `dtype` and `value_range`); `text` and
`detection` are `501` with the reason. Every refusal is a `success=False`
`dataset.register` row and persists nothing. Success writes the row, the blobs,
the `ml_datasets` row in `validating` (the manifest digest as the revision), an
`ml.dataset_ingest` `Run` with no target and a `dataset.validate` `Job`, then
enqueues `redsim.ml_dataset_validate` on `scans`.
`redsim/workers/tasks/dataset_validate.py` re-hashes the blobs in the parent
and spawns `python -m redsim.ml.interop.consume` (the parse child, pyarrow
inside functions) under the ML sandbox's allowlisted credential-free
environment, rlimits, process group and wall clock; the child checks the
manifest digests, reads row-group batches under `REDSIM_ML_DATASET_MAX_ROWS`,
checks columns, types, labels, image sizes and value ranges, and returns a
`consumed-slice-1` report in the sandbox envelope shape. The row becomes
`available` or `refused` with the child's code, one `dataset.validate` audit
row and the `ml.dataset_validation_report` artifact are written, then
`job.complete`. The binding helpers (`resolve_consumed_slice`,
`consumed_dataset_binding`, `load_consumed_slice`) exist; the campaign
admission calls `resolve_consumed_slice` since the B3 reconcile pass (a
`ds-…` id must be an `available` slice of the project matching the campaign
modality, else `422 dataset_incompatible`; `dataset_revision` defaults to the
manifest digest; `dataset_id` and `dataset_role` on the audit rows). Since
wave B4 the upload admission binds a consumed slice too
(`check_upload_dataset` falls back to `consumed_upload_binding`, an
`available` slice of the project, split `eval` only) and the target loader
reads one the worker parent materialised
(`ml/targets/artifact.py::consumed_eval_slice` over a
`target_detail["consumed_slice"]` block written by
`services.ml_models.materialize_consumed_slice`, digest re-checked, the same
`load_consumed_slice` reader the parse child used, image rows scaled onto
[0, 1] from the declared range). What stays open is the one call in the
worker parent that writes that block (`redsim/workers/tasks/ml_model.py`,
`ml_campaign.py`), so a campaign on a consumed-bound model does not run end
to end yet; `tests/e2e/test_ml_interop.py` fails on it by attribution.

### ATLAS stamping, coverage and the Foundry push (wave B3, `atlas-foundry`)

`redsim/ml/atlas.py` carries `STAMP_TECHNIQUE_IDS`, checked at import against
`atlas_data.ATTACK_TECHNIQUE_IDS` (`fgsm`, `pgd`, `cw_l2`, `deepfool`, the
surrogate PGD, `word_substitution` and `dpatch` stamp `AML.T0043`;
`hopskipjump` and `zoo` stamp `AML.T0040`; the poisoning ids map to
`AML.T0020` for package F; controls `None`), `technique_for_attack`,
`attack_atlas_row` for the catalog and `coverage(record, catalog_attacks)`,
the per-campaign view with no `int` or `float` anywhere (a `ValueError` if
one appears). `services.ml_findings.build_finding_detail` stamps
`atlas_technique` on every new ML finding; `GET /v1/attacks` rows gain the
ATLAS block and the response the release citation; `GET
/v1/runs/{id}/atlas-coverage` serves the view. `redsim/integrations/foundry.py`
holds the settings (`REDSIM_INTEGRATION_FOUNDRY_URL` unset means disabled;
the B0 egress rules and the `REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL=1`
attestation; no token variable), the roster block, `build_scorecard_payload`,
the D9 payload guard `validate_push_payload` / `assert_push_payload`,
`scrub_detail` and the `FoundryClient` over the Datasets v2 flow;
`redsim/integrations/__init__.py` is the admission boundary
(`create_foundry_push`: the typed refusals, the `integration.push` row on the
follow-up run's chain, the `Run` with scanner `ml.integration_push` and the
`Job` of type `integration.push`, the enqueue on `default`) plus the
`LATTICE_STATUS` text; `redsim/workers/tasks/integration_push.py`
(`redsim.integration_push`, `max_retries=0`) re-reads the settings, loads the
digest-checked record, guards the payload, stores `ml.integration.payload` /
`ml.integration.rows` first, decrypts the bearer token only then, pushes,
stores `ml.integration.receipt` and writes `integration.push.execute` and
`job.complete`. Proven against `tests/ml/fake_foundry_server.py` only
(INTEROP-26 unmet); the dataset push is not built. Details in
[Interoperability](../interop.md#foundry-the-scorecard-push) and the
[API reference](../api/v1.md#integrations).

### Batch campaigns and bulk verify (wave B3, `bulk-service-routes`)

`redsim/services/ml_batches.py::create_campaign_batch` runs write-free
pre-checks (`params_out_of_range`, `batch_too_large` against
`REDSIM_ML_BATCH_MAX_MEMBERS`, `not_found`, `batch_modality_mismatch` with
groups, each a `success=False` `batch.create` row), writes one `batch.create`
row and the `ml_batches` row, then admits each member through the unchanged
`create_attack_campaign` (its own `attack.run` row before its rows) and
stamps `batch_id` on the member's `ml_campaigns` row, `Run.stage_table` and
`Job.detail` (`batch_member_index`); the capacity service is consulted per
member (deferral or a collected `daily_budget_exceeded`), `max_parallel`
defers members beyond it, per-member refusals are collected and the batch is
`422 batch_member_refused` only when nothing was admitted. `rollup_status`
(`queued`, `running`, `succeeded`, `partial`, `failed`, `cancelled`) is
recomputed by `batch_view`, which lists members with `score_status` and a
`scorecard_url` and never an MRI number. `cancel_batch` writes one
`batch.cancel` row then cancels every live member through
`services.runs.cancel_run`. `redsim/ml/compare.py::comparability_groups`
partitions members by the pairwise rule with no delta, mean or rank
(`assert_no_aggregate_keys`). `create_verify_batch` is owner decision BULK-16
as implemented: one `create_verify_campaign` per `(defense, params)` on a
primary finding and one `verify.replay` row per additional selected finding
naming the shared run, both written through the single boundary's
`before_enqueue` hook so the worker never sees the job without them; since
wave B4 the worker projects the shared record onto every listed finding from
that finding's own attack rows (one `verify.execute` row per finding, the
primary first, every listed finding `inconclusive` / `open` on a child
failure), and the view says per finding whether the shared run is projected. `redsim/api/v1/batches.py` is the thin route layer
([API reference](../api/v1.md#batch-campaigns)).

### Bulk upload, capacity and the CLI matrix (wave B3, `bulk-upload-capacity-cli`)

`redsim/api/v1/models_bulk.py` admits several model files in one multipart
request (`411` / `413 bulk_too_large` before parsing, `422
bulk_too_many_files`, a one-to-one filename match, one `bulk.upload` row and
an `ml_batches` row of kind `upload`, then the single-upload admission per
file with `bulk_id` stamped; `201`, `207` or `422 batch_member_refused`; no
model bytes deserialised in the API) and serves `GET /v1/ml/capacity`.
`redsim/services/ml_capacity.py::admit_or_defer` reads
`Project.ml_max_concurrent_runs` (default 2) and `ml_daily_run_budget`
(unset is uncapped) from the `0011` columns, counts from the jobs table, defers
an over-cap admission (queued, `detail.deferred`, the `capacity_deferred`
marker, no broker message) and refuses an over-budget one with the audited
`429 daily_budget_exceeded`; `dispatch_deferred` enqueues oldest-first while a
slot is free. `redsim/workers/tasks/capacity.py` holds `continue_deferred`
(`continue_deferred`, wrapped by the `deferred_continuation` context manager
that `ml_campaign_run` enters around `task_context`, so every exit path of the
campaign task dispatches the project's deferred jobs once the terminal status
is committed; it never raises) and the beat task
`redsim.ml_dispatch_deferred` every 60 s on `default`;
`redsim/observability.py` fills `redsim_jobs_active` and adds
`redsim_ml_deferred_runs{project}` and `redsim_ml_daily_budget_used{project}`.
At the B3 integration the caps bind batch members; the single-run admissions
do not consult the service. `redsim/cli/ml.py`: `redsim ml attack` takes
several target ids or `--matrix FILE.yaml` (models x attack sets x ε grids x
seeds, the schema printed by `--help`), runs one offline campaign per cell
with its own run directory and hash-chained `audit.jsonl` verified with
`verify_chain`, prints a per-cell table with no mean or rank, writes
`<out>/matrix-<id>/summary.json`, honours `--fail-fast` and exits 1 when any
cell was refused or failed; the single-target path is unchanged.

### What wave B4 closed and what stays open

| Carried into wave B4 (from waves B0 to B3) | State at the B4 push |
|---|---|
| e2e evidence covered Phase A only (22 cases); everything B2 and B3 built was proven by `tests/ml/` | closed: `tests/e2e/test_ml_endpoint.py`, `test_ml_llm.py`, `test_ml_text_detection.py`, `test_ml_attacks_harden.py`, `test_ml_review_reports.py`, `test_ml_interop.py`, `test_ml_bulk.py` drive every path through the real API, worker and sandbox child. Where a file meets a product defect it fails with an attribution naming the module (below), never with a weaker assertion |
| no `make check-phase-b`, no docs-consistency test | closed: `scripts/phase_b_gate.sh` (nine steps, the first failure naming its spec 26 criterion, a stack probe program, the scrubbed offline environment, the Postgres-lane tripwire, the worktree `PYTHONPATH` rule), the `Makefile` target, the `e2e-python` and `garak-offline` jobs calling the script, `tests/test_docs_phase_b_consistency.py`. Since B4 the garak step fails on pytest exit 5, on an all-skipped run and on a missing extra |
| the plan-07 file with its v1 body; `EXECUTION-CONTEXT.md` not refreshed for Phase B; the spec 22 and 26 addenda and the garak supply-chain paragraph not written | closed: plan 07 rewritten onto spec 27 as built, `EXECUTION-CONTEXT.md` refreshed, spec 3.2, 11.6, 11.7, 17.4, 22.6 and 26.7 addenda, `docs/security/supply-chain.md` and `SECURITY.md` garak paragraphs, master plan v2.8 |
| the wave B2 follow-ups: the capabilities roster, the attacks filter, the completion path writing three formats and no snapshot, the codes off the 17.3 table, `FindingType` without the LLM and manual literals, `auth_profile_in_use` not emitted | closed by the fix pass: the roster read from the tree with the explainer roster, the `endpoint-v1` summary and an `interop` block; `?modality=` on capability tags; four formats and the first snapshot at completion; the third 17.3 addendum (ten codes) with the `endpoint_schema_mismatch` row corrected; `adversarial_llm` and `adversarial_ml_manual` in `redsim/schema.py`; `409 auth_profile_in_use` on `DELETE /v1/auth-profiles/{id}` |
| the wave B3 follow-ups: the text and detection runners' self-describing slices (INTEROP-04), the consumed-slice binding calls (INTEROP-16), the JWT redaction pattern (INTEROP-28), `atlas_technique_id` on drafts and list rows (INTEROP-18), the capabilities interop block and the `.env.example` and compose pass-through (INTEROP-29, BULK-23), the single-run admissions under the caps (BULK-20, -21), the bulk-verify worker projection (BULK-16), the `batch_id` overlay (BULK-02), `REDSIM_ML_MAX_ADV_ARTIFACT_MB` never reaching the child | closed by the fix pass except: the worker-parent `materialize_consumed_slice` call (INTEROP-16 remainder), so a campaign on a consumed-bound model does not run end to end; the `atlas_technique_id` key on finding list rows (the stamp is on every finding's `schema_blob.ml.atlas_technique`, drafts included) |
| ENDPOINT-30 (typed transport-failure mapping in the campaign task), INTEROP-07 (regenerate-in-child), INTEROP-23 (the dataset push to Foundry), INTEROP-26 (a real non-operational instance) | open, unchanged, recorded in the README |
| product defects the B4 files found | open, by attribution: `redsim/ml/targets/endpoint.py:228` sends the 8-row probe unscaled, so no endpoint reaches `available` through the tiny server (three cases of `test_ml_endpoint.py`); no bundled image target exposes a training slice to the child, so `apply_training_defense` records the defense unavailable and no derived target or `MeasuredDelta` exists (`test_ml_attacks_harden.py`; the verify run succeeds on the undefended model with the score withheld); no route derives `architecture_kwargs` from the dataset binding, so a `small_cnn` `state_dict` for a 3-class dataset is refused at validation (`test_ml_bulk.py`); `redsim/ml/pdf.py` raises reportlab's `LayoutError` on a 13-column table (degraded at completion, still raised by the on-demand render); three report-format pins the completion render made stale (`tests/ml/test_audit_campaign.py:113`, `tests/e2e/test_ml_verify_upload_reports.py`, `tests/e2e/test_ml_review_reports.py`), to be moved by their owners |

## Stages and the stage table

`STAGES` in `redsim/ml/schema.py` is the ordered tuple `load_target`,
`defense_apply` (since wave B0, where spec 6.5 places it), `sample`,
`clean_eval`, `attack`, `control`, `explain`, `score`, `interpret`,
`recommend`, `report`. The child reports `attack` per attack as
`attack:<attack_id>`, and `score` runs after `explain` because `S_expl` needs
SHAP. `defense_apply` is emitted by the campaign frame directly after
`load_target` only when a `kind: training` defense was actually applied
(adversarial training or distillation inside the verify child); a
preprocessing defense wraps the loaded target and adds no stage, and a
training defense the hook refused (no torch module, no training slice) writes
no stage either, since nothing was applied. `expected_stages(config)` in the
task derives the keys one campaign will write with the same rule (no
`control` when `include_control` is off, no `explain` when `explain_k = 0`,
no `recommend` when `auto_recommend` is off, `defense_apply` only for a
training defense).

`Run.stage_table` has the spec 6.5 shape and is maintained by `_StageTracker`:

```jsonc
{
  "stage": "attack:pgd",                 // the stage currently running, null when idle or finished
  "stages_done": ["load_target", "sample", "clean_eval", "attack:fgsm"],
  "stages": {
    "load_target": { "status": "succeeded", "started_at": "…", "finished_at": "…", "job_id": "job-…" },
    "attack:pgd":  { "status": "running",   "started_at": "…", "finished_at": null, "job_id": "job-…" }
  },
  "jobs": { "job-…": { "type": "attack.run", "status": "running", "stage": "attack:pgd", "attack_ids": ["fgsm", "pgd"] } },
  "completeness": null,                  // "complete" | "partial" once the record is in
  "error": null,
  "parent_run_id": "run-…"               // reruns and follow-ups; verify runs carry baseline_run_id
}
```

Per-stage `status` is one of `queued`, `running`, `succeeded`, `failed`,
`skipped`, `cancelled`, `timed_out`. A stage reported finished sets
`finished_at` and marks the next expected stage `running`. An expected stage
that never completes before a later one does (a `not_run` attack, a skipped
explain) becomes `skipped`. The stage running when the child died becomes
`failed`, `timed_out` or `cancelled`. Every transition is also published on
the run's event channel as
`{"type": "stage", "name": "<stage>", "status": "<status>", …}` for the
WebSocket. A verify run reuses the same stages with a preprocessing defense
applied to the evaluation copy inside `load_target`, or a training defense
recorded as its own `defense_apply` stage. A campaign whose `modality` has no
importable runner module is refused before any stage with the typed
`ModalityRunnerUnavailable` (`modality_runner_unavailable`).

## Artifact kinds

`DatabaseArtifactSink` maps the file names the pure modules write to the spec
5.8 kind vocabulary with an explicit table (`artifact_kind()` in
`redsim/workers/tasks/ml_campaign.py`). Every row carries the blob location,
sha256, content type and size, and `GET /v1/artifacts/{id}` streams it under
`nosniff` and `default-src 'none'`.

| Kind | File | Content |
|---|---|---|
| `ml.run_record` | `run_record.json` | the immutable `CampaignRecord`. `GET /v1/runs/{id}/campaign` serves these bytes |
| `ml.score` | `score.json` | the `MRIRecord` |
| `ml.flip_matrix` | `flip_matrix.json` | per-sample flip table |
| `ml.validation_report` | `validation_report.json` | the `model.validate` outcome |
| `ml.curve` | `curve/robustness_curve.png` and the curve JSON | accuracy versus ε, evasion, control and clean point |
| `ml.adv_slice` | `adv_slice/…` | adversarial rows kept inside the worker boundary |
| `ml.input.clean`, `ml.input.adv`, `ml.perturbation` | `obs_<i>/clean.png`, `adv.png`, `diff.png` | per-observation images |
| `ml.shap.image`, `ml.shap.values`, `ml.shap.meta`, `ml.shap.force` | `obs_<i>/shap_*.png`, `shap_values.npz`, `shap_meta.json`, `shap_pair.png` | per-observation SHAP |
| `ml.shap.summary`, `ml.shap.summary_text`, `ml.shap.bar`, `ml.shap.beeswarm` | `shap_summary.json`, `shap_summary.txt`, `shap_bar_*.png`, `shap_beeswarm_*.png` | campaign-level SHAP. The text summary is the only SHAP material the narrative sees |
| `ml.feature_diff` | `feature_diff.json`, `top_features.json` | tabular feature deltas |
| `ml.text.diff`, `ml.shap.text` | `obs_<i>/text_diff.json`, `obs_<i>/shap_text.png` | text modality (wave B1, kinds added in the B1 integration): the escaped word diff of one observation and its token-attribution bars. `shap_values.npz` keeps `ml.shap.values`; the campaign `shap_summary.json` carries counts, ranks and shifts only, never message text |
| `ml.detection.boxes`, `ml.detection.scorecard` | `obs_<i>/boxes.json`, `detection_scorecard.json` | detection modality (wave B1): the per-observation box record (ground truth, clean and adversarial predictions, matches, patch location) and the campaign-level scorecard (worst-case recall ratio, suppression rate at the reference patch area, recall AUC, mAP@0.5, all with denominators, validated to carry no MRI key). The drawn `clean_boxes.png` / `adv_boxes.png` are `ml.input.clean` / `ml.input.adv` |
| `ml.adv_slice` (text) | `adv_slice/<attack>_eps<e>.jsonl` | JSON lines of adversarial message strings, served as attachments |
| `ml.derived_model`, `ml.training_report` | `derived_model/weights.pt`, `derived_model/training_report.json` | a training defense (wave B1): the derived `state_dict` and the `TrainingRecord`. Since wave B2 the worker registers the derived weights as a new `Target` with `derived_from` lineage |
| `ml.clean_slice`, `ml.control_slice` | `clean_slice.npz`, `clean_slice/…`, `control_slice/…` | wave B2: the kinds for the clean and control slices the B3 export consumes. Since the B3 reconcile pass the classification runner writes `clean_slice.npz` and `control_slice/<eps>.npz` with the prediction keys and embedded `family` / `attack` / `eps` descriptors, so a live classification export carries all three families (INTEROP-04) |
| `ml.dataset.manifest`, `ml.dataset.parquet`, `ml.dataset.card` | `datasets/<source-run-id>/croissant.json`, `data/<family>/<attack>_eps<e>.parquet`, `README.md` | wave B3: the Croissant export of a run, content-addressed, on the source run; `GET /v1/datasets/{run_id}` serves the digest-checked manifest as `application/ld+json` |
| `ml.dataset_validation_report` | `dataset_validation_report.json` on the `ml.dataset_ingest` run | wave B3: the sandbox child's parse report of a consumed slice (`consumed-slice-1`: rows, per-class counts, columns, shape, observed range, digests, library versions) |
| `ml.integration.payload`, `ml.integration.rows`, `ml.integration.receipt` | `redsim/scorecards/<run_id>/scorecard.json`, `rows.jsonl`, the receipt JSON, on the `ml.integration_push` run | wave B3: the exact bytes that left for Foundry, stored before the push, and the receipt (host, dataset rid, transaction rid, per-file digests and statuses; never a token) |
| `ml.harden.prompt`, `ml.harden.completion`, `ml.harden.narrative` | `harden/prompt.txt`, `completion.txt`, `narrative.md` | the Pythia exchange, written by the parent |
| `ml.events` | `events.jsonl` | the child's stage event log |
| `report.md`, `report.json`, `report.html` | `report.<ext>` | the rendered report. `GET /v1/runs/{id}/report.{ext}` serves the newest non-archived snapshot's row, then the newest row of the kind (legacy `ml.report_<ext>` rows are also accepted) |
| `report.pdf` | `report.pdf` | wave B2: the reportlab projection written by a `report.render` job (the campaign completion path does not write it); served under `application/pdf`, never from the filesystem |
| `ml.llm.report_jsonl`, `ml.llm.hitlog_jsonl`, `ml.llm.digest_html`, `ml.llm.usage`, `ml.llm.child_result`, `ml.llm.scorecard` | `llm/report.jsonl`, `llm/hitlog.jsonl`, `llm/digest.html`, `llm/usage.json`, `llm/child_result.json`, `llm/scorecard.json` | wave B2, a probe run: garak's own files stored and never parsed for text (storage fails closed when the key shape appears), the token ledger, the child's counts and the k/n scorecard `GET /v1/runs/{id}/llm-scorecard` serves. `ml.llm.partial.*` when the child did not succeed |
| `ml.partial.*` | `ml/partial/<name>` | whatever a killed or timed-out child had written |

## Audit trail

Every ML mutation is admitted through `redsim.safety.authorize()` before any
`Run` or `Job` row exists and before Celery is touched
(`tests/test_admission_audit_before_enqueue.py`), and the worker writes the
spec 10.5 rows on the run chain through `_AuditEmitter`. Detail carries ids,
digests and counts only. `redact_audit_detail` blanks any key naming a token
and scrubs `pk_…` Pythia keys and Kaggle token shapes.

| Action | Written by | Chain |
|---|---|---|
| `model.register` | `POST /v1/models` (bundled, upload, since wave B2 endpoint and LLM registration with the `allowlist_check` verdict; `success=False` rows for every refusal), and since wave B2 the worker when it registers a derived model after a training verify | project (the derived model's row on the validate run's chain) |
| `model.validate`, `job.complete` | `redsim.ml_model_validate` (uploads, and since wave B2 endpoint probes with `target` the URL and the allowlist verdict, and derived models) | run (`ml.ingest`) |
| `attack.run`, `explain.run`, `harden.recommend`, `verify.replay` | the admission services, before any row (`success=False` on refusal); since wave B2 `attack.run` carries `modality`, `budget`, `target_kind`, `scoring_source`, `scoring_weights`, `non_default_weights` and a host-only `endpoint` block | project |
| `llm.probe.run` | `POST /v1/models/{id}/probes` (wave B2), before any row, ids and counts only | project |
| `llm.probe.entitlement`, `llm.probe.execute.<probe short id>`, `llm.probe.score` | `redsim.ml_llm_probe_run` (wave B2): the key's entitlement to the model (`success=False` with `model_not_entitled` or `gateway_unreachable`), one row per probe (`success=False` for `not_run` or failed probes), the scorecard digest | run |
| `finding.author` | `submit`, `POST /v1/findings` (`op: create`) and `PATCH /v1/findings/{id}/draft` (wave B2): ids, counts and text digests, never the text | project |
| `report.snapshot.archive`, `report.snapshot.restore` | the snapshot archive and restore routes (wave B2): snapshot id, version, record digest, artifact count, before and after flags, written before the flag flips | run |
| `project.settings` | `PUT /v1/projects/{slug}/ml-scoring` (wave B2): field, old and new sha256, `cleared`, the vector; `success=False` on a refused vector | project |
| `dataset.export`, `dataset.export.execute` | `POST /v1/runs/{id}/dataset` admission (wave B3: source run id, follow-up ids; `success=False` on `export_unavailable`, `export_in_flight`, `fixture_not_exportable`), then `redsim.dataset_export` (manifest sha256, file count, bytes, prefix; `success=False` on a projection mismatch or an invalid manifest) | the follow-up run (`ml.dataset_export`) |
| `dataset.register`, `dataset.validate` | `POST /v1/datasets` admission (wave B3: ids, sha256 per part, counts, modality, licence text, revision; every static refusal a `success=False` row with reason and field, never a URL string or bytes), then `redsim.ml_dataset_validate` (dataset id, status, rows, per-class counts, revision, digests, refusal reason) | project, then the ingest run (`ml.dataset_ingest`) |
| `integration.push`, `integration.push.execute` | `POST /v1/runs/{id}/integrations/foundry` admission (wave B3: `target` the Foundry host with the allowlist verdict, ids, `target_ref`, payload kind; refusals `success=False` on the campaign run's chain with the code and a `target_ref_problem` marker, never the value), then `redsim.integration_push` (host, dataset rid, transaction rid, payload, rows and record sha256, HTTP statuses, file count, bytes, outcome; on failure `step`, `http_status`, `error_class`, `transaction_aborted`). Every row is scrubbed of JWT-shaped tokens, `Bearer` values and URL strings before it reaches a writer | the follow-up run (`ml.integration_push`), refusals on the campaign run |
| `batch.create`, `batch.cancel` | `POST /v1/campaigns/batch` and `POST /v1/findings/{id}/verify/bulk` (wave B3: `batch_id`, kind, target or finding ids, `n_members`, modality, `config_hash`, `max_parallel`, `max_members`, the sha256 of the `Idempotency-Key` when sent; pre-check refusals and an all-refused batch `success=False`), `POST /v1/campaigns/batch/{id}/cancel` (member ids, `cancelling`, `already_terminal`; `success=False` on `run_terminal`). Each member's own `attack.run` or `verify.replay` row follows, and a bulk verify writes one `verify.replay` row per additional finding naming the shared run | project |
| `bulk.upload` | `POST /v1/models/bulk` (wave B3: `bulk_id`, file count, safe file names, content length, declared formats, modalities, dataset ids; then each file's own `model.register` row; a refused request or file `success=False`) | project |

Since wave B3 `Run.scanner` also takes `ml.dataset_export` and
`ml.integration_push` (follow-up runs with `parent_run_id`) and
`ml.dataset_ingest` (an ingest run with no target), and `Job.type`
`dataset.export`, `dataset.validate` and `integration.push`.
| `model.load` | the task, once `load_target` completes (or `success=False` with the error class when it did not) | run |
| `attack.execute.<attack_id>` | the task, per attack as its stage completes. A `not_run` attack gets a `success=False` row with the reason | run |
| `explain.execute` | the task, when `explain` ran (observation count, artifact ids and digests, expl_shift) | run |
| `campaign.score` | the task, when a score record exists (`mri`, `grade`, `completeness`, `missing`, `settings_hash`, score digest, ΔMRI on verify) | run |
| `harden.execute` | the task, on an attack or harden job with candidates (rules fired, `llm_requested`, `llm_used`, `narrative_source`, `skipped_reason`, redacted Pythia settings, prompt and completion sha256, `usage.{prompt,completion}`, cost) | run |
| `verify.execute` | the task, on a verify job (defense, outcome, validation state, delta) | run |
| `report.render` | the task at completion (`formats`, artifact ids, digests), `redsim.report_render` on re-render, and since wave B2 the `POST /v1/runs/{id}/report.render` admission (`phase: admitted`, `job_id`, `formats`, `requested_by`) before the job row | run |
| `job.complete` | the task, last (`status`, counts, `completeness`, envelope digest, `error_class`, and `success=False` on failure or cancellation; since wave B2 the endpoint broker counts on an endpoint run) | run |
| `finding.review`, `finding.annotate`, `target.manage`, `run.cancel` | the finding status and, since wave B2, the review decisions (`decision`, from and to status and review state, the expectations, reviewer, author, campaign creator, revision, verify run id; `success=False` with the unmet list or the independence violations on a refusal), reviewer notes, model delete and cancel routes | run or project |

`GET /v1/audit/verify?run=<id>` (or `redsim audit verify --run <id>`) proves a
whole campaign's trail because every worker row shares the run chain and the
admission row carries the `run_id`. The full table with the retained platform
events is in [audit-chain.md](audit-chain.md#planned-ml-events).

## The frozen schema

`redsim/ml/schema.py` is the M0 contract (spec 5.3 to 5.7, 12.5, 13.3, 14, 15
and 16.4). Later milestones add behaviour, not fields. A field change after the
freeze follows the change protocol in the
[P0 plan](../plans/01-p0-contracts-api-skeleton.md) section 8: no silent
renames, announce the change in the master plan, and prefer an additive
default-valued field.

| Model | What it holds |
|---|---|
| `TargetInfo`, `AttackInfo`, `ParamSpec` | Catalog entries. `AttackInfo` is the `GET /v1/attacks` row: `family` (`evasion` or `control`), `phase`, `access`, `requires_gradients`, `status` with `reason`, and a `params_schema` of bounded parameters. |
| `CampaignConfig` | One campaign, immutable after admission: `target_id`, `modality`, `attack_ids`, `attack_params`, `norm` (`linf` or `l2`), `eps_grid` (strictly ascending, each in (0, 1]), `reference_eps` (a member of the grid), `finding_asr_threshold` (0.2), `n_samples` (10 to 1000, default 200), `seed`, `include_control`, `explain_k` (0 to 32, default 8), the dataset binding, `scoring`, `defense` (verify only), `llm_narrative`, `auto_recommend`, `target_snapshot`, `attacks`. |
| `ScoringConfig`, `MRIWeights`, `SeverityThresholds`, `ConfidenceThresholds`, `InterpretationThresholds` | The `ml.scoring` block copied onto the campaign at admission. `MRIWeights` validates that the five weights sum to 1. |
| `DefenseConfig` | An ART preprocessing defense (`id`, `art_class`, `params`) applied to an evaluation copy in a verify run. |
| `Provenance` | Library versions, `model_sha256`, dataset id, revision and split, `sample_indices_sha256`, `settings_hash`, lineage (`baseline_run_id`, `parent_run_id`), `defense`, the redacted `llm` settings, `thread_env`, device and `nondeterminism`. |
| `Measurement` | One row per test family at one setting, id `m.clean`, `m.evasion.<attack_id>.eps<ε>` or `m.control.noise.eps<ε>`. Counts and rates with denominators: `n`, `n_correct`, `accuracy`, `n_flipped_from_clean`, `n_clean_correct`, `attack_success_rate`, realised norms, `pert_first_success_*`, `conf_gap_*`, `expl_shift_*` with its noise floor, `queries_mean`, `per_class`, `wall_time_s`, `notes`. |
| `Observation` | Per-sample evidence: labels, predictions, confidences, artifact ids and digests, `center_mass_ratio_*`, `expl_shift`, top SHAP features. `metric_kind` is the literal `heuristic` with a fixed note. |
| `Interpretation` | An inferred sentence with a non-empty `basis` of measurement or observation ids. `kind` is the literal `inferred`. |
| `CandidateRecommendation`, `MeasuredDelta` | `status` is the literal `candidate`. `validation` is `not evaluated` or `measured`, and a `measured` block must be present exactly when `validation` is `measured`. `narrative_source` is `rules` or `llm`. |
| `MRIInputRow`, `ScoredValue`, `PerAttackSubscores`, `Subscores`, `MRIDelta`, `MRIRecord` | The score record, described below. |
| `MLModelManifest`, `FeatureSpec`, `SurrogateInfo`, `CleanAccuracy` | The model manifest stored in `targets.detail` for `ml_model_artifact` and `ml_model_endpoint` targets: format, sha256, size, architecture id, input shape, classes, features, build-time surrogate, dataset binding, clean accuracy with `n`, `status` (`registered`, `validating`, `available`, `refused`) with a paired `refusal_reason`, `gradients`, `bundled`, license and source. |
| `MLFindingDetail`, `FindingReview`, `FindingVerify`, `AtlasTechnique` | The `ml` sub-object of `findings.schema_blob`: attack, norm, grid, first-success ε, ASR by ε, the four evidence lists, limitations, artifacts, review state and verify outcome. `AtlasTechnique` is Phase B2 and is never back-filled by guesswork. |
| `RobustnessCurve`, `CurvePoint`, `AccuracyPoint` | Accuracy versus ε per attack with the clean point and the control curve, every point carrying `n`. |
| `RunRecord`, `CampaignRecord`, `RunSummary`, `ScoreStatus` | The run record artifact and the `GET /v1/runs/{id}/campaign` response. A succeeded run must carry limitations, every citation must resolve, and a campaign carries either `score` or `score_status`, never both. `CampaignRecord.schema_version` is `"campaign-record-1"` since wave B0. |
| Phase B additions (wave B0, all default-valued): `DetectionMetrics`, `TextObservation`, `DetectionObservation`, `TextModelSpec`, `DetectionModelSpec`, `EndpointSpec`, `DerivedFrom`, `ReviewEvent`, `FindingRevision`, `RunKind` | `Domain` and `Modality` gain `text` and `detection`, `Norm` gains `edit` (the maximum share of words replaced) and `patch_area` (the patch area as a fraction of the image, side `sqrt(eps * H * W)`), `Measurement.edit_fraction_mean` and `.detection`, `Observation.text` and `.detection`, `MLModelManifest.text`, `.detection`, `.endpoint` and `.derived_from` (omitted from dumps while `None`, so every pre-Phase-B `manifest_sha256` is unchanged), `ReviewState` widened with `draft`, `in_review`, `confirmed`, `resolved`, `FindingReview.history` and `.revisions`, `MLFindingDetail.retests`, `FindingVerify.settings_hash` and `.baseline_run_id`, `RunSummary.kind` and `.probe_ids`, `STAGES` with `defense_apply`. Master plan section 0 lists them one per line. |

Helpers frozen with the models: `STAGES`, `BANNED_SCORE_WORDS`,
`GRADE_STATEMENT`, `grade_for_mri()`, `contains_banned_score_word()`,
`STANDING_LIMITATIONS`, `standing_limitations()` and
`CAMPAIGN_RECORD_SCHEMA_VERSION`.

## MRI

The Model Robustness Index is a 0 to 100 integer computed once per campaign,
meaning one model, one modality, one declared attack set, one ε grid and one
reference budget (spec 15). Its inputs come only from the run's own
`Measurement` and `Observation` rows. Control rows never enter the score.

Each subscore is on a 0 to 100 scale, the unweighted mean over the in-scope
attacks (attacks recorded `not_run` are removed from the set first), with
ratios clamped to [0, 1]:

| Subscore | Per-attack value | Weight |
|---|---|---|
| `S_acc` robust accuracy | `min over ε of acc_adv(a, ε) / acc_clean` | 0.35 |
| `S_asr` evasion resistance | `1 - asr(a, ε_ref)` | 0.25 |
| `S_eps` budget resilience | trapezoidal area of `acc_adv(a, ε) / acc_clean` over the grid, divided by `ε_max - ε_min` | 0.20 |
| `S_conf` confidence calibration | `1 - conf_gap(a, ε_ref)` | 0.10 |
| `S_expl` explanation stability | `1 - expl_shift(a, ε_ref)` | 0.10 |

```
MRI = round(0.35 * S_acc + 0.25 * S_asr + 0.20 * S_eps + 0.10 * S_conf + 0.10 * S_expl)
```

Constraints the schema enforces (`MRIRecord._mri_needs_all_five`) and the spec
requires (15.4 and 15.8):

- An MRI exists only when all five subscores are present and `completeness`
  is `complete`. A partial record carries the available subscores and names
  each missing dimension with its reason. Weights are never renormalised over
  the available dimensions. `GET /v1/runs/{id}/compare` refuses a partial
  score with `409 score_unavailable`.
- `grade` must equal `grade_for_mri(mri)`: A from 90, B from 75, C from 60, D
  from 40, F below. A grade never appears without an MRI.
- `reading` is attack-scoped text and may not contain a banned word
  (`hardened`, `harden before fielding`, `deployment-ready`,
  `not deployment-ready`, `certified`, `safe`, `fielding`).
  `GRADE_STATEMENT` is printed under every grade.
- The record always carries `inputs`, `per_attack`, `subscores`, `weights`,
  `eps_grid`, `reference_eps`, `norm`, `attack_ids`, `finding_asr_threshold`,
  `settings_hash`, `scoring_version` and `computed_at`. The UI and the report
  never render the number without the subscores, the per-family table and the
  ε curve.
- MRIs are never aggregated, averaged, ranked or compared across campaigns.
  Two campaigns are comparable only when the compared config variables and
  `sample_indices_sha256` match (the compare route names every variable that
  differs).
- ΔMRI exists only on a verify run (`MRIDelta` on a `kind = verify` row),
  always beside the change in clean accuracy, and is the only numeric gain the
  product ever shows. A recommendation carries no expected gain until a verify
  run has measured it (`MeasuredDelta`). `redsim.ml.scoring.delta` refuses to
  mix modalities, and a family or ε cell absent on one side renders as
  unavailable, never as a delta of zero.

Finding severity is derived from the first-success ε and the ASR, never
hand-set (spec 15.5).

## Verify loop

1. `POST /v1/findings/{id}/verify` with an optional `defense`, `params` and
   `recommendation_id`. The service resolves the defense (the recommendation's
   own when it names one, `feature_squeezing` when nothing is named), copies
   the baseline's frozen config with `defense` set, requires the baseline to
   be terminal with a complete score whose record bytes verify, refuses a
   second in-flight verify on the same finding, writes the `verify.replay`
   row, moves the finding to `fixing` and admits a `verify.replay` job.
2. The child loads the model, applies the ART preprocessor to the evaluation
   copy (`defense_apply`) and re-runs the same attacks, control and SHAP on
   the same seeded slice.
3. The parent loads the baseline record, attaches the `MRIDelta` (both scores
   complete) or records `DELTA_UNAVAILABLE_LIMITATION`, and projects the
   outcome: `verified -> poc_passed / fixed`, `still_vulnerable ->
   poc_failed / failed`, `inconclusive -> inconclusive / open`. The
   `MeasuredDelta` (`validation = "measured"`) is attached only to the
   recommendation naming the defense. A `RemediationAttempt` row
   (`ml.verify.<defense>`) and the `verify.execute` audit row are written. A
   sandbox failure on a verify job leaves the finding `inconclusive` / `open`.
4. `GET /v1/runs/{verify_id}/compare?with=<baseline_id>` answers
   `mode: "verify_delta"` with the persisted delta (or the same computation
   over the two stored records).
5. Since wave B2: a training defense (`adversarial_training`,
   `defensive_distillation`) is admitted on an image target with a torch
   module and runs as the `defense_apply` stage; the derived weights become a
   new `Target` with `derived_from` lineage through validate; every verify
   appends a `FindingVerify` with `settings_hash` and `baseline_run_id` to
   `MLFindingDetail.retests`; and the review workflow's `resolve` decision
   reads the latest retest and refuses (`409 resolution_blocked`) until it is
   `verified` at the baseline's settings and the finding is `poc_passed`,
   `fixed` and `confirmed`.

## Evidence separation

A run makes exactly four kinds of statement, kept in separate fields, separate
report sections and separate UI panels (spec 14.1):

| Kind | Type | Label enforced by |
|---|---|---|
| Measurement | `Measurement` | the field set: counts and rates only, `notes` for caveats |
| Observation | `Observation` | `metric_kind: "heuristic"` |
| Interpretation | `Interpretation` | `kind: "inferred"` and a non-empty `basis` |
| Candidate recommendation | `CandidateRecommendation` | `status: "candidate"`, `validation`, `narrative_source` |

Ids are the citation mechanism: `m.<family>[.<attack_id>][.eps<ε>]`,
`o.<index:03d>`, `i.<n>`, `r.<rule_id>`. `RunRecord._no_dangling_citations`
rejects a record whose interpretation `basis` or recommendation
`triggered_by` cites an id that does not exist in the same run. Provenance and
limitations accompany the four in every report and page.
`standing_limitations(dataset_name, eps_grid)` returns the dataset sentence,
the budget sentence and the five standing limitations (SHAP is sensitivity not
cause, the slice is small, white-box gradient attacks assume full access,
recommendations are unvalidated candidates, passing does not establish safety
or readiness). The campaign runner appends the build-time dataset caveats from
the manifest, a weak-subject caveat when the manifest flags
`subject_centered: false`, a surrogate-transfer limitation when white-box rows
came from the surrogate, and the narrative outcome. Reviewer notes are a
fifth, human voice under their own heading.

The interpretation rules I1 to I6 (spec 14.6) and the recommendation rules
(spec 16.2) are deterministic, read `InterpretationThresholds`, cite the ids
that fired them and print their thresholds (`redsim/ml/recommend/rules.py`).

## Datasets and handling rules

Every dataset is open, unclassified, public, and carries a stated license
(spec 11). Nothing is committed except the CI fixtures under
`tests/ml/fixtures/` (the 500-image CIFAR-10 slice `cifar10_test_500.npz`
written by `build-assets --fixture`, and a seeded stratified sample of the
malicious-URLs file).

| Role | Dataset | License | Notes |
|---|---|---|---|
| Demo image | `leibnitz-lab/military_vehicles` (HF), coarse 7-class task | MIT for the compilation and labels | Ground-level photographs, not overhead. Photo copyright is not cleared by the MIT tag, so images stay inside the team's blob store. |
| CI image fixture | `uoft-cs/cifar10` (HF), pinned 500-image subset | unknown on the card | Fixture only, never presented as results, and `GET /v1/models` never lists `cifar10_smallcnn`. |
| Demo tabular | Kaggle `sid321axn/malicious-urls-dataset` | CC0 | The download needs a Kaggle token (`KAGGLE_API_TOKEN`, or the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair) at build time only. URL strings are data: never fetched, resolved or rendered as links. |
| Tabular fallback | `lacg030175/UNSW-NB15` (HF, config `standard`) | CC-BY-4.0 | Named in the spec as the fallback if the Kaggle download cannot be completed. Not built, not wired. Fallback datasets are excluded from this completion pass. |
| Demo text (Phase B, wave B0 / B1) | UCI SMS Spam Collection (Almeida and Gomez Hidalgo 2011, DOI 10.24432/C5CC84), `uci:sms-spam-collection` | CC BY 4.0 (stated on the UCI page, read 2026-09-09) | 5,574 messages (4,827 ham, 747 spam), zip sha256 `1587ea43…`, corpus sha256 `7d039a24…`. Published verbatim to the public repository as `data/sms_spam_collection.tsv` with a seeded 20 percent eval split (owner default MODALITIES-12 applied: no redaction, reason recorded). CI fixture `tests/ml/fixtures/sms_spam_sample.tsv` (300 rows). Bundled model `sms_tfidf_lr`. Caveats recorded: era, English only, imbalance, phone numbers present. |
| Synonym lexicon (Phase B) | WordNet 3.0 from `nltk/nltk_data` gh-pages `550b6625` (`packages/corpora/wordnet.zip`, sha256 `cbda5ea6…`) | WordNet 3.0 license (BSD-style, `wordnet/LICENSE` sha256 `7731175a…`) | Fetched by `build-assets` into `<assets>/cache/wordnet/nltk_data/corpora/wordnet` (gitignored), not republished (reference entry `external/wordnet-3.0.md` in the public repository). CI fixture `tests/ml/fixtures/synonyms_tiny.json` (47 entries). |
| Demo detection (Phase B, pending owner review) | Kaggle `rawsi18/military-assets-dataset-12-classes-yolo8-format` (version 5), a capped seeded subset: 300 images, 607 boxes, 4 classes x 75 images (`military_tank`, `military_truck`, `military_vehicle`, `military_aircraft`) | CC BY 4.0 (Kaggle metadata `licenseName`, read 2026-09-09) | Published to the public repository as `data/military_assets_subset/` (52 MB, per-file sha256 in its `manifest.json`, sha256 `749611b4…`) for review under owner decision MODALITIES-27; removable in one commit if the owner declines. Person and weapon classes excluded by construction (1,536 of 4,336 candidate images dropped). The full 4.1 GB archive is cached locally only. Bundled model `assets_frcnn_mnv3`. |
| Training slice (Phase B) | `military_vehicles` training split, 1,536 rows stratified | MIT (already published) | `assets/bundled/vehicles_cnn/train_slice.npz` (file sha256 `5f9e5d49…`, indices sha256 `7caaf3a1…`), written by `build-assets` for the training defenses (ATTACKS_HARDEN-11); nothing new is published. |
| ATLAS technique data (Phase B) | `mitre-atlas/atlas-data` release `v2026.08` (`ATLAS-2026.08.yaml` sha256 `a8d32f67…`, tag object `b8613404…`, published 2026-09-01, checked 2026-09-09) | Apache-2.0 (LICENSE reproduced verbatim as `ATLAS_NOTICE`) | Vendored as constants in `redsim/ml/atlas_data.py` (AML.T0043 and its sub-techniques, T0040, T0024, T0015, T0031, T0020, T0018, T0059) with the 4.x prior names kept so stored findings are never rewritten; `verify_atlas_data` checks a local release file offline. Stamping findings is wave B3. |
| Public copies for other teams | [IntelliBridge/ai-red-teaming-data](https://github.com/IntelliBridge/ai-red-teaming-data) (GitHub, public, head `4048a209` on 2026-09-09; commits `a9ba6ba3` and `4048a209` added the Phase B rows) | CC BY 4.0 for the repository's own contents, upstream licenses kept per file | Phase A: the military vehicles parquet, the two URL CSVs (redacted copies: credential-shaped query values replaced with `REDACTED` in 2,346 of 651,191 rows and 406 of 128,224 in the eval split, so their hashes differ from the unredacted Kaggle file the local build trains on, spec 11.7). Phase B: the SMS corpus and split, the military-assets subset, the `data/garak/` copy plus reference entries `external/garak-probe-corpora.md` and `external/wordnet-3.0.md`, and an `atlas` release record, all with `INDEX.csv` rows (bytes, sha256, source, licence, attribution) and `MANIFEST.json` entries. No models and no CIFAR-10. `tests/ml/fixtures/public_index.csv` is the byte-identical snapshot of `INDEX.csv` at that head and `tests/ml/test_datasets.py` checks every code-named dataset has its rows (`REDSIM_PUBLIC_DATA_CHECK=1` runs the live check). |
| Phase B LLM-track probe corpora | garak 0.16.0's `garak/data` (wheel sha256 `871100d7…`) | Apache-2.0 for the garak packaging, upstream terms per subset (`inthewild_jailbreak_llms.json` upstream terms unconfirmed) | Loaded by garak itself from the installed package, never re-packaged by redsim. The public repository carries `data/garak/` and the reference entry with per-subset licences (owner decision TESTS_DOCS-33). Prompts are untrusted data and go only to the permission-gate-only Pythia persona declared on the LLM target (wave B2 requires the persona and a `guardrail_mode` at registration; the e2e evidence is wave B4). |

Rules that apply to all of them: bytes are fetched once by
`redsim ml build-assets` into the asset tree, read only by the worker and the
sandbox child (`REDSIM_ML_ASSETS_DIR`). The API and web containers never hold
dataset bytes. `MANIFEST.json` records the id, the resolved revision, the
license, the split, per-class `n`, the preprocessing, the caveats and the
bundled model's recipe and weight sha256, and is copied into `Provenance` and
served by `GET /v1/datasets`. The evaluation slice is a seeded stratified
sample whose indices are hashed into `Provenance.sample_indices_sha256`.
Fixture data never populates a Finding or a results page. No dataset row,
image, adversarial example, SHAP array or model parameter ever leaves the
worker boundary.

## Model loading

Accepted upload formats are ONNX and PyTorch `state_dict` (`.pt` or `.pth`
loaded with `weights_only=True`, or `.safetensors`) with an `architecture_id`
from the loader allowlist (`small_cnn`, alias `smallcnn`, and `resnet18`). Full
pickles are refused with `415 pickle_refused` and there is no override in
Phase A or Phase B (owner default REVIEW_REPORTS-33). Two more `ModelFormat`
literals exist for bundled and endpoint targets, not for uploads: the bundled
text classifier is `sklearn_joblib` and is opened with `joblib.load` only
after the manifest digest matched (the spec 9.2 exception `url_trees` already
uses), and an endpoint target is `format: "endpoint"` with no bytes at all
(the descriptor digest as `sha256`). The API never loads a model: it streams bytes to the blob store,
computes the sha256 and sniffs the magic bytes. Loading happens only on the
worker inside the sandbox child described under
[Orchestration](#orchestration). ONNX artifacts are converted with onnx2torch
so gradient attacks can run. The argmax agreement between the ONNX and torch
views on the evaluation slice is measured and recorded in the validation
report, and a model that cannot be converted is served through a black-box
ART estimator with `gradients: false` (white-box attacks are then refused at
admission with `422 attack_requires_gradients`). The `ml` extra (torch,
torchvision, onnx, onnxruntime, scikit-learn, ART, onnx2torch, safetensors,
shap, matplotlib) installs only in the worker image (spec 8.4 and 9), and
`tests/test_api_process_has_no_ml.py` builds the API with those imports
blocked.

## Pythia narrative path

The only outbound call the vertical makes is the optional hardening narrative,
and since wave 2 it runs in the worker parent after the sandbox child returns
(step 7 under [Orchestration](#orchestration)), never in the child:

1. `redsim.llm.router.route("ml.harden_narrative", …)` picks the model: the
   organisation override wins, else `config.task_models` seeded from
   `REDSIM_ML_LLM_MODEL`. The project daily cap and the organisation monthly
   cap apply through `DbBudgetChecker`, and with `REDSIM_LLM_BUDGET_STRICT` an
   unreadable budget denies the call.
2. `redsim.llm.pythia.chat_text` sends one non-streaming
   `POST {PYTHIA_BASE_URL}/v1/chat/completions` with
   `Authorization: Bearer pk_…` and an optional `X-Pythia-Persona`.
   `PythiaSettings.from_env()` reads the process environment layered over
   `.env`, verifies TLS through the OS trust store (`REDSIM_TLS_TRUSTSTORE`,
   default on) or a PEM bundle (`REDSIM_CA_BUNDLE`, then `SSL_CERT_FILE`), and
   returns `None` when `PYTHIA_BASE_URL`, `PYTHIA_API_KEY` or
   `REDSIM_ML_LLM_MODEL` is missing.
3. The payload is text only: the ranked rule outputs and the SHAP text summary
   (`shap_summary.txt`) with the measurements and limitations. `guard_input`
   and `guard_output` from `redsim.llm.guardrails` wrap the call, then a
   numeric-consistency check and a banned-word check run on the response.
4. Any failure leaves the rule output standing with
   `narrative_source = "rules"` and the reason recorded as a limitation and on
   the `harden.execute` row. The narrative never fails a job and never invents
   prose. A verify job never calls Pythia.

Prompt and completion are `ml.harden.prompt` and `ml.harden.completion`
artifacts, their digests and the token counts (as `usage.{prompt,completion}`)
go on the `harden.execute` row, and one `LLMUsage` row with
`task = "ml.harden_narrative"` feeds `GET /v1/orgs/{id}/cost`. Operator notes
are in [ops/pythia.md](../ops/pythia.md).

## Audit, roles and tenancy

The seven ML `Action` members and their minimum roles (`model.register`
remediator, `attack.run` scanner, `explain.run` scanner, `harden.recommend`
remediator, `finding.review` approver, `finding.annotate` remediator,
`report.export` scanner) are in [auth.md](auth.md#rbac); wave B0 added the
seven Phase B members (`llm.probe.run` remediator, `dataset.register`
remediator, `dataset.export` remediator since wave B2 (scanner at B0),
`integration.push` admin, `batch.run` scanner, `report.render` scanner,
`finding.author` remediator), mirrored in the OPA and Cedar bundles; since
wave B3 every one of them gates a real handler (`dataset.register` the consume
route, `dataset.export` the export route, `integration.push` the Foundry
push, `batch.run` the batch admission, `verify.replay` the bulk verify,
`model.register` the bulk upload, `run.cancel` the batch cancel). Endpoint and
LLM registration gate on `target.manage` (admin). The independence rule (a
campaign creator or a
system principal cannot dismiss a finding) is enforced in
`redsim/services/ml_findings.py` and, since wave B2, for every review
decision by identity in `redsim/services/finding_review.py`
(`reviewer_not_independent`). `ml_campaigns` and the four
`0011` tables (`report_snapshots`, `idempotency_keys`, `ml_batches`,
`ml_datasets`) carry the same RLS policy and trigger pair as the other scoped
tables, see [multi-tenancy.md](multi-tenancy.md). Bundled model targets are per project
(`Target.id` is `<bundled_id>-<8 hex>`, `Target.value` is
`bundled:<bundled_id>`), so two projects can register the same bundled model
independently.

## Accepted divergences

Recorded per the change protocol of `docs/plans/01` section 8. Each is a
knowing departure from the spec text that the tree follows. The spec is not
silently reinterpreted elsewhere.

| Spec says | Tree does | Why |
|---|---|---|
| 10.3: one Celery job per attack in declared order, then `explain.run`, then `harden.recommend`, chained | one `attack.run` job runs the whole campaign in one sandbox child. `explain.run` and `harden.recommend` are follow-up child campaigns admitted from a finding | one child keeps one seeded slice, one model load and one envelope per campaign, and the stage table and the per-attack `attack.execute.<id>` rows preserve the per-attack visibility |
| task names `redsim.attack_run`, `redsim.explain_run`, `redsim.harden_recommend`, `redsim.model_validate` | `redsim.ml_campaign_run` and `redsim.ml_model_validate` (both on the `scans` queue), while `Job.type` keeps the spec vocabulary `attack.run`, `explain.run`, `harden.recommend`, `verify.replay`, `model.validate` | follows from the single-job orchestration |
| 5.8: report artifact kinds `report.md`, `report.json`, `report.html` | the sink writes exactly those kinds, and the earlier `ml.report_<ext>` rows written by the pre-wave sink are still read by the report route | backward compatibility with runs recorded before wave 2 |
| 5.11: `harden.execute` carries `prompt_tokens` and `completion_tokens` | `usage.prompt` and `usage.completion` | `redact_audit_detail` blanks any key containing `token`, so under the spec names the counts would never reach the chain |
| 5.11: worker rows use the admitting principal as actor | actor `worker:<job.type>` with the requesting principal in `detail.requested_by` | the row records who executed and who asked, separately |
| 6.4 / 16.5: verify outcome mapping | a verify run whose baseline or verify score is partial cannot measure ΔMRI. The outcome is still projected from the attack measurements and `inconclusive` maps to `open`, with the reason recorded as a limitation | no gain is ever shown that was not measured, and the run is not failed for a scoring gap |
| 17.3: the code table is complete | operational codes outside the table (`ml_catalog_unavailable`, `campaign_not_found`, the two digest-mismatch codes, the reviewer-notes codes; `license_required` gained its row in wave B0) | import failures and evidence-integrity failures have no admission row in the spec table, so they are named rather than folded into a wrong code |
| plan 12 brief: `defense_apply` "appended at the end" of `STAGES` | `defense_apply` directly after `load_target` (wave B0) | spec 6.5 places it there and says `report` is last; the tripwire asserts `STAGES[-1] == "report"` and the P0 relative order |
| register ENDPOINT-02: contract name `redsim-predict-proba/1`, request body with an `encoding` key | `endpoint-v1`, body `{contract, input_format, inputs}` (wave B0) | the brief's name; the spec 17.3 addendum row for `endpoint_schema_mismatch` was corrected to `endpoint-v1` by the wave B4 fix pass |
| register INTEROP-02 and spec 17.4: `dataset.export` at remediator | remediator since wave B2 (`codes-b2`); wave B0 had scanner from the brief's wording | closed: the three policy files were aligned to the spec table in one commit and the spec 7.4 addendum row records both states |
| register ENDPOINT-06: `query_budget_exceeded` at 422; REVIEW_REPORTS-32: `idempotency_key_reused` at 422 and `idempotency_in_flight`; INTEROP-03: `fixture_not_exportable` at 409 | `query_budget_exceeded` 429, `idempotency_key_reused` 409, `idempotency_conflict`, `fixture_not_exportable` 422 (wave B2) | a budget refusal sits with `daily_budget_exceeded`; a reused key and an exportability rule are conflicts and validation failures respectively; recorded in the spec 17.3 second addendum |
| 7.4 / REVIEW_REPORTS-12: one independence refusal | the Phase A dismissal route keeps its plain-string `forbidden`; the wave B2 review decisions emit the structured `reviewer_not_independent` with `relation` | byte-compatibility for the Phase A route, a structured code for the new ones |
| spec 17.3 rows for `attestation_required`, `scoring_weights_invalid`, `model_id_invalid`, `model_not_chat`, `gateway_url_required`, `unknown_probe`, `probe_excluded`, `probe_detector_unavailable`, `llm_probe_quota_exceeded` (register names) | closed in wave B4: the ten codes (plus `endpoint_auth_failed` 502) are on the table in a third dated addendum and the routes raise them by name; the `reason` field the routes carried is kept for one release | between B2 and B4 the routes resolved them with `getattr` onto documented neighbours |
| register LLM-24 / REVIEW_REPORTS-05: `FindingType` `adversarial_llm` and `adversarial_ml_manual` | closed in wave B4: both literals added to `redsim/schema.py` additively (every stored `adversarial_ml` blob still validates); between B2 and B4 LLM findings and drafts carried `adversarial_ml` with a `finding_kind` marker | `redsim/schema.py` is a platform module no B2 track owned; the addition is additive under the plan-01 section 8 protocol |
| register paths for five Phase B routes | the brief's paths (`report.render`, `snapshots`, `findings/{id}/verify/bulk`, `atlas-coverage`, `integrations/foundry`) | the stubs follow the brief; the wave that builds each keeps or moves the stub and the docs row together |
| register MODALITIES-03 names `map_50`, `n_gt_boxes` | `DetectionMetrics(n_boxes, n_matched, map50, recall, suppression_rate)` (wave B0) | the brief's names; `CurvePoint` gained no `map_50` (it lives in the curve JSON) |
| 12.2: image HopSkipJump as a Phase B adapter | the Phase A `hopskipjump` adapter serves images with `IMAGE_DEFAULTS` and both modality tags, `phase: "A"` (wave B1) | one adapter, one denominator convention; the measured budgets are on this page |
| 13.2: KernelSHAP for black-box image targets | not built; `PartitionExplainer` stays the black-box image explainer, `KernelExplainer` serves predict-only tabular targets (wave B1, ATTACKS_HARDEN-08) | about 100k predict calls per 3x128x128 sample does not fit the sandbox budget; the reason is recorded in `redsim/ml/explain/base.py` |
| 16.5: ART `DefensiveDistillation` | native torch distillation with a temperature, ART's class cited as the reference (wave B1) | ART's transformer needs probability outputs and has no temperature |
| 21 / ENDPOINT-07: connection pinned to the resolved address | the broker resolves, classifies and refuses, but does not pin the connection; recorded in `BrokerStats.egress_notes` (wave B1) | the httpx pinned-connect transport is follow-up work; redirects are disabled and the resolve-once session pin exists in `endpoint_egress` |
| 21.7: DNS-TXT ownership verification for endpoint targets | not built; egress allowlist plus admin-only registration plus the audited attestation (owner default ENDPOINT-26) | the ownership engine was removed with the pentest domain |
| 27.3: a configured Foundry URL is the switch | the URL plus the operator attestation `REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL=1`, else the roster reads `misconfigured` and the push is `501 integration_disabled` (wave B3) | the spec's last sentence asks the operator to attest the instance is non-operational (D3); the variable makes the attestation checkable. Drop it if the owner prefers the bare URL switch |
| 27.1 / register INTEROP-04: the export carries clean, adversarial and control rows with true, clean and adversarial labels and confidences | met for every runner since wave B4 (the classification runner since the B3 reconcile pass; the text and detection runners write the same self-describing slices through `runners/base.py::slice_bytes`); the export schema gained a nullable `text` column that only a text slice fills, and a detection export's `flipped` column comes from the flip matrix because a detector predicts boxes, not one label | nothing is fabricated at export time and the card says which families the source run retained; a text model has no numeric input tensor, so `input` is null on its rows |
| register BULK-15 / -16: one verify run per finding | one defended run per `(defense, params)` projected onto every selected finding of the baseline run, one `verify.replay` row per finding naming the shared run (wave B3), the worker projecting the record onto every listed finding from its own attack rows since wave B4 | owner decision BULK-16 (one defended run projected onto N findings); the batch view still reports per finding whether the projection was written |
| register BULK-13: bulk upload refused whole on any bad file | per-file admission with collected refusals: `201` all validating, `207` mixed, `422 batch_member_refused` only when every file was refused (wave B3) | the single-upload boundary and its audit row run per file; a mixed answer is more truthful than refusing admitted files after the fact |
| register INTEROP-05: `mlcroissant` as the manifest library | a pure-Python manifest builder and validator (`redsim/ml/interop/croissant.py`); `mlcroissant` stays blocked in the API-process tripwire and is not imported anywhere (wave B3) | the API process must not import it, the worker needs only the JSON-LD shape, and the structural gate also enforces the D9 bans a generic validator would not |
| register BULK-02: the batch a run was admitted in | an overlay on `GET /v1/runs/{id}/campaign` from `ml_campaigns.batch_id`, `null` for a single-run admission (wave B4) | the owner default: no frozen-schema change for a projection the record does not need |
| 14.8 / REVIEW_REPORTS-16: every report format at completion | the completion path renders `md`, `json`, `html` and `pdf` and records the first snapshot; a PDF the renderer cannot typeset degrades to the text formats with `pdf_unavailable` on the `report.render` row and the job completes (wave B4) | a projection never fails the evidence job and nothing empty is written; the on-demand render still raises on such a record (open item) |
| 15.6 / 16.4: a training verify registers a derived target and measures a delta | when the child cannot apply the defense (no training slice exposed by the target) the verify run succeeds on the undefended model, the defense is recorded `unavailable` with its reason, the score is withheld, no derived target or `MeasuredDelta` exists and the finding is `inconclusive` / `open` (wave B4) | the honest state until the bundled targets expose `train_sample`; nothing is claimed that was not measured |

## Open items

The README section "Open items and not implemented" is the single list. In
short: the web UI (the one deferral of the Phase B plan); the Phase B items
the wave B4 e2e files found and left open by attribution ([What wave B4
closed and what stays open](#what-wave-b4-closed-and-what-stays-open): the
unscaled endpoint probe, no training slice exposed to the child, the
worker-parent consumed-slice call, `architecture_kwargs` for `state_dict`
uploads, the PDF `LayoutError`, three stale report pins, the recorded endpoint
seams, ENDPOINT-30, INTEROP-07, -23, -26, the `atlas_technique_id` list key);
the owner decisions of plan 12 section 2 with their recommended defaults (the
military-assets subset is published pending MODALITIES-27; MODALITIES-12
applied; ENDPOINT-26, LLM-08, LLM-26 and MODALITIES-36 applied by B2;
INTEROP-26, INTEROP-27 and BULK-16 applied by B3 and B4); the remaining-work
brief's packages A to F (compose operations and the gate against `make up`,
CI parity, the process-gate documents that need named human reviewers,
residual Phase A rows, the Fargate runtime follow-ups, the data-poisoning
module); and the recorded non-builds (`adv_patch`, KernelSHAP for images, a
detection explainer, the DNS-TXT ownership check, the pickle override,
HarmBench and the other excluded garak probes, an LLM narrative for probe
results, Lattice as text only, the `reviewer` role, the UNSW-NB15 fallback,
`text` and `detection` consumed slices, the dataset push to Foundry). CI: no
run on `main` after `58461cc` has been read and nothing is claimed green
([ci.md](../dev/ci.md)).

## Spec index

| Topic | Spec section |
|---|---|
| Domain model and schema | 5.3 to 5.8 |
| Audit detail per action | 5.11 |
| Job lifecycle, run status, stages | 6 |
| Roles, access matrix, independence rule | 7 |
| Architecture and package layout | 8 |
| Model loading and the sandbox | 9 |
| Tasks, campaign chain, failure classes, cancel, narrative | 10 |
| Datasets | 11 |
| Attack catalog, ε sweep, control, metrics, surrogate transfer | 12 |
| Explainability | 13 |
| Evidence model, limitations, report sections | 14 |
| MRI | 15 |
| Recommendations and the verify loop | 16 |
| API surface and error codes | 17 |
| Web UI | 18 |
| Deployment and environment variables | 20 |
| Security and trust | 21 |
| Testing | 22 |
| Milestones | 23 |
| Completion criteria | 26 |
