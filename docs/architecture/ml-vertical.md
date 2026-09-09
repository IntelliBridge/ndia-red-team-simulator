# ML vertical

Status as of 2026-09-08, `main` at `bb43bd7` (waves 1 and 2 of the completion
plan merged after PR #22). This page describes the adversarial-ML vertical as
it runs from this tree: the flow from admission to report, the stage table,
the artifact and audit vocabularies, the verify loop, and the places where the
tree knowingly departs from the spec. Items from wave 3 of the plan, which is
landing on `main` in parallel, are marked "(wave 3, landing 2026-09-09)". The
authoritative design is the
[product spec](../superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md),
the coordination plan is the [master plan](../plans/00-master-plan.md), and
the spec-versus-tree audit that drove the completion waves is the
[gap register](../plans/09-gap-register-2026-09-08.md). Where this page and
the spec disagree and the divergence is not listed below, the spec wins and
this page is stale.

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

## Where things stand

| Piece | State at `bb43bd7` |
|---|---|
| Frozen contracts: `redsim/ml/schema.py`, `redsim/ml/targets/base.py`, `redsim/ml/attacks/base.py`, migration `0010_ml_vertical`, the seven ML `Action` members | on `main`, frozen by P0. `redsim/ml/errors.py` adds the spec 10.6 failure classes (`ModelLoadRefused`, `ArtifactDigestMismatch`, `SandboxTimeout`, `SandboxKilled`, `EnvelopeInvalid`, `DatasetUnavailable`, `MlExtraUnavailable`, `ExplainerUnavailable`), each with a stable `code` |
| Targets, attacks, eval, scoring, campaign runner, SHAP, rules, narrative writer (`redsim/ml/`) | on `main` (#8, #9, then wave 1 `f8693c2..a99d9cc`). Registered targets `cifar10_smallcnn` (fixture only), `url_trees` (alias `url_classifier`), `vehicles_cnn`, `endpoint_stub`, and attacks `fgsm`, `pgd`, `hopskipjump`, `noise_control`. Loaders read the build-assets manifest shape, ONNX uploads are converted with onnx2torch and their argmax agreement recorded, `pgd` on a tree ensemble runs by surrogate transfer with per-feature ε scaling and an ART mask for frozen features, attacks that cannot run are recorded `not_run` and dropped from the scored set, the robustness curve is rendered to PNG, the control check is a binomial predicate, an image target without a torch module falls back to `PartitionExplainer`, explanations are cached per (model, sample, attack, ε, explainer, seed), and the report renderer writes the six sections of spec 14.8 |
| Sandbox child (`redsim/ml/sandbox.py`, `redsim/ml/sandbox_worker.py`) | on `main`. Typed `MlSandboxConfig` from `REDSIM_ML_SANDBOX_*`, per-job work directory, typed result envelope, `SandboxTimeout` / `SandboxKilled` / `EnvelopeInvalid` distinct from a model refusal |
| Worker (`redsim.ml_campaign_run`, `redsim.ml_model_validate`, ML branch of `redsim.report_render`) | on `main` (wave 2 `055bdee..bb43bd7`). Spec 10.5 audit vocabulary, spec 6.5 stage table, Pythia narrative in the worker parent, typed validate envelope with a parent-side digest check, observability init, stage spans and the run roll-up in the reaper |
| API admission and routes | on `main` (#22, then wave 2). Every ML route of spec 17.2 is mounted and uses the spec 17.3 codes from `redsim/api/errors.py`. See the [API reference](../api/v1.md) |
| Offline CLI `redsim ml attack`, `redsim ml seed`, the `ml-campaign` scanner adapter, `redsim.ml.attacks` plugin discovery, the `tests/e2e` harness, the Pythia-centred `redsim doctor`, Pythia-only `redsim.yaml` and `.env.example` | wave 3, landing 2026-09-09. Not in this tree: `redsim ml` has `build-assets` only, `GET /v1/scanners` is empty, `tests/e2e/` holds an `__init__.py`, and `redsim doctor` still derives a provider key from `redsim.yaml` |
| Web pages `/models`, `/models/[id]`, MRI panels on `/runs/[id]`, three-pane `/findings/[id]` | on `main` (#16). #22 aligned the web contract with the mounted routes. Wiring beyond that alignment and the Playwright browser e2e are excluded from this completion pass |
| ECS Fargate deployment | Terraform foundation only (#19, `deploy/terraform/`). Applying it, Helm and compose operations are excluded from this completion pass |

The bundled assets were built locally with `redsim ml build-assets` on
2026-09-09. They are gitignored under `assets/`, so a fresh clone builds its
own. The numbers below are illustrative local build figures read from that
manifest, not results and not product claims:

| Asset | Recipe | Clean accuracy (illustrative, local build) |
|---|---|---|
| `url_trees` | scikit-learn `HistGradientBoosting` on lexical URL features, with a build-time PGD surrogate | 0.9087 on `n = 128224` (Kaggle malicious-URLs eval split), surrogate clean agreement 0.7891 |
| `vehicles_cnn` | `resnet18`, ImageNet initialisation from the local torch hub cache, fine-tune at lr 3e-4 with cosine decay, flip and crop augmentation, best epoch by a 10 percent validation slice held out of the training split | 0.7687 on `n = 1621` (`test_coarse`). The earlier `small_cnn` recipe reached 0.5151 on the same split |
| `cifar10_smallcnn` | `small_cnn`, CI fixture only, never a demo target | 0.6872 on the CIFAR-10 test split |

## Orchestration

One API-launched campaign is one job. The flow at `bb43bd7`:

1. **Admission** (`POST /v1/models/{id}/attacks`, `redsim/services/ml_campaigns.py::create_attack_campaign`).
   The route checks membership and `attack.run`. The service resolves the
   target (status must be `available`), fills defaults (norm `linf`, the
   default ε grid for the norm, `reference_eps`, the dataset the manifest
   binds), validates every attack against the registry, freezes a
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
   Hugging Face offline flags and `REDSIM_ML_ASSETS_DIR`. No `REDSIM_*`
   secret, no `PYTHIA_*` value and no proxy variable reaches it, and the child
   scrubs the LLM variables again itself. Bundled targets load from the asset
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

The offline path (wave 3, landing 2026-09-09) runs the same
`run_campaign_sandboxed` from `redsim ml attack <target_id>` without the
database: the `attack.run` row goes first to a `JsonlAuditWriter` at
`<out>/<run_id>/audit.jsonl` (chain `run:<run_id>`), then `run_record.json`,
`report.md/json/html` and the curve land under `<out>/<run_id>/`, stage
events and `job.complete` join the same chain, `llm_narrative` stays off and
the command prints `narrative_source=rules`. `endpoint_stub` and fixture-only
targets are refused before anything is written.

## Stages and the stage table

`STAGES` in `redsim/ml/schema.py` is the ordered tuple `load_target`,
`sample`, `clean_eval`, `attack`, `control`, `explain`, `score`, `interpret`,
`recommend`, `report`. The child reports `attack` per attack as
`attack:<attack_id>`, and `score` runs after `explain` because `S_expl` needs
SHAP. `expected_stages(config)` in the task derives the keys one campaign
will write (no `control` when `include_control` is off, no `explain` when
`explain_k = 0`, no `recommend` when `auto_recommend` is off).

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
WebSocket. A verify run reuses the same stages with the defense applied to the
evaluation copy after `load_target`.

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
| `ml.harden.prompt`, `ml.harden.completion`, `ml.harden.narrative` | `harden/prompt.txt`, `completion.txt`, `narrative.md` | the Pythia exchange, written by the parent |
| `ml.events` | `events.jsonl` | the child's stage event log |
| `report.md`, `report.json`, `report.html` | `report.<ext>` | the rendered report. `GET /v1/runs/{id}/report.{ext}` serves the newest row (legacy `ml.report_<ext>` rows are also accepted) |
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
| `model.register` | `POST /v1/models` (bundled or upload, `success=False` rows for every refusal) | project |
| `model.validate`, `job.complete` | `redsim.ml_model_validate` | run (`ml.ingest`) |
| `attack.run`, `explain.run`, `harden.recommend`, `verify.replay` | the admission services, before any row (`success=False` on refusal) | project |
| `model.load` | the task, once `load_target` completes (or `success=False` with the error class when it did not) | run |
| `attack.execute.<attack_id>` | the task, per attack as its stage completes. A `not_run` attack gets a `success=False` row with the reason | run |
| `explain.execute` | the task, when `explain` ran (observation count, artifact ids and digests, expl_shift) | run |
| `campaign.score` | the task, when a score record exists (`mri`, `grade`, `completeness`, `missing`, `settings_hash`, score digest, ΔMRI on verify) | run |
| `harden.execute` | the task, on an attack or harden job with candidates (rules fired, `llm_requested`, `llm_used`, `narrative_source`, `skipped_reason`, redacted Pythia settings, prompt and completion sha256, `usage.{prompt,completion}`, cost) | run |
| `verify.execute` | the task, on a verify job (defense, outcome, validation state, delta) | run |
| `report.render` | the task at completion (`formats`, artifact ids, digests), and `redsim.report_render` on re-render | run |
| `job.complete` | the task, last (`status`, counts, `completeness`, envelope digest, `error_class`, and `success=False` on failure or cancellation) | run |
| `finding.review`, `finding.annotate`, `target.manage`, `run.cancel` | the finding status, reviewer notes, model delete and cancel routes | run or project |

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
| `RunRecord`, `CampaignRecord`, `RunSummary`, `ScoreStatus` | The run record artifact and the `GET /v1/runs/{id}/campaign` response. A succeeded run must carry limitations, every citation must resolve, and a campaign carries either `score` or `score_status`, never both. |

Helpers frozen with the models: `STAGES`, `BANNED_SCORE_WORDS`,
`GRADE_STATEMENT`, `grade_for_mri()`, `contains_banned_score_word()`,
`STANDING_LIMITATIONS` and `standing_limitations()`.

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
| Public copies for other teams | [IntelliBridge/ai-red-teaming-data](https://github.com/IntelliBridge/ai-red-teaming-data) (GitHub, public, commit `ff6a36b`) | CC BY 4.0 for the repository's own contents, upstream licenses kept per file | No models and no CIFAR-10. The URL CSVs are redacted copies (credential-shaped query values replaced with `REDACTED` in 2,346 of 651,191 rows and 406 of 128,224 in the eval split), so their hashes differ from the unredacted Kaggle file the local build trains on (spec 11.7). |
| Phase B LLM-track probe corpora | garak's bundled data under `garak/data` | Apache-2.0 for the garak package, upstream terms per subset | Phase B only (spec 11.6), excluded from this pass. Prompts are untrusted data and go only to the permission-gate-only Pythia persona. |

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
Phase A. The API never loads a model: it streams bytes to the blob store,
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
`report.export` scanner) are in [auth.md](auth.md#rbac). The independence
rule (a campaign creator or a system principal cannot dismiss a finding) is
enforced in `redsim/services/ml_findings.py`. `ml_campaigns` carries the same
RLS policy and trigger pair as the other scoped tables, see
[multi-tenancy.md](multi-tenancy.md). Bundled model targets are per project
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
| 17.3: the code table is complete | operational codes outside the table (`ml_catalog_unavailable`, `license_required`, `campaign_not_found`, the two digest-mismatch codes, the reviewer-notes codes) | import failures and evidence-integrity failures have no admission row in the spec table, so they are named rather than folded into a wrong code |

## Open items

Excluded from this completion pass and listed in the README as open: web UI
wiring beyond the #22 contract alignment, the Playwright browser e2e, applying
the Fargate Terraform, Helm and compose operations, Phase B (garak via Pythia,
the endpoint connector, interoperability B2), the fallback datasets, and every
spec 26 criterion that needs a named human reviewer (26.18 upload sign-off,
26.25 to 26.27 checklists and approvals, and decisions D006 and D007 stay open).

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
