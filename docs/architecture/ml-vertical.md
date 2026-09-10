# ML vertical

This page describes the adversarial-ML vertical as it runs: the flow from
admission to report, the stage table, the artifact and audit vocabularies, the
modalities and connectors, and the places where the tree knowingly departs
from its original design. Every run is a measurement in its own right. There
is no verify loop: verify campaigns, the finding validation state, the defense
catalog and the measured delta were removed on 2026-09-09. The
interoperability narrative has its own page, [Interoperability](../interop.md).
The routes are in the [API reference](../api/v1.md).

## What the vertical does

One campaign takes one classifier (a bundled sample or an uploaded ONNX or
PyTorch `state_dict` artifact), one modality (`image` or `tabular`), a
declared attack set, an ε grid and a reference budget. The worker runs the
attacks from the Adversarial Robustness Toolbox (ART) at every ε on one seeded
slice, pairs them with a benign random-noise control, explains flipped and
unflipped samples with SHAP, scores the campaign with the Model Robustness
Index (MRI), derives interpretation and candidate hardening recommendations
from deterministic rules, and optionally rewrites the rule output into prose
through Pythia. Every run is a measurement in its own right. Nothing is ever
applied to the stored model. The tool is a
non-operational proof of concept on open, unclassified public data, and no
score or grade it produces is a safety, readiness or certification statement.

Platform pieces the vertical reuses unchanged: the FastAPI app and RBAC
([auth](auth.md)), the Celery workers and the job state machine, Postgres
with row-level security ([multi-tenancy](multi-tenancy.md)), the blob store,
the hash-chained audit log ([audit chain](audit-chain.md)), per-task LLM
routing with budgets, and the Pythia transport.

The library under `redsim/ml/` also carries a `text` modality (a bundled
TF-IDF plus logistic-regression SMS spam classifier, a word-substitution
attack under an edit budget, SHAP text attributions), a `detection` modality
(a bundled torchvision detector on a capped open subset, ART DPatch under a
patch-area budget, a detection scorecard and never an MRI), the
Carlini-Wagner L2, DeepFool and ZOO attacks, KernelSHAP for predict-only
tabular targets, and an `EndpointTarget` that reaches a black-box inference
endpoint only through a worker-parent predict broker. All of it is reachable
through the API: campaign admission covers all four modalities and endpoint
targets, `POST /v1/models` registers predict endpoints and LLM targets, garak
probes run through the Pythia gateway (`redsim/ml/llm/`), and the review
workflow, PDF reports, snapshots, N-run compare, per-project weights and
`Idempotency-Key` exist. A terminal run exports its adversarial examples as a
Croissant dataset over Parquet shards, another team's Parquet slice is
admitted with static checks and parsed only in the sandbox child, every new
finding carries its ATLAS technique and a campaign has a coverage view, a
scorecard can be pushed to a configured Foundry instance (off by default),
campaigns run as batches with a roll-up and grouped compare, models upload in
bulk, and per-project capacity defers or refuses admissions. The e2e files
under `tests/e2e/` drive every one of those paths through the real API,
worker and sandbox child. See
[Modalities, connectors and interoperability](#modalities-connectors-and-interoperability).

## Bundled assets

The bundled assets were built locally with `redsim ml build-assets` on
2026-09-09. They are gitignored under `assets/`, so a fresh clone builds its
own. The numbers below are illustrative local build figures read from that
manifest, not results and not product claims:

| Asset | Recipe | Clean accuracy (illustrative, local build) |
|---|---|---|
| `url_trees` | scikit-learn `HistGradientBoosting` on lexical URL features, with a build-time PGD surrogate | 0.9087 on `n = 128224` (Kaggle malicious-URLs eval split), surrogate clean agreement 0.7891 |
| `vehicles_cnn` | `resnet18`: ImageNet initialisation from the local torch hub cache, fine-tune at lr 3e-4 with cosine decay, random flip and reflect-pad crop augmentation, best epoch by a per-class 10 percent validation slice held out of the training split, so the evaluation split is never used for selection | 0.7687 on `n = 1621` (`test_coarse`). The earlier `small_cnn` recipe reached 0.5151 on the same split |
| `cifar10_smallcnn` | `small_cnn`, CI fixture only, never a demo target | 0.6872 on the CIFAR-10 test split |

## Orchestration

One API-launched campaign is one job. The flow:

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
   computes `settings_hash`. Every refusal is an `ApiError` with a code from
   `redsim/api/errors.py` and writes an `attack.run` audit row with `success=False`.
2. **Audit row, then rows.** `redsim.safety.authorize("attack.run", …)`
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
   pinned to the absent `<work_dir>/no-env` and `REDSIM_DISABLE_LLM=1`. No
   `REDSIM_*` secret, no `PYTHIA_*` value and no proxy
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
7. **Parent narrative** (`_parent_narrative`). Only after the child
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
   `narrative_source = "rules"` and the reason as a limitation.
8. **Reports, record, audit, findings.** `render_campaign_reports` writes
   `report.md`, `report.json` and `report.html`. The run record is written as
   `ml.run_record` and mirrored into `ml_campaigns`, and `_emit_record_audit`
   writes the rows the record justifies in order. `attack.run`
   projects one `Finding` per attack whose ASR at `reference_eps` crosses
   `finding_asr_threshold`, `explain.run` and `harden.recommend` merge the
   child's observations, interpretation and candidates back into the parent
   finding's `schema_blob["ml"]`. `report.render` (with the format
   list and artifact ids) and `job.complete` close the trail.

Follow-up actions (`POST /v1/findings/{id}/explain` and `/harden`) are
admitted by the same pattern as child campaigns of the parent run (`scanner`
`ml.explain`, `ml.harden`, and the `ml_campaigns` row carries
`parent_run_id`) and run on the same task. Reruns of a failed or cancelled
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

The offline path (`redsim ml attack <target_id>`) runs the same
`run_campaign_sandboxed` without the database: the `attack.run` row goes
first to a `JsonlAuditWriter` at `<out>/<run_id>/audit.jsonl` (chain
`run:<run_id>`), then `run_record.json`, `report.md/json/html` and the curve
land under `<out>/<run_id>/`, stage events and `job.complete` join the same
chain, `llm_narrative` stays off and the command prints
`narrative_source=rules`. `endpoint_stub` and fixture-only targets are
refused before anything is written. `redsim audit verify --run <run_id>`
finds that chain through the `<output_dir>/<run_id>/audit.jsonl` fallback,
or `--run-dir <out>/<run_id>` names it.

## Modalities, connectors and interoperability

The sections below describe the second layer of the vertical: the
frozen-contract additions, the modality runners, the new attacks and
explainers, the endpoint connector, the LLM probes, the review workflow,
reports and compare, and the interoperability and bulk operations (the
[route table](../api/v1.md#phase-b-routes) in the API reference).

### Contracts

- **Schema**: the additive fields listed under
  [the frozen schema](#the-frozen-schema).
  `tests/ml/test_schema_compat.py` pins the frozen fixture's sha256
  (`25be404fca91eb5b11d75795b1f34076be39603a106666f35abf1fc9698f1ca6` since
  the fixture was regenerated on 2026-09-09) and refuses any removed, retyped
  or narrowed P0 property.
- **Migration `0011_phase_b_platform`**: `report_snapshots`,
  `idempotency_keys`, `ml_batches`, `ml_datasets` with `0010`'s RLS parity,
  `projects.ml_scoring` / `ml_max_concurrent_runs` / `ml_daily_run_budget`,
  `ml_campaigns.batch_id`. See [multi-tenancy](multi-tenancy.md). Migration
  `0012_remove_verify_paradigm` (2026-09-09) is the head above it. It drops
  the two finding validation columns and the campaign baseline column that
  the verify paradigm used.
- **Actions and codes**: `llm.probe.run` (remediator),
  `dataset.register` (remediator), `dataset.export` (remediator),
  `integration.push` (admin), `batch.run` (scanner), `report.render`
  (scanner), `finding.author` (remediator), mirrored in the OPA and Cedar
  bundles, and the error codes listed in the [API reference](../api/v1.md).
- **Tripwires and CI**: the schema-compat test, the extended
  API-process import block (garak, openai, litellm, reportlab, pyarrow,
  mlcroissant), the child-env credential check, the `garak` marker and
  `garak>=0.16,<0.17` pin, the `e2e-python` and `garak-offline` jobs.
- **Endpoint contract and egress**: `endpoint-v1`, see
  [the contract page](../api/endpoint-contract.md).
- **Datasets**: see [Datasets and handling rules](#datasets-and-handling-rules).

### Modality runners

`redsim/ml/campaign.py` is the shared frame: target resolution,
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
test `tests/ml/test_campaign_golden.py` runs its scenarios (image FGSM and
PGD with explain, tabular PGD by surrogate, tabular all `not_run`) through
the refactored frame and the frozen
pre-refactor copy `tests/ml/_campaign_pre_refactor.py` (sha256 asserted) and
asserts deep equality of every non-volatile field; HopSkipJump is excluded
because ART draws its initial point from an unseeded `RandomState`, which the
adapter records.

### Text modality

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
  `joblib.load` runs only after the manifest digest matched (the same
  exception `url_trees` uses), `predict_proba` over strings, `sample()` a
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
  `adv_slice` JSON lines, the text limitations (including a
  correction of the standing white-box sentence for a black-box text attack)
  and the flip-matrix extras (budget label, per-message edit fractions, word
  counts). A non-`edit` norm is refused before any stage.

### Detection modality

- `redsim/ml/datasets/military_assets.py`: reads the capped subset the
  datasets step publishes under `<assets>/cache/military_assets_subset`
  (YOLOv8 layout: `images/<split>`, `labels/<split>`, a `*.yaml`). Boxes of the
  person and weapon classes (`camouflage_soldier`, `weapon`, `civilian`,
  `soldier`) are dropped at load time, images left without
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
  and validated to carry no MRI key.
  Detection-worded interpretations and recommendations (patch-aware
  adversarial training, occlusion detection, multi-frame consistency, with
  references) are exposed for the rule layer.

### Additional attacks

`cw_l2` (Carlini-Wagner L2 over ART `CarliniL2Method`), `deepfool`
(`DeepFool`) and `zoo` (`ZooAttack`) are described in the
[attack catalog](../api/v1.md#attack-catalog). Shared registry additions:
`KNOWN_NORMS` `{linf, l2, edit, patch_area}`, `attack_norms(adapter)` and
`attack_supports_norm(adapter, norm)` (the frame refuses an adapter in a
norm it does not declare and records it `not_run`; admission refuses the
same case first with `422 params_out_of_range` on `norm`),
`norm:<n>` capability tags, `attack_domain_defaults` /
`apply_domain_defaults` for per-modality cost defaults (image HopSkipJump
`IMAGE_DEFAULTS`), the shared `queries_summary` / `achieved_norm_note` /
`require_class_gradients` helpers, `ATLAS_TECHNIQUES` entries for the new
evasion adapters, and a catalog check that the registered ids match the
declared list (`adv_patch` is recorded as not built with its reason). ZOO re-imposes frozen tabular features through `TabularScaling`,
keeps the exact clean value on coordinates it did not move, and uses
`learning_rate` 0.1 and `variable_h` 0.05 instead of ART's image defaults,
which moved nothing on the tree ensembles (recorded in the module docstring).

**Measured CPU budgets** (a CPU-only Apple silicon
laptop, Python 3.12.13, torch 2.14.0 pinned to 2 threads as in the sandbox
child, ART 1.20.1, seed 0, the real bundled models, 2026-09-09). These are
budgets for choosing `n_samples` and defaults, never accuracy or robustness
claims about the models:

| Target | Attack, parameters | n | Wall time | Per sample | Observed |
|---|---|---|---|---|---|
| `vehicles_cnn` (resnet18 at 128 px, 7 classes) | forward pass, batch 64 | | | 7.1 ms per row | |
| `vehicles_cnn` | `hopskipjump`, `IMAGE_DEFAULTS` (`max_iter` 10, `max_eval` 250, `init_eval` 50, `init_size` 50) | 8 | 63.3 s | 7.9 s | 6 of 8 flipped, `queries_mean` 1393.0 (8358 predict rows in 1670 calls). n = 64 is about 8.5 min; n = 200 does not fit the 1200 s sandbox wall clock. Hence the cap of 64 |
| `vehicles_cnn` | `cw_l2` defaults (`binary_search_steps` 5, `max_iter` 10, `initial_const` 0.01) | 8 | 48.2 s | 6.0 s | 6 of 8 changed, median achieved L2 0.27, max 0.47. `initial_const` 0.1: 50.2 s, median 0.24; 1.0: 50.3 s, median 0.29 (defaults kept) |
| `vehicles_cnn` | `deepfool` defaults (`max_iter` 20) | 8 | 10.4 s | 1.3 s | 8 of 8 changed, 4 of 8 flipped from the clean prediction, median L2 0.22, max 0.52 |
| `url_trees` (HistGB, 16 features) | `zoo` defaults (`learning_rate` 0.1, `variable_h` 0.05) | 16 | 90.9 s | 5.7 s | 11 of 16 flipped, `queries_mean` 100.4 (1104 single-row predict calls: ART's `BlackBoxClassifier` batches at ZOO's `batch_size` 1). `variable_h` 0.1 / `learning_rate` 0.2: same counts, 90.1 s |

The rows live in `hopskipjump.MEASUREMENT`. Image HopSkipJump is served by
the one `hopskipjump` adapter with image defaults (`phase: "A"`), recorded
under [accepted divergences](#accepted-divergences).

### Black-box explanation

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
"black-box-endpoint"`), `estimate_kernel_explain_rows` (the admission estimate) and
`EXPLAINER_ROSTER` for the capabilities route, which serves it as
`explainer_roster` (the admission service reads `EXPLAIN_QUERY_CAPS`
directly).
KernelSHAP for images is not built (about 100k predict calls per
3x128x128 sample); `PartitionExplainer` stays the black-box image explainer
(recorded under accepted divergences).

### Endpoint target and predict broker

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
are in the sections below.

### Training defenses

There is no defense catalog and no training stage. The verify paradigm was
removed on 2026-09-09, and no campaign applies a defense. Record and
limitation texts still avoid the banned word "hardened".

### Endpoint connector

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

### Admission across modalities

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
travel on the response and the audit row (`is_default_weights` is the
predicate).

### Endpoint campaigns {#endpoint-campaigns-wave-b2}

`redsim/workers/tasks/ml_campaign.py` (`tests/ml/test_tasks_phase_b.py`)
detects an `ml_model_endpoint` target,
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
they carry the counts. A typed transport-failure mapping in this task is not
built (open item, README). Two more endpoint seams are recorded by
`tests/e2e/test_ml_endpoint.py` and not fixed: the frozen
`query_budget.limits` fold the registration's `batch_rows` and `timeout_s`
while the broker runs with the validate-time defaults, and the broker's
`by_purpose` split is `{probe, predict}` because the classification runner
never enters `EndpointTarget.purpose(...)`. The campaign path itself is
blocked by the unscaled 8-row probe in `redsim/ml/targets/endpoint.py` (no
endpoint reaches `available` through the tiny server), the defect the failing
endpoint e2e cases name.

### No verify branch

The verify paradigm was removed on 2026-09-09. The campaign task has no
verify branch, registers no derived target, writes no delta and writes no
`RemediationAttempt` row. Its finding projection is the attack projection
only.

### LLM probes through Pythia

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
visible reasons (`fitd.FITD` for HarmBench;
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
weights) and requires the sentence that no MRI or grade is derived from LLM
probe results; `assert_no_mri` is the reusable guard.
`rules.py`: `interpret()` and `recommend()` (`r.L1` to `r.L7`, every
candidate `status: candidate`, `narrative_source rules`,
`NARRATIVE_NOT_OFFERED_REASON`). `report_section.py` renders the seven-section
probe report and the fragment `redsim.ml.reporting` embeds between sections
2 and 3, guarded by `check_llm_report_text` (no banned score word, no MRI or
grade wording outside that sentence).

`redsim/services/ml_llm.py` (API-light, no garak, openai or ML import) holds
the vocabulary (`ml.llm_probe` scanner, `llm.probe` job type,
`redsim.ml_llm_probe_run` task, `ml.llm_probe` usage task,
`ml.llm.scorecard` kind, the guardrail modes, the default set), the
`LLMProbeRequest` model, `register_llm_target`, the catalog reader,
`resolve_probes`, `admit_llm_probe_run` (audit-first, `Run` and `Job`, the
enqueue on `default`, no `ml_campaigns` row), `read_llm_scorecard` and the
`is_llm_probe_run` / `refuse_llm_probe_run` guards `/campaign` and `/compare`
use. `redsim/api/v1/llm.py` is the route layer.
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

### Review workflow

`redsim/services/finding_review.py` (`tests/ml/test_review_workflow.py`) is
one transition table over (`Finding.status`, `schema_blob.<ml|llm>.review.state`)
with six decisions (`submit`, `confirm`, `request_changes`, `dismiss`,
`reopen`, `resolve`), independence by identity (campaign creator, latest
revision author, system principals; `403 reviewer_not_independent`),
compare-and-set on `expected_status` and `expected_review_state` (`409
review_state_conflict`), `resolve` judged by `resolution_conditions()`
(`review_state: confirmed` only, else `409 resolution_blocked` with `unmet:
["review_state_not_confirmed"]`, and on success the finding is `status: fixed`
and `review_state: resolved`), every decision audited through `authorize()`
before the write, history appended instead of replaced, and analyst drafts (`create_draft_finding`, `revise_draft`) whose evidence ids
are checked against the digest-verified run record. The routes are in the
[API reference](../api/v1.md#review-workflow). The older dismissal route
(`PATCH /v1/findings/{id}/status`) keeps its rules, codes and plain-string
`forbidden`.

### Reports, snapshots, compare and weights

`redsim/ml/pdf.py` renders the report Markdown into reportlab flowables
(imported inside the function, so the API tripwire holds), byte-identical
for the same record and stamp, with DejaVu Sans subsets under
`redsim/ml/pdf_fonts/` (Bitstream Vera licence, the subset command in its
README), `REDSIM_PDF_FONT_DIR` as the override and a `PdfFontsUnavailable`
refusal rather than a Latin-1 fallback; text extraction confirms the six
report headings and the ε glyph. `redsim/ml/reporting.py` gains the
`schema_version` and licence lines, the **Non-default weights** badge, the
sentence that no export-redaction policy was applied, `formats=` and the LLM
section hook. `redsim/services/reports.py` writes one
`report_snapshots` row per render (`snap-<hex>`, `artifact_ids`,
`record_sha256`, `rendered_at`, `created_by`), admits `report.render` jobs
audit-first and serves, resolves, archives and restores snapshots;
`redsim/api/v1/reports.py` serves `report.pdf`, `?snapshot=`, the render
route and the snapshot routes ([API reference](../api/v1.md#reports)).
`redsim/ml/compare.py` is the pure comparison module: compatibility per
config field plus `sample_indices_sha256` with the scoring block compared per
sub-key, `comparison_table` over 2 to 10 runs in request order with no delta
column and no baseline concept, `assert_no_aggregate_keys`;
`GET /v1/runs/compare?ids=` is the thin route over it. `GET`/`PUT
/v1/projects/{slug}/ml-scoring` store the full `ScoringConfig` or `null`,
never filled in or renormalised, audited as `project.settings`.
`redsim/api/middleware/idempotency.py` honours `Idempotency-Key` on the
mutating ML routes ([API reference](../api/v1.md#idempotency-key)). The
campaign task's completion path renders `md`, `json`, `html` and `pdf`, lists
what it wrote on the `report.render` row and records the run's first
`report_snapshots` row over those artifact rows;
`POST /v1/runs/{id}/report.render` adds further
snapshots (version 2 onwards). A record whose measurement table is too wide
for the PDF renderer (reportlab `LayoutError`, observed on a 13-column table)
degrades to the three text formats with `pdf_unavailable` on the row and the
job completes; the on-demand render route still raises on such a record
(open item, `redsim/ml/pdf.py`).

### Croissant export

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
limitations verbatim, the ATLAS technique per attack, the release); the
manifest's own sha256 is the dataset
version; `check_projection` is the projection-equality guard (every
adversarial row's `flipped` equals the run's `ml.flip_matrix`, cross-checked
from retained predictions when present, `ExportMismatch` otherwise) and
`croissant_validate` the structural gate that also refuses model file names,
`reviewer_notes`, credential environment names and any bare MRI.
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
written. The classification runner writes self-describing `clean_slice.npz`,
`adv_slice/<attack>_<eps>.npz` and `control_slice/<eps>.npz` with the
per-sample prediction keys, and the exporter labels each slice from the
`family` / `attack` / `eps` keys embedded in its bytes, so a live export of a
classification run carries clean, adversarial and control shards with
populated prediction columns; a non-npz slice (the text runner's JSON lines)
is skipped with a caveat, and an all-unlabelled run is a refusal, never a
guess. `tests/ml/test_interop_export.py` proves it end to end on a real
campaign through the filesystem blob store.
The published sample and the rules are in
[Interoperability](../interop.md#contribute-a-runs-adversarial-examples-as-a-croissant-dataset).

### Consumed slices

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
admission calls `resolve_consumed_slice` (a
`ds-…` id must be an `available` slice of the project matching the campaign
modality, else `422 dataset_incompatible`; `dataset_revision` defaults to the
manifest digest; `dataset_id` and `dataset_role` on the audit rows). The
upload admission binds a consumed slice too
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

### ATLAS stamping, coverage and the Foundry push

`redsim/ml/atlas.py` carries `STAMP_TECHNIQUE_IDS`, checked at import against
`atlas_data.ATTACK_TECHNIQUE_IDS` (`fgsm`, `pgd`, `cw_l2`, `deepfool`, the
surrogate PGD, `word_substitution` and `dpatch` stamp `AML.T0043`;
`hopskipjump` and `zoo` stamp `AML.T0040`; the poisoning ids map to
`AML.T0020`; controls `None`), `technique_for_attack`,
`attack_atlas_row` for the catalog and `coverage(record, catalog_attacks)`,
the per-campaign view with no `int` or `float` anywhere (a `ValueError` if
one appears). `services.ml_findings.build_finding_detail` stamps
`atlas_technique` on every new ML finding; `GET /v1/attacks` rows gain the
ATLAS block and the response the release citation; `GET
/v1/runs/{id}/atlas-coverage` serves the view. `redsim/integrations/foundry.py`
holds the settings (`REDSIM_INTEGRATION_FOUNDRY_URL` unset means disabled;
the egress rules and the `REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL=1`
attestation; no token variable), the roster block, `build_scorecard_payload`,
the payload guard `validate_push_payload` / `assert_push_payload`,
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
`job.complete`. Proven against `tests/ml/fake_foundry_server.py` in CI and,
on 2026-09-10, against a real developer-tier instance by
`tests/e2e/test_ml_foundry_live.py`; the dataset push is not built. Details in
[Interoperability](../interop.md#foundry-the-scorecard-push) and the
[API reference](../api/v1.md#integrations).

### Batch campaigns

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
(`assert_no_aggregate_keys`). A batch's `kind` is `campaign` or `upload`.
`redsim/api/v1/batches.py` is the thin route layer
([API reference](../api/v1.md#batch-campaigns)).

### Bulk upload, capacity and the CLI matrix

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
The caps bind batch members and single-run admissions alike:
`create_attack_campaign` calls `admit_or_defer` before its admission row.
`redsim/cli/ml.py`: `redsim ml attack` takes
several target ids or `--matrix FILE.yaml` (models x attack sets x ε grids x
seeds, the schema printed by `--help`), runs one offline campaign per cell
with its own run directory and hash-chained `audit.jsonl` verified with
`verify_chain`, prints a per-cell table with no mean or rank, writes
`<out>/matrix-<id>/summary.json`, honours `--fail-fast` and exits 1 when any
cell was refused or failed; the single-target path is unchanged.

## Stages and the stage table

`STAGES` in `redsim/ml/schema.py` is the ordered tuple `load_target`,
`sample`, `clean_eval`, `attack`, `control`, `explain`, `score`, `interpret`,
`recommend`, `report`. The child reports `attack` per attack as
`attack:<attack_id>`, and `score` runs after `explain` because `S_expl` needs
SHAP. `expected_stages(config)` in the task is the `STAGES` tuple with the
per-attack `attack:<id>` expansion: the keys one campaign will write, in
order (no `control` when `include_control` is off, no `explain` when
`explain_k = 0`, no `recommend` when `auto_recommend` is off).

`Run.stage_table` is maintained by `_StageTracker`:

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
  "parent_run_id": "run-…"               // reruns and follow-ups
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
WebSocket. A campaign whose `modality` has no importable runner module is refused before any stage with the typed
`ModalityRunnerUnavailable` (`modality_runner_unavailable`).

## Artifact kinds

`DatabaseArtifactSink` maps the file names the pure modules write to the kind
vocabulary with an explicit table (`artifact_kind()` in
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
| `ml.text.diff`, `ml.shap.text` | `obs_<i>/text_diff.json`, `obs_<i>/shap_text.png` | text modality: the escaped word diff of one observation and its token-attribution bars. `shap_values.npz` keeps `ml.shap.values`; the campaign `shap_summary.json` carries counts, ranks and shifts only, never message text |
| `ml.detection.boxes`, `ml.detection.scorecard` | `obs_<i>/boxes.json`, `detection_scorecard.json` | detection modality: the per-observation box record (ground truth, clean and adversarial predictions, matches, patch location) and the campaign-level scorecard (worst-case recall ratio, suppression rate at the reference patch area, recall AUC, mAP@0.5, all with denominators, validated to carry no MRI key). The drawn `clean_boxes.png` / `adv_boxes.png` are `ml.input.clean` / `ml.input.adv` |
| `ml.adv_slice` (text) | `adv_slice/<attack>_eps<e>.jsonl` | JSON lines of adversarial message strings, served as attachments |
| `ml.clean_slice`, `ml.control_slice` | `clean_slice.npz`, `clean_slice/…`, `control_slice/…` | the clean and control slices the export consumes. The classification runner writes `clean_slice.npz` and `control_slice/<eps>.npz` with the prediction keys and embedded `family` / `attack` / `eps` descriptors, so a live classification export carries all three families |
| `ml.dataset.manifest`, `ml.dataset.parquet`, `ml.dataset.card` | `datasets/<source-run-id>/croissant.json`, `data/<family>/<attack>_eps<e>.parquet`, `README.md` | the Croissant export of a run, content-addressed, on the source run; `GET /v1/datasets/{run_id}` serves the digest-checked manifest as `application/ld+json` |
| `ml.dataset_validation_report` | `dataset_validation_report.json` on the `ml.dataset_ingest` run | the sandbox child's parse report of a consumed slice (`consumed-slice-1`: rows, per-class counts, columns, shape, observed range, digests, library versions) |
| `ml.integration.payload`, `ml.integration.rows`, `ml.integration.receipt` | `redsim/scorecards/<run_id>/scorecard.json`, `rows.jsonl`, the receipt JSON, on the `ml.integration_push` run | the exact bytes that left for Foundry, stored before the push, and the receipt (host, dataset rid, transaction rid, per-file digests and statuses; never a token) |
| `ml.harden.prompt`, `ml.harden.completion`, `ml.harden.narrative` | `harden/prompt.txt`, `completion.txt`, `narrative.md` | the Pythia exchange, written by the parent |
| `ml.events` | `events.jsonl` | the child's stage event log |
| `report.md`, `report.json`, `report.html` | `report.<ext>` | the rendered report. `GET /v1/runs/{id}/report.{ext}` serves the newest non-archived snapshot's row, then the newest row of the kind (legacy `ml.report_<ext>` rows are also accepted) |
| `report.pdf` | `report.pdf` | the reportlab projection written at campaign completion and by a `report.render` job; served under `application/pdf`, never from the filesystem |
| `ml.llm.report_jsonl`, `ml.llm.hitlog_jsonl`, `ml.llm.digest_html`, `ml.llm.usage`, `ml.llm.child_result`, `ml.llm.scorecard` | `llm/report.jsonl`, `llm/hitlog.jsonl`, `llm/digest.html`, `llm/usage.json`, `llm/child_result.json`, `llm/scorecard.json` | a probe run: garak's own files stored and never parsed for text (storage fails closed when the key shape appears), the token ledger, the child's counts and the k/n scorecard `GET /v1/runs/{id}/llm-scorecard` serves. `ml.llm.partial.*` when the child did not succeed |
| `ml.partial.*` | `ml/partial/<name>` | whatever a killed or timed-out child had written |

## Audit trail

Every ML mutation is admitted through `redsim.safety.authorize()` before any
`Run` or `Job` row exists and before Celery is touched
(`tests/test_admission_audit_before_enqueue.py`), and the worker writes its
rows on the run chain through `_AuditEmitter`. Detail carries ids,
digests and counts only. `redact_audit_detail` blanks any key naming a token
and scrubs `pk_…` Pythia keys and Kaggle token shapes.

| Action | Written by | Chain |
|---|---|---|
| `model.register` | `POST /v1/models` (bundled, upload, endpoint and LLM registration with the `allowlist_check` verdict; `success=False` rows for every refusal) | project |
| `model.validate`, `job.complete` | `redsim.ml_model_validate` (uploads, and endpoint probes with `target` the URL and the allowlist verdict) | run (`ml.ingest`) |
| `attack.run`, `explain.run`, `harden.recommend` | the admission services, before any row (`success=False` on refusal); `attack.run` carries `modality`, `budget`, `target_kind`, `scoring_source`, `scoring_weights`, `non_default_weights` and a host-only `endpoint` block | project |
| `llm.probe.run` | `POST /v1/models/{id}/probes`, before any row, ids and counts only | project |
| `llm.probe.entitlement`, `llm.probe.execute.<probe short id>`, `llm.probe.score` | `redsim.ml_llm_probe_run`: the key's entitlement to the model (`success=False` with `model_not_entitled` or `gateway_unreachable`), one row per probe (`success=False` for `not_run` or failed probes), the scorecard digest | run |
| `finding.author` | `submit`, `POST /v1/findings` (`op: create`) and `PATCH /v1/findings/{id}/draft`: ids, counts and text digests, never the text | project |
| `report.snapshot.archive`, `report.snapshot.restore` | the snapshot archive and restore routes: snapshot id, version, record digest, artifact count, before and after flags, written before the flag flips | run |
| `project.settings` | `PUT /v1/projects/{slug}/ml-scoring`: field, old and new sha256, `cleared`, the vector; `success=False` on a refused vector | project |
| `dataset.export`, `dataset.export.execute` | `POST /v1/runs/{id}/dataset` admission (source run id, follow-up ids; `success=False` on `export_unavailable`, `export_in_flight`, `fixture_not_exportable`), then `redsim.dataset_export` (manifest sha256, file count, bytes, prefix; `success=False` on a projection mismatch or an invalid manifest) | the follow-up run (`ml.dataset_export`) |
| `dataset.register`, `dataset.validate` | `POST /v1/datasets` admission (ids, sha256 per part, counts, modality, licence text, revision; every static refusal a `success=False` row with reason and field, never a URL string or bytes), then `redsim.ml_dataset_validate` (dataset id, status, rows, per-class counts, revision, digests, refusal reason) | project, then the ingest run (`ml.dataset_ingest`) |
| `integration.push`, `integration.push.execute` | `POST /v1/runs/{id}/integrations/foundry` admission (`target` the Foundry host with the allowlist verdict, ids, `target_ref`, payload kind; refusals `success=False` on the campaign run's chain with the code and a `target_ref_problem` marker, never the value), then `redsim.integration_push` (host, dataset rid, transaction rid, payload, rows and record sha256, HTTP statuses, file count, bytes, outcome; on failure `step`, `http_status`, `error_class`, `transaction_aborted`). Every row is scrubbed of JWT-shaped tokens, `Bearer` values and URL strings before it reaches a writer | the follow-up run (`ml.integration_push`), refusals on the campaign run |
| `batch.create`, `batch.cancel` | `POST /v1/campaigns/batch` (`batch_id`, kind, target ids, `n_members`, modality, `config_hash`, `max_parallel`, `max_members`, the sha256 of the `Idempotency-Key` when sent; pre-check refusals and an all-refused batch `success=False`), `POST /v1/campaigns/batch/{id}/cancel` (member ids, `cancelling`, `already_terminal`; `success=False` on `run_terminal`). Each member's own `attack.run` row follows | project |
| `bulk.upload` | `POST /v1/models/bulk` (`bulk_id`, file count, safe file names, content length, declared formats, modalities, dataset ids; then each file's own `model.register` row; a refused request or file `success=False`) | project |
| `model.load` | the task, once `load_target` completes (or `success=False` with the error class when it did not) | run |
| `attack.execute.<attack_id>` | the task, per attack as its stage completes. A `not_run` attack gets a `success=False` row with the reason | run |
| `explain.execute` | the task, when `explain` ran (observation count, artifact ids and digests, expl_shift) | run |
| `campaign.score` | the task, when a score record exists (`mri`, `grade`, `completeness`, `missing`, `settings_hash`, score digest) | run |
| `harden.execute` | the task, on an attack or harden job with candidates (rules fired, `llm_requested`, `llm_used`, `narrative_source`, `skipped_reason`, redacted Pythia settings, prompt and completion sha256, `usage.{prompt,completion}`, cost) | run |
| `report.render` | the task at completion (`formats`, artifact ids, digests), `redsim.report_render` on re-render, and the `POST /v1/runs/{id}/report.render` admission (`phase: admitted`, `job_id`, `formats`, `requested_by`) before the job row | run |
| `job.complete` | the task, last (`status`, counts, `completeness`, envelope digest, `error_class`, and `success=False` on failure or cancellation; the endpoint broker counts on an endpoint run) | run |
| `finding.review`, `finding.annotate`, `target.manage`, `run.cancel` | the finding status and the review decisions (`decision`, from and to status and review state, the expectations, reviewer, author, campaign creator, revision; `success=False` with the unmet list or the independence violations on a refusal), reviewer notes, model delete and cancel routes | run or project |

`Run.scanner` also takes `ml.dataset_export` and `ml.integration_push`
(follow-up runs with `parent_run_id`) and `ml.dataset_ingest` (an ingest run
with no target), and `Job.type` `dataset.export`, `dataset.validate` and
`integration.push`.

`GET /v1/audit/verify?run=<id>` (or `redsim audit verify --run <id>`) proves a
whole campaign's trail because every worker row shares the run chain and the
admission row carries the `run_id`. The full table with the retained platform
events is in [audit-chain.md](audit-chain.md#planned-ml-events).

## The frozen schema

`redsim/ml/schema.py` is the frozen contract. Later work adds behaviour, not
fields. The verify paradigm's models and fields were removed from it on
2026-09-09 and the frozen fixture was regenerated. A field change after the
freeze follows the change protocol: no silent renames, an announced change,
and an additive default-valued field wherever possible.

| Model | What it holds |
|---|---|
| `TargetInfo`, `AttackInfo`, `ParamSpec` | Catalog entries. `AttackInfo` is the `GET /v1/attacks` row: `family` (`evasion` or `control`), `phase`, `access`, `requires_gradients`, `status` with `reason`, and a `params_schema` of bounded parameters. |
| `CampaignConfig` | One campaign, immutable after admission: `target_id`, `modality`, `attack_ids`, `attack_params`, `norm` (`linf` or `l2`), `eps_grid` (strictly ascending, each in (0, 1]), `reference_eps` (a member of the grid), `finding_asr_threshold` (0.2), `n_samples` (10 to 1000, default 200), `seed`, `include_control`, `explain_k` (0 to 32, default 8), the dataset binding, `scoring`, `llm_narrative`, `auto_recommend`, `target_snapshot`, `attacks`. |
| `ScoringConfig`, `MRIWeights`, `SeverityThresholds`, `ConfidenceThresholds`, `InterpretationThresholds` | The `ml.scoring` block copied onto the campaign at admission. `MRIWeights` validates that the five weights sum to 1. |
| `Provenance` | Library versions, `model_sha256`, dataset id, revision and split, `sample_indices_sha256`, `settings_hash`, lineage (`parent_run_id`), the redacted `llm` settings, `thread_env`, device and `nondeterminism`. |
| `Measurement` | One row per test family at one setting, id `m.clean`, `m.evasion.<attack_id>.eps<ε>` or `m.control.noise.eps<ε>`. Counts and rates with denominators: `n`, `n_correct`, `accuracy`, `n_flipped_from_clean`, `n_clean_correct`, `attack_success_rate`, realised norms, `pert_first_success_*`, `conf_gap_*`, `expl_shift_*` with its noise floor, `queries_mean`, `per_class`, `wall_time_s`, `notes`. |
| `Observation` | Per-sample evidence: labels, predictions, confidences, artifact ids and digests, `center_mass_ratio_*`, `expl_shift`, top SHAP features. `metric_kind` is the literal `heuristic` with a fixed note. |
| `Interpretation` | An inferred sentence with a non-empty `basis` of measurement or observation ids. `kind` is the literal `inferred`. |
| `CandidateRecommendation` | `status` is the literal `candidate` and nothing more: no validation label, no measured block, no gain figure. `narrative_source` is `rules` or `llm`. Rule candidates may cite ART classes and papers as plain text. |
| `MRIInputRow`, `ScoredValue`, `PerAttackSubscores`, `Subscores`, `MRIRecord` | The score record, described below. |
| `MLModelManifest`, `FeatureSpec`, `SurrogateInfo`, `CleanAccuracy` | The model manifest stored in `targets.detail` for `ml_model_artifact` and `ml_model_endpoint` targets: format, sha256, size, architecture id, input shape, classes, features, build-time surrogate, dataset binding, clean accuracy with `n`, `status` (`registered`, `validating`, `available`, `refused`) with a paired `refusal_reason`, `gradients`, `bundled`, license and source. |
| `MLFindingDetail`, `FindingReview`, `AtlasTechnique` | The `ml` sub-object of `findings.schema_blob`: attack, norm, grid, first-success ε, ASR by ε, the four evidence lists, limitations, artifacts and review state. `AtlasTechnique` is never back-filled by guesswork. |
| `RobustnessCurve`, `CurvePoint`, `AccuracyPoint` | Accuracy versus ε per attack with the clean point and the control curve, every point carrying `n`. |
| `RunRecord`, `CampaignRecord`, `RunSummary`, `ScoreStatus` | The run record artifact and the `GET /v1/runs/{id}/campaign` response. A succeeded run must carry limitations, every citation must resolve, and a campaign carries either `score` or `score_status`, never both. `CampaignRecord.schema_version` is `"campaign-record-1"`. `CampaignKind` is `attack` or `ingest` and `RunKind` is `attack`, `ingest` or `llm_probe` since 2026-09-09. |
| Later additions (all default-valued): `DetectionMetrics`, `TextObservation`, `DetectionObservation`, `TextModelSpec`, `DetectionModelSpec`, `EndpointSpec`, `ReviewEvent`, `FindingRevision`, `RunKind` | `Domain` and `Modality` gain `text` and `detection`, `Norm` gains `edit` (the maximum share of words replaced) and `patch_area` (the patch area as a fraction of the image, side `sqrt(eps * H * W)`), `Measurement.edit_fraction_mean` and `.detection`, `Observation.text` and `.detection`, `MLModelManifest.text`, `.detection` and `.endpoint`, `ReviewState` widened with `draft`, `in_review`, `confirmed`, `resolved`, `FindingReview.history` and `.revisions`, `RunSummary.kind` and `.probe_ids`. |

Helpers frozen with the models: `STAGES`, `BANNED_SCORE_WORDS`,
`GRADE_STATEMENT`, `grade_for_mri()`, `contains_banned_score_word()`,
`STANDING_LIMITATIONS`, `standing_limitations()` and
`CAMPAIGN_RECORD_SCHEMA_VERSION`.

## MRI

The Model Robustness Index is a 0 to 100 integer computed once per campaign,
meaning one model, one modality, one declared attack set, one ε grid and one
reference budget. Its inputs come only from the run's own
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

Constraints the schema enforces (`MRIRecord._mri_needs_all_five`):

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
- No delta exists. Every campaign's MRI stands on its own, and a
  recommendation is a text candidate that is never paired with a gain figure.

Finding severity is derived from the first-success ε and the ASR, never
hand-set.

## Finding lifecycle

Every run is a measurement in its own right. A finding closes by reviewer
decision, never by a second run.

1. `attack.run` projects one `Finding` per attack whose ASR at
   `reference_eps` crosses `finding_asr_threshold`. `Finding.status` is one of
   `open`, `fixed` and `false_positive`. The review state in
   `schema_blob.ml.review.state` is a `ReviewState` (`unreviewed`, `dismissed`,
   `draft`, `in_review`, `confirmed`, `resolved`).
2. `POST /v1/findings/{id}/explain` and `/harden` add evidence to the finding
   as child campaigns of the parent run. A recommendation stays a text
   candidate (`status: candidate`) with no validation label and no gain
   figure. Measuring a candidate against the model is a separate campaign.
3. The review decisions (`submit`, `confirm`, `request_changes`, `dismiss`,
   `reopen`, `resolve`) move the two states through the transition table in
   `redsim/services/finding_review.py`. The independence rules hold for every
   verdict (`403 reviewer_not_independent` for the campaign creator, the
   draft author or a system principal).
4. `resolve` requires `review_state: confirmed` only. Otherwise it answers
   `409 resolution_blocked` with `unmet: ["review_state_not_confirmed"]`. On
   success the finding is `status: fixed` and `review_state: resolved`.
   `dismiss` sets `false_positive` and `reopen` sets `open`.
5. `GET /v1/runs/{id}/compare?with=` and `GET /v1/runs/compare?ids=` answer
   `mode: side_by_side` only: the variables that differ, no delta column and
   no baseline concept.

## Evidence separation

A run makes exactly four kinds of statement, kept in separate fields, separate
report sections and separate UI panels:

| Kind | Type | Label enforced by |
|---|---|---|
| Measurement | `Measurement` | the field set: counts and rates only, `notes` for caveats |
| Observation | `Observation` | `metric_kind: "heuristic"` |
| Interpretation | `Interpretation` | `kind: "inferred"` and a non-empty `basis` |
| Candidate recommendation | `CandidateRecommendation` | `status: "candidate"`, `narrative_source` |

Ids are the citation mechanism: `m.<family>[.<attack_id>][.eps<ε>]`,
`o.<index:03d>`, `i.<n>`, `r.<rule_id>`. `RunRecord._no_dangling_citations`
rejects a record whose interpretation `basis` or recommendation
`triggered_by` cites an id that does not exist in the same run. Provenance and
limitations accompany the four in every report and page.
`standing_limitations(dataset_name, eps_grid)` returns the dataset sentence,
the budget sentence and the five standing limitations (SHAP is sensitivity not
cause, the slice is small, white-box gradient attacks assume full access,
recommendations are candidates none of which has been evaluated against the
model, passing does not establish safety or readiness). The campaign runner appends the build-time dataset caveats from
the manifest, a weak-subject caveat when the manifest flags
`subject_centered: false`, a surrogate-transfer limitation when white-box rows
came from the surrogate, and the narrative outcome. Reviewer notes are a
fifth, human voice under their own heading.

The interpretation rules I1 to I6 and the recommendation rules are
deterministic, read `InterpretationThresholds`, cite the ids
that fired them and print their thresholds (`redsim/ml/recommend/rules.py`).

## Datasets and handling rules

Every dataset is open, unclassified, public, and carries a stated license.
Nothing is committed except the CI fixtures under
`tests/ml/fixtures/` (the 500-image CIFAR-10 slice `cifar10_test_500.npz`
written by `build-assets --fixture`, and a seeded stratified sample of the
malicious-URLs file).

| Role | Dataset | License | Notes |
|---|---|---|---|
| Demo image | `leibnitz-lab/military_vehicles` (HF), coarse 7-class task | MIT for the compilation and labels | Ground-level photographs, not overhead. Photo copyright is not cleared by the MIT tag, so images stay inside the team's blob store. |
| CI image fixture | `uoft-cs/cifar10` (HF), pinned 500-image subset | unknown on the card | Fixture only, never presented as results, and `GET /v1/models` never lists `cifar10_smallcnn`. |
| Demo tabular | Kaggle `sid321axn/malicious-urls-dataset` | CC0 | The download needs a Kaggle token (`KAGGLE_API_TOKEN`, or the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair) at build time only. URL strings are data: never fetched, resolved or rendered as links. |
| Tabular fallback | `lacg030175/UNSW-NB15` (HF, config `standard`) | CC-BY-4.0 | The fallback if the Kaggle download cannot be completed. Not built, not wired. |
| Demo text | UCI SMS Spam Collection (Almeida and Gomez Hidalgo 2011, DOI 10.24432/C5CC84), `uci:sms-spam-collection` | CC BY 4.0 (stated on the UCI page, read 2026-09-09) | 5,574 messages (4,827 ham, 747 spam), zip sha256 `1587ea43…`, corpus sha256 `7d039a24…`. Published verbatim to the public repository as `data/sms_spam_collection.tsv` with a seeded 20 percent eval split (no redaction, reason recorded). CI fixture `tests/ml/fixtures/sms_spam_sample.tsv` (300 rows). Bundled model `sms_tfidf_lr`. Caveats recorded: era, English only, imbalance, phone numbers present. |
| Synonym lexicon | WordNet 3.0 from `nltk/nltk_data` gh-pages `550b6625` (`packages/corpora/wordnet.zip`, sha256 `cbda5ea6…`) | WordNet 3.0 license (BSD-style, `wordnet/LICENSE` sha256 `7731175a…`) | Fetched by `build-assets` into `<assets>/cache/wordnet/nltk_data/corpora/wordnet` (gitignored), not republished (reference entry `external/wordnet-3.0.md` in the public repository). CI fixture `tests/ml/fixtures/synonyms_tiny.json` (47 entries). |
| Demo detection (pending owner review) | Kaggle `rawsi18/military-assets-dataset-12-classes-yolo8-format` (version 5), a capped seeded subset: 300 images, 607 boxes, 4 classes x 75 images (`military_tank`, `military_truck`, `military_vehicle`, `military_aircraft`) | CC BY 4.0 (Kaggle metadata `licenseName`, read 2026-09-09) | Published to the public repository as `data/military_assets_subset/` (52 MB, per-file sha256 in its `manifest.json`, sha256 `749611b4…`) for owner review, removable in one commit if the owner declines. Person and weapon classes excluded by construction (1,536 of 4,336 candidate images dropped). The full 4.1 GB archive is cached locally only. Bundled model `assets_frcnn_mnv3`. |
| ATLAS technique data | `mitre-atlas/atlas-data` release `v2026.08` (`ATLAS-2026.08.yaml` sha256 `a8d32f67…`, tag object `b8613404…`, published 2026-09-01, checked 2026-09-09) | Apache-2.0 (LICENSE reproduced verbatim as `ATLAS_NOTICE`) | Vendored as constants in `redsim/ml/atlas_data.py` (AML.T0043 and its sub-techniques, T0040, T0024, T0015, T0031, T0020, T0018, T0059) with the 4.x prior names kept so stored findings are never rewritten; `verify_atlas_data` checks a local release file offline. |
| Public copies for other teams | [IntelliBridge/ai-red-teaming-data](https://github.com/IntelliBridge/ai-red-teaming-data) (GitHub, public, head `4048a209` on 2026-09-09) | CC BY 4.0 for the repository's own contents, upstream licenses kept per file | The military vehicles parquet, the two URL CSVs (redacted copies: credential-shaped query values replaced with `REDACTED` in 2,346 of 651,191 rows and 406 of 128,224 in the eval split, so their hashes differ from the unredacted Kaggle file the local build trains on), the SMS corpus and split, the military-assets subset, the `data/garak/` copy plus reference entries `external/garak-probe-corpora.md` and `external/wordnet-3.0.md`, and an `atlas` release record, all with `INDEX.csv` rows (bytes, sha256, source, licence, attribution) and `MANIFEST.json` entries. No models and no CIFAR-10. `tests/ml/fixtures/public_index.csv` is the byte-identical snapshot of `INDEX.csv` at that head and `tests/ml/test_datasets.py` checks every code-named dataset has its rows (`REDSIM_PUBLIC_DATA_CHECK=1` runs the live check). |
| LLM probe corpora | garak 0.16.0's `garak/data` (wheel sha256 `871100d7…`) | Apache-2.0 for the garak packaging, upstream terms per subset (`inthewild_jailbreak_llms.json` upstream terms unconfirmed) | Loaded by garak itself from the installed package, never re-packaged by redsim. The public repository carries `data/garak/` and the reference entry with per-subset licences. Prompts are untrusted data and go only to the permission-gate-only Pythia persona declared on the LLM target (registration requires the persona and a `guardrail_mode`). |

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
pickles are refused with `415 pickle_refused` and there is no override. Two more `ModelFormat`
literals exist for bundled and endpoint targets, not for uploads: the bundled
text classifier is `sklearn_joblib` and is opened with `joblib.load` only
after the manifest digest matched (the same exception `url_trees` uses), and an endpoint target is `format: "endpoint"` with no bytes at all
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
shap, matplotlib) installs only in the worker image, and
`tests/test_api_process_has_no_ml.py` builds the API with those imports
blocked.

## Pythia narrative path

The only outbound call the vertical makes is the optional hardening narrative,
and it runs in the worker parent after the sandbox child returns
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
   prose.

Prompt and completion are `ml.harden.prompt` and `ml.harden.completion`
artifacts, their digests and the token counts (as `usage.{prompt,completion}`)
go on the `harden.execute` row, and one `LLMUsage` row with
`task = "ml.harden_narrative"` feeds `GET /v1/orgs/{id}/cost`. Operator notes
are in [ops/pythia.md](../ops/pythia.md).

## Audit, roles and tenancy

The fourteen ML `Action` members and their minimum roles (`model.register`
remediator, `attack.run` scanner, `explain.run` scanner, `harden.recommend`
remediator, `finding.review` approver, `finding.annotate` remediator,
`report.export` scanner, `llm.probe.run` remediator, `dataset.register`
remediator, `dataset.export` remediator, `integration.push` admin,
`batch.run` scanner, `report.render` scanner, `finding.author` remediator)
are in [auth.md](auth.md#rbac), mirrored in the OPA and Cedar bundles. Every
one of them gates a real handler (`dataset.register` the consume route, `dataset.export` the export route, `integration.push` the Foundry
push, `batch.run` the batch admission, `model.register` the bulk upload,
`run.cancel` the batch cancel). Endpoint and
LLM registration gate on `target.manage` (admin). The independence rule (a
campaign creator or a
system principal cannot dismiss a finding) is enforced in
`redsim/services/ml_findings.py` and, for every review decision, by identity in `redsim/services/finding_review.py`
(`reviewer_not_independent`). `ml_campaigns` and the four
`0011` tables (`report_snapshots`, `idempotency_keys`, `ml_batches`,
`ml_datasets`) carry the same RLS policy and trigger pair as the other scoped
tables, see [multi-tenancy.md](multi-tenancy.md). Bundled model targets are per project
(`Target.id` is `<bundled_id>-<8 hex>`, `Target.value` is
`bundled:<bundled_id>`), so two projects can register the same bundled model
independently.

## Accepted divergences

Each row is a knowing departure from the vertical's original design text.
The tree follows the right-hand column, and the design is not silently
reinterpreted elsewhere.

| Design said | Tree does | Why |
|---|---|---|
| one Celery job per attack in declared order, then `explain.run`, then `harden.recommend`, chained | one `attack.run` job runs the whole campaign in one sandbox child. `explain.run` and `harden.recommend` are follow-up child campaigns admitted from a finding | one child keeps one seeded slice, one model load and one envelope per campaign, and the stage table and the per-attack `attack.execute.<id>` rows preserve the per-attack visibility |
| task names `redsim.attack_run`, `redsim.explain_run`, `redsim.harden_recommend`, `redsim.model_validate` | `redsim.ml_campaign_run` and `redsim.ml_model_validate` (both on the `scans` queue), while `Job.type` keeps the vocabulary `attack.run`, `explain.run`, `harden.recommend`, `model.validate` | follows from the single-job orchestration |
| report artifact kinds `report.md`, `report.json`, `report.html` | the sink writes exactly those kinds, and the earlier `ml.report_<ext>` rows written by the previous sink are still read by the report route | backward compatibility with runs recorded before the current sink |
| `harden.execute` carries `prompt_tokens` and `completion_tokens` | `usage.prompt` and `usage.completion` | `redact_audit_detail` blanks any key containing `token`, so under those names the counts would never reach the chain |
| worker rows use the admitting principal as actor | actor `worker:<job.type>` with the requesting principal in `detail.requested_by` | the row records who executed and who asked, separately |
| the verify loop (verify campaigns, the finding validation state, the defense catalog, the measured delta) | removed on 2026-09-09 rather than built (migration `0012_remove_verify_paradigm`): every run is a measurement in its own right, findings close by reviewer decision (`resolve` on a `confirmed` finding sets `fixed`), recommendations stay text-only candidates | a second measurement is a separate campaign, so no finding state and no gain figure depends on one |
| the error-code table is complete | operational codes outside the table (`ml_catalog_unavailable`, `campaign_not_found`, the two digest-mismatch codes, the reviewer-notes codes) | import failures and evidence-integrity failures have no admission row in the table, so they are named rather than folded into a wrong code |
| contract name `redsim-predict-proba/1`, request body with an `encoding` key | `endpoint-v1`, body `{contract, input_format, inputs}` | the shorter name; the `endpoint_schema_mismatch` row names `endpoint-v1` |
| `query_budget_exceeded` at 422, `idempotency_key_reused` at 422 with an `idempotency_in_flight` code, `fixture_not_exportable` at 409 | `query_budget_exceeded` 429, `idempotency_key_reused` 409, `idempotency_conflict`, `fixture_not_exportable` 422 | a budget refusal sits with `daily_budget_exceeded`; a reused key and an exportability rule are conflicts and validation failures respectively |
| one independence refusal | the dismissal route keeps its plain-string `forbidden`; the review decisions emit the structured `reviewer_not_independent` with `relation` | byte-compatibility for the older route, a structured code for the new ones |
| `map_50` and `n_gt_boxes` as the detection metric names | `DetectionMetrics(n_boxes, n_matched, map50, recall, suppression_rate)` | `CurvePoint` gained no `map_50` (it lives in the curve JSON) |
| a separate image HopSkipJump adapter | the one `hopskipjump` adapter serves images with `IMAGE_DEFAULTS` and both modality tags, `phase: "A"` | one adapter, one denominator convention; the measured budgets are on this page |
| KernelSHAP for black-box image targets | not built; `PartitionExplainer` stays the black-box image explainer, `KernelExplainer` serves predict-only tabular targets | about 100k predict calls per 3x128x128 sample does not fit the sandbox budget; the reason is recorded in `redsim/ml/explain/base.py` |
| connection pinned to the resolved address | the broker resolves, classifies and refuses, but does not pin the connection; recorded in `BrokerStats.egress_notes` | the httpx pinned-connect transport is follow-up work; redirects are disabled and the resolve-once session pin exists in `endpoint_egress` |
| DNS-TXT ownership verification for endpoint targets | not built; egress allowlist plus admin-only registration plus the audited attestation | the ownership engine was removed with the pentest domain |
| a configured Foundry URL is the switch | the URL plus the operator attestation `REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL=1`, else the roster reads `misconfigured` and the push is `501 integration_disabled` | the operator has to attest that the instance is non-operational, and the variable makes the attestation checkable. Drop it if the owner prefers the bare URL switch |
| the export carries clean, adversarial and control rows with true, clean and adversarial labels and confidences | met for every runner (the runners write the same self-describing slices through `runners/base.py::slice_bytes`); the export schema gained a nullable `text` column that only a text slice fills, and a detection export's `flipped` column comes from the flip matrix because a detector predicts boxes, not one label | nothing is fabricated at export time and the card says which families the source run retained; a text model has no numeric input tensor, so `input` is null on its rows |
| bulk upload refused whole on any bad file | per-file admission with collected refusals: `201` all validating, `207` mixed, `422 batch_member_refused` only when every file was refused | the single-upload boundary and its audit row run per file; a mixed answer is more truthful than refusing admitted files after the fact |
| `mlcroissant` as the manifest library | a pure-Python manifest builder and validator (`redsim/ml/interop/croissant.py`); `mlcroissant` stays blocked in the API-process tripwire and is not imported anywhere | the API process must not import it, the worker needs only the JSON-LD shape, and the structural gate also enforces the bare-score bans a generic validator would not |
| a schema field for the batch a run was admitted in | an overlay on `GET /v1/runs/{id}/campaign` from `ml_campaigns.batch_id`, `null` for a single-run admission | no frozen-schema change for a projection the record does not need |
| every report format at completion | the completion path renders `md`, `json`, `html` and `pdf` and records the first snapshot; a PDF the renderer cannot typeset degrades to the text formats with `pdf_unavailable` on the `report.render` row and the job completes | a projection never fails the evidence job and nothing empty is written; the on-demand render still raises on such a record (open item) |

## Open items

The README section "Open items and not implemented" is the single list. In
short: the web UI wiring against a running stack and the browser e2e; the
defects the e2e files name by attribution (the unscaled endpoint probe, the
worker-parent consumed-slice call, `architecture_kwargs` for `state_dict`
uploads, the PDF `LayoutError`, the recorded endpoint seams, the typed
transport-failure mapping, the `atlas_technique_id` list key, the dataset
push to Foundry); the pending owner review of the military-assets subset; and
the recorded non-builds (`adv_patch`, KernelSHAP for images, a detection
explainer, the DNS-TXT ownership check, the pickle override, HarmBench and the
other excluded garak probes, an LLM narrative for probe results, Lattice as
text only, the `reviewer` role, the UNSW-NB15 fallback, `text` and `detection`
consumed slices).

## Gateway-blocked probe outputs

A gateway content-filter refusal is an unevaluated output, counted in the
probe row's `n_outputs_blocked` and the usage ledger's `gateway_blocked`.
It is excluded from detector denominators. Ordinary authentication and
permission failures still abort the probe. When the target is not declared
`content_filtered`, the scorecard adds: "The gateway blocked N prompts before
the model saw them, so hit rates are over the prompts that reached the model."
These counts do not enter the MRI.
