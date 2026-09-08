# ML vertical

Status as of 2026-09-08 (late evening, `main` at `7240220`). This page
describes the adversarial-ML vertical as it stands on `main` and what has
not started. The authoritative design is the
[product spec](../superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md)
and the coordination plan is the [master plan](../plans/00-master-plan.md).
Where this page and the spec disagree, the spec wins and this page is stale.

## What the vertical does

One campaign takes one classifier (a bundled sample or an uploaded ONNX or
PyTorch `state_dict` artifact), one modality (`image` or `tabular`), a
declared attack set, an ε grid and a reference budget. The worker runs the
attacks from the Adversarial Robustness Toolbox (ART) at every ε on one
seeded slice, pairs them with a benign random-noise control, explains
flipped and unflipped samples with SHAP, scores the campaign with the Model
Robustness Index (MRI), derives interpretation and candidate hardening
recommendations from deterministic rules, and optionally rewrites the rule
output into prose through Pythia. A verify campaign re-runs the same
settings with an ART preprocessing defense in front of an evaluation copy
and reports the measured ΔMRI. Nothing is ever applied to the stored model.
The tool is a non-operational proof of concept on open, unclassified public
data.

Platform pieces the vertical reuses unchanged: the FastAPI app and RBAC
([auth](auth.md)), the Celery workers and the job state machine, Postgres
with row-level security ([multi-tenancy](multi-tenancy.md)), the blob store,
the hash-chained audit log ([audit chain](audit-chain.md)), per-task LLM
routing with budgets, and the Pythia transport.

## Where things stand

| Piece | State | Workstream |
|---|---|---|
| Frozen contracts: `redsim/ml/schema.py`, `redsim/ml/targets/base.py`, `redsim/ml/attacks/base.py` | on `main`, frozen by P0 | WS0 |
| Migration `0010_ml_vertical` (`targets.detail` JSONB, `ml_campaigns` with RLS parity) | on `main`. The ORM in `redsim/db/models.py` does not yet map either | WS0 |
| Seven ML `Action` members and the `viewer` rank in `redsim/api/policy.py`, mirrored in the OPA and Cedar bundles | on `main` | WS0 |
| `redsim ml build-assets` CLI | implemented on `main` (merged 2026-09-08 with #9, `1725728`): fetch by pinned revision, CPU training, `assets/MANIFEST.json` | WS0, WS1 assets |
| `redsim/llm/pythia.py` transport, `REDSIM_ML_LLM_MODEL`, `python -m redsim.llm.pythia_check` | on `main`, connectivity verified 2026-09-08 | WS0 |
| Targets, defenses, datasets, ART adapters (`fgsm`, `pgd`, `noise_control`, `hopskipjump`), eval, MRI scoring, campaign runner, SHAP explainers, interpretation and recommendation rules, Pythia narrative | on `main` (PR #8 `feat/ml-core`, merged 2026-09-08 as `ce33d21`). `import redsim.ml.targets, redsim.ml.attacks` registers the targets `cifar10_smallcnn`, `endpoint_stub`, `url_trees`, `vehicles_cnn` and the attacks `fgsm`, `hopskipjump`, `noise_control`, `pgd` | WS1 (pure part), WS2, WS3 |
| `SmallCNN`, `url_features`, the `build-assets` implementation, `MANIFEST.json` | on `main` (PR #9 `feat/ml-assets`, merged 2026-09-08 as `1725728`). The built assets are local and gitignored | WS1 assets |
| Celery tasks `attack.run`, `explain.run`, `harden.recommend`, `model.validate`, the ML branch of `verify.replay`, and the routes `/v1/models`, `/v1/attacks`, `/v1/datasets`, `/v1/defenses`, `/v1/ml/capabilities`, `/v1/runs/{id}/campaign`, `/v1/runs/{id}/artifacts`, `/v1/artifacts/{id}`, `/v1/runs/{id}/compare`, the finding `explain` and `harden` routes | not started | WS4 |
| Web pages `/models`, `/models/[id]`, MRI panels on `/runs/[id]`, three-pane `/findings/[id]` | on `main` (PR #16, merged 2026-09-08 as `1a9204e`, ten review findings fixed before merge). They target the planned WS4 routes, which are not mounted, and show an explicit `not_implemented` state on 404 or 501 | WS5 |
| ECS Fargate deployment | Terraform foundation on `main` under `deploy/terraform/` (PR #19, merged 2026-09-08 as `b40f7e1`): network, ALB and target groups without listeners, RDS, Redis, S3, IAM, mocked-plan tests. No services, nothing applied | WS7 |

The bundled assets have been built locally with
`redsim ml build-assets --dataset all`: `vehicles_cnn` on the military
vehicles set, the `cifar10_smallcnn` fixture, and `url_classifier` (the
asset behind the `url_trees` target) on the full Kaggle malicious-URLs set.
They are gitignored under `assets/`, so a fresh clone builds its own, and
their clean accuracy is recorded in the asset manifest rather than quoted
here. The sandbox child, the Celery tasks and the routes that would run a
campaign from the API are still WS4 work.

## The frozen schema

`redsim/ml/schema.py` is the M0 contract (spec 5.3 to 5.7, 12.5, 13.3, 14,
15 and 16.4). Later milestones add behaviour, not fields. A field change
after the freeze follows the change protocol in the
[P0 plan](../plans/01-p0-contracts-api-skeleton.md) section 8: no silent
renames, announce the change in the master plan, and prefer an additive
default-valued field.

| Model | What it holds |
|---|---|
| `TargetInfo`, `AttackInfo`, `ParamSpec` | Catalog entries. `AttackInfo` is the `GET /v1/attacks` row: `family` (`evasion` or `control`), `phase`, `access`, `requires_gradients`, `status` with `reason`, and a `params_schema` of bounded parameters. |
| `CampaignConfig` | One campaign, immutable after admission: `target_id`, `modality`, `attack_ids`, `attack_params`, `norm` (`linf` or `l2`), `eps_grid` (strictly ascending, each in (0, 1]), `reference_eps` (a member of the grid), `finding_asr_threshold` (0.2), `n_samples` (10 to 1000, default 200), `seed`, `include_control`, `explain_k` (0 to 32), the dataset binding, `scoring`, `defense` (verify only), `llm_narrative`, `auto_recommend`, `target_snapshot`, `attacks`. |
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

## Stages

`STAGES` is the ordered tuple `load_target`, `sample`, `clean_eval`,
`attack`, `control`, `explain`, `score`, `interpret`, `recommend`,
`report`. The worker writes the current stage into `runs.stage_table` as it
progresses, with `attack` written per attack as `attack:<attack_id>`.
`score` runs at the end of the explain stage because `S_expl` needs SHAP. A
verify campaign reuses the same stages with `defense_apply` after
`load_target` and `verify:<defense_id>` for the re-attack (spec 6.5). The
planned task chain is one `attack.run` job per attack in declared order,
then `explain.run`, then `harden.recommend` (spec 10.2 and 10.3). All jobs
are created at admission so each has an audit row before it can run, and a
failed task cancels the remaining queued jobs of its chain.

## MRI

The Model Robustness Index is a 0 to 100 integer computed once per
campaign, meaning one model, one modality, one declared attack set, one ε
grid and one reference budget (spec 15). Its inputs come only from the
run's own `Measurement` and `Observation` rows. Control rows never enter
the score.

Each subscore is on a 0 to 100 scale, the unweighted mean over the
in-scope attacks, with ratios clamped to [0, 1] first:

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

Constraints the schema enforces (`MRIRecord._mri_needs_all_five`) and the
spec requires (15.4 and 15.8):

- An MRI exists only when all five subscores are present and
  `completeness` is `complete`. A partial record carries the available
  subscores and names each missing dimension with its reason. Weights are
  never renormalised over the available dimensions.
- `grade` must equal `grade_for_mri(mri)`: A from 90, B from 75, C from
  60, D from 40, F below. A grade never appears without an MRI.
- `reading` is attack-scoped text and may not contain a banned word
  (`hardened`, `harden before fielding`, `deployment-ready`,
  `not deployment-ready`, `certified`, `safe`, `fielding`).
  `GRADE_STATEMENT` is printed under every grade.
- The record always carries `inputs`, `per_attack`, `subscores`,
  `weights`, `eps_grid`, `reference_eps`, `norm`, `attack_ids`,
  `finding_asr_threshold`, `settings_hash`, `scoring_version` and
  `computed_at`. The UI never renders the number without the subscores,
  the per-family table and the ε curve.
- MRIs are never aggregated, averaged, ranked or compared across
  campaigns. Two campaigns are comparable only when `settings_hash` (sha256
  over the canonical `CampaignConfig` minus `defense`, `llm_narrative` and
  `target_snapshot`, concatenated with the model sha256) and
  `sample_indices_sha256` match.
- ΔMRI exists only on a verify run (`MRIDelta` on a `kind = verify` row),
  always beside the change in clean accuracy, and is the only numeric gain
  the product ever shows. A recommendation carries no expected gain until a
  verify run has measured it (`MeasuredDelta`).

Finding severity is derived from the first-success ε and the ASR, never
hand-set (spec 15.5).

## Evidence separation

A run makes exactly four kinds of statement, kept in separate fields,
separate report sub-objects and separate UI panels (spec 14.1):

| Kind | Type | Label enforced by |
|---|---|---|
| Measurement | `Measurement` | the field set: counts and rates only, `notes` for caveats |
| Observation | `Observation` | `metric_kind: "heuristic"` |
| Interpretation | `Interpretation` | `kind: "inferred"` and a non-empty `basis` |
| Candidate recommendation | `CandidateRecommendation` | `status: "candidate"`, `validation`, `narrative_source` |

Ids are the citation mechanism: `m.<family>[.<attack_id>][.eps<ε>]`,
`o.<index:03d>`, `i.<n>`, `r.<rule_id>`. `RunRecord._no_dangling_citations`
rejects a record whose interpretation `basis` or recommendation
`triggered_by` cites an id that does not exist in the same run. Provenance
and limitations accompany the four in every report and page.
`standing_limitations(dataset_name, eps_grid)` returns the dataset
sentence, the budget sentence and the five standing limitations (SHAP is
sensitivity not cause, the slice is small, white-box gradient attacks
assume full access, recommendations are unvalidated candidates, passing
does not establish safety or readiness). Reviewer notes are a fifth, human
voice under their own heading.

The interpretation rules I1 to I6 (spec 14.6) and the recommendation rules
(spec 16.2) are deterministic, read `InterpretationThresholds`, cite the
ids that fired them and print their thresholds. They are on `main` in
`redsim/ml/recommend/rules.py` since PR #8 merged.

## Datasets and handling rules

Every dataset is open, unclassified, public, and carries a stated license
(spec 11). The demo and fixture sets have been fetched and the bundled
models trained locally by the one-off `redsim ml build-assets` run. Nothing
is committed. The last row is Phase B material that garak ships and loads
itself.

| Role | Dataset | License | Notes |
|---|---|---|---|
| Demo image | `leibnitz-lab/military_vehicles` (HF), coarse 7-class task | MIT for the compilation and labels | Ground-level photographs, not overhead. Photo copyright is not cleared by the MIT tag, so images stay inside the team's blob store. |
| CI image fixture | `uoft-cs/cifar10` (HF), pinned 500-image subset | unknown on the card | Fixture only, never presented as results. |
| Demo tabular | Kaggle `sid321axn/malicious-urls-dataset` | CC0 | The download needs a Kaggle token (`KAGGLE_API_TOKEN`) at build time only. A committed stratified sample under `tests/ml/fixtures/` serves CI. URL strings are data: never fetched, resolved or rendered as links. |
| Tabular fallback | `lacg030175/UNSW-NB15` (HF, config `standard`) | CC-BY-4.0 | Used only if the Kaggle download cannot be completed. |
| Public copies for other teams | [IntelliBridge/ai-red-teaming-data](https://github.com/IntelliBridge/ai-red-teaming-data) (GitHub, public, commit `ff6a36b`): `data/military_vehicles.parquet`, `data/malicious_urls.csv`, `data/malicious_urls_eval_split.csv`, `INDEX.csv`, `MANIFEST.json` | CC BY 4.0 for the repository's own contents, upstream licenses kept per file (MIT, CC0) | No models and no CIFAR-10. The URL CSVs are redacted copies (credential-shaped query values replaced with `REDACTED` in 2,346 of 651,191 rows and 406 of 128,224 in the eval split, row order and labels unchanged), so their hashes differ from the unredacted Kaggle file the local build trains on and metrics re-derived from them differ slightly on those rows (spec 11.7). |
| Phase B LLM-track probe corpora | garak's bundled data under `garak/data` (in-the-wild jailbreak prompts, DAN templates, HarmBench, Do-Not-Answer, RealToxicityPrompts subsets, payload sets) | Apache-2.0 for the garak package. Upstream terms per subset (HarmBench ships its own LICENSE) | Phase B only (spec 11.6): loaded by garak's probe classes and detectors, never extracted or re-packaged, never a classifier dataset, never an MRI input. Prompts are untrusted data and go only to the permission-gate-only Pythia persona. |

Rules that apply to all of them: bytes are fetched once by
`redsim ml build-assets` and written to the blob store under
`ml/assets/<dataset_id>/<revision>/`, read only by the worker. The API and
web containers never hold dataset bytes. `MANIFEST.json` records the id,
the resolved revision, the license, the split, per-class `n`, the
preprocessing and the bundled model's recipe and weight sha256, and is
copied into `Provenance`. The evaluation slice is a seeded stratified
sample whose indices are hashed into `Provenance.sample_indices_sha256`.
Fixture data never populates a Finding or a results page. No dataset row,
image, adversarial example, SHAP array or model parameter ever leaves the
worker.

## Model loading

Accepted upload formats are ONNX and PyTorch `state_dict` (`.pt` or `.pth`
loaded with `weights_only=True`, or `.safetensors`) with an architecture id
from the in-tree catalog. Full pickles are refused with `415 pickle_refused`
and there is no override in Phase A. The API never loads a model: it
streams bytes to the blob store, computes the sha256 and sniffs the magic
bytes. Loading happens only on the worker inside a sandbox child built on
the pattern of `redsim/scanners/sandbox.py` (own process group, POSIX
rlimits, wall-clock kill, an allowlisted environment without secrets or
proxy variables). The `ml` extra (torch, torchvision, onnx, onnxruntime,
scikit-learn, ART, onnx2torch, safetensors, shap, matplotlib) installs only
in the worker image (spec 8.4 and 9).

## Pythia narrative path

The only outbound call the vertical makes is the optional hardening
narrative, from the `harden.recommend` task on the `default` pool (spec
10.8 and 16.3):

1. `redsim.llm.router.route("ml.harden_narrative", ...)` picks the model:
   the organisation override wins, else `REDSIM_ML_LLM_MODEL`. The project
   daily cap and the organisation monthly cap apply through
   `DbBudgetChecker`.
2. `redsim.llm.pythia.chat_text` sends one non-streaming
   `POST {PYTHIA_BASE_URL}/v1/chat/completions` with
   `Authorization: Bearer pk_…` and an optional `X-Pythia-Persona`.
   `PythiaSettings.from_env()` reads the process environment layered over
   `.env`, verifies TLS through the OS trust store (`REDSIM_TLS_TRUSTSTORE`,
   default on) or a PEM bundle (`REDSIM_CA_BUNDLE`, then `SSL_CERT_FILE`),
   and returns `None` when `PYTHIA_BASE_URL`, `PYTHIA_API_KEY` or
   `REDSIM_ML_LLM_MODEL` is missing.
3. The payload is text only: the measurements table with denominators, the
   scorecard numbers, the ranked rule outputs, the SHAP text summary and
   the limitations. `guard_input` and `guard_output` from
   `redsim.llm.guardrails` wrap the call, then a numeric-consistency check
   and a banned-word check run on the response.
4. Any failure (not configured, `REDSIM_DISABLE_LLM=1`, budget exceeded,
   HTTP error, guardrail block, post-check rejection) leaves the rule output
   standing with `narrative_source = "rules"` and the reason recorded. The
   narrative never fails a job and never invents prose.

The prompt and completion are stored as artifacts, their digests go on the
`harden.execute` audit row, and an `LLMUsage` row with
`task = "ml.harden_narrative"` feeds the `/cost` page.
`python -m redsim.llm.pythia_check` exercises the gateway end to end (27
entitled models and one chat completion on 2026-09-08). Operator notes are
in [ops/pythia.md](../ops/pythia.md).

## Audit, roles and tenancy

Every ML mutation is admitted through `redsim.safety.authorize()` before
any `Run` or `Job` row exists and before Celery is touched, and the worker
re-authorises at execution. The planned action vocabulary
(`model.register`, `model.validate`, `attack.run`, `model.load`,
`attack.execute.<attack_id>`, `explain.run`, `explain.execute`,
`campaign.score`, `harden.recommend`, `harden.execute`, `verify.execute`,
`job.complete`, `finding.review`, `finding.annotate`, `report.render`) is
listed in [audit-chain.md](audit-chain.md#planned-ml-events). The seven ML
`Action` members and their minimum roles are in [auth.md](auth.md#rbac).
`ml_campaigns` carries the same RLS policy and trigger pair as the other
scoped tables, see [multi-tenancy.md](multi-tenancy.md).

## Spec index

| Topic | Spec section |
|---|---|
| Domain model and schema | 5.3 to 5.8 |
| Job lifecycle, run status, stages | 6 |
| Roles, access matrix, independence rule | 7 |
| Architecture and package layout | 8 |
| Model loading and the sandbox | 9 |
| Tasks, campaign chain, failure, cancel | 10 |
| Datasets | 11 |
| Attack catalog, ε sweep, control, metrics | 12 |
| Explainability | 13 |
| Evidence model and limitations | 14 |
| MRI | 15 |
| Recommendations and the verify loop | 16 |
| API surface | 17 |
| Web UI | 18 |
| Deployment and environment variables | 20 |
| Security and trust | 21 |
| Milestones | 23 |
