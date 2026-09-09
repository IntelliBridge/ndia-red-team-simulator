# Phase B plan (2026-09-09)

Execution plan for everything the spec defers to Phase B, plus the owner's bulk
operations requirement. It is derived from the nine-scope register in
`docs/plans/11-phase-b-register-2026-09-09.md` (309 items: 205 missing, 65
partial, 21 owner decisions, 5 infeasible, 13 done), audited against `main` at
`10650da`. The web UI is the only deferral. Infrastructure completion and the
data-poisoning module are executed through `docs/plans/10-remaining-work-brief.md`
(packages E and F), not through these waves; its section H is the coordination
contract between the two efforts.

Each wave below is one workflow run: parallel writer tracks with disjoint file
ownership, then one assemble step that runs ruff, mypy, the default, `ml`,
`garak` and `e2e` tiers, `mkdocs build --strict`, the web typecheck and vitest
(untouched by these waves), commits one commit per track and pushes to `main`.
There are no separate verify or fix stages. Items are cited by register id.

## 1. Ground rules

- `redsim/ml/schema.py` is P0-frozen. Every Phase B field lands in the single
  schema-additive track of wave B0, additive and default-valued, announced in
  `docs/plans/00-master-plan.md` under the plan-01 section 8 protocol, and
  guarded by the schema-compatibility tripwire (`TESTS_DOCS-40`): the frozen
  `tests/ml/fixtures/run_record.json` must validate byte-identical afterwards.
- Nothing unimplemented is faked. Every new route is mounted as
  `501 not_implemented` with a reason in wave B0 and replaced by its
  implementation in a later wave, so the tree is truthful at every push.
- The MRI never aggregates across modalities. LLM probe results and detection
  runs never enter an MRI; each gets its own record with k/n denominators.
- Pythia is the only LLM transport; garak's OpenAI-compatible generator points
  at it. No provider key, no litellm code path, even though garak installs it.
- Model bytes, inference calls and dataset parsing happen only in the sandbox
  child or the worker parent, never in the API process
  (`tests/test_api_process_has_no_ml.py` extends to every new module).
- Datasets are open, licensed and published to
  `https://github.com/IntelliBridge/ai-red-teaming-data` with an `INDEX.csv`
  row before the modality that needs them lands.
- CI stays green on both unit lanes; new heavy tests carry `ml` or `garak`.

## 2. Owner decisions

Each row names the recommended default. Code is planned only for the default;
the alternative is recorded here so the owner can overrule.

| Id | Decision | Recommended default |
|---|---|---|
| ENDPOINT-26 | Target-ownership verification (DNS TXT) for endpoint targets: the engine was removed with the pentest domain. | Accept egress allowlist + admin-only registration + audited attestation; record the divergence from spec 21.7. |
| LLM-08 | HarmBench subset as probe material (spec 11.6 names it). | Exclude: garak 0.16 reaches it only through a probe that needs a red-team LLM and a model-as-judge. |
| LLM-26 | A separate Pythia persona and key for probe traffic, declared as `guardrail_mode` on the target. | Yes: probe traffic must not share the narrative writer's key or persona. |
| MODALITIES-12 | Publish a copy of the UCI SMS Spam Collection (CC BY 4.0) to the public data repository. | Yes, with attribution row and eval split. |
| MODALITIES-27 | Detection dataset: Kaggle `rawsi18/military-assets-dataset-12-classes-yolo8-format` (CC BY 4.0, 4.19 GB). The owner declined this set once on 2026-09-08. | Use a capped, seeded subset (a few hundred images, 3 to 4 classes) published as a derived slice with attribution; the owner confirms or names another open detection set before wave B1. |
| MODALITIES-36 | Detection MRI is not computable by construction (no `S_conf`, no `S_expl`). | Accept: detection campaigns carry a detection scorecard, never an MRI. |
| REVIEW_REPORTS-13 | A non-ranked `reviewer` role (read plus approve, cannot run campaigns). | Defer; the `approver` role covers dismissal and confirmation. |
| REVIEW_REPORTS-33 | Pickle trust override. | Do not build; pickles stay refused. |
| REVIEW_REPORTS-35, -36, -41, -42 | F001 membership administration and invitations; F008 retention purge and governance policy versions. | Defer to the platform team; keep `501` with reason. |
| INTEROP-26 | The B2 exit check requires a real Foundry push. | Test against the fake endpoint; a real push needs an operator-configured non-operational Foundry instance and the owner's confirmation. |
| INTEROP-27, TESTS_DOCS-41 | Anduril Lattice push. | Text only under the D3 bound; no code. |
| INTEROP-30 | B2 deployment posture (S3 prefix for exports, HTTPS egress from the default pool). | Runbook item for the infrastructure package of the brief. |
| INTEROP-34 | Redistribution of imagery adversarial-dataset exports. | Tabular exports only to the public repository; imagery exports stay in the artifacts bucket until a reviewer confirms redistribution. |
| BULK-16 | Bulk verify: N linked verify runs, or one defended run projected onto N findings. | One defended run per (baseline, defense, params) projected onto every selected finding; N times cheaper and equally honest. |
| TESTS_DOCS-33 | The public repository already publishes garak's `data/` directory while spec 11.6 says the tool redistributes none of it. | Update the spec and brief wording to the owner's 2026-09-08 decision to publish, with the licence note per subset. |

## 3. Schema additions (one track, wave B0)

All default-valued; announced in the master plan before the PR that adds them.

- `Domain` and `Modality` gain `text` and `detection`; `Norm` gains `edit` and
  `patch_area` (MODALITIES-01, -02).
- `Measurement.edit_fraction_mean: float | None`, `Measurement.detection:
  DetectionMetrics | None` (MODALITIES-03).
- `Observation.text: TextObservation | None`, `Observation.detection:
  DetectionObservation | None` (MODALITIES-04).
- `MLModelManifest.text`, `.detection`, `.endpoint: EndpointSpec | None`,
  `.derived_from: DerivedFrom | None` (MODALITIES-05, ENDPOINT-03,
  ATTACKS_HARDEN-15).
- `ReviewState` widened with `draft`, `in_review`, `confirmed`, `resolved`;
  review history and revisions; `MLFindingDetail.retests: list[FindingVerify]`
  with `settings_hash` and `baseline_run_id` on `FindingVerify`
  (REVIEW_REPORTS-01, -08).
- `CampaignRecord.schema_version: str = "campaign-record-1"`
  (REVIEW_REPORTS-18).
- `RunSummary.kind` and `RunSummary.probe_ids` (LLM-24, optional).
- `STAGES` gains `defense_apply` (ATTACKS_HARDEN-15).
- No change for bulk (batch id is overlaid on the response, BULK-02) or for
  interop (INTEROP-35).

## 4. Datasets and external data

| Dataset | Use | Licence | Size | Public-repo path |
|---|---|---|---|---|
| UCI SMS Spam Collection (Almeida and Hidalgo) | text classifier, bundled `sms_tfidf_lr` | CC BY 4.0 | 5,574 messages, 203 KB | `data/sms_spam_collection.tsv` + eval split (MODALITIES-11, -12) |
| WordNet 3.0 (nltk_data) | synonym set for the word-substitution attack, fetched at build time | WordNet licence, recorded | small | not republished; digest recorded in the asset manifest |
| Kaggle `rawsi18/military-assets-dataset-12-classes-yolo8-format` | detection, capped seeded subset | CC BY 4.0 | subset of a 4.19 GB set | `data/military_assets_subset/` with attribution (MODALITIES-27, owner confirms) |
| military_vehicles training slice | adversarial training inside the sandbox child | MIT (already published) | capped, seeded | no new publication (ATTACKS_HARDEN-11) |
| MITRE ATLAS release data | technique ids and names | Apache 2.0 | one JSON | vendored constant with the pinned release (INTEROP-19) |
| garak 0.16.0 corpora | probe material, loaded by garak itself | per subset | already published | reference entry only (LLM-27, TESTS_DOCS-33) |
| Tabular adversarial export sample | contribute proof | CC0 derived | small | `data/exports/url_trees_sample/` (INTEROP-33) |

## 5. Waves

### Wave B0: contracts, tripwires, stubs, datasets

Status (2026-09-09): landed on `main` at `29db42c` (seven track commits `934838e`, `a625583`, `7b1f2fa`, `3cd3362`, `0b0981b`, `ff9e658`, `622d741` plus the integration commit `29db42c`; 2081 passed, 35 skipped in the default tier and 22 e2e passed at that commit). Open items carried to B1 to B4 are recorded in `docs/plans/00-master-plan.md` section 4.1.

Goal: land every frozen-contract change once, make the tree truthful about
Phase B with `501` stubs, and acquire the data, so every later wave builds on
landed fields.

| Track | Items | Files owned | Brief |
|---|---|---|---|
| schema-additive | MODALITIES-01..05, -44; ENDPOINT-03; REVIEW_REPORTS-01, -08, -18; ATTACKS_HARDEN-15; LLM-24 | `redsim/ml/schema.py`, `tests/ml/test_schema.py`, `docs/plans/00-master-plan.md` (section 0 and 5 announcements only) | Add the section 3 fields, all default-valued; round-trip tests; the frozen fixture unchanged. |
| tripwires-and-ci | TESTS_DOCS-40, -17, -01, -04, -02 | `tests/ml/test_schema_compat.py`, `tests/ml/fixtures/run_record_phase_b.json`, `tests/test_api_process_has_no_ml.py`, `pyproject.toml` (markers, `garak` extra pin), `.github/workflows/redsim-ci.yml` (`e2e-python`, `garak-offline` jobs), `docs/dev/ci.md` | Schema-compat test with a sha256 constant on the P0 fixture; blocked-module and child-env lists extended; `garak` marker; a CI job that runs the existing e2e tier. |
| migration-0011 | REVIEW_REPORTS-44; BULK-01, -20; INTEROP-14 | `redsim/db/migrations/versions/0011_phase_b_platform.py`, `redsim/db/models.py`, `tests/test_migration_0011.py`, `tests/test_tenant_rls.py` | One additive migration: `report_snapshots`, `idempotency_keys`, `projects.ml_scoring`, `ml_campaigns.batch_id`, `ml_batches`, project capacity columns, `ml_datasets`, each with 0010's RLS parity; heads test updated. |
| actions-and-codes | INTEROP-02, -03; LLM-25; ENDPOINT-06; BULK codes and actions; REVIEW_REPORTS codes; `Action.DATASET_REGISTER`, `INTEGRATION_PUSH`, `LLM_PROBE_RUN`, `BATCH_RUN` | `redsim/api/policy.py`, `deploy/opa/redsim-authz.rego`, `deploy/cedar/redsim-policy.cedar`, `redsim/api/errors.py`, the spec section 17.3 table (addendum), `tests/test_policy_ml_actions.py`, `tests/ml/test_error_codes.py` | Every Phase B action and error code in one place; the three policy files change together; the error-code test parses the spec, so the spec addendum is part of the track. |
| route-stubs | INTEROP-01; the batches, probes, poisoning-free stub set | `redsim/api/v1/{batches,llm,integrations}.py` (new, stubs), `redsim/api/v1/datasets.py` (export and consume stubs), `redsim/api/app.py` (`include_router` lines), `tests/ml/test_phase_b_stubs.py` | Mount every new route as `501 not_implemented` behind its gate with the reason and `phase`; `docs/api/v1.md` rows say so. |
| datasets | MODALITIES-11, -12, -27 (subset), ATTACKS_HARDEN-11, INTEROP-19, LLM-27, TESTS_DOCS-33, -35 | `redsim/ml/assets/datasets.py`, `redsim/ml/assets/fixture_sample.py`, `redsim/ml/atlas_data.py`, `tests/ml/fixtures/public_index.csv`, `tests/ml/test_datasets.py`, the public data repository clone | Download, licence check, redaction where needed, `INDEX.csv` rows and `MANIFEST.json` in the public repository, loaders behind pinned revisions, the training slice, the ATLAS constant, the garak reference entry and the spec 11.6 wording fix. |
| endpoint-contracts | ENDPOINT-02, -07 | `redsim/ml/targets/endpoint_contract.py`, `redsim/ml/endpoint_egress.py`, `tests/ml/test_endpoint_contract.py` | Pure-Python request/response contract and egress policy (allowlist, private-address blocking, no userinfo or query) so the API stays ML-free. |

Gate: default and `ml` tiers green; `tests/ml/test_schema_compat.py` passes
with the P0 fixture unchanged; the new CI jobs run on the push; every stub
answers 501 with a reason.

### Wave B1: runners, targets, attacks, hardening (library layer)

Status (2026-09-09): landed. Seven track commits plus the integration commit (`refactor(ml): split run_campaign into a frame plus modality runners` through `fix: integrate Phase B wave B1 tracks`), written in an isolated worktree in parallel with B0, rebased onto `29db42c` and pushed to `main` with this documentation pass; the B0 reconciliation list (schema literals, contract imports, hardening hooks, registration wiring) is closed in the integration commit. `adv_patch` (MODALITIES-32) is recorded as not built. The B1 gate's offline CLI runs (`redsim ml attack sms_tfidf_lr` and against the detector) need the `--dataset text` / `--dataset detection` builds that the integration commit wires into `redsim ml build-assets`.

Depends on B0.

| Track | Items | Files owned | Brief |
|---|---|---|---|
| runner-refactor | MODALITIES-09, -10; ATTACKS_HARDEN-06 | `redsim/ml/campaign.py`, `redsim/ml/runners/{base,classification}.py`, `tests/ml/test_campaign_golden.py`, `tests/ml/test_campaign.py` | Split `run_campaign` into a shared frame plus a `ModalityRunner`; classification byte-for-byte (golden-record test); stage vocabulary, `not_run` and partial semantics unchanged; hooks named `run_text`, `run_detection`, `apply_training_defense` for sibling tracks; child env pins `NLTK_DATA`, `TORCH_HOME` offline. |
| text-modality | MODALITIES-13..26 | `redsim/ml/targets/text.py`, `redsim/ml/attacks/word_substitution.py`, `redsim/ml/explain/shap_text.py`, `redsim/ml/datasets/sms_spam.py`, `redsim/ml/assets/train_text_classifier.py`, `redsim/ml/runners/text.py`, `tests/ml/fakes_text.py`, `tests/ml/test_text_modality.py` | TF-IDF plus logistic regression bundled model; TextFooler-style greedy word substitution with WordNet synonyms, query-counted, deviations stated; random-swap control at the same edit budget; edit grid {0.1, 0.2, 0.3}; SHAP text attributions; `build-assets --dataset text`. |
| detection-modality | MODALITIES-28..43 | `redsim/ml/targets/detection.py`, `redsim/ml/attacks/dpatch.py`, `redsim/ml/datasets/military_assets.py`, `redsim/ml/assets/train_detector.py`, `redsim/ml/runners/detection.py`, `tests/ml/fakes_detection.py`, `tests/ml/test_detection_modality.py` | Small torchvision detector fine-tuned on the capped subset; ART DPatch with a patch-area budget; random-patch control; mAP and matched-box measurements with denominators; `ExplainerUnavailable` recorded honestly; detection scorecard, never an MRI. |
| attacks | ATTACKS_HARDEN-01..05, -22 | `redsim/ml/attacks/{cw_l2,deepfool,zoo}.py`, `redsim/ml/attacks/hopskipjump.py`, `redsim/ml/attacks/registry.py`, `redsim/ml/attacks/__init__.py`, `tests/ml/test_attacks_phase_b.py` | Carlini-Wagner L2 and DeepFool (image, white-box, L2 grid), ZOO (tabular, score-based, frozen features re-imposed), `norms` attribute and `norm:*` tags, image HopSkipJump defaults on the real ResNet-18. |
| explain-blackbox | ATTACKS_HARDEN-07, -09; ENDPOINT-14 | `redsim/ml/explain/shap_tabular.py`, `redsim/ml/explain/base.py`, `tests/ml/test_explain_blackbox.py` | KernelExplainer for predict-only tabular targets with a seeded 100-row background and an explicit explainer choice; explainer caps for endpoint targets; the image KernelSHAP decision recorded, not built. |
| endpoint-target | ENDPOINT-04, -05, -08, -09 | `redsim/ml/targets/endpoint.py`, `redsim/ml/endpoint_broker.py`, `redsim/ml/sandbox.py` (socket plumbing only), `redsim/ml/sandbox_worker.py` (socket client only), `tests/ml/test_endpoint_target.py`, `tests/ml/tiny_endpoint_server.py` | `EndpointTarget` over ART `BlackBoxClassifier`; the only outbound HTTP in a worker-parent `PredictBroker` reached from the child over a unix socket in the 0700 work dir; query counts, rate limits and budgets on every row; probe as the endpoint variant of validate. |
| hardening | ATTACKS_HARDEN-10, -12, -14 | `redsim/ml/harden/{apply,adversarial_training,distillation}.py`, `redsim/ml/defenses.py`, `tests/ml/test_hardening.py` | Adversarial fine-tuning with ART `AdversarialTrainer` at the reference eps and a native torch distillation as the `defense_apply` stage inside the verify child, bounded epochs and wall budget, backbone frozen by default; `kind: training` rows in the defenses catalog; the tabular tree-ensemble case recorded infeasible. |

Gate: `ml` tier green including `TinyTextTarget`, `TinyDetector`, the tiny
endpoint server and the golden-record test; `redsim ml attack sms_tfidf_lr`
and `redsim ml attack <detector>` complete offline.

### Wave B2: services, workers and routes for B1

Status (2026-09-09): landed. Eight track commits plus the integration commit (`api: add thirteen Phase B error codes; dataset.export to remediator`, `feat(ml): endpoint registration, validate via broker, projections`, `worker: endpoint broker lifecycle, derived-target registration, retests (Phase B B2)`, `admission(ml): modality table, norm checks, endpoint budget, project scoring`, `ml(llm): garak through Pythia core: catalog, generator, probe child, scorecard`, `feat(llm): probe routes, admission, worker, scorecard and findings`, `review: transition table, resolve gates, retest links, analyst drafts`, `reports: PDF projection, snapshots, N-run compare, weights API, idempotency`, `fix: integrate Phase B wave B2 tracks`), written in a worktree whose base predates the B1 integration, rebased onto `1439f92` and pushed to `main` with this documentation pass. The eighth track, `codes-b2` (the first commit above, not in the table below), added the 13 codes the register named and B0 left out and moved `dataset.export` to `remediator`. Five of the B0 stubs are real handlers (`GET /v1/llm/probes`, `POST /v1/models/{id}/probes`, `GET /v1/runs/{id}/llm-scorecard`, `POST /v1/runs/{id}/report.render`, `GET /v1/runs/{id}/snapshots`) and eleven new paths exist (N-run compare, snapshot detail, archive and restore, the ml-scoring pair, the review decisions, retests and analyst drafts). Checks before the rebase: ruff and mypy (236 files) clean, 251 passed and 1 xfailed in the writers' ten test files, the default tier 2431 passed with 17 failures all present at the base and fixed on `main` by the B1 integration, the 11 `garak`-marked tests green against the fake gateway. The B2 integration pass re-ran every tier on the rebased tree (default 2480 passed, 35 skipped; `ml` 420 passed, 1 skipped; garak 12; e2e 22; mypy 236 files; ruff clean). The gate below is met for the `ml` and `garak` tiers only: the `e2e` items (an endpoint campaign through the broker against the tiny server, a probe run against the fake server, a training verify registering a derived target) are proven by unit tests in `tests/ml/` and wait for the wave B4 e2e files. Open after B2, carried in the README's "Wave B2 follow-ups": the capabilities roster and the attacks filter not updated, the campaign completion path writing three formats and no snapshot row, `auth_profile_in_use` not emitted, the codes off the 17.3 table (`attestation_required`, `scoring_weights_invalid`, the LLM-12 set), `FindingType` without `adversarial_llm` / `adversarial_ml_manual`, ENDPOINT-30, and the CLI items (`redsim ml attack` matrix and endpoint targets on the CLI; text and detection targets run offline since the integration, which taught the adapter the `edit` and `patch_area` norms).

Depends on B1.

| Track | Items | Files owned | Brief |
|---|---|---|---|
| endpoint-admission | ENDPOINT-01, -10, -11, -15, -17..20, -27, -29, -30 | `redsim/api/v1/models.py` (endpoint branch), `redsim/services/ml_models.py`, `redsim/workers/tasks/ml_model.py`, `tests/ml/test_endpoint_routes.py` | Registration at admin with static checks and audited refusals; validate through the broker; projections, delete, redaction, failure semantics, response fingerprint; white-box attacks refused with `attack_requires_gradients`. |
| worker-campaign-phase-b | ENDPOINT-05 lifecycle, ATTACKS_HARDEN-13, -18, MODALITIES artifact kinds, INTEROP-04 | `redsim/workers/tasks/ml_campaign.py`, `tests/ml/test_tasks_phase_b.py` | Broker start and stop around the child; text and detection artifact kinds in the sink; per-sample keys and clean and control slices persisted for export; derived hardened model registered as a new Target with `derived_from` lineage through validate. |
| admission-phase-b | MODALITIES-06..08; ATTACKS_HARDEN-03; REVIEW_REPORTS-29 | `redsim/services/ml_campaigns.py`, `tests/ml/test_admission_phase_b.py` | `SUPPORTED_MODALITIES`, norm-to-modality check, per-modality default grids, detection `n_samples` cap, the project scoring override applied at admission. |
| llm-core | LLM-01..02, -04..07, -09..14, -16..23 | `redsim/ml/llm/*` (new package), `tests/ml/test_llm_core.py`, `tests/ml/fake_openai_server.py` | Committed catalog of entitled models, `PythiaGenerator(OpenAICompatible)` with persona header and truststore TLS, garak run in a fresh credential-minimised subprocess with `--config`, the offline `redsim-core` probe set, `LLMProbeScorecard` k/n per probe family with a validator that forbids MRI keys. |
| llm-api | LLM-03, -15, -25 usage, -28..33 | `redsim/api/v1/llm.py`, `redsim/services/ml_llm.py`, `redsim/workers/tasks/ml_llm.py`, `redsim/ml/reporting.py` (LLM section only), `tests/ml/test_llm_routes.py` | LLM target registration (`endpoint_kind=llm`, probe key from an AuthProfile), `POST /v1/models/{id}/probes`, `GET /v1/llm/probes`, `GET /v1/runs/{id}/llm-scorecard`, one task on the default queue, findings with hit-rate severity labelled as such, report section, refused by `/campaign` and `/compare`. |
| review-workflow | REVIEW_REPORTS-02..07, -09, -11, -12, then -05 | `redsim/services/finding_review.py`, `redsim/api/v1/ml_findings.py`, `redsim/services/ml_findings.py` (read side), `tests/ml/test_review_workflow.py` | Transition table over the widened states without inventing a `Finding.status`; confirm, reopen, request changes, resolve gated on `poc_passed`, equal `settings_hash` and an independent reviewer; retest links; analyst drafts last. |
| reports-compare-weights | REVIEW_REPORTS-15..17, -19..22, -26, -28, -30, idempotency keys | `redsim/ml/pdf.py`, `redsim/ml/compare.py`, `redsim/services/reports.py`, `redsim/api/v1/reports.py`, `redsim/api/v1/compare.py`, `redsim/api/v1/projects.py`, `redsim/api/middleware/idempotency.py`, `tests/ml/test_reports_phase_b.py` | PDF as a third projection of `CampaignRecord` through reportlab with bundled fonts; snapshots as immutable rows over content-addressed artifacts; N-run comparison with no mean or rank; per-project weights API that never renormalises; `Idempotency-Key` on mutating routes. |

Gate: `ml`, `garak` and `e2e` tiers green; an LLM probe run against the fake
OpenAI-compatible server yields a scorecard with denominators and no MRI; an
endpoint campaign against the tiny server completes through the broker; a
verify run with adversarial training registers a derived target.

### Wave B3: interoperability and bulk

Status (2026-09-09): landed. Five track commits plus the integration commit (`feat(interop): Croissant/Parquet dataset export of a campaign run`, `interop(consume): POST /v1/datasets static admission, sandboxed Parquet parse, binding hook`, `bulk: batch campaigns, roll-up, cancel, compare groups, bulk verify`, `feat(ml): bulk upload, per-project capacity/deferral, CLI attack matrix`, `interop(atlas,foundry): ATLAS stamp and coverage, Foundry push, roster`, `fix: integrate Phase B wave B3 tracks`), written in a worktree on the B2 integration, rebased onto it and pushed to `main` with this documentation pass. Every one of the 14 remaining B0 stubs is a real handler; the integration commit added the three B3 task modules to the Celery `include` list, removed the B0 export stub from `integrations.py` (the datasets router serves the path) and rewrote `tests/ml/test_phase_b_stubs.py` as the Phase B surface pin (61 cases, never `501 not_implemented`). No frozen contract, error code, `Action` or migration changed. The public data repository gained the first export sample built with the new modules (`data/exports/url_trees_sample/` at `0dababc`, INTEROP-33). The B3 assembler's checks in its worktree: ruff and `mypy redsim` (253 files) clean, the six writers' test files 140 passed and 1 skipped, the surface pin 61 passed, the e2e smoke file 8 passed; final counts at the B3 integration on the rebased tree (the reconcile pass): ruff and `mypy redsim` (253 files) clean, the default tier 2634 passed and 35 skipped (the `test_campaign_golden` artifact pin excludes the Phase B export slices, `test_cli_ml` pins the `l2` default `pgd`), the `ml` tier 433 passed and 1 skipped, the `garak` tier 12 passed, the `e2e` tier 22 passed, `mkdocs build --strict` exit 0. Partial inside the tracks' file sets and carried to B4 or the README's open items: INTEROP-04 (closed for the classification runner in the reconcile pass: self-describing clean, adversarial and control slices with the prediction keys; the text and detection runners still persist their own formats), INTEROP-07 (regenerate-in-child: `export_unavailable` instead), INTEROP-16 (the campaign admission binds an available consumed slice since the reconcile pass; the upload and worker-loader hooks are not called), INTEROP-17 (docs only, in `docs/interop.md`), INTEROP-18 (the finding list `atlas_technique_id` key), INTEROP-23 second half (the dataset push), INTEROP-26 (a real non-operational Foundry instance; the push is proven against the fake server), INTEROP-28 (the JWT pattern in `redsim/audit/redact.py`; the B3 rows are scrubbed before any writer), INTEROP-29 (the capabilities interop block, `.env.example` and compose pass-through), INTEROP-31 (the export-side invariants beyond the manifest validator), BULK-02 (the `batch_id` overlay on `GET /v1/runs/{id}/campaign`), BULK-09 (the continuation call at the end of `ml_campaign_run` landed in the reconcile pass via `deferred_continuation`; the single-run admissions under the caps; the 60 s beat backstop moves deferred members), BULK-15 / -16 (the worker projection onto `finding_ids`; admission per the owner decision), BULK-25 (the batch LLM-budget interplay), and the single-run admissions do not consult the capacity caps. The gate below is met for the `ml` tier only (`tests/ml/` proves each criterion in isolation); the `e2e` round trip waits for the wave B4 files. The table's file ownership for BULK-14 and BULK-17..19 was the `bulk-upload-capacity-cli` track's in practice (`redsim/cli/ml.py`, `redsim/api/v1/models_bulk.py`).

Depends on B2.

| Track | Items | Files owned | Brief |
|---|---|---|---|
| interop-contribute | INTEROP-05..12 | `redsim/ml/interop/{croissant,parquet,card}.py`, `redsim/workers/tasks/dataset_export.py`, `redsim/services/ml_datasets_export.py`, `tests/ml/test_interop_export.py` | Croissant JSON-LD over Parquet shards per (attack, eps) plus the control family; projection-equality guard; export task on the scans queue writing `datasets/<run-id>/`; generated card; one export per run. |
| interop-consume | INTEROP-13, -15, -16, -17 (docs) | `redsim/api/v1/datasets.py`, `redsim/services/ml_datasets.py`, `redsim/ml/interop/consume.py`, `tests/ml/test_interop_consume.py` | `POST /v1/datasets` with static checks (magic bytes, manifest shape, remote references refused, licence required), parse only in the sandbox child, bind a consumed slice to uploads and campaigns. |
| atlas-foundry | INTEROP-18, -20..25, -28, -29, -31 | `redsim/ml/atlas.py`, `redsim/integrations/foundry.py`, `redsim/workers/tasks/integration_push.py`, `redsim/api/v1/integrations.py`, `redsim/services/ml_findings.py` (ATLAS stamp only), `redsim/api/v1/attacks.py` (ATLAS exposure only), `tests/ml/test_atlas_foundry.py`, `tests/ml/fake_foundry_server.py` | ATLAS technique stamped on findings and exposed on the attack catalog; coverage route with no numeric field; Foundry client with payload validator (no bare MRI, no key, no URL string leaves), push job on the default pool behind an admin gate, off by default; Lattice text only. |
| bulk-service-routes | BULK-03..11, -14, -15 (as decided), -17..19 | `redsim/services/ml_batches.py`, `redsim/api/v1/batches.py`, `redsim/ml/compare.py` (batch grouping only), `tests/ml/test_batches.py` | Batch admission reusing the single-run boundaries (`admit_attack_config`, `batch_id` kwargs), one audit row per run plus one per batch, batch status roll-up, batch compare grouped by comparability with no delta or rank, batch cancel, bulk verify per the owner decision. |
| bulk-upload-capacity-cli | BULK-12, -13, -21..25, -27, -28 | `redsim/api/v1/models_bulk.py`, `redsim/services/ml_capacity.py`, `redsim/workers/tasks/capacity.py`, `redsim/cli/ml.py`, `redsim/observability.py` (gauges), `tests/ml/test_bulk_upload_capacity.py`, `tests/ml/test_cli_matrix.py` | Bulk upload with per-file targets and audit rows and total caps; per-project caps with deferral, daily budget with audited 429, continuation dispatch and beat backstop, `GET /v1/ml/capacity`, filled gauges; `redsim ml attack` matrix from YAML with one chain per run. |

Gate: `e2e` tier green with an export that validates against the Croissant
schema, a consumed slice bound to a campaign, an ATLAS-stamped finding, a fake
Foundry push, and a batch across both bundled models plus an uploaded ONNX.

### Wave B4: end-to-end evidence, gate, documentation

Status (2026-09-09): not started. The documentation items that B0 and B1 made true (TESTS_DOCS-28, -29, -30, the `0011` and public-repository citations, `docs/api/endpoint-contract.md` for ENDPOINT-02) were brought forward into the B1 documentation pass, the B2 items into the B2 pass, and the B3 items (INTEROP-17, INTEROP-32 and BULK-29 as `docs/interop.md` and the route sections of `docs/api/v1.md`, the master plan v2.7 note, the plan-07 status banner) into the B3 pass. Still owed by this wave: the e2e files for everything B2 and B3 built, `make check-phase-b` with the docs-consistency test, the plan-07 rewrite onto the section 27 vocabulary, `EXECUTION-CONTEXT.md`, the spec 22 and 26 addenda and the garak supply-chain paragraph, plus the B3 cross-track hooks listed in the B3 status line where a gate criterion needs one.

Depends on B3.

| Track | Items | Files owned | Brief |
|---|---|---|---|
| e2e-endpoint-llm | TESTS_DOCS-05, -06, LLM-30, ENDPOINT-21..23 | `tests/e2e/test_ml_endpoint.py`, `tests/e2e/test_ml_llm.py` | Endpoint registration to campaign through the broker against the tiny server; LLM probe run against the fake server with scorecard, findings, report and audit chain; RBAC negatives. |
| e2e-modalities-attacks | TESTS_DOCS-08, -09, -10, MODALITIES-47, ATTACKS_HARDEN-21, -23 | `tests/e2e/test_ml_text_detection.py`, `tests/e2e/test_ml_attacks_harden.py` | Text and detection campaigns with their scorecards and the D9 negatives; CW, DeepFool, ZOO runs; adversarial-training verify with a derived target and a measured delta. |
| e2e-review-reports-interop-bulk | TESTS_DOCS-07, -11..16, BULK-26, -30..32 | `tests/e2e/test_ml_review_reports.py`, `tests/e2e/test_ml_interop.py`, `tests/e2e/test_ml_bulk.py`, `tests/e2e/harness.py` (additive helpers only) | Review transitions and independence, PDF bytes and snapshots, N-run compare, Croissant export and consume round trip, Foundry fake push, batch and bulk upload and bulk verify with audit verification. |
| phase-b-gate | TESTS_DOCS-36, -03, -18..23 | `scripts/phase_b_gate.sh`, `Makefile`, `.github/workflows/redsim-ci.yml` (job wiring only), `tests/test_docs_phase_b_consistency.py` | `make check-phase-b` running every tier, mkdocs, the docs-consistency test and the HTTP probes behind `REDSIM_API_URL`; fails on the first miss naming the spec 26 criterion. |
| docs | TESTS_DOCS-24..32, -34, -37, -38, -39; the scope docs items (ENDPOINT-25, LLM-31, MODALITIES-46, ATTACKS_HARDEN-24, REVIEW_REPORTS-43, INTEROP-32, BULK-29) | `docs/plans/00-master-plan.md`, `docs/plans/07-p6-interoperability.md`, `docs/plans/08-p7-infra-cd.md` (banner), `docs/plans/EXECUTION-CONTEXT.md`, `docs/api/v1.md`, `docs/architecture/ml-vertical.md`, `docs/ops/pythia.md`, `docs/security/supply-chain.md`, `SECURITY.md`, `README.md`, `CLAUDE.md`, the spec (22 and 26 addenda, 3.2 and 17.4 status), `docs/interop/*` | One rewrite pass: master plan v2.4 with the waves and the schema announcements, plan 07 onto the section 27 vocabulary, `docs/api/v1.md` regenerated from OpenAPI with an honest status table, README open items shrinking to the UI and the owner decisions, spec 22 and 26 addenda tagged with their decisions, the garak supply-chain paragraph. |

Gate: `make check-phase-b` exits 0 locally against `make up`; CI green on
every lane; `mkdocs build --strict` clean.

## 6. Completion checks

- `ruff check --select E4,E7,E9,F,I redsim tests` and `mypy redsim` clean.
- `pytest -q` (default tier), `pytest -q -m ml`, `pytest -q -m garak` green.
- `REDSIM_E2E=1 pytest -q -m e2e tests/e2e` green, including
  `test_ml_endpoint.py`, `test_ml_llm.py`, `test_ml_text_detection.py`,
  `test_ml_attacks_harden.py`, `test_ml_review_reports.py`,
  `test_ml_interop.py`, `test_ml_bulk.py`; the Postgres lane with
  `REDSIM_E2E_POSTGRES_URL` set.
- `pytest -q tests/ml/test_schema_compat.py`: the P0 fixture unchanged.
- `pytest -q tests/test_docs_phase_b_consistency.py` green;
  `mkdocs build --strict` clean.
- `make check-phase-b` exits 0 against a running stack: capabilities list
  `text`, `detection`, `llm` and the endpoint connector as available;
  `POST /v1/models source=endpoint` is not 501; `report.pdf` starts with
  `%PDF-`; `POST /v1/runs/{id}/dataset` is 202 and the manifest validates;
  a probe run yields a scorecard with denominators and no MRI; a batch of
  two models completes; the Lattice control still answers 501 with its
  reason; `redsim audit verify --all` exits 0.
- `gh run list --branch main --workflow redsim-ci.yml --limit 1` green on
  every job (the Next.js job depends on brief item B5).

## 7. Goal statement

Every Phase A completion criterion that does not depend on the browser UI
still holds on main and is proven by the e2e tier. Phase B is built and proven
the same way. A black-box inference endpoint registers with credentials in an
AuthProfile, is queried only from the worker through an egress allowlist, and
runs HopSkipJump, ZOO and KernelSHAP campaigns. An LLM target carrying a
Pythia model id runs garak probes through the Pythia gateway and reports a
probe scorecard with denominators that never enters an MRI. A bundled text
classifier and a bundled object detector on open licensed datasets run their
own attacks, controls, explanations and scorecards. Carlini-Wagner, DeepFool
and ZOO run with noise controls, and adversarial training and distillation
produce derived model artifacts whose verify loop records a measured delta.
The full finding review states, PDF export, report snapshots, N-run
comparison, per-project scoring weights and idempotency keys work through the
API. A run exports as a Croissant dataset with a content-addressed manifest,
another team's slice can be consumed, findings carry ATLAS techniques with a
coverage view, and the Foundry push is opt-in and off by default while the
Lattice push stays text only. Batch campaigns, bulk uploads and bulk verify
run through the API and a CLI matrix with one audit chain per run. Every new
dataset is published with its licence, every new action is on the hash chain
and redsim audit verify passes, RBAC and RLS cover every new route and table,
unsupported paths return not-implemented with a reason, pytest, ruff and mypy
are green on main with the e2e tier green locally, and the plan and docs match
the tree. The web UI is the only deferral.
