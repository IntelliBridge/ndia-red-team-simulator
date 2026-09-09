# redsim/ml Master Implementation Plan (reconciled)

Status: v2.8, 2026-09-09. Supersedes v1, amends v2 to v2.7. This version is
rebased on the **redsim platform** (the aegis platform kept whole under D1
and renamed to the `redsim` namespace in commit `b39d933`) after the `main`
restructure of 2026-09-08, and records the tree at `703f8f6` (Phase A
complete through wave 4, Phase B waves B0 to B3) plus Phase B wave B4, pushed
with this revision. Phase B is landed through all five waves; what stays open
is listed in the README and tagged in spec 26.7.

## 0. What changed since v1 (read this first)

### v2.8 (2026-09-09): change note, Phase B wave B4

Phase B wave B4, the end-to-end evidence, the gate and the documentation, is
pushed to `main` with this revision: four track commits written in the
worktree `wt/waveb4` on the B3 integration and rebased onto `703f8f6`, then
the fix pass the e2e files demanded (three tracks), then this documentation
pass. By subject:

- `e2e(endpoint,llm): endpoint connector and garak LLM probe evidence on the
  shared harness` (`e2e-endpoint-llm`): `tests/e2e/test_ml_endpoint.py`
  (registration through `POST /v1/models` with a bearer `AuthProfile`, RBAC,
  the `endpoint_url_invalid` and `endpoint_not_allowlisted` refusals,
  validation to `available` with the fingerprint, a HopSkipJump plus control
  campaign through the worker-parent broker with the query tally on the
  record and the audit rows, `422 attack_requires_gradients`, the credential
  in no child file, environment, audit detail or report, `409
  auth_profile_in_use`, the audited delete) and `tests/e2e/test_ml_llm.py`
  (`garak`-marked: the catalog with HarmBench excluded, admin-only LLM
  registration, remediator-only probe runs, one real garak 0.16.0 run against
  the fake gateway with a k/n scorecard carrying no MRI key, findings with
  hit-rate severity labelled so, the probe key in no file or row, `redsim
  audit verify --all`).
- `e2e(text,detection,attacks,harden): modality, norm, ZOO and
  training-defense evidence` (`e2e-modalities-attacks`):
  `tests/e2e/test_ml_text_detection.py` (text and detection campaigns on tiny
  assets built with the real builders, each scorecard its own, detection with
  box denominators and no MRI, the D9 negatives, admission caps) and
  `tests/e2e/test_ml_attacks_harden.py` (norm tags at admission, the L2
  campaign with minimal-norm rows, ZOO's frozen features, the training-defense
  verify).
- `e2e(review,reports,interop,bulk): review workflow, PDF/snapshots, compare,
  Croissant, ATLAS, Foundry, batches, capacity, CLI matrix evidence`
  (`e2e-review-reports-interop-bulk`): `tests/e2e/test_ml_review_reports.py`,
  `tests/e2e/test_ml_interop.py`, `tests/e2e/test_ml_bulk.py` (the plan's B3
  gate end to end: an export whose shards and manifest check out, a consumed
  slice validated through the real child, an ATLAS-stamped finding with the
  coverage view, the fake Foundry push, batches across the bundled models and
  an upload, bulk verify, capacity deferral and dispatch, the CLI matrix).
- `ci(phase-b-gate): scripts/phase_b_gate.sh, make check-phase-b, CI jobs,
  docs consistency test` (`phase-b-gate`): nine ordered steps stopping at the
  first failure and naming its spec 26 criterion, a stdlib HTTP probe program
  for a running stack, the scrubbed offline environment for the test tiers,
  the Postgres-lane tripwire, `make check-phase-b`, the `e2e-python` and
  `garak-offline` jobs calling the script, and
  `tests/test_docs_phase_b_consistency.py` (every test file the docs name
  exists, the Phase B route table's status column against the OpenAPI
  document and the live handlers, the README open items, no page saying
  that PR #23 is open or that a landed wave is unstarted, the nav, and a fake-HTTP
  proof that the gate fails on a `501` stub).
- The fix pass, one commit per track when the assembler lands it:
  `fix-api-services` (the capabilities roster read from the tree with the
  explainer roster, the `endpoint-v1` contract summary and an `interop` block;
  the `?modality=` filter on capability tags; the `batch_id` overlay on
  `/campaign`; `409 auth_profile_in_use` on `DELETE /v1/auth-profiles/{id}`;
  `FindingType` `adversarial_llm` / `adversarial_ml_manual`; the ATLAS stamp
  on analyst drafts; the JWT pattern in `redsim/audit/redact.py`; the ten
  off-table codes in a third 17.3 addendum with the `endpoint_schema_mismatch`
  row corrected; the consumed-slice binding at upload and in the artifact
  loader with a parent-side `materialize_consumed_slice`; `.env.example` and
  compose pass-through of the B2 and B3 variables), `fix-worker-runners` (the
  BULK-16 projection over `finding_ids` with the batch stamps moved before the
  broker message; `admit_or_defer` in both single-run boundaries with the
  `capacity_deferred` marker; the four-format completion render and the
  run's first `report_snapshots` row with a text-format fallback when the PDF
  renderer fails; self-describing text and detection export slices and the
  nullable `text` export column; `REDSIM_ML_MAX_ADV_ARTIFACT_MB` forwarded to
  the child; the record-authoritative stage close; four e2e test-isolation
  fixes), `fix-gate-ci` (the garak step failing on pytest exit 5, on an
  all-skipped run and on a missing extra; the worktree `PYTHONPATH` rule in
  the e2e step; the `garak` extra in the `e2e-python` lane and its 30 minute
  timeout; the stale-phrase heuristic of the docs-consistency test).
- This documentation pass: v2.8, the plan-07 rewrite onto spec section 27 as
  built, `EXECUTION-CONTEXT.md`, the register's header paragraph, the plan-12
  status lines, the spec 3.2, 11.6, 11.7, 17.4, 22.6 and 26.7 addenda,
  `docs/api/v1.md` against the OpenAPI document, the garak supply-chain
  paragraph, the README, CLAUDE.md, the testing and CI pages.

Phase B by wave, for the record (each subject on `main`; section 4.1 has the
rows): B0 `934838e..29db42c` (`feat(schema): Phase B additive fields`,
`test(ci): Phase B schema tripwire, garak marker/pin, e2e and garak CI jobs`,
`feat(db): 0011_phase_b_platform migration, RLS parity, ORM models`, `Add
Phase B Action members and 17.3 error codes with policy mirrors`, `feat(api):
mount Phase B routes as gated 501 stubs (INTEROP-01)`, `Phase B datasets: SMS
spam, WordNet, ATLAS, detection subset, slice`, `ml: endpoint-v1 predict
contract and egress policy (ENDPOINT-02, -07)`, `fix: integrate Phase B wave
B0`); B1 `6e1312f..1439f92` (the seven library commits and `fix: integrate
Phase B wave B1`); B2 `b6c82ef..57da31f` (eight track commits, `fix:
integrate Phase B wave B2 tracks`, the seam commit `9671e36`, `fix: integrate
Phase B wave B2`); B3 `1f1b52b..703f8f6` (five track commits, `fix: integrate
Phase B wave B3 tracks`, the reconcile commits `f718f10` and `5f02ac6`, the
docs commit `4da7193`, `fix: integrate Phase B wave B3`); B4 `f1e6cad`,
`2e00ce7`, `6484f2c`, `3836c48` plus the fix and docs commits of this push.

Checks: the counts of record are the B3 integration's on `main` at `703f8f6`
(default tier 2634 passed, 35 skipped, 13 deselected; `ml` 433 passed, 1
skipped; `garak` 12 passed; `e2e` 22 passed; ruff and `mypy redsim` (253
files) clean; `mkdocs build --strict` exit 0). The B4 tree's counts are the
B4 assembler's to record with its commit. Read from the B4 tree before this
pass: ruff and mypy clean, `tests/test_docs_phase_b_consistency.py` green
after this pass, one stale pin in the default tier
(`tests/ml/test_audit_campaign.py:113`), the e2e tier carrying the attributed
failures below, `make check-phase-b` not run against `make up`. No CI run on
`main` after `58461cc` has been read.

What is still open is the README list: the web UI (the plan's one deferral);
the items the B4 e2e files found and left open by attribution (the unscaled
8-row probe in `redsim/ml/targets/endpoint.py:228`, so no endpoint reaches
`available` through the tiny server; no bundled image target exposes a
training slice to the child, so every training verify records the defense
unavailable with the score withheld; the worker-parent
`materialize_consumed_slice` call for a consumed-bound model; no route
derives `architecture_kwargs` from the dataset binding for a `state_dict`
upload; the reportlab `LayoutError` on wide tables; three stale report pins;
the recorded endpoint seams; INTEROP-07, -23, -26); the owner decisions with
their applied defaults; the brief's packages; the recorded non-builds; the
unread CI runs.

Divergences recorded in this revision under the plan-01 section 8 protocol,
all in `docs/architecture/ml-vertical.md` "Accepted divergences": the B2
code divergence is closed (the ten codes are on the table in a third dated
addendum and the `endpoint_schema_mismatch` row names `endpoint-v1`); the
`FindingType` divergence is closed (`adversarial_llm` and
`adversarial_ml_manual` added additively to the platform module
`redsim/schema.py`, every stored blob still validating); the `batch_id` of a
run is an overlay on `GET /v1/runs/{id}/campaign`, not a schema field
(BULK-02, the owner default); the export schema gained a nullable `text`
column for text-modality slices (27.1, INTEROP-04 closed for every runner); a
PDF the renderer cannot typeset degrades to the text formats with
`pdf_unavailable` on the `report.render` row rather than failing the
evidence job; the completion snapshot is version 1 and an on-demand render
version 2 onwards (REVIEW_REPORTS-20); a training defense the child cannot
apply is recorded unavailable with the score withheld and the verify run
succeeds on the undefended model (spec 15.6 / 16.4, the honest state until
the bundled targets expose a slice). Nothing in D1 to D14 changes.

### v2.7 (2026-09-09): change note, Phase B wave B3

Phase B wave B3, interoperability and bulk operations, is pushed to `main`
with this revision: five track commits and the integration commit, written
in the worktree `wt/waveb3` on the B2 integration commit and rebased onto it.
By subject:

- `feat(interop): Croissant/Parquet dataset export of a campaign run`
  (`interop-contribute`): `redsim/ml/interop/{parquet,croissant,card}.py`
  (one deterministic Parquet shard per (attack, ε) plus the control family
  and the clean slice when persisted, on one fixed nullable schema; the
  MLCommons Croissant 1.0 manifest with a `redsim:provenance` block whose own
  sha256 is the dataset version; `check_projection`, the projection-equality
  guard against `ml.flip_matrix`; `croissant_validate` refusing model file
  names, `reviewer_notes`, credential names and any bare MRI; the
  template-only card), `redsim/services/ml_datasets_export.py`
  (`admit_export`: the `dataset.export` row, a follow-up `Run` with scanner
  `ml.dataset_export`, `409 export_unavailable` / `export_in_flight`, `422
  fixture_not_exportable`, one export per run) and
  `redsim/workers/tasks/dataset_export.py` (`redsim.dataset_export` on
  `scans`, the `ml.dataset.manifest` / `parquet` / `card` rows on the source
  run, `dataset.export.execute`). INTEROP-33: the first export built with
  these modules is in the public data repository at `0dababc`
  (`data/exports/url_trees_sample/`).
- `interop(consume): POST /v1/datasets static admission, sandboxed Parquet
  parse, binding hook` (`interop-consume`): `redsim/api/v1/datasets.py` (the
  consume route, the consumed rows on `GET /v1/datasets`, the manifest read
  and the export route over the contribute service),
  `redsim/services/ml_datasets.py` (stdlib-only static checks: length cap,
  Parquet magic, no pickle-shaped name, the Croissant shape, bare-file-name
  `contentUrl`s, licence, declared schema; `413`, `415`, `422
  remote_reference_refused` / `license_required` / `schema_undeclared`, `501`
  for `text` and `detection`; every refusal a `success=False`
  `dataset.register` row; the `ml_datasets` row, an `ml.dataset_ingest` `Run`
  and a `dataset.validate` `Job`; the binding helpers),
  `redsim/ml/interop/consume.py` (the parse child) and
  `redsim/workers/tasks/dataset_validate.py` (`redsim.ml_dataset_validate`
  on `scans`: re-hash in the parent, the credential-free child, the
  `dataset.validate` row and the `ml.dataset_validation_report`).
- `bulk: batch campaigns, roll-up, cancel, compare groups, bulk verify`
  (`bulk-service-routes`): `redsim/services/ml_batches.py`
  (`create_campaign_batch` through the unchanged single-run boundary per
  member with `batch_id` stamped after admission, write-free pre-checks, one
  `batch.create` row, collected per-member refusals, `422
  batch_member_refused` only when nothing was admitted, the capacity seam
  per member; `rollup_status`; `batch_view` with no MRI number;
  `cancel_batch`; `create_verify_batch` per owner decision BULK-16, one
  defended run per `(defense, params)` with one `verify.replay` row per
  additional finding), `redsim/api/v1/batches.py` (the six routes),
  `redsim/ml/compare.py::comparability_groups` (no aggregate) and the
  `batch_id` mirror in the e2e harness and the campaign-route tests.
- `feat(ml): bulk upload, per-project capacity/deferral, CLI attack matrix`
  (`bulk-upload-capacity-cli`): `redsim/api/v1/models_bulk.py`
  (`POST /v1/models/bulk`: `411` / `413 bulk_too_large`, `422
  bulk_too_many_files`, one `bulk.upload` row, the single-upload admission
  per file, `201` / `207` / `422 batch_member_refused`; `GET /v1/ml/capacity`),
  `redsim/services/ml_capacity.py` (`admit_or_defer` over
  `projects.ml_max_concurrent_runs` and `ml_daily_run_budget`, deferral with
  the `capacity_deferred` marker, the audited `429 daily_budget_exceeded`,
  counts from the jobs table, `dispatch_deferred`),
  `redsim/workers/tasks/capacity.py` (`continue_deferred` and the beat task
  `redsim.ml_dispatch_deferred` every 60 s), `redsim/observability.py` (the
  filled `redsim_jobs_active`, `redsim_ml_deferred_runs`,
  `redsim_ml_daily_budget_used`), `redsim/workers/celery_app.py` (the
  `capacity` include) and `redsim/cli/ml.py` (`redsim ml attack` with
  several ids or `--matrix FILE.yaml`: one offline run and one verified
  chain per cell, a summary table and `summary.json`, `--fail-fast`, exit 1
  on any refused or failed cell, no aggregate).
- `interop(atlas,foundry): ATLAS stamp and coverage, Foundry push, roster`
  (`atlas-foundry`): `redsim/ml/atlas.py` (`STAMP_TECHNIQUE_IDS` checked at
  import against `atlas_data`: `AML.T0043` for the gradient, text and patch
  attacks, `AML.T0040` for `hopskipjump` and `zoo`, `AML.T0020` reserved for
  the poisoning ids, `None` for controls; `technique_for_attack`,
  `attack_atlas_row`, the number-free `coverage` view),
  `redsim/services/ml_findings.py` (the stamp on every new finding, one
  line), `redsim/api/v1/attacks.py` (the ATLAS block per row and the release
  citation), `redsim/integrations/foundry.py` (settings from the process
  environment with the B0 egress rules and the
  `REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL=1` attestation, no token
  variable; the roster block; `build_scorecard_payload`; the D9 guard
  `validate_push_payload` / `assert_push_payload`; `scrub_detail`; the
  Datasets v2 client), `redsim/integrations/__init__.py`
  (`create_foundry_push`: the typed refusals, the `integration.push` row on
  the follow-up run's chain, `501 integration_disabled` while unset or
  misconfigured; `LATTICE_STATUS` text only by D3),
  `redsim/workers/tasks/integration_push.py` (`redsim.integration_push` on
  `default`, `max_retries=0`: the record digest check, the guard, the
  payload and rows stored before the push, the token decrypted only then,
  `ml.integration.receipt`, `integration.push.execute`),
  `redsim/api/v1/integrations.py` (coverage, roster, push) and
  `tests/ml/fake_foundry_server.py`. The push is proven against that fake
  server only (INTEROP-26).
- `fix: integrate Phase B wave B3 tracks`: the three B3 task modules added to
  the Celery `include` list (`task_routes` unchanged so the worker-hardening
  pin holds), the B0 `POST /v1/runs/{id}/dataset` stub removed from
  `integrations.py` (the datasets router serves the path, no duplicate
  operation id), and `tests/ml/test_phase_b_stubs.py` rewritten as the Phase
  B surface pin (every B0 path gated and answering with a real handler, never
  `501 not_implemented`; 61 cases).

Checks (the B3 assembler's worktree, head `a780d88` before the atlas-foundry
and integration commits and the rebase): `ruff check --select E4,E7,E9,F,I
redsim tests` clean, `mypy redsim` clean (253 source files), the six
writers' test files together 140 passed and 1 skipped, the surface pin 61
passed, the e2e smoke file 8 passed through the real child. Final counts at
the B3 integration on the rebased tree (the reconcile pass, run from the repository root): `ruff check --select E4,E7,E9,F,I redsim tests` clean, `mypy redsim` clean (253 source files), the default tier `pytest -q -p no:cacheprovider --ignore=tests/e2e` 2634 passed, 35 skipped, 13 deselected (the `test_campaign_golden` artifact pin now excludes the Phase B export slices, `test_cli_ml` pins the `l2` default `pgd`; the `test_campaign` harden-hook and `test_datasets` synonyms failures of the B2 tree are not present), the `ml` tier 433 passed and 1 skipped, the `garak` tier 12 passed, the `e2e` tier against the compose Postgres 22 passed, `mkdocs build --strict` exit 0. 69
routes under `/v1` as before: the 14 B0 stubs replaced one for one, no path
added. No frozen contract changed: `redsim/ml/schema.py`, the migration
head, the `Action` set, the error-code table and the three policy files are
as B2 left them.

What is still open is the README list: the web UI (the plan's one deferral),
wave B4 (no e2e evidence for what B2 and B3 built, no gate, no
docs-consistency test, the plan-07 rewrite), the wave B3 follow-ups read
from the tree (the text and detection runners' self-describing slices;
regenerate-in-child; the upload and worker-loader consumed-slice binding
calls; the JWT redaction pattern; the finding-list
ATLAS key; the capabilities interop block and the `.env.example` and compose
pass-through of the B3 variables; the single-run admissions under the caps;
the bulk-verify worker projection; the
`batch_id` overlay; the dataset push; a real Foundry push), the wave B2
follow-ups, the owner decisions with their defaults (INTEROP-26, INTEROP-27
and BULK-16 applied by B3; one new choice, the Foundry attestation variable,
droppable if the owner prefers the bare URL switch), the brief's packages,
the recorded non-builds. The CI
runs for `29db42c` and `1439f92` had not been read when this revision was
written and the B2 and B3 pushes had not happened; nothing is claimed green.

Divergences recorded in this revision under the plan-01 section 8 protocol,
all in `docs/architecture/ml-vertical.md` "Accepted divergences": the Foundry
switch as the URL plus the attestation variable (spec 27.3's last sentence
made checkable); a text or detection export carrying the adversarial family
only until those runners persist self-describing slices (register INTEROP-04,
closed for the classification runner in the reconcile pass); bulk verify as
one defended run per `(defense, params)` with the worker projection pending
(BULK-16); bulk upload answering per file (`201` / `207` / `422`) rather
than refusing whole (BULK-13); the manifest built and validated in pure
Python with `mlcroissant` blocked in the API tripwire (INTEROP-05). Nothing
in D1 to D14 changes.

### v2.6 (2026-09-09): change note, Phase B wave B2

Phase B wave B2, the services, workers and routes over the B1 library, is
pushed to `main` with this revision: eight track commits and the integration
commit, written in a worktree whose base (`b404eb8`) predates the B1
integration and rebased onto `1439f92`. By subject:

- `api: add thirteen Phase B error codes; dataset.export to remediator`
  (`codes-b2`): the 13 codes the register named and B0 left out, in a second
  dated spec 17.3 addendum (`reviewer_not_independent` 403;
  `auth_profile_in_use`, `idempotency_key_reused`, `idempotency_conflict`,
  `review_state_conflict`, `snapshot_archived` 409; `bulk_too_large` 413;
  `auth_profile_required`, `probe_key_required`, `batch_member_refused`,
  `bulk_too_many_files`, `fixture_not_exportable` 422;
  `query_budget_exceeded` 429), and `dataset.export` moved to `remediator`
  in `redsim/api/policy.py`, the Rego and the Cedar bundle together (spec
  17.4 and 27.4), closing the B0 divergence.
- `feat(ml): endpoint registration, validate via broker, projections`
  (`endpoint-admission`): `POST /v1/models` with `source: endpoint` at
  `target.manage`, `EndpointRegistration` plus the static egress check, the
  `model.register` row with the allowlist verdict, a `Target` of kind
  `ml_model_endpoint` in `validating`, the endpoint variant of
  `redsim.ml_model_validate` through the broker with the credential resolved
  at pickup, credential-free projections and delete; `endpoint_kind: llm`
  handed to the LLM registration.
- `worker: endpoint broker lifecycle, derived-target registration, retests
  (Phase B B2)` (`worker-campaign-phase-b`): the broker started in the worker
  parent around an endpoint campaign with the tally on the record and the
  audit rows, the derived weights of a training verify registered as a new
  `Target` with `derived_from` lineage through validate, every verify
  appended to `MLFindingDetail.retests`, the `ml.clean_slice` and
  `ml.control_slice` kinds.
- `admission(ml): modality table, norm checks, endpoint budget, project
  scoring` (`admission-phase-b`): `SUPPORTED_MODALITIES` over `image`,
  `tabular`, `text` and `detection` with per-modality norms, default grids
  and caps (detection `n_samples` cap 200, `mri=False`), `llm` as
  `not_implemented` pointing at the probe route, the adapter norm check
  (`422 params_out_of_range` on `norm`), endpoint targets admitted with a
  worst-case query budget (`429 query_budget_exceeded`), the project scoring
  override frozen at admission, and the training defenses admitted on verify
  (`ALL_DEFENSES`).
- `ml(llm): garak through Pythia core: catalog, generator, probe child,
  scorecard` (`llm-core`): `redsim/ml/llm/` with the committed catalog (103
  probes, `redsim-core` 76, `redsim-extended` 85 opt-in, 18 excluded with
  reasons, `fitd.FITD` for HarmBench under LLM-08), `PythiaGenerator`, the
  credential-minimised probe child and runner, the k/n `LLMProbeScorecard`
  whose validator refuses every MRI, grade and subscore key, the rules and
  the report section.
- `feat(llm): probe routes, admission, worker, scorecard and findings`
  (`llm-api`): LLM target registration (`endpoint_kind: llm`, a canonical
  Pythia model id, a persona, a `guardrail_mode` and a bearer `AuthProfile`
  probe key, LLM-26), `GET /v1/llm/probes`, `POST /v1/models/{id}/probes`,
  `GET /v1/runs/{id}/llm-scorecard`, the task `redsim.ml_llm_probe_run` on
  the `default` queue with the entitlement check, findings with hit-rate
  severity labelled as such, `/campaign` and `/compare` refusing probe runs.
- `review: transition table, resolve gates, retest links, analyst drafts`
  (`review-workflow`): one transition table over the widened review states,
  independence by identity (`reviewer_not_independent`), compare-and-set
  (`review_state_conflict`), `resolve` gated on `poc_passed`, `fixed`,
  `confirmed` and a compatible retest (`resolution_blocked`), retest links,
  analyst drafts and revisions; the Phase A dismissal route byte for byte.
- `reports: PDF projection, snapshots, N-run compare, weights API,
  idempotency` (`reports-compare-weights`): `report.pdf` through reportlab
  with bundled DejaVu subsets, `report.render` as an audit-first job writing
  one immutable `report_snapshots` row per render, the snapshot routes,
  `GET /v1/runs/compare?ids=` with no mean or rank, `GET`/`PUT
  /v1/projects/{slug}/ml-scoring` never renormalising, the `Idempotency-Key`
  middleware over `idempotency_keys`.
- `fix: integrate Phase B wave B2 tracks`: six test pins moved to the B2
  behaviour, the worker's `_endpoint_request_block` reading the URL from
  `Target.value`, and the environment snapshotted around the `litellm`
  import in `redsim/llm/pricing.py`.

Checks before the rebase (the B2 assembler's worktree): ruff and `mypy
redsim` (236 files) clean, 251 passed and 1 xfailed in the writers' ten test
files, the full default tier 2431 passed, 36 skipped, 12 deselected,
1 xfailed and 17 failed, every failure present at the base and fixed on
`main` by the B1 integration, the 11 `garak`-marked tests green with garak
0.16.0 against the fake gateway. The B2 integration pass (`fix: integrate Phase B wave B2`, pushed with the B2 commits) re-ran every tier on the rebased tree from the venv: ruff (CI selection) and `mypy redsim` (236 files) clean, the default tier 2480 passed, 35 skipped, 13 deselected, the `ml` tier 420 passed, 1 skipped, the 12 `garak`-marked tests green against the fake gateway, the e2e tier 22 passed against Postgres with the sandbox child, `mkdocs build --strict` exit 0. Counts on `main` are the B1
integration's at `1439f92`: default 2257 passed, 35 skipped, 1 deselected;
`ml` 418 passed, 1 skipped; e2e 22 passed; mypy 220 files. No frozen contract
changed: `redsim/ml/schema.py`, the migration head and the `Action` set are
as B0 left them, and the one policy change (`dataset.export`) edited the
three policy files together.

What is still open is the README list: the web UI (the plan's one deferral),
waves B3 and B4 (the 14 remaining `501` stubs, no e2e evidence for what B2
built, no gate), the wave B2 follow-ups read from the tree (the capabilities
roster, the attacks filter and the defenses `phase` stamp not updated, the
campaign completion path writing three formats and no snapshot, the two e2e
`report.pdf` pins, the codes still off the 17.3 table, `FindingType` without
the LLM and manual literals, `auth_profile_in_use` not emitted, ENDPOINT-30,
the CLI items), the owner decisions with their defaults, the brief's
packages, and the recorded non-builds. The CI runs for `29db42c` and
`1439f92` had not been read when this revision was written and the B2 push
had not happened; nothing is claimed green.

Divergences recorded in this revision under the plan-01 section 8 protocol,
all in `docs/architecture/ml-vertical.md` "Accepted divergences":
`query_budget_exceeded` at 429 (register 422), `idempotency_key_reused` at
409 (register 422) with `idempotency_in_flight` spelled
`idempotency_conflict`, `fixture_not_exportable` at 422 (register 409), the
Phase A dismissal route keeping its plain-string `forbidden` beside the
structured `reviewer_not_independent` of the new decisions, the codes the
routes resolve by `getattr` with documented fallbacks until their rows land,
and `adversarial_ml` with a `finding_kind` marker for LLM and manual
findings. The `dataset.export` divergence of v2.5 is closed. Nothing in D1 to
D14 changes.

### v2.5 (2026-09-09): change note, Phase B waves B0 and B1

Phase A is complete through wave 4 and Phase B has started. In order:

- **Wave 4** landed (`3dda572..e73dea0`, integration commit `e73dea0`): the
  three end-to-end completion-criteria files (22 e2e cases with the smoke
  file), the CI fixes (`python-multipart` in the `api` extra, the `Sample`
  move that breaks the `datasets` / `targets` import cycle, the `.trivyignore`
  baseline, the lazy torch imports behind `redsim ml build-assets`), the
  admission follow-ups (`8eb8870`) and the v2.4 documentation pass
  (`ae8d77c`). PR #23 (the Fargate runtime) merged as `10650da`; PR #24
  (tRPC and env management, `b93d9a9`) and PR #25 (design reference,
  `6cbb661`) landed on the web side. The Phase B register and plan were
  written (`7706950`: `docs/plans/11-phase-b-register-2026-09-09.md`, 309
  items, and `docs/plans/12-phase-b-plan.md`, five waves) and the
  remaining-work brief (`docs/plans/10-remaining-work-brief.md`, packages A
  to F with section H as the coordination contract) carries what runs outside
  the waves.
- **Phase B wave B0** landed on `main` as `934838e..29db42c` (seven track
  commits and the integration commit `29db42c`, pushed 2026-09-09): every
  frozen-contract change once (the schema additions of the note below,
  migration `0011_phase_b_platform`, seven `Action` members and 23 spec 17.3
  codes with their OPA and Cedar mirrors and spec addenda), the schema-compat
  tripwire and the `garak` marker with the `e2e-python` and `garak-offline`
  CI jobs, the 19 Phase B routes as gated `501` stubs, the `endpoint-v1`
  predict contract and egress policy, and the datasets (SMS Spam Collection
  published verbatim under owner default MODALITIES-12, WordNet 3.0 cached,
  the military-assets subset published pending MODALITIES-27, the
  `vehicles_cnn` training slice, ATLAS `v2026.08` vendored, the garak
  reference entry; public repository head `4048a209`). Checks at `29db42c`:
  2081 passed, 35 skipped, 1 deselected in the default tier, 22 e2e passed
  with the Postgres lane, ruff and mypy (197 files) clean, `mkdocs build
  --strict` clean. Section 4.1 has the row, section 5 the contract changes.
- **Phase B wave B1**, the library layer, was written in an isolated
  worktree in parallel with B0 (seven tracks: `runner-refactor`,
  `text-modality`, `detection-modality`, `attacks`, `explain-blackbox`,
  `endpoint-target`, `hardening`, one commit each plus the integration
  commit `fix: integrate Phase B wave B1 tracks`), rebased onto `29db42c`
  and pushed to `main` with this revision. It changed no route and no frozen
  contract: `run_campaign` is now a frame plus one `ModalityRunner` per
  `Modality` literal (golden-tested against the frozen pre-refactor copy),
  the `text` and `detection` modalities exist end to end in the library
  (`sms_tfidf_lr` and `word_substitution` under an `edit` budget with SHAP
  text; `assets_frcnn_mnv3` and `dpatch` under a `patch_area` budget with a
  detection scorecard and never an MRI), `cw_l2`, `deepfool` and `zoo` are
  registered with declared norms and measured CPU budgets, KernelSHAP serves
  predict-only tabular targets with endpoint query caps, `EndpointTarget`
  reaches an endpoint only through the worker-parent `PredictBroker` over a
  unix socket, and `adversarial_training` and `defensive_distillation` run
  as the `defense_apply` stage with the tabular tree ensemble a typed
  refusal. Its own checks before the rebase: ruff and mypy (213 files)
  clean, 206 passed in the writers' test files. `adv_patch` (MODALITIES-32)
  is recorded as not built.
- **What is still open** is the README list: the web UI (the plan's one
  deferral), waves B2 to B4 (every Phase B route is still a `501` stub and
  the API admits no Phase B modality, norm, training defense or endpoint
  target), the owner decisions of plan 12 section 2 with their defaults, the
  brief's packages, and the recorded non-builds. The CI run for `29db42c`
  had not been read when this revision was written; nothing is claimed green.

Divergences recorded in this revision under the plan-01 section 8 protocol,
all in `docs/architecture/ml-vertical.md` "Accepted divergences": the
`defense_apply` position (after `load_target`, not appended), the
`endpoint-v1` contract name and body (not the register's
`redsim-predict-proba/1` with an `encoding` key), `dataset.export` at
`scanner` (the brief) rather than `remediator` (register INTEROP-02, spec
17.4), five stub paths per the brief rather than the register, the
`DetectionMetrics` field names, image HopSkipJump served by the Phase A
adapter (spec 12.2), KernelSHAP for images not built (spec 13.2), native
torch distillation with ART's class cited (spec 16.5), no connection IP
pinning in the broker (ENDPOINT-07 risk note), and no DNS-TXT ownership check
for endpoints (spec 21.7, owner default ENDPOINT-26). Nothing in D1 to D13
changes; D14 (the data-poisoning module) is the brief's package F.

### v2.4 (2026-09-09): change note

Wave 3 is on `main`: ten commits `7556b22..58461cc`, integrated by `58461cc`
and verified from that tree rather than from the writers' reports. Section
4.1 carries the shas per item, section 8 the checks at `58461cc` (1663
passed and 30 skipped, 8 e2e passed, ruff and mypy clean) and the CI state
(red on three jobs, wave 4 fixing the `python-multipart`, import-cycle and
advisory causes and the 3.13 lane's eager torch import behind the asset
builder, no green run claimed). Wave 4 is
in progress in parallel: the three end-to-end completion-criteria files
`tests/e2e/test_ml_campaigns.py`, `tests/e2e/test_ml_verify_upload_reports.py`
and `tests/e2e/test_ml_governance.py` (added in wave 4, on the wave-3
harness), the CI fixes, the admission follow-ups and this documentation pass.
PR #23 (`feat/p7-fargate-runtime`, William; open when v2.4 was written,
merged as `10650da` on 2026-09-08) is recorded in section 4.1: a public HTTPS
Fargate demo runtime its author reports applied to the AWS account, with the
pinned asset bundle, demo users and automatic rollout still outstanding. Nothing in D1 to D13 changes and no new divergence is recorded:
the surrogate-transfer admission exemption of `58461cc` follows spec 12.9
rather than departing from it.

### v2.4 change note: Phase B schema additions (2026-09-09, wave B0)

Announced under the plan 01 section 8 protocol in the commit that adds them
(`docs/plans/12-phase-b-plan.md` section 3, register
`docs/plans/11-phase-b-register-2026-09-09.md`). Every item is additive and
default-valued: no field is renamed or retyped, the frozen
`tests/ml/fixtures/run_record.json` validates unchanged and dumps unchanged
under `exclude_unset`, and the tripwire `tests/ml/test_schema_compat.py`
holds. One line per addition, in `redsim/ml/schema.py`:

- `Domain` gains `text` and `detection`; `Modality` gains `text` and
  `detection` (MODALITIES-01).
- `Norm` gains `edit` (text: ε is the maximum share of words replaced per
  input) and `patch_area` (detection: ε is the patch area as a fraction of the
  image area) (MODALITIES-02).
- `Measurement.edit_fraction_mean: float | None = None` and
  `Measurement.detection: DetectionMetrics | None = None`; new
  `DetectionMetrics(n_boxes, n_matched, map50, recall, suppression_rate)`, all
  optional (MODALITIES-03).
- `Observation.text: TextObservation | None = None` and
  `Observation.detection: DetectionObservation | None = None`; new
  `TextObservation` (word counts, positions, attribution artifact names, no
  message text) and `DetectionObservation` (box counts, `patch_bbox`)
  (MODALITIES-04).
- `MLModelManifest.text: TextModelSpec | None = None` and
  `MLModelManifest.detection: DetectionModelSpec | None = None`
  (MODALITIES-05).
- `MLModelManifest.endpoint: EndpointSpec | None = None`; new
  `EndpointSpec(url_host, auth_profile_id, contract_version, input_shape,
  batch_rows, timeout_s)`, no credential and no URL string; `format ==
  "endpoint"` requires the block, the block requires `format == "endpoint"`
  and no gradients (ENDPOINT-03).
- `MLModelManifest.derived_from: DerivedFrom | None = None`; new
  `DerivedFrom(parent_target_id, parent_sha256, defense_id, training_budget)`
  (ATTACKS_HARDEN-15).
- The four manifest blocks are omitted from `model_dump` while `None`, so
  `manifest_sha256` of every manifest written before Phase B (built asset
  trees, stored `targets.detail`) is unchanged (MODALITIES-05 risk).
- `ReviewState` gains `draft`, `in_review`, `confirmed`, `resolved`;
  `FindingReview.history: list[ReviewEvent] = []` and
  `FindingReview.revisions: list[FindingRevision] = []`; new `ReviewEvent`
  and `FindingRevision` (REVIEW_REPORTS-01).
- `MLFindingDetail.retests: list[FindingVerify] = []` (`verify` stays the
  latest); `FindingVerify.settings_hash: str | None = None` and
  `FindingVerify.baseline_run_id: str | None = None` (REVIEW_REPORTS-08).
- `CampaignRecord.schema_version: str = "campaign-record-1"` (constant
  `CAMPAIGN_RECORD_SCHEMA_VERSION`); `report.json` stays the record dump and
  now discloses it (REVIEW_REPORTS-18).
- `RunSummary.kind: RunKind | None = None` with `RunKind = Literal["attack",
  "verify", "ingest", "llm_probe"]`, and `RunSummary.probe_ids: list[str] =
  []` (LLM-24).
- `STAGES` gains `defense_apply` directly after `load_target`, where spec 6.5
  places it; the Phase A stages keep their relative order and `report` stays
  last (ATTACKS_HARDEN-15).

Wave B1 built against these additions (no further schema change):

- `redsim/ml/runners/base.py` keys `MODALITY_RUNNERS` by the `Modality`
  literals (`image`, `tabular`, `text`, `detection`) and checks at import that
  every literal has a runner; a runner module that fails to import is the
  typed `ModalityRunnerUnavailable` (`modality_runner_unavailable`) before any
  stage runs.
- The campaign frame emits `defense_apply` directly after `load_target` only
  when a `kind: training` defense was applied (`redsim.ml.harden.apply`), and
  the worker's `expected_stages` mirrors the rule (B1 integration): a
  preprocessing defense adds no stage, a training defense the hook refused
  (no torch module, no training slice) writes no stage and is recorded
  unavailable with the score withheld.
- The text runner fills `Measurement.edit_fraction_mean` and
  `Observation.text`, the detection runner `Measurement.detection` and
  `Observation.detection` beside scalar `det_*` params, the text and
  detection builds write `MLModelManifest.text` and `.detection`, the
  endpoint target writes `MLModelManifest.endpoint` with exactly the
  `EndpointSpec` names, and the training record's `derived_from()` matches
  `DerivedFrom`. `redsim/ml/assets/manifest.py`'s `DatasetSource` gains
  `uci` and `github` and `ModelEntry` a build-record `train_slice_split`,
  both outside the frozen projection.
- Not added, by design: `CampaignConfig.explainer` (ATTACKS_HARDEN-15 item 3)
  and the artifact-kind names of MODALITIES-44 are outside plan 12 section 3
  and wait for their owning tracks; the LLM records live in
  `redsim/ml/llm/schema.py`, never in the frozen module.

### v2.3 (2026-09-08, night): change note

The ML vertical is on `main` end to end at `bb43bd7`: routes, admission,
worker, sandbox child, scoring, explain, recommend, verify, reports and
compare. What landed since v2.2, in order:

- **PR #22** (`a864da6`, Metz): P4 campaign orchestration, the campaign,
  compare and report routes, and the web contract alignment
  (`web/src/lib/api.ts` and the run and finding pages call the routes that
  exist). Eight codex-pr-review findings were fixed on the branch before the
  squash merge, per the review.
- **`cc781ad`**: the spec 10.6 failure classes in `redsim/ml/errors.py`
  (`ModelLoadRefused`, `ArtifactDigestMismatch`, `SandboxTimeout`,
  `SandboxKilled`, `EnvelopeInvalid`, `DatasetUnavailable`,
  `MlExtraUnavailable`, `ExplainerUnavailable`) and
  `docs/plans/09-gap-register-2026-09-08.md`, the 560-item spec-vs-tree
  register the completion waves work from.
- **Completion wave 1** (`f8693c2..a99d9cc`, seven commits): loaders read
  the build-assets manifest, onnx2torch conversion with the argmax agreement
  recorded, `build-assets --fixture` committing
  `tests/ml/fixtures/cifar10_test_500.npz`, the `resnet18` architecture
  behind `--arch`, the tabular id `url_trees` (alias `url_classifier`),
  surrogate PGD with per-feature ε and the ART mask, the scoring constants
  with the `control_preserves_accuracy` binomial predicate, `FamilyDelta` and
  the typed delta refusal, `not_run` attacks with the curve PNG, the dataset
  caveats and `TinyTabularTarget`, the six-section report renderer, the
  `PartitionExplainer` fallback and the explanation cache, the typed sandbox
  config and envelope, and `redsim/api/errors.py` with the spec 17.3 code
  table.
- **Completion wave 2** (`055bdee..bb43bd7`, eight commits): the spec 10.5
  audit vocabulary and the 6.5 stage table in the worker, the Pythia
  narrative moved from the sandbox child to the worker parent through
  `redsim.llm.router.route("ml.harden_narrative")` with `DbBudgetChecker` and
  `LLMUsage` rows, the typed validate envelope with the parent digest check,
  spec 5.11 detail and `job.complete`, worker observability (init, the
  `job.run` span and `stage_span` helper, run roll-up in the reaper,
  cancel-safe `task_context`), spec 17.3
  codes on every ML route, per-project bundled Target ids
  `<bundled_id>-<8 hex>` with `Target.value = "bundled:<id>"` and
  `register_bundled_model(session, project_id, bundled_id, actor)`, the
  audited soft delete, upload refusal codes with `success=False`
  `model.register` rows, the finding projection of spec 5.7 and the
  dismissal rules, compare with variable-level incompatibility and
  `verify_delta`, report routes `md` / `json` / `html` with `report.pdf`
  answering `501`, `GET /v1/audit/verify?all=1`, and build-assets dataset
  caveats with `subject_centered`.
- **Completion wave 3** (`7556b22..58461cc`, ten commits, on `main` since
  2026-09-09 and verified in v2.4): the offline `redsim ml attack
  <target_id>` campaign, `redsim ml seed`, the `ml-campaign` scanner
  adapter, opt-in `redsim.ml.attacks` plugin discovery, the `tests/e2e`
  harness and its smoke file, `redsim doctor` rewritten around Pythia,
  Pythia-only `redsim.yaml` and `.env.example`, canonical audit timestamps,
  the `resnet18` fine-tune recipe and the defect fixes. Section 4.1 lists
  them with their shas.

Divergences from the spec that the tree keeps, recorded here under the
`01-p0-contracts-api-skeleton.md` section 8 protocol (announce in this file,
prefer additive fields):

1. **One job per campaign.** Spec 10.3 describes a Celery chain with one
   `attack.run` Job per attack followed by `explain.run` and
   `harden.recommend`. The tree runs the whole campaign in one
   `redsim.ml_campaign_run` job. `explain.run`, `harden.recommend` and
   `verify.replay` are separate jobs on the same task, created by the finding
   routes. `Run.stage_table` still carries the per-stage rows of spec 6.5.
2. **Task names.** The shipped tasks are `redsim.ml_campaign_run` and
   `redsim.ml_model_validate` (both on the `scans` queue) plus the ML branch
   of `redsim.report_render`. The spec names `redsim.attack_run`,
   `redsim.explain_run`, `redsim.harden_recommend` and
   `redsim.model_validate` are not registered.
3. **Report artifact kinds.** The worker's artifact sink writes the reports
   as `report.md`, `report.json` and `report.html` (the spec 5.8 names). The
   report route also serves the `ml.report_<ext>` kinds written before wave 2.
4. **`harden.execute` usage keys.** The audit row carries `usage.prompt` and
   `usage.completion` rather than `prompt_tokens` / `completion_tokens`,
   because `redact_audit_detail` blanks any key containing `token`.
5. **Worker audit actor.** Worker rows carry `actor = worker:<job.type>` with
   the requesting principal in `detail.requested_by`. Spec 10.3 said
   `actor = Job.created_by`.
6. **Partial verify score.** A verify run whose score is partial is
   `inconclusive` and leaves the finding `open`. The spec 6.4 outcome table
   did not name the case.

Nothing in D1 to D13 changes. Sections 4.1, 5 (the jobs and errors bullets),
7, 8 and 9 are updated below. Local asset numbers quoted in section 8 are
illustrative and are not results.

### v2.2 (2026-09-08, evening): change note

P0 / M0 merged. PR #18 (branch `P0`, John Sasser) landed on `main` as
`4350d38` (868 passed and 30 skipped offline per the PR body), and PR #11
(Pythia access) followed as `5fa2d79`. P0 froze `redsim/ml/schema.py` under the spec 5.3 names, so the
"frozen on PR #8" contracts that v2.1 section 5 listed (`Scoring`,
`RunRecord.scoring`, `RunRecord.atlas_coverage`, the `AttackInfo` ATLAS
fields, `Measurement.severity`, the widened `RunConfig`) are superseded.
Section 5 now lists the P0 shapes, section 4.1 records #18 and #11 as merged
and #8 and #9 as rebased on P0 with adaptation in progress, and the WS0 / WS2
naming coordination item is closed. The eight points where P0 resolved spec
text in favour of the tree are recorded in spec section 4.5. Nothing in D1 to
D13 changes.

### v2.1 (2026-09-08, later): change note

What changed in this revision and why. Nothing below alters a D1–D13 decision
except D7, which the product owner amended.

Two commits earlier the same afternoon already touched every file in this
directory: `c582c40` (interop adopted as B2, the malicious-URLs dataset, the
`@redsim/*` web packages, CLAUDE.md marked current) and `836b0e1` (every
`aegis` path and identifier in the plans flipped to `redsim`). v2.1 builds on
both, adds what they did not carry (the amended D7 as the reason for the
rename, the frozen contract names on PR #8, the workstream status, the Pythia
access facts) and restates the rest so this file reads as one document.

- **(a) Rename.** D7 was amended by the product owner: redsim is the product
  name AND the code name. Commit `b39d933` renamed the Python package to
  `redsim/` (import `redsim.…`), the console script to `redsim`, environment
  variables to `REDSIM_*` (including `REDSIM_ML_LLM_MODEL`), the API title to
  "Redsim API", compose services and images to `redsim-*`, the Helm chart to
  `deploy/helm/redsim`, the config file to `redsim.yaml`, the CI workflow to
  `.github/workflows/redsim-ci.yml`, and the web packages to `@redsim/web` and
  `@redsim/design-system` (web env `NEXT_PUBLIC_REDSIM_API_URL`). The ML
  vertical is `redsim/ml/`. Every path and identifier in sections 2, 4 and 5 is
  updated. The v2 line "redsim retired" is struck. Mentions of "aegis" that
  refer to the upstream project or to history ("forked from aegis", "restored
  from the aegis head") stay correct and are kept.
- **(b) CLAUDE.md.** The v2 note calling the repo `CLAUDE.md` stale is
  withdrawn. It was rewritten on 2026-09-08 (commit `ce3ee02`) onto the
  platform architecture. See section 1 for the one caveat that remains.
- **(c) Tabular demo dataset.** The Kaggle malicious-URLs dataset
  (`sid321axn/malicious-urls-dataset`, CC0) is THE demo tabular dataset and
  `lacg030175/UNSW-NB15` is the fallback (spec section 11, rows 55 of the
  reconciliation table, decision register D001 and D005). v2 named UNSW-NB15 as
  primary. Section 2, section 3 and section 8 are corrected.
- **(d) Interoperability.** Re-proposed and adopted into the product spec as
  section 27, Phase B2 (spec row 57). v2 section 6 said "dropped, decision
  needed". It now records the decision taken.
- **(e) Frozen contracts.** Section 5 names the contracts as they exist on PR #8
  (`feat/ml-core`): `Scoring`, `RunRecord.scoring`, `RunRecord.atlas_coverage`,
  the `AttackInfo` ATLAS fields, `Measurement.severity`, the widened
  `RunConfig`, and the id-keyed `TARGETS` / `ATTACKS` registries. The MRI
  no-renormalize rule is restated beside them.
- **(f) Workstream status.** Section 4.1 maps our open and closed pull requests
  to the workstreams.
- **(g) Pythia access.** Section 5 carries the gateway facts a developer needs
  behind the corporate proxy.
- **(h) Demo-critical order.** Unchanged from D8. Section 7 is as in v2.

### v2 (2026-09-08): what changed since v1

v1 of this plan was written against a standalone `redsim/` package with a
filesystem store, a thread-pool, no auth, and no audit. That package was
**deleted on `main`**. The repository now:

- keeps the ML vertical in **`redsim/ml/`** (contracts only today), inside the
  full platform restored from the aegis head and renamed;
- is governed by a new canonical product spec,
  `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`, which
  supersedes both the hackathon spec and the lean redsim design spec;
- adds a **Spec Kit feature layer**, `specs/F001`–`F008`, as the feature-level
  source of truth beneath that product spec.

Every architectural assumption in v1 is overridden. The corrections are in
sections 2 and 5. Two things we had **missed** and now cover: authentication
(F001) and the audit chain (F008). One thing that was dropped in the first
consolidation and has since been re-adopted as Phase B2: interoperability (see
section 6).

## 1. Authoritative sources (in order)

1. `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`, the
   product spec, 27 sections. Decisions D1–D13 (section 4) are final and
   override every source. Section 27 (Interoperability) is Phase B2.
2. `docs/project-brief.md`, the governance brief. Its reporting principles are
   design constraints. "Decisions taken (2026-09-08)" records every decision
   and every knowing divergence from the brief and the constitution.
3. `specs/README.md` and `specs/00N-*/`, the Spec Kit feature layer
   (F001–F008), each with spec, plan, and tasks, plus
   `specs/_shared/{architecture,decisions,analysis}.md` (the D001–D007 register:
   D001–D005 resolved, D006 and D007 still open). Where a feature file
   conflicts with the product spec, the product spec wins.
4. This plan and its phase files (`docs/plans/`), the parallel-execution
   overlay.
5. `docs/architecture/*`, platform docs, still accurate for the platform.

Note on D7. The spec text of D7 and of reconciliation row 56 predates the
amendment and still reads "namespace `aegis`, vertical `aegis/ml/`, web app
`@aegis/web`". The product owner amended D7 on 2026-09-08 (later): the Python
namespace is `redsim`. Until those texts are refreshed, read every `aegis/…`
path, `aegis.…` import, `AEGIS_*` variable, `aegis-*` service and `@aegis/*`
package in the spec text, in item 7 of "Decisions taken" in
`docs/project-brief.md`, in the `CLAUDE.md` Naming section and in `README.md`
as `redsim/…`, `redsim.…`, `REDSIM_*`, `redsim-*` and `@redsim/*`. The plan
files in this directory and the `specs/` tree already use the `redsim` names
(commit `836b0e1`).

Note on `CLAUDE.md`. It was rewritten on 2026-09-08 (`ce3ee02`) onto the
platform architecture (Postgres, Celery, Keycloak, audit chain, `.venv` and
`make` workflow) and is no longer stale in the sense v2 meant. Its "Naming"
section and its environment table were written before the rename commit
`b39d933` and still say namespace `aegis` and `AEGIS_*`. Read those as
`redsim` and `REDSIM_*` until it is refreshed. Its "How to run things" and
"Working rules" sections are current. Build against it together with this plan.

## 2. Substrate correction (v1 → v2.1)

| Concern | v1 assumption (wrong now) | v2.1 authoritative (redsim platform) |
|---|---|---|
| Package | standalone `redsim/` (filesystem store, thread pool) | `redsim/ml/…` vertical inside the full platform (D7 as amended). The name survives, the substrate does not |
| Console script and CLI | none | `redsim` (`redsim ml build-assets`, `redsim ml attack`, `redsim audit verify`) |
| Persistence | filesystem `RunStore` on EFS | Postgres + RLS; run record as sha256 Artifact; `ml_campaigns` table; S3/MinIO for bytes (D1) |
| Run progress | `run.json` per stage | `Run.stage_table` JSON column + Redis run-event channel |
| Jobs | in-process thread pool `redsim/jobs.py` | Celery on Redis; admission→execution split; `redsim/workers/job_state.py`; task names prefixed `redsim.` |
| Model loading | in worker process | sandboxed child subprocess `python -m redsim.ml.sandbox_worker` (D2) |
| API | new `redsim/api/app.py:create_app` as a fresh app | routers under `redsim/api/v1/` mounted on the existing `redsim/api/app.py:create_app`; API title "Redsim API" |
| Auth | none | Keycloak OIDC + NextAuth + session cookie; role ranks `scanner<remediator<approver<admin` (F001) |
| Audit | none | hash-chained append-only audit + WORM to S3 (F008), inherited from aegis |
| Storage on AWS | EFS + RDS | RDS PostgreSQL 16 + ElastiCache Redis + **S3 (two buckets, one Object-Lock WORM); no EFS** |
| Config | `REDSIM_OUTPUT_DIR` and friends | `RedsimConfig` (`redsim/config.py`), `redsim.yaml`, `REDSIM_*` env (`REDSIM_DB_URL`, `REDSIM_BROKER_URL`, `REDSIM_BLOB_BACKEND`, `REDSIM_AUTH_MODE`, …) |
| LLM env | `REDSIM_LLM_MODEL` | `REDSIM_ML_LLM_MODEL`, via Pythia only. The M0 rename landed with P0 (`4350d38`): `redsim/llm/pythia.py`, `tests/test_llm_pythia.py` and `.env.example` use the new name, and PR #11 (`5fa2d79`) keeps the old one only as a deprecated alias |
| Services and images | two compose services | `redsim-api`, `redsim-worker` (`-Q scans`), `redsim-worker-default` (`-Q default`), `redsim-beat`, `redsim-web`, `redsim-log-ingest`; Helm chart `deploy/helm/redsim`; CI `.github/workflows/redsim-ci.yml` |
| Web | none | `@redsim/web` (Next.js 14, `web/`), `@redsim/design-system` (`packages/design-system/`), `NEXT_PUBLIC_REDSIM_API_URL`, cookies `redsim_api_session` / `redsim_csrf` |
| Demo data | CIFAR-10 | `leibnitz-lab/military_vehicles` (image, spec 11.3.1; `Illia56/Military-Aircraft-Detection` fallback) + Kaggle `sid321axn/malicious-urls-dataset` (tabular, CC0, spec 11.3.3); `lacg030175/UNSW-NB15` is the tabular fallback (11.3.4) and `mstz/spambase` the second fallback and CI tabular fixture (11.3.6); CIFAR-10 is the image CI fixture only (D3, D4(d)). Phase B, LLM track: garak's bundled probe corpora (spec 11.6), loaded by garak itself, Apache-2.0 packaging with upstream licences per subset |

## 3. Scope (canonical Phase A)

Image and tabular classifiers, both live end to end. Bundled models plus
white-box upload (ONNX preferred; PyTorch `state_dict` with declared
architecture; full pickles refused; loaded only in the sandboxed worker).
Attacks FGSM and PGD for image, PGD-surrogate and HopSkipJump for tabular, each
paired with a benign noise control, swept over ε `{0.01, 0.03, 0.1}` with a
robustness curve. The tabular target is a URL maliciousness classifier
(sklearn / XGBoost on lexical URL features) trained by the asset build on the
Kaggle malicious-URLs dataset. URL strings are inert data and are never fetched,
resolved or rendered, and feature-space perturbations carry the realizability
caveat of spec 12.9. SHAP explanations, the five-subscore MRI, deterministic
plus Pythia-written recommendations, the verify-after-harden loop with measured
ΔMRI, hash-chained audit, evidence and reports, the web UI, and Keycloak auth
with RLS. The spec states plainly that this scope exceeds a 1–2 day build.

Phase B, LLM track, outside the scope above. The B1 milestone's garak
probes through Pythia (D6) use the probe corpora garak ships under
`garak/data` (in-the-wild jailbreak prompts, the DAN templates, HarmBench,
Do-Not-Answer, RealToxicityPrompts subsets and the payload sets), recorded
in spec section 11.6. garak's probe classes and detectors load those files
themselves. Nothing is extracted or re-packaged for this tool. The garak
package is Apache-2.0 and each subset keeps its upstream terms. It is probe
material only, never a classifier dataset and never an MRI input (D9). No
workstream reads it in Phase A.

## 4. Workstreams for 3–4 developers

The canonical spec owns the decomposition twice over: milestones **M0–M7**
(build order) and features **F001–F008** (outcome verticals). This plan does not
invent a third. It assigns those to parallel workstreams and gives the
integration waves. Each workstream cites the milestone(s) and feature(s) it
delivers.

| WS | Owner | Milestones | Features | Deliverable |
|---|---|---|---|---|
| **WS0 Scaffold** | Backend lead | M0 | cross-cutting | `redsim/ml/` package, migration `0010_ml_vertical` (`targets.detail` JSONB + `ml_campaigns` table), schema freeze (`CampaignConfig`, `ScoringConfig`, `MRIRecord`, `MLFindingDetail`, `MLModelManifest`, `CampaignRecord`, landed on #18), new `Action` members + `viewer` rank, `ml` dep group (+`onnx2torch`, `safetensors`), env rename `REDSIM_LLM_MODEL` → `REDSIM_ML_LLM_MODEL`, `/v1/scans` unmounted, `redsim ml build-assets` CLI skeleton. Blocks all. **Merged** as `4350d38`. |
| **WS1 Catalog & ingest** | Dev A | M1, M4, M5b | F002 | `redsim/ml/targets/`, bundled-model seeding via `build-assets`, `POST /v1/models` upload, `model.validate` sandboxed task, `redsim/services/ml_models.py`, web `/models`. |
| **WS2 Attacks, engine & scoring** | Dev B | M1, M3, M4, M6 | F003, F004 | `redsim/ml/attacks/`, `campaign.py`, `eval.py`, `scoring.py`; the `attack.run` Celery chain (sample→clean_eval→control→attack); MRI + severity. |
| **WS3 Explain, recommend & findings** | Dev C | M2, M3, M6 | F005, F006 | `redsim/ml/explain/`, `recommend/{rules,narrative}.py`, `explain.run` / `harden.recommend` / `verify.replay` tasks, `Finding.schema_blob.ml` projection, dismissal + reviewer-notes routes. |
| **WS4 API & campaign service** | Backend lead | M1–M6 | F004 | routers `redsim/api/v1/{models,attacks,datasets,defenses,ml_capabilities,artifacts,compare,ml_findings}.py` mounted on `redsim/api/app.py`; `redsim/services/ml_campaigns.py`; WS events channel. |
| **WS5 Web UI** | Dev D | M5a, M5b | F005, F006, F007 UI | `@redsim/web` pages `/models`, `/models/[id]` launcher, 13-panel `/runs/[id]`, three-pane `/findings/[id]`; `@redsim/design-system` `MriScorecard`, `DimensionBars`, `RobustnessCurve`, `MeasurementTable`, `ObservationCard`. |
| **WS6 Reports & comparison** | rotates | M3, M6 | F007 | extend `redsim/report.py` to render the ML run record + scorecard; `GET /v1/runs/{id}/compare`; report Artifact rows. |
| **WS7 Infra, auth & deploy** | Dev D / lead | M7 | F001, F008 | ECS Fargate services (`redsim-api`, `redsim-worker`, `redsim-beat`, `redsim-web`, `redsim-log-ingest`) + ALB; RDS PostgreSQL 16; ElastiCache Redis; two S3 buckets (one Object-Lock); Secrets Manager; Keycloak on Fargate; activate the existing deploy pipeline. Reuse the audit chain (F008) already in the platform. |

F001 (auth) and F008 (audit) are largely **reused platform foundation**
(inherited from aegis), not new builds; the new work is emitting ML audit events
on the existing chain and wiring Keycloak on Fargate. These are the two features
v1 missed entirely.

### 4.1 Workstream status (2026-09-09, `main` at `703f8f6` plus wave B4)

Pull requests and direct commits on `IntelliBridge/ndia-red-team-simulator` as
of this revision. No names are invented for unassigned work (D007 stays open).
The rows are in merge order. The wave rows at the end are the completion
passes that followed PR #22 and the Phase B waves.

| WS | Branch / PR | State | Notes |
|---|---|---|---|
| WS0 Scaffold (M0, P0) | #18 `P0` (John Sasser) | **merged** into `main` as `4350d38` (2026-09-08, 868 passed and 30 skipped offline per the PR body) | Not ours. Freezes `redsim/ml/schema.py` under the spec 5.3 names (section 5), migration `0010_ml_vertical`, the seven ML `Action` members and the `viewer` rank, the `REDSIM_ML_LLM_MODEL` rename, `/v1/scans` unmounted, the `redsim ml build-assets` skeleton (`BUILD_ASSETS_STATUS = "not_implemented"`) and the lint baseline. PR #10 `feat/ml-db-migration` was **closed** earlier so that WS0 / P0 had one owner. A change to the frozen contract follows `01-p0-contracts-api-skeleton.md` section 8. Spec section 4.5 records the eight points P0 resolved in favour of the tree. |
| WS1 targets (pure part), WS2 attacks / engine / scoring, WS3 explain / recommend | #8 `feat/ml-core` | **merged** into `main` as `ce33d21` (2026-09-08) | Adapted to the frozen P0 schema before merge (`CampaignConfig`, `MRIRecord`, the enriched `Measurement` / `Observation` / `Provenance`), no P0-owned file changed. On `main` now: `redsim/ml/{registry,artifacts,errors,defenses,eval,scoring,campaign}.py`, `targets/` (`registry`, `bundled`, `tabular`, `artifact`, `unavailable`), `attacks/` (`registry`, `fgsm`, `pgd`, `hopskipjump`, `noise_control`), `datasets/` (`cifar10`, `image_hub`, `sampling`), `explain/` (SHAP image and tabular, `stability`, `summary`), `recommend/{rules,narrative}.py` and `docs/workstreams/ml-core.md`, with no platform imports. `import redsim.ml.targets, redsim.ml.attacks` registers the targets `cifar10_smallcnn`, `endpoint_stub`, `url_trees`, `vehicles_cnn` and the attacks `fgsm`, `hopskipjump`, `noise_control`, `pgd`. The follow-up `5bb382f` adds an autouse fixture in `tests/ml/conftest.py` that isolates every ML test from a developer's `.env`. The sandbox child, the Celery tasks and the routes stay with WS4. |
| WS1 assets (bundled-model seeding) | #9 `feat/ml-assets` | **merged** into `main` as `1725728` (2026-09-08) | Workstream `docs/workstreams/ml-assets.md`. `redsim ml build-assets` is real on top of P0's `redsim/cli/ml.py`: `--dataset {image,tabular,cifar10,all}`, `--only`, `--epochs`, `--out`, `--cache-dir`, `--seed`. `redsim/ml/assets/` fetches by pinned revision (HuggingFace hub, Kaggle with `KAGGLE_API_TOKEN` as a bearer token or the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair, else the committed CI sample), trains `SmallCNN` (`targets/architectures.py`) and the URL tree ensemble (`datasets/url_features.py`) on CPU with a fixed seed, and writes `assets/MANIFEST.json` on `MLModelManifest`. The `tests/ml/test_cli_ml.py` open point was reconciled in the PR. The assets were built locally on 2026-09-08 with `--dataset all`, are gitignored, and carry their clean accuracy in the manifest. |
| Cross-cutting: Pythia transport | #11 `feat/pythia-access` | **merged** into `main` as `5fa2d79` (2026-09-08) | Gateway URL, key provisioning, trust-store TLS, `.env` loading, `python -m redsim.llm.pythia_check`, `docs/ops/pythia.md` and `docs/workstreams/pythia-access.md`. Reads `REDSIM_ML_LLM_MODEL` as frozen by P0. Two follow-up commits (`6f4d06d`, `6a0b8b9`) isolate the `.env` discovery tests. See the Pythia note in section 5. |
| F008 audit foundation contract | #12 `feat/audit-log-foundation` (William) | **merged** | Contract doc for the audit chain the ML events append to. |
| Earlier contributions | #2 (schema and registry contract tests), #4 (CIFAR-10 target and asset pipeline), both by Metz | closed by their author | Superseded by the platform substrate. CIFAR-10 stays a CI fixture. |
| WS5 Web UI | #16 `feat/replit-redsim-migration` (Metz) | **merged** into `main` as `1a9204e` (2026-09-08) | Reworked by its author into a P5-only change that keeps the platform auth and adds `/models`, `/models/[id]`, the MRI panels on `/runs/[id]` and the three-pane `/findings/[id]` with the design-system evidence components (`MriScorecard`, `DimensionBars`, `RobustnessCurve`, `MeasurementTable`, `ObservationCard`, `LabelBadge`, `PanelSection`, `CompatibilityList`). The earlier Replit-port shape that D1 rejected is gone. codex-pr-review verdict blocking with 10 confirmed findings, one fix commit per finding landed before the squash merge, and `7240220` (product owner) tightened the `not_implemented` wording on the model pages afterwards. PR #22 (`a864da6`) then aligned `web/src/lib/api.ts` and the run and finding pages with the mounted WS4 routes. Wiring beyond that contract alignment and a Playwright browser e2e are open (section 8). |
| WS7 Fargate foundation | #19 `feat/p7-fargate-foundation` (William) | **merged** into `main` as `b40f7e1` (2026-09-08) | 26 new files under `deploy/terraform/`: existing-VPC selection with checks, private endpoints, an ALB with target groups but no listeners, RDS PostgreSQL 16, Redis, two S3 buckets (the audit bucket Object-Lock capable with no default retention), per-service IAM roles, mocked-plan tests behind `validate.sh`. No task definitions, no services, nothing applied. codex-pr-review verdict needs-changes with 2 confirmed findings (RDS storage autoscaling headroom validation, empty `plugin_args` expansion under Bash 3.2), both fixed on the branch before merge. |
| Docs | #20 `docs/refresh` | **merged** into `main` as `72eecc2` (2026-09-08) | README, CLAUDE.md, architecture and plan pages refreshed to the redsim / P0 truth, plus the Archify architecture diagrams under `docs/architecture/diagrams/`. |
| Web toolchain, CI, `viewer` role | #21 `ci/web-fixes` | **merged** into `main` as `ea39f97` (2026-09-08) | Reverts the #15 web bump (Next 14, React 18 and TypeScript 5 stay) and restores `pnpm-lock.yaml` to match, installs pnpm with `npm install -g pnpm@10.33.2` on `node:26` in `deploy/Dockerfile.web`, adds the `viewer` role to the Keycloak realm export and to the design-system `ROLES` with 0-based ranks matching `redsim/api/policy.py`. Redsim CI was fully green at this commit. |
| Dependabot | #13 (docker), #14 (actions), #15 (npm, `web/`) | **merged** (`ff24944`, `eb99386`, `4c928c5`) | Routine, with two regressions: #13 moved the web image to `node:26`, where corepack is gone, and #15 bumped `web/package.json` past the root lockfile. Both fixed by #21. |
| WS4 API & campaign service, WS6 reports & comparison | #22 (Metz) | **merged** into `main` as `a864da6` (2026-09-08) | Routers `redsim/api/v1/{ml_capabilities,attacks,datasets,defenses,models,artifacts,compare,ml_findings,reports}.py` mounted on `redsim/api/app.py`, `redsim/services/{ml_campaigns,ml_models,ml_findings}.py`, the tasks `redsim.ml_campaign_run` and `redsim.ml_model_validate` (`redsim/workers/tasks/{ml_campaign,ml_model}.py`), the sandbox child `redsim/ml/sandbox.py` and `sandbox_worker.py`, `GET /v1/runs/{id}/compare`, the report routes and the web contract alignment. Eight codex-pr-review findings were fixed on the branch before the squash merge. The per-attack chain of spec 10.3 was not built, and section 0 (v2.3) records the divergence. |
| Gap register and failure classes | `cc781ad` (direct) | on `main` | `redsim/ml/errors.py` gains the spec 10.6 classes. `docs/plans/09-gap-register-2026-09-08.md` is the 560-item spec-vs-tree register, audited against `a864da6`, with the four-wave execution order. |
| Completion wave 1 (libraries and contracts) | `f8693c2..a99d9cc`, seven commits (direct) | on `main` | WS1: manifest-shaped loaders, onnx2torch agreement, `--fixture` and the committed CIFAR-10 slice, `resnet18` behind `--arch`, `url_trees`. WS2: surrogate PGD with per-feature ε and the ART mask, capability tags, scoring constants, the binomial control predicate, `FamilyDelta`, typed delta refusal, `not_run` attacks, curve PNG, caveats, `TinyTabularTarget`. WS3: PartitionExplainer fallback, explanation cache, spec artifact names. WS6: the six-section report renderer. WS4: typed sandbox config and envelope, `redsim/api/errors.py`. |
| Completion wave 2 (worker, audit, admission) | `055bdee..bb43bd7`, eight commits (direct) | on `main` | Spec 10.5 audit vocabulary and 6.5 stage table, parent-side Pythia narrative with router, budget and `LLMUsage`, typed validate envelope with parent digest check and `job.complete`, worker observability init with the `job.run` span and cancel-safe `task_context`, spec 17.3 codes on every ML route, per-project bundled ids and `register_bundled_model`, audited soft delete, refusal audit rows, spec 5.7 finding projection and dismissal rules, compare incompatibility and `verify_delta`, report routes with `report.pdf` as `501`, `GET /v1/audit/verify?all=1`, dataset caveats and `subject_centered` in the manifest. `bb43bd7` is the integration commit. |
| Completion wave 3 (CLI, config, seeding, e2e harness) | `7556b22..58461cc`, ten commits (direct) | on `main` since 2026-09-09, integrated by `58461cc` | `7556b22`: `redsim doctor` rewritten around Pythia (informational Pythia block with the key redacted, `ml` extra, sandbox child and assets manifest checks required in worker mode, the `ml-campaign` roster check, no provider key), `redsim.yaml` and `redsim init` without a provider-style `model` (`task_models: {}`), `.env.example` Pythia-only with every spec 20.3 ML variable. `39126ce`: the `resnet18` fine-tune recipe (lr 3e-4 with cosine decay, random flip and reflect-pad crop, best epoch on a per-class 10 percent validation slice held out of the training split, recorded in the manifest `training` block). `3ab9de7`: `redsim ml attack <target_id>` (an offline campaign for a bundled target writing `<out>/<run_id>/{run_record.json, report.md, report.json, report.html, artifacts/curve/robustness_curve.png, audit.jsonl}` with the `attack.run` row first on a `JsonlAuditWriter` chain, `narrative_source = "rules"`, `endpoint_stub` and fixture-only targets refused before anything is written), `redsim ml seed [--project] [--only]`, `CampaignScannerAdapter` (`ml-campaign`, capabilities `adversarial_ml` and `explainability`) registered at `import redsim.scanners`, opt-in `redsim.ml.attacks` entry-point discovery (`REDSIM_PLUGINS=1`, `REDSIM_PLUGINS_ALLOW`, Ed25519). `35e71c7`: `tests/e2e/{conftest,harness}.py` gated by `REDSIM_E2E`, `REDSIM_E2E_POSTGRES_URL` for the RLS lane, `REDSIM_E2E_SANDBOX`. `aa9674e`: audit chain `ts` canonicalised to the UTC isoformat on write and read (`canonical_ts`, no migration, old rows still verify), `redsim audit verify --run` falling back to `<output_dir>/<run_id>/audit.jsonl` and the new `--run-dir PATH`. `c3868e5`: the sandbox child pins `REDSIM_ENV_FILE` to the absent `<work_dir>/no-env` and sets `REDSIM_DISABLE_LLM=1`, `GET /v1/attacks` loads the plugins once per process and answers with a `plugins` block (`503 ml_plugins_unavailable` on a loader failure), `redsim doctor --worker-mode`. `dd2bbd4`: admission strips the grid-owned `eps` and `norm_l2` and freezes caller keys only, applicability by `modality:<domain>` capability tag. `98a8733`: `redsim ml seed` reconciled with the real `register_bundled_model` (keyword extras, `Target` return, `already_registered`, one commit per model, route-parity refusal rows). `a45a787`: the harness reconciled with the tree (per-project bundled ids, the tz shim now a guarded no-op, parent-side Pythia mock, propagate-off eager Celery, one autocommit sqlite connection) plus `tests/e2e/test_harness_smoke.py`, 8 cases through the real sandbox child. `58461cc`: integration, admission admits a white-box attack on a gradient-free model when the adapter declares `surrogate_transfer` and the target declares a surrogate (PGD on `url_trees`, the defect the smoke test had reported), and the tests other tracks flagged aligned. |
| Completion wave 4 (end-to-end completion criteria, CI fixes, documentation) | `3dda572..e73dea0`, seven commits (direct) | on `main`, integrated by `e73dea0` (2026-09-09) | `3dda572` `tests/e2e/test_ml_campaigns.py`, `35662e4` `tests/e2e/test_ml_verify_upload_reports.py`, `6a8a534` `tests/e2e/test_ml_governance.py` on the wave-3 harness (22 e2e cases with the smoke file, 22 passed at `29db42c` with the Postgres lane), `d8a9f15` the CI fixes (`python-multipart` in the `api` extra, the `redsim.ml.datasets.sampling` / `redsim.ml.targets` import cycle, a `.trivyignore` entry for the `next` advisory with its reason, the asset builder's torch imports made lazy so the 3.13 lane's `tests/ml/test_cli_ml.py` cases pass without the `ml` extra), `8eb8870` admission refuses a control or `fgsm` on the L2 grid at admission and plugin loading is idempotent, `ae8d77c` the v2.4 documentation pass, `e73dea0` integration. Whether the fixes turn CI green is proven by a run on `main`, which this revision has not read. |
| Phase B register, plan and brief | `938bbe4`, `8ef7a88`, `7706950` (direct) | on `main` | `docs/plans/10-remaining-work-brief.md` (packages A to F, section H coordination with the waves), `docs/plans/11-phase-b-register-2026-09-09.md` (309 items audited against `10650da`) and `docs/plans/12-phase-b-plan.md` (five waves; a dated status line per wave since this revision). |
| Web: tRPC and env management, design reference | #24 (`b93d9a9`), #25 (`6cbb661`) | **merged** | Web-side only; no Python file changed. The web UI stays the Phase B plan's one deferral. |
| Phase B wave B0 (contracts, tripwires, stubs, datasets) | `934838e..29db42c`, eight commits (direct, pushed `6cbb661..29db42c`) | on `main` at `29db42c` (2026-09-09) | `934838e` schema-additive (every plan 12 section 3 field, section 0 note), `a625583` tripwires and CI (`tests/ml/test_schema_compat.py` pinning the frozen fixture's sha256, the extended API-process import block and child-env credential check, the `garak` marker and `garak>=0.16,<0.17` pin, the `e2e-python` and `garak-offline` jobs, `docs/dev/ci.md`), `7b1f2fa` migration `0011_phase_b_platform` with ORM models and RLS parity tests, `3cd3362` seven Phase B `Action` members and 23 codes with the rego and Cedar mirrors and the spec 7.4 and 17.3 addenda, `0b0981b` the 19 route stubs behind their real gates (`docs/api/v1.md` "Phase B routes"), `ff9e658` datasets (SMS Spam Collection, WordNet 3.0, the military-assets subset, the `vehicles_cnn` training slice, `redsim/ml/atlas_data.py` at ATLAS `v2026.08`, the garak reference entry, public repository commits `a9ba6ba3` and `4048a209`), `622d741` the `endpoint-v1` contract and egress policy, `29db42c` integration (three test-side edits for `exclude_unset` and `defense_apply`; no production code). Checks: default tier 2081 passed, 35 skipped, 1 deselected; e2e 22 passed; ruff and mypy (197 files) clean; `mkdocs build --strict` clean; the frozen fixture unchanged. Open items carried forward: `tenant_reconcile` scope, `DatasetSource` literals, the `build.py` slice wiring, the `expected_stages` emission and the artifact kinds (all closed by the B1 integration), the B2 and B3 items listed in the plan's status lines, and the two owner decisions MODALITIES-27 and the `dataset.export` role. |
| Phase B wave B1 (library layer) | eight commits, rebased onto `29db42c`, pushed `29db42c..1439f92` | on `main` at `1439f92` (2026-09-09; default tier 2257 passed, 35 skipped, 1 deselected; `ml` tier 418 passed, 1 skipped; e2e 22 passed; mypy 220 files; the counts every later document quotes) | `refactor(ml): split run_campaign into a frame plus modality runners` (`redsim/ml/campaign.py`, `redsim/ml/runners/{base,classification}.py`, the golden test with the frozen pre-refactor copy), `feat(ml): text modality target, attack, SHAP text and runner` (`datasets/sms_spam.py`, `assets/train_text_classifier.py`, `targets/text.py`, `attacks/word_substitution.py`, `explain/shap_text.py`, `runners/text.py`), `feat(ml): detection modality with DPatch, patch control and scorecard` (`datasets/military_assets.py`, `targets/detection.py`, `attacks/dpatch.py`, `assets/train_detector.py`, `runners/detection.py`), `feat(ml/attacks): CW-L2, DeepFool, ZOO adapters, norms tags, HSJ image defaults` (`attacks/{cw_l2,deepfool,zoo,hopskipjump,registry,__init__,base}.py`, measured CPU budgets), `feat(ml/explain): KernelSHAP for predict-only tabular targets, endpoint caps` (`explain/base.py`, `explain/shap_tabular.py`), `ml: EndpointTarget, worker-parent PredictBroker, sandbox socket plumbing` (`endpoint_broker.py`, `targets/endpoint.py`, `sandbox.py`, `sandbox_worker.py`, the tiny endpoint server), `ml(harden): training defenses catalog, defense_apply trainers, tests` (`defenses.py`, `harden/{apply,adversarial_training,distillation}.py`), and the integration commit (stale registry and catalog pins in `tests/ml/test_attacks.py` and `tests/ml/test_defenses.py` updated to filter and superset semantics, then the B0 reconciliation: schema literals read directly, the contract and egress modules imported, the endpoint error classes re-exported from `redsim/ml/errors.py`, `targets/__init__` and `attacks/__init__` registration, `expected_stages` and the artifact kinds in the worker, `tenant_reconcile` over the `0010` and `0011` tables, `DatasetSource` `uci` / `github`, `build-assets --dataset text` / `detection` and the training slice). Library only: no route, no admission change. Checks before the rebase: ruff and mypy (213 files) clean, 206 passed in the writers' files, default tier 1840 passed and 31 skipped in a worktree without B0's tests. |
| Phase B wave B2 (services, workers and routes over the B1 library) | eight track commits plus `fix: integrate Phase B wave B2 tracks`, written in a worktree on `b404eb8`, rebased onto `1439f92`, pushed with v2.6 | on `main` at `57da31f` (`fix: integrate Phase B wave B2`) | By subject (section 0, v2.6): `api: add thirteen Phase B error codes; dataset.export to remediator` (`redsim/api/errors.py`, the spec 17.3 second addendum, `redsim/api/policy.py`, the Rego and Cedar bundles), `feat(ml): endpoint registration, validate via broker, projections` (`redsim/api/v1/models.py`, `redsim/services/ml_models.py`, `redsim/workers/tasks/ml_model.py`), `worker: endpoint broker lifecycle, derived-target registration, retests (Phase B B2)` (`redsim/workers/tasks/ml_campaign.py`), `admission(ml): modality table, norm checks, endpoint budget, project scoring` (`redsim/services/ml_campaigns.py`), `ml(llm): garak through Pythia core: catalog, generator, probe child, scorecard` (`redsim/ml/llm/`, eleven files with `catalog.json`, `tests/ml/fake_openai_server.py`), `feat(llm): probe routes, admission, worker, scorecard and findings` (`redsim/api/v1/llm.py`, `redsim/services/ml_llm.py`, `redsim/workers/tasks/ml_llm.py`, `redsim/workers/celery_app.py`, `redsim/services/ml_findings.py`), `review: transition table, resolve gates, retest links, analyst drafts` (`redsim/services/finding_review.py`, `redsim/api/v1/ml_findings.py`), `reports: PDF projection, snapshots, N-run compare, weights API, idempotency` (`redsim/ml/pdf.py`, `redsim/ml/pdf_fonts/`, `redsim/ml/compare.py`, `redsim/ml/reporting.py`, `redsim/services/reports.py`, `redsim/api/v1/{reports,compare,projects,batches}.py`, `redsim/api/middleware/idempotency.py`, `redsim/api/app.py`, `pyproject.toml`), and the integration commit (six test pins, the `Target.value` URL fallback in the worker, the environment-preserving `litellm` import). 69 routes under `/v1` afterwards: 39 Phase A, 16 built by B2 (five former stubs, eleven new paths), 14 stubs left for B3. Checks before the rebase: ruff and mypy (236 files) clean, 251 passed and 1 xfailed in the writers' ten files, the default tier 2431 passed with 17 base failures the B1 integration fixed on `main`, 11 `garak`-marked tests green; The B2 integration pass re-ran every tier on the rebased tree (default 2480 passed, 35 skipped; `ml` 420 passed, 1 skipped; garak 12; e2e 22; mypy 236 files; ruff clean). Open after B2: the README's "Wave B2 follow-ups". |
| Phase B wave B3 (interoperability and bulk operations) | five track commits plus `fix: integrate Phase B wave B3 tracks`, the reconcile commits `f718f10` and `5f02ac6`, the docs commit `4da7193`, written in the worktree `wt/waveb3` on the B2 integration, rebased onto it, pushed with v2.7 | on `main` at `703f8f6` (`fix: integrate Phase B wave B3`; default 2634 / `ml` 433 / `garak` 12 / `e2e` 22, the counts every later document quotes) | By subject (section 0, v2.7): `feat(interop): Croissant/Parquet dataset export of a campaign run` (`interop-contribute`: `redsim/ml/interop/{__init__,parquet,croissant,card}.py`, `redsim/services/ml_datasets_export.py`, `redsim/workers/tasks/dataset_export.py`), `interop(consume): POST /v1/datasets static admission, sandboxed Parquet parse, binding hook` (`interop-consume`: `redsim/api/v1/datasets.py`, `redsim/services/ml_datasets.py`, `redsim/ml/interop/consume.py`, `redsim/workers/tasks/dataset_validate.py`), `bulk: batch campaigns, roll-up, cancel, compare groups, bulk verify` (`bulk-service-routes`: `redsim/services/ml_batches.py`, `redsim/api/v1/batches.py`, `redsim/ml/compare.py`, the `batch_id` mirror in `tests/e2e/harness.py` and `tests/ml/test_campaign_routes.py`), `feat(ml): bulk upload, per-project capacity/deferral, CLI attack matrix` (`bulk-upload-capacity-cli`: `redsim/api/v1/models_bulk.py`, `redsim/api/app.py`, `redsim/services/ml_capacity.py`, `redsim/workers/tasks/capacity.py`, `redsim/workers/celery_app.py`, `redsim/cli/ml.py`, `redsim/observability.py`), `interop(atlas,foundry): ATLAS stamp and coverage, Foundry push, roster` (`atlas-foundry`: `redsim/ml/atlas.py`, `redsim/integrations/{__init__,foundry}.py`, `redsim/workers/tasks/integration_push.py`, `redsim/api/v1/integrations.py`, `redsim/services/ml_findings.py`, `redsim/api/v1/attacks.py`, `tests/ml/fake_foundry_server.py`), and the integration commit (the Celery `include` list, the B0 export stub removed, `tests/ml/test_phase_b_stubs.py` as the surface pin). 69 routes under `/v1` afterwards, the 14 B0 stubs replaced one for one; thirteen Celery tasks. Checks (the assembler's worktree at `a780d88`): ruff and mypy (253 files) clean, the six writers' test files 140 passed and 1 skipped, the surface pin 61 passed, the e2e smoke file 8 passed; then at the B3 integration on the rebased tree the default tier 2634 passed, 35 skipped, 13 deselected, `ml` 433 passed, 1 skipped, `garak` 12, `e2e` 22, `mkdocs build --strict` exit 0. The public data repository is at `0dababc` with the first export sample. Open after B3 and closed by the wave B4 fix pass except the worker-parent consumed-slice call, the dataset push and a real Foundry push: the README's former "Wave B3 follow-ups". |
| Phase B wave B4 (e2e evidence, gate, docs) | four track commits `f1e6cad`, `2e00ce7`, `6484f2c`, `3836c48` (written in `wt/waveb4` on the B3 integration, rebased onto `703f8f6`), the fix pass (`fix-api-services`, `fix-worker-runners`, `fix-gate-ci`) and this documentation pass, pushed with this revision | landing on `main` with v2.8 | Section 0 (v2.8) lists the subjects. `tests/e2e/` gains seven files; `scripts/phase_b_gate.sh` behind `make check-phase-b` is the Phase B definition of done; `tests/test_docs_phase_b_consistency.py` is its docs half. The e2e files report product defects by attribution rather than weakening an assertion, and what they left open (the unscaled endpoint probe, no training slice exposed to the child, the worker-parent consumed-slice call, `architecture_kwargs` for `state_dict` uploads, the PDF `LayoutError`, three stale report pins) is in the README's open items. The B4 tree's counts are the assembler's to record. |
| WS7 Fargate runtime | #23 `feat/p7-fargate-runtime` (William) | **merged** into `main` as `10650da` (2026-09-09), applied by its author | `deploy/bootstrap/` and `deploy/runtime/`: a dedicated VPC and state bootstrap and a private Fargate runtime behind public HTTPS at https://redsim.ndia.agiledefense.xyz with ACM and DNS, Keycloak, separate migration tasks, service-scoped secrets and immutable images. The PR body reports it applied to account `140381642432` in `us-east-1`, migrated through `0010_ml_vertical` (the runtime has to migrate to `0011` with the next rollout), with public health, login and OIDC discovery answering 200 and unauthenticated API access 401. Workers stay at zero until a pinned asset bundle is supplied, demo users and project memberships and real model assets are outstanding, and automatic ECS rollout stays disabled until CI can advance pinned task definitions and run migrations. `deploy/runtime/README.md` is the deployment sequence (with a rough 200 dollars a month core estimate). Its completion is package E of `docs/plans/10-remaining-work-brief.md`, outside the Phase B waves. No campaign has been run on it. |
| Cross-cutting: CI on `main` | Redsim CI | red at `58461cc` (run 34307513075); wave 4 landed the fixes; no run after `58461cc` has been read (not `e73dea0`, `7706950`, `6cbb661`, `29db42c` with the first `e2e-python` and `garak-offline` jobs, `1439f92`, `57da31f`, `703f8f6`, nor the B4 push, the first with the gate script in both lanes, the `garak` extra in `e2e-python`, the 30 minute e2e timeout and the exit-5 rule gone), so no state after `58461cc` is recorded here and nothing is claimed green. Local tiers were green at `703f8f6`; the B4 tree is described in section 0 (v2.8) | Red from `1725728` through `7240220` at the mypy step (`no-any-return` in `redsim/ml/datasets/image_hub.py` with `truststore` typed `Any`, and on 3.13 `redsim/ml/assets/train_cnn.py` without the `ml` extra), both since typed. At `bb43bd7` and again at `58461cc` three jobs fail and the rest pass: the Coverage gate (23 upload-route tests in `tests/ml/test_models_routes.py` and `tests/test_review22_models.py` fail with "The `python-multipart` library must be installed to use form parsing", 1668 pass, coverage 88.89 percent over the 81 percent floor), Unit tests (py3.13) (at `bb43bd7` a collection error from the `redsim.ml.datasets.sampling` / `redsim.ml.targets` import cycle, at `58461cc` two `tests/ml/test_cli_ml.py` cases reaching `redsim.ml.assets.build` and `torch` without the `ml` extra) and Dependency CVEs (trivy: `next` 14.2.35, CVE-2026-75604 / GHSA-2xp9-vwfh-vxw4, fixed in 15.5.24 and 16.3.3). Unit tests (py3.12) passes at both. The Next.js build, API integration and image builds are skipped behind the unit lane. `Deploy to AWS` built and pushed the three images under OIDC on the `58461cc` push (the AssumeRole step that failed on the `bb43bd7` push now succeeds) and skipped its deploy job (`ECS_CLUSTER` unset). Wave 4 lands `python-multipart` in the `api` extra, breaks the import cycle and baselines the `next` advisory in `.trivyignore`, and makes the asset builder's torch imports lazy (`redsim/ml/assets/build.py`) so the 3.13 lane's two `tests/ml/test_cli_ml.py` cases pass without the `ml` extra (`docs/dev/ci.md`). Nothing is claimed green until a run on `main` proves it. The last fully green run was `ea39f97` (#21). Local checks at `58461cc` with the venv interpreter and the `ml` extra: `pytest -q tests --ignore=tests/e2e` 1663 passed and 30 skipped, `REDSIM_E2E=1 pytest -q -m e2e tests/e2e` 8 passed, `ruff check --select E4,E7,E9,F,I redsim tests` clean, `mypy redsim` clean (190 files). |

## 5. Corrected shared contracts

- **Schema** (`redsim/ml/schema.py`): the `RunRecord`/`Measurement`/`Observation`/
  `Interpretation`/`CandidateRecommendation` evidence model stays. It is written
  as a sha256-addressed Artifact (`ml.run_record`) and **projected** onto
  `ml_campaigns.score` and `findings.schema_blob.ml`; a projection that
  disagrees with the record is a bug. Frozen on `main` by P0 (PR #18,
  `4350d38`) under the spec 5.3 names. Read the module in full before
  building against it. The shapes, in brief:
  - `CampaignConfig` replaces `RunConfig`: `target_id`, `modality`,
    `attack_ids`, `attack_params`, `norm`, `eps_grid` (strictly ascending,
    each in (0, 1]), `reference_eps` (a member of the grid),
    `finding_asr_threshold`, `n_samples`, `seed`, `include_control`,
    `explain_k`, `dataset_id`, `dataset_revision`, `dataset_split`,
    `scoring: ScoringConfig`, `defense: DefenseConfig | None`,
    `llm_narrative`, `auto_recommend`, `target_snapshot`, `attacks`.
  - `ScoringConfig`: `version`, `weights: MRIWeights` (0.35 / 0.25 / 0.20 /
    0.10 / 0.10, validated to sum to 1), `severity`, `confidence` and
    `interpretation` thresholds. `finding_asr_threshold` is not inside it.
  - `MRIRecord` (`RunRecord.score`) replaces `Scoring` and
    `RunRecord.scoring`: `scoring_version`, `weights`, `eps_grid`,
    `reference_eps`, `norm`, `attack_ids`, `finding_asr_threshold`,
    `settings_hash`, `inputs: list[MRIInputRow]`, `per_attack: dict[str,
    PerAttackSubscores]`, `subscores: Subscores` (`S_acc`, `S_asr`, `S_eps`,
    `S_conf`, `S_expl`), `mri`, `grade`, `completeness`, `missing`,
    `reading`, `delta: MRIDelta | None`, `computed_at`. It refuses an `mri`
    without all five subscores, a `grade` that does not match the band
    (`schema.grade_for_mri`) and a `reading` with a banned readiness word.
    Weights are never renormalised.
  - `Measurement` has **no `severity` field**. Severity is finding-level
    (`MLFindingDetail`, `SeverityThresholds`, spec 15.5). It gains the scoring
    inputs (`n_clean_correct`, `attack_success_rate`, `pert_first_success_*`,
    `conf_gap_*`, `expl_shift_mean`, `expl_shift_n`, `expl_shift_n_excluded`,
    `expl_shift_noise_floor`, `expl_shift_noise_floor_n`, `queries_mean`), and
    `params` values may be `str`.
  - `AttackInfo` gains `phase`, `access`, `requires_gradients`, `status` and
    `reason` with defaults. It has **no ATLAS fields**, and there is no
    `RunRecord.atlas_coverage`: ATLAS is Phase B2 through
    `MLFindingDetail.atlas_technique: AtlasTechnique(id, name,
    atlas_version)`, "never back-filled by guesswork". Keep the
    attack-to-technique mapping as a module-level constant for B2 and stamp
    nothing on records in Phase A.
  - `Provenance` gains `baseline_run_id`, `dataset_revision`, `defense`,
    `llm`, `onnxruntime`, `parent_run_id`, `sample_indices_sha256`,
    `settings_hash`, `sklearn`, `thread_env` and `xgboost`.
  - `CandidateRecommendation.validation` is `Literal["not evaluated",
    "measured"]`, paired with `measured: MeasuredDelta | None`. A candidate
    carries no numeric gain until a verify run measures a delta.
  - `RunRecord` rejects dangling citations (`Interpretation.basis` and
    `CandidateRecommendation.triggered_by` must name existing measurement or
    observation ids) and carries `score: MRIRecord | None`. `RunStatus`
    includes `cancelled`. `CampaignRecord` extends it with `kind`,
    `completed_at`, `settings_hash`, `baseline_run_id`, `parent_run_id`,
    `curve: list[RobustnessCurve]`, `completeness`, `missing` and
    `score_status`. `RunSummary.attack_ids` replaces `attack_id`.
  - `standing_limitations(dataset_name, eps_grid)` builds the per-campaign
    limitations list. `STANDING_LIMITATIONS` no longer carries the CIFAR-10
    sentence.
  - `Provenance.redsim_version` (was `aegis_version` in the spec text).
  The WS0 / WS2 naming question of v2.1 is closed: P0 merged with the spec
  names, so the `RunConfig` and `Scoring` shapes on PR #8 are superseded and
  #8 is being adapted to P0's names and semantics (section 4.1). A change to
  the frozen contract follows `01-p0-contracts-api-skeleton.md` section 8:
  announce it first and prefer additive optional fields.
  Phase B additions (wave B0, 2026-09-09; the section 0 v2.4 change note has
  the detail), every one additive and default-valued so a Phase A record
  validates unchanged:
  - `Domain` and `Modality` gain `text` and `detection` (MODALITIES-01).
  - `Norm` gains `edit` and `patch_area` (MODALITIES-02).
  - `Measurement.edit_fraction_mean` and `Measurement.detection:
    DetectionMetrics | None` (MODALITIES-03).
  - `Observation.text: TextObservation | None` and `Observation.detection:
    DetectionObservation | None` (MODALITIES-04).
  - `MLModelManifest.text: TextModelSpec | None` and `.detection:
    DetectionModelSpec | None` (MODALITIES-05).
  - `MLModelManifest.endpoint: EndpointSpec | None` (ENDPOINT-03).
  - `MLModelManifest.derived_from: DerivedFrom | None` (ATTACKS_HARDEN-15).
  - The four manifest blocks are omitted from dumps while `None`, so
    `manifest_sha256` of pre-Phase-B manifests is unchanged.
  - `ReviewState` gains `draft`, `in_review`, `confirmed`, `resolved`;
    `FindingReview.history: list[ReviewEvent]` and `FindingReview.revisions:
    list[FindingRevision]` (REVIEW_REPORTS-01).
  - `MLFindingDetail.retests: list[FindingVerify]`; `FindingVerify.settings_hash`
    and `FindingVerify.baseline_run_id` (REVIEW_REPORTS-08).
  - `CampaignRecord.schema_version: str = "campaign-record-1"`
    (REVIEW_REPORTS-18).
  - `RunSummary.kind: RunKind | None` and `RunSummary.probe_ids: list[str]`
    (LLM-24).
  - `STAGES` gains `defense_apply` after `load_target`; `report` stays last
    (ATTACKS_HARDEN-15).
- **Registries** (`redsim/ml/registry.py`): one id-keyed `Registry[T]` class
  with `register(item)` (`TypeError` when the item misses a non-empty string
  `id` or fails the protocol check, `DuplicateRegistration` on a repeated id),
  `get(id)` (`KeyError` on unknown), `maybe_get(id)`, `ids()` (sorted),
  `items()`, `__contains__`, iteration in id order, `len()`, and a `clear()`
  test hook. Singletons `TARGETS` (`redsim/ml/targets/registry.py`,
  `Registry[Target]`) and `ATTACKS` (`redsim/ml/attacks/registry.py`,
  `Registry[AttackAdapter]`). Concrete targets and adapters call
  `register(...)` at import. This is distinct from the name-keyed
  `redsim.registry.Registry` that does entry-point discovery for the platform.
  Phase B wave B1 adds two more tables that are not registries: the modality
  runner map `MODALITY_RUNNERS` (`redsim/ml/runners/base.py`, one
  `"module:attribute"` per `Modality` literal, resolved lazily) and the
  defense catalog split `DEFENSES` (preprocessing, the set the Phase A verify
  admission treats as runnable) / `TRAINING_DEFENSES` / `ALL_DEFENSES`
  (`redsim/ml/defenses.py`, every row with `kind` and `phase`). Since B1 the
  attack registry holds `cw_l2`, `deepfool`, `dpatch`, `fgsm`,
  `hopskipjump`, `noise_control`, `patch_noise_control`, `pgd`,
  `word_substitution`, `zoo`, checked at import against the declared list.
  Since B2 the admission service carries `SUPPORTED_MODALITIES`
  (`redsim/services/ml_campaigns.py`, one `ModalitySpec` per `Modality`
  literal: norms, default grids, `n_samples` default and cap, endpoint and
  `mri` flags) and the LLM track a committed probe catalog
  (`redsim/ml/llm/catalog.json`, read with json and pydantic only).
- **Actions** (`redsim/api/policy.py`): the seven ML members frozen by P0
  (`model.register` remediator, `attack.run` scanner, `explain.run` scanner,
  `harden.recommend` remediator, `finding.review` approver,
  `finding.annotate` remediator, `report.export` scanner) plus, since Phase B
  wave B0 (`3cd3362`, spec 7.4 addendum), `llm.probe.run` remediator,
  `dataset.register` remediator, `dataset.export` remediator (scanner at B0
  from the brief's wording; wave B2 `codes-b2` aligned the three policy
  files to spec 17.4 and 27.4), `integration.push` admin, `batch.run`
  scanner, `report.render` scanner, `finding.author` remediator. Mirrored
  verbatim in `deploy/opa/redsim-authz.rego` and
  `deploy/cedar/redsim-policy.cedar`; `tests/test_policy_ml_actions.py`
  parses both mirrors and asserts equality with the Python table. The gate is
  checked before the handler runs, so an under-ranked caller gets `403` and
  learns nothing about the route; since wave B3 every Phase B member gates a
  real handler (`dataset.register` the consume route, `dataset.export` the
  export route, `integration.push` the Foundry push, `batch.run` the batch
  admission). Endpoint and LLM registration (wave B2) gate on
  `target.manage`, not `model.register`; the bulk upload (wave B3) gates on
  `model.register` like the single upload.
- **Artifact sink** (`redsim/ml/artifacts.py`): `ArtifactSink` protocol
  (`put(name, data, content_type) -> run-relative path`, `sha256(name)`) and a
  `FilesystemSink` for tests. The Celery task adapts the blob store and
  `Artifact` rows to this protocol. Pure modules never import the platform.
- **Errors** (`redsim/ml/errors.py`): `MLError` and its subclasses
  `TargetUnavailable`, `UnsupportedArtifact`, `AttackNotApplicable`,
  `ExplainUnavailable`, plus the spec 10.6 failure classes added in
  `cc781ad`: `ModelLoadRefused` and `ArtifactDigestMismatch` (both under
  `UnsupportedArtifact`), `SandboxTimeout`, `SandboxKilled`,
  `EnvelopeInvalid`, `DatasetUnavailable`, `MlExtraUnavailable` and
  `ExplainerUnavailable` (under `ExplainUnavailable`). Phase B adds the
  typed library states `ModalityRunnerUnavailable`
  (`modality_runner_unavailable`, `redsim/ml/runners/base.py`),
  `TrainingDefenseUnavailable` (`training_defense_unavailable`,
  `redsim/ml/harden/apply.py`), `LexiconUnavailable` (`lexicon_unavailable`,
  an `AttackNotApplicable`), and the endpoint classes `EndpointError`,
  `EndpointUnreachable`, `EndpointAuthFailed`, `QueryBudgetExceeded` in
  `redsim/ml/errors.py` with `EndpointSchemaMismatch`, `EgressRefused`,
  `EndpointUrlInvalid` and `EndpointNotAllowlisted` re-exported from the
  contract and egress modules, all rebuilt by name from the child's envelope.
  Wave B2 adds the probe child's `probe_child_failed`,
  `probe_child_timeout` and `probe_child_cancelled`
  (`redsim/ml/llm/runner.py`) and the LLM job refusals of `LLMProbeRefused`.
  These are run and infrastructure states, never model outcomes. The HTTP
  side is `redsim/api/errors.py`: the spec 17.3 code table, the dated Phase
  B addendum of 23 codes (wave B0, `3cd3362`), the second dated addendum of
  13 codes (wave B2, `api: add thirteen Phase B error codes; dataset.export
  to remediator`), `ApiError`, and the `{"detail": {"code", "message", ...}}`
  envelope every ML route returns, and since wave B4 the third dated
  addendum of 10 codes (`attestation_required`, `scoring_weights_invalid`,
  `model_id_invalid`, `model_not_chat`, `gateway_url_required`,
  `unknown_probe`, `probe_excluded`, `probe_detector_unavailable` 422;
  `llm_probe_quota_exceeded` 429; `endpoint_auth_failed` 502), the codes the
  B2 routes had resolved by `getattr`; `tests/ml/test_error_codes.py` parses
  all three addenda. One `errors.py` row plus one addendum row land together
  when a wave adds a code.
- **Migration**: `0010_ml_vertical` adds `targets.detail` (JSONB) and
  `ml_campaigns` (1:1 with `runs`, full RLS parity). Additive and reversible.
  Owned by WS0. The frozen head moved once, under the plan-01 section 8
  protocol, on 2026-09-09 (Phase B wave B0, `7b1f2fa`, REVIEW_REPORTS-44):
  `0010_ml_vertical` to `0011_phase_b_platform`, one additive reversible
  revision with six DDL groups, `report_snapshots`, `idempotency_keys`
  (primary key `(project_id, key)`), `projects.ml_scoring` /
  `ml_max_concurrent_runs` / `ml_daily_run_budget`, `ml_campaigns.batch_id`
  (nullable, indexed, no FK), `ml_batches` and `ml_datasets`, every new table
  with `0010`'s RLS parity token for token. `ml_campaigns` stays
  migration-owned (no ORM model); the four new tables have ORM models.
- **API** (all under `/v1`, on the redsim app, auth + RLS enforced): a campaign
  starts with `POST /v1/models/{id}/attacks`, **not** a generic `POST /v1/runs`.
  Read the campaign at `GET /v1/runs/{id}/campaign`; stream a blob at
  `GET /v1/artifacts/{id}`; act on findings via `POST /v1/findings/{id}/{explain,harden,verify}`;
  compare with `GET /v1/runs/{id}/compare?with=` (pairwise) or
  `GET /v1/runs/compare?ids=` (2 to 10 runs, wave B2). Read a report at
  `GET /v1/runs/{id}/report.{md,json,html,pdf}` (`pdf` since wave B2, a
  `404` until `POST /v1/runs/{id}/report.render` produced it) and verify the
  chain at `GET /v1/audit/verify?run=` or `?all=1` (the `{"chains": [...]}`
  shape the audit page renders). All of these are mounted on `main` since PR
  #22 and wave 2. `POST /v1/scans` was unmounted by P0 (`4350d38`) and
  `POST /v1/targets` refuses ML kinds with `400 use_models_route`. Since
  Phase B wave B0 (`0b0981b`) every Phase B route is mounted behind its real
  gate; wave B2 replaced five stubs with real handlers (`GET /v1/llm/probes`,
  `POST /v1/models/{id}/probes`, `GET /v1/runs/{id}/llm-scorecard`,
  `POST /v1/runs/{id}/report.render`, `GET /v1/runs/{id}/snapshots`), added
  eleven paths (`GET /v1/runs/compare?ids=`, the snapshot detail, archive and
  restore routes, `GET`/`PUT /v1/projects/{slug}/ml-scoring`,
  `POST /v1/findings/{id}/review[/{transition}]`, `GET /v1/findings/{id}/retests`,
  `POST /v1/findings`, `PATCH /v1/findings/{id}/draft`), and made
  `POST /v1/models` with `source: endpoint` real (predict endpoints and, with
  `endpoint_kind: llm`, LLM targets). Wave B3 replaced the 14 routes that
  remained with their handlers and added no path: `POST /v1/runs/{id}/dataset`
  and `GET /v1/datasets/{id}` (the Croissant export and its manifest),
  `POST /v1/datasets` (a consumed Parquet slice), `GET
  /v1/runs/{id}/atlas-coverage`, `GET /v1/integrations` and `POST
  /v1/runs/{id}/integrations/foundry` (the roster and the push, off by
  default), `POST`/`GET /v1/campaigns/batch`, `GET .../{id}`, `GET
  .../{id}/compare`, `POST .../{id}/cancel`, `POST /v1/models/bulk`, `POST
  /v1/findings/{id}/verify/bulk` and `GET /v1/ml/capacity` (`docs/api/v1.md`
  "Phase B routes", `docs/interop.md`). No route is a `501` stub; the `501`s
  that remain are documented non-builds with a reason. The mutating ML
  routes honour `Idempotency-Key` since B2, the B3 routes included. The
  `endpoint-v1` predict contract for `source: endpoint` registrations is
  `docs/api/endpoint-contract.md`.
- **Jobs** (as shipped, section 0 v2.3 divergences 1 and 2): two ML Celery
  tasks, `redsim.ml_campaign_run` and `redsim.ml_model_validate`, both on
  the `scans` queue (`redsim/workers/celery_app.py`), plus the ML branch of
  `redsim.report_render` on `default` and, since wave B2,
  `redsim.ml_llm_probe_run` on `default` (the only pool with Pythia egress;
  `Job.type = llm.probe`, `Run.scanner = ml.llm_probe`, no `ml_campaigns`
  row), and since wave B3 `redsim.dataset_export` (`Job.type =
  dataset.export`, `Run.scanner = ml.dataset_export`, a follow-up run) and
  `redsim.ml_dataset_validate` (`Job.type = dataset.validate`, `Run.scanner
  = ml.dataset_ingest`, no target) on `scans`, `redsim.integration_push`
  (`Job.type = integration.push`, `Run.scanner = ml.integration_push`, a
  follow-up run) on `default`, the pool with egress, and the beat task
  `redsim.ml_dispatch_deferred` every 60 s on `default` (thirteen tasks;
  `task_routes` unchanged, the B3 modules registered through `include`). A
  batch campaign is N `attack.run` jobs with `batch_id` stamped, a bulk
  verify one `verify.replay` job per `(defense, params)` and a bulk upload N
  `model.validate` jobs with `bulk_id`. One `ml_campaign_run` job runs a whole attack campaign
  (`Job.type = attack.run`). The follow-on jobs `explain.run` and
  `harden.recommend` (from `POST /v1/findings/{id}/explain` and `/harden`)
  and `verify.replay` (from `POST /v1/findings/{id}/verify`) are separate
  jobs on the same task. `report.render` jobs (from
  `POST /v1/runs/{id}/report.render`, wave B2) run on `redsim.report_render`
  and write one `report_snapshots` row each; since wave B4 the campaign
  completion path renders all four formats itself and records the run's
  first snapshot, a bulk verify projects its one record onto every listed
  finding, and every single-run admission consults the capacity service.
  There is no per-attack chain.
  Admission is audit-first: the audit event is appended before any Run/Job
  row and before `task.delay`, and a failed enqueue removes the rows and
  answers `503 queue_unavailable`. The worker emits the spec 10.5 vocabulary
  (`model.load`, `attack.execute.<id>`, `explain.execute`, `campaign.score`,
  `harden.execute`, `verify.execute`, `report.render`, `job.complete`, and
  since B2 `llm.probe.entitlement`, `llm.probe.execute.<probe>`,
  `llm.probe.score`, plus `model.register` when it registers a derived
  model) as `worker:<job.type>` with `requested_by` in the detail. Since B2
  `ml_model_validate` dispatches on `Target.kind`: uploads load in the
  sandbox child, endpoints are probed through the worker-parent broker with
  the `AuthProfile` credential resolved at pickup.
- **MRI** (unchanged formula): `round(0.35·S_acc + 0.25·S_asr + 0.20·S_eps +
  0.10·S_conf + 0.10·S_expl)`, computed **only when all five subscores exist**,
  **weights never renormalized** over the available dimensions (spec 15.4: the
  scorecard then shows the available subscores and "MRI not computed:
  <dimension> unavailable (<reason>)"), per campaign only, never shown without
  its subscores, per-family table with denominators, and ε curve.
  `MRIRecord.weights` records the vector used. A non-default vector puts a badge
  on the scorecard and makes the campaign incomparable with any other. Grade
  text is attack-scoped; the words "hardened", "deployment-ready", "certified",
  "safe" are banned. ΔMRI is the only sanctioned form of "gain" and appears only
  on a verify run whose `settings_hash` matches its baseline.
- **Env**: `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`,
  `PYTHIA_TIMEOUT_S`, `REDSIM_ML_LLM_MODEL`, `REDSIM_ML_WORK_DIR` (and the other
  `REDSIM_ML_*` knobs of spec 20.3). LLM calls go through
  `redsim/llm/pythia.py` under the platform router and budget. The M0 rename
  landed with P0 (`4350d38`): `PythiaSettings.from_env` reads
  `REDSIM_ML_LLM_MODEL`, `.env.example` and `tests/test_llm_pythia.py` use
  that name, and PR #11 (`5fa2d79`) keeps `REDSIM_LLM_MODEL` only as a
  deprecated alias.
- **Pythia access** (cross-cutting, PR #11, merged as `5fa2d79`, facts as
  reported by that workstream on 2026-09-08 and kept in `docs/ops/pythia.md`): the gateway is
  `https://pythia.fdet.agiledefense.xyz`, reached through the corporate Zscaler
  proxy. The team key is entitled to 27 models, including
  `amazon/nova-lite-v1:0` (the id `tests/test_llm_pythia.py` uses) and the
  router alias `pythia/auto`. `curl` works because it uses the macOS keychain.
  Python clients (`httpx`, `requests`) fail with `CERTIFICATE_VERIFY_FAILED`
  unless they use the system trust store: either `import truststore;
  truststore.inject_into_ssl()` (`truststore` is installed in `.venv`) or
  `SSL_CERT_FILE` pointing at a bundle that contains the Zscaler root
  (`deploy/certs/README.md`). `uv` needs `--native-tls` for the same reason.
  The worker's `default` pool is the only process that makes the call. The API
  and the sandbox child have no Pythia egress.

## 6. Interoperability, decision taken: spec section 27, Phase B2

The interop work John added to the hackathon spec (S1 §14, commit `4acdb85`)
was missing from the first consolidation. It has since been **re-proposed and
adopted** into the product spec as section 27 (reconciliation row 57) and as
milestone **B2 | Interop** in spec section 23. It sat behind every Phase A item
and behind B1+ (D8), was built as Phase B wave B3 (`interop-contribute`,
`interop-consume`, `atlas-foundry`; `703f8f6`) and proven end to end where it
can be in wave B4 (`tests/e2e/test_ml_interop.py`). Nothing in it changes D1
to D14: D3, D5 and D9 bind it. `docs/plans/07-p6-interoperability.md` (v2)
and `docs/interop.md` describe it as built; the paragraphs below are the
decision as taken.

What B2 delivers, in the consolidated vocabulary:

- **Contribute.** `POST /v1/runs/{id}/dataset` builds a **Croissant**
  (MLCommons JSON-LD) manifest over a Parquet payload from a terminal campaign
  or verify run: clean and adversarial inputs, true / clean / adversarial
  labels with confidences, attack id, norm, ε, `flipped`, and the source-slice
  indices with dataset id, revision and split. Content-addressed
  (`croissant.json` lists each file's sha256, and the manifest sha256 is the
  dataset version), written under `datasets/<run-id>/` and registered as
  `Artifact` rows (`ml.dataset.manifest`, `ml.dataset.parquet`,
  `ml.dataset.card`). `GET /v1/datasets/{id}` returns the manifest. Tabular
  exports carry feature vectors only, never URL strings. Imagery exports stay
  in the team bucket while D006 (export redaction) is open.
- **Consume.** Another team's model arrives as ONNX through the existing upload
  path (section 9 rules unchanged). Another team's evaluation slice arrives as
  Croissant + Parquet through `POST /v1/datasets`, parsed only in the sandbox
  child, refused without a license statement, and never compared with a
  campaign on a bundled dataset (D9(i)).
- **MITRE ATLAS.** Every Finding is tagged with the technique it demonstrates:
  `fgsm` / `pgd` → `AML.T0043 Craft Adversarial Data`, `hopskipjump` →
  `AML.T0040 ML Model Inference API Access`, `noise_control` → none. S1's path
  `Finding.schema_blob.atlas_technique` resolves to
  `Finding.schema_blob.ml.atlas_technique` because all ML detail lives in the
  `ml` block. The mapping is declared beside the attack registry as a
  module-level constant (P0 froze `AttackInfo` without ATLAS fields and
  `RunRecord` without `atlas_coverage`), recorded with the ATLAS version it
  was checked against (spec 27.4), and B2 adds the per-campaign coverage view
  of spec 27.2 that lists the techniques exercised. Coverage is a description
  of the declared attack set, never a score.
- **Platform pushes.** Palantir **Foundry** is primary (scorecard and dataset
  written as Foundry datasets, always with subscores, denominators, ε points,
  `settings_hash` and the grade sentence). Anduril **Lattice** is exploratory
  and **text-only**: it conflicts with the D3 bound "no mission-system
  connections" and cannot be enabled without an explicit product-owner
  decision and a constitution amendment proposal. Both are env-selected, off by
  default, hold no standing credential, and make no LLM call.

Where it stands after wave B4: the export, the consume side, the ATLAS stamp
and coverage view and the Foundry push exist as decided (`redsim/ml/interop/`,
`redsim/ml/atlas.py`, `redsim/integrations/`), the mapping is checked at
import against the vendored release, every new finding is stamped, and the
Lattice entry stays text only. Open: the worker-parent materialisation of a
consumed slice for the target loader (INTEROP-16 remainder), the dataset push
(INTEROP-23), a push against a real non-operational instance (INTEROP-26).
The web controls for these routes are part of the web UI deferral.

## 7. Integration waves and demo-critical order

Build order follows D8, not numeric milestone order (unchanged in v2.1):

```
Gate 0:  WS0 (M0 scaffold + migration)            ── blocks all
Slice 1: F001 auth · F002 catalog · F008 audit    ── foundation (WS1, WS7 auth)
Slice 2: F003 profile · F004 runs · F005 evidence ── the engine (WS2, WS3, WS4, WS5)
Slice 3: F006 findings · F007 reports/compare     ── the tools (WS3, WS6)
```

Gate 0 cleared on 2026-09-08 with PR #18 (`4350d38`), so Slices 1 to 3 build
against the frozen section 5 contracts.

Where the slices stand at `58461cc` (2026-09-09):

- Slice 1 is on `main`: F001 auth and F008 audit were inherited, F002 catalog
  landed through #8, #9, #22 and waves 1 and 2 (bundled and uploaded targets,
  `redsim ml build-assets`, `POST /v1/models`, `redsim.ml_model_validate`,
  `register_bundled_model`).
- Slice 2 is on `main`: F003 profiles and F004 runs through #22 and wave 2
  (admission, `redsim.ml_campaign_run`, the sandbox child, the stage table,
  the audit vocabulary), F005 evidence through #8 and wave 1 (SHAP,
  explanation cache, artifact kinds). The web pages of #16 were aligned to
  these routes in #22.
- Slice 3 is on `main`: F006 findings (projection, dismissal, explain and
  harden follow-ons, the verify loop with `MeasuredDelta`) and F007 reports
  and compare (the six-section renderer, the report routes, `verify_delta`
  and `side_by_side` compare).
- The completion passes then ran as the four waves of
  `docs/plans/09-gap-register-2026-09-08.md`: all four are on `main` (wave 4
  integrated by `e73dea0`).
- Phase B runs as the five waves of `docs/plans/12-phase-b-plan.md`. B0
  (contracts, tripwires, stubs, datasets) is on `main` at `29db42c`; B1 (the
  library layer) is on `main` at `1439f92`; B2 (services, workers and routes
  for B1: the endpoint connector, Phase B admission, the worker wiring, LLM
  probes through Pythia, the review workflow, reports with PDF, snapshots,
  N-run compare, weights and idempotency, the 13 codes) is on `main` at
  `57da31f`; B3 (interoperability and bulk: the Croissant export and the
  consumed-slice admission, ATLAS stamping and coverage, the Foundry push off
  by default, batch campaigns, bulk upload, bulk verify, per-project
  capacity, the CLI matrix) at `703f8f6`; B4 (the seven e2e files, `make
  check-phase-b`, the docs-consistency test, the fix pass and this
  documentation) is pushed with this revision. No Phase B route is a `501`
  stub; the plan carries a status line per wave and spec 26.7 tags each
  completion criterion with its decision and its open state.

Demo-critical path (D8, spec 3.4): image path end to end → MRI scorecard →
verify-after-harden → tabular path → ONNX upload → Fargate deploy. **M5a (the
image UI slice) is the cut line for a demo.** Against that path at `1439f92`
plus waves B2 and B3: the image and tabular paths, the scorecard, the verify
loop and the ONNX upload exist in code, are covered by the unit suite, and
run end to end through the real sandbox child in the 22 e2e cases of
`tests/e2e/` on synthetic assets (22 passed at `29db42c`, `1439f92`, `57da31f`
and `703f8f6`, and on every PR in the `e2e-python` CI job since wave B0);
since wave B4 the text, detection, LLM, review, report, interop and bulk
paths run end to end in the seven B4 files too, and the endpoint campaign,
the training-defense verify, the consumed-bound campaign and the bulk
`state_dict` upload fail there by attribution until the defects in the
README's open items close. No campaign has been run on a
deployed stack: the runtime of #23 (`10650da`) has no workers and no assets
yet (brief package E). Phase B was planned to wait behind Fargate; the plan of
2026-09-09 runs its waves in parallel with the brief's packages, with
section H of the brief as the coordination contract.

## 8. Definition of done (canonical section 26) and where it stands

The target, unchanged: the demo runs live on ECS Fargate. A campaign started
from `/models` against the bundled vehicle-imagery CNN and the bundled URL
maliciousness classifier (Kaggle malicious-URLs dataset, UNSW-NB15 only if the
fallback had to be used, and then the campaign says so) runs FGSM and PGD with
the noise control and ε sweep. `/runs/[id]` shows the MRI scorecard with its
subscores, per-family table and robustness curve. `/findings/[id]` shows the
three panes and a measured ΔMRI after Verify. Every action is on the audit
chain and `redsim audit verify` passes. Access is gated by Keycloak with RLS.
`pytest` and `vitest` pass.

Where it stands at `703f8f6` plus wave B4 (2026-09-09). This is a
description of the tree, not a completion claim:

- In code, covered by the unit suite and run end to end through the real
  sandbox child by the e2e tier on synthetic assets: the bundled image,
  tabular, text and detection targets and the upload path, FGSM, PGD
  (surrogate transfer on tabular), HopSkipJump, CW-L2, DeepFool, ZOO, word
  substitution and DPatch with their controls over the eps grid, the MRI with
  its five subscores and the no-renormalize rule (never for detection or an
  LLM probe run), the per-family table and curve, SHAP evidence (Partition,
  Kernel and text explainers where gradients are absent), the rules and the
  Pythia narrative under router and budget, the verify loop with
  `MeasuredDelta`, the six-section reports in four formats with immutable
  snapshots, pairwise and N-run compare, the spec 10.5 audit trail, RBAC on
  every mutating route, RLS on every Phase B table, the review workflow, the
  endpoint connector's registration and refusals, garak probes through the
  fake gateway, the Croissant export and the consumed-slice admission, ATLAS
  stamping and coverage, the Foundry push against the fake server, batches,
  bulk upload, bulk verify, per-project capacity and the CLI matrix. The
  offline `redsim ml attack` path (single target and matrix) and `redsim ml
  seed` exist and are tested.
- Not yet holding end to end, by attribution in the B4 e2e files (the README's
  open items): an endpoint campaign through the tiny server (the unscaled
  probe), a training verify that registers a derived target (no training
  slice exposed to the child), a campaign on a consumed-bound model (the
  worker-parent materialisation call), a `state_dict` upload for a dataset
  with other than 10 classes (`architecture_kwargs`).
- Local assets, built with `redsim ml build-assets` on 2026-09-09 and
  gitignored, so a fresh clone has none until it runs the build. The numbers
  below are illustrative local manifest values from one build, not results:
  `url_trees` clean accuracy 0.9087 on n=128224 with surrogate agreement
  0.7891, `vehicles_cnn` as `resnet18` 0.7687 on n=1621 `test_coarse`,
  `cifar10_smallcnn` 0.6872, fixture only. Quote such numbers from the
  manifest of the build in hand.
- Checks of record at `703f8f6`, run locally with the venv interpreter and the
  `ml` extra: default tier 2634 passed, 35 skipped, 13 deselected; `ml` 433
  passed, 1 skipped; `garak` 12 passed; `e2e` 22 passed with the Postgres
  lane; ruff and `mypy redsim` (253 files) clean; `mkdocs build --strict`
  exit 0. The B4 tree's counts are the assembler's to record; read from it
  before this pass, one stale default-tier pin
  (`tests/ml/test_audit_campaign.py:113`) and the e2e attributions above.
  `make check-phase-b` exists and has not been run against `make up`. No CI
  run on `main` after `58461cc` has been read (section 4.1). No green CI run
  is claimed.
- No campaign has been run on a deployed stack. The Fargate foundation (#19)
  has no task definitions or services; the runtime of PR #23 (`10650da`) is
  reported applied with workers at zero and no assets or demo users yet
  (brief package E).

Excluded from the completion passes and listed as open, in the README as
well:

- Web UI wiring beyond the PR #22 contract alignment, pages for the Phase B
  surfaces, and a Playwright browser e2e (the Phase B plan's one deferral).
- Fargate, Terraform, Helm apply and compose operations from this tree, the
  PR #23 runtime follow-ups (pinned asset bundle, demo users and memberships,
  the `0011` migration, automatic rollout) and the gate against `make up`.
- The items the B4 e2e files left open by attribution, above.
- The fallback datasets (UNSW-NB15, spambase, the aircraft image fallback)
  and the other recorded non-builds (`adv_patch`, KernelSHAP for images, a
  detection explainer, the DNS-TXT ownership check, the pickle override,
  Lattice, the dataset push to Foundry, an LLM narrative for probe results,
  `text` and `detection` consumed slices).
- Every spec 26 criterion that needs a named human reviewer: 26.18 (the
  upload sign-off, so the upload dialog stays disabled and says why), 26.25
  to 26.27 (readiness checklists, approval records and the separate "done"
  record). D006 and D007 stay open and no owner is invented for them.
- The owner decisions of plan 12 section 2, each applied at its recommended
  default and open for the owner to overrule.

## 9. Status of the P0–P7 phase files

The eight phase files `01`–`08` in this directory were written for v1 against
the deleted standalone `redsim/` substrate and then rebased. Their state as of
v2.3:

- `01` closes with a dated Landed note (PR #18, `4350d38`). Its section 8 is
  the change protocol for everything P0 froze, and the divergences the tree
  keeps are recorded under it in section 0 (v2.3) of this file.
- `02`–`05` carry v2 bodies rebased onto the platform (commit `836b0e1`
  flipped every path and identifier in them to the `redsim` names) and, since
  v2.3, open with a dated "Landed status" block that lists what is on `main`
  at `bb43bd7`, what lands with wave 3, and what is still open. Those blocks
  were written at `bb43bd7` and not refreshed in v2.4, so read their wave-3
  items as landed (section 4.1 has the shas). The bodies below those blocks
  still read as the pre-merge plans and were not rewritten. Where a body names a file or task that the tree spelled
  differently (`targets/image_vehicles.py`, `workers/tasks/attack.py`, the
  six task names of `05` section 4), the Landed block and the tree win.
- `06` and `08` carry v2 bodies. `06` (web UI) has the #16 pages and the #22
  contract alignment on `main` and the rest open. `08` (infra) has the #19
  Terraform foundation on `main` and nothing applied. Neither was refreshed
  in this pass.
- `07` was rewritten in v2.8 (Phase B wave B4) onto the spec section 27
  vocabulary as built: objective, scope as built with the out-of-scope
  decisions, the seams the tree provides, the routes, what an export
  contains, the consume side and its open worker-parent call, the Foundry
  payload guard, the build order, the files, the tests, the acceptance
  criteria with where each stands and the recorded divergences. Its v1 body
  is gone; `docs/interop.md` is the narrative and the tree wins over both.
- `08` carries its v2 body under a dated status banner (v2.8): PR #19 is the
  Terraform foundation, PR #23 merged as `10650da` and is reported applied
  with workers at zero, its completion is brief package E.
- `09-gap-register-2026-09-08.md` is the spec-vs-tree register audited at
  `a864da6`. Its rows are kept as found at audit time and a header paragraph
  records the status after waves 1 to 3 at `58461cc` and names the wave-4
  files.
- `EXECUTION-CONTEXT.md` was refreshed in v2.3 (modules on `main`, the CLI
  surface, the spec 20.3 environment variables, the local assets and the
  portable TLS options), in v2.4 (wave 3, the e2e tier, the CI state, PR #23)
  and in v2.8 for the B4 tree (the Phase B packages and routes, thirteen
  tasks, the Phase B environment variables, the gate, the worktree rule, the
  attributed open items, the Phase B doubles and e2e files).
- `10-remaining-work-brief.md` (packages A to F and the section H
  coordination contract), `11-phase-b-register-2026-09-09.md` (the 309-item
  Phase B register audited against `10650da`, rows kept as found) and
  `12-phase-b-plan.md` (the five waves) were written on 2026-09-09. Since
  v2.5 the plan carries a dated "Status" line under each wave: B0 landed at
  `29db42c`, B1 at `1439f92`, B2 at `57da31f`, B3 at `703f8f6`, B4 with this
  revision (v2.8), and a dated status paragraph under its section 6
  completion checks. The register's rows are not edited as items close; its
  header paragraph (v2.8) says which ids landed in which wave, which stay
  open by owner decision and which stay open by attribution, and the plan's
  status lines and section 4.1 of this file are where closure is recorded.
  `docs/interop.md` (v2.7) is the narrative of the interoperability as
  built.

Use the phase files for the parallel-execution shape, not for the literal
contracts. The canonical spec, `specs/F00#` and the tree win over any body.
