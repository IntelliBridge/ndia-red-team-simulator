# End-to-end tier (`tests/e2e`)

The e2e tier drives one adversarial-ML campaign through the **real** API, the
**real** admission services, the **real** Celery task bodies (eager, in
process), the **real** ML sandbox (a child process by default) and the **real**
CLI, against a tiny asset tree built with the **real** `redsim.ml.assets`
builder. Nothing is stubbed on the redsim side except three things that need
infrastructure the harness does not have: the Celery broker (eager mode), the
Redis event publisher (no-op) and the Pythia gateway (an `httpx.MockTransport`,
off unless a test switches it on). Register row: G-TESTS. Spec: sections 22.5
(end-to-end and CI), 24 (demo script) and 26 (completion criteria).

The fixtures live in `conftest.py`; the builders and plain helpers live in
`harness.py`. `test_harness_smoke.py` is the harness's own smoke test against
the tree (asset build, bundled registration, one role gate, an image campaign
through the real child, tabular campaigns, `audit verify --all` clean then
broken, the mocked narrative flipping `narrative_source`). Wave 4 added the
completion-criteria files `test_ml_campaigns.py`,
`test_ml_verify_upload_reports.py` and `test_ml_governance.py` here (see
"State at `58461cc` and the wave-4 files" below), and Phase B wave B4 added
the seven files of "Phase B wave B4 files" below; none of them edits the
fixtures.

## Running

```sh
# the harness smoke test (about 30 s on a laptop CPU; the two asset builds dominate)
REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e/test_harness_smoke.py

# the whole tier
REDSIM_E2E=1 pytest -q -m e2e tests/e2e

# one file, verbose, keep the sandbox work directories for inspection
REDSIM_E2E=1 REDSIM_ML_KEEP_WORK_DIR=1 pytest -q -m e2e tests/e2e/test_ml_campaigns.py -vv

# run the campaign sandbox in-process instead of as a child (a traceback instead of
# a child envelope when debugging; the child-process boundary is then not exercised)
REDSIM_E2E=1 REDSIM_E2E_SANDBOX=inprocess pytest -q -m e2e tests/e2e

# the tier as the Phase B gate and the e2e-python CI job run it: one invocation,
# -rs, the stack and gateway variables scrubbed, the Postgres RLS lane on when
# REDSIM_E2E_POSTGRES_URL names a migrated database (the step fails if the
# harness still reports "Postgres lane is off"); `make check-phase-b` runs every step
scripts/phase_b_gate.sh --only e2e
```

Requirements: the `ml` extra (torch, ART, scikit-learn, SHAP) plus the `api`
and `worker` extras; the `garak` extra for `test_ml_llm.py`, which is
`garak`-marked as well and is skipped at collection without it
(`tests/conftest.py`; the `e2e-python` CI job installs the extra for that
reason). No network, no Kaggle, no Docker, no Redis; Postgres only for the RLS
lane.

**Running from a git worktree.** The tier spawns subprocesses: the ML sandbox
child (`python -m redsim.ml.sandbox_worker`) and the CLI
(`redsim audit verify --all`). They import `redsim` through the editable
install, which points at the checkout that ran `make install`, so from that
main checkout nothing is needed, while from a worktree they would silently run
the *other* tree. Put the worktree first on `PYTHONPATH`
(`PYTHONPATH=$PWD REDSIM_E2E=1 pytest -q -m e2e tests/e2e`); the sandbox
allowlist forwards it to the child (`redsim/scanners/sandbox.py`
`_SAFE_ENV_KEYS`) and `E2EApp.cli_env` prepends it for the CLI.
`scripts/phase_b_gate.sh --only e2e` detects the mismatch itself (it resolves
`redsim` from a neutral directory), prints a notice and sets the variable for
the step.

Gating is automatic. Every item collected under `tests/e2e` is stamped `e2e`
by `conftest.py`, so:

* `pytest -q` (the default tier; `addopts` deselects `e2e`) runs nothing here;
* `pytest -m e2e tests/e2e` without `REDSIM_E2E` **skips** everything with a
  message rather than failing;
* `REDSIM_E2E=1 pytest -m e2e tests/e2e` runs the tier.

`-m e2e` on the command line overrides the `-m` in `addopts`. Collection needs
neither the `api` nor the `ml` extra: `conftest.py` and `harness.py` import
only the standard library and pytest at module level.

## State at `58461cc` and the wave-4 files

At `58461cc` (2026-09-09, the wave-3 integration commit)
`REDSIM_E2E=1 pytest -q -m e2e tests/e2e` is 8 passed: the smoke file runs
the asset build, bundled registration, the role gate, an image campaign and
two tabular campaigns (PGD by surrogate transfer plus HopSkipJump plus the
control, and HopSkipJump plus the control) through the real sandbox child,
`audit verify --all` clean then broken, and the four narrative states.
Without `REDSIM_E2E` the same command is 8 skipped, and `pytest -q tests/e2e`
is 8 deselected.

The completion-criteria evidence of spec 26 is added in wave 4 as three files
on this harness, written in parallel with this page:

| File (added in wave 4) | What it asserts | Spec 26 items |
|---|---|---|
| `test_ml_campaigns.py` | an image campaign on `vehicles_cnn` (FGSM, PGD, the control, the default grid, `explain_k > 0`) reaches `succeeded` and the campaign body carries clean, evasion and control measurements with denominators, SHAP observations, a five-subscore scorecard with grade and per-family table, interpretation, recommendations and non-empty limitations. The tabular campaign on `url_trees` (PGD by surrogate, HopSkipJump, the control) has its own MRI, never compared with the image one, with the realizability caveat on every row. Each runs with the Pythia mock on and off and `narrative_source` flips between `llm` and `rules` | 4 to 9, 12 to 15 |
| `test_ml_verify_upload_reports.py` | verify-after-harden with `feature_squeezing` re-runs the frozen slice and `GET /v1/runs/{verify}/compare?with={baseline}` answers `verify_delta` with a measured ΔMRI and per-dimension deltas, and no bare gain appears before it. An ONNX export uploads to `available` with gradients and a pickled `.pt` is `415 pickle_refused` with a `success=False` `model.register` row. `report.md`, `report.json` and `report.html` carry the six sections and the scorecard sub-block, and `report.pdf` is `404` until a `POST report.render` writes it (the completion path renders md/json/html) | 2, 15, 17, 24 |
| `test_ml_governance.py` | the RBAC negative matrix per mutating ML route (viewer, scanner and the campaign creator refused where the spec requires), the RLS negatives on the Postgres lane (a cross-organisation read of an `ml_campaigns` score returns nothing), `redsim audit verify --all` passing over a completed campaign chain and failing after one event is mutated, and `GET /v1/ml/capabilities` carrying neither the Pythia key nor the base URL | 20 to 22 |

A partial score in any of these is the honest state (`score` absent,
`score_status` present, `mri` null with the missing dimension named as a
limitation), never a number to assert on.

## Phase B wave B4 files

Plan 12 wave B4 (`docs/plans/12-phase-b-plan.md`) added the end-to-end
evidence for everything waves B0 to B3 built, on the same fixtures. Each file
drives the production route, the admission service, the eager worker and the
real sandbox child, then asserts on what those left behind; where a finding is
needed, it comes from an **uploaded** `SmallCNN` that memorises the harness's
seeded images (the bundled 1-epoch CNN cannot yield one), and nothing measured
is a demo result. A test that meets a product defect fails with an
attribution naming the module (`pytest.fail(..., pytrace=False)` prefixed
"product defect, not a harness problem"), never with a weaker assertion.

| File | What it drives | Spec / register |
|---|---|---|
| `test_ml_endpoint.py` | the black-box endpoint connector against `tests/ml/tiny_endpoint_server.py` on the loopback interface: `POST /v1/models` `source=endpoint` and its refusal codes, validation through the worker-parent broker to `available`, a black-box campaign, the refusal of a white-box attack, egress and credential boundaries, the audit chain | 9.1, 17.2, 17.3, 21.7, 26.2 item 7, 26.3 items 12 to 14, 26.4 items 17, 20, 21, 26.5 item 22; ENDPOINT-20..23 |
| `test_ml_llm.py` | garak probe runs through the gateway contract against `tests/ml/fake_openai_server.py`: the probe catalog (HarmBench excluded), LLM target registration gates, the probe-run gates and one end-to-end run with k/n scorecards that never enter an MRI. `garak`-marked: needs the extra | 11.6, 15.9, 17.4, 21.7, 26.4 item 20, 26.5 item 22; LLM-30 |
| `test_ml_text_detection.py` | text (`sms_tfidf_lr`, word substitution under an edit budget, the harness synonym table) and detection (`assets_frcnn_mnv3`, patch area) campaigns on tiny assets the module builds with the real builders; each modality's scorecard is its own and detection has no MRI | TESTS_DOCS-08, -09; MODALITIES-47 |
| `test_ml_attacks_harden.py` | norm tags enforced at admission, an L2 campaign (PGD, CW-L2, DeepFool) with minimal-norm rows and the control, ZOO, and a training defense (`adversarial_training`, `defensive_distillation`) verify that registers a derived target | TESTS_DOCS-10; ATTACKS_HARDEN-21, -23 |
| `test_ml_review_reports.py` | the review workflow (states, independence, conflicts, retests, resolution), `report.pdf` with immutable snapshots and archive, `GET /v1/runs/compare` over three runs with no aggregate, `Idempotency-Key` replay and reuse, per-project scoring weights on the next campaign | 6.4, 7.7, 14.8, 15.3, 15.6 to 15.8, 17.3, 26.3 items 12 to 15, 26.5 item 22; REVIEW_REPORTS-02..12, -16..22, -26, -30..32 |
| `test_ml_interop.py` | Croissant export and shards, a consumed slice bound to a model and a campaign, ATLAS technique tags and coverage, the Foundry push against `tests/ml/fake_foundry_server.py`, `audit verify --all` over the lot | 27.1 to 27.5, 26.5 item 22; INTEROP-05..16, -18, -20..25, -27..29 |
| `test_ml_bulk.py` | batches, bulk upload (two state_dicts and the file cap), capacity deferral, dispatch and batch cancel, bulk verify projected onto every selected finding (owner decision BULK-16), single-run admission against the caps, the CLI matrix | owner requirement 5; BULK-03..09, -13..18, -20..22, -26, -30..32 |

The count of record for the tier is the gate's e2e step (`scripts/phase_b_gate.sh
--only e2e`, the `e2e-python` CI job); this page pins no pass count because the
B4 files were written against the B3 tree and report product defects by
attribution while those are being fixed.

## What the fixtures give you

All session-scoped unless noted; the graph is
`e2e_harness_dir -> e2e_env -> e2e_assets -> e2e_app -> e2e_org -> e2e_bundled`.

| Fixture | Type | Provides |
|---|---|---|
| `e2e_env` | `pytest.MonkeyPatch` | Session patch with `KAGGLE_*`, `PYTHIA_*`, LLM-model, `REDSIM_TEST_AUDIT`, `REDSIM_DB_URL` and the storage/config selectors scrubbed; `REDSIM_ENV_FILE` points at an absent file and the Pythia repo-root `.env` fallback at the harness directory. |
| `e2e_assets` | `Path` | A complete asset tree written by `build_cnn_asset` (small_cnn, 1 epoch, 48 seeded 8x8 RGB images, 3 classes, 24 in the eval split, dataset `local:synthetic-images`) and `build_url_asset` (sklearn ensemble + declared surrogate on the committed `malicious_urls_sample.csv` rows under the harness-owned dataset `local:e2e-url-sample`, see `harness.harness_url_table`). Neither entry is `fixture_only`, otherwise `register_bundled_model` would refuse them. `REDSIM_ML_ASSETS_DIR` points at the tree. `harness.asset_dataset_ids(root)` gives the dataset ids the builder recorded. |
| `e2e_app` | `harness.E2EApp` | The FastAPI app (dev auth, rate limiter effectively off) over `sqlite:///<harness>/e2e.db`: one autocommit `StaticPool` connection in WAL mode carrying the ORM schema plus a mirror of the migration-owned `ml_campaigns` table (see the notes for why); `FilesystemBlobStore` under `<harness>/blobs` via `REDSIM_BLOB_BACKEND=fs`; Celery `task_always_eager` with `task_eager_propagate` **off** (a failed campaign is a failed `Run`, not a `503 queue_unavailable`); `redsim.yaml` with `output_dir` under the harness directory (`REDSIM_CONFIG`). Exposes `session()`, `audit_writer()`, `chain_ids()`, `read_chain()`, `client_for(user)`, `cli_argv()`, `cli_env()`, `sandbox` (see below) and `sqlite_tz_shim` (`True` only if the pysqlite timestamp shim had to be installed; `False` on the current tree). |
| `e2e_org` | `harness.E2EOrg` | Organisation `org-e2e` / project `proj-e2e` with one identity per role, plus organisation `org-e2e-other` / project `proj-e2e-other`. `e2e_org.client("viewer" \| "scanner" \| "remediator" \| "approver" \| "admin")` are members of `proj-e2e` with that role; `client("outsider")` is admin of the *other* project; `client("stranger")` has no memberships. `e2e_org.actor(role)` is the `user:<sub>` string the audit rows carry. Users and `project_memberships` rows exist in the database too, so `/v1/projects` agrees with the token. |
| `e2e_bundled` | `dict[str, str]` | `{"vehicles_cnn": <Target.id>, "url_trees": <Target.id>}` registered into `proj-e2e` by the remediator through `redsim.services.ml_models.register_bundled_model(session, project_id, bundled_id, actor)`. The returned `Target` is a **per-project row**: `id` is `<bundled_id>-<8 hex>` (never the bundled id), `value` is `bundled:<bundled_id>`, `detail.bundled_id` names the registry entry, `detail.status == "available"`, `detail.modality` and `detail.manifest.dataset_id` are the manifest's. Campaigns name the returned id; the child resolves the registry id from the frozen `target_snapshot` (`redsim.ml.campaign._bundled_registry_id`). `harness.registered_target(e2e_app, model_id)` reads the row back. |
| `pythia` | `harness.PythiaToggle` | Mocked gateway, **off by default**; observed in child mode because the writer runs in the worker parent. See "Pythia" below. |
| `audit_verify_all` | callable (function-scoped) | `() -> (exit_code, output)`: runs `redsim audit verify --all` as a subprocess (`E2EApp.cli_argv`) with `REDSIM_DB_URL` pointing at the harness database and the worktree first on `PYTHONPATH`; ANSI colours stripped. Exit `0` = every chain verified (`chain '<id>': N events verified` per chain); `1` and `broken at seq=N` otherwise. |
| `tamper_audit_event` | callable (function-scoped) | `(chain_id=None, seq=None, mutation="detail" \| "actor" \| "action" \| "success") -> (chain_id, seq)`: mutates one stored `audit_events` row. Defaults to a `run:` chain and its middle event so both the event hash and the next `prev_hash` break. |
| `postgres_url` | `str` | `REDSIM_E2E_POSTGRES_URL`; skips when unset, **fails** when set but the database is not migrated. See "Postgres lane". |

Authentication is the production path. `e2e_app` replaces
`redsim.api.auth._dev_user` with a lookup over the seeded identities, so
`Authorization: Bearer dev:<email>` flows through `get_current_user` (and the
tenant middleware) exactly as in dev mode, only with role-specific
`project_memberships` instead of the dev default.

### Helpers in `harness.py`

```python
from tests.e2e import harness as h

result = h.run_campaign_via_api(e2e_org.client("scanner"), e2e_bundled["vehicles_cnn"], h.image_campaign())
result.status          # "succeeded" | "failed" | "cancelled"  (from GET /v1/runs/{id})
result.campaign        # GET /v1/runs/{id}/campaign body, or None when that route refused
result.campaign_error  # the 17.3 detail of that refusal
result.findings        # the projected Finding rows inside the campaign body
result.stage_table     # the run's stage table
```

* `image_campaign(**overrides)` / `tabular_campaign(**overrides)` are the POST
  bodies sized for the tiny assets (12 samples; PGD `max_iter=3`; HopSkipJump
  with the small query budget the ml tier uses; `explain_k=2`;
  `include_control=True`). `dataset_id` and `dataset_revision` are copied from
  the model's manifest when absent, so the builder's ids are never guessed.
  `attack_params` carry caller overrides only; `eps` is grid-owned and
  admission strips it before freezing.
* `run_campaign_via_api` raises `CampaignLaunchRefused(status_code, detail)`
  on a non-202 launch; tests asserting refusal codes should call the route
  directly. It waits for the eager run to reach a terminal status and raises a
  clear `E2EHarnessError` if it never does.
* `register_bundled(harness, client, project_id=..., bundled_id=..., actor=...,
  prefer_route=False)` registers one bundled model through the service (or
  `POST /v1/models` with `source=bundled` when `prefer_route=True`) and returns
  the per-project `Target.id`. `registered_target(harness, model_id)` returns
  the stored row (`id`, `project_id`, `kind`, `value`, `verified`, `detail`).
* `harness_url_table()` is the committed URL sample under the harness-owned,
  non-fixture-only dataset entry `URL_DATASET_ID`; `synthetic_images()` the
  seeded image set. `model_record`, `wait_for_run`, `strip_ansi`,
  `asset_manifest`, `asset_dataset_ids`, `unload_bundled_targets`,
  `sqlite_audit_roundtrip_verifies` and `install_sqlite_tz_datetime_if_needed`
  are also public.

### The sandbox

`e2e_app.sandbox` is a `SandboxController`:

* `mode` is `"child"` (default; `run_campaign_sandboxed` spawns
  `python -m redsim.ml.sandbox_worker` with the allowlisted environment, exactly
  as the worker does in production) or `"inprocess"` (calls
  `redsim.ml.campaign.run_campaign` in the worker thread, mirroring
  `sandbox_worker._campaign` including the failed-partial-record path; a
  debugging aid only).
* `e2e_app.sandbox.use("inprocess")` is a context manager; `set(mode)` is
  permanent; `calls` records the mode every campaign actually ran in.
* `validate_model_sandboxed` (uploads) is never replaced: uploads validate in
  the real child in both modes.

`REDSIM_E2E_SANDBOX=child|inprocess` sets the session default.

The child's environment is the sandbox allowlist: it carries the resolved
`REDSIM_ML_ASSETS_DIR`, `REDSIM_DISABLE_LLM=1` and a `REDSIM_ENV_FILE` naming
an absent file, and no `PYTHIA_*`, `KAGGLE_*`, `AWS_*`, `REDSIM_DB_URL`,
`REDSIM_BLOB_FS_PATH` or `REDSIM_CONFIG`; the smoke test records and asserts it.

### Pythia

The LLM writer runs in the **worker parent**
(`redsim.workers.tasks.ml_campaign._parent_narrative`) after the child's
envelope comes back; the child strips every `PYTHIA_*` variable, runs with
`REDSIM_DISABLE_LLM=1` and never narrates (spec 10.8, 16.1). The mock therefore
lives in the test process and is observed in child mode; the sandbox mode is
not touched. `pythia.on()`:

1. exports `PYTHIA_BASE_URL=https://pythia.e2e.invalid`, a placeholder
   `PYTHIA_API_KEY` and `REDSIM_ML_LLM_MODEL=e2e/mock-writer`;
2. replaces `make_backend` in `redsim.llm.pythia` **and** the name bound in
   `redsim.ml.recommend.narrative` with the in-repo httpx client over an
   `httpx.MockTransport` whose canned answer is one `[r.X]` paragraph per
   candidate built **only from words already in the payload** (so the writer's
   numeric-consistency and banned-word post-checks pass and
   `narrative_source == "llm"`).

`pythia.requests` records every call (method, URL, headers, JSON body);
`pythia.last_payload()` is the writer's text-only user message.
`pythia.on(narrative="...")` or `narrative=lambda body: ...` replaces the
canned text (for example to invent a number and prove the post-check rejects
it); `pythia.on(status_code=503)` makes the gateway fail so the writer degrades
to rules. `pythia.disable_llm(True)` sets `REDSIM_DISABLE_LLM=1` independently.
`with pythia:` is `on()` / `off()`.

What the record and the chain say, as the smoke test asserts them
(`llm_narrative=True` in the POST body):

| Gateway state | `narrative_source` | `harden.execute` detail | Limitation |
|---|---|---|---|
| mock on | `llm`; `provenance.llm.model == e2e/mock-writer`, no key | `llm_used=True`, `prompt_sha256`/`completion_sha256` set; artifacts `ml.harden.prompt/completion/narrative`; one `LLMUsage` row | "LLM narrative generated via Pythia ..." |
| mock off (unconfigured) | `rules`; `provenance.llm is None`; no call | `llm_used=False`, `skipped_reason` names "not configured" | "... not configured ..." |
| mock on + `REDSIM_DISABLE_LLM=1` | `rules`; no call reaches the transport | `llm_used=False` | names `REDSIM_DISABLE_LLM` |
| mock on, narrative invents a number | `rules`; one call, answer refused | `llm_used=False`, `skipped_reason` "rejected by post-check", `completion_sha256` still set | "... rejected by post-check ..." |

### Postgres lane

Row-level security exists only on Postgres. On the sqlite harness a cross-org
negative (`e2e_org.client("outsider")` reading a `proj-e2e` run) proves the
application gates (`ensure_project_access`, membership scoping), **not** the
database policy. To exercise RLS and the append-only audit trigger:

```sh
export REDSIM_E2E_POSTGRES_URL=postgresql+psycopg://redsim:redsim@localhost:5432/redsim_e2e
REDSIM_DB_URL="$REDSIM_E2E_POSTGRES_URL" alembic upgrade head
REDSIM_E2E=1 pytest -q -m e2e tests/e2e -k postgres
```

`postgres_url` returns the URL, skips when it is unset and fails (does not
skip) when the database lacks `ml_campaigns`, `audit_events` or `targets`.
Remember that a Postgres superuser bypasses RLS even under `FORCE ROW LEVEL
SECURITY`; the policy is only observable through a non-superuser, non-owner
role (see `tests/test_tenant_rls.py`). On Postgres, `tamper_audit_event`
raises `E2EHarnessError` because the append-only trigger refuses the UPDATE;
that refusal is the property to assert there.

## Excluded from this tier

* **The browser UI.** Spec 22.5's Playwright campaign (`web/tests/ml_campaign.spec.ts`)
  needs the compose stack and lives with the web app; nothing here renders or
  drives a page.
* **ECS Fargate / the compose stack.** No container, queue, S3/MinIO bucket or
  WORM export is started. `REDSIM_BLOB_BACKEND=fs`, Celery is eager, the Redis
  event publisher is a no-op.
* **Real model assets and datasets.** The tree is synthetic (seeded random
  pixels; the committed URL sample). Every number a run produces here is a
  harness measurement on a test double, never a demo result.
* **Uploads at scale.** The upload route is reachable, but the tier ships no
  ONNX/state_dict fixtures of its own.

## Notes and caveats

* **The PGD-by-surrogate admission defect this file once reported is fixed
  at `58461cc`.** `test_tabular_campaign_runs_pgd_hopskipjump_and_control`
  had been refused `422 attack_requires_gradients` ("attack 'pgd' needs loss
  gradients the model does not expose (manifest gradients: false)") because
  `redsim/services/ml_campaigns.py` read only `manifest.gradients` and
  ignored the declared surrogate and the PGD adapter's `surrogate_transfer` +
  `modality:tabular` capabilities. The integration commit admits a white-box
  attack on a gradient-free model when the adapter declares
  `surrogate_transfer` and the target declares a surrogate, the runner then
  runs PGD by surrogate transfer and records it (spec 12.9, demo step 6), and
  the test passes through the real child. `fgsm` on a gradient-free model
  without a surrogate is still refused.
  `test_tabular_hopskipjump_and_control_run_in_the_real_sandbox_child` stays
  as the independent proof of the tabular path (load, sample, HopSkipJump,
  control at every eps, score, report, audit rows).
* **Two earlier cross-track defects are fixed on this tree** (`dd2bbd4`):
  admission strips the grid-owned `eps` / `norm_l2` before freezing
  `attack_params` (`_GRID_OWNED_PARAMS`), and applicability is decided from
  the adapter's `modality:<domain>` capability tags rather than
  `AttackInfo.domain`. The smoke test asserts both (`"eps" not in
  config.attack_params.pgd`; the tabular launch is no longer
  `attack_modality_mismatch`).
* **sqlite timestamps.** SQLAlchemy's sqlite `DateTime` storage format has no
  offset, so `AuditEvent.created_at` comes back naive. The audit module
  (`aa9674e`) renders and re-derives `ts` through
  `redsim.audit.chain.canonical_ts`, so
  the production `PostgresAuditWriter` round-trips and verifies on plain
  sqlite. The harness still guards against a regression:
  `harness.install_sqlite_tz_datetime_if_needed()` first writes and verifies a
  two-event probe chain on a throwaway in-memory database with the production
  writer and installs the pysqlite `DateTime` shim **only** when that probe
  fails (`e2e_app.sqlite_tz_shim` says which happened; it is `False` on this
  tree). The CLI subprocess (`E2EApp.cli_argv`) enters `redsim.cli.main.main`
  through a one-line bootstrap that makes the same decision. On a Postgres URL
  the plain `python -m redsim.cli` is used. The writer and verifier themselves
  are never patched.
* **One autocommit sqlite connection.** The worker keeps its `task_context`
  session open across steps that write audit rows through a *separate*
  `get_session()`; on a normal-pool file sqlite that second connection blocks on
  the first's open write transaction (`database is locked`). And the
  migration-owned `ml_campaigns` is read by reflection
  (`Table(..., autoload_with=session.get_bind())`), whose own `Connection`
  close would roll a shared transaction back. `harness.install_shared_sqlite_engine`
  therefore builds the engine as a `StaticPool` with `isolation_level="AUTOCOMMIT"`
  (WAL, `busy_timeout`), and patches `init_engine` idempotently so the worker's
  per-task `init_engine(REDSIM_DB_URL)` keeps it. A failed campaign keeps the
  partial rows it wrote, which is what the tier records as evidence anyway.
* **The harness datasets are not `fixture_only`.** `register_bundled_model`
  refuses fixture-only entries (`404 unknown_bundled_model`, spec 5.5), and the
  builder copies the dataset flag onto the model entry, so the synthetic image
  set and the URL rows are declared as harness-owned, non-fixture-only entries
  with notes saying what they are. Nothing measured on them is a demo result.
* The harness process imports torch/ART/sklearn (to build the assets and, in
  in-process mode, to run the campaign). The "API process never imports an ML
  library" rule is enforced by `tests/test_api_process_has_no_ml.py` in a fresh
  subprocess and is unaffected; do not assert on `sys.modules` from an e2e test.
* Session-scoped state is shared across the tier: `e2e_bundled` registers the
  two models once; a test that deletes one changes what later tests see.
  Re-register with `harness.register_bundled(...)` if needed. A second
  registration of the same bundled model in the same project is a typed
  `409 already_registered` naming the existing `target_id`.
* sqlite foreign keys are not enforced (the worker re-creates the engine per
  task, so a per-connection pragma would not hold). `ml_campaigns` is created
  from a column mirror of migration 0010 without FK constraints.
* The worker's `task_context` re-runs `init_engine(REDSIM_DB_URL)` per task, as
  in production; `E2EApp.session()` always follows the current engine.
* Every e2e test is stamped `e2e`; the integration auto-stamp from
  `tests/conftest.py` does not apply because these fixtures have different
  names.
