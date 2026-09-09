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
`harness.py`. Wave 4 adds the `test_*.py` files here and should not need to
edit either.

## Running

```sh
# the tier (about a minute on a laptop CPU; the two asset builds dominate)
REDSIM_E2E=1 pytest -q -m e2e tests/e2e

# one file, verbose, keep the sandbox work directories for inspection
REDSIM_E2E=1 REDSIM_ML_KEEP_WORK_DIR=1 pytest -q -m e2e tests/e2e/test_demo_path.py -vv

# run the campaign sandbox in-process instead of as a child (faster to debug,
# but the child-process boundary is then not exercised)
REDSIM_E2E=1 REDSIM_E2E_SANDBOX=inprocess pytest -q -m e2e tests/e2e
```

Requirements: the `ml` extra (torch, ART, scikit-learn, SHAP) plus the `api`
and `worker` extras. No network, no Kaggle, no Docker, no Redis, no Postgres.

Gating is automatic. Every item collected under `tests/e2e` is stamped `e2e`
by `conftest.py`, so:

* `pytest -q` (the default tier; `addopts` deselects `e2e`) runs nothing here;
* `pytest -m e2e tests/e2e` without `REDSIM_E2E` **skips** everything with a
  message rather than failing;
* `REDSIM_E2E=1 pytest -m e2e tests/e2e` runs the tier.

`-m e2e` on the command line overrides the `-m` in `addopts`.

## What the fixtures give you

All session-scoped unless noted; the graph is
`e2e_harness_dir -> e2e_env -> e2e_assets -> e2e_app -> e2e_org -> e2e_bundled`.

| Fixture | Type | Provides |
|---|---|---|
| `e2e_env` | `pytest.MonkeyPatch` | Session patch with `KAGGLE_*`, `PYTHIA_*`, LLM-model, `REDSIM_TEST_AUDIT`, `REDSIM_DB_URL` and the storage/config selectors scrubbed; `REDSIM_ENV_FILE` points at an absent file and the Pythia repo-root `.env` fallback at the harness directory. |
| `e2e_assets` | `Path` | A complete asset tree written by `build_cnn_asset` (small_cnn, 1 epoch, 48 seeded 8x8 RGB images, 3 classes, 24 in the eval split) and `build_url_asset` (sklearn ensemble + declared surrogate on the committed `malicious_urls_sample.csv`, 12 eval rows). `REDSIM_ML_ASSETS_DIR` points at it. `harness.asset_dataset_ids(root)` gives the dataset ids the builder recorded. |
| `e2e_app` | `harness.E2EApp` | The FastAPI app (dev auth, rate limiter effectively off) over `sqlite:///<harness>/e2e.db` in WAL mode with the ORM schema plus a mirror of the migration-owned `ml_campaigns` table; `FilesystemBlobStore` under `<harness>/blobs` via `REDSIM_BLOB_BACKEND=fs`; Celery `task_always_eager` + `task_eager_propagate`; `redsim.yaml` with `output_dir` under the harness directory (`REDSIM_CONFIG`). Exposes `session()`, `audit_writer()`, `chain_ids()`, `read_chain()`, `client_for(user)`, `cli_env()`, and `sandbox` (see below). |
| `e2e_org` | `harness.E2EOrg` | Organisation `org-e2e` / project `proj-e2e` with one identity per role, plus organisation `org-e2e-other` / project `proj-e2e-other`. `e2e_org.client("viewer" \| "scanner" \| "remediator" \| "approver" \| "admin")` are members of `proj-e2e` with that role; `client("outsider")` is admin of the *other* project; `client("stranger")` has no memberships. `e2e_org.actor(role)` is the `user:<sub>` string the audit rows carry. Users and `project_memberships` rows exist in the database too, so `/v1/projects` agrees with the token. |
| `e2e_bundled` | `dict[str, str]` | `{"vehicles_cnn": <model_id>, "url_trees": <model_id>}` registered into `proj-e2e` by the remediator. Uses `redsim.services.ml_models.register_bundled_model(session, project_id, bundled_id, actor)` when that wave-2 service exists on the tree, else `POST /v1/models` with `source=bundled`. |
| `pythia` | `harness.PythiaToggle` | Mocked gateway, **off by default**. See "Pythia" below. |
| `audit_verify_all` | callable (function-scoped) | `() -> (exit_code, output)`: runs `python -m redsim.cli audit verify --all` as a subprocess with `REDSIM_DB_URL` pointing at the harness database and the worktree first on `PYTHONPATH`; ANSI colours stripped. Exit `0` = every chain verified; `1` and `broken at seq=N` otherwise. |
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
  with the small query budget the ml tier uses; `explain_k=2`). `dataset_id`
  and `dataset_revision` are copied from the model's manifest when absent, so
  the builder's ids are never guessed.
* `run_campaign_via_api` raises `CampaignLaunchRefused(status_code, detail)`
  on a non-202 launch; tests asserting refusal codes should call the route
  directly. It waits for the eager run to reach a terminal status and raises a
  clear `E2EHarnessError` if it never does.
* `register_bundled(harness, client, project_id=..., bundled_id=..., actor=...,
  prefer_route=False)` registers one bundled model (service when present, else
  route). `model_record`, `wait_for_run`, `strip_ansi`, `asset_manifest`,
  `asset_dataset_ids`, `unload_bundled_targets` are also public.

### The sandbox

`e2e_app.sandbox` is a `SandboxController`:

* `mode` is `"child"` (default; `run_campaign_sandboxed` spawns
  `python -m redsim.ml.sandbox_worker` with the allowlisted environment, exactly
  as the worker does in production) or `"inprocess"` (calls
  `redsim.ml.campaign.run_campaign` in the worker thread, mirroring
  `sandbox_worker._campaign` including the failed-partial-record path).
* `e2e_app.sandbox.use("inprocess")` is a context manager; `set(mode)` is
  permanent; `calls` records the mode every campaign actually ran in.
* `validate_model_sandboxed` (uploads) is never replaced: uploads validate in
  the real child in both modes.

`REDSIM_E2E_SANDBOX=child|inprocess` sets the session default.

### Pythia

The LLM writer runs inside `run_campaign`, which the worker executes in the
sandbox child. The child's environment strips every `PYTHIA_*` variable, so a
mock in the test process can only observe the writer when the campaign runs
in-process. `pythia.on()` therefore:

1. exports `PYTHIA_BASE_URL=https://pythia.e2e.invalid`, a placeholder
   `PYTHIA_API_KEY` and `REDSIM_ML_LLM_MODEL=e2e/mock-writer`;
2. routes `redsim.llm.pythia.make_backend` through the in-repo httpx client over
   an `httpx.MockTransport` whose canned answer is one `[r.X]` paragraph per
   candidate built **only from words already in the payload** (so the writer's
   numeric-consistency and banned-word post-checks pass and
   `narrative_source == "llm"`);
3. switches the sandbox to `inprocess` for as long as it is on.

`pythia.requests` records every call (method, URL, headers, JSON body);
`pythia.last_payload()` is the writer's text-only user message.
`pythia.on(narrative="...")` or `narrative=lambda body: ...` replaces the
canned text (for example to invent a number and prove the post-check rejects
it); `pythia.on(status_code=503)` makes the gateway fail so the writer degrades
to rules. `pythia.disable_llm(True)` sets `REDSIM_DISABLE_LLM=1` independently.
`with pythia:` is `on()` / `off()`.

With the mock **off** and `llm_narrative=True`, the record carries the "Pythia
is not configured" limitation and `narrative_source == "rules"` (spec 10.8).
`run_campaign_via_api` refuses `llm_narrative=True` in child mode when a
developer `.env` exists at the cwd or the repo root, because the child would
read it and contact a real gateway from a test.

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

* **sqlite timestamps.** SQLAlchemy's sqlite `DateTime` storage format has no
  offset, so `AuditEvent.created_at` comes back naive and the production
  `PostgresAuditWriter.read_chain` re-derives `ts` without `+00:00`; every
  chain would then fail `verify_chain` at `seq=1` untouched. `e2e_app` installs
  `harness.install_sqlite_tz_datetime()` (a pysqlite `DateTime` implementation
  that stores and parses `isoformat()` with the offset) before creating its
  engine, and `audit_verify_all` enters `redsim.cli.main.main` through a
  one-line bootstrap that installs the same shim in the subprocess
  (`E2EApp.cli_argv`). On a Postgres URL the plain `python -m redsim.cli` is
  used. The writer and verifier themselves are never patched.
* **Cross-track defects the first run of this harness surfaced** (reported in
  the track report; if `run_campaign_via_api` fails on them, the fixes have not
  landed yet): (1) `create_attack_campaign` freezes `resolve_params()` output,
  which fills the `eps` default, into `attack_params`, and
  `run_campaign._attack_params` refuses `eps` there, so every API-launched
  campaign fails at the child's configuration check; (2) admission compares
  `AttackInfo.domain` with the modality, refusing PGD-by-surrogate on the
  tabular model although the adapter declares `modality:tabular` in its
  capabilities (spec 12.2, demo step 6). `tabular_campaign()` keeps the spec's
  PGD + HopSkipJump set on purpose.
* The harness process imports torch/ART/sklearn (to build the assets and, in
  in-process mode, to run the campaign). The "API process never imports an ML
  library" rule is enforced by `tests/test_api_process_has_no_ml.py` in a fresh
  subprocess and is unaffected; do not assert on `sys.modules` from an e2e test.
* Session-scoped state is shared across the tier: `e2e_bundled` registers the
  two models once; a test that deletes one changes what later tests see.
  Re-register with `harness.register_bundled(...)` if needed.
* sqlite foreign keys are not enforced (the worker re-creates the engine per
  task, so a per-connection pragma would not hold). `ml_campaigns` is created
  from a column mirror of migration 0010 without FK constraints.
* The worker's `task_context` re-runs `init_engine(REDSIM_DB_URL)` per task, as
  in production; `E2EApp.session()` always follows the current engine.
* Every e2e test is stamped `e2e`; the integration auto-stamp from
  `tests/conftest.py` does not apply because these fixtures have different
  names.
