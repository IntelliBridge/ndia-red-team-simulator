# Phase P0 · Milestone M0 · redsim/ml scaffold (v2, redsim substrate)

Status: v2, 2026-09-08. Owner: Backend lead. Wave: Gate 0 (blocking, about
0.5 to 1 day). Read `docs/plans/00-master-plan.md` sections 2, 5 and 7 first,
then the canonical spec
`docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md` sections 5,
6, 7 and 23. Those sources are canonical. Do not invent alternatives.

This phase lands Milestone M0 (Scaffold and contracts) on the restored redsim
platform (the aegis platform under its new name). The ML vertical lives in
`redsim/ml/`. The v1 standalone `redsim/` package is gone: no `RunStore`, no
thread pool, and no new `create_app`. ML routers mount on the
existing `redsim/api/app.py:create_app`.

---

## 1. Objective

Freeze the ML wire contract and the database shape so every later slice builds
against a fixed surface. P0 is additive and low risk. It wires no ML code.

P0 does six things:

1. Add one Alembic migration, `0010_ml_vertical`, that adds the `targets.detail`
   JSONB column and the `ml_campaigns` table with full row-level-security
   parity.
2. Widen the config and record types in `redsim/ml/schema.py`: generalise
   `RunConfig` into `CampaignConfig` (attack set, epsilon grid, MRI weight
   vector) and add the campaign, score, manifest and finding-detail models.
3. Add the seven new `Action` members and the `viewer` rank to
   `redsim/api/policy.py`, and prune the stale members whose routes are gone.
4. Add `onnx2torch` and `safetensors` to the `ml` optional-dependency group,
   and rename the environment variable `REDSIM_LLM_MODEL` to
   `REDSIM_ML_LLM_MODEL`.
5. Unmount `/v1/scans` from the existing app factory.
6. Add the `redsim ml build-assets` CLI skeleton and commit a campaign fixture
   under `tests/ml/fixtures/` for the UI team.

After P0 merges, the schema, the migration head, the policy table and the
campaign response shape are frozen. Later changes follow the protocol in
section 8.

## 2. Scope — in / out

### In scope

- **Migration `0010_ml_vertical`.** One migration file. `targets.detail` as
  `ADD COLUMN detail JSONB NULL`. The `ml_campaigns` table with the columns of
  spec section 5.6: `run_id` PK and FK to `runs.id`, `project_id` NOT NULL FK,
  `org_id` nullable FK, `target_id`, `kind`, `modality`, `baseline_run_id`,
  `parent_run_id`, `settings_hash`, `config`, `provenance`, `score`,
  `limitations`, `reviewer_notes`, `created_at`, `completed_at`. Full RLS
  parity: the `redsim_set_org_id_ml_campaigns` BEFORE INSERT trigger, the
  `redsim_check_org_id_ml_campaigns` BEFORE UPDATE guard, `ENABLE` and `FORCE ROW
  LEVEL SECURITY`, and the `redsim_tenant_isolation` policy, all copied verbatim
  from `0006_tenant_rls.py` and `0009_tenant_org_id_guard.py`. `down_revision`
  is `0009_tenant_org_id_guard`. The migration is additive and reversible.
- **Schema widening in `redsim/ml/schema.py`.** Generalise `RunConfig` into
  `CampaignConfig` and add `ScoringConfig`, `DefenseConfig`, `MRIInputRow`,
  `MRIRecord`, `MRIDelta`, `MeasuredDelta`, `MLFindingDetail` and
  `MLModelManifest`. Add the `score` stage to `STAGES` after `explain`. Add the
  `MLModelManifest` field set of spec 5.5. Field names and types come from spec
  5.3 and 5.6 exactly.
- **Policy additions in `redsim/api/policy.py`.** Add the seven `Action` members
  and their minimum roles (section 4). Add `"viewer": 0` to `_ROLE_RANK`. Prune
  the stale members `AGENT_RUN`, `AGENT_EXECUTE`, `FIX_GENERATE`, `FIX_APPLY`,
  `TOOL_INVOKE`, `TICKET_SYNC` from both `Action` and `_ACTION_MIN_ROLE`.
- **Dependencies.** Add `onnx2torch` and `safetensors` to the `ml` group in
  `pyproject.toml`. Install `ml` only in `deploy/Dockerfile.worker`.
- **Environment rename.** Change `REDSIM_LLM_MODEL` to `REDSIM_ML_LLM_MODEL` in
  `redsim/llm/pythia.py`, the comment in `redsim/ml/schema.py`, and
  `tests/test_llm_pythia.py`, in the same change.
- **Unmount `/v1/scans`.** Remove the `scans` router include and its import from
  `redsim/api/app.py`, and delete `redsim/api/v1/scans.py` and its tests.
- **CLI skeleton `redsim/cli/ml.py`.** Add the `redsim ml build-assets`
  subcommand skeleton, wired into `build_parser` and the dispatch in
  `redsim/cli/main.py`. The body is a stub that reports not-implemented and
  exits cleanly.
- **Fixture `tests/ml/fixtures/run_record.json`.** One campaign record shaped
  like the `GET /v1/runs/{id}/campaign` response (spec 17.2), for the web page
  tests.
- **Tests.** Schema round-trip, policy, environment rename, the app-has-no-ML
  guard, and the fixture validation (section 7).

### Out of scope

- Any attack, loader, explain, scoring, recommend, sandbox, or defense logic.
  Those land in M1 to M6.
- The eight new ML routers (`redsim/api/v1/{models,attacks,datasets,defenses,
  ml_capabilities,artifacts,compare,ml_findings}.py`) and their admission
  services (`redsim/services/ml_*.py`). Slices 1 to 3 own these.
- The Celery task modules (`redsim/workers/tasks/{model_validate,attack,explain,
  harden}.py`) and the `verify.py` ML branch. M1 to M6 own these.
- Bundled models, datasets, and the real `build-assets` implementation. M1 and
  M4 own these.
- Editing an existing field in `redsim/db/models.py`. The migration adds one
  column and one table. No existing table changes shape.

## 3. Prerequisites & dependencies

- Python 3.12 environment with `pip install -e ".[api,worker,test,dev]"`. The
  default `pytest -q` tier is green today.
- These files are read-only inputs to P0:
  - `redsim/ml/schema.py` — the scaffold contract to widen.
  - `redsim/db/models.py` — the redsim tables the migration extends; `Run` and
    `Target` are the FK anchors for `ml_campaigns`.
  - `redsim/api/app.py` — the existing `create_app` factory that mounts routers.
  - `redsim/api/v1/__init__.py` — the v1 router collection.
  - `redsim/api/policy.py` — the `Action` enum, `_ROLE_RANK`, `_ACTION_MIN_ROLE`
    and `check()`.
  - `redsim/llm/pythia.py` — `PythiaSettings.from_env`, which reads the LLM model
    variable today.
  - `redsim/db/migrations/versions/0006_tenant_rls.py` and
    `0009_tenant_org_id_guard.py` — the RLS trigger, guard and policy DDL to
    copy verbatim for `ml_campaigns`.
  - `redsim/cli/main.py` — `build_parser` and the `_COMMANDS` dispatch table.
  - `tests/ml/fakes.py` (`TinyTarget`) and `tests/conftest.py` (the sqlite
    session harness) — reused by later tiers.
- P0 is Gate 0. It blocks all slices. No slice blocks P0. Merge it first.

## 4. Interfaces consumed / exposed

### 4.1 Consumed

- From `redsim/db/models.py`: `Base`, `Run`, `Target`. The migration copies the
  RLS trigger, guard and `redsim_tenant_isolation` policy DDL from
  `0006_tenant_rls.py` and `0009_tenant_org_id_guard.py`.
- From `redsim/api/policy.py`: the `Action` enum, `_ROLE_RANK`,
  `_ACTION_MIN_ROLE`, `check()`, `ensure_project_access`.
- From `redsim/llm/pythia.py`: `PythiaSettings.from_env`.
- From `redsim/cli/main.py`: `build_parser` and `_COMMANDS`.

### 4.2 Exposed

- **Migration.** `revision = "0010_ml_vertical"`, `down_revision =
  "0009_tenant_org_id_guard"`. `upgrade` adds `targets.detail` and
  `ml_campaigns`; `downgrade` drops the table and the column.
- **Column and table.** `targets.detail` (JSONB, holds `MLModelManifest` for
  `ml_model_*` kinds). `ml_campaigns` (1:1 with `runs`, RLS-scoped by `org_id`).
- **Schema additions in `redsim/ml/schema.py`** (spec 5.3, 5.5, 5.6):

  - `CampaignConfig`: `target_id`, `modality`, `attack_ids: list[str]`,
    `attack_params: dict[str, dict]`, `norm: Literal["linf","l2"]`,
    `eps_grid: list[float]` (sorted ascending), `reference_eps: float` (a member
    of `eps_grid`), `finding_asr_threshold: float = 0.2`, `n_samples`, `seed`,
    `include_control`, `explain_k`, `dataset_id`, `dataset_revision`,
    `dataset_split`, `scoring: ScoringConfig`, `defense: DefenseConfig | None`,
    `llm_narrative: bool = False`, `auto_recommend: bool = True`,
    `target_snapshot`, `attacks`.
  - `ScoringConfig`: the MRI weight vector `S_acc 0.35 / S_asr 0.25 /
    S_eps 0.20 / S_conf 0.10 / S_expl 0.10`, severity and confidence
    thresholds, interpretation thresholds, and `version`.
  - `MRIRecord`, `MRIInputRow`, `MRIDelta`, `MeasuredDelta`, `DefenseConfig`,
    `MLFindingDetail`, `MLModelManifest`.
  - `RunRecord.config` becomes `CampaignConfig`. `STAGES` gains `score` after
    `explain`.
- **Policy table.** New `Action` members and minimum roles:

  | `Action` | value | min role |
  |---|---|---|
  | `MODEL_REGISTER` | `model.register` | `remediator` |
  | `ATTACK_RUN` | `attack.run` | `scanner` |
  | `EXPLAIN_RUN` | `explain.run` | `scanner` |
  | `HARDEN_RECOMMEND` | `harden.recommend` | `remediator` |
  | `FINDING_REVIEW` | `finding.review` | `approver` |
  | `FINDING_ANNOTATE` | `finding.annotate` | `remediator` |
  | `REPORT_EXPORT` | `report.export` | `scanner` |

  `_ROLE_RANK` gains `"viewer": 0`. A `viewer` passes every read gate and fails
  every `check`.
- **Environment variable.** `REDSIM_ML_LLM_MODEL`, read by
  `PythiaSettings.from_env` alongside `PYTHIA_BASE_URL` and `PYTHIA_API_KEY`.
  All three must be present or the narrative is skipped, never faked.
- **CLI.** `redsim ml build-assets` (skeleton). Reachable through
  `redsim/cli/main.py`.
- **Fixture.** `tests/ml/fixtures/run_record.json`, a `GET
  /v1/runs/{id}/campaign` payload for the web page tests.
- **App surface change.** `POST /v1/scans` is removed from the app factory.

### 4.3 Reused interfaces, unchanged

ML routers mount on the existing `redsim/api/app.py:create_app`. There is no new
factory. The mount happens through `app.include_router(..., prefix="/v1")`, the
same call the retained routers use. `redsim/db/models.py` tables (`Run`, `Job`,
`Finding`, `Artifact`, `AuditEvent`) are reused in place, not copied. Nothing
in P0 references `redsim/`, `RunStore`, a thread pool, or a second `create_app`.

## 5. Ordered implementation steps

1. Branch `p0-ml-scaffold` off the integration branch. Never commit to `main`.

2. Write `redsim/db/migrations/versions/0010_ml_vertical.py`. Set `revision =
   "0010_ml_vertical"` and `down_revision = "0009_tenant_org_id_guard"`. In
   `upgrade`, add `targets.detail` as JSONB nullable, then create `ml_campaigns`
   with the columns of spec 5.6. Copy the RLS trigger
   (`redsim_set_org_id_ml_campaigns`), the update guard
   (`redsim_check_org_id_ml_campaigns`), the `ENABLE` and `FORCE ROW LEVEL
   SECURITY` statements, and the `redsim_tenant_isolation` policy verbatim from
   `0006_tenant_rls.py` and `0009_tenant_org_id_guard.py`, substituting the
   table name. In `downgrade`, drop the policy, the triggers, the functions, the
   table, and the column, in reverse order.

3. Edit `redsim/ml/schema.py`. Generalise `RunConfig` into `CampaignConfig`. Add
   `ScoringConfig`, `DefenseConfig`, `MRIInputRow`, `MRIRecord`, `MRIDelta`,
   `MeasuredDelta`, `MLFindingDetail` and `MLModelManifest`. Point
   `RunRecord.config` at `CampaignConfig`. Add `score` to `STAGES` after
   `explain`. Keep Pydantic v2 style and match the surrounding models. Add only.
   Do not change the meaning of an existing field.

4. Edit `redsim/api/policy.py`. Add the seven `Action` members and their
   `_ACTION_MIN_ROLE` rows. Add `"viewer": 0` to `_ROLE_RANK`. Remove
   `AGENT_RUN`, `AGENT_EXECUTE`, `FIX_GENERATE`, `FIX_APPLY`, `TOOL_INVOKE` and
   `TICKET_SYNC` from `Action` and `_ACTION_MIN_ROLE`.

5. Edit `pyproject.toml`. Add `onnx2torch` and `safetensors` to the `ml`
   optional-dependency group.

6. Rename the environment variable. In `redsim/llm/pythia.py`, change the
   `from_env` read from `REDSIM_LLM_MODEL` to `REDSIM_ML_LLM_MODEL`. Update the
   `llm_narrative` comment in `redsim/ml/schema.py`. Update
   `tests/test_llm_pythia.py` in the same change.

7. Unmount `/v1/scans`. Remove `scans` from the import block and the
   `include_router` call in `redsim/api/app.py`. Delete `redsim/api/v1/scans.py`
   and its tests.

8. Create `redsim/cli/ml.py`. Add `cmd_ml` and the `redsim ml build-assets`
   subcommand skeleton. Register the `ml` subparser in `build_parser` and add
   the dispatch entry in `redsim/cli/main.py` (`_COMMANDS` or a
   `_cmd_ml_dispatch`, matching the `status` and `audit` pattern). The body
   reports not-implemented and returns cleanly. It seeds no assets in P0.

9. Create `tests/ml/fixtures/run_record.json`. Shape it like `GET
   /v1/runs/{id}/campaign` (spec 17.2). Populate every field the web pages
   render. See section 7 for the required contents.

10. Add the tests of section 7.

11. Run the validation of section 7. Run `alembic upgrade head` on a fresh
    database, then `alembic downgrade -1`, and confirm both succeed. Run
    `pytest -q`. Confirm the API process imports no ML library.

12. Open a PR into the integration branch. State that the schema, the migration
    head, the policy table and the campaign response shape are now frozen, and
    link section 8.

## 6. Files to create / modify

Create:

- `redsim/db/migrations/versions/0010_ml_vertical.py`
- `redsim/cli/ml.py`
- `tests/ml/fixtures/run_record.json`
- `tests/ml/test_schema.py`
- `tests/test_api_process_has_no_ml.py`

Modify:

- `redsim/ml/schema.py` (widen the config and record types; add the new models)
- `redsim/api/policy.py` (new `Action` members, `viewer` rank, prune stale
  members)
- `redsim/api/app.py` (remove the `scans` import and its `include_router` call)
- `redsim/llm/pythia.py` (environment rename)
- `redsim/cli/main.py` (register the `ml` subcommand and its dispatch)
- `pyproject.toml` (`ml` group gains `onnx2torch`, `safetensors`)
- `tests/test_llm_pythia.py` (environment rename)
- `deploy/Dockerfile.worker` (install `.[worker,ml]`; keep the API image free
  of the `ml` extra)

Remove:

- `redsim/api/v1/scans.py` and its tests

Do not modify: `redsim/db/models.py` (the migration owns the DDL; the ORM
`ml_campaigns` model lands with its service in a later slice), the retained
routers, or the existing migrations `0001`–`0009`.

## 7. Testing & validation

The default tier runs offline in under a minute with no services and no `ml`
extra (the redsim offline-path rule).

**Migration up and down.**

- `alembic upgrade head` on a fresh database creates `targets.detail` and
  `ml_campaigns`, and `ml_campaigns` carries the trigger, the guard, and `FORCE
  ROW LEVEL SECURITY`.
- `alembic downgrade -1` drops the table and the column cleanly. The migration
  is additive and reversible.

**App factory still boots.**

- `create_app()` returns a `FastAPI` instance without raising. `GET /health`
  returns 200 through `fastapi.testclient.TestClient(create_app())`.
- `POST /v1/scans` no longer routes. After the router include is removed the
  path returns `404`. This closes the pre-M0 behaviour where the inert `scans`
  router returned `400 unknown scanner`. Confirm the include and the router file
  are gone.

**`tests/test_api_process_has_no_ml.py` (unit).** Import `redsim.api.app` and
build the app with `torch`, `art`, `onnxruntime` and `shap` blocked in
`sys.modules`. The app still builds. The API process imports no ML library.

**`tests/ml/test_schema.py` (unit).**

- `CampaignConfig` and `MRIRecord` round-trip through `model_dump` and
  `model_validate`.
- `STAGES` contains `score` after `explain`.
- `ScoringConfig` weights are `0.35 / 0.25 / 0.20 / 0.10 / 0.10` and sum to 1.
- `MLModelManifest` accepts the field set of spec 5.5.

**Policy (unit).**

- The seven new `Action` members resolve their minimum roles through
  `_ACTION_MIN_ROLE`.
- `viewer` ranks 0: it passes a read gate and fails `check` on a gated action.
- The pruned members (`AGENT_RUN`, `FIX_GENERATE`, and the rest) are absent from
  `Action`.

**Environment rename.** `tests/test_llm_pythia.py` reads `REDSIM_ML_LLM_MODEL`.
`PythiaSettings.from_env` returns `None` when any of `PYTHIA_BASE_URL`,
`PYTHIA_API_KEY` or `REDSIM_ML_LLM_MODEL` is missing.

**Fixture.** `tests/ml/fixtures/run_record.json` validates against the campaign
response shape and holds:

- `config` (`CampaignConfig`) with `attack_ids`, `eps_grid` `[0.01, 0.03, 0.1]`,
  `reference_eps` a member of the grid, and `finding_asr_threshold`.
- `target` (`TargetInfo`), with `target.name` set to `"Tiny random CNN (test
  double)"` so the fixture can never masquerade as a real model in a screenshot.
- `attacks` (a list of `AttackInfo`), `provenance`, `measurements[]` (clean,
  evasion and control rows with `n` and `n_correct`), `curve`, `observations[]`
  (with `center_mass_ratio_*` and `metric_kind: "heuristic"`),
  `interpretation[]` (`kind: "inferred"`), `recommendations[]` (`status:
  "candidate"`, `validation: "not evaluated"`, no numeric expected-gain field),
  `limitations[]` (non-empty), `completeness`, and a full `score` (`MRIRecord`
  with the five subscores, the per-attack table with denominators, the epsilon
  grid, and `reading`).

**Postgres RLS (integration, Postgres only).** Extend `tests/test_tenant_rls.py`
so `ml_campaigns` is covered by `FORCE ROW LEVEL SECURITY`, and a cross-org read
of a campaign row returns nothing.

## 8. Acceptance criteria / Definition of Done

M0 exit check (spec section 23): `alembic upgrade head` on a fresh database,
`pytest -q` green, and the API process imports no ML library.

- [ ] `0010_ml_vertical` applies on a fresh database and reverses cleanly.
      `ml_campaigns` has the `redsim_set_org_id_ml_campaigns` trigger, the
      `redsim_check_org_id_ml_campaigns` guard, `FORCE ROW LEVEL SECURITY`, and
      the `redsim_tenant_isolation` policy. `targets.detail` is JSONB nullable.
- [ ] `redsim/ml/schema.py` defines `CampaignConfig` with the attack set, the
      epsilon grid and the MRI weight vector, plus `ScoringConfig`,
      `MRIRecord`, `MRIInputRow`, `MRIDelta`, `MeasuredDelta`, `DefenseConfig`,
      `MLFindingDetail` and `MLModelManifest`. `STAGES` gains `score`. No
      existing field changed meaning.
- [ ] `redsim/api/policy.py` adds the seven `Action` members with their minimum
      roles, adds `"viewer": 0` to `_ROLE_RANK`, and removes the six stale
      members.
- [ ] The `ml` group in `pyproject.toml` lists `onnx2torch` and `safetensors`.
      The worker image installs `.[worker,ml]`; the API image does not.
- [ ] `PythiaSettings.from_env` reads `REDSIM_ML_LLM_MODEL`. The comment in
      `redsim/ml/schema.py` and `tests/test_llm_pythia.py` use the new name.
- [ ] `POST /v1/scans` is unmounted. `redsim/api/v1/scans.py` and its tests are
      removed. `create_app()` still boots and serves `GET /health`.
- [ ] `redsim ml build-assets` is reachable through `redsim/cli/main.py` and
      returns cleanly as a not-implemented skeleton.
- [ ] `tests/ml/fixtures/run_record.json` validates against the campaign
      response shape and carries a full `score` block.
- [ ] `pytest -q` passes. `alembic upgrade head` then `alembic downgrade -1`
      passes.

### What P0 must freeze

After merge, treat these as locked. A silent change breaks a parallel slice.

- Every field name and type in `redsim/ml/schema.py`, old and new.
  `CampaignConfig`, `MRIRecord`, `MLModelManifest` and `MLFindingDetail` are the
  shared contracts.
- The migration head `0010_ml_vertical` and the `ml_campaigns` column set.
- The `Action` values and their minimum roles, and the `viewer` rank.
- The `GET /v1/runs/{id}/campaign` response shape the fixture encodes.
- The environment variable name `REDSIM_ML_LLM_MODEL`.

### Change protocol after freeze

1. Do not rename a schema field, a column, an `Action` value, or a response key
   silently.
2. Announce any change as a one-line note in master section 5, plus a heads-up
   to the team.
3. Prefer an additive, default-valued field over a change to an existing one.
   Additive fields do not break a parallel slice; renames and type changes do.

## 9. Effort estimate & special considerations

Estimate: about 0.5 to 1 day for one backend developer. The work is a
migration, a schema widening, a policy edit, a dependency and environment
change, one route removal, a CLI stub, and a fixture. It wires no ML.

Special considerations:

- **RLS parity is the risk in the migration.** Copy the trigger, the update
  guard, the `FORCE ROW LEVEL SECURITY` statements and the
  `redsim_tenant_isolation` policy verbatim from `0006_tenant_rls.py` and
  `0009_tenant_org_id_guard.py`, changing only the table name to
  `ml_campaigns`. `org_id` is trigger-backfilled on insert and guarded against
  drift on update. ML code never sets `org_id`.
- **The migration is additive and reversible.** `targets.detail` is nullable.
  No existing row changes meaning. `downgrade` drops the table and the column.
- **The API image must never import an ML library.** The
  `tests/test_api_process_has_no_ml.py` guard enforces the boundary rather than
  assuming it. Keep the `ml` extra in the worker image only.
- **The environment rename must land in three places at once.**
  `redsim/llm/pythia.py`, the comment in `redsim/ml/schema.py`, and
  `tests/test_llm_pythia.py`. A partial rename leaves `from_env` returning
  `None` and the narrative silently skipped.
- **Stale-member pruning travels with the route removal.** Remove the six unused
  `Action` members in the same change that unmounts `/v1/scans`, so nothing
  references a deleted member. The OPA and Cedar bundles gain the seven new rows
  when those engines are configured; an unknown action fails closed.
- **`viewer` needs two more homes outside this Python change.** The Keycloak
  realm roles (`deploy/keycloak/realm-export.json`) and the design-system
  `ROLES` tuple (`packages/design-system/src/components/role-gated.tsx`) must
  also list `viewer`. Flag this to the web and infra owners as a coordination
  point; it is not blocking for the P0 Python merge.
- **The fixture is a test double, never a demo result.** Its `target.name` is
  `"Tiny random CNN (test double)"`. No code path serves it as a real campaign
  result.
- **Follow repo prose conventions.** No em dashes and no semicolons in code
  comments or in this document.
