# F004 — Run Management

## Reconciliation with the product spec (2026-09-08)

This feature is the feature-level layer beneath the canonical product spec, [docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md](../../docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md); the product owner's decisions D1–D13 of 2026-09-08 recorded there override this file wherever they conflict, and the body of this file below this section is retained as written for history. Under D1 and D10, F004 "Run management" maps onto aegis's existing run lifecycle rather than onto a new orchestration layer: a **Run** is one attack campaign against one model (`aegis/db/models.py::Run`); each pipeline step is a **Job** (`Job.type` gains `attack.run`, `explain.run`, `harden.recommend`, and the existing `verify.replay` is reused); work executes on the **Celery worker** (`aegis/workers/celery_app.py`, `task_acks_late=True`, soft/hard time limits 1800 s / 2100 s) and every status write goes through the authoritative guard `aegis/workers/job_state.py`; admission is audit-first in the `aegis/services/scans.py::create_scan_job` pattern (`authorize()` appends the hash-chained `AuditEvent` before any Run or Job row exists, then enqueues); cancellation is `POST /v1/runs/{id}/cancel` → `aegis/services/runs.py::cancel_run`; crashed jobs are reaped by `aegis/workers/tasks/reaper.py`; live status reaches the browser over the Redis channel `run:{run_id}:events` (`aegis/workers/events.py`) into the existing `web/src/app/runs/` pages. Uploaded model artifacts are loaded only on the worker inside the plugin sandbox (`aegis/scanners/sandbox.py`, `aegis/scanners/sandbox_worker.py`: separate process, no network, rlimits — D2), never in the API process. The "approved published profile" this file inherits from F003 becomes the approved attack-campaign configuration (attack set, eps grid, reference budget, sample dataset, scoring weights — D9(i)) snapshotted with the Run. In John Sasser's build sequence (product spec, build sequence and milestones) this feature lands across **M0** (scaffold: `aegis/ml/`, the new `Job.type` values), **M1** (first `attack.run` jobs writing Findings), **M5** (the `/runs/[id]` campaign screen) and **M6** (the `verify.replay` re-attack loop); the demo-critical order inside Phase A (D8) puts the image path end-to-end first. Nothing here claims the ML vertical is implemented: `aegis/ml/` holds contracts only (`schema.py`, `targets/base.py`, `attacks/base.py`), the Celery tasks named above do not exist yet, and the state-contract and role mappings below describe how this file's vocabulary maps onto aegis code that does exist.

### State contract mapping (per D10)

aegis's Job state machine is canonical in code; the shared run state contract in `specs/_shared/architecture.md` maps onto it as follows. Legal aegis transitions: `queued → running | cancelled`; `running → succeeded | failed | cancelled | queued`; `succeeded`, `failed`, `cancelled` are sinks.

| Shared-contract state | aegis `Job.status` | How the meaning carries over |
| --- | --- | --- |
| `queued` | `queued` | Same. |
| `running` | `running` | Same. aegis adds one internal edge, `running → queued` (transient-retry requeue inside `task_context`), which is never a user-facing state. |
| `cancel_requested` | none | Cancellation is terminal at commit: `cancel_run` appends the `run.cancel` audit row, then in one transaction writes `Run.status = "cancelled"` and moves every `queued`/`running` Job to `cancelled`, then best-effort revokes the Celery task. "Cancelling" exists only as a client-side in-flight state while the POST is pending. |
| `completed` | `succeeded` | Same meaning; different word. |
| `failed` | `failed` | Same. |
| `cancelled` | `cancelled` | Same. |
| `timed_out` | `failed` + `Job.error` | Not a distinct status. The reaper writes `error = "reaped: exceeded max runtime TTL"`; a Celery soft-time-limit exception is captured into `Job.error` by `task_context`. Timeouts are distinguished by error text and surfaced as such in the UI. |

`Run.status` is a free `String(32)` roll-up, not guarded by `job_state.py` (admission writes `queued`; `cancel_run` writes `cancelled`). F004's roll-up rule: a Run is `running` while any Job is `queued`/`running`, `succeeded` only when every Job succeeded, `failed` when any Job failed and none is still active, and `cancelled` on cancel. Two contract consequences for code (not edited by this note): `aegis/ml/schema.py::RunStatus` must gain `cancelled`, and its `not_implemented` value stays an admission-time HTTP 501 (S2 API contract) and is never persisted as a Job status; and `cancel_run` must reject a Run that is already terminal (HTTP 409) instead of rewriting `Run.status` — see US2/FR-007 below.

### Requirement status after consolidation

| Requirement | Status after consolidation | Note |
| --- | --- | --- |
| Scope — "Request a run only from an approved published profile" | amended | Profile → approved attack-campaign configuration snapshotted with the Run (D10, F003). Approval workflow is F003's; F004 requires the exact snapshot. |
| Exclusions — "standalone worker in Replit" | superseded | The runtime is decided: Celery worker (`aegis/workers/`, `deploy/Dockerfile.worker`, `deploy/docker-compose.yml`) plus the plugin sandbox. Replit is not part of the stack (D1, D11-D004). |
| Exclusions — "running … unrestricted uploaded code" | amended | Still excluded as *unrestricted* execution. Bounded execution is in scope: ONNX preferred, PyTorch `state_dict` with explicit architecture accepted, full pickles refused by default, loaded only on the worker in the sandbox (D2; constitution amendment proposal D12(b)). |
| Exclusions — "attack recipes, operational targets, weapons, mission systems, or sensitive data" | amended | FGSM/PGD (image) and PGD/HopSkipJump (tabular) against a classifier are in scope as evaluation attacks; demo imagery is open, unclassified aerial/military-vehicle data (D3). Targeting, weapons, mission-system connections and sensitive data remain excluded (D3 bounds; D12(a)). |
| US1 | amended | (1) "Published profile" → campaign configuration as above. (2) "No approved runtime" is no longer an open condition; the scenario becomes: HTTP 503 when Postgres/Redis are unreachable at admission, HTTP 501 when the target's `TargetInfo.status == "not_implemented"` (S2 contract preserved), and a model that fails to load in the sandbox yields a `failed` Job with the captured error — never an in-process fallback. (3) Duplicate request identity is **deferred to Phase B**: aegis admission mints a fresh run id per call and has no client idempotency key; worker-side idempotency (redelivery guard, no-op same-status writes) is Phase A. |
| US2 | amended | No `cancel_requested` state (see mapping). Race rule: whichever commit lands first wins; the loser is rejected by `set_job_status` (`IllegalJobTransition` — terminal states are sinks), and a Job that already committed `succeeded` is not selected by `cancel_run` (it filters `queued`/`running`), so completion remains terminal. Ordering is retained by the audit chain (`run.cancel` row appended before mutation) and `Job.completed_at`, not by a RunTransition table. Third scenario (cancel on a terminal run is rejected without changing provenance) requires the `cancel_run` 409 amendment named above; today it rewrites `Run.status`. |
| US3 | amended | aegis has no user-facing retry; its internal `running → queued` requeue is not a retry record. Retry/rerun = a new campaign request that copies the original Run's stored configuration and records the original run id in the new Run's snapshot; the original is untouched. Eligibility in Phase A = original is `failed` or `cancelled` (reaper-failed included) and the `Target` row is still present and not archived; "approval no longer valid" reduces to that until F003's approval workflow exists (Phase B). Partial evidence = `RunRecord.stage`/`stages_done` (`STAGES` in `aegis/ml/schema.py`) plus any `Measurement` rows already written, labelled incomplete; the "a succeeded run must state its limitations" validator applies only to `succeeded`. |
| FR-001 | amended | Roles map onto the aegis rank ladder `_ROLE_RANK` in `aegis/api/policy.py`: Owner → `admin`; Analyst → `remediator` (start needs the new `ATTACK_RUN` (`attack.run`) ≥ `remediator`, not `SCAN_START`; cancel needs `RUN_CANCEL` ≥ `remediator`; verify needs `VERIFY_REPLAY` ≥ `remediator`); Reviewer → `approver`. Divergence: aegis is rank-monotonic, so an `approver` may also start/cancel (this file's matrix said Reviewer cannot), and "except own authored item" is not in the rank table (F006, Phase B). Viewer → `scanner` (the baseline mapping): aegis has no rank below `scanner`, which may start a legacy scan but not a campaign once `attack.run` is registered at `remediator`; a rank-0 read-only role is deferred to Phase B. The demo runs in dev-token mode (D11-D002) with `admin` on the `default` project. |
| FR-002 | amended | Profile version → campaign configuration posted to `POST /v1/models/{id}/attacks` (product spec API surface, from S1) and snapshotted with the Run; catalog versions → the `Target` row (`kind = ml_model_artifact`, `Target.value` = S3 key) plus `Provenance.model_sha256`, `dataset`, `dataset_split`, `model_manifest`. Independent approval of the configuration is F003's and is Phase B unless F003 lands it cheaply. |
| FR-003 | amended | Request-time snapshot = `Run` (`project_id`, `org_id`, `target_id`, `created_by`, `mode`, `created_at`) + `Job` (`type`, `created_by`, `created_at`, `celery_task_id`, `detail` JSONB carrying the campaign configuration) + the admission audit row. Runtime provenance = `aegis/ml/schema.py::Provenance` (library versions, `model_sha256`, dataset/split, manifest, hostname, device, `nondeterminism` sources), written by the worker. Lineage = original run id in the retry's snapshot (no FK column in Phase A). "Request identity" as a client idempotency key is deferred to Phase B. The product spec fixes which `RunRecord` fields live in `Finding.schema_blob` vs `Artifact` rows vs the campaign/score record. |
| FR-004 | superseded | The shared run state contract is replaced by `aegis/workers/job_state.py` (canonical in code) per the mapping table above; "terminal states never become running" holds (sinks). |
| FR-005 | amended | "Approved authenticated adapter contract" = the in-boundary Celery task over the Redis broker plus `aegis/workers/bootstrap.py::task_context`; there is no public HTTP adapter and no `execution-adapter.openapi.yaml`. Untrusted model loading happens only on the worker in `aegis/scanners/sandbox.py` (D2). "Never in the web process" is unchanged and stronger: the API process never loads a model file. |
| FR-006 | amended | Runtime, isolation and capability are now fixed, so the explicit failures are: HTTP 503 (Postgres/Redis unreachable at admission), HTTP 501 (`not_implemented` target), HTTP 4xx (refused artifact format, e.g. full pickle), and a `failed` Job with the captured sandbox error. "Adapter authentication unavailable" = missing worker service credentials to Postgres/Redis → admission fails. No fallback path exists in aegis. |
| FR-007 | amended | Ordering is recorded by the audit chain (`run.cancel` appended before mutation), `Job.completed_at`, and `publish_job_event` events; the state guard, not a separate shared ordering rule, decides the race. Requires the `cancel_run` terminal-run rejection amendment (code change, not made by this note). |
| FR-008 | amended | New linked Run + Jobs; the original is never edited (aegis has no run edit/archive/delete API); lineage lives in the snapshot; reauthorization = RBAC check on the new request plus target availability; configuration-approval validity is Phase B (F003). |
| FR-009 | amended | Worker updates are in-boundary DB writes: idempotent (same-status write is a no-op), transition-valid (`IllegalJobTransition`), correlated (`Job.run_id`, `Job.celery_task_id`), stale-rejected (redelivery guard skips any non-`queued` Job; `task_acks_late=True`). "Authorized" = worker service credentials to Postgres/Redis (`tests/test_worker_sa_auth.py`), not a per-message signature or schema-versioned `ExecutionUpdate`. |
| FR-010 | unchanged | Enforced structurally by `aegis/ml/schema.py`: `Measurement.family ∈ {clean, evasion, control}` with `n` denominators; `TargetStatus`/`RunStatus` `not_implemented`; `Observation.metric_kind = "heuristic"`; `Interpretation.kind = "inferred"`; `CandidateRecommendation.status = "candidate"`; `limitations` required on success. Transport failures and timeouts land in `Job.error`, never in a `Measurement`. |
| FR-011 | amended | The existing `web/src/app/runs/page.tsx` and `web/src/app/runs/[id]/page.tsx` (cancel dialog; `isCancellable` accepts `queued`/`running`/`pending`) are extended, not replaced. Rendered states are the aegis vocabulary; "cancel_requested" is a client in-flight state and "timed_out" is `failed` plus error text. Retry, partial completeness (`stages_done`) and 503/501 presentation are new. Live updates arrive over the WebSocket fed by `run:{run_id}:events`. The `/runs/[id]` page also hosts the MRI scorecard, five subscores, per-family table with denominators and the eps curve (D9(ii)) — F005/F007 content that shares this page. |
| FR-012 | amended | "F008 event writer contract" = `aegis/audit/chain.py::AuditWriter.append(action, actor, target, allowlist_check, override, success, detail, run_id, project_id)` over the Postgres `audit_events` hash chain (JSONL offline; `InMemoryAuditWriter` in tests). Audit-first admission means an unavailable writer fails the request before any Run/Job row exists (`tests/test_admission_audit_before_enqueue.py`). Events per D4(c): model upload, `attack.run`, `explain.run`, `harden.recommend`, `verify.replay`, `run.cancel`; payloads carry metrics and identifiers only, never images or model data. |
| SC-001 | amended | Measured against `job_state.py` transitions (`tests/test_job_state.py`) plus the terminal-run-cancel rejection once amended. "Unauthenticated updates" has no per-message meaning in aegis; the equivalent check is that a worker without DB/broker credentials cannot write. |
| SC-002 | amended | Provenance = Run/Job snapshot + `Provenance`; lineage = recorded original run id. |
| SC-003 | amended | "Runtime deliberately unavailable" = broker/DB down or sandbox refusing the artifact → 503/501/`failed` Job; zero web-process execution is unchanged. |
| Unresolved decisions and gates — D001, D002, D003, D004, D005 | superseded | RESOLVED on 2026-09-08 by the product owner (D11; recorded in `specs/_shared/decisions.md`): open aerial/military-vehicle imagery + tabular classifier; aegis Keycloak OIDC + NextAuth with dev-token mode for the demo; bundled models + ONNX/state_dict upload with sandboxed worker loading, endpoints Phase B; Celery worker + aegis plugin sandbox, OpenSandbox not used; per-family metrics with denominators, benign noise control, eps sweep, SHAP, MRI per D9. |
| Unresolved decisions and gates — D007 | unchanged | Still OPEN; no owner or reviewer is assigned by this note. |
| Unresolved decisions and gates — "F008 event writer contract is foundational" | superseded | The contract exists in code (`aegis/audit/chain.py`); it is no longer a gate. |
| Edge cases — "Adapter acknowledgment is lost after the adapter accepted work" | amended | Covered by `task_acks_late=True` redelivery plus the fail-closed redelivery guard (a redelivered non-`queued` Job is skipped) and the reaper for Jobs that died mid-run. |

### plan.md and tasks.md items pointing at superseded locations

The Replit monorepo paths in `plan.md` and `tasks.md` are replaced by aegis paths (D10). This list does not rewrite those files; it records the correct target for each.

**plan.md**

- Approach step 1 and gate G2 (D004: "never assume a standalone worker exists in Replit") → runtime is decided: `aegis/workers/celery_app.py`, `aegis/workers/bootstrap.py`, `deploy/Dockerfile.worker`, `deploy/docker-compose.yml`.
- Approach step 2 and table row "Data model" (`specs/004-run-management/data-model.md`) → the authoritative model is `aegis/db/models.py` (`Run`, `Job`, `Finding`, `Artifact`, `AuditEvent`) plus `aegis/ml/schema.py` (`RunConfig`, `Provenance`, `RunRecord`); the state machine is `aegis/workers/job_state.py`. A feature-local `data-model.md`, if written, documents this mapping and defines no tables.
- Approach step 3 and table row "User contract" (`specs/004-run-management/contracts/run-management.openapi.yaml`) → FastAPI routers `aegis/api/v1/runs.py`, `aegis/api/v1/runs_cancel.py`, `aegis/api/v1/findings.py`, `aegis/api/v1/verify.py`, plus the new ML router(s) under `aegis/api/v1/` for `/v1/models` and `/v1/models/{id}/attacks`; OpenAPI is generated by FastAPI (`/openapi.json` from `aegis/api/app.py`), not hand-authored.
- Approach step 4 and table row "Adapter contract" (`specs/004-run-management/contracts/execution-adapter.openapi.yaml`) → no HTTP adapter exists or is planned; the boundary is `aegis/workers/tasks/` (new `attack.py`, `explain.py`, `harden.py`; existing `verify.py`), `aegis/workers/bootstrap.py::task_context`, and `aegis/scanners/sandbox.py` / `aegis/scanners/sandbox_worker.py`.
- Approach step 5 and table row "Shared API integration" (`lib/api-spec/openapi.yaml`, "existing generators") → there is no shared hand-written OpenAPI file and no generated client; the web client is the hand-maintained `web/src/lib/api.ts`. `lib/api-client-react/` and `lib/api-zod/` do not exist in this repository.
- Approach step 8 and table row "Run UI" (`artifacts/ai-assurance/src/features/run-management/`) → `web/src/app/runs/page.tsx`, `web/src/app/runs/[id]/page.tsx`, `web/src/lib/api.ts` (`cancelRun`, `isCancellable`).
- Table row "Run service" (`artifacts/api-server/src/services/assurance/run-management.ts`) → `aegis/services/runs.py` (cancel, exists) plus a new attack-campaign admission module in `aegis/services/` following `aegis/services/scans.py::create_scan_job` and `aegis/services/verify.py::create_verify_job`.
- Table row "Run routes" (`artifacts/api-server/src/routes/assurance/run-management.ts`) → `aegis/api/v1/runs.py`, `aegis/api/v1/runs_cancel.py`, and the new ML router under `aegis/api/v1/`.
- Table row "Persistence schema" (`lib/db/src/schema/run-management.ts`) → `aegis/db/models.py`; schema changes are Alembic revisions under `aegis/db/migrations/versions/` (latest existing: `0009_tenant_org_id_guard.py`). `Target.kind` and `Job.type` are free `String` columns, so the M0 vocabulary additions need no DDL.
- Table row "Server checks" (`artifacts/api-server/src/tests/assurance/run-management.test.ts`) → pytest under `tests/` using the sqlite harness in `tests/conftest.py`: existing `tests/test_job_state.py`, `tests/test_reaper.py`, `tests/test_admission_audit_before_enqueue.py`, `tests/test_worker_hardening.py`; ML-specific tests under `tests/ml/` with the `ml` marker and the `TinyTarget` fake (`tests/ml/fakes.py`).
- Table row "UI checks" (`artifacts/ai-assurance/src/tests/run-management.test.tsx`) → `web/src/app/runs/page.test.tsx`, `web/src/app/runs/[id]/page.test.tsx` (vitest).
- Dependencies ("F008 event writer contract") → exists: `aegis/audit/chain.py`.

**tasks.md**

- T002 (resolve D004; "install nothing") → resolved (D11-D004); the runtime lives in `aegis/workers/` and `deploy/`.
- T004 (`specs/004-run-management/data-model.md`) → `aegis/db/models.py`, `aegis/ml/schema.py`, `aegis/workers/job_state.py`, as above.
- T005 (`run-management.openapi.yaml`; `lib/api-spec/openapi.yaml` and regeneration) → FastAPI routers under `aegis/api/v1/`; no shared YAML, no generator.
- T006 (`execution-adapter.openapi.yaml`) → no adapter contract; `aegis/workers/tasks/`, `aegis/workers/bootstrap.py`, `aegis/scanners/sandbox.py`.
- T007 (`lib/db/src/schema/run-management.ts`) → `aegis/db/models.py` and `aegis/db/migrations/versions/`.
- T008 (`artifacts/api-server/src/services/assurance/run-management.ts`) → new admission module in `aegis/services/`; cancel already in `aegis/services/runs.py`.
- T009 (`artifacts/api-server/src/routes/assurance/run-management.ts`) → `aegis/api/v1/runs.py`, `aegis/api/v1/runs_cancel.py`, new ML router.
- T010 (`artifacts/ai-assurance/src/features/run-management/RunManagement.tsx`) → `web/src/app/runs/page.tsx`, `web/src/app/runs/[id]/page.tsx`.
- T011 (no path; "authenticated idempotent adapter updates") → `aegis/workers/bootstrap.py`, `aegis/workers/job_state.py`, `aegis/services/runs.py` (the 409 terminal-run amendment).
- T012 (`artifacts/ai-assurance/src/features/run-management/RunActions.tsx`) → the cancel dialog already in `web/src/app/runs/[id]/page.tsx` plus `web/src/lib/api.ts`.
- T013 (`artifacts/api-server/src/tests/assurance/run-management.test.ts`) → `tests/` (pytest, sqlite conftest) and `tests/ml/`.
- T014 (no path; retry/rerun) → the new admission module in `aegis/services/`.
- T016 (`artifacts/ai-assurance/src/tests/run-management.test.tsx`) → `web/src/app/runs/page.test.tsx`, `web/src/app/runs/[id]/page.test.tsx`.

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned  
**Suggested owner role:** Platform lead  
**Required reviewers:** Product owner; engineering reviewer; security/data reviewer

## What and why

Save and present an authorized asynchronous evaluation lifecycle with immutable provenance, explicit adapter boundaries, safe cancel/retry behavior, and honest failure when no approved runtime exists.

## Scope

- Request a run only from an approved published profile.
- Snapshot exact actor, profile, catalog, evaluator, environment, and request provenance.
- Present shared lifecycle states and partial-evidence completeness.
- Request cancellation and create linked retry/rerun records.
- Ingest outcomes only through an approved authenticated adapter boundary.
- Fail gracefully when execution runtime or supported capability is unavailable.
- Emit the F008 event writer contract for run actions and transitions.

## Exclusions

- Selecting, installing, or assuming a standalone worker in Replit.
- Running evaluations in the web process or unrestricted uploaded code.
- Attack recipes, operational targets, weapons, mission systems, or sensitive data.
- Treating transport errors, skipped cases, or unavailable explanations as model outcomes.
- Evidence analysis, findings, reports, or claims of certification.

## Prioritized user stories

### US1 (P1) — Request and observe an authorized run

As an Owner or Analyst, I can request a bounded run from a published profile and observe its saved lifecycle.

**Independent test:** Request with authorized/unauthorized actors, approved/unapproved profiles, duplicate identities, and absent runtime; verify no web-process fallback.

- **Given** an authorized actor, published profile, and approved available adapter, **when** a request is confirmed, **then** one queued run with immutable provenance is saved.
- **Given** no approved runtime, **when** a run is requested, **then** the UI reports execution unavailable and no evaluation is silently started.
- **Given** a duplicate request identity, **when** it is submitted again, **then** the existing outcome is returned without creating another execution.

### US2 (P1) — Cancel a running evaluation

As an Owner or Analyst, I can request cancellation and see whether cancellation or a racing completion won.

**Independent test:** Exercise every allowed transition, cancellation races, stale updates, and direct unauthorized calls.

- **Given** a running run, **when** cancellation is accepted, **then** status becomes cancel_requested until a terminal adapter outcome arrives.
- **Given** completion occurred before cancellation acceptance, **when** events are reconciled, **then** completed remains terminal and ordering is retained.
- **Given** a terminal run, **when** cancellation is requested, **then** it is rejected without changing provenance.

### US3 (P2) — Retry without rewriting history

As an authorized user, I can retry an eligible failed, cancelled, or timed-out run as a new linked run.

**Independent test:** Retry eligible/ineligible states and inspect linkage, current approvals, errors, and partial evidence labels.

- **Given** an eligible terminal run and still-approved inputs, **when** retry is confirmed, **then** a new run links to the original and snapshots current request context.
- **Given** inputs are archived or approval is no longer valid, **when** retry is requested, **then** it is blocked with a reason.
- **Given** partial evidence before failure, **when** details open, **then** retained evidence is labeled incomplete and not summarized as a complete evaluation.

## Functional requirements

- **FR-001:** Only active Owners and Analysts MAY request, cancel, retry, or rerun; Reviewers and Viewers MAY read authorized run status and provenance.
- **FR-002:** A run request MUST reference one exact published, non-archived profile version and its exact approved catalog versions.
- **FR-003:** Each accepted request MUST create one saved run with immutable project, actor, request identity, input/profile versions, evaluator/environment versions, timestamps, and lineage.
- **FR-004:** States and transitions MUST exactly follow the shared run state contract, and terminal states MUST never become running.
- **FR-005:** Execution MUST cross an approved authenticated adapter contract and MUST never execute untrusted work in the web process.
- **FR-006:** If runtime, isolation, capability, or adapter authentication is unavailable, the request MUST fail explicitly without execution fallback.
- **FR-007:** Cancellation MUST record request and acceptance ordering; racing completion is accepted only under the shared ordering rule.
- **FR-008:** Retry or rerun MUST create a new linked run and reauthorize current eligibility; F004 MUST NOT edit, archive, or delete the original run.
- **FR-009:** Adapter updates MUST be idempotent, authorized, transition-valid, correlated, and rejected when stale or inconsistent.
- **FR-010:** Transport failure, timeout, skipped cases, unsupported explanations, and incomplete evidence MUST remain distinct from evaluated model outcomes.
- **FR-011:** Run list/detail/trigger/cancel/retry UI MUST show loading, empty, queued, active, cancellation, every terminal state, partial completeness, denied, stale, and runtime-unavailable behavior.
- **FR-012:** Run actions and transitions MUST use the F008 event writer contract; an inability to persist required provenance or events MUST fail explicitly.

## Key entities

- **Run:** Immutable request/provenance snapshot, lifecycle state, completeness, and lineage.
- **RunTransition:** Prior/new state, source, ordering, reason, timestamp, and correlation.
- **ExecutionRequest:** Idempotent bounded handoff to an approved adapter.
- **ExecutionUpdate:** Authenticated transition/outcome message with schema version.
- **RunError:** Category, safe message, retry eligibility, and non-secret diagnostic reference.

## Edge cases

- Adapter acknowledgment is lost after the adapter accepted work.
- Cancel and complete updates arrive out of order.
- Profile or catalog versions are archived after queueing.
- Partial evidence arrives before failure or timeout.
- Event/provenance storage fails while an adapter update arrives.

## Success criteria

- **SC-001:** Focused transition checks reject 100% of invalid, stale, unauthenticated, or terminal-to-running updates while preserving accepted ordering.
- **SC-002:** Every sampled run and retry exposes exact immutable input/profile/evaluator provenance and correct original-run lineage.
- **SC-003:** With runtime deliberately unavailable, 100% of sampled requests show an explicit unavailable outcome and zero execute in the web process.

## Unresolved decisions and gates

- **D001, D003, D005:** Domain, permitted inputs, and definitions constrain adapter capability.
- **D002:** F001 managed authorization blocks implementation.
- **D004:** Runtime, isolation, ceilings, and timeout/cancel semantics block live execution.
- **D007:** Named owner and reviewers remain unassigned.
- F008 event writer contract is foundational; full F008 feature is not required.