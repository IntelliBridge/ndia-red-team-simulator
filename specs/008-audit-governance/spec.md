# Feature Specification: Audit and Governance

## Reconciliation with the product spec (2026-09-08)

This feature is the feature-level layer beneath the canonical product spec, [docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md](../../docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md), which overrides this file wherever they conflict. Under decisions D1 (reuse the full redsim platform) and D10 (feature map), F008 "Audit and governance" maps onto the redsim audit chain that already exists at the restored redsim head rather than onto a new event contract: the envelope is the `AuditEvent` record of `redsim/audit/chain.py` (`chain_id`, `seq`, `ts`, `actor`, `action`, `target`, `allowlist_check`, `override`, `success`, `detail`, `schema_version`, `prev_hash`, `this_hash`, `run_id`, `project_id`; `SCHEMA_VERSION = 1`), hash-linked as `this_hash = sha256(prev_hash || canonical_json(record))` on one chain per run (`run:<id>`), per project (`project:<id>`) or install-wide (`system`); the writer is the `AuditWriter` Protocol with `PostgresAuditWriter` (tables `audit_events` and `audit_chain_heads` in `redsim/db/models.py`, row lock on the chain head) online, `JsonlAuditWriter` offline (`<output_dir>/audit/<chain>.jsonl`) and `InMemoryAuditWriter` for tests (`REDSIM_TEST_AUDIT=memory`), selected by `resolve_writer`; write-time redaction is `redsim/audit/redact.py` (`redact_audit_detail`: sensitive keys, header names, token patterns) and the digests-not-bytes forensic detail shape is `redsim/audit/forensic.py` (64 KiB cap, blob refs); append-only is enforced at the database by migration `redsim/db/migrations/versions/0004_audit_append_only.py` (a `BEFORE UPDATE OR DELETE` row trigger and a `BEFORE TRUNCATE` statement trigger that raise for every role, superuser included; `INSERT, SELECT`-only grants and pgaudit where the deploy-time roles and extension exist); every admission service (`redsim/services/{scans,runs,targets,verify,auth_profiles}.py`) appends its event through `authorize()` in `redsim/safety.py` before it writes `Run`/`Job` rows or enqueues Celery (`tests/test_admission_audit_before_enqueue.py`); integrity is verified by `verify_chain` through `GET /v1/audit/verify` (`redsim/api/v1/audit.py`, `Action.AUDIT_VERIFY`, minimum role `admin`), `redsim audit verify --run|--project|--all` (`redsim/cli/audit.py`) and the `/audit` page (`web/src/app/audit/page.tsx`); off-database tamper resistance is the WORM export (`redsim/storage/worm.py` `WormArchive`; beat task `redsim.export_chains_to_worm` in `redsim/workers/tasks/worm_export.py`; `redsim audit export`; S3/MinIO Object Lock, `REDSIM_WORM_EXPORT`, `REDSIM_WORM_BUCKET`, `REDSIM_WORM_RETENTION_DAYS` default 2555, `REDSIM_WORM_LOCK_MODE` default `COMPLIANCE`); and the offline reviewer bundle is `redsim evidence-pack` (`redsim/services/evidence.py`: per-chain JSONL, `verification.json`, secret-free `system.json`, `manifest.json` with a pack hash). Against John Sasser's milestones (S1 section 14) F008's foundation is pre-existing and is confirmed in M0; D4(c) requires an event for every upload, attack, explain, harden and verify from M1 onward (S1 section 10: "every mutating call emits a chained audit event before enqueue", S1 section 13), so the Phase A work is emitting ML events with the right `action`, `target` and bounded `detail` values through the same `authorize(writer=…)` seam, plus the demo step "open `/audit`, show the tamper-evident chain of the whole campaign" (S1 section 15, M5); M7 (deploy) enables S3 Object Lock for the WORM export. The governance half of this spec (versioned policy, policy decisions, retention requests, deletion markers, an event browser with filters and pagination) has no redsim counterpart and is Phase B; retention stays gated on D006, which remains OPEN. Two observations from reading the restored code are recorded here for the concurrent code fix-up rather than fixed: `web/src/app/audit/page.tsx` requests `/v1/audit/verify?all=1` and expects `{chains: [...]}` while `redsim/api/v1/audit.py` verifies one chain and returns `{chain_id, verified, count, broken_at, reason}`; and `audit_events` is not among the tables migration `0006_tenant_rls` places under row-level security (`projects`, `targets`, `runs`, `jobs`, `findings`, `llm_usage`, `artifacts`, `remediation_attempts`, `application_logs`), so cross-project isolation of audit reads is the `check()` role gate plus chain-id scoping. Role mapping follows F001: Owner → `admin`, Reviewer → `approver`, Analyst → `remediator`, Viewer → `scanner` (the baseline mapping; a rank-0 `viewer` role is Phase B). D002 is RESOLVED (redsim Keycloak OIDC + NextAuth, dev-token mode allowed for the demo; recorded in [../_shared/decisions.md](../_shared/decisions.md)); D007 stays OPEN, so the Owner line below remains "Unassigned". Nothing in this section claims the ML vertical is implemented; the redsim paths above name platform code that exists, and the ML event vocabulary is the product spec's to fix.

| Requirement | Status after consolidation | Note |
| --- | --- | --- |
| US1 | amended | The "one bounded event envelope and writer" already exists: `AuditEvent` and `AuditWriter` in `redsim/audit/chain.py`, appended through `authorize()` in `redsim/safety.py`. The story's remaining Phase A content is the ML event vocabulary (which `action` and `target` each upload/attack/explain/harden/verify call emits, and what its `detail` may carry: target and run ids, model manifest digest, campaign configuration hash, attack id, ε, `n`, seed, artifact ids; never sample bytes, model weights or credentials). Prohibited metadata is sanitized, not rejected: `redact_audit_detail` replaces sensitive keys and token patterns with `<REDACTED>` at write time. Mutation of an existing event fails at the database (migration `0004`), not only at the service layer. The independent test "without the governance UI" holds today through `InMemoryAuditWriter` and `verify_chain`. |
| US2 | amended | Phase A browsing is the existing admin-only `/audit` page and `GET /v1/audit/verify`: per-chain integrity cards (verified/broken, length, head hash, `broken_at`) with explicit empty ("No audit chains found") and failure ("Failed to verify") states, plus `redsim audit verify` and `redsim evidence-pack --project`. Non-Owners (`scanner`, `remediator`, `approver`, non-members) receive 403 from `check(user, Action.AUDIT_VERIFY, project_id)` without event disclosure. A project-scoped event list with filters and pagination is Phase B (see FR-006); until then the chain is read through `AuditWriter.read_chain`, the evidence pack, or SQL on `audit_events`. |
| US3 | deferred to Phase B | No `GovernancePolicyVersion`, `PolicyDecision`, `RetentionRequest` or `DeletionMarker` exists in redsim. What exists today and stands in Phase A: write-time audit redaction; the secret-free evidence pack; F007 report streaming gated by `ensure_run_access`; and Object Lock retention on archived chains, which is a minimum-retention floor (nothing can delete an archived chain before `retention_until`), not a purge capability. No purge or retention operation exists anywhere in redsim, so "blocked while D006 is OPEN" holds by absence; D006 remains OPEN. |
| FR-001 | amended | Field mapping onto the redsim envelope: event ID → (`chain_id`, `seq`) plus `this_hash` (Postgres also has an autoincrement `id`); project ID → `project_id` (nullable for the `system` chain); actor or service identity → `actor` string with the platform prefixes `user:<email>`, `worker:<task>` (e.g. `worker:worm_export`), `cli:anonymous`; timestamp → `ts` / `created_at`; action → `action` (dotted, ≤ 64 chars, e.g. `target.manage`, `verify.replay`, `audit.worm_export`); entity type/ID/version → `target` (≤ 1024 chars) plus `detail` keys such as `target_id`, `kind`, and the model manifest digest or configuration hash, because no dedicated version column exists; outcome → `success` with `allowlist_check` and `override`; correlation ID → `run_id` (the chain itself is per run) and `detail.request_id`; bounded non-sensitive metadata → `detail` JSONB after redaction. The envelope adds fields this FR did not list (`allowlist_check`, `override`, `prev_hash`, `this_hash`, `schema_version`). |
| FR-002 | amended | redsim sanitizes rather than validates against an allowlist: `redact_audit_detail` runs on every write, and the 64 KiB `MAX_AUDIT_ATTRS_BYTES` bound applies to the `tool_detail` builder in `redsim/audit/forensic.py`, not to the writer generally. Under the product spec the Phase A bound is a `detail` builder for ML events in `redsim/ml/`, mirroring `forensic.tool_detail` (ids, digests, ε, counts, artifact refs; raw inputs, outputs and model artifacts stay in the blob store and appear only as `{sha256, location, kind}` refs). A rejecting metadata allowlist inside the writer is Phase B. |
| FR-003 | amended | Stronger than required and enforced in three layers: the hash chain (`verify_chain`), the database triggers and `UNIQUE (chain_id, seq)` / `UNIQUE (chain_id, this_hash)` constraints of migration `0004`, and the Object Lock archive. No edit, archive or delete route exists for audit events. Caveat stated by the product spec: the offline `JsonlAuditWriter` is append-only by construction but not enforced against file edits; tampering there is detectable by `verify_chain`, not prevented. |
| FR-004 | amended | Admission is fail-closed today: `authorize()` calls `writer.append` synchronously and lets exceptions propagate, so a failed audit write means no `Run`/`Job` row and no enqueue (ordering pinned by `tests/test_admission_audit_before_enqueue.py`). The ML admission routes of S1 section 10 (`POST /v1/models`, `/v1/models/{id}/attacks`, `/v1/findings/{id}/explain`, `/harden`, `/verify`) must reuse this seam. The one known fail-open spot is the WORM beat task, which swallows a failure of its own `audit.worm_export` emit so an export is never lost to a logging error; the product spec records it. Worker-side events (the scan worker's `scan.execute.<scanner>` pattern) follow the policy the product spec sets for `attack.run`, `explain.run`, `harden.recommend` and `verify.replay`. |
| FR-005 | amended | Owner → `admin`; the gate is `check(user, Action.AUDIT_VERIFY, project_id)` on `GET /v1/audit/verify` (and, for application-log queries, `GET /v1/logs`). Scoping is by chain id (`project:<id>`, `run:<id>`). Because `audit_events` is not under RLS (migration `0006`) and the verify route gates on the caller-supplied `project_id` while returning only integrity verdicts, the Phase B browse endpoint must resolve a run chain's project through `ensure_run_access` (as `redsim/api/v1/reports.py` does) and filter events by the authorized project before any event content is returned. |
| FR-006 | deferred to Phase B | No filtering or pagination endpoint exists; Phase A distinguishes "no chains", "verify failed" and "chain broken at seq N" on `/audit`, and 403 for denied access. Field filters, cursors and the "invalid cursor" state arrive with the Phase B event browser, added to `redsim/api/v1/audit.py` and `web/src/app/audit/`. |
| FR-007 | deferred to Phase B | No policy entity, revision history or approval workflow exists in redsim. The closest Phase A records are the campaign configuration stored with the `Run` (F003) and the WORM lock settings, which are environment values, not versioned policy. |
| FR-008 | deferred to Phase B | No policy-decision interface exists; F007 exports in Phase A are the Markdown/JSON/HTML reports streamed by `GET /v1/runs/{id}/report.{ext}` behind `ensure_run_access`, with the audit chain's write-time redaction and the secret-free evidence pack as the only redaction in force. Dataset licence restrictions (D3: open, unclassified, licensed data only) are recorded in the bundled asset manifest at build time and printed in reports; a versioned licence decision returned by a policy interface is Phase B. |
| FR-009 | amended | The pre-D006 clause is in force and is stronger than written: no destructive retention operation exists in redsim, `DELETE`/`TRUNCATE` on `audit_events` is blocked at the database, and archived chains under `COMPLIANCE`-mode Object Lock cannot be removed before `retention_until` by anyone. The post-D006 operation (Owner authorization, approved policy, eligible entity, explicit scope, confirmation) is Phase B and can never reach an archived chain before its lock expires; D006 must set `REDSIM_WORM_RETENTION_DAYS` deliberately rather than inherit the default 2555. |
| FR-010 | deferred to Phase B | A deletion marker would be an ordinary chain event (same writer, a dotted `action` in the existing style, `detail` carrying target identity/version, scope, policy version, outcome and no deleted content), so it is cheap once a purge exists; no purge exists in Phase A. |
| FR-011 | amended | The wording is fixed by the product spec to match what redsim can show: "hash-chained, append-only application event history; tamper-evident (`redsim audit verify` recomputes every hash); append-only at the database; archived copies tamper-resistant under S3 Object Lock when WORM export is enabled; not independent certification and not a non-repudiation claim." The MUST NOT on "cryptographically tamper-proof" stands. The inherited compliance crosswalk (`build_controls_matrix` in `redsim/services/evidence.py`, `docs/ops/compliance-evidence.md`) maps controls including AU-10 "non-repudiation"; F008 text in this product does not repeat that claim, and the crosswalk is flagged for review as platform documentation. Known gaps to disclose: offline JSONL mode has no database trigger; the WORM task's own emit is fail-open; denied policy decisions (403) are not written to the chain today (a Phase B addition shared with F001). |
| FR-012 | amended | The fail-explicit behaviors that exist: `verify_chain` returns `verified=false` with `broken_at` and `reason`; `/audit` renders broken chains and verify failures; `authorize()` raises `AuthorizationError` and writes a `success=false` event; the WORM export archives a broken chain with `verified: false` and lists it in `broken_chains`. The policy-change, stale-revision, unapproved-purge, partial-purge and policy-evaluation clauses are Phase B with FR-007 to FR-010. |
| SC-001 | amended | Mutation rejection is covered by `tests/test_audit_append_only.py` (Postgres-gated) and chain integrity by `tests/test_audit_chain.py`, which also covers secret-key and header redaction; cross-project event requests are the `check()` gate. A raw-payload rejection check follows the Phase B allowlist validator (FR-002); in Phase A the ML `detail` builder is tested for carrying refs, not bytes, under `tests/ml/` with the `ml` marker where torch is needed. |
| SC-002 | deferred to Phase B | Policy versions do not exist; every event already resolves to an `actor` and a `seq` on a verifiable chain. |
| SC-003 | amended | "Zero purge attempts succeed before D006" holds by absence of any purge path, by the database trigger and by Object Lock; the truthful-marker half is Phase B with FR-010. |

**Exclusions, entities, edge cases and open decisions.** The exclusion "operational/tactical content … or attack-recipe logging" is read with D3: events carry the published ART attack id, ε, `n` and seed as provenance for rerun (D4(b), constitution Principle V), on open, unclassified, licensed data; that is configuration provenance, not an attack recipe, and no mission system is connected. Key entities: `AuditEvent` → `audit_events` / the `AuditEvent` dataclass; `GovernancePolicyVersion`, `PolicyDecision`, `RetentionRequest`, `DeletionMarker` → no redsim tables (Phase B, one Alembic revision after `0009_tenant_org_id_guard.py`). Edge cases: a service identity with no human actor is the platform convention `worker:<task>`; "underlying content removed while the event reference remains" is the designed behavior, since `detail` carries digests and blob refs and outlives the blob; "business action succeeds but its event write fails" cannot happen at admission because the event precedes the action, and for worker-side events the product spec fixes the policy. Success criteria SC-002 and the marker half of SC-003 move to Phase B acceptance. The "Unresolved decisions" list changes: D002 is RESOLVED (2026-09-08, product owner); D006 and D007 remain OPEN and are not assigned here.

### Locations in plan.md and tasks.md that point at the Replit monorepo

D10 replaces William's "Proposed implementation locations" with redsim paths. The items below are listed, not rewritten; plan.md and tasks.md stand as written and no task box is checked.

plan.md:

- "Proposed shared API edits: `lib/api-spec/openapi.yaml`" → the FastAPI router is the contract: `redsim/api/v1/audit.py`, registered in `redsim/api/app.py` under `/v1`; human-readable references are `docs/api/v1.md` and `docs/architecture/audit-chain.md`. Nothing is coordinated into a shared YAML.
- "Proposed schemas: `lib/db/src/schema/audit-events.ts`" → `redsim/db/models.py` (`AuditEvent`, `AuditChainHead`) and `redsim/db/migrations/versions/0004_audit_append_only.py` (both exist). "`lib/db/src/schema/governance-policies.ts`" → a new Alembic revision in `redsim/db/migrations/versions/` after `0009_tenant_org_id_guard.py` (Phase B).
- "Proposed services: `artifacts/api-server/src/services/assurance/audit-writer.ts`" → `redsim/audit/chain.py`, `redsim/audit/redact.py`, `redsim/audit/forensic.py`, and the `authorize()` seam in `redsim/safety.py` (all exist). "`audit-query.ts`", "`governance-policy.ts`", "`retention.ts`" → no redsim module exists; Phase B modules belong under `redsim/services/`.
- "Proposed routes: `artifacts/api-server/src/routes/assurance/audit.ts`" → `redsim/api/v1/audit.py`. "`governance.ts`" → a Phase B router under `redsim/api/v1/`.
- "Proposed frontend feature: `artifacts/ai-assurance/src/features/governance/`" → the `@redsim/web` app: `web/src/app/audit/page.tsx` exists; policy and retention screens are Phase B routes under `web/src/app/`.
- "Generated clients/validators remain `lib/api-client-react/` and `lib/api-zod/`; never hand-edit" → redsim has no generated client or validator layer; the web app calls the API through `web/src/lib/api.ts`. The item has no redsim counterpart.
- Approach step 3 ("add an append-only application writer alongside F001") and the "Foundation" dependency → already present in redsim; the step's remaining content is the ML event vocabulary.
- "Proposed contract: `specs/008-audit-governance/contracts/audit-event.yaml`" and "`contracts/governance-policy.yaml`" → paths under `specs/` remain valid as feature documentation; the code contract for the event is the `AuditEvent` record in `redsim/audit/chain.py` (`SCHEMA_VERSION = 1`) and the event shape in `docs/architecture/audit-chain.md`.

tasks.md:

- T001 (`contracts/audit-event.yaml`): path valid as feature documentation; the envelope fields are fixed by redsim, so the task's remaining content is the ML `detail` vocabulary and the writer failure policy for worker-side events.
- T003 (`contracts/governance-policy.yaml`): path valid; Phase B content.
- T004: `lib/api-spec/openapi.yaml`, `lib/api-client-react/`, `lib/api-zod/` → `redsim/api/v1/audit.py` plus `web/src/lib/api.ts` and `docs/api/v1.md`; there is no regeneration step.
- T005: `lib/db/src/schema/audit-events.ts` → `redsim/db/models.py` and `0004_audit_append_only.py` (exist; the task is already satisfied by the platform).
- T006, T007: `artifacts/api-server/src/services/assurance/audit-writer.ts` → `redsim/audit/chain.py`, `redsim/audit/redact.py`, `redsim/audit/forensic.py` (exist); the ML `detail` builder is Phase A under `redsim/ml/`; T007's rejecting allowlist is Phase B.
- T008: `artifacts/api-server/src/tests/assurance/audit-writer.test.ts` → `tests/test_audit_chain.py`, `tests/test_audit_single_file_chains.py`, `tests/test_audit_append_only.py` (Postgres-gated), `tests/test_admission_audit_before_enqueue.py` (exist); new ML-event tests under `tests/ml/` with the sqlite harness from `tests/conftest.py` and the `ml` marker where torch is needed.
- T009 (`contracts/event-integration.md`): path valid; its content is the `authorize(writer=…)` call pattern and the action table in `docs/architecture/audit-chain.md` "What lands on the chain", extended with the ML actions.
- T010: `artifacts/api-server/src/services/assurance/audit-query.ts` → no redsim module; a Phase B module under `redsim/services/`.
- T011: `artifacts/api-server/src/routes/assurance/audit.ts` → `redsim/api/v1/audit.py` (the Phase B list endpoint is added there).
- T012, T013: `artifacts/ai-assurance/src/features/governance/AuditHistory.tsx`, `AuditState.tsx` → `web/src/app/audit/page.tsx` (chain cards with empty and failure states exist); filters, pagination and gap disclosure are Phase B in the same route.
- T014: `artifacts/api-server/src/tests/assurance/audit-query.test.ts` → pytest under `tests/` using `make_sqlite_session_factory` (Phase B).
- T015 (`contracts/retention-policy.md`): path valid; D006 OPEN.
- T016: `lib/db/src/schema/governance-policies.ts` → a new Alembic revision after `0009_tenant_org_id_guard.py` (Phase B).
- T017: `artifacts/api-server/src/services/assurance/governance-policy.ts` → a Phase B module under `redsim/services/`.
- T018: `artifacts/ai-assurance/src/features/governance/GovernancePolicy.tsx` → a Phase B route under `web/src/app/`.
- T019: `artifacts/api-server/src/services/assurance/retention.ts` → a Phase B module under `redsim/services/`; it must honor Object Lock (archived chains are not purgeable before `retention_until`) and the `0004` triggers (audit events are never purge targets).
- T020: `artifacts/ai-assurance/src/features/governance/RetentionRequest.tsx` → a Phase B route under `web/src/app/`.
- T021: `artifacts/api-server/src/tests/assurance/governance-policy.test.ts` → pytest under `tests/` (Phase B).
- T022: `artifacts/ai-assurance/src/tests/governance-content.test.tsx` → the co-located Vitest file `web/src/app/audit/page.test.tsx` (exists), extended with the FR-011 wording check.
- T023 (`specs/008-audit-governance/acceptance.md`): path valid.

**Feature:** F008 — Audit and Governance  
**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: security and data governance lead)  
**Approval required:** Product owner, engineering reviewer, security/data reviewer
## What and why

Audit and governance first provides a minimal shared event envelope and reliable application writer so other features can record accountable outcomes from the start. A later increment lets authorized Owners browse event history and administer approved redaction, export, and retention policy without placing raw inputs or secrets in audit records.

This feature provides append-only application event history. It MUST NOT be described as independently certified, cryptographically tamper-proof, or external compliance logging unless a separate reviewed capability later establishes those properties.
## Scope

- Early minimal AuditEvent envelope and writer usable alongside F001 foundation work.
- Append-only records of actor/service, project, action, entity/version, outcome, correlation, time, and bounded non-sensitive metadata.
- Later Owner-only audit browsing with filters and explicit empty/denied/failure states.
- Versioned draft and approved policy for evidence redaction and F007 export decisions.
- Authorized retention operations only after D006 approval and relevant storage contracts exist.
- Purge markers that truthfully distinguish removed content from retained event history.
## Exclusions

- Raw model inputs/outputs, datasets, model artifacts, credentials, tokens, secrets, or unrestricted metadata in audit events.
- Claims of independent certification, tamper-proofing, non-repudiation, or complete external-system history.
- Unapproved exact retention durations or destructive purge before D006 is resolved.
- Editing or deleting historical AuditEvents as an ordinary application action.
- Operational/tactical content, live mission integrations, or attack-recipe logging.
## User stories

### US1 — Record minimal accountable events (P1 foundation)

As a feature developer, I want one bounded event envelope and writer so authorized and denied application actions can produce consistent history from the first increment.

**Independent test:** Submit valid and invalid envelopes without the governance UI and verify accepted records are append-only while sensitive or oversized metadata is rejected.

- **Given** a valid project action outcome, **When** the writer receives the minimal envelope, **Then** it stores one event with identity, entity/version, outcome, correlation, timestamp, and bounded metadata.
- **Given** metadata contains prohibited raw input or a secret-classified field, **When** writing is attempted, **Then** the event is rejected or sanitized according to an approved field allowlist and the action does not silently proceed as fully audited.
- **Given** a caller attempts to alter an existing event, **When** the request reaches the service, **Then** mutation fails and the original event remains unchanged.

### US2 — Browse application event history (P2)

As an authorized Owner, I want to browse project-scoped events so I can review who attempted or completed governed actions.

**Independent test:** Query a project containing successful and denied events, then verify a non-Owner and cross-project identifier cannot retrieve them.

- **Given** an active Owner, **When** they filter project event history, **Then** matching events and pagination/completeness context are shown.
- **Given** an Analyst, Reviewer, Viewer, or non-member, **When** they request audit history, **Then** access fails server-side without event disclosure.
- **Given** there are no matching records or retrieval fails, **When** the browser responds, **Then** it distinguishes empty results from unavailable history.

### US3 — Govern export, redaction, and retention (P2/P3)

As an authorized Owner, I want reviewed policy versions and explicit retention operations so data minimization does not falsify history.

**Independent test:** Evaluate a draft/approved export policy and attempt purge before and after the D006 gate; no purge occurs before approval, and an approved purge retains a truthful marker.

- **Given** an approved policy version, **When** F007 requests an export decision, **Then** allowed, denied, omitted, and redacted fields are returned with the policy version.
- **Given** D006 is OPEN, **When** any purge is requested, **Then** it is blocked regardless of Owner role.
- **Given** D006 is resolved and a permitted target is purged, **When** history is later viewed, **Then** a deletion marker identifies scope, authority, policy version, and outcome without claiming the removed content remains intact.

## Functional requirements

- **FR-001:** The minimal AuditEvent MUST contain event ID, project ID, actor or service identity, timestamp, action, entity type/ID/version, outcome, correlation ID, and bounded non-sensitive metadata.
- **FR-002:** The writer MUST validate an explicit metadata allowlist and size bounds and MUST reject secrets, credentials, raw input/output payloads, model artifacts, and other prohibited content.
- **FR-003:** Accepted AuditEvents MUST be append-only through application interfaces; create is writer-controlled, while edit, archive, and ordinary delete operations MUST be unavailable.
- **FR-004:** Event writing MUST expose success or explicit failure to the calling feature so security-relevant actions can follow an approved fail-closed policy rather than falsely claiming complete history.
- **FR-005:** Only active project Owners MUST be able to browse audit history, with server-side project/object authorization and no cross-project disclosure.
- **FR-006:** Audit browsing MUST support bounded filtering and pagination by approved event fields and distinguish no matches, unavailable storage, invalid cursor, and denied access.
- **FR-007:** Policy drafts MUST support Owner creation and edit with revision history; approval MUST require designated review, approved versions MUST be immutable, and supersession MUST retain prior versions.
- **FR-008:** The approved policy decision interface MUST return export allowance, omission/redaction instructions, license restrictions, and exact policy version without returning protected values.
- **FR-009:** Destructive retention operations MUST remain disabled until D006 is formally resolved and MUST then require Owner authorization, approved policy, eligible storage entity, explicit scope, and confirmation.
- **FR-010:** Every permitted purge MUST retain an append-only deletion marker recording target identity/version, scope, policy/authority, actor, timestamp, and outcome without raw deleted content.
- **FR-011:** History and UI language MUST state that this is append-only application event history, not independently certified tamper-proof logging, and MUST disclose known gaps or writer failures.
- **FR-012:** Unauthorized policy changes, stale revisions, unapproved purge, partial purge, policy-evaluation failure, and audit retrieval failure MUST fail explicitly without silently broadening access or asserting intact history.

## Key entities
- **AuditEvent:** Immutable bounded application event envelope and outcome.
- **GovernancePolicyVersion:** Draft or approved redaction, export, licensing, and retention rules with author/reviewer history.
- **PolicyDecision:** Versioned allow, deny, omit, or redact result for a specific authorized request.
- **RetentionRequest:** Explicit scope, eligible entity versions, authority, status, confirmation, and result.
- **DeletionMarker:** Durable event stating what was purged and under which authority, without deleted raw content.

## Edge cases

- The business action succeeds but its event write fails under the approved fail-closed/fail-open classification.
- A service identity has no human actor, or an actor loses membership after an event occurred.
- Metadata keys are acceptable but values exceed bounds or resemble credentials.
- Pagination spans concurrent event appends.
- A policy is superseded while an export request is being evaluated.
- A multi-object purge partially fails; each actual outcome remains distinguishable.
- Underlying content is removed while an AuditEvent reference remains.

## Success criteria

- **SC-001:** Focused validation rejects 100% of sampled prohibited raw-payload, secret-field, mutation, and cross-project event requests.
- **SC-002:** Every sampled policy/export decision and retention outcome resolves to an exact policy version and authorized actor or service.
- **SC-003:** Every sampled approved purge retains a truthful deletion marker, while zero purge attempts succeed before D006 resolution.

## Unresolved decisions

- **D002:** Managed identity and initial Owner bootstrap.
- **D006:** Retention periods, export redaction, license restrictions, metadata retention, and destructive-operation authority.
- **D007:** Accountable owner and independent reviewers.