# F004 — Run Management

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