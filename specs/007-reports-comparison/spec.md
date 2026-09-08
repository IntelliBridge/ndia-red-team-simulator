# Feature Specification: Reports and Comparison

**Feature:** F007 — Reports and Comparison  
**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: assurance reporting lead)  
**Approval required:** Product owner, engineering reviewer, security/data reviewer
## What and why

Reports and comparison create immutable, versioned snapshots of selected run evidence and reviewed findings, then provide policy-permitted PDF and JSON exports. Compatible run comparisons identify exactly which controlled variables changed, preserve coverage and partial-run labels, and avoid a universal score across unrelated measures.
## Scope

- Authorized creation and reading of versioned ReportSnapshot records.
- Snapshot selection of F004 run/evidence versions and F006 finding/review revisions.
- PDF and JSON exports after F008 redaction/export policy evaluation.
- Comparison of compatible runs with explicit changed and unchanged variables.
- Metric-family denominators, coverage, limitations, provenance, and partial-run labels.
- Explicit denied, incompatible, empty, redacted, stale-selection, and export-failure states.

## Exclusions

- Editing immutable source runs, evidence, findings, reviews, or snapshots.
- Universal assurance scores, certification, operational-readiness claims, or causal claims.
- Export that bypasses project membership, object authorization, license, or redaction policy.
- Tactical, weapon, live-target, sensitive-data, or attack-recipe reporting.
- Automatically treating a changed metric as proof a recommendation caused improvement.

## User stories

### US1 — Create a versioned report snapshot (P1)

As an authorized analyst or reviewer, I want a fixed report snapshot so the report remains traceable when later findings or labels change.

**Independent test:** Create and reopen a snapshot from one completed or partial run and verify every selected version, limitation, denominator, and status remains fixed.

- **Given** authorized compatible source records, **When** a user creates a snapshot, **Then** exact run, evidence, finding, and review versions plus scope and policy version are retained.
- **Given** the selected run is partial, **When** the snapshot is viewed, **Then** every relevant summary and export is prominently labeled partial.
- **Given** a selection becomes stale or unreadable, **When** creation is attempted, **Then** creation fails explicitly and no incomplete snapshot is presented as successful.

### US2 — Export a policy-permitted report (P1)

As an authorized exporter, I want PDF or JSON output with required redaction so I can share only approved report content.

**Independent test:** Export one permitted snapshot in both formats and attempt denied/redacted fields, verifying policy is enforced server-side.

- **Given** an Owner, Analyst, or Reviewer is permitted by F001 and F008 policy, **When** PDF or JSON is requested, **Then** the export records format, snapshot version, redaction policy, and limitations.
- **Given** a Viewer or policy-denied actor requests export, **When** the request is evaluated, **Then** it fails without generating or disclosing the file.
- **Given** fields require redaction, **When** export succeeds, **Then** omission/redaction markers are truthful and protected values are absent.

### US3 — Compare compatible runs (P2)

As a reviewer, I want two compatible runs compared by metric family with changed variables listed so I can interpret differences honestly.

**Independent test:** Compare a compatible pair and an incompatible pair; only the former yields a comparison and it lists all known changed variables.

- **Given** two runs satisfy approved compatibility rules, **When** compared, **Then** changed and unchanged model, dataset, profile, evaluator, and environment variables are explicit.
- **Given** runs are incompatible or compatibility is unknown, **When** comparison is requested, **Then** it is blocked with reasons and no misleading delta is calculated.
- **Given** a metric is absent from either run, **When** the comparison renders, **Then** it shows unavailable coverage rather than zero change.

## Functional requirements

- **FR-001:** Report reads, snapshot creation, archive actions, and exports MUST require active F001 membership plus server-side project, object, and role authorization.
- **FR-002:** Authorized users MUST be able to create an immutable ReportSnapshot containing exact selected run, evidence, finding, review, scope, provenance, limitations, coverage, policy, and schema versions.
- **FR-003:** Snapshot creation MUST reject stale, inaccessible, cross-project, or unsupported source selections and MUST not claim success after partial persistence failure.
- **FR-004:** A partial source run MUST be labeled `partial` in snapshot views and every export location where its results appear.
- **FR-005:** PDF and JSON exports MUST represent the same snapshot semantics and disclose format, generation time, schema version, limitations, and redaction policy version.
- **FR-006:** Export authorization, license restrictions, field omission, and redaction MUST be enforced server-side using the approved F008 policy; denied exports MUST not produce retrievable artifacts.
- **FR-007:** Comparisons MUST proceed only for runs satisfying approved compatibility rules and MUST list known changed, unchanged, and unknown variables.
- **FR-008:** Comparison metrics MUST retain per-family definitions, denominators, exclusions, coverage, and missing values and MUST NOT be combined into a universal score.
- **FR-009:** Reports and comparisons MUST distinguish observations, reviewer judgments, candidate recommendations, and retest outcomes without attributing causality.
- **FR-010:** ReportSnapshots MUST be immutable after creation; an authorized Owner MAY archive a snapshot, restore it if policy permits, but ordinary edit or delete MUST be unavailable and retention deletion MUST defer to F008.
- **FR-011:** Empty report lists, no comparable runs, unavailable/redacted sources, unknown compatibility, export timeout, and format-generation failure MUST be explicit and must not leak protected content.

## Key entities

- **ReportSnapshot:** Immutable selected versions, scope, coverage, provenance, limitations, partial label, redaction policy version, and archive status.
- **ExportRequest:** Actor, snapshot version, PDF or JSON format, policy decision, outcome, and non-sensitive artifact reference.
- **RunComparison:** Two source runs, compatibility result, changed/unchanged/unknown variables, metric-family deltas, and limitations.
- **PolicyProjection:** F008-owned export/redaction decision consumed by F007.

## Edge cases

- One selected finding revision is superseded after snapshot creation.
- A report contains both complete and partial source runs.
- PDF succeeds while a separately requested JSON export fails.
- Export permission is revoked between request and retrieval.
- Runs use the same profile ID but different immutable profile versions.
- A metric definition changes while retaining a similar display label.
- An archived snapshot is still referenced by an authorized historical audit event.

## Success criteria

- **SC-001:** Every sampled report/export resolves to exact immutable source versions and displays all applicable limitations and partial-run labels.
- **SC-002:** In focused checks, 100% of denied or redaction-required export cases enforce policy server-side with zero protected field disclosure.
- **SC-003:** Every accepted comparison lists known changed variables and retains metric denominators/coverage; zero sampled outputs contain a universal score.

## Unresolved decisions

- **D001:** First benign domain and report vocabulary.
- **D005:** Metric definitions, denominators, and compatibility criteria.
- **D006:** Export redaction, licensing, retention, and artifact policy.
- **D007:** Accountable owner and independent reviewers.