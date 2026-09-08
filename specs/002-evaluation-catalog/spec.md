# F002 — Evaluation Catalog

## Reconciliation with the product spec (2026-09-08)

The canonical product spec is [docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md](../../docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md). Where this feature spec and that document differ, the product spec and the product-owner decisions it records (D1–D13, approved 2026-09-08) win; this section records what those decisions change here. The body of this spec below is William Yiu's original feature text and is kept as the feature-level layer beneath the product spec (D10). Its header status stays Draft: the readiness checklist in `specs/_shared/readiness-checklist.md` remains the approval gate, and the decision resolutions below close gates, not the gate itself.

**(a) Mapping to aegis and to John's milestones.** F002 is the catalog of things a campaign can evaluate. In aegis terms it is the `Target` table (`aegis/db/models.py`) with two new `Target.kind` values, `ml_model_artifact` and `ml_model_endpoint` (John's section 4; `kind` is a free `String(32)` whose comment lists `url|github_repo|image`, so the M0 "migration" is API-side validation of the two new values rather than a column change); the existing admin-gated `/v1/targets` router (`aegis/api/v1/targets.py`, service `aegis/services/targets.py`, which writes the `target.manage` audit event through `aegis.safety.authorize` before the row is mutated) extended by John's `/v1/models` surface (section 10); and the bundled sample models and datasets the demo uses. A "model version" is a content-addressed artifact: an uploaded file lands in the blob store (`aegis/storage/blobs.py`; `AEGIS_BLOB_BACKEND=s3` for MinIO/S3, where a second put of identical bytes is a no-op), `Target.value` is the blob key, and the sha256 plus the asset manifest travel with every campaign as `Provenance.model_sha256` / `Provenance.model_manifest` (`aegis/ml/schema.py`). Upload rules are D2: ONNX preferred, PyTorch `state_dict` with an explicit architecture accepted, full pickles refused by default, and every uploaded model loaded only on the Celery worker inside aegis's plugin-sandbox pattern (`aegis/scanners/sandbox.py`, `AEGIS_PLUGINS_SANDBOX`: separate process, no network, rlimits) — never in the API process. Bundled assets are D3 and D4(d): open, unclassified, clearly licensed aerial / military-vehicle imagery for the demo; CIFAR-10 as the CI/fixture dataset only; and a bundled sklearn/XGBoost tabular model. Clean accuracy, dataset identity, license and sha256 are recorded in the asset manifest at build time, never in prose. The black-box endpoint connector (`ml_model_endpoint`, credentials in the Fernet-encrypted `AuthProfile`) is Phase B (D2; John's B1+). Milestones: M0 (scaffold and the `Target.kind` values), M1 (load the bundled CNN from ONNX in the sandbox) and M4 (bundled tabular model); in the D8 demo-critical order the bundled image model is step 1 and ONNX upload is step 5, after tabular. William's entities map as follows: CatalogRecord → a `Target` row; ModelVersion → the sha256-addressed blob plus its manifest; DatasetVersion → a bundled dataset manifest entry (no table in Phase A); FixtureReference → `Target.value` (blob key or bundled asset id) plus the manifest; CatalogReview → Phase B (FR-005 / FR-006 below). Role names used in this spec (Owner / Analyst / Reviewer / Viewer) are William's; the product spec maps them onto aegis's ranked roles (`scanner` < `remediator` < `approver` < `admin`, `aegis/api/policy.py`), and in the restored code `Action.TARGET_MANAGE` requires `admin`.

**(b) Requirements whose meaning changes.** Every user story and functional requirement in this spec is listed; "unchanged" rows are included so coverage is visible.

| Requirement | Status after consolidation | Note |
| --- | --- | --- |
| US1 | amended | A "record and draft version" becomes a `Target` row (`kind=ml_model_artifact`) pointing at a sha256-addressed blob, or a bundled asset selected from the manifest. Scenario 2 splits: an ONNX / `state_dict` upload is accepted in Phase A under the D2 admission rules (format detected by file signature at upload, sha256 recorded, any load deferred to the worker sandbox); a full pickle is refused with the reason stated; an arbitrary endpoint is still rejected, now with "Phase B" guidance rather than "pending D003". Dataset records are bundled only (D3); there is no dataset upload in Phase A. Scenario 3 (empty state, permitted roles) is unchanged apart from the role mapping in FR-001. |
| US2 | deferred to Phase B | Independent Reviewer approval of a catalog version is not on the D8 demo-critical path and has no aegis counterpart today (`Target` has `verified: bool` but no author column, and `POST /v1/targets/{id}/verify` returns 501 because the ownership-verification engine was removed). Phase A substitute: bundled assets are approved at build time by the D3 decision and their manifest; uploads are admitted by rule with the upload event on the audit chain. When it lands, the natural home is `Target.verified` set by an `approver`-tier action whose audit event carries actor, decision and reason. |
| US3 | amended | Archive is Phase B (FR-008). Hard delete exists today: `DELETE /v1/targets/{id}` (admin tier; audit event written before the row is removed; the web page already confirms through a dialog). A target referenced by a run cannot be deleted because `runs.target_id` is a foreign key to `targets.id`; the friendly "blocked with reference context" response is not implemented yet. Deleting a `Target` row never deletes the content-addressed blob or any campaign evidence — that is a retention operation under F008 / D006, not catalog editing. |
| FR-001 | amended | Role names defer to the product spec's access-matrix mapping onto aegis roles. As restored, registering or deleting a target is `Action.TARGET_MANAGE`, minimum role `admin`, and the shared baseline (`specs/_shared/architecture.md`, access matrix) keeps that bar: registration and ONNX / `state_dict` upload are Owner (`admin`, `target.manage`) actions; Analysts (`remediator`) select registered models and configure campaigns. This is a recorded divergence from the first draft's Analyst-level registration. Reads are gated by active project membership (`ensure_project_access`) plus Postgres row-level security by `org_id`. |
| FR-002 | amended | Stable ID → `Target.id` (project-scoped through `project_id`, tenant-scoped through `org_id`); explicit type → `Target.kind`; immutable version ID → the artifact sha256 (content-addressed blob). Bundled datasets are identified by manifest name, version, split and sha256; there is no DatasetVersion table in Phase A. |
| FR-003 | amended | The provenance fields survive but live in the asset manifest (bundled) or the upload metadata (uploaded), are surfaced as `TargetInfo.metadata`, and are copied into `Provenance.model_manifest` / `dataset` / `dataset_split` for every campaign. "Public-or-synthetic classification" becomes "open, unclassified, named license" per D3. Domain values are the `Domain` literal in `aegis/ml/schema.py`: `image` and `tabular` live, `llm` registered but not evaluated (Phase B). |
| FR-004 | superseded | D003 is RESOLVED (D11): bundled models plus ONNX / `state_dict` upload in Phase A, endpoints Phase B, pickles refused by default. The "allowlist" survives in three forms: the bundled asset manifest, the upload format allowlist enforced on the worker, and aegis's `target_allowlist` admission check in `aegis.safety.authorize`. |
| FR-005 | deferred to Phase B | The draft / approved / rejected / archived state machine with actor, reason and timestamp is Phase B. Phase A has two states: a `Target` row exists (admitted) or has been deleted; both transitions are `target.manage` audit events with `op: create` / `op: delete` in `detail`. |
| FR-006 | deferred to Phase B | Author-independent approval needs an author column (or an audit-chain lookup) plus an `approver`-tier action; neither is on the D8 path. The rule itself — an Owner cannot bypass independence — is retained for Phase B unchanged. |
| FR-007 | amended | Immutability is by construction: a version is a sha256, and `/v1/targets` has no update route, so a descriptive change is a new `Target` row (Phase A) or, in Phase B, a new draft version. Meaning unchanged; mechanism named. |
| FR-008 | deferred to Phase B | There is no archived flag on `Target` today. Phase A delivers the second half — historical readability — differently: every campaign snapshots `model_sha256` and `model_manifest` into its `Provenance`, so a run stays readable regardless of the catalog row, and referenced rows cannot be deleted (FK). Exclusion from new selections without deletion is the Phase B part. |
| FR-009 | amended | Route, admin gating, audit-before-mutate and UI confirmation exist. "Unused only" is enforced for runs by the FK; there are no profile or governance references to check in Phase A (F003 stores the campaign configuration with the Run). Blob and evidence deletion are excluded from this operation (F008 / D006). |
| FR-010 | amended | The list/detail UI is John's `/models` and `/models/[id]` (section 11), grown from `web/src/app/targets/page.tsx`, which today still offers pentest scanners and must be replaced by the bundled sample picker and the upload dialog. "Version" renders as the short sha256 plus manifest fields. The "Connect endpoint" control is shown as unavailable with its reason (`TargetInfo.status = not_implemented`, the S2 honesty rule), not hidden and not faked. Loading, empty, validation, denied, stale and unavailable states are retained. |
| FR-011 | amended | The F008 event envelope is aegis's hash-chained `AuditEvent` (`aegis/audit/chain.py`, `AuditWriter.append(action, actor, target, detail)`), written before the DB mutation by `aegis/services/targets.py`; D4(c) requires the upload event on this chain. `detail` carries kind, blob key and sha256 — never model bytes, dataset rows or credentials; Phase B endpoint credentials go in `AuthProfile` (Fernet), never in `Target.value`. Authorization is the configured policy engine (static, OPA or Cedar) plus RLS. |
| FR-012 | unchanged | Audit-before-mutate means a failed event write aborts the create or delete (fail closed — the same ordering the existing admission tests exercise in `tests/test_admission_audit_before_enqueue.py`). Uploading identical bytes twice resolves to the same sha256. "No partial approval" applies in Phase B. |
| Bundled tabular dataset reference (D001 / D005) | added 2026-09-08 | The bundled sklearn / XGBoost tabular model is trained on lexical features of the Kaggle malicious-URLs dataset, id `sid321axn/malicious-urls-dataset` (https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset; owner Manu Siddhartha; file `malicious_phish.csv`, columns `url` and `type`; 651,191 rows, 45,664,439 bytes; classes benign / defacement / phishing / malware, benign the majority; compiled from ISCX-URL-2016, PhishTank, the Malware Domain Blacklist, faizann24's phishing-URL set and a 2021 Kaggle URL dataset). Licence: "CC0: Public Domain" as stated by Kaggle's metadata API, recorded in the asset manifest together with the file sha256, the per-class counts and the clean metrics; that manifest entry is the tabular `DatasetVersion`. Handling rule: URL strings are data — the pipeline never fetches, resolves, or renders a URL from the dataset and computes lexical features only. The full download requires a Kaggle API token (`KAGGLE_USERNAME` / `KAGGLE_KEY`) read by the asset script and absent from CI; a small committed stratified sample (a few hundred rows) is the CI fixture, so tests never touch Kaggle and, per the Slice 2 rule, the sample is never presented as a demo result. The HuggingFace mirrors `joshtobin/malicious_urls` (<1K rows) and `JorgeGMM/malicious_urls` (10K–100K rows) are partial: fallback fixtures only if their licence is confirmed, never the source of record. |

Also affected outside the FR/US identifiers: SC-001 now reads "manifest-recorded license and sha256" where it says "approved benign fixture reference"; SC-002's archive half is Phase B; SC-003 is unchanged. In "Unresolved decisions and gates", D001, D002 and D003 are RESOLVED as of 2026-09-08 (see `specs/_shared/decisions.md`, D11) and D007 remains OPEN; the "Catalog approval" note's independence rule is kept for Phase B. The Scope bullet "approved public or synthetic benign fixtures" and the Exclusions bullets "arbitrary uploads, executable artifacts" and "fetching or executing a model" are narrowed, not removed: D3 substitutes open, unclassified, licensed imagery (a recorded divergence from the constitution's Principle II, proposed as an amendment under D12), and D2 permits bounded — not arbitrary — uploads whose only execution is a sandboxed load on the worker.

**(c) Plan and task items that point at Replit monorepo paths.** The correct aegis locations are given; `plan.md` and `tasks.md` are not rewritten here and no task box is checked.

- `plan.md` Approach step 3 and the "Shared API integration" row (`lib/api-spec/openapi.yaml`, "existing generators") → aegis has no hand-maintained OpenAPI file and no generated client. FastAPI serves the schema from the routers registered in `aegis/api/app.py` (`app.include_router(..., prefix="/v1")`); the contract is the Pydantic request/response models in the router module; the web client is the hand-written `web/src/lib/api.ts`.
- `plan.md` "Catalog service" row (`artifacts/api-server/src/services/assurance/evaluation-catalog.ts`) → `aegis/services/targets.py` (extend) or a new `aegis/services/models.py`; framework detection by file signature belongs in `aegis/ml/loaders.py` (John's section 5; not yet present) and runs on the worker.
- `plan.md` "Catalog routes" row and Approach step 4 (`artifacts/api-server/src/routes/assurance/evaluation-catalog.ts`) → `aegis/api/v1/models.py` (new `/v1/models`, John's section 10) alongside the existing `aegis/api/v1/targets.py`, registered in `aegis/api/app.py`.
- `plan.md` "Persistence schema" row and Approach step 7 (`lib/db/src/schema/evaluation-catalog.ts`) → `aegis/db/models.py` (`Target`), with a new Alembic revision under `aegis/db/migrations/versions/` (latest is `0009_tenant_org_id_guard.py`) only if a column is added; the two new `kind` values need API-side validation, not a column change.
- `plan.md` "Catalog UI" row and Approach step 6 (`artifacts/ai-assurance/src/features/evaluation-catalog/`, "the future frontend") → `web/src/app/models/page.tsx` and `web/src/app/models/[id]/page.tsx` (John's section 11), evolving `web/src/app/targets/page.tsx`; components from `packages/design-system`.
- `plan.md` "Server checks" row (`artifacts/api-server/src/tests/assurance/evaluation-catalog.test.ts`) → `tests/test_targets.py` (existing) and `tests/ml/` (pytest marker `ml`; `tests/ml/fakes.py` provides `TinyTarget`; the sqlite harness is `tests/conftest.py`).
- `plan.md` "UI checks" row (`artifacts/ai-assurance/src/tests/evaluation-catalog.test.tsx`) → `web/src/app/models/page.test.tsx` (vitest, alongside the existing `web/src/app/targets/page.test.tsx`).
- `plan.md` paths `specs/002-evaluation-catalog/data-model.md` and `specs/002-evaluation-catalog/contracts/evaluation-catalog.openapi.yaml` are spec-folder paths and remain valid; if the OpenAPI file is written it documents the FastAPI routes and is not fed to a generator.
- `tasks.md` T004 (`lib/api-spec/openapi.yaml`, regeneration) → `aegis/api/v1/models.py` bodies and `web/src/lib/api.ts`, as above.
- `tasks.md` T006 (`lib/db/src/schema/evaluation-catalog.ts`) → `aegis/db/models.py` plus `aegis/db/migrations/versions/` if a column is added.
- `tasks.md` T007 (`artifacts/api-server/src/services/assurance/evaluation-catalog.ts`) → `aegis/services/targets.py` or `aegis/services/models.py`.
- `tasks.md` T008 (`artifacts/api-server/src/routes/assurance/evaluation-catalog.ts`) → `aegis/api/v1/models.py`, registered in `aegis/api/app.py`.
- `tasks.md` T009 (`artifacts/ai-assurance/src/features/evaluation-catalog/CatalogEditor.tsx`) → `web/src/app/models/page.tsx` (bundled sample picker plus upload dialog).
- `tasks.md` T011 (`artifacts/ai-assurance/src/features/evaluation-catalog/CatalogReview.tsx`) → Phase B; when built it lives under `web/src/app/models/[id]/`.
- `tasks.md` T012 (`artifacts/api-server/src/tests/assurance/evaluation-catalog.test.ts`) → `tests/test_targets.py` and `tests/ml/`.
- `tasks.md` T014 (`artifacts/ai-assurance/src/features/evaluation-catalog/`) → `web/src/app/models/`.
- `tasks.md` T015 (`artifacts/ai-assurance/src/tests/evaluation-catalog.test.tsx`) → `web/src/app/models/page.test.tsx`.
- `tasks.md` T001 names `specs/_shared/decisions.md`, which is correct; its content changes, not its path: D001 and D003 are RESOLVED there as of 2026-09-08 and D007 remains OPEN. Correspondingly, `plan.md` gates G1 (D001), G2 (D003) and G3 (D002) are closed by D11; G4 is satisfied by the aegis audit chain (FR-011 above); G5 (D007) stays open.

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned  
**Suggested owner role:** Evaluation researcher  
**Required reviewers:** Product owner; security/data reviewer

## What and why

Maintain traceable, versioned metadata for benign model and dataset resources so profiles and runs refer to reviewed provenance rather than mutable labels.

## Scope

- Register stable model and dataset records with immutable metadata versions.
- Reference only approved public or synthetic benign fixtures in the initial scope.
- Review provenance and approval status independently of authorship.
- Edit drafts by creating or updating an unused draft version.
- Archive records or versions without breaking historical references.
- Hard-delete only unused draft versions after explicit confirmation.

## Exclusions

- Arbitrary uploads, executable artifacts, arbitrary endpoints, secrets, or provider setup.
- Fetching or executing a model or dataset.
- Sensitive, operational, mission-system, weapons, or combat-targeting content.
- Profile definition, run execution, evidence, or retention purge.

## Prioritized user stories

### US1 (P1) — Register traceable benign metadata

As an Analyst, I can create a model or dataset record and draft version with provenance and an approved fixture reference.

**Independent test:** Create each record type, validate required metadata, and verify unsupported or unapproved references fail without partial records.

- **Given** an approved public fixture reference and complete provenance, **when** an Analyst saves a draft, **then** a stable record and draft version are visible.
- **Given** an arbitrary endpoint or upload, **when** registration is attempted, **then** it is rejected with D003-gated guidance.
- **Given** no records, **when** the catalog opens, **then** a benign empty state offers registration only to permitted roles.

### US2 (P1) — Review and approve a version

As an independent Reviewer, I can inspect provenance and approve or reject a draft version for later profile use.

**Independent test:** Verify author independence, required provenance, permissions, immutable approval, and visible rejection reasons.

- **Given** a complete draft authored by another member, **when** a Reviewer approves it, **then** that exact version becomes approved and immutable.
- **Given** the author is also the acting Reviewer, **when** approval is attempted, **then** it is blocked.
- **Given** missing provenance, **when** review is submitted, **then** approval fails and the missing fields are identified.

### US3 (P2) — Retire or remove safely

As an Analyst or Owner acting within policy, I can archive referenced catalog material or delete only an unused draft.

**Independent test:** Attempt archive and delete against referenced, approved, unused-draft, and stale versions.

- **Given** a version referenced by a profile or run, **when** retirement is requested, **then** it is archived and historical references remain readable.
- **Given** an unused draft, **when** an authorized user confirms deletion, **then** it is removed and the outcome is recorded.
- **Given** a referenced or non-draft version, **when** hard deletion is requested, **then** it is blocked with reference context.

## Functional requirements

- **FR-001:** Only active Owners and Analysts MAY create/edit drafts, archive, or request eligible draft deletion; Reviewers and Viewers are read-only except for a separately authorized review action.
- **FR-002:** Each record MUST have a stable project-scoped ID and one or more immutable version IDs with explicit type.
- **FR-003:** Each version MUST capture source, license/usage statement, public-or-synthetic classification, domain, content summary, and non-secret fixture reference.
- **FR-004:** Initial references MUST come from an approved benign fixture allowlist; uploads and arbitrary endpoints MUST be rejected pending D003.
- **FR-005:** Version states MUST include draft, approved, rejected, and archived, with actor, reason, and timestamp for review transitions.
- **FR-006:** Approval MUST require an authorized Reviewer or Owner who did not author the version; an Owner cannot bypass independence.
- **FR-007:** Approved versions MUST be immutable; descriptive changes MUST create a new draft version.
- **FR-008:** Only active Owners and Analysts MAY archive; archived versions MUST be excluded from new selections while remaining readable wherever historically referenced.
- **FR-009:** Only active Owners and Analysts MAY request hard deletion, which MUST be limited to unused drafts, require explicit confirmation, and fail if any profile, run, or governance reference exists.
- **FR-010:** Catalog list/detail UI MUST expose type, version, provenance, state, archived status, loading, empty, validation, denied, stale, and unavailable behavior.
- **FR-011:** Mutations MUST enforce project/object authorization server-side and emit the agreed F008 event envelope without sensitive payloads.
- **FR-012:** Duplicate, stale, missing-reference, and event-write failures MUST be explicit and MUST NOT produce partial approval or deletion.

## Key entities

- **CatalogRecord:** Stable project-scoped identity and model/dataset type.
- **ModelVersion:** Immutable metadata version, provenance, benign reference, author, and state.
- **DatasetVersion:** Immutable metadata version, provenance, benign reference, author, and state.
- **CatalogReview:** Version, independent reviewer, decision, reason, and timestamp.
- **FixtureReference:** Approved non-secret pointer and governance classification.

## Edge cases

- A fixture is withdrawn after an approved version was used by a run.
- A draft becomes referenced between delete confirmation and commit.
- Two reviewers decide the same draft concurrently.
- Source metadata changes without changing the underlying fixture.
- A catalog result exists but is filtered out because it is archived.

## Success criteria

- **SC-001:** Focused checks show 100% of approved sampled versions contain all required provenance and an approved benign fixture reference.
- **SC-002:** Focused lifecycle checks permit hard deletion for unused drafts only and preserve every sampled historical reference after archive.
- **SC-003:** In moderated review, users identify record type, exact version, provenance, and approval state for all sampled catalog entries without opening another tool.

## Unresolved decisions and gates

- **D001:** First domain determines domain-specific metadata.
- **D002:** Managed identity blocks authorized implementation through F001.
- **D003:** Permitted formats, access method, and proposed catalog approval policy require product/security review.
- **D007:** Named owner and reviewers remain unassigned.
- **Catalog approval:** FR-006 now matches the proposed shared access matrix: an independent Reviewer or Owner may approve. This resolves the document inconsistency, not the pending D003 approval.