# Shared Planning Baseline

**Status:** Contracts and conventions mapped onto the redsim platform this repository is a fork of. The product spec ([docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md](../../docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md)) is canonical for scope; the redsim code named below is canonical for what exists. Nothing in this document implements application behavior, and the ML vertical under `redsim/ml/` is contracts only as of 2026-09-08.

## Feature boundaries

| ID | Slug | Owns |
| --- | --- | --- |
| F001 | 001-project-access | Application identity, project membership, role enforcement |
| F002 | 002-evaluation-catalog | Versioned model and dataset metadata, upload rules, compatibility and approval status |
| F003 | 003-evaluation-profiles | Attack-campaign configuration: attack set, ε grid, reference budget, sample dataset, scoring weights |
| F004 | 004-run-management | Run lifecycle, Celery task execution in the sandboxed worker, cancellation and result ingestion |
| F005 | 005-evidence-workbench | Evidence browsing, per-family metrics with denominators, ε curve, modality-appropriate SHAP |
| F006 | 006-findings-review | Findings, derived severity, candidate recommendations, verify links; dismiss-with-reason and audited `reviewer_notes` (Phase A, after the D8 order); all other reviewer decisions (Phase B) |
| F007 | 007-reports-comparison | Report snapshots, exports, ΔMRI comparison of compatible runs |
| F008 | 008-audit-governance | Hash-chained audit events, WORM export, approved retention and redaction |

## Access matrix mapped onto redsim roles

redsim enforces authorization server-side in two layers (`redsim/api/policy.py`):

- **Read:** any active membership on the project (`has_project_access` / `ensure_project_access`); list endpoints are scoped by `accessible_project_ids`; Postgres row-level security by `org_id` (`redsim/db/migrations/versions/0006_tenant_rls.py`) backs it at the database.
- **Mutate:** a role-rank table. Roles, lowest to highest: `scanner` (1) < `remediator` (2) < `approver` (3) < `admin` (4). Each `Action` has a minimum role; the default `StaticPolicyEngine` reproduces the table, and `REDSIM_POLICY_ENGINE=opa|cedar` can delegate the same decision to an external policy service.
- **Membership** arrives in the OIDC token as the `redsim_project_roles` claim (Keycloak) or, in dev-token mode, as `admin` on the `default` project. Membership is not inherited from any hosting-platform collaboration; the application has no member-management route in Phase A (Keycloak owns it).

Mapping of the proposed roles onto redsim roles:

| Proposed role | redsim role | Notes |
| --- | --- | --- |
| Viewer | `scanner` | redsim has no read-only role. The lowest rank can also start scans (`scan.start`). Campaign start is therefore a new `Action.ATTACK_RUN = "attack.run"` registered at `remediator` (named here; F003 and F004 cite it), not a reuse of `scan.start`, so that `scanner` stays read-mostly in the ML vertical. This is the single Phase A Viewer mapping used by F001, F003, F004, F006, F007 and F008. A strict rank-0 `viewer` role (an entry in `_ROLE_RANK`, the Keycloak realm roles and any OPA/Cedar policy) is a Phase B policy change; in Phase A a Viewer holds `scanner` and can still start a legacy scan, a gap the demo accepts. |
| Analyst | `remediator` | Starts and cancels campaigns; requests explain, harden, verify. |
| Reviewer | `approver` | Reserved for approval actions. In Phase A the only `approver`-gated ML route is the optional dismiss-with-reason (F006 cheap item, permitted after the D8 demo-critical order); profile approval and finding confirm are Phase B. |
| Owner | `admin` | Registers and uploads models (`target.manage`), manages endpoint credentials (`auth_profile.manage`, Phase B), verifies the audit chain (`audit.verify`), edits project settings. |

Matrix, with the redsim gate that enforces each row:

| Action | Owner (`admin`) | Analyst (`remediator`) | Reviewer (`approver`) | Viewer (`scanner`) | redsim gate |
| --- | --- | --- | --- | --- | --- |
| Read project evidence, findings, runs, artifacts, audit trail | Yes | Yes | Yes | Yes | any membership + RLS |
| Register bundled models; upload ONNX / `state_dict` artifacts | Yes | No | No | No | `target.manage` (admin). Divergence from the first draft, which let Analysts register catalog entries: redsim treats a target as an authorization boundary and the product spec keeps that bar for model artifacts. Analysts select registered models and configure campaigns. |
| Configure and start an attack campaign (`POST /v1/models/{id}/attacks`) | Yes | Yes | Yes | No | new `Action.ATTACK_RUN` (`attack.run`) at `remediator` rank — the same dual use as an `Action` and a `Job.type` that `verify.replay` already has; not `scan.start`. F003 FR-001 and F004 FR-001 cite it. |
| Cancel a campaign | Yes | Yes | Yes | No | `run.cancel` (remediator) |
| Request explanation / candidate recommendations (`explain.run`, `harden.recommend`) | Yes | Yes | Yes | No | new `Action`s at `remediator` rank, same bar as `fix.generate` |
| Verify-after-harden (`verify.replay`) | Yes | Yes | Yes | No | `verify.replay` (remediator) |
| Approve profiles; confirm/dismiss findings | Yes, except own item | No | Yes, except own item | No | `approver` rank. Dismiss-with-reason (`status=false_positive`, reason mandatory in the audit detail, new `Action` such as `finding.dismiss`) and an audited `reviewer_notes` PATCH (`finding.notes`) are Phase A cheap items permitted only after the D8 demo-critical order; profile approval and finding confirm are Phase B. The "except own authored item" rule is vacuous in Phase A (no human authors a finding or a candidate) and in Phase B is not expressible in the static engine: it needs the OPA/Cedar engine or an explicit author check in the route. |
| Export reports (`GET /v1/runs/{id}/report.{md,json,html}`) | Yes | Yes | Yes | Yes | any membership (`ensure_project_access`). Divergence from the first draft (Viewer: No); restricting export is a D006 policy question, not a Phase A change. |
| Manage members, policy, retention | Yes | No | No | No | `PUT /v1/projects/{slug}/settings` (admin); membership in Keycloak; retention operations wait on D006 |

Removing the last owner is not enforced by the application; it is a Keycloak realm concern until F001 adds a check. Initial owner bootstrap is realm configuration under `deploy/keycloak/`; in dev-token mode (`REDSIM_AUTH_MODE=dev`, token `dev:<email>`, refused when `REDSIM_ENV=prod`, the value `redsim/api/settings.py` and `redsim/config.py` test for) every caller is `admin` on `default`, which is acceptable for the demo only. Invitations are Keycloak-managed; the application stores no invitation secrets.

## Entities mapped onto redsim tables

`redsim/db/models.py` is canonical. The product spec adds two `Target.kind` values and new `Job.type` values as M0 vocabulary additions (`Target.kind` is a free `String(32)` and `Job.type` a free `String(64)` in `redsim/db/models.py`, so the addition is API-side validation of the new values; an Alembic revision is needed only if a column is added); it fixes which `RunRecord` fields (`redsim/ml/schema.py`) live in `Finding.schema_blob`, in `Artifact` rows, and in a campaign/score record, and which MRI fields are stored where. This table records the mapping the feature files must use.

| Planning concept | redsim table / contract | Notes and invariants |
| --- | --- | --- |
| Project / Membership | `organizations`, `projects`, `users`, `project_memberships` (`role` ∈ scanner, remediator, approver, admin) | Tenant isolation by `org_id` RLS. "A project must retain an active owner" is not enforced by redsim today. |
| Invitation | none | Keycloak-managed. No table, no secrets in the application. |
| ModelVersion | `targets` (`kind` = `ml_model_artifact` or `ml_model_endpoint`; `value` = object-store key or inference URL; `verified`, `allowlist_until`) plus the artifact's sha256 and the build-time asset manifest | The immutable version identity of a model is its sha256; bundled models carry a manifest (dataset name/version/split, architecture, seed, clean accuracy recorded at build time, library versions, weights sha256). Descriptive edits never change `value` used by a run. Endpoints are Phase B. |
| DatasetVersion | asset manifest recorded in the campaign configuration and in `Provenance.dataset` / `dataset_split` / `model_manifest` | No table in Phase A; bundled datasets are versioned by manifest and sha256. CIFAR-10 is the CI fixture dataset, not the demo dataset (D001). |
| ProfileVersion | campaign configuration (`RunConfig` shape: target, attacks, params, ε grid, reference budget, `n_samples`, `seed`, `include_control`, `explain_k`, scoring weights) stored with the `Run` as JSONB | The product spec's campaign/score record fixes the column. Stored verbatim with the run so a rerun and a ΔMRI comparison can check compatibility. Approved-and-immutable profiles are Phase B. |
| Run | `runs` (`status`, `stage_table` JSONB, `target_id`, `created_by`, timestamps) and its `jobs` (`type` ∈ `attack.run`, `explain.run`, `harden.recommend`, `verify.replay`; `status`; `celery_task_id`; `error`; `detail` JSONB) | One `Run` is one attack campaign: one model × one modality × a declared attack set × a declared ε grid × a reference budget. `Provenance` (library versions, model sha256, dataset, seed, device, `nondeterminism` list) is stored with the run. |
| Evidence | `Measurement` and `Observation` (`redsim/ml/schema.py`) serialized into `Finding.schema_blob` / the campaign record; binary evidence as `artifacts` rows (`kind`, `sha256`, `location`, `content_type`, `size_bytes`) | Artifacts: adversarial examples, SHAP PNG and raw-values JSON, robustness curve. `Observation.metric_kind` is `Literal["heuristic"]`; the center-mass ratio is labelled heuristic in schema and UI. |
| Finding / Recommendation / Review | `findings` (`schema_blob` = `RedsimFinding` plus attack name, ε, ASR, confidence drop, SHAP artifact ids; `severity` derived by the MRI severity rules; `status`; `validation_state`) and `CandidateRecommendation` records (`status: Literal["candidate"]`, `validation: Literal["not evaluated"]`) | A finding is one attack that crossed its success threshold at some ε. `Interpretation.kind` is `Literal["inferred"]`. Review decisions are Phase B; `Finding.status` is not mutated by any kept route today (there is no PATCH endpoint in `redsim/api/v1/findings.py`). |
| ReportSnapshot | report artifacts from `redsim/report.py` via `GET /v1/runs/{id}/report.{ext}` and `redsim/workers/tasks/report.py`; WORM export via `redsim/storage/worm.py` | Reports carry the campaign configuration, provenance, per-family table with denominators, ε curve, MRI with its five subscores, limitations, and the candidate label on every recommendation. |
| AuditEvent | `audit_events` (`chain_id`, `seq`, `actor`, `action`, `target`, `allowlist_check`, `success`, `detail`, `prev_hash`, `this_hash`) and `audit_chain_heads`; `JsonlAuditWriter` for the offline chain | Upload, attack, explain, harden, verify each append an event before enqueue. `detail` carries bounded non-sensitive metadata; never model bytes, input payloads, or secrets. |
| LLM usage | `llm_usage` (`model`, `task`, tokens, `cost_cents`) | Every Pythia call is metered here under redsim's per-task routing and budget caps. |
| Endpoint credentials | `auth_profiles` (Fernet-encrypted `secret_ciphertext`) | Phase B, for `ml_model_endpoint` connectors. |

`RemediationAttempt`, `FindingTicket`, and `GitHubInstallation` are legacy pentest tables kept for schema compatibility; the ML vertical does not write them.

## Run state contract

redsim's Job state machine (`redsim/workers/job_state.py`) is canonical in code; `Run.status` summarizes its Jobs (created `queued` by the admission service, set `cancelled` by `redsim/services/runs.py`). Legal Job transitions:

```
queued  → running | cancelled
running → succeeded | failed | cancelled | queued   (queued = transient-retry requeue)
succeeded | failed | cancelled → ∅                 (terminal sinks)
```

The proposed states map as follows:

| Proposed state | redsim | Notes |
| --- | --- | --- |
| `queued` | `queued` | Admission writes the audit event first, then enqueues. |
| `running` | `running` | `Job.started_at` set by the worker's `task_context`. |
| `cancel_requested` | none | Cancellation is applied immediately: `Run.status` and every `queued`/`running` Job become `cancelled`. Because terminal states are sinks, a worker that finishes after the cancel cannot flip the row back to `succeeded` (`IllegalJobTransition`); the audit chain's `seq` is the ordering record. |
| `completed` | `succeeded` | A succeeded run must state its limitations (`RunRecord` validator). |
| `failed` | `failed` | `Job.error` carries the reason. Transport failures, skipped cases, and unavailable explanations are recorded as failures or partial evidence, never as model success or model failure. |
| `cancelled` | `cancelled` | — |
| `timed_out` | `failed` with `error = "reaped: exceeded max runtime TTL"` | Set by the stale-job reaper (`redsim/workers/tasks/reaper.py`); the worker sandbox's rlimits bound resource use. |

Invariants kept from the first draft: terminal states never become running again; a retry or rerun creates a new linked run; partial evidence is preserved with explicit completeness and never displayed as a complete evaluation.

## Finding state contract

redsim's `Finding.status` vocabulary (`redsim/schema.py`: `open`, `fixing`, `fixed`, `failed`, `false_positive`) and the stored `Finding.validation_state` vocabulary (`redsim/workers/tasks/verify.py`: `unvalidated` — the column default in `redsim/db/models.py` — `poc_passed`, `poc_failed`, `inconclusive`) are canonical in code. `verified` / `still_vulnerable` / `inconclusive` are the verify *outcome* names (`VerifyStatus` in `redsim/verify.py`) that the worker maps to the stored values (`verified → poc_passed`, `still_vulnerable → poc_failed`, `inconclusive → inconclusive`). In Phase A the ML path writes `validation_state` from a measured `verify.replay` and — only after the D8 demo-critical order is complete — `status=false_positive` (dismiss-with-reason) and `reviewer_notes`; no other status write exists in Phase A.

| Proposed review state | redsim | Phase |
| --- | --- | --- |
| `draft` | none — ML findings are engine-derived, created `open` / `unvalidated` | — |
| `in_review` | `open` | A (every open finding awaits human review; no separate state) |
| `confirmed` | `open` plus a reviewer decision record | B |
| `dismissed` | `false_positive`, reason mandatory in the audit event detail, gated at `approver` | A (cheap item, after the D8 demo-critical order) |
| `retest_requested` | `fixing` while `harden.recommend` / `verify.replay` is in flight | A (implicit), B (explicit) |
| `resolved` | `fixed` with `validation_state = poc_passed` after a measured verify and an independent review | B for the status write; A for `validation_state` |

**Decision (one for the whole layer; F006 and F007 mirror it):** reviewer states are a Phase B addition. The full set is not cheap: it needs a status-mutation route with an `approver` gate and an author check, a revision record, and UI. Two items are cheap because they add no state and no table, and are admitted in Phase A only after the D8 demo-critical order is complete: (1) `reviewer_notes` free text (already a `RunRecord` field) edited through an audited `PATCH`; (2) dismiss-with-reason, written as `status=false_positive` with the reason in the audit event detail and gated at `approver`. Both need a new `Action` member in `redsim/api/policy.py` and a first mutation route in `redsim/api/v1/findings.py`, which today exposes only `GET`. Whether or not they land, Phase A meets the human-review obligation by the separate evidence / interpretation / candidate panels, the candidate and heuristic labels enforced by `Literal` types, `reviewer_notes` on the run record, and `validation_state` written only by a measured verify. A rerun alone is never proof of resolution; changes after review create a new revision and require renewed review when review states arrive.

## Implementation locations

The Replit monorepo paths in the first draft (`artifacts/api-server`, `lib/api-spec`, `lib/db`, `artifacts/ai-assurance`) are replaced by the redsim layout of this repository.

| Concern | Location | Exists today |
| --- | --- | --- |
| ML contracts | `redsim/ml/schema.py`, `redsim/ml/targets/base.py`, `redsim/ml/attacks/base.py` | Yes (contracts only) |
| Targets, attacks, explainers, recommendations, loaders, scoring | `redsim/ml/targets/`, `redsim/ml/attacks/`, `redsim/ml/explain/`, `redsim/ml/recommend/`, `redsim/ml/loaders.py`, `redsim/ml/eval.py` (or the product spec's named scoring module) | Package directories exist; modules are assigned, not written |
| LLM transport | `redsim/llm/pythia.py` (Pythia only; `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`, `REDSIM_ML_LLM_MODEL`); routing and budgets in `redsim/llm/` | Yes |
| API routes | `redsim/api/v1/` (`targets.py` extended for `/v1/models`, new `models`/`attacks` routes, reuse of `runs.py`, `findings.py`, `reports.py`, `verify.py`, `audit.py`) | Existing routes yes; ML routes no |
| Authorization | `redsim/api/policy.py`, `redsim/policy/` | Yes |
| Worker tasks | `redsim/workers/tasks/{attack,explain,harden}.py` (new), `verify.py`, `report.py`, `reaper.py`, `worm_export.py`; `redsim/workers/job_state.py`, `redsim/workers/bootstrap.py` | Existing tasks yes; ML tasks no |
| Persistence | `redsim/db/models.py`; migrations in `redsim/db/migrations/versions/` (next number after `0009_tenant_org_id_guard.py`) | Yes |
| Audit and storage | `redsim/audit/chain.py`, `redsim/storage/{blobs,s3,worm}.py` | Yes |
| Web app (`@redsim/web`) | `web/src/app/**` (`login`, `projects`, `targets`, `runs/[id]`, `findings/[id]`, `audit`, `cost`, `logs`; new `models` pages), `web/src/lib/api.ts`, `web/src/hooks/` | Existing pages yes; model/attack pages no |
| Design system | `packages/design-system/src/` | Yes |
| Tests | `tests/` (sqlite `conftest.py`, `integration` marker), `tests/ml/` (`fakes.py` `TinyTarget`; `ml` marker skips when the `ml` extra is absent) | Harness yes; ML tests to be written |
| Deployment | `deploy/` (docker-compose, Dockerfiles for api / worker / web / postgres / log_ingest, helm, keycloak, opa, cedar, otel, loki); Fargate manifests per the product spec | Compose and helm yes; Fargate no |

Paths marked "no" are proposed targets, not claims that files exist. Each plan must confirm exact paths before its implementation is marked ready.

## Parallel work and shared-file ownership

F001 and F008's event foundation exist in redsim; the foundation work for this product is M0 (scaffold; the `Target.kind` / `Job.type` vocabulary additions with API-side validation; ML event vocabulary). Do not defer ML event capture to the end.

After the product spec's contracts are accepted, frontend, backend, and evidence research can work in parallel on separate files. One integration owner coordinates the FastAPI routes, the typed client in `web/src/lib/api.ts`, and the Pydantic contracts in `redsim/ml/schema.py`; FastAPI's generated OpenAPI document is the reference for both sides. Do not hand-edit generated files where generation is used.

Fixtures used before live execution must be visibly labeled as fixtures. CIFAR-10 and `TinyTarget` are CI fixtures. The final demonstration must use genuine evidence from a real campaign on a bundled model, not fabricated integration results, and no number in the demo script is a measurement until the run that produced it exists.
