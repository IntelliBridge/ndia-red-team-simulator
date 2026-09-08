# AI Assurance — Feature Specifications

**Status:** Feature-level layer beneath the approved product spec, [Adversarial ML Red-Team Simulator — Product Spec](../docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md) (2026-09-08). No feature is implemented or approved for implementation by the existence of these files; the readiness checklist still gates each one.  
**Scope:** Non-operational robustness evaluation of ML classifiers on open, unclassified, publicly licensed data. The tool evaluates and hardens the robustness of a classifier; it never trains, optimizes, or deploys targeting or weapons models, and it connects to no mission system (see D001 in the [decision register](_shared/decisions.md) and the amendment proposals appended to the [constitution](../.specify/memory/constitution.md)).

## Relationship to the product spec

The product spec is the canonical statement of *what* the product is: the redsim stack it reuses, Phase A / Phase B scope, the attack catalog, explainability, the Model Robustness Index (MRI) and its binding constraints, the API surface, the web UI, deployment, and the project brief's reporting principles as design constraints. It supersedes John Sasser's hackathon spec (`docs/adversarial-ml-redteam-spec.md`) and the lean design (`docs/superpowers/specs/2026-09-08-redsim-design.md`).

These feature folders are the feature-level layer beneath it:

- The product spec decides scope and architecture. A feature `spec.md` decomposes one user outcome into stories, requirements, and acceptance scenarios that must agree with it; a feature `plan.md` names the redsim components the product spec assigns to that feature.
- Where a feature file and the product spec conflict, the product spec wins until the feature file is updated. Record the conflict in the [consistency review](_shared/analysis.md) rather than resolving it silently in code.
- Decisions D001–D005 were resolved by the product owner on 2026-09-08 and are recorded in the [decision register](_shared/decisions.md). D006 (retention and export policy) and D007 (named owners and reviewers) remain open.
- The constitution has not been ratified. Three amendment proposals (open vehicle imagery, bounded model upload, per-campaign score) are appended to it with status "proposed, pending named approval". The product spec proceeds on the product owner's decisions and states that gap; it does not claim ratification.
- The implementation locations in the [shared architecture](_shared/architecture.md) now point at the redsim platform this repository is a fork of (`redsim/`, `web/`, `packages/design-system`, `tests/`), not the Replit monorepo they were first written against.

## How this follows Spec Kit

We use the separation of **constitution → specification → clarification → plan → tasks → analysis → implementation**:

- [Constitution](../.specify/memory/constitution.md): the shared principles every feature must respect.
- `spec.md`: user needs, scope, stories, requirements, and measurable acceptance criteria.
- `plan.md`: proposed implementation approach, interfaces, dependencies, and verification.
- `tasks.md`: assignable, unchecked work items derived from the spec and plan.
- [Decision register](_shared/decisions.md): resolved and unresolved choices with approval records.
- [Shared architecture](_shared/architecture.md): roles, data concepts, and states mapped onto the redsim platform.
- [Readiness checklist](_shared/readiness-checklist.md): the review gate before implementation.
- [Consistency review](_shared/analysis.md): document checks, reconciled issues, and remaining blockers.

This is **Spec Kit–style documentation**, not an installation of its CLI or agent slash commands. No scripts, providers, runtimes, or applications were installed for it. The workflow can be followed manually now; actual command integration can be considered separately without overwriting these documents.

Method reference: [GitHub Spec Kit](https://github.com/github/spec-kit).

## Feature map

All accountable owners are **unassigned** (D007 is open). The role column suggests expertise, not a staffing commitment. Priority P1 means part of Phase A of the product spec; P2 capabilities inside a feature may follow its P1 story. The last column maps each feature onto the redsim components it reuses or extends and the product-spec milestones (John Sasser's M0–M7 and B1+, kept by the product spec) in which its behavior lands. Under `redsim/ml/` only `schema.py`, `targets/base.py`, and `attacks/base.py` hold code (contracts); the `redsim/ml/explain/` and `redsim/ml/recommend/` packages exist but are empty; every other path named below is an assigned location from the product spec, not an existing file.

| Feature | User outcome | Priority | Suggested lead | Implementation dependencies | redsim components and milestones |
| --- | --- | --- | --- | --- | --- |
| [F001 — Project access](001-project-access/spec.md) | Sign in and work within explicit project permissions | P1 | Full-stack / identity engineer | D002 (resolved); shared event envelope agreed | Keycloak OIDC + NextAuth (`redsim/api/auth.py`, `redsim/api/settings.py`, `web/src/app/login`, `web/src/app/api/auth`, `web/src/hooks/useRoles.ts`), role-rank RBAC (`redsim/api/policy.py`, `redsim/policy/`), Postgres RLS (`redsim/db/migrations/versions/0006_tenant_rls.py`), `project_memberships`. Pre-existing in redsim; confirmed working in M0. Dev-token mode (`REDSIM_AUTH_MODE=dev`) is allowed for the demo. |
| [F002 — Evaluation catalog](002-evaluation-catalog/spec.md) | Register, version, and select approved model and dataset references | P1 | Backend + evaluation researcher | F001; D001 and D003 (resolved) | `/v1/models` on top of `redsim/api/v1/targets.py`; `Target.kind` values `ml_model_artifact` and `ml_model_endpoint` (M0 vocabulary addition with API-side validation; no DDL); bundled sample models and datasets with build-time manifests in `redsim/ml/targets/` (image M1 on open, unclassified aerial / military-vehicle imagery; tabular M4 on lexical features of the Kaggle malicious-URLs dataset `sid321axn/malicious-urls-dataset`, CC0 per Kaggle — URL strings are data and are never fetched; full download needs a Kaggle API token, CI uses a committed stratified sample); ONNX / `state_dict` upload with worker-side sandboxed loading (`redsim/ml/loaders.py`, the `redsim/plugins.py` sandbox pattern), landing after tabular in the Phase A order; endpoint connector B1+. |
| [F003 — Evaluation profiles](003-evaluation-profiles/spec.md) | Define and independently approve a repeatable evaluation configuration | P1 | Evaluation researcher + backend | F001 + F002; D005 (resolved) | An attack-campaign configuration — attack set, ε grid, reference budget, sample dataset, scoring weights — validated by `redsim/ml/schema.py` (`RunConfig`) and stored with the `Run`; accepted through `POST /v1/models/{id}/attacks` (M1; weights and reference budget with the MRI scorecard step). Independent approval of profiles is Phase B; see the architecture baseline. |
| [F004 — Run management](004-run-management/spec.md) | Start, monitor, cancel, and rerun an approved benign evaluation | P1 | Platform / backend engineer | F001–F003; F008 event writer; D004 and D005 (resolved) | redsim `Run` / `Job` (`redsim/db/models.py`), the Job state machine (`redsim/workers/job_state.py`), cancel service (`redsim/services/runs.py`), stale-job reaper (`redsim/workers/tasks/reaper.py`), Celery tasks `attack.run`, `explain.run`, `harden.recommend` (`redsim/workers/tasks/{attack,explain,harden}.py`; types added in M0; behavior in M1, M2, M3) and `verify.replay` (`redsim/workers/tasks/verify.py`, M6). |
| [F005 — Evidence workbench](005-evidence-workbench/spec.md) | Inspect baseline/evaluated observations, metrics, and appropriate explanations | P1 | Frontend + evaluation researcher | F004 evidence contract; optional F006 summary | SHAP explainers in `redsim/ml/explain/` writing `Artifact` rows (image M2, tabular M4); `/runs/[id]` with the MRI scorecard, robustness curve, and per-family accuracy table with denominators; `/findings/[id]` three-pane screen with separate measurements / observations / interpretation / candidate-recommendation panels (`web/src/app/runs/[id]`, `web/src/app/findings/[id]`, `packages/design-system`; M5). |
| [F006 — Findings review](006-findings-review/spec.md) | Review evidence-linked findings and candidate recommendations | P1 story; reviewer states P2 | Full-stack + independent reviewer | F001 + F004 evidence; F005 navigation integration | `Finding` with `schema_blob` (`RedsimFinding` plus the ML fields), `severity` derived by the MRI severity rules, `validation_state` written by verify (`redsim/verify.py`, `redsim/workers/tasks/verify.py`); rule layer + Pythia writer in `redsim/ml/recommend/` (M3). Reviewer states (`draft` … `resolved`) are a Phase B addition, with one carve-out recorded in the architecture baseline: dismiss-with-reason (`status=false_positive`, `approver`-gated, reason in the audit detail) and an audited `reviewer_notes` PATCH are Phase A cheap items permitted only after the D8 demo-critical order. |
| [F007 — Reports and comparison](007-reports-comparison/spec.md) | Export traceable reports and compare compatible runs | P1 | Full-stack engineer | F004 + F006; F008 export policy; D006 (open) | Markdown / JSON / HTML reports (`redsim/report.py`, `redsim/api/v1/reports.py`, `redsim/workers/tasks/report.py`; M3); ΔMRI comparison of compatible runs after verify (M6). Export redaction and retention wait on D006. |
| [F008 — Audit and governance](008-audit-governance/spec.md) | See accountable history and apply approved data-handling policies | P1 foundation / P2 management UI | Security + backend engineer | Event contract starts with F001; UI needs F001; retention needs D006 and stored-entity lifecycle | Hash-chained audit log (`redsim/audit/chain.py`: Postgres-backed, JSONL offline), `redsim audit verify` (`redsim/api/v1/audit.py`, `web/src/app/audit`), WORM export (`redsim/storage/worm.py`, `redsim/workers/tasks/worm_export.py`; S3 Object Lock at M7). Pre-existing; every upload, attack, explain, harden, and verify appends an event from M1 on. |

F008 is intentionally split into an **early event foundation** and **later management tools**. This avoids a circular dependency and prevents logging from being postponed until the end. In this fork the event foundation already exists; the new work is emitting ML-specific events with the right `action` and `target` values.

## Delivery order

The slices remain the review structure. The milestones inside them come from the product spec (M0–M7 and B1+). The product owner's decided Phase A scope exceeds a 1–2 day build, so the product spec fixes a demo-critical order inside Phase A: image path end-to-end (bundled model, FGSM/PGD, ε sweep, SHAP, rules + LLM writer) → MRI scorecard → verify-after-harden → tabular → ONNX upload → Fargate. That order moves the tabular path (M4) after the verify loop (M6) relative to the milestone numbering; milestone contents are unchanged.

### Gate 0 — Agree on the product and boundaries

Status on 2026-09-08: D001–D005 resolved by the product owner (see the decision register); the product spec is the reviewed scope and interface statement. Still open: constitution ratification (amendment proposals pending named approval), D006 (retention and export), D007 (owners and reviewers).

Output: reviewed scope and interfaces, not a running evaluation engine. That remains the state of the repository: the redsim platform is restored and being made import-clean, and the ML vertical under `redsim/ml/` is contracts only (`schema.py`, `targets/base.py`, `attacks/base.py`, plus `redsim/llm/pythia.py` and `tests/ml/fakes.py`).

### Slice 1 — Team access and approved catalog

F001 + F002 + the minimal F008 event foundation. Milestones: M0 (scaffold; the new `Target.kind` / `Job.type` values are vocabulary additions with API-side validation, since both are free string columns — an Alembic revision only if a column is added) and the bundled-model halves of M1 and M4.

Authentication, RBAC, RLS, and the audit chain already exist in redsim; the slice's new work is the ML target kinds, the bundled sample models with their build-time asset manifests, and the upload rules. Demo: authorized teammates can register and select approved versioned references; unauthorized users cannot read or mutate project records. Uploads are accepted only within the D003 bounds — ONNX preferred, PyTorch `state_dict` with an explicit architecture, full pickles refused by default, loaded only on the worker inside the plugin sandbox — and a metadata record never implies an artifact was accepted.

### Slice 2 — One genuine evaluation and its evidence

F003 + F004 + F005. Milestones: M1 (load + attack, image), M2 (SHAP, image), M5 (UI), the MRI scorecard, then M4 (tabular). Build order per D8: M6 (Slice 3, verify-after-harden) lands before M4; the slice grouping is for review, not sequence.

Demo: create a campaign configuration, run it, inspect real evidence — per-family accuracy with denominators, the benign random-noise control at the same ε, the ε curve, SHAP clean vs adversarial — and distinguish an interrupted run from a completed evaluation. Do not substitute fixture data for a working execution path: CIFAR-10, the committed stratified malicious-URL sample, and the `TinyTarget` fake are CI fixtures, not demo results.

### Slice 3 — Human review and accountable reporting

F006 + F007 + the remaining F008 governance tools. Milestones: M3 (recommendations: rule layer + Pythia writer), M6 (verify loop with ΔMRI), M7 (Fargate; S3 Object Lock for WORM export).

Demo: open a finding, read candidate recommendations labelled candidate / not evaluated, run verify-after-harden, see the measured ΔMRI on this model at these settings, export a report, inspect the audit chain. Compare a compatible rerun without claiming an unreviewed improvement; the measured delta is the only sanctioned form of "gain".

## Safe parallel work

- Product/evaluation clarification and security/runtime feasibility can proceed in parallel.
- After shared contracts are approved, frontend and backend contributors can work on separate feature files.
- F005 and F006 can develop against the same approved F004 evidence contract (`redsim/ml/schema.py`); the workbench must not wait for a recommendations implementation to show evidence.
- F008's event foundation already exists; its ML event vocabulary can be agreed alongside F001 review, and its full management UI does not gate catalog development.
- One integration owner coordinates the FastAPI routes under `redsim/api/v1/`, the typed web client in `web/src/lib/api.ts`, and the Pydantic contracts in `redsim/ml/schema.py`.
- `[P]` in a feature task means parallel **after its named prerequisites**, not permission to ignore dependencies.

## First team meeting

1. Assign an accountable owner and an independent reviewer to each feature (D007).
2. Review the constitution amendment proposals and decide on ratification; resolve D006 (retention, export redaction, dataset licence handling).
3. Review the first stories of F001, F002, and F008's event foundation against the redsim components they now map to.
4. Use the readiness checklist; mark specs and plans approved only when their gates are satisfied.
5. Pick a single story-sized increment — the image path end-to-end on a bundled model — before anything else in Phase A.

## Team working agreement

- Feature folders are the source of truth for feature behavior and task status; the product spec is the source of truth for product scope.
- Tasks are scoped to a feature: identify them as `F001/T001`, not just `T001`, when discussing across the team.
- Proposed feature branches can use the folder name, such as `001-project-access`; no branches were created automatically.
- Store acceptance evidence next to the feature when implemented; do not check tasks off because the specification is written.
- These Markdown tasks are not assigned tracker tickets or GitHub issues. A tracker can link to them later without duplicating the specification.

## Deferred extensions

Changed since the first draft: white-box model upload is now Phase A, bounded by D003 (ONNX preferred; PyTorch `state_dict` with an explicit architecture; full pickles refused by default; loaded only on the worker inside redsim's plugin sandbox — separate process, no network, rlimits — never in the API process). ART and SHAP are selected dependencies of the `ml` extra. Pythia is the only LLM transport; the LLM writer receives metrics and a SHAP text summary, never images or model data.

Still deferred to Phase B or later: the black-box endpoint connector (`ml_model_endpoint`, query-only), text/NLP and object-detection modalities, Carlini-Wagner / DeepFool / query-based black-box attacks, KernelSHAP for black-box models, adversarial training as an applied defense, garak and the LLM-assistant domain (if added, garak's OpenAI-compatible generator points at Pythia), finding reviewer states, data-poisoning pipelines, tool-using agents, automatic remediation, and stronger deployment claims. The TIP research informs possible LLM coverage only. OpenSandbox is not used; the redsim plugin sandbox is the isolation boundary (D004).

See the [project brief](../docs/project-brief.md) for the original context, reference limitations, and the decisions taken on 2026-09-08.
