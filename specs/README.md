# AI Assurance — Feature Specifications

**Status:** Draft feature breakdown for team review; no feature is implemented or approved by the existence of these files.  
**Scope:** General-purpose, non-operational assurance using public or synthetic, non-sensitive data.

## How this follows Spec Kit

We use the separation of **constitution → specification → clarification → plan → tasks → analysis → implementation**:

- [Constitution](../.specify/memory/constitution.md): the shared principles every feature must respect.
- `spec.md`: user needs, scope, stories, requirements, and measurable acceptance criteria.
- `plan.md`: proposed implementation approach, interfaces, dependencies, and verification.
- `tasks.md`: assignable, unchecked work items derived from the spec and plan.
- [Decision register](_shared/decisions.md): unresolved choices and approval records.
- [Shared architecture](_shared/architecture.md): proposed roles, data concepts, states, and integration boundaries.
- [Readiness checklist](_shared/readiness-checklist.md): the review gate before implementation.
- [Consistency review](_shared/analysis.md): document checks, reconciled issues, and remaining blockers.

This is **Spec Kit–style documentation**, not an installation of its CLI or agent slash commands. No scripts, providers, runtimes, or applications were installed. The workflow can be followed manually now; actual command integration can be considered separately without overwriting these documents.

Method reference: [GitHub Spec Kit](https://github.com/github/spec-kit).

## Feature map

All accountable owners are **unassigned**. The role column suggests expertise, not a staffing commitment. Priority P1 means part of the proposed coherent first release; P2 capabilities inside a feature may follow its P1 story.

| Feature | User outcome | Priority | Suggested lead | Implementation dependencies |
| --- | --- | --- | --- | --- |
| [F001 — Project access](001-project-access/spec.md) | Sign in and work within explicit project permissions | P1 | Full-stack / identity engineer | D002; shared event envelope agreed |
| [F002 — Evaluation catalog](002-evaluation-catalog/spec.md) | Register, version, and select approved model and dataset references | P1 | Backend + evaluation researcher | F001; D001/D003 for domain-specific validation |
| [F003 — Evaluation profiles](003-evaluation-profiles/spec.md) | Define and independently approve a repeatable evaluation configuration | P1 | Evaluation researcher + backend | F001 + F002; D005 |
| [F004 — Run management](004-run-management/spec.md) | Start, monitor, cancel, and rerun an approved benign evaluation | P1 | Platform / backend engineer | F001–F003; F008 event writer; D004/D005 |
| [F005 — Evidence workbench](005-evidence-workbench/spec.md) | Inspect baseline/evaluated observations, metrics, and appropriate explanations | P1 | Frontend + evaluation researcher | F004 evidence contract; optional F006 summary |
| [F006 — Findings review](006-findings-review/spec.md) | Review evidence-linked findings and candidate recommendations | P1 | Full-stack + independent reviewer | F001 + F004 evidence; F005 navigation integration |
| [F007 — Reports and comparison](007-reports-comparison/spec.md) | Export traceable reports and compare compatible runs | P1 | Full-stack engineer | F004 + F006; F008 export policy; D006 |
| [F008 — Audit and governance](008-audit-governance/spec.md) | See accountable history and apply approved data-handling policies | P1 foundation / P2 management UI | Security + backend engineer | Event contract starts with F001; UI needs F001; retention needs D006 and stored-entity lifecycle |

F008 is intentionally split into an **early event foundation** and **later management tools**. This avoids a circular dependency and prevents logging from being postponed until the end.

## Delivery order

### Gate 0 — Agree on the product and boundaries

Ratify the constitution; select one benign evaluation domain and approved inputs; choose the managed identity approach; define evidence, execution, and data-handling requirements. Record owners and decisions.

Output: reviewed scope and interfaces, not a running evaluation engine.

### Slice 1 — Team access and approved catalog

F001 + F002 + the minimal F008 event foundation.

Demo: authorized teammates can register and select approved versioned references; unauthorized users cannot read or mutate project records. Do not accept arbitrary uploads just because a metadata record can be created.

### Slice 2 — One genuine evaluation and its evidence

F003 + F004 + F005, for exactly one approved benign domain and adapter.

Demo: create and approve a profile, run it, inspect real evidence, and distinguish an interrupted run from a completed evaluation. Do not substitute fixture data for a working execution path.

### Slice 3 — Human review and accountable reporting

F006 + F007 + the remaining F008 governance tools.

Demo: submit a finding, independently review it, export a policy-compliant report, and inspect the history. Compare a compatible rerun without claiming an unreviewed improvement.

## Safe parallel work

- Product/evaluation clarification and security/runtime feasibility can proceed in parallel.
- After shared contracts are approved, frontend and backend contributors can work on separate feature files.
- F005 and F006 can develop against the same approved F004 evidence contract; the workbench must not wait for a recommendations implementation to show evidence.
- F008's event foundation can proceed alongside F001; its full management UI does not gate catalog development.
- One integration owner coordinates the shared OpenAPI file, generated clients, and schema exports.
- `[P]` in a feature task means parallel **after its named prerequisites**, not permission to ignore dependencies.

## First team meeting

1. Assign an accountable owner and an independent reviewer to each feature.
2. Resolve D001 (first domain) and D002 (managed identity), then assign the other decision owners.
3. Review the first stories of F001, F002, and F008's event foundation.
4. Use the readiness checklist; mark specs and plans approved only when their gates are satisfied.
5. Pick a single story-sized increment, not an entire multi-domain platform, for the first implementation.

## Team working agreement

- Feature folders are the source of truth for behavior and task status.
- Tasks are scoped to a feature: identify them as `F001/T001`, not just `T001`, when discussing across the team.
- Proposed feature branches can use the folder name, such as `001-project-access`; no branches were created automatically.
- Store acceptance evidence next to the feature when implemented; do not check tasks off because the specification is written.
- These Markdown tasks are not assigned Replit tasks or GitHub issues. A tracker can link to them later without duplicating the specification.

## Deferred extensions

Adding another modality, arbitrary model uploads, arbitrary provider endpoints, data-poisoning pipelines, tool-using agents, automatic remediation, and stronger deployment claims are not part of this first release. ART, SHAP, garak, the TIP research, and OpenSandbox inform scope; they are not selected or installed dependencies.

See the [project brief](../docs/project-brief.md) for the original context and reference limitations.