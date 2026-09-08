# Specification Consistency Review

**Disposition:** Ready for team clarification and review — **not approved for implementation**.

## Document checks

- Each of the eight features has a specification, proposed plan, and draft task list.
- Functional requirements and success criteria have feature-scoped identifiers.
- Every functional requirement appears in its feature's task-coverage table.
- Referenced task IDs exist within their feature; implementation checkboxes remain unchecked.
- Local document links resolve.
- The packages consistently distinguish draft proposals from existing application behavior.

These checks establish document structure and traceability, not correctness of future software or proof that every task will satisfy its requirement.

## Cross-feature issues reconciled

1. **Catalog approval authority:** The proposed access matrix now explicitly assigns independent approval to a Reviewer or Owner. F002 uses the same rule. D003 approval remains open.
2. **Team onboarding:** F001 includes proposed managed invitations as well as membership editing and removal. No invitations were actually sent. Identity verification, invitation behavior, and initial bootstrap remain gated by D002.
3. **Onboarding authorization:** Verified invitation acceptance and initial owner bootstrap are narrowly scoped exceptions to the active-membership prerequisite; they do not grant pre-acceptance project access.
4. **Audit dependency:** F008's event contract/writer is early foundation work; its full management UI is not a prerequisite for every other feature.
5. **Evidence/review dependency:** F005 can display evidence without F006 recommendations. Recommendations are a later integration, avoiding a cycle.
6. **Runtime assumptions:** F004 does not assume that OpenSandbox or another execution environment is installed, available, or approved.

## Open blockers

The decision register remains authoritative. In particular, the first benign domain, managed identity/invitation policy, input access and catalog policy, runtime boundary, evaluation criteria, retention/export policy, and named reviewers require team decisions.

The technical plans are proposals. Feature-level research, final data models, and interface contracts are future tasks, not missing files that can be silently replaced by implementation assumptions.

## What has not been validated

- No application workflow, access control, execution isolation, evaluator, export, or data migration has been implemented or tested.
- No dependency security assessment or operational assurance claim is made.
- No human approval or constitution ratification has been recorded.
- No Spec Kit CLI, slash-command integration, GitHub issue sync, or Replit task assignment was installed or performed.

Use the readiness checklist before approving any feature and record actual acceptance evidence only after implementation.
## 2026-09-08 consolidation

**Disposition after this entry:** the product scope is approved by the product owner; the feature packages remain **drafts, not approved for implementation** until each passes the readiness checklist against the product spec.

What changed:

- A single product spec now exists at `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`. It supersedes the hackathon spec (`docs/adversarial-ml-redteam-spec.md`) and the lean design (`docs/superpowers/specs/2026-09-08-redsim-design.md`). The eight feature packages are the feature-level layer beneath it; where they conflict, the product spec wins until the feature file is updated, and the conflict is recorded here.
- `specs/README.md` gained a "Relationship to the product spec" section, an aegis-components-and-milestones column in the feature map, delivery slices reconciled with milestones M0–M7 (with the Phase A demo-critical order: image path end-to-end → MRI scorecard → verify-after-harden → tabular → ONNX upload → Fargate), and an updated "Deferred extensions" section (bounded upload is now Phase A; endpoints, text/detection, garak/LLM domain, reviewer states remain deferred).
- `specs/_shared/architecture.md` replaced the Replit monorepo implementation locations with aegis paths, mapped the access matrix onto aegis roles (`scanner` < `remediator` < `approver` < `admin`, read by any membership plus RLS), mapped the planning entities onto aegis tables, and mapped the proposed run and finding states onto the aegis Job state machine and `Finding.status` / `validation_state`. Two divergences from the first-draft matrix are stated: model registration/upload is `admin`-gated, and report export is open to any member pending D006. Finding reviewer states are decided to be Phase B.
- `specs/_shared/decisions.md`: D001–D005 are RESOLVED with the register's resolution format, approver "product owner (hackathon), 2026-09-08". D001 (open aerial / military-vehicle imagery plus a tabular classifier) and D003 (bundled models plus bounded ONNX / `state_dict` upload with sandboxed worker-side loading) diverge from their proposals and say so. D006 (retention, export redaction, licence restrictions) and D007 (named owners and reviewers) remain OPEN; no owners or names were assigned.
- `.specify/memory/constitution.md`: principles unchanged; an "Amendment proposals (2026-09-08)" section is appended with status "proposed, pending named approval" covering Principle II vs vehicle imagery, Principle II vs bounded upload, and Principle III vs the per-campaign Model Robustness Index. Ratification is not claimed.
- `docs/brief.md` was folded into `docs/project-brief.md` (original use-case text, additional references including Pythia and the aegis fork, a "Decisions taken (2026-09-08)" section) and deleted. References in `docs/`, `specs/`, and `.specify/` were updated.

Cross-feature issues to carry into the next feature-file review:

1. **Role vocabulary.** Feature files still use Owner / Analyst / Reviewer / Viewer. The architecture baseline maps them to aegis roles; each `spec.md` must adopt the mapping or state why it needs a new role. aegis has no read-only role today.
2. **Run and finding states.** Feature files still use `cancel_requested`, `completed`, `timed_out` and the six reviewer states. The architecture baseline maps them onto aegis's Job machine and `validation_state`; F004 and F006 acceptance scenarios need rewriting against the mapping, and the reviewer-state stories move to Phase B.
3. **Implementation paths.** Feature `plan.md` and `tasks.md` files still cite Replit monorepo paths. They must be replaced with the aegis locations in the architecture baseline before any plan is marked ready.
4. **Scope statements.** Feature files that say "one benign domain" or name a document classifier / FAQ assistant must be updated to D001 (image and tabular classification, open imagery with bounds).
5. **Score presentation.** F005 and F007 must add the MRI display rules from D005 (never without subscores, denominators, and ε curve; attack-scoped grade readings; ΔMRI as the only "gain").

Open blockers: constitution ratification and approval of the three amendment proposals; D006; D007.

What has still not been validated: no ML attack, explanation, scoring, hardening, or upload path is implemented — `aegis/ml/` holds contracts only (`schema.py`, `targets/base.py`, `attacks/base.py`) alongside `aegis/llm/pythia.py` and `tests/ml/fakes.py`; the restored aegis platform is being made import-clean concurrently. No acceptance evidence exists for any feature.
