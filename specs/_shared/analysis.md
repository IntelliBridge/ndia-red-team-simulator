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