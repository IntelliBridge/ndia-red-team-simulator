# Team Backlog

The initial kickoff workstreams have been expanded into [eight feature packages](../specs/README.md). That feature map and each feature's `tasks.md` are now the source of truth for work breakdown and task status.

Product scope is fixed by the [Adversarial ML Red-Team Simulator — Product Spec](superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md) (2026-09-08); the feature packages are the feature-level layer beneath it, and its Phase A demo-critical order sets what to implement first.

All owners are currently **unassigned**. The specs, plans, and tasks are **drafts for team review**, not assigned platform tasks, completed work, or approval to implement every candidate technology.

| Start here | Suggested role | Dependency | Outcome |
| --- | --- | --- | --- |
| Ratify the [constitution](../.specify/memory/constitution.md) | Project owner + engineering/security leads | None | Shared principles approved |
| Resolve the [decision register](../specs/_shared/decisions.md) | Named decision owners | Relevant research | No hidden domain, provider, runtime, or data-handling assumptions |
| Assign [feature owners and reviewers](../specs/README.md) | Project owner | Team availability | Accountable ownership without inventing names |
| Review each spec, plan, and task list | Feature owner + independent reviewer | Relevant decisions | Completed [readiness checklist](../specs/_shared/readiness-checklist.md) |
| Implement the first approved story | Assigned contributors | Approved spec/plan/contracts | Genuine user-visible behavior with acceptance evidence |

## Feature task lists

- [F001 — Project access](../specs/001-project-access/tasks.md)
- [F002 — Evaluation catalog](../specs/002-evaluation-catalog/tasks.md)
- [F003 — Evaluation profiles](../specs/003-evaluation-profiles/tasks.md)
- [F004 — Run management](../specs/004-run-management/tasks.md)
- [F005 — Evidence workbench](../specs/005-evidence-workbench/tasks.md)
- [F006 — Findings review](../specs/006-findings-review/tasks.md)
- [F007 — Reports and comparison](../specs/007-reports-comparison/tasks.md)
- [F008 — Audit and governance](../specs/008-audit-governance/tasks.md)

## Tracking conventions

Use `F001/T001`-style references in team discussions because task IDs repeat across features. Update task status in its feature folder; do not maintain a competing checkbox list here.

Follow the [spec-driven workflow](spec-driven-workflow.md) for reviews, shared-file ownership, safe parallel work, and requirement changes.

No GitHub issues, Replit task assignments, collaborator invitations, or implementation branches have been created automatically.