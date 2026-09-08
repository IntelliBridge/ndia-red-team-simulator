# Tasks: <feature>

**Status:** Draft — unchecked, unassigned  
**Inputs:** Reviewed `spec.md`, `plan.md`, and applicable contracts

Task IDs are local to the feature. Refer to a task across the team as `Fxxx/T001`. `[P]` means parallel only after prerequisites and on separate files. Replace sample placeholders before a feature is considered ready.

## Foundation

- [ ] T001 Resolve the named blockers and review the feature contract in `specs/<feature>/contracts/` — lead: <role>.

## US1 — <outcome>

- [ ] T002 [US1] Implement <specific requirement> in <proposed exact target path> — lead: <role>; depends on T001.
- [ ] T003 [US1] Verify <specific acceptance/failure behavior> in <proposed check path> — lead: <role>; depends on T002.

## Cross-cutting Review

- [ ] T004 Record acceptance evidence and limitations in `specs/<feature>/acceptance.md` — lead: independent reviewer.

## Requirement Coverage

| Requirement | Implementation tasks | Verification tasks |
| --- | --- | --- |
| FR-001 | T002 | T003 |

Map every requirement; do not mark a task complete just because the spec or its test outline exists.