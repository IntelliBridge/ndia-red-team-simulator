# F001 Project Access: evidence record

Created 2026-09-09. This file maps every success criterion in
`specs/001-project-access/spec.md` to the automated tests that prove it, or
says "no automated evidence" where that is true. It follows the per-SC
disposition table in the spec's reconciliation section (2026-09-08) and does
not change it. "Done" is recorded here, separately from approval, and is not
claimed until the named reviewers record it.

Test tiers: `unit` is the default pytest tier, `integration` needs sqlite or
Postgres (`-m integration`, the Postgres cases skip without `REDSIM_DB_URL`),
`ml` needs the `ml` extra, `e2e` needs `REDSIM_E2E=1` (`tests/e2e/README.md`),
`web` is vitest under `web/`.

## Success criteria

| SC | Disposition (spec) | Clause | Evidence | Tier |
| --- | --- | --- | --- | --- |
| SC-001 | amended | Protected requests from an absent membership are rejected across every role | `tests/test_project_access_read.py::test_report_403_when_no_membership`, `::test_ws_closes_1008_for_unauthorised_project`, `tests/test_projects_api.py::test_list_returns_only_projects_with_membership`, `::test_membership_403_when_caller_not_in_project`, `tests/test_api_auth.py::test_missing_bearer_returns_401`, `::test_dev_token_rejected_in_prod`, `tests/test_policy_ml_actions.py::test_viewer_ranks_zero_reads_but_never_acts`, `::test_phase_b_actions_gate_exactly_at_their_minimum_role`, `tests/test_list_endpoint_scoping.py` | unit |
| SC-001 | amended | Tenant rows of another organisation are hidden and cross-tenant writes are refused | `tests/test_tenant_rls.py::test_tenant_scope_hides_other_orgs_rows`, `::test_cross_tenant_write_rejected_by_with_check`, `::test_ml_campaigns_has_rls_parity_and_hides_other_orgs_rows` | integration (Postgres) |
| SC-001 | amended | The RBAC negative matrix per mutating ML route and the RLS negatives on a live stack | `tests/e2e/test_ml_governance.py::test_rbac_negatives`, `::test_rls_hides_other_orgs_scores`, `tests/e2e/test_harness_smoke.py::test_role_gate_refuses_before_any_row_or_audit_event` | e2e |
| SC-001 | amended | Suspended or removed memberships | No automated evidence. Phase A has no suspended or removed state (FR-006, Phase B). | |
| SC-002 | deferred to Phase B | No transition leaves a project without an active Owner | No automated evidence. No last-owner guard and no in-app membership transition exist (FR-007). | |
| SC-003 | deferred to Phase B | Invitation clauses | No automated evidence. No invitation entity exists (FR-013 to FR-016). | |
| SC-003 | superseded | Users distinguish Replit collaboration from application invitations | Not applicable. The repository is a GitHub fork (FR-004). The surviving rule, that repository access implies no membership, has no automated test. | |

## Web evidence (supporting, not a success criterion)

`web/src/hooks/useRoles.test.ts`, `web/src/hooks/useRequireAuth.test.ts`,
`web/src/app/projects/page.test.tsx`,
`web/src/app/projects/[slug]/settings/page.test.tsx` (vitest). Not run in a
browser against a running stack (README "Open items").

## Done gate

- Passing checks: not recorded. Re-run the tiers above before quoting them.
- Acceptance evidence reviewed by: (blank)
- Behaviour-to-spec comparison reviewed by: (blank)
- Done: not recorded.
