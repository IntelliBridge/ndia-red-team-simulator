# F006 Findings Review: evidence record

Created 2026-09-09. This file maps every success criterion in
`specs/006-findings-review/spec.md` to the automated tests that prove it, or
says "no automated evidence" where that is true. It follows the spec's
reconciliation section (2026-09-08), which placed SC-001 and SC-003 in Phase B
and kept SC-002 in Phase A for machine-derived findings, and does not change
it. Phase B wave B2 built the review workflow, so the Phase B criteria now have
evidence. "Done" is recorded here, separately from approval, and is not claimed
until the named reviewers record it.

Test tiers: `unit` is the default pytest tier, `ml` needs the `ml` extra,
`e2e` needs `REDSIM_E2E=1` (`tests/e2e/README.md`), `web` is vitest under
`web/`.

## Success criteria

| SC | Disposition (spec) | Clause | Evidence | Tier |
| --- | --- | --- | --- | --- |
| SC-001 | Phase B acceptance check (built by wave B2) | Self-confirmation fails without changing finding state, Owner-authors included | `tests/ml/test_review_workflow.py::test_independence_is_identity_not_rank`, `::test_confirm_dismiss_reopen_matrix`, `::test_dismiss_from_failed_and_confirm_from_fixed`, `tests/ml/test_findings_routes.py::test_finding_fields_and_dismissal_matrix` | ml |
| SC-001 | Phase B acceptance check | The focused check on a live stack | No e2e evidence. The e2e tier has no case for the review workflow (Phase B wave B4, README "Open items"). | |
| SC-002 | applies in Phase A | A finding cites exact `Measurement`, `Observation` and `Artifact` ids | `tests/ml/test_campaign.py::test_finding_facts_are_derived_never_stamped_on_rows`, `::test_finding_derivation_on_a_larger_slice`, `tests/ml/test_tasks.py::test_campaign_completes_and_projects_findings`, `::test_followon_writeback_merges_child_results_into_the_parent_finding`, `::test_explain_followon_writes_observations_back`, `tests/ml/test_scoring.py::test_finding_inputs_derive_severity_confidence_and_the_finding_detail_shape` | ml |
| SC-002 | applies in Phase A | Observation, interpretation and recommendation are separate fields and separate panels | `tests/ml/test_fixture.py::test_fixture_has_every_panel`, `tests/ml/test_schema_compat.py::test_p0_fixture_reaches_every_panel`, `tests/ml/test_recommend.py::test_interpretation_rules_fire_and_cite_ids`, `::test_recommendation_rules_fire_and_cite_ids`, `web/src/app/findings/[id]/page.test.tsx` | ml, web |
| SC-002 | applies in Phase A | Revisions of an analyst draft are kept | `tests/ml/test_review_workflow.py::test_analyst_draft_lifecycle` | ml |
| SC-002 | Phase B | An explicit later redaction marker | No automated evidence. Redaction waits on D006 (OPEN). | |
| SC-003 | Phase B acceptance check (built by wave B2) | No finding reaches `resolved` without a compatible linked retest and a recorded independent review | `tests/ml/test_review_workflow.py::test_resolve_gates_and_retest_links`, `::test_resolve_needs_a_verified_retest`, `tests/ml/test_tasks.py::test_verify_worker_measures_delta_and_moves_state` (the retest link with `settings_hash` and `baseline_run_id`) | ml |
| SC-003 | Phase B acceptance check | The acceptance review itself | No automated evidence. An acceptance review has not been held. | |

## Done gate

- Passing checks: not recorded. Re-run the tiers above before quoting them.
- Acceptance evidence reviewed by: (blank)
- Accessibility and error-state checks: `web/src/app/findings/page.a11y.test.tsx`, `web/src/app/findings/[id]/page.a11y.test.tsx` (vitest, not run in a browser).
- Behaviour-to-spec comparison reviewed by: (blank)
- Done: not recorded.
