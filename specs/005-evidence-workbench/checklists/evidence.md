# F005 Evidence Workbench: evidence record

Created 2026-09-09. This file maps every success criterion in
`specs/005-evidence-workbench/spec.md` to the automated tests that prove it, or
says "no automated evidence" where that is true. It follows the spec's
reconciliation section (2026-09-08), which keeps SC-001 to SC-003 unchanged in
meaning, and does not change it. "Done" is recorded here, separately from
approval, and is not claimed until the named reviewers record it.

Test tiers: `unit` is the default pytest tier, `ml` needs the `ml` extra,
`e2e` needs `REDSIM_E2E=1` (`tests/e2e/README.md`), `web` is vitest under
`web/`.

## Success criteria

| SC | Disposition (spec) | Clause | Evidence | Tier |
| --- | --- | --- | --- | --- |
| SC-001 | unchanged | Every metric row carries a reconcilable denominator and coverage | `tests/ml/test_campaign.py::test_measurement_rows_ids_denominators_and_control`, `tests/ml/test_scoring.py::test_input_rows_carry_denominators`, `tests/ml/test_fixture.py::test_fixture_asr_denominators_are_the_clean_row`, `tests/ml/test_report.py::test_six_sections_in_order` | ml |
| SC-001 | unchanged | An absent or partial value renders as unavailable, never as zero or an invented number | `tests/ml/test_scoring.py::test_delta_absent_cell_renders_unavailable_not_zero`, `::test_missing_expl_shift_yields_a_partial_record_without_mri_and_no_renormalisation`, `tests/ml/test_report.py::test_partial_and_unscored_records_refuse_to_invent_numbers`, `tests/ml/test_campaign.py::test_all_attacks_not_run_leaves_the_score_unavailable` | ml |
| SC-001 | unchanged | The panels render denominators and unavailable states | `packages/design-system/src/components/evidence-components.test.tsx`, `web/src/app/runs/[id]/page.test.tsx` | web |
| SC-001 | unchanged | The acceptance review itself | No automated evidence. An acceptance review has not been held. | |
| SC-002 | unchanged | An unsupported explanation is a labelled unsupported state with no fabricated attribution | `tests/ml/test_campaign.py::test_explainer_raising_explain_unavailable_is_recorded_not_faked`, `::test_missing_explain_module_records_interpretation_and_partial_score`, `::test_explainer_without_shift_leaves_the_score_partial`, `tests/ml/test_explain.py::test_image_explain_raises_when_shap_cannot_run_or_k_zero`, `tests/ml/test_explain_blackbox.py::test_kernel_explainer_request_on_image_is_refused_with_reason`, `::test_image_and_unknown_explainer_names_are_refused_on_tabular`, `tests/ml/test_recommend.py::test_interpretation_states_absent_score_when_expl_missing` | ml |
| SC-002 | unchanged | The acceptance review itself | No automated evidence. An acceptance review has not been held. | |
| SC-003 | unchanged | A baseline-versus-evaluated comparison is available from the workbench without raw storage references | `tests/ml/test_compare.py::test_incompatible_verify_delta_and_side_by_side`, `tests/ml/test_reports_phase_b.py::test_n_run_table_rows_in_request_order_with_delta_only_on_the_verify_row`, `tests/ml/test_tasks.py::test_verify_worker_measures_delta_and_moves_state`, `tests/e2e/test_ml_upload_reports.py::test_verify_measures_delta_mri`, `tests/ml/test_artifacts_api.py::test_stream_headers_and_404s` (artifacts are served by id, never by blob key) | ml, e2e |
| SC-003 | unchanged | Fixtures are labelled and never shown as results | `tests/ml/test_fixture.py::test_fixture_is_labelled_as_a_test_double`, `tests/ml/test_models_routes.py::test_list_hides_deleted_and_fixture_only`, `tests/e2e/test_ml_upload_reports.py::test_bundled_tiny_cnn_yields_no_finding_and_says_so` | ml, e2e |
| SC-003 | unchanged | Reviewers complete the comparison for at least 90 percent of representative fixtures | No automated evidence. This is a usability measure from a review session that has not been held. | |

## Done gate

- Passing checks: not recorded. Re-run the tiers above before quoting them.
- Acceptance evidence reviewed by: (blank)
- Accessibility and error-state checks: `web/src/app/runs/[id]/page.a11y.test.tsx`, `web/src/app/findings/[id]/page.a11y.test.tsx` (vitest, not run in a browser).
- Behaviour-to-spec comparison reviewed by: (blank)
- Done: not recorded.
