# F007 Reports and Comparison: evidence record

Created 2026-09-09. This file maps every success criterion in
`specs/007-reports-comparison/spec.md` to the automated tests that prove it, or
says "no automated evidence" where that is true. It follows the spec's
reconciliation section (2026-09-08) and does not change it. "Done" is recorded
here, separately from approval, and is not claimed until the named reviewers
record it.

Test tiers: `unit` is the default pytest tier, `ml` needs the `ml` extra,
`e2e` needs `REDSIM_E2E=1` (`tests/e2e/README.md`).

## Success criteria

| SC | Disposition (spec) | Clause | Evidence | Tier |
| --- | --- | --- | --- | --- |
| SC-001 | amended (FR-002) | Every report resolves to exact immutable source versions (`Run.id`, `settings_hash`, `model_sha256`, dataset revision, artifact digests) | `tests/ml/test_report.py::test_json_round_trips_record`, `::test_generated_at_defaults_to_now_and_is_stamped_in_markdown`, `tests/ml/test_findings_routes.py::test_report_route_serves_newest_artifact_and_pdf_is_404_until_rendered`, `::test_ml_report_render_rerenders_from_run_record`, `tests/ml/test_reports_phase_b.py::test_snapshots_are_immutable_rows_over_the_artifacts_and_pdf_is_served`, `::test_schema_version_and_llm_hook_render_for_a_real_record_and_a_probe_record`, `::test_pdf_is_deterministic_and_carries_the_six_sections_with_glyphs` | ml |
| SC-001 | amended | Every report displays its limitations and the partial-run label | `tests/ml/test_report.py::test_six_sections_in_order`, `::test_partial_and_unscored_records_refuse_to_invent_numbers`, `tests/ml/test_reports_phase_b.py::test_pdf_partial_record_says_mri_not_computed_and_verify_record_has_delta_block`, `tests/ml/test_campaign.py::test_limitations_carry_the_d3_bounds_statement_after_the_standing_text`, `tests/e2e/test_ml_upload_reports.py::test_reports_sections_and_pdf_404` | ml, e2e |
| SC-002 | amended (FR-006 deferred) | A denied actor receives no bytes: the membership gate is enforced server-side | `tests/test_project_access_read.py::test_report_403_when_no_membership`, `::test_report_404_when_no_artifact`, `tests/test_report_xss.py::test_html_response_carries_csp_and_nosniff`, `::test_json_response_carries_nosniff_and_attachment`, `tests/ml/test_reports_phase_b.py::test_snapshot_archive_is_an_audited_admin_soft_flag`, `tests/e2e/test_ml_governance.py::test_rbac_negatives` | unit, ml, e2e |
| SC-002 | deferred to Phase B | Redaction-required export cases and protected-field omission | No automated evidence. No export-redaction policy exists (D006 OPEN). The report states that no policy was applied (`tests/ml/test_report.py::test_six_sections_in_order` covers the limitations section). | |
| SC-003 | amended (D9) | Every accepted comparison lists the changed variables and keeps denominators and coverage | `tests/ml/test_compare.py::test_incompatible_verify_delta_and_side_by_side`, `tests/ml/test_reports_phase_b.py::test_n_run_table_rows_in_request_order_with_delta_only_on_the_verify_row`, `::test_n_run_table_refusals`, `::test_differing_weight_vectors_are_incomparable_and_the_campaign_carries_the_badge`, `tests/ml/test_scoring.py::test_delta_refuses_incompatible_campaigns`, `::test_delta_refuses_mixing_two_modalities`, `::test_delta_builds_an_mri_delta_from_two_complete_records`, `tests/ml/test_batches.py` (batch compare returns comparability groups only) | ml |
| SC-003 | amended (D9) | Zero outputs contain a universal score, mean or rank | `tests/ml/test_reports_phase_b.py::test_comparison_table_is_pure_and_refuses_aggregate_keys`, `tests/ml/test_scoring.py::test_readings_are_attack_scoped_and_free_of_banned_words`, `tests/ml/test_recommend.py::test_no_numeric_expected_gain_and_no_banned_words_anywhere`, `tests/ml/test_cli_matrix.py` (the matrix summary carries no mean, rank or aggregate) | ml |
| SC-003 | amended | The sampled review of outputs | No automated evidence. A review of sampled outputs has not been held. | |

## Done gate

- Passing checks: not recorded. Re-run the tiers above before quoting them.
- Acceptance evidence reviewed by: (blank)
- Behaviour-to-spec comparison reviewed by: (blank)
- Done: not recorded.
