# F004 Run Management: evidence record

Created 2026-09-09. This file maps every success criterion in
`specs/004-run-management/spec.md` to the automated tests that prove it, or
says "no automated evidence" where that is true. It follows the per-SC
disposition table in the spec's reconciliation section (2026-09-08) and does
not change it. "Done" is recorded here, separately from approval, and is not
claimed until the named reviewers record it.

Test tiers: `unit` is the default pytest tier, `ml` needs the `ml` extra,
`e2e` needs `REDSIM_E2E=1` (`tests/e2e/README.md`).

## Success criteria

| SC | Disposition (spec) | Clause | Evidence | Tier |
| --- | --- | --- | --- | --- |
| SC-001 | amended | Invalid, stale and terminal-to-running transitions are rejected and accepted ordering is preserved | `tests/test_job_state.py::test_terminal_states_reject_all_transitions`, `::test_every_disallowed_edge_is_rejected`, `::test_every_allowed_edge_is_accepted`, `::test_map_matches_spec_exactly`, `tests/test_run_rollup.py::test_terminal_run_is_never_reopened`, `::test_terminal_run_refused_with_audit_row`, `::test_cancelled_run_stays_cancelled_even_when_jobs_succeeded`, `tests/ml/test_cancel_terminal.py::test_cancel_terminal_run_409`, `::test_cancel_live_run_still_admits`, `tests/test_admission_audit_before_enqueue.py::test_cancel_emits_chain_row_then_marks_cancelled`, `tests/test_reaper.py` | unit, ml |
| SC-001 | amended | A worker without database or broker credentials cannot write (the redsim reading of "unauthenticated updates") | `tests/test_worker_sa_auth.py`, `tests/test_worker_hardening.py` | unit |
| SC-001 | amended | A terminal run is never mutated by a rerun | `tests/e2e/test_ml_campaigns.py::test_rerun_links_parent_and_never_mutates_terminal` | e2e |
| SC-002 | amended | Every run exposes its frozen configuration and `Provenance` | `tests/ml/test_campaign.py::test_stages_provenance_and_limitations`, `tests/ml/test_admission_params.py::test_frozen_params_carry_no_grid_owned_keys_and_the_runner_accepts_them`, `tests/ml/test_campaign_routes.py::test_start_campaign_fills_spec_defaults_and_audits_before_rows`, `tests/ml/test_tasks.py::test_stage_table_has_the_6_5_shape` | ml |
| SC-002 | amended | A rerun records its original run id | `tests/ml/test_admission.py::test_rerun_links_parent`, `::test_rerun_of_a_cancelled_parent_is_admitted_too`, `tests/ml/test_campaign_routes.py::test_rerun_refuses_a_parent_that_is_not_terminal`, `::test_rerun_refuses_a_parent_on_another_model`, `::test_rerun_unknown_parent_404`, `tests/e2e/test_ml_campaigns.py::test_rerun_links_parent_and_never_mutates_terminal` | ml, e2e |
| SC-003 | amended | Broker or database down at admission is an explicit `503` with the rows rolled back | `tests/ml/test_campaign_routes.py::test_queue_unavailable_503`, `tests/ml/test_admission.py::test_verify_queue_unavailable_rolls_back` | ml |
| SC-003 | amended | A sandbox refusal or timeout is a `failed` job with the reason, never a fabricated result | `tests/ml/test_tasks.py::test_child_load_refusal_is_a_failed_job_with_refused_model_load`, `::test_sandbox_timeout_marks_partial`, `tests/test_ml_sandbox.py::test_sandbox_returns_partial_record_when_child_fails`, `::test_sandbox_kills_process_group_when_cancelled`, `tests/ml/test_sandbox_loader.py::test_timeout_raises_sandboxtimeout`, `::test_nonzero_exit_raises_sandbox_killed_with_exit_status` | unit, ml |
| SC-003 | amended | Zero execution in the web process | `tests/test_api_process_has_no_ml.py::test_api_app_builds_with_ml_libraries_blocked`, `::test_sandbox_child_env_allowlist_excludes_gateway_and_cloud_credentials`, `tests/e2e/test_ml_upload_reports.py::test_api_process_admits_uploads_without_importing_ml` | unit, e2e |

## Done gate

- Passing checks: not recorded. Re-run the tiers above before quoting them.
- Acceptance evidence reviewed by: (blank)
- Behaviour-to-spec comparison reviewed by: (blank)
- Done: not recorded.
