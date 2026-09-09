# F003 Evaluation Profiles: evidence record

Created 2026-09-09. This file maps every success criterion in
`specs/003-evaluation-profiles/spec.md` to the automated tests that prove it, or
says "no automated evidence" where that is true. It follows the "Also affected"
paragraph of the spec's reconciliation section (2026-09-08) and does not change
it. "Done" is recorded here, separately from approval, and is not claimed until
the named reviewers record it.

Test tiers: `unit` is the default pytest tier, `ml` needs the `ml` extra,
`e2e` needs `REDSIM_E2E=1` (`tests/e2e/README.md`), `web` is vitest under
`web/`.

## Success criteria

| SC | Disposition (spec) | Clause | Evidence | Tier |
| --- | --- | --- | --- | --- |
| SC-001 | deferred to Phase B (follows US2) | Publish attempts without independent approval, required controls, compatible inputs or explicit limitations are rejected | No automated evidence for publication. There is no publish step. The Phase A analogue, admission of a campaign configuration, is covered by `tests/ml/test_campaign_routes.py::test_start_campaign_validation_matrix`, `::test_attack_requires_gradients_422`, `::test_dataset_missing_everywhere_is_dataset_incompatible`, `tests/ml/test_admission_params.py::test_image_only_attack_on_a_tabular_target_is_refused` and `tests/ml/test_campaign.py::test_frozen_config_rejects_invalid_campaigns_at_construction`. These prove admission rules, not the SC. | ml |
| SC-002 | applies in Phase A to the snapshot | A frozen configuration is byte-for-byte unchanged after admission | `tests/ml/test_scoring.py::test_settings_hash_excludes_verify_only_fields_and_covers_the_model`, `tests/ml/test_admission_params.py::test_frozen_params_carry_no_grid_owned_keys_and_the_runner_accepts_them`, `tests/ml/test_campaign_routes.py::test_rerun_refuses_a_succeeded_parent`, `::test_rerun_refuses_a_verify_parent_and_extra_config`, `tests/ml/test_admission.py::test_rerun_links_parent`, `tests/e2e/test_ml_campaigns.py::test_rerun_links_parent_and_never_mutates_terminal` | ml, e2e |
| SC-002 | deferred to Phase B | Revisions receive distinct version ids and renewed review | No automated evidence. No profile revision exists. | |
| SC-003 | applies in Phase A to the snapshot | A reader can identify the controls, limitations, `model_sha256` and dataset version of any campaign | `tests/ml/test_campaign.py::test_stages_provenance_and_limitations`, `::test_control_toggle`, `tests/ml/test_report.py::test_six_sections_in_order`, `tests/ml/test_fixture.py::test_fixture_has_every_panel`, `::test_fixture_config`, `tests/ml/test_schema_compat.py::test_p0_fixture_reaches_every_panel`, `web/src/app/runs/[id]/page.test.tsx` | ml, web |
| SC-003 | applies in Phase A to the snapshot | The moderated review session itself | No automated evidence. A moderated review has not been held. | |

## Done gate

- Passing checks: not recorded. Re-run the tiers above before quoting them.
- Acceptance evidence reviewed by: (blank)
- Behaviour-to-spec comparison reviewed by: (blank)
- Done: not recorded.
