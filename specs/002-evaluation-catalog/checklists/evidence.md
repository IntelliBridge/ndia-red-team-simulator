# F002 Evaluation Catalog: evidence record

Created 2026-09-09. This file maps every success criterion in
`specs/002-evaluation-catalog/spec.md` to the automated tests that prove it, or
says "no automated evidence" where that is true. It follows the "Also affected"
paragraph of the spec's reconciliation section (2026-09-08) and does not change
it. "Done" is recorded here, separately from approval, and is not claimed until
the named reviewers record it.

Test tiers: `unit` is the default pytest tier, `integration` needs sqlite or
Postgres, `ml` needs the `ml` extra, `e2e` needs `REDSIM_E2E=1`
(`tests/e2e/README.md`), `web` is vitest under `web/`.

## Success criteria

| SC | Disposition (spec) | Clause | Evidence | Tier |
| --- | --- | --- | --- | --- |
| SC-001 | amended | Every bundled entry carries a manifest-recorded licence and sha256 | `tests/ml/test_assets_manifest.py::test_file_entry_requires_a_real_sha256`, `::test_model_entry_is_an_ml_model_manifest`, `::test_model_entry_refuses_inconsistent_records`, `::test_manifest_round_trip_and_sorted_keys`, `tests/ml/test_datasets.py` (public-index rows per code-named dataset) | ml |
| SC-001 | amended | A tampered bundled asset is refused at registration | `tests/ml/test_models_routes.py::test_bundled_register_refuses_tampered_assets`, `::test_register_bundled_model_service_audits_before_rows` | ml |
| SC-001 | amended | Uploads record sha256 and format, and refuse pickles and unsupported formats | `tests/ml/test_models_routes.py::test_upload_success_writes_blob_key_rows_and_audit`, `::test_upload_refusal_codes_and_audit`, `::test_upload_size_cap_and_content_length`, `tests/ml/test_model_validate.py::test_pickle_refused_and_blob_deleted`, `::test_digest_mismatch_refused`, `::test_state_dict_available_gradients_true`, `tests/e2e/test_ml_verify_upload_reports.py::test_onnx_available_and_pickle_refused`, `::test_api_process_admits_uploads_without_importing_ml` | ml, e2e |
| SC-001 | amended | "Approved" versions in the F002 sense (independent Reviewer approval) | No automated evidence. The approval workflow is Phase B (US2, FR-006). | |
| SC-002 | amended | Hard deletion for unused drafts only | Partial. `tests/ml/test_models_routes.py::test_list_hides_deleted_and_fixture_only` covers the audited soft delete. The FK block on a referenced target has no dedicated test: no automated evidence for the "unused only" clause. | ml |
| SC-002 | amended | Historical references survive | `tests/ml/test_models_routes.py::test_detail_campaign_history_and_last_run_id`, `tests/ml/test_campaign.py::test_stages_provenance_and_limitations` (the `Provenance` snapshot carries `model_sha256` and the manifest) | ml |
| SC-002 | deferred to Phase B | Archive (exclusion from new selections without deletion) | No automated evidence. No archive flag exists (FR-008). | |
| SC-003 | unchanged | Record type, exact version, provenance and status are readable from the catalog | `tests/ml/test_catalog_routes.py::test_models_catalog_without_built_assets_is_honest`, `tests/ml/test_models_routes.py::test_detail_campaign_history_and_last_run_id`, `web/src/app/models/page.test.tsx`, `web/src/app/models/[id]/page.test.tsx` | ml, web |
| SC-003 | unchanged | The moderated review session itself | No automated evidence. A moderated review has not been held. | |

## Done gate

- Passing checks: not recorded. Re-run the tiers above before quoting them.
- Acceptance evidence reviewed by: (blank)
- Behaviour-to-spec comparison reviewed by: (blank)
- Done: not recorded.
