# F008 Audit and Governance: evidence record

Created 2026-09-09. This file maps every success criterion in
`specs/008-audit-governance/spec.md` to the automated tests that prove it, or
says "no automated evidence" where that is true. It follows the per-SC
disposition table in the spec's reconciliation section (2026-09-08) and does
not change it. "Done" is recorded here, separately from approval, and is not
claimed until the named reviewers record it.

Test tiers: `unit` is the default pytest tier, `integration` needs sqlite or
Postgres (the Postgres cases skip without `REDSIM_DB_URL`), `ml` needs the
`ml` extra, `e2e` needs `REDSIM_E2E=1` (`tests/e2e/README.md`).

## Success criteria

| SC | Disposition (spec) | Clause | Evidence | Tier |
| --- | --- | --- | --- | --- |
| SC-001 | amended | Mutation of a stored event is rejected | `tests/test_audit_append_only.py::test_update_delete_truncate_blocked_append_and_verify_ok` (Postgres trigger) | integration (Postgres) |
| SC-001 | amended | Chain integrity: a mutated or deleted event breaks verification | `tests/test_audit_chain.py::test_n_events_verify_ok`, `::test_mutation_breaks_chain`, `::test_deletion_breaks_chain`, `tests/test_audit_single_file_chains.py`, `tests/test_audit_cli_offline.py`, `tests/e2e/test_ml_governance.py::test_audit_verify_all_and_tamper`, `tests/e2e/test_harness_smoke.py::test_audit_verify_all_is_clean_then_breaks_at_the_tampered_seq` | unit, e2e |
| SC-001 | amended | Secret fields are redacted | `tests/test_audit_chain.py::test_authorization_header_redacted`, `::test_credential_keys_redacted_by_name`, `::test_chain_writer_scrubs_pythia_and_kaggle_tokens`, `::test_pythia_key_scrubbed_from_string_values`, `tests/test_otel_redaction.py` | unit |
| SC-001 | amended | Cross-project event requests are refused by the `check()` gate | `tests/ml/test_audit_verify_api.py::test_all_chains_admin_only`, `tests/test_project_access_read.py::test_report_403_when_no_membership`, `tests/e2e/test_ml_governance.py::test_rbac_negatives` | ml, unit, e2e |
| SC-001 | amended | ML audit detail carries ids, digests and counts, never payloads | `tests/ml/test_audit_campaign.py::test_audit_detail_carries_digests_and_ids_never_text_or_keys`, `::test_refused_steps_are_success_false_rows_that_still_chain`, `::test_full_chain_carries_5_11_vocabulary`, `tests/test_admission_audit_before_enqueue.py`, `tests/ml/test_admission.py::test_create_attack_campaign_audits_before_rows` | ml, unit |
| SC-001 | Phase B (FR-002) | A raw-payload allowlist validator rejects prohibited payloads | No automated evidence. The validator is Phase B. | |
| SC-002 | deferred to Phase B | Every decision resolves to an exact policy version | No automated evidence. Policy versions do not exist. | |
| SC-002 | deferred to Phase B | Every event resolves to an actor and a `seq` on a verifiable chain (the Phase A half) | `tests/test_audit_chain.py::test_n_events_verify_ok`, `tests/ml/test_audit_campaign.py::test_full_chain_carries_5_11_vocabulary` | unit, ml |
| SC-003 | amended | Zero purge attempts succeed before D006: no purge path, the append-only trigger, Object Lock on the WORM export | `tests/test_audit_append_only.py::test_update_delete_truncate_blocked_append_and_verify_ok`, `tests/test_worm_export.py::test_object_lock_headers_and_roundtrip`, `::test_broken_chain_flagged_but_archived`, `::test_idempotent_reexport_skips`, `::test_archive_chain_writes_jsonl_and_manifest_with_fields` | integration, unit |
| SC-003 | Phase B (FR-010) | Every approved purge retains a truthful deletion marker | No automated evidence. No purge exists. | |

## Done gate

- Passing checks: not recorded. Re-run the tiers above before quoting them.
- Acceptance evidence reviewed by: (blank)
- Behaviour-to-spec comparison reviewed by: (blank)
- Done: not recorded.
