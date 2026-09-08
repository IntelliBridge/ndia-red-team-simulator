# Workstream: Pythia access: gateway URL, key provisioning, connectivity check

Status: placeholder, work in progress (opened 2026-09-08).

Wires the hardening writer to the Pythia gateway: PYTHIA_BASE_URL / PYTHIA_API_KEY / PYTHIA_PERSONA / AEGIS_ML_LLM_MODEL in .env.example and deploy config, an aegis ml pythia-check command that lists /v1/models and runs one chat completion, and a note on how the key is provisioned (GovCloud). No secrets committed.

Source of truth: docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md.
