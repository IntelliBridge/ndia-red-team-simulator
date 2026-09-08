# Workstream: Pythia access: gateway URL, key provisioning, connectivity check

Status: implemented on `feat/pythia-access` (PR #11), opened 2026-09-08.

Wires the hardening writer to the Pythia gateway. Delivered:

- `redsim/llm/pythia.py`: `.env` loading (`REDSIM_ENV_FILE`, default `./.env`, environment wins), `REDSIM_ML_LLM_MODEL` with `AEGIS_ML_LLM_MODEL` as a deprecated alias, TLS verification through the OS trust store (`truststore`) or a PEM bundle (`REDSIM_CA_BUNDLE` / `SSL_CERT_FILE`), and `GET /v1/models`.
- `python -m redsim.llm.pythia_check`: prints which settings are present (never the key), lists entitled models, runs one short chat completion, exits 0 or 1.
- `deploy/docker-compose.yml`: `PYTHIA_*` and `REDSIM_ML_LLM_MODEL` passthrough on `redsim-api` and the worker pool.
- `docs/ops/pythia.md`: operator guide, including the Zscaler note and the entitled model list observed on 2026-09-08.

No secrets committed. The key lives in the gitignored `.env`.

Source of truth: docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md (D5, section 20).
