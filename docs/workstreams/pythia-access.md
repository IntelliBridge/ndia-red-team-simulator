# Workstream: Pythia access: gateway URL, key provisioning, connectivity check

Status: merged. PR #11 `feat/pythia-access` landed on 2026-09-08, the worker
side moved to the parent process in wave 2 (`055bdee`), and the doctor and
configuration cleanup landed in wave 3 (`7556b22`, `c3868e5`). State
described here is `main` at `58461cc`.

Delivered:

- `redsim/llm/pythia.py`: `.env` loading (`REDSIM_ENV_FILE`, default `./.env`,
  environment wins), `REDSIM_ML_LLM_MODEL` with `AEGIS_ML_LLM_MODEL` and
  `REDSIM_LLM_MODEL` as deprecated aliases, TLS verification through the OS
  trust store (`truststore`) or a PEM bundle (`REDSIM_CA_BUNDLE` /
  `SSL_CERT_FILE`), `GET /v1/models`, `chat_text`, and
  `PythiaSettings.redacted()` as the only view that reaches provenance and
  audit.
- `python -m redsim.llm.pythia_check`: prints which settings are present
  (never the key), lists entitled models, runs one short chat completion,
  exits 0 or 1. Verified 2026-09-08 behind the corporate proxy: 27 entitled
  models, one completion OK.
- Worker path (wave 2): the hardening narrative runs in the worker parent
  after the sandbox child returns, through
  `redsim.llm.router.route("ml.harden_narrative")` with `DbBudgetChecker`,
  writes `ml.harden.prompt` / `ml.harden.completion` / `ml.harden.narrative`
  artifacts, one `LLMUsage(task="ml.harden_narrative")` row per call, and the
  `harden.execute` audit row with the redacted settings, digests and
  `usage.{prompt,completion}`. The child never receives `PYTHIA_*` and scrubs
  them again in-process. `redsim/config.py` seeds
  `task_models["ml.harden_narrative"]` from `REDSIM_ML_LLM_MODEL`.
  `redsim/audit/redact.py` scrubs `pk_…` and Kaggle token shapes.
- API: `GET /v1/ml/capabilities.llm_narrative` reports `configured`, the
  routed model and whether a persona is set, never the key or URL, and
  `GET /v1/orgs/{id}/cost` sums the usage rows by task.
- `deploy/docker-compose.yml`: `PYTHIA_*` and `REDSIM_ML_LLM_MODEL`
  passthrough on `redsim-api` and the worker pool. The worker anchor sets
  `REDSIM_DISABLE_LLM: "1"`, which has to be unset on `redsim-worker` (the
  `scans` pool) for a compose stack to narrate.
- `docs/ops/pythia.md`: operator guide, including the Zscaler note, the
  entitled model list observed on 2026-09-08 and the worker call path.
- Wave 3 (`7556b22`, `c3868e5`, on `main`): `redsim doctor` drops the provider-key check
  for an informational Pythia block (redacted key, model, deprecated-alias
  note) plus `ml` extra, sandbox child and asset manifest checks,
  `redsim.yaml` and `redsim init` stop writing a provider-style `model`,
  `.env.example` drops every provider key and documents the Pythia variables,
  `REDSIM_DISABLE_LLM`, `REDSIM_ENV_FILE`, every spec 20.3 ML variable and
  `KAGGLE_API_TOKEN` with empty values, and the sandbox child pins
  `REDSIM_ENV_FILE` to an absent path and sets `REDSIM_DISABLE_LLM`.

No secrets committed. The key lives in the gitignored `.env`. No campaign
narrative has been produced against the live gateway as part of the completion
pass. The worker path is tested with a mock transport.

Open: the Phase B garak persona (permission-gate-only guardrails, separate
key) is excluded from this pass.

Source of truth: docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md (D5, sections 10.8, 16.3, 20).
