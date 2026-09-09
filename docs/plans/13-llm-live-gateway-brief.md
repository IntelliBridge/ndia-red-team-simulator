# LLM probe path on the live gateway and the runtime: agent brief (2026-09-09)

This is a self-contained brief for an agent (or a person working like one). It
covers exactly the work that neither Phase B wave B4 nor the remaining-work
brief (`docs/plans/10-remaining-work-brief.md`, "brief 10") owns: what a live
run of the garak probe path against the real Pythia gateway on 2026-09-09
showed the product does not yet handle, and what the runtime still lacks
before the same probe can run there. Everything else about the LLM track is
already on `main` or is being landed by wave B4, and section 1 says which is
which so nothing here is done twice.

## 0. Your task

Take the LLM probe path from "proven end to end against a fake gateway, and
proven live only at the child layer" to "proven end to end against the real
Pythia gateway, on the compose stack and on the Fargate runtime", and make the
product handle the three gateway behaviours the live run surfaced. Four
packages: **L** (gateway behaviours in the product code), **R** (image and
runtime additions for the probe path), **A** (the acceptance runs) and **D**
(documentation of all of it). Every item is a row with a criterion. Do not
redo anything listed in section 1.2.

## 1. State of the tree and what is already owned elsewhere

### 1.1 What is on `main` (verified 2026-09-09 at `703f8f6`)

The probe path exists and is tested against a loopback fake gateway:

- `POST /v1/models {source: endpoint, endpoint_kind: llm, model_id, persona,
  guardrail_mode, auth_profile_id}` registers an LLM target (admin);
  `POST /v1/models/{id}/probes` admits a run (remediator, audit row first,
  `Run` and `Job` rows, then the enqueue); `redsim.ml_llm_probe_run` on the
  `default` queue checks `REDSIM_DISABLE_LLM`, resolves the bearer
  `AuthProfile`, confirms entitlement with `GET {gateway}/v1/models` using the
  probe key, runs `redsim.ml.llm.runner.run_probe_child` in a credential-
  minimised subprocess, and stores the garak files, the k/n scorecard
  (`ml.llm.scorecard`), findings, the report and the audit rows.
  `GET /v1/runs/{id}/llm-scorecard` serves the scorecard digest-checked.
- `redsim/ml/llm/generator.py` `PythiaGenerator(OpenAICompatible)` posts to
  `{gateway}/v1/chat/completions` with `X-Pythia-Persona`, truststore TLS,
  `max_retries=0` on the OpenAI client and its own bounded loop:
  `transport_max_tries` 4, `transport_backoff_s` 1.0 doubling to
  `transport_max_sleep_s` 20.0, retrying `RateLimitError`,
  `InternalServerError`, `APITimeoutError`, `APIConnectionError` and
  `GeneratorBackoffTrigger`, then raising `GarakException("gateway transport
  failed after N tries: <class>")`, which aborts the whole probe. garak's own
  `OpenAICompatible._call_model` treats `AuthenticationError` and
  `PermissionDeniedError` (401 and 403) as terminal without retry.
- The garak tier: 12 tests in `tests/ml/test_llm_core.py` and
  `tests/ml/test_llm_routes.py` drive garak 0.16.0 against
  `tests/ml/fake_openai_server.py` (switches: `fail_status`, `fail_first`,
  a low-entropy fake token, persona and body-key recording). Green at the B3
  integration.
- `docs/ops/pythia.md` sections "Probe traffic (wave B2)" and "Personas and
  guardrails" describe the design, including owner default LLM-26 (a separate
  persona and key for probe traffic).

### 1.2 Owned elsewhere: do not redo

| Owner | Items | What it gives you |
|---|---|---|
| Wave B4 (landing on `main` as you read this) | `tests/e2e/test_ml_llm.py` (registration gates, probe run end to end against the fake server, scorecard, findings, report, audit chain, RBAC negatives); `scripts/phase_b_gate.sh` and `make check-phase-b` (every tier, mkdocs, the docs-consistency test, and HTTP probes behind `REDSIM_API_URL` including "a probe run yields a scorecard with denominators and no MRI"); CI job wiring in `.github/workflows/redsim-ci.yml`; the B4 documentation pass | The e2e evidence on fake infrastructure and the gate script you will point at real infrastructure in package A |
| Brief 10, package A (compose) | A1 proxy-tolerant Postgres image, A2 `make up` with `/health`, A3 worker image runs the sandbox child, A4 assets mounted and `redsim ml seed`, A5 the Pythia environment split (`redsim-worker-default` gets `PYTHIA_*` with `REDSIM_DISABLE_LLM` unset, the `scans` pool keeps `1`), A8 `make seed` and `make token-for`, A9 a live-mode smoke target, A10 Helm parity | A running compose stack whose default pool may talk to Pythia |
| Brief 10, package E (runtime) | E1 Keycloak role claim, E2 pinned asset bundle, E3 worker desired count above zero with a default pool holding the Pythia secret and beat running, E4 CI-driven rollout that runs the migration task (this is what takes RDS from `0010` to `0011`), E5 deploy role, E6 demo users and memberships, E8 API-level smoke against the live URL (`make smoke-live`, a classifier campaign) | A runtime with workers, users and the narrative writer's Pythia secret |
| Phase B waves after B4 | Nothing on the LLM track. The remaining wave work is the CI workflow fix and the completion checks | No file contention on the files this brief touches |

Brief 10 section G explicitly scopes "LLM red-teaming through Pythia with
garak" out of that brief, and E8's smoke runs a classifier campaign, so
without this brief the runtime could pass every E row and still never run a
probe.

### 1.3 What the live run showed (2026-09-09, run by hand at the child layer)

The owner asked for a live test of the gateway with the key in `.env`. It ran
`run_probe_child` directly from a driver script (no API, no worker, no
database), so nothing from it is persisted in redsim. Counts only were
retained; the report and its CSV are committed beside this brief as
`docs/ops/reports/pythia-jailbreak-probe-2026-09-09.html` and `.csv`.

- **Entitlement.** `GET /v1/models` with the key answered 27 ids under
  persona `default`. Persona `redteam` is "Unknown or unauthorized persona"
  for this key. During the day the operators added `openai/gpt-5.4`,
  `openai/gpt-5.6-luna` and `openai/gpt-5.6-terra` and removed three ids
  that answered 502. Model ids not in the catalog answer
  `HTTP 404 model_not_found` ("is not in the model catalog"), which is the
  catalog, not the key's entitlement.
- **403 content filter.** With the `default` persona's content guardrails
  on, the first `dan.DanInTheWild` prompt was refused by the gateway:
  `HTTP 403 {"error": {"code": "persona_denied", "type":
  "permission_error", "message": "Blocked by prompt_injection_detector:
  ..."}}`. garak mapped the 403 to an authentication failure and aborted the
  probe (`n_attempts_complete: 0`, status `failed`). Encoding probes passed.
  The owner then switched content filtering off on `default`; the jailbreak
  probe reached every chat model afterwards.
- **429 under bursts.** Nine concurrent probe children (one per model) hit
  the per-key rate limit: 15 of 27 runs ended in `gateway transport failed
  after 4 tries: RateLimitError`. Two to three concurrent children were
  clean. The bounded loop's four tries with a 20 s cap are not enough under
  a burst, and the failure aborts the whole probe rather than the request.
- **502 provider unavailable.** `openai/gpt-5.5`, `xai/grok-4.6`,
  `anthropic/claude-3-haiku-20240307-v1:0` and the two embedding ids answered
  `HTTP 502 {"error": {"code": "provider_unavailable", "type": "api_error",
  "message": "all upstream providers failed"}}` on every request, in garak's
  request shape and a minimal one. The generator retried each of the five
  prompts five times before the probe failed, so a dead upstream costs a
  full retry storm and ends as a generic transport failure.
- **Result.** 25 chat models completed 5 prompts each with the offline
  `mitigation.MitigationBypass` detector; every one returned at least one
  hit. That is a single bounded run at n=5 and is labelled so.

## 2. Ground rules

Brief 10 section 2 applies in full (frozen schema and the plan-01 section 8
protocol, error codes only from `redsim/api/errors.py` with the spec 17.3
table parsed by `tests/ml/test_error_codes.py`, audit row before any write,
`not_implemented` with a `phase`, no readiness or certification wording,
numbers labelled illustrative unless from a record in hand, the Aikido
pre-commit hook never skipped for anything but the known redaction fixtures,
small PRs rebased onto `main` immediately before the push, squash merges).
Three rules specific to this brief:

1. **Key hygiene.** The Pythia key lives in `.env` (gitignored) on a laptop
   and in Secrets Manager on the runtime. Never print it, log it, put it in
   a task environment variable, a Terraform value, a ticket, a test fixture
   or a commit. `PythiaSettings.redacted()` is the only view that reaches
   any output. The probe key reaches the product only as a bearer
   `AuthProfile` (Fernet-encrypted at rest under `REDSIM_AUTH_PROFILES_KEY`).
2. **Never read the prompts.** garak's `report.jsonl` and `hitlog.jsonl`
   carry prompt and completion text and are stored as artifacts by design.
   Nothing you write (logs, docs, tickets, test output, this brief's
   report-back) may quote a prompt or a completion. Work from counts,
   codes, digests and ids.
3. **The gateway is shared and rate-limited.** Keep concurrent probe traffic
   at or below two children while you work, and run acceptance probes with
   `max_prompts_per_probe` of 5 and one or two probe ids.

Commands are in brief 10 section 3. The garak tier is
`.venv/bin/python -m pytest -q -p no:cacheprovider -m garak tests`; the fake
gateway needs no network.

## 3. Package L: gateway behaviours in the product code

Files: `redsim/ml/llm/generator.py`, `redsim/ml/llm/probe_child.py`,
`redsim/ml/llm/runner.py`, `redsim/ml/llm/scorecard.py`,
`redsim/services/ml_llm.py`, `redsim/workers/tasks/ml_llm.py`,
`tests/ml/fake_openai_server.py`, `tests/ml/test_llm_core.py`,
`tests/ml/test_llm_routes.py`. Land L5 first (the switches), then L1 to L4
each with its tests.

| # | Item | Criterion |
|---|---|---|
| L1 | **429 handling.** Honour `Retry-After` (seconds or HTTP-date) when the gateway sends it, else keep the doubling backoff. Raise the defaults to `transport_max_tries` 8 and `transport_max_sleep_s` 60, read overrides from `REDSIM_LLM_PROBE_TRANSPORT_MAX_TRIES` and `REDSIM_LLM_PROBE_TRANSPORT_MAX_SLEEP_S` in the worker parent and pass them through `LLMProbeChildSpec` (its `transport_max_tries` bound `le=10` may rise to 12). Count waits in the usage ledger (`retries`, and a new `retry_after_honoured` counter). | A garak-tier test with the fake server answering 429 with `Retry-After: 2` for the first three requests completes 5 of 5 attempts, the ledger shows the retries, and the scorecard is `complete`. The abort path still fires when the cap is exhausted. |
| L2 | **Per-gateway concurrency cap.** Bound concurrent probe jobs per `(gateway host, persona)` across projects: `REDSIM_LLM_PROBE_MAX_CONCURRENT_PER_GATEWAY`, default 2. Enforce at admission in `services.ml_llm.admit_llm_probe_run` with the capacity pattern (`services.ml_capacity`: a deferred job with `detail.deferred`, the `capacity_deferred` 202 marker, no broker message) and let the existing `redsim.ml_dispatch_deferred` sweep and the `deferred_continuation` hook dispatch it; count live probe jobs from the jobs table by target host and persona, not per project. Also cap `max_parallel` for any batch that carries LLM targets. | Three admissions for targets on the same host and persona: two enqueue, the third is `202` with `capacity_deferred` and no broker call; when one finishes, the sweep dispatches it. A different host is not counted. `GET /v1/ml/capacity` shows the gateway cap under `limits`. |
| L3 | **403 content filter is a blocked prompt, not an auth failure.** In `PythiaGenerator._call_model`, catch `openai.PermissionDeniedError`; when the body's `error.code` is `persona_denied` or the message starts with `Blocked by`, return `[None] * generations_this_call` (garak counts a `None` output as not evaluated), increment a new `gateway_blocked` ledger counter, and continue. Any other 401 or 403 stays terminal (a wrong key or an unauthorized persona must still abort at once). Surface the count on `ChildProbeResult` (`n_outputs_blocked`), on the scorecard row, and add the limitation sentence when `gateway_blocked > 0` and `guardrail_mode` is not `content_filtered` ("the gateway blocked N prompts before the model saw them, so hit rates are over the prompts that reached the model"). Never store the blocked prompt text anywhere new. | A garak-tier test with the fake server answering the exact 403 body for two of five prompts ends `succeeded` with `n_attempts_complete 5`, `n_outputs_blocked 2`, denominators over the three evaluated, and the limitation sentence present; a plain 403 with `{"detail": "Unknown or unauthorized persona"}` still aborts with the auth message. |
| L4 | **502 `provider_unavailable` is terminal for the run, with a typed reason.** When a 5xx body carries `error.code == "provider_unavailable"`, stop retrying that request, mark the probe row `not_run` with reason `provider_unavailable` (or fail the run with that code when it is the first request), and end the child with `status: failed`, `error_type: provider_unavailable`. Other 5xx keep the L1 retry. In the worker, project the code onto the job (`job.detail.error_code`), the `llm.probe.execute` audit row and the run summary. Expose it on the API only through documented codes: if a new table code is wanted, add `provider_unavailable` (503) to the spec 17.3 addendum and `redsim/api/errors.py` together so `tests/ml/test_error_codes.py` stays green; otherwise the job carries the code and the route keeps `score_unavailable`. | A garak-tier test with the fake server answering the exact 502 body ends within one request per prompt (ledger `requests` equals the prompt count, `retries` 0), the row is `not_run` with the reason, and the worker test shows the code on the job and the audit row. |
| L5 | **Fake gateway switches for the observed bodies.** Extend `tests/ml/fake_openai_server.py` with `fail_body` (a structured error object to return with `fail_status`), `fail_indices` (which request numbers fail, so L3's "two of five" is expressible), `retry_after` (seconds header on 429) and a `served_model` recorder, keeping the existing `fail_status` and `fail_first` behaviour and the low-entropy fake token. | The three bodies in section 1.3 are reproducible from the switches, and the existing 12 garak-tier tests still pass. |
| L6 | **Runbook reflection.** The generator's retry contract (tries, cap, `Retry-After`, what aborts and what continues) and the two new ledger counters documented in `docs/ops/pythia.md` "Probe traffic" and the limitation sentence in `docs/architecture/ml-vertical.md`. | Both pages name the variables and match the code; `mkdocs build --strict` clean. |

## 4. Package R: image and runtime additions for the probe path

Files: `deploy/Dockerfile.worker`, `deploy/runtime/tasks.tf`,
`deploy/runtime/scripts/prepare_secrets.py` (or a new script beside it),
`deploy/runtime/README.md`, `deploy/docker-compose.yml` and
`deploy/helm/redsim/values.yaml` (one line each for parity, coordinated with
brief 10 A3, A5 and A10), `Makefile`.

| # | Item | Criterion |
|---|---|---|
| R1 | **The worker image installs the `garak` extra.** `deploy/Dockerfile.worker` installs `.[worker,ml]` today; a probe on the compose stack or on Fargate fails on `import garak`. Add the extra to the image (`.[worker,ml,garak]`, `garak>=0.16,<0.17` as `pyproject.toml` pins it) and keep the CPU torch wheel step first. Tell the brief 10 owner so A3 verifies `python -c "import garak"` as well as the sandbox child. | The built image runs `python -c "import garak, redsim.ml.llm.probe_child"` and `python -m redsim.ml.llm.probe_child --help` exits 0. |
| R2 | **Default pool environment on the runtime.** `deploy/runtime/tasks.tf` puts `REDSIM_DISABLE_LLM = "1"` in `common_environment` for every service, so the probe task on Fargate refuses `llm_disabled` before any request. Unset it for the `default` service only (the `scans` pool, api and beat keep `1`), give the `default` pool the Pythia variables and `REDSIM_AUTH_PROFILES_KEY` from Secrets Manager (the api task needs the same profiles key), and add the gateway host to whatever egress control the default pool has. Extends brief 10 E3, which names the Pythia secret but not the flag. | `terraform plan` shows the flag absent from the default task definition and present on the others; `deploy/runtime/tests/runtime.tftest.hcl` gains the assertion; the runtime README lists the default pool's variables. |
| R3 | **Probe key as an AuthProfile, never a task variable.** An idempotent seed step (extend `prepare_secrets.py`'s pattern, or a `redsim` command run through `run_task.py`) that reads the probe key from Secrets Manager in memory and creates the bearer `AuthProfile` through `POST /v1/auth-profiles {kind: "bearer", name, config: {}, secret}` (or the service call) under a service principal, prints only the profile id, and re-runs without duplicating. Record the profile id in the runtime README, not the key. Then LLM-26: ask the Pythia operators for a permission-gate-only persona with its own key, and record in `docs/ops/pythia.md` that until it exists the `default` persona with content filtering switched off (owner action, 2026-09-09) stands in for it, as a knowing divergence. | The profile exists on the runtime, `GET /v1/auth-profiles` shows it without any secret material, the seed step is idempotent, and the README names the profile and the LLM-26 status. |
| R4 | **Egress from the default pool to the gateway.** One-shot check from a default-pool task: `redsim.llm.pythia_check --skip-chat` (reads the key from the environment of that one task invocation only, prints the redacted key and the model ids) through the NAT. Document the security group or NAT rule if one has to change. | The task prints the entitled ids from inside the VPC and no rule change is undocumented. |
| R5 | **Compose parity for the probe.** With brief 10 A5 in place, the compose default pool also needs R1's image and `REDSIM_AUTH_PROFILES_KEY`; add a `make probe-key-profile` (or extend `make seed`) that creates the bearer profile from `PYTHIA_API_KEY` in the operator's shell environment, never from a file baked into the image. | `make up && make seed && make probe-key-profile` leaves a bearer profile in the compose database and no key in any container environment except the default worker's `PYTHIA_API_KEY` for the narrative writer. |

## 5. Package A: acceptance runs on real infrastructure

Both runs use wave B4's gate rather than a new smoke: `make check-phase-b`
with `REDSIM_API_URL` pointed at the stack under test already includes "a
probe run yields a scorecard with denominators and no MRI". If the gate's
probe step needs a target id or profile id passed in, add the two variables
to `scripts/phase_b_gate.sh` and tell the B4 owner in the PR.

| # | Item | Criterion |
|---|---|---|
| A1 | **Compose stack against the real gateway.** After brief 10 A2, A5, A8 and this brief's R1, R5: register an LLM target for `openai/gpt-5.6-luna` (or any entitled chat id) with persona `default`, `guardrail_mode: permission_gate_only`, the bearer profile from R5; run `POST /v1/models/{id}/probes {probe_ids: ["dan.DanInTheWild"], max_prompts_per_probe: 5, detector_mode: "offline"}`; then read the scorecard route, the artifacts list, `report.html`, `GET /v1/audit/verify?run=` and `redsim audit verify --run <id>`. Then run `make check-phase-b` against the stack. | The scorecard has one row with `k/n` over 5, no MRI key (the validator), the five `ml.llm.*` artifacts exist with digests, the chain verifies, one `LLMUsage(task="ml.llm_probe")` row exists, and `make check-phase-b` exits 0. Record counts and ids only. |
| A2 | **Runtime against the real gateway.** After brief 10 E2, E3, E4, E6 and this brief's R1 to R4: the same registration and probe through the public URL with an OIDC token from a demo user at `remediator` or above (E6), then the same reads, then `make check-phase-b` with `REDSIM_API_URL` set to the runtime. | Same criteria as A1 on RDS and S3, with the audit chain verified against RDS. This is the first campaign or probe of any kind on the runtime; say so in the report-back. |
| A3 | **Behaviour checks on the live gateway, once each.** With L1 to L4 landed: a probe against an id known to answer 502 (`openai/gpt-5.5` on 2026-09-09; re-check first) ends `not_run: provider_unavailable` within one request per prompt; a probe with `max_parallel` above the L2 cap defers the surplus; and, only if the operators can re-enable content filtering on a test persona for the check, a probe records `n_outputs_blocked` instead of aborting. | Each outcome is visible in the scorecard, the job detail and the audit rows with the typed code, and none of them needed a retry storm. |

## 6. Package D: documentation

| # | Item | Criterion |
|---|---|---|
| D1 | `docs/ops/pythia.md`: a "Live observations (2026-09-09)" section with the facts in section 1.3 (catalog versus entitlement, the 403 body and its meaning, the burst limit, the 502 body), a refreshed "Entitled models observed" table dated to the run with the afternoon additions and removals, the `redteam` persona result, the guardrail switch as an owner action, and links to `ops/reports/pythia-jailbreak-probe-2026-09-09.html` and `.csv`. Then the L6 and R3 text. | The page matches the committed report, names no key, quotes no prompt, and `mkdocs build --strict` is clean. |
| D2 | `deploy/runtime/README.md`: the default pool's variables (R2), the probe-key profile step (R3), the egress check (R4), the garak extra (R1), and the acceptance probe (A2) in the deployment sequence. | A reader can run A2 from the README alone. |
| D3 | `README.md` "Open items" and `CLAUDE.md`: the LLM path is proven against the real gateway on compose (A1) and on the runtime (A2) with dates, or still open, whichever is true when you push; the worker image's extras line updated. | The two files and `docs/architecture/ml-vertical.md` agree with each other and with the tree. |
| D4 | Brief 10 cross-reference: a one-line note in brief 10 section G pointing at this brief, and a line in section H's file list for the files in section 7 below. | Both briefs name each other. |

## 7. Coordination

- **Files this brief touches.** `redsim/ml/llm/{generator,probe_child,runner,
  scorecard}.py`, `redsim/services/ml_llm.py`,
  `redsim/workers/tasks/ml_llm.py`, `redsim/services/ml_capacity.py` (L2,
  additive), `tests/ml/fake_openai_server.py`, `tests/ml/test_llm_core.py`,
  `tests/ml/test_llm_routes.py`, `deploy/Dockerfile.worker`,
  `deploy/runtime/tasks.tf`, `deploy/runtime/scripts/*`,
  `deploy/runtime/README.md`, `deploy/docker-compose.yml` (one line),
  `deploy/helm/redsim/values.yaml` (one line), `scripts/phase_b_gate.sh`
  (two variables at most), `docs/ops/pythia.md`,
  `docs/architecture/ml-vertical.md`, `README.md`, `CLAUDE.md`,
  `docs/plans/10-remaining-work-brief.md` (D4 only).
- **Who else edits them.** Wave B4 lands `tests/e2e/test_ml_llm.py`,
  `scripts/phase_b_gate.sh` and the docs pages once, then no Phase B wave
  touches the LLM files again. Brief 10's owner edits `Dockerfile.worker`
  (A3), `docker-compose.yml` (A2, A5), `values.yaml` (A10) and
  `deploy/runtime/*` (package E). For those, agree the one-line edits in the
  PR description and rebase immediately before pushing; land R1 as its own
  PR first because A3 and E3 both depend on the image.
- **Order.** L5, L1, L3, L4 (each a PR with its garak-tier test), L2, then
  R1 and R5 for compose, A1, then R2 to R4 as brief 10 E3 lands, A2, A3, and
  D1 to D4 with each PR that changes what they describe. Wait for wave B4's
  push before touching `scripts/phase_b_gate.sh` or `docs/ops/pythia.md`.
- **Push convention.** Branch, PR, squash merge (the repository allows only
  squash), rebased onto `main` immediately before the push with the garak
  tier, `ruff check --select E4,E7,E9,F,I redsim tests`, `mypy redsim` and
  `mkdocs build --strict` re-run after the rebase.

## 8. How to report back

One message per package: the rows with `done` or `open` and a reason, the
commit ids, the test counts by tier (garak, default, e2e) after the rebase,
and for A1 and A2 the run id, the scorecard's `k/n` per probe, the artifact
kinds with their digests, and the `audit verify` result. Counts and ids only.
No key material, no prompt text, no completion text, no readiness wording.

## Implementation progress

- **L5 implemented (2026-09-09):** `tests/ml/fake_openai_server.py` now
  supports structured failure bodies, selected one-based completion indices,
  `Retry-After` on 429 responses, and the served model on successful request
  records. Catalog requests do not consume completion failure indices.
  `tests/ml/test_fake_openai_server.py` has six passing cases covering the
  observed status/code shapes, selection, legacy failure modes and auth
  precedence. All 12 existing garak regression tests also passed on 2026-09-09;
  L5 acceptance is complete.
- **L1 implemented:** bounded retries default to 8 tries/60 seconds, with
  validated worker overrides, seconds/date `Retry-After` handling and a
  `retry_after_honoured` ledger counter. A header above the wait budget aborts
  rather than retrying early. Regression validation is recorded in its PR.
- **L3 implemented:** gateway content-filter refusals become unevaluated
  outputs with per-probe blocked counts and a scorecard limitation. Plain
  authentication/permission refusals remain terminal. Offline tests verify
  five completed attempts, two blocked outputs and a denominator of three.
- **L4 implemented:** a structured unavailable-provider response aborts on
  the first request, with no retries, `not_run` rows and the typed reason in
  worker job detail, run summary, scorecard and execute audit rows. This uses
  the brief's permitted first-request abort path, rather than sending further
  prompts to an upstream already declared unavailable.
- **L2 implemented:** gateway/persona admission reservations span projects,
  use transaction locking on Postgres, defer surplus jobs, and dispatch through
  the existing sweep and completion hook. Capacity and batch limits expose the
  deployment cap. Tests cover concurrent reservations, cross-project counting,
  broker recovery and restoration of the caller's Postgres RLS scope.
- **L6 implemented:** `docs/ops/pythia.md` documents the retry bounds, headers,
  terminal/continuing outcomes, concurrency limit and ledger counters;
  `docs/architecture/ml-vertical.md` documents blocked-output denominators.
- Packages R/A/D remain open. No live gateway traffic or runtime
  changes were made for this test-helper increment.
