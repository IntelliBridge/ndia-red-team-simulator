# Pythia access (LLM gateway)

Pythia (https://github.com/IntelliBridge/pythia) is IntelliBridge's
OpenAI-compatible agent gateway. Redsim never talks to a model provider
directly. It holds one Pythia `pk_…` key, and the gateway applies the
persona, guardrails, metering and audit before a request reaches a model.
Every LLM call in redsim goes through `redsim/llm/pythia.py` (decision D5 in
the product spec). There is no litellm and there are no provider keys anywhere
in the stack.

Status at `main` `703f8f6` plus Phase B wave B4 (2026-09-09): two consumers
in the Python services, plus the finding chat of the web process described
under [Finding chat (web)](#finding-chat-web).
The first is the optional hardening narrative, one plain, non-streaming chat
completion per campaign with candidate recommendations, fed the rule outputs,
the measurements and a SHAP text summary. Since wave 2 it runs in the
**worker parent** after the sandbox child returns
(`redsim/workers/tasks/ml_campaign.py::_parent_narrative`), routed through
`redsim.llm.router.route("ml.harden_narrative")` with the `DbBudgetChecker`,
and metered as one `LLMUsage` row per call. The sandbox child never holds the
key. When Pythia is not configured the narrative is skipped, never faked, and
recommendations render from the rule layer alone with
`narrative_source = "rules"`. The second, since wave B2, is the garak probe
traffic of `redsim.ml_llm_probe_run` described under
[Probe traffic](#probe-traffic-wave-b2): it uses its own key from an
`AuthProfile` and its own persona, never `PYTHIA_API_KEY` or the narrative
writer's persona. Since `7556b22` `redsim doctor`, `redsim.yaml` and
`.env.example` are Pythia-only: no provider key is listed, checked or written
anywhere, and `PYTHIA_API_KEY` is the only LLM credential the tree names in
its configuration files (the probe key lives encrypted in the database).

## The four environment variables

| Variable | Required | Meaning |
| --- | --- | --- |
| `PYTHIA_BASE_URL` | yes | Gateway base URL. The client calls `{PYTHIA_BASE_URL}/v1/chat/completions` and `{PYTHIA_BASE_URL}/v1/models`. |
| `PYTHIA_API_KEY` | yes | The `pk_…` gateway key, sent as `Authorization: Bearer`. The only LLM secret redsim holds. |
| `PYTHIA_PERSONA` | no | Sent as `X-Pythia-Persona`. Selects the gateway-side persona (system prompt, guardrails, model entitlements). The key used on 2026-09-08 runs the `default` persona. |
| `REDSIM_ML_LLM_MODEL` | yes | Canonical model id, `<vendor>/<model>` or `pythia/auto`. `AEGIS_ML_LLM_MODEL` is still read as a deprecated alias (a `DeprecationWarning` is raised) and so is the older scaffold name `REDSIM_LLM_MODEL`. Rename to the canonical name when you touch a config. `redsim/config.py` seeds `task_models["ml.harden_narrative"]` from it so the router resolves the task without a `redsim.yaml` entry. |

`PythiaSettings.from_env()` returns `None` unless the three required values
are present. Supporting variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PYTHIA_TIMEOUT_S` | `60` | Per-request timeout in seconds. |
| `REDSIM_DISABLE_LLM` | unset | Any truthy value skips the narrative with the recorded reason `disabled (REDSIM_DISABLE_LLM=1)`. The compose worker anchor sets it. |
| `REDSIM_LLM_BUDGET_STRICT` | unset (true in prod) | When the budget store cannot be read, deny the call instead of routing without a budget gate. |
| `REDSIM_ENV_FILE` | `./.env` | Path of the `.env` file to read. When unset, `./.env` in the current directory is tried, then `.env` at the repo root. |
| `REDSIM_TLS_TRUSTSTORE` | `1` | Verify TLS against the operating-system trust store through the `truststore` package. Set `0` to fall back to a PEM bundle. |
| `REDSIM_CA_BUNDLE` | unset | PEM bundle to trust when the trust store is off. `SSL_CERT_FILE` is honoured as well, with `REDSIM_CA_BUNDLE` taking precedence. |

## Where the key lives

The key, the URL, the persona and the model id live in `.env` at the repo
root. That file is gitignored and dockerignored, and the Aikido pre-commit
hook scans staged files for secrets, so the key should never appear in a
commit. `.env.example` documents the variables with empty values.

`redsim/llm/pythia.py` reads `.env` itself with a small `KEY=VALUE` parser
(comments, blank lines, `export`, quoted values), so no `python-dotenv`
dependency is needed. A variable set in the process environment always wins
over the file. Nothing in redsim ever logs the key: `PythiaSettings.redacted()`
is the only view that reaches provenance and the `harden.execute` audit row,
the connectivity check prints at most the first three characters, and
`redact_audit_detail` scrubs any `pk_…` shape that reaches an audit detail.
`GET /v1/ml/capabilities` reports `llm_narrative.configured` and the routed
model name, never the key or the URL.

Keys are provisioned by the Pythia operators (GovCloud deployment) per team
and per persona. Ask for a key scoped to the `default` persona for the
hardening writer. See "Personas and guardrails" below for what Phase B needs.

## Where the call is made

The narrative runs in the parent process of the `scans` worker after
`run_campaign_sandboxed` returns, only on a succeeded `attack.run` or
`harden.recommend` job whose config set `llm_narrative = true`. In order:

1. `REDSIM_DISABLE_LLM` is checked, then `PythiaSettings.from_env()`.
2. `redsim.llm.router.route("ml.harden_narrative")` resolves the model
   (organisation override, else `task_models` seeded from
   `REDSIM_ML_LLM_MODEL`) and checks the project daily cap and the
   organisation monthly cap through `DbBudgetChecker`. `BudgetExceeded` and
   `ModelNotConfigured` skip the narrative with the reason.
3. `redsim.ml.recommend.narrative.narrate` builds the text-only prompt (rule
   outputs, measurements with denominators, limitations, the SHAP text
   summary), wraps `chat_text` in `guard_input` and `guard_output`, and runs
   the numeric-consistency and banned-word checks on the reply.
4. The prompt and completion are stored as `ml.harden.prompt` and
   `ml.harden.completion` artifacts, the rendered prose as
   `ml.harden.narrative`. Their sha256, the redacted settings, `llm_used`,
   `narrative_source`, the skip reason if any, the token counts as
   `usage.{prompt,completion}` (the audit redactor blanks any key naming
   `token`) and `cost_cents` go on the `harden.execute` audit row.
5. One `LLMUsage(task="ml.harden_narrative")` row is written per call that
   received a response (a transport failure consumes nothing). A model
   without a pricing entry records zero cost and `unpriced_model` on the
   audit row. `GET /v1/orgs/{id}/cost` sums these rows.

The sandbox child is built from an empty environment and additionally
scrubs every `PYTHIA_*` variable and the model variables in-process, so a
widened allowlist can never turn it into an LLM caller. Because
`redsim.llm.pythia` falls back to `./.env` and the repo-root `.env` when
`REDSIM_ENV_FILE` is unset, the sandbox parent additionally pins
`REDSIM_ENV_FILE` to the absent `<work_dir>/no-env` and sets
`REDSIM_DISABLE_LLM=1` in the child environment (`c3868e5`), and an explicit
`REDSIM_ENV_FILE` that is not a file means "no `.env`" rather than a fall
through to `./.env` or the repo root.

## Finding chat (web) {#finding-chat-web}

The "Chat" button on `/findings/[id]` opens a slide-out drawer
(`web/src/components/finding-chat-panel.tsx`) that talks to the web app's
own route, `web/src/app/api/chat/finding/route.ts`. The route runs in the
Next server, never in the browser and never in FastAPI:

1. The same-origin gate of the tRPC layer runs first, then the session
   cookie is required. `GET` answers `{configured, model}` so the panel can
   say "unavailable" before the analyst types.
2. `POST {finding_id, messages}` fetches `GET /v1/findings/{id}` and
   `GET /v1/runs/{run_id}/campaign` through `upstreamFetch` with the caller's
   own cookie, so the model sees exactly what the analyst may see. An API
   refusal comes back with the API's status and code. A campaign record the
   API refuses (`409 llm_target_required` on a probe finding, a `404`) leaves
   the chat on the finding alone with the reason in the prompt.
3. `web/src/server/chat/context.ts` builds one system message: the reporting
   rules of the brief as instructions (labels kept, denominators quoted, no
   expected gain before a verify, no readiness wording) plus a compact JSON
   projection of the two records (measurements with `n` and `n_correct`, the
   score with its subscores and weights, the curve, the candidates with their
   validation state, the limitations; artifact ids and raw feature dumps
   dropped, observations capped at 8, the whole capped at 60,000 characters
   with the trims recorded).
4. `web/src/server/chat/pythia.ts` posts `{model, messages, stream: true,
   temperature: 0.2, max_tokens: 1200}` to `{PYTHIA_BASE_URL}/v1/chat/completions`
   with `Authorization: Bearer` and `X-Pythia-Persona`, and reads the
   server-sent events back. A gateway that answers a plain JSON completion is
   read as one delta. The route relays the deltas to the browser as
   newline-delimited JSON (`meta`, `delta`, `done`, `error`).

The web process reads `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`
and `PYTHIA_TIMEOUT_S` (default 120 here, the whole streamed answer) through
`web/src/env.js`, plus `REDSIM_WEB_CHAT_MODEL` (default
`anthropic/claude-opus-5`) for the model id. Without a base URL and a key the
route answers `503 llm_not_configured` and the panel says so. TLS runs on
Node's trust store: behind the corporate proxy set `NODE_EXTRA_CA_CERTS` to
the Zscaler root (the Python `truststore` path does not apply to Node).

### Proposed campaigns (2026-09-10)

The assistant may end an answer with one fenced block tagged
`redsim-proposal` (rule 8 of the system prompt): a JSON object with
`attack_ids`, `norm`, `eps_grid`, `reference_eps`, `n_samples` and a
one-sentence `rationale`. To bound it, the route also fetches
`GET /v1/attacks?modality=<campaign modality>` with the caller's cookie and
puts the roster in the context as `available_attacks` (ids, access,
`requires_gradients`, status, the `norm:*` tags; never the params schema). A
catalog the API cannot serve leaves the roster `null` and the prompt tells
the model to propose nothing.

The browser (`web/src/lib/chat.ts::parseProposal`) keeps the block out of
the prose, checks its shape (ids non-empty, a known norm, 1 to 8 positive
grid values with the reference among them, `n_samples` 1 to 500) and renders
it as a card labelled "candidate, not run" with the exact settings the
request would carry. The one control is "Run this campaign", shown to a
scanner and above. It posts `buildProposalRequest(campaign.config, proposal)`
to `POST /v1/models/{target_id}/attacks` through the normal cookie and CSRF
client: the recorded campaign's settings with the proposal's attack set,
norm, grid, reference and sample count in place of the parent's, and no
server-owned key (`scoring`, `modality`, `target_id`, `attack_params`). The
admission service does every check and writes the `attack.run` audit row,
`success=False` on refusal, exactly as for any other request; the panel shows
the refusal by code and links the admitted run. Nothing in the web process
runs or predicts a campaign, and the standing caveat still applies to the
prose around the card.

What the chat does not do, recorded under the README's open items: no audit
row and no `LLMUsage` row is written per turn, so the org cost view does not
include chat traffic; no per-user rate limit beyond the gateway's own; the
transcript lives in the browser's `sessionStorage` per finding and is sent
whole on every turn, so the server keeps no conversation state. The panel's
standing caveat says that an answer is a reading of recorded evidence and
not a measurement, and the analyst keeps the evidence panels beside it.

## Corporate proxy (Zscaler) and TLS

Behind the corporate proxy every HTTPS connection is re-signed by the Zscaler
root CA. `curl` works because it uses the macOS keychain, but Python's `ssl`
module and httpx default to the bundled `certifi` roots, which do not include
Zscaler, so a plain httpx client fails with `CERTIFICATE_VERIFY_FAILED`.

`redsim/llm/pythia.py` handles this in `tls_verify()`:

1. When `REDSIM_TLS_TRUSTSTORE` is not `0` and the `truststore` package is
   importable, the httpx client is built with
   `verify=truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)`. Certificates are
   then checked against the OS store (macOS keychain, Windows store, the distro
   bundle on Linux), where the Zscaler root already lives. This is the default
   on a developer laptop and is what the 2026-09-08 check used.
2. Otherwise, when `REDSIM_CA_BUNDLE` or `SSL_CERT_FILE` names a PEM bundle,
   the client uses `ssl.create_default_context(cafile=<path>)`.
3. Otherwise httpx's default certifi roots are used.

Tests inject an `httpx.MockTransport`, which bypasses TLS entirely, so no test
depends on the machine's trust store.

Containers do not have a keychain. They receive the CA through
`deploy/certs/`: the `Dockerfile.api` and `Dockerfile.worker` builds copy any
`*.pem` or `*.crt` there into the system store, run `update-ca-certificates`,
and set `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` to
`/etc/ssl/certs/ca-certificates.crt`. Inside a container `truststore` reads
that same distro bundle, so both paths agree. See `deploy/certs/README.md`
for how to export the Zscaler root.

## How the compose services receive the variables

`deploy/docker-compose.yml` passes the four variables through to `redsim-api`
and to the worker pool (`redsim-worker`, `redsim-worker-default`,
`redsim-beat`, which share the `&worker-env` anchor) with the `${VAR:-}` form:

```yaml
PYTHIA_BASE_URL: ${PYTHIA_BASE_URL:-}
PYTHIA_API_KEY: ${PYTHIA_API_KEY:-}
PYTHIA_PERSONA: ${PYTHIA_PERSONA:-}
REDSIM_ML_LLM_MODEL: ${REDSIM_ML_LLM_MODEL:-}
```

Compose interpolates these from the shell that runs it. When a variable is not
exported the container sees an empty string, `from_env()` returns `None`, and
the narrative stays off. Because `make up` runs
`docker compose -f deploy/docker-compose.yml` from the repo root, compose
looks for its own `.env` in `deploy/`, not at the repo root, so either export
the values first:

```bash
set -a; source .env; set +a
make up
```

or point compose at the file explicitly:

```bash
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
```

`redsim-web` receives `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`
and `REDSIM_WEB_CHAT_MODEL` the same way, for the finding chat.

The worker anchor also sets `REDSIM_DISABLE_LLM: "1"`, which the evidence
pack reports as `llm_enabled: false`. The narrative runs on the `scans`
worker (`redsim-worker`) since wave 2, so that is the service on which the
variable has to be unset (a `docker-compose.override.yml` is the least
invasive way) before a compose stack can produce a narrative. The API only
reads the variables to report `llm_narrative.configured`.

## Connectivity check

```bash
python -m redsim.llm.pythia_check              # reads ./.env
REDSIM_ENV_FILE=/path/to/.env python -m redsim.llm.pythia_check
python -m redsim.llm.pythia_check --skip-chat  # only GET /v1/models
python -m redsim.llm.pythia_check --model anthropic/claude-3-haiku-20240307-v1:0
```

The check prints which settings are present (the key as its three-character
prefix and length only), the TLS mode, `GET /v1/models` (count and ids), and
one short chat completion with the reply, latency and token usage. It exits 0
on success and 1 on any failure with a one-line reason. Any accidental echo of
the key in an error body is scrubbed before printing. `redsim doctor`
(`7556b22`) prints the same redacted block as an informational check that
never fails the doctor.

Observed on 2026-09-08 from a laptop behind Zscaler, persona `default`, model
`pythia/auto` (gateway URL redacted here, it is in `.env`):

```
Pythia connectivity check
  env file:         /Users/<user>/.../ndia-red-team-simulator/.env
  PYTHIA_BASE_URL:  https://<gateway>/
  PYTHIA_API_KEY:   pk_… (50 chars)
  PYTHIA_PERSONA:   default
  REDSIM_ML_LLM_MODEL: pythia/auto  (read from deprecated AEGIS_ML_LLM_MODEL, rename it to REDSIM_ML_LLM_MODEL)
  TLS:              truststore
models: 27 entitled. First: amazon/nova-lite-v1:0, amazon/nova-pro-v1:0, ...
chat: ok in 808 ms via model amazon/nova-micro-v1:0
  reply: 'Pong.'
  usage: prompt=21 completion=3 total=24
OK
```

This is the connectivity probe only. No campaign narrative has been produced
against the live gateway as part of the completion pass. The worker path is
exercised by `tests/ml/test_tasks.py` and `tests/ml/test_narrative.py` with a
mock transport.

### Entitled models observed (2026-09-08, persona `default`)

27 ids were returned by `GET /v1/models`. `pythia/auto` resolved the probe to
`amazon/nova-micro-v1:0`.

| Vendor | Model ids |
| --- | --- |
| amazon | `nova-micro-v1:0`, `nova-lite-v1:0`, `nova-pro-v1:0`, `titan-embed-text-v2:0`, `nova-2-multimodal-embeddings-v1:0` |
| anthropic | `claude-3-haiku-20240307-v1:0`, `claude-sonnet-4-5-20250929-v1:0`, `claude-sonnet-5`, `claude-opus-4-8`, `claude-opus-5` |
| openai | `gpt-5.5`, `gpt-oss-20b`, `gpt-oss-20b-1:0`, `gpt-oss-120b`, `gpt-oss-120b-1:0` |
| nvidia | `nemotron-nano-9b-v2`, `nemotron-nano-12b-v2`, `nemotron-nano-3-30b`, `nemotron-super-3-120b` |
| meta | `llama3-8b-instruct-v1:0`, `llama3-70b-instruct-v1:0` |
| google | `gemma-4-e2b`, `gemma-4-26b-a4b`, `gemma-4-31b` |
| xai | `grok-4.3`, `grok-4.6` |
| pythia | `auto` |

The two embedding models are listed by the gateway but are not chat models.
Entitlements are a property of the key and persona, so re-run the check after
a key or persona change rather than relying on this table.

## Probe traffic (wave B2) {#probe-traffic-wave-b2}

Since Phase B wave B2 (`ml(llm): garak through Pythia core: catalog,
generator, probe child, scorecard` and `feat(llm): probe routes, admission,
worker, scorecard and findings`) the second Pythia consumer is the LLM
red-teaming track: garak 0.16.0 probes run against an LLM target through the
gateway and produce a probe scorecard with k/n denominators and no MRI. How
the traffic reaches Pythia, verified from `redsim/ml/llm/generator.py`,
`redsim/ml/llm/runner.py`, `redsim/ml/llm/probe_child.py`,
`redsim/services/ml_llm.py` and `redsim/workers/tasks/ml_llm.py`:

- **The target.** `POST /v1/models` with `source: endpoint`,
  `endpoint_kind: llm` (admin) names a canonical Pythia model id
  (`<vendor>/<model>` or `pythia/auto`; embedding ids refused), the
  `persona` the probe key is scoped to, a `guardrail_mode`
  (`permission_gate_only`, `content_filtered` or `unknown`) and a `bearer`
  `AuthProfile` holding the probe key (`probe_key_required` otherwise). The
  gateway URL is the body's `gateway_url` or the API's `PYTHIA_BASE_URL`, and
  it goes through the endpoint egress policy (`endpoint_url_invalid`,
  `endpoint_not_allowlisted`). The target row carries the host, the model
  id, the persona and the profile id, never the key.
- **The generator.** `PythiaGenerator(garak.generators.openai.OpenAICompatible)`
  posts to `{gateway}/v1/chat/completions` with `X-Pythia-Persona` as a
  default header, TLS from `redsim.llm.pythia.tls_verify` (the OS trust store
  on a laptop, recorded in the ledger as `tls_mode`), the OpenAI client at
  `max_retries=0` and a bounded retry loop in place of garak's uncapped
  backoff (8 total tries by default, exponential sleeps capped at 60 seconds).
  The worker reads `REDSIM_LLM_PROBE_TRANSPORT_MAX_TRIES` (1–12) and
  `REDSIM_LLM_PROBE_TRANSPORT_MAX_SLEEP_S` (0–600 seconds), validates them
  in the child spec and passes them as configuration, not child environment.
  A 429 honours `Retry-After` seconds or HTTP-date; missing or malformed values
  use exponential backoff. A requested wait beyond the cap terminates the run
  instead of retrying earlier than permitted. The ledger counts actual retries
  and `retry_after_honoured` waits. Exhausted tries abort; a 401 remains terminal.
  Other retryable transport failures use the same bounded loop.
  A 403 with `error.code=persona_denied` or an error message beginning
  `Blocked by` counts as `gateway_blocked` and returns an unevaluated output;
  the probe continues. Ordinary 401/403 responses remain terminal authentication
  failures. Each probe records `n_outputs_blocked`, and its detector denominator
  excludes blocked outputs. The response body is never copied to logs by this
  classification. The request uses and a body of exactly `model`, `messages`,
  `temperature`, `max_tokens`. The key is caller-supplied (an `api_key=` or a
  0600 `key_file=`), never read from the environment (`ENV_VAR` is `None`),
  never written into garak's `_config` (which garak dumps into
  `report.jsonl`) and never a class attribute. `assert_no_litellm` checks
  that the litellm garak installs never enters the generator's MRO. A
  `UsageLedger` records requests, statuses, retries, prompt and completion
  tokens, wall time and the model ids the gateway answered with (`pythia/auto`
  resolves per request, which the scorecard limitations say).
- **The worker.** `redsim.ml_llm_probe_run` (queue `default`, the only pool
  with Pythia egress) refuses before any gateway request when
  `REDSIM_DISABLE_LLM` is set, when the project or organisation LLM budget is
  spent (`enforce_budget_for_run`) or when the profile is gone; resolves the
  probe key at job pickup (`services.auth_profiles.resolve_auth_for_scan`);
  lists `GET /v1/models` on the gateway with that key and refuses
  (`model_not_entitled`, an `llm.probe.entitlement` `success=False` row) when
  the target model is absent, so a probe run never starts against a model the
  key cannot reach; then launches the garak child.
- **The child.** `python -m redsim.ml.llm.probe_child --spec <json>` in a
  fresh process with the plugin sandbox's interpreter allowlist, network on,
  `HOME` and `TMPDIR` inside a 0700 work directory, the TLS and proxy
  variables kept, `REDSIM_ENV_FILE` pinned to an absent file, and every
  `PYTHIA_*`, `AWS_*`, `KAGGLE*`, `OPENAI*`, `HF_TOKEN`, `HUGGING_FACE*`,
  `GOOGLE_`/`AZURE_`/`ANTHROPIC_` and other `REDSIM_*` name swept
  (`assert_child_env_minimal`). The key arrives in a 0600 file the child
  reads and deletes at once; the XDG and Hugging Face offline variables are
  pinned before garak imports; the run is configured through a `garak.yaml`
  (no deprecated argv flags); the hard prompt cap is enforced on every probe;
  the openai, httpx and httpcore loggers are raised to WARNING so `garak.log`
  carries no request headers; every written file is checked for the key and
  scrubbed if found (recorded, observed false in the tests). Wall clock
  `REDSIM_LLM_PROBE_TIMEOUT_S` (1500 s), CPU 1200 s, 4096 MB, 64 processes,
  process-group kill on timeout or cancel.
- **What is stored.** garak's `report.jsonl`, `hitlog.jsonl` and digest HTML,
  the usage ledger and the child's counts as `ml.llm.*` artifacts, never
  parsed for text and never stored when the key shape appears in them; the
  k/n scorecard; one `LLMUsage(task="ml.llm_probe")` row with `cost_cents`
  from the pricing table (`unpriced_model` otherwise); findings with a
  severity derived from the hit rate and labelled so; rule-text candidates
  only, no narrative for probe results.
- **Knobs.** `REDSIM_LLM_PROBE_MAX_PROMPTS_PER_PROBE` (64, the cap on a
  request's `max_prompts_per_probe`, default 16),
  `REDSIM_LLM_PROBE_MAX_RUNS_PER_PROJECT_PER_DAY` (10, `429` with
  `retry_after`), `REDSIM_LLM_PROBE_HF_DETECTORS` (truthy admits
  `detector_mode=hf` and the `redsim-extended` set, whose primary detectors
  are Hugging Face classifiers loaded from `REDSIM_LLM_PROBE_HF_CACHE`),
  `REDSIM_LLM_PROBE_TIMEOUT_S`, `REDSIM_DISABLE_LLM`.

No probe run against the live gateway has been recorded. The tests
(`tests/ml/test_llm_core.py` and `tests/ml/test_llm_routes.py`, 12 of them
`garak`-marked, and since wave B4 the e2e file `tests/e2e/test_ml_llm.py`,
four `garak`-marked cases that register an LLM target through
`POST /v1/models`, run `POST /v1/models/{id}/probes` as each role and drive
one real garak 0.16.0 run through the eager worker) drive real garak probes
through `PythiaGenerator` against `tests/ml/fake_openai_server.py`, a stdlib
OpenAI-compatible server on the loopback interface with a low-entropy fake
token, and assert the persona on every request, the minimal body, the token
sums, that the DAN prompt text appears only in garak's own `report.jsonl` and
nowhere else, that the child environment, the work directory and every stored
file are free of the key, that the k/n scorecard carries no MRI, grade or
subscore key, and that `/campaign` and `/compare` refuse the probe run. The
`garak offline` CI lane runs the `tests/ml` cases and the `e2e-python` lane
(which installs the `garak` extra since wave B4) the e2e file; since wave B4
the gate's garak step fails on an empty collection rather than passing. No
deploy image installs the `garak` extra: the transitive `openai` and `litellm`
clients garak pulls in exist only where the extra is installed, no
configuration path reaches them (no provider key variable exists,
`assert_no_litellm` checks the generator's MRO, the API tripwire blocks both
modules), and the only LLM credentials anywhere are the gateway key and the
probe key in an `AuthProfile` (D5; `docs/security/supply-chain.md`).

## Personas and guardrails

The hardening writer is text-only. It sends one system message and one user
message containing metrics, scorecard numbers, rule outputs, limitations and a
SHAP text summary, with no tools, no images and no structured output. The
`default` persona's guardrails are appropriate for that traffic and nothing in
the narrative prompt should trip them.

The probe traffic of wave B2 is different. Its probes are adversarial by
design: prompt injection, jailbreak attempts, toxicity elicitation. A persona
with content guardrails enabled would block or rewrite those probes and the
results would measure Pythia's filters rather than the target model. The
garak persona therefore needs the permission-gate-only guardrail default
(authentication, entitlement and metering stay on, content filtering off),
provisioned as a separate key and persona so the hardening writer's `default`
persona keeps its guardrails (owner default LLM-26, applied: the registration
requires the persona and a `guardrail_mode`, the scorecard limitations state
the mode, and a mode other than `permission_gate_only` adds the sentence that
the hit rates measure the gateway's content filters as much as the model).
The two keys are kept apart by construction: the narrative writer reads
`PYTHIA_API_KEY` and `PYTHIA_PERSONA` from the worker environment, the probe
runner reads its key from the target's `AuthProfile` and its persona from the
target row. Ask the Pythia operators for the permission-gate-only persona and
key before the first probe run against the live gateway. The probe material
is the set of corpora garak ships and loads itself (spec section 11.6; the
public data repository carries a copy with per-subset licences, owner
decision TESTS_DOCS-33): those prompts are untrusted data and may only be
sent to that permission-gate-only persona, never to the `default` persona and
never to a production system. HarmBench material is excluded (`fitd.FITD`,
owner default LLM-08), as are `dan.AutoDAN`, `grandma.GrandmaIntent` and the
uncapped corpus variants, each an excluded catalog row with its reason.
