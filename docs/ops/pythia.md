# Pythia access (LLM gateway)

Pythia (https://github.com/IntelliBridge/pythia) is IntelliBridge's
OpenAI-compatible agent gateway. Redsim never talks to a model provider
directly. It holds one Pythia `pk_…` key, and the gateway applies the
persona, guardrails, metering and audit before a request reaches a model.
Every LLM call in redsim goes through `redsim/llm/pythia.py` (decision D5 in
the product spec). There is no litellm and there are no provider keys anywhere
in the stack.

Today the only consumer is the optional hardening narrative: one plain,
non-streaming chat completion per recommendation, fed metrics and a SHAP text
summary. When Pythia is not configured the narrative is skipped, never faked,
and recommendations render from the rule layer alone.

## The four environment variables

| Variable | Required | Meaning |
| --- | --- | --- |
| `PYTHIA_BASE_URL` | yes | Gateway base URL. The client calls `{PYTHIA_BASE_URL}/v1/chat/completions` and `{PYTHIA_BASE_URL}/v1/models`. |
| `PYTHIA_API_KEY` | yes | The `pk_…` gateway key, sent as `Authorization: Bearer`. The only LLM secret redsim holds. |
| `PYTHIA_PERSONA` | no | Sent as `X-Pythia-Persona`. Selects the gateway-side persona (system prompt, guardrails, model entitlements). The key used on 2026-09-08 runs the `default` persona. |
| `REDSIM_ML_LLM_MODEL` | yes | Canonical model id, `<vendor>/<model>` or `pythia/auto`. `AEGIS_ML_LLM_MODEL` is still read as a deprecated alias (a `DeprecationWarning` is raised) and so is the older scaffold name `REDSIM_LLM_MODEL`. Rename to the canonical name when you touch a config. |

`PythiaSettings.from_env()` returns `None` unless the three required values
are present. Supporting variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PYTHIA_TIMEOUT_S` | `60` | Per-request timeout in seconds. |
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
is the only view that reaches provenance records and the connectivity check
prints at most the first three characters.

Keys are provisioned by the Pythia operators (GovCloud deployment) per team
and per persona. Ask for a key scoped to the `default` persona for the
hardening writer. See "Personas and guardrails" below for what Phase B needs.

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

Tests inject an `httpx.MockTransport`, which bypasses TLS entirely, so no
test depends on the machine's trust store.

Containers do not have a keychain. They receive the CA through
`deploy/certs/`: the `Dockerfile.api` and `Dockerfile.worker` builds copy any
`*.pem` or `*.crt` there into the system store, run `update-ca-certificates`,
and set `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` to
`/etc/ssl/certs/ca-certificates.crt`. Inside a container `truststore` reads
that same distro bundle, so both paths agree. See `deploy/certs/README.md`
for how to export the Zscaler root.

## How the compose services receive the variables

`deploy/docker-compose.yml` passes the four variables through to
`redsim-api` and to the worker pool (`redsim-worker`,
`redsim-worker-default`, `redsim-beat`, which share the `&worker-env`
anchor) with the `${VAR:-}` form:

```yaml
PYTHIA_BASE_URL: ${PYTHIA_BASE_URL:-}
PYTHIA_API_KEY: ${PYTHIA_API_KEY:-}
PYTHIA_PERSONA: ${PYTHIA_PERSONA:-}
REDSIM_ML_LLM_MODEL: ${REDSIM_ML_LLM_MODEL:-}
```

Compose interpolates these from the shell that runs it. When a variable is
not exported the container sees an empty string, `from_env()` returns
`None`, and the narrative stays off. Because `make up` runs
`docker compose -f deploy/docker-compose.yml` from the repo root, compose
looks for its own `.env` in `deploy/`, not at the repo root, so either
export the values first:

```bash
set -a; source .env; set +a
make up
```

or point compose at the file explicitly:

```bash
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
```

The worker anchor also sets `REDSIM_DISABLE_LLM: "1"`, which the evidence
pack reports as `llm_enabled: false`. The spec (section 23) asks for it to be
unset on `redsim-worker-default` when the narrative is on, so remove it there
(a `docker-compose.override.yml` is the least invasive way) before expecting
a narrative from a compose stack.

## Connectivity check

```bash
python -m redsim.llm.pythia_check              # reads ./.env
REDSIM_ENV_FILE=/path/to/.env python -m redsim.llm.pythia_check
python -m redsim.llm.pythia_check --skip-chat  # only GET /v1/models
python -m redsim.llm.pythia_check --model anthropic/claude-3-haiku-20240307-v1:0
```

The check prints which settings are present (the key as its three-character
prefix and length only), the TLS mode, `GET /v1/models` (count and ids), and
one short chat completion with the reply, latency and token usage. It exits
0 on success and 1 on any failure with a one-line reason. Any accidental echo
of the key in an error body is scrubbed before printing.

Observed on 2026-09-08 from a laptop behind Zscaler, persona `default`,
model `pythia/auto` (gateway URL redacted here, it is in `.env`):

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

## Personas and guardrails

The hardening writer is text-only. It sends one system message and one user
message containing metrics, scorecard numbers, rule outputs, limitations and
a SHAP text summary, with no tools, no images and no structured output. The
`default` persona's guardrails are appropriate for that traffic and nothing
in the narrative prompt should trip them.

Phase B (LLM red-teaming with garak through Pythia) is different. Its probes
are adversarial by design: prompt injection, jailbreak attempts, toxicity
elicitation. A persona with content guardrails enabled would block or rewrite
those probes and the results would measure Pythia's filters rather than the
target model. The garak persona therefore needs the permission-gate-only
guardrail default (authentication, entitlement and metering stay on, content
filtering off), provisioned as a separate key and persona so the hardening
writer's `default` persona keeps its guardrails. Ask the Pythia operators for
that persona when Phase B starts, and keep the two keys apart in `.env`
(`PYTHIA_PERSONA` selects which one a process uses). The probe material
for that track is the malicious-gpt jailbreak corpus recorded in spec
section 11.6 (200 prompts, licence unresolved, decision D008): its prompts
are untrusted data and may only be sent to that permission-gate-only
persona, never to the `default` persona and never to a production system.
