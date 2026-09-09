# Endpoint predict contract (`endpoint-v1`)

The contract a black-box inference endpoint has to speak before redsim can
register it as an `ml_model_endpoint` target and run query-only attacks against
it. The source of truth is the pure-Python module
`redsim/ml/targets/endpoint_contract.py`: its `contract_summary()` returns the
JSON block this page is written from. Nothing on this page is stubbed: every
rule below is enforced by code on `main` and tested
(`tests/ml/test_endpoint_contract.py`, 90 cases, and
`tests/ml/test_endpoint_egress.py`, 125 cases, both on the torch-less lane;
the registration and campaign paths in `tests/ml/test_endpoint_routes.py`,
`tests/ml/test_admission_phase_b.py` and `tests/ml/test_tasks_phase_b.py`
since wave B2; the end-to-end file `tests/e2e/test_ml_endpoint.py` since
wave B4). Since wave B4 `GET /v1/ml/capabilities` carries the summary block
under `endpoint_connector.contract`, read from `contract_summary()`.

## Status

| Piece | Where | State |
|---|---|---|
| Request and response contract, `EndpointRegistration`, `encode_request`, `validate_response_bytes`, `contract_summary()` | `redsim/ml/targets/endpoint_contract.py` | on `main` (wave B0, `622d741`, register ENDPOINT-02 code side) |
| Egress policy: URL rules, allowlist, private-address refusal, resolve-once session pin, `EgressPolicy` | `redsim/ml/endpoint_egress.py` | on `main` (wave B0, `622d741`, ENDPOINT-07) |
| `EndpointTarget` (the `Target` protocol over ART `BlackBoxClassifier`), the worker-parent `PredictBroker` (the only outbound HTTP), the sandbox socket plumbing, `probe_endpoint_sandboxed` | `redsim/ml/targets/endpoint.py`, `redsim/ml/endpoint_broker.py`, `redsim/ml/sandbox.py`, `redsim/ml/sandbox_worker.py` | on `main` (wave B1, `ml: EndpointTarget, worker-parent PredictBroker, sandbox socket plumbing`, integrated by `1439f92`, which wired the broker onto the `endpoint-v1` encode and validate helpers; ENDPOINT-04, -05; -08 and -09 library halves) |
| `MLModelManifest.endpoint: EndpointSpec` and `format: "endpoint"` | `redsim/ml/schema.py` | on `main` (wave B0, `934838e`, ENDPOINT-03) |
| The six HTTP codes (`endpoint_url_invalid`, `endpoint_not_allowlisted`, `egress_refused`, `endpoint_schema_mismatch`, `auth_profile_kind_unsupported`, `endpoint_unreachable`) | `redsim/api/errors.py`, spec 17.3 addendum | on `main` (wave B0, `3cd3362`, ENDPOINT-06) |
| `auth_profile_required` (422), `auth_profile_in_use` (409), `query_budget_exceeded` (429) | `redsim/api/errors.py`, spec 17.3 second addendum | landed (wave B2, `api: add thirteen Phase B error codes; dataset.export to remediator`). Since wave B4 `DELETE /v1/auth-profiles/{id}` answers `409 auth_profile_in_use` with `target_ids` while a live endpoint or LLM target references the profile, after a `success=False` `auth_profile.delete` row (ENDPOINT-18) |
| `attestation_required` (422), `endpoint_auth_failed` (502) | `redsim/api/errors.py`, spec 17.3 third addendum | landed (wave B4, `fix-api-services`): a registration without `evaluation_instance_attestation: true` is refused with its own code (ENDPOINT-31, `license_required` was the stand-in), and a synchronous call answered `401` or `403` to the credential has its code; inside validate or a campaign that condition stays the target's `refusal_reason: load_failed` |
| `POST /v1/models` with `source: "endpoint"`, the `model.register` audit row, validate through the broker, the `ml_model_endpoint` projections, delete | `redsim/api/v1/models.py`, `redsim/services/ml_models.py`, `redsim/workers/tasks/ml_model.py` | **landed** (wave B2, `feat(ml): endpoint registration, validate via broker, projections`, `endpoint-admission` track: ENDPOINT-01, -10, -11, -15, -17 to -20, -27, -29; -30's typed transport-failure mapping in the campaign task is still open). Gate `target.manage` (admin). Route table in [the API reference](v1.md#register-an-endpoint) |
| Campaign admission for endpoint targets (white-box attacks refused with `attack_requires_gradients`, the query-budget estimate, `POST /v1/models/{id}/attacks` on an `ml_model_endpoint` target) and the worker's broker lifecycle | `redsim/services/ml_campaigns.py`, `redsim/workers/tasks/ml_campaign.py` | **landed** (wave B2, `admission(ml): modality table, norm checks, endpoint budget, project scoring` and `worker: endpoint broker lifecycle, derived-target registration, retests (Phase B B2)`): `429 query_budget_exceeded` at admission, the credential resolved at run time in the worker parent, the broker tally on the record and the audit rows |
| End-to-end evidence through the tiny server | `tests/e2e/test_ml_endpoint.py` | landed (wave B4, `e2e-endpoint-llm`, `e2e(endpoint,llm): endpoint connector and garak LLM probe evidence on the shared harness`): registration through `POST /v1/models` with a bearer `AuthProfile`, RBAC, the `endpoint_url_invalid` and `endpoint_not_allowlisted` refusals, `409 auth_profile_in_use` on the profile while the target is live, the audited delete. On the tree at the B4 push its three campaign-path cases (validation to `available`, the HopSkipJump campaign through the broker, `422 attack_requires_gradients`) fail with one attribution: `EndpointTarget.load` (`redsim/ml/targets/endpoint.py:228`) sends the 8-row probe as unscaled uint8 values, which the `float32_nchw` rule of this contract refuses, so no endpoint reaches `available` through the tiny server (README open items). The B2 unit evidence is `tests/ml/test_endpoint_routes.py` |

What B2 built, verified from the tree: the route gates on `target.manage`
before any field is read, validates the body with `EndpointRegistration`,
runs `check_url(config.target_allowlist)` (the static egress check), resolves
the `AuthProfile` without decrypting it, binds the dataset, writes the
`model.register` audit row (`allowlist_check` `pass` or `fail`, the refusal
code and `detail()` on failure, never the URL's userinfo or query, never the
secret), stores a `Target` of kind `ml_model_endpoint` whose manifest has
`format: "endpoint"`, `gradients: false`, `sha256 = descriptor_sha256()` and
`status: validating`, commits the `ml.ingest` `Run` and `model.validate`
`Job`, and enqueues `redsim.ml_model_validate`, whose endpoint variant resolves
the credential at pickup and hands it only to `probe_endpoint_sandboxed`: the
child builds an `EndpointTarget`, `load()` sends one seeded 8-row stratified
batch through the broker, checks the contract and records latency, status,
`output_kind` and the response fingerprint. The target then moves to
`available` or `refused` with `refusal_reason` exactly as an upload does
(`shape_mismatch` for a contract violation, `load_failed` for unreachable,
auth, egress or budget failures), the typed class and code recorded beside
it under `validation.probe`.

## Registration (what `POST /v1/models` with `source: "endpoint"` validates)

`EndpointRegistration` (`extra="forbid"`):

| Field | Rule |
|---|---|
| `url` | 1 to 2048 characters, then the egress URL rules below |
| `auth_profile_id` | the `AuthProfile` whose secret the worker parent sends (`auth_profile_required` when absent). Only `bearer` and `header` kinds can be sent to an inference endpoint (`auth_profile_kind_unsupported` otherwise; a `header` profile needs `config.header_name`); a profile of another project or an unknown id is `404 not_found`. The secret never reaches the API response, the manifest, the child or the audit row |
| `modality` | `image` or `tabular` (text, detection and LLM endpoints are not part of this contract) |
| `dataset_id`, `dataset_split` (default `test`) | the bundled evaluation split the campaign samples from, bound exactly as an upload is bound |
| `name`, `license_statement` | non-blank (spec 11.1: no license statement, no registration) |
| `evaluation_instance_attestation` | the literal `true`, required, no default: the caller attests that the endpoint is an evaluation instance and not a production or mission system |
| `input_shape` | 3 dimensions for `image` (`[C, H, W]`), 1 for `tabular` |
| `class_names` and/or `n_classes` | consistent, unique, at least 2 |
| `batch_rows` | 1 to 1024, default 32 (list-encoded images are large) |
| `timeout_s` | (0, 60], default 30 |
| `input_format` | derived from the modality (`float32_nchw` for image, `tabular_features` for tabular), refused when it disagrees |
| `contract_version` | the literal `endpoint-v1` |

`descriptor()` / `descriptor_sha256()` give the manifest its `sha256`: the
digest of the credential-free descriptor (`url_host`, scheme,
`auth_profile_id`, contract, modality, dataset binding, `input_shape`,
class names). There are no weights to hash.

## Request

`POST <url>` with `Content-Type: application/json` and one of the two auth
headers (`Authorization: Bearer <secret>` or `<header_name>: <secret>`,
from the `AuthProfile`):

```json
{
  "contract": "endpoint-v1",
  "input_format": "float32_nchw",
  "inputs": [[[[0.0, 0.5], [1.0, 0.25]]]]
}
```

- `inputs` is `[n, *input_shape]` as nested lists of finite numbers. Images
  are raw `[0, 1]` NCHW pixels, tabular rows are the declared feature vector.
  Preprocessing is the endpoint's job.
- `n` is at most `batch_rows` (never above 1024).
- Any other key is refused (`extra="forbid"`). There is no `encoding` key.
- `encode_request(x, input_format=, input_shape=)` builds the body from a
  numpy array or nested lists and refuses ragged, empty, boolean or non-finite
  leaves, images outside `[0, 1]`, the wrong rank, or a shape that disagrees
  with the registration. Request-side violations are `ValueError` (the
  caller's bug), never a contract error attributed to the endpoint.

## Response

`200` with `Content-Type: application/json` and exactly one of
`probabilities` or `logits`:

```json
{ "probabilities": [[0.1, 0.9]], "model_id": "optional", "latency_ms": 12.5 }
```

- `probabilities`: `[n, n_classes]` finite values in `[0, 1]`, each row summing
  to 1 within `0.001`.
- `logits`: the alternative; softmax is applied client-side and `output_kind`
  is recorded on the target's manifest and every measurement.
- `model_id` and `latency_ms` are optional. Nothing else is accepted.

Every violation is `EndpointSchemaMismatch` (`code`
`endpoint_schema_mismatch`, with `field` and `reason`): a status other than
200, a redirect, a non-JSON body, both or neither of the two keys, an extra
key, the wrong row count, a row with the wrong number of classes, a NaN or
infinity (as a value or as a JSON token), a row summing outside the tolerance,
a string or boolean where a number belongs (`strict=True`, nothing is
coerced), or a body over 16 MiB. Inside validate or a campaign the same
condition becomes the target's `refusal_reason: shape_mismatch` or the job's
failure, never a fabricated row.

## Limits

| Limit | Value |
|---|---|
| `batch_rows_max` | 1024 |
| `batch_rows_default` | 32 |
| `timeout_s_max` | 60.0 |
| `timeout_s_default` | 30.0 |
| `response_bytes_max` | 16777216 (16 MiB) |
| `row_sum_tolerance` | 0.001 |

Runtime limits on the worker parent (`EndpointLimits.from_env(modality)`,
wave B1, overridable per admission): `REDSIM_ML_ENDPOINT_RPS` (10),
`REDSIM_ML_ENDPOINT_BATCH_ROWS` (32 for image, 256 for tabular, capped at
1024), `REDSIM_ML_ENDPOINT_TIMEOUT_S` (30), `REDSIM_ML_ENDPOINT_MAX_ROWS`
(500000) and `REDSIM_ML_ENDPOINT_MAX_REQUESTS` (20000). The budget is checked
before every request: a campaign that reaches it stops with
`QueryBudgetExceeded` (`query_budget_exceeded`) and no invented rows. Since
wave B2 the same limits bound the admission estimate: `POST /v1/models/{id}/attacks`
on an endpoint target sums the clean and control rows, HopSkipJump
`n * (init_size + max_iter * (max_eval + 1))` or ZOO
`n * max_iter * binary_search_steps * 2 * nb_parallel` from the resolved
parameters (times the grid size for attacks that take eps) and the kernel or
partition explain bound at `EXPLAIN_QUERY_CAPS`, compares the worst case with
`max_rows`, and refuses with `429 query_budget_exceeded` carrying `estimate`
and `cap` before any row is written. `explain_k` is capped at 8 on endpoint
targets with the requested value recorded.

## Egress policy (`redsim/ml/endpoint_egress.py`)

Two moments, both in the worker parent and never in the sandbox child:

1. **Registration and `model.load`**: `check_registration_url(url, allowlist)`
   returns a `ParsedEndpoint` or refuses. `https` and `http` only, no
   userinfo, query, fragment, whitespace, control or non-ASCII characters,
   no URL over 2048 characters, no malformed host (trailing dot, numeric
   last label, underscores, IPv6 zone ids), port 1 to 65535. Otherwise
   `EndpointUrlInvalid` (`endpoint_url_invalid`). The host must match the
   project's `target_allowlist` by exact host, literal IP or CIDR (the same
   semantics as `redsim.safety.is_target_allowed`, parity-tested), otherwise
   `EndpointNotAllowlisted` (`endpoint_not_allowlisted`). A literal loopback,
   private or link-local address that the allowlist does not name as that
   literal or as a private CIDR, and any multicast, reserved or unspecified
   address, is `EgressRefused` (`egress_refused`). Plaintext `http` is allowed
   only to loopback (`127/8`, `::1`, `localhost`, `host.docker.internal`) or
   to an allowlisted private or link-local literal; `0.0.0.0/0` admits public
   hosts but exempts no private address.
2. **Every request**: `check_request_host(host, allowlist, session=)`
   resolves the host once with `getaddrinfo`, classifies every answer
   (IPv4-mapped, 6to4 and Teredo addresses by their embedded IPv4), refuses
   any non-public answer the allowlist does not exempt (a public hostname
   that resolves to loopback is refused even with the default allowlist),
   and pins the first permitted address for the `EgressSession`.
   `recheck=True` re-resolves and refuses a set that dropped the pin
   (`dns_rebinding`). `EgressPolicy(allowlist)` wraps both moments.

Every refusal message and `detail()` carry the code, the rule, the host and
the address only, never the URL's userinfo, query or fragment (tested).

The broker (wave B1) adds its own floor on top: scheme, userinfo, query and
fragment checks, the allowlist, plaintext only to loopback or private literal
hosts, `follow_redirects=False`, TLS verified through the OS trust store or a
CA bundle (`redsim.llm.pythia.tls_verify`, never `verify=False`), proxy
variables honoured only for non-loopback hosts. Known limitation, recorded in
`BrokerStats.egress_notes` and here: the broker does not pin the connection
to the resolved IP, so a DNS-rebinding window between resolution and connect
remains (the ENDPOINT-07 risk note). The httpx pinned-connect transport is
follow-up work.

## Runtime path (wave B1 library, wave B2 worker wiring)

```
sandbox child (no network, no credential)      worker parent (the only outbound HTTP)
  EndpointTarget.predict_proba(x)
    -> SocketPredictTransport                     PredictBroker on <work_dir>/predict.sock (0600)
       length-prefixed JSON frame  ---------->     EgressPolicy check, TokenBucket, budget check
                                                   HttpPredictTransport: encode_request, POST, 2 bounded
                                                   retries on 5xx or transport errors, validate_response_bytes
       typed error frame or rows   <----------     BrokerStats (rows, requests, bytes, latency, fingerprint)
```

- The child receives a credential-free `target_endpoint` block in
  `request.json` (`url_host` and scheme, the socket path, the resolved
  limits, the dataset binding). The URL, the secret, the allowlist and the
  auth profile travel only as separate parent-side arguments of
  `run_campaign_sandboxed(..., target_endpoint=, endpoint_auth=,
  endpoint_allowlist=)` and `probe_endpoint_sandboxed(...)`; the child
  environment allowlist is unchanged. Since wave B2 the worker tasks build
  that block (`services.ml_models.endpoint_request_block`, the URL read from
  `Target.value`) and resolve the credential from the vault at job pickup
  (`services.auth_profiles.resolve_auth_for_scan`), so the secret exists in
  the worker parent for the duration of one job and is never written to
  `Job.detail`, a log or an audit row; the broker's tally by purpose, budget
  and fingerprint is copied onto the run record and the `attack.execute`,
  `campaign.score` and `job.complete` rows.
- The broker starts after the work directory is cleared and before the child
  is spawned (so an egress refusal is raised before any child exists, with a
  partial record persisted in campaign mode), stops right after the child
  exits or is killed, and attaches its final counters to
  `Provenance.model_manifest["endpoint_broker"]` (or `manifest["endpoint_broker"]`
  on a probe).
- Query counts are recorded twice and never summed: the broker's tally by
  purpose (`probe`, `attack`, `control`, `explain`) and the child's own
  client-side counters (`EndpointTarget.queries()`).
- The response fingerprint (sha256 of the first response's shape, argmax
  ordering and probabilities rounded to 4 places) is labelled "remote model
  identity, not a weights digest".
- `EndpointTarget.info()` carries `metadata["access"] = "black-box-endpoint"`
  and `gradients: false`, so white-box attacks are refused at admission with
  `attack_requires_gradients`; `hopskipjump` and `zoo` run through ART's
  `BlackBoxClassifier`, and the tabular explainer falls back to
  `KernelExplainer` under `EXPLAIN_QUERY_CAPS` (background 20 rows, `nsamples`
  200, `explain_k` 8; `redsim/ml/explain/base.py`).

## Manifest block

`MLModelManifest.endpoint` is `EndpointSpec(url_host, auth_profile_id,
contract_version, input_shape, batch_rows, timeout_s)`: `url_host` is
`host[:port]` only (no scheme, path, query or userinfo), there is no
credential and no URL string. `format: "endpoint"` requires the block, the
block requires `format: "endpoint"` and `gradients: false`, `size_bytes` is 0
and `sha256` is the descriptor digest. `EndpointTarget.manifest()` writes
exactly those six keys under `endpoint` and its probe, fingerprint, query and
broker records beside it (`endpoint_probe`, `endpoint_fingerprint`,
`endpoint_queries`, `endpoint_broker`, `endpoint_limits`).

## Error codes

| Code | Kind | Raised by |
|---|---|---|
| `endpoint_url_invalid` | HTTP 422 (`field: url`) | the URL rules above at registration (wave B2); an empty registration body fails here first |
| `auth_profile_required` | HTTP 422 | a registration with no `auth_profile_id` (wave B2, second addendum) |
| `endpoint_not_allowlisted` | HTTP 403 | host outside `target_allowlist` at registration (wave B2), after the `success=False` audit row with `allowlist_check: fail`, `target` the URL |
| `egress_refused` | HTTP 403 | private, loopback, link-local, multicast or reserved address the allowlist does not exempt; inside a campaign the same refusal is raised before the child is spawned |
| `endpoint_schema_mismatch` | HTTP 422 on a synchronous call made on the caller's behalf (none exists yet); `refusal_reason: shape_mismatch` inside validate or a campaign | the response rules above |
| `auth_profile_kind_unsupported` | HTTP 422 | an `AuthProfile` kind other than `bearer` or `header`, or `header` without a header name |
| `endpoint_unreachable` | HTTP 502 on a synchronous call (none exists yet); `refusal_reason: load_failed` inside validate | no answer within `timeout_s` after the bounded retries |
| `endpoint_auth_failed` | job and target state only (`refusal_reason: load_failed`) | 401 or 403 from the endpoint |
| `query_budget_exceeded` | HTTP 429 (`estimate`, `cap`) at campaign admission (wave B2, second addendum); job state only when the broker reaches `max_rows` or `max_requests` at run time | the admission estimate; the broker |
| `auth_profile_in_use` | HTTP 409 (`target_ids`) | code on the tree since wave B2; `DELETE /v1/auth-profiles/{id}` does not emit it yet |

The typed classes are `redsim.ml.errors.EndpointError`, `EndpointUnreachable`,
`EndpointAuthFailed`, `QueryBudgetExceeded`, the re-exported
`EndpointSchemaMismatch` (from the contract module) and `EgressRefused`,
`EndpointUrlInvalid`, `EndpointNotAllowlisted` (from the egress module), all
`MLError` subclasses with stable `code`s, rebuilt by name from the child's
envelope and the broker's error frames. Inside validate the worker maps them
onto the frozen `RefusalReason` vocabulary (`EndpointSchemaMismatch` to
`shape_mismatch`; `EndpointUnreachable`, `EndpointAuthFailed`, the egress
classes and `QueryBudgetExceeded` to `load_failed`) and keeps the class, code
and message under `validation.probe`; widening the vocabulary (ENDPOINT-28)
is deferred as the register says. `endpoint_auth_failed` still has no HTTP
row, by design: it is only ever a target or job state.

## Recorded divergences

- The contract version is the brief's `endpoint-v1`. The register's working
  name `redsim-predict-proba/1` is superseded and a request carrying it is
  refused as a wrong literal; the spec 17.3 addendum row for
  `endpoint_schema_mismatch` still reads `redsim-predict-proba/1` (the B2
  `codes-b2` track added the second addendum table and did not touch that
  row), so it is still to be corrected.
- The request body has no `encoding` key; `input_format` names the layout.
- Target-ownership verification by DNS TXT (spec 21.7) is not built for
  endpoint targets: the owner default of plan 12 section 2 (ENDPOINT-26) is
  the egress allowlist plus admin-only registration plus the audited
  attestation, applied by wave B2 (`Target.verified` stays `false`, option a).
- `query_budget_exceeded` is a `429` (the register's ENDPOINT-06 wrote 422):
  a budget refusal that sits with `daily_budget_exceeded`.
- `attestation_required` has no 17.3 row: a registration without
  `evaluation_instance_attestation: true` is refused with `license_required`
  and `field: evaluation_instance_attestation` until the row lands.

## Trying it

`tests/ml/tiny_endpoint_server.py` is a stdlib `http.server` over the
`TinyTarget` test double behind `POST /predict` with bearer or header auth and
misbehaviour switches (`n_columns`, `fail_status`, `logits`, `fail_first`).
`tests/ml/test_endpoint_target.py` runs a HopSkipJump campaign against it
through the real sandbox child and the broker socket, and asserts that the
child environment holds no token, that `request.json` holds only the socket
path, that the socket lived under the 0700 job directory with mode 0600 and is
gone afterwards, and that the server saw the bearer on every request. Since
wave B2 `tests/ml/test_endpoint_routes.py` drives the registration route,
the projections and the validate task against the same server (the URL, the
token and the ciphertext scanned for in every response) and
`tests/ml/test_admission_phase_b.py` the campaign admission with its query
budget.
