"""Worker-parent predict broker for black-box endpoint targets (spec 9.1 rules 3 and 4, 9.4, 21.7).

This module is the ONLY place in the worker that makes an outbound HTTP request to a
registered inference endpoint. The sandbox child never gets network configuration
(spec 20.3) and never holds the AuthProfile secret; it reaches the endpoint through a
unix-domain socket that :class:`PredictBroker` serves from inside the 0700 per-job
work directory (``redsim.ml.sandbox`` starts and stops it around the child). Unix
sockets are IPC, not network, so the child's no-network posture holds.

Components:

* :class:`EndpointLimits` -- rate limit and per-job query budget, read from
  ``REDSIM_ML_ENDPOINT_*`` (ENDPOINT-08) and recorded in provenance.
* :class:`HttpPredictTransport` -- one ``httpx.Client`` with ``verify`` from
  :func:`redsim.llm.pythia.tls_verify` (truststore / CA bundle, never ``verify=False``),
  redirects disabled, the credential supplied by the caller and held in memory only,
  request and response per the ``endpoint-v1`` contract
  (``redsim.ml.targets.endpoint_contract``: :func:`~redsim.ml.targets.endpoint_contract.encode_request`
  out, :func:`~redsim.ml.targets.endpoint_contract.parse_response` back, nothing coerced),
  batch-row and timeout caps, a token-bucket rate limit, a rows/requests/bytes counter per
  purpose (attack, control, explain, probe), bounded retries on 5xx / timeouts, and typed
  failures.
* :class:`PredictBroker` -- a ``ThreadingUnixStreamServer`` that turns length-prefixed
  JSON frames from the child (``redsim.ml.targets.endpoint.SocketPredictTransport``)
  into transport calls and answers with probabilities or a typed error frame.
* The typed failures, all resolvable by name through ``redsim.ml.errors``:
  :class:`~redsim.ml.errors.EndpointUnreachable`, :class:`~redsim.ml.errors.EndpointAuthFailed`,
  :class:`~redsim.ml.errors.QueryBudgetExceeded` (transport), the egress policy's
  :class:`~redsim.ml.endpoint_egress.EgressRefused` family and the contract's
  :class:`~redsim.ml.targets.endpoint_contract.EndpointSchemaMismatch` (spec 6.3: a transport
  failure is never a model outcome; the job fails with the evidence gathered so far, no row is
  ever invented).

Egress (ENDPOINT-07, ``redsim.ml.endpoint_egress.EgressPolicy``): the URL is checked before
any request leaves the worker (``check_endpoint``: scheme, no userinfo / query / fragment, host
on the target allowlist, plaintext only for a loopback or allowlisted private literal, every
resolved address classified) and the first permitted address is pinned for the job. Every
request then connects to the pinned address with the original hostname as TLS SNI and
``Host`` header, redirects disabled, after ``EgressSession.verify_pin`` has confirmed that the
address about to be dialled is the pin; a later attempt to connect anywhere else is refused
as DNS rebinding.

The response fingerprint (sha256 of the first response's shape, class ordering and
rounded probabilities) is labelled *remote model identity*: it identifies what the
endpoint answered at that moment, not a weights digest, and a changed fingerprint on a
later job means the remote model may have changed (ENDPOINT-27 re-checks it).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import socket
import socketserver
import struct
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from pydantic import ValidationError

from redsim.ml.endpoint_egress import (
    DEFAULT_PORTS,
    EgressPolicy,
    EgressRefused,
    EndpointNotAllowlisted,
    EndpointUrlInvalid,
    ParsedEndpoint,
    Resolver,
)
from redsim.ml.errors import (
    EndpointAuthFailed,
    EndpointError,
    EndpointUnreachable,
    MLError,
    QueryBudgetExceeded,
    error_detail,
    rebuild_error,
)
from redsim.ml.targets.endpoint_contract import (
    CONTRACT_VERSION,
    INPUT_FORMAT_RANK,
    MAX_BATCH_ROWS,
    MAX_RESPONSE_BYTES,
    MODALITY_INPUT_FORMAT,
    EndpointSchemaMismatch,
    InputFormat,
    ValidatedPrediction,
    encode_request,
    parse_response,
    validate_response_bytes,
)
from redsim.safety import is_loopback

if TYPE_CHECKING:
    import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Typed failures (spec 6.3, 10.6): infrastructure states, never model outcomes.
# ---------------------------------------------------------------------------

#: Every class a broker frame or a sandbox envelope may name for an endpoint failure, by name.
ENDPOINT_ERRORS: dict[str, type[MLError]] = {
    cls.__name__: cls
    for cls in (EndpointError, EndpointUnreachable, EndpointAuthFailed, QueryBudgetExceeded,
                EgressRefused, EndpointUrlInvalid, EndpointNotAllowlisted, EndpointSchemaMismatch)
}
#: ``isinstance`` tuple of the same set (the egress and contract classes are not ``EndpointError``s).
ENDPOINT_FAILURE_TYPES: tuple[type[MLError], ...] = (EndpointError, EgressRefused, EndpointSchemaMismatch)


def endpoint_error_class(name: str) -> type[MLError] | None:
    """The typed class for an ``error_class`` name travelling in an envelope or a socket frame."""
    return ENDPOINT_ERRORS.get(name)


# ---------------------------------------------------------------------------
# The predict contract (endpoint-v1) lives in ``redsim.ml.targets.endpoint_contract``.
# ---------------------------------------------------------------------------

#: Cap on a predict response (contract: anything larger is a violation, never read further).
RESPONSE_MAX_BYTES = MAX_RESPONSE_BYTES
#: Cap on one socket frame between the child and the broker.
FRAME_MAX_BYTES = 64 * 1024 * 1024
#: Hard ceiling on rows per request whatever the environment says (ENDPOINT-08; the contract's cap).
BATCH_ROWS_MAX = MAX_BATCH_ROWS

#: Row rank -> ``input_format`` for a transport built without a modality (the contract's table, inverted).
_RANK_INPUT_FORMAT: dict[int, InputFormat] = {rank: cast("InputFormat", fmt)
                                              for fmt, rank in INPUT_FORMAT_RANK.items()}


def _row_rank(row: Any) -> int:
    rank = 0
    node = row
    while isinstance(node, (list, tuple)) and node:
        rank += 1
        node = node[0]
    return rank


def input_format_for(modality: str | None, inputs: list[Any] | None = None) -> InputFormat:
    """The contract ``input_format`` for ``modality`` (``image`` / ``tabular``), else from the rows' rank.

    Raises :class:`EndpointSchemaMismatch` (field ``inputs``) when neither settles it.
    """
    if modality is not None:
        fmt = MODALITY_INPUT_FORMAT.get(str(modality))
        if fmt is None:
            raise EndpointSchemaMismatch(f"no endpoint-v1 input format serves modality {modality!r}", field="inputs")
        return cast("InputFormat", fmt)
    if inputs:
        inferred = _RANK_INPUT_FORMAT.get(_row_rank(inputs[0]))
        if inferred is not None:
            return inferred
    raise EndpointSchemaMismatch("rows are neither [C][H][W] images nor flat feature vectors", field="inputs")


def _refuse_constant(name: str) -> None:
    raise ValueError(f"non-finite JSON constant {name}")


def _first_row_width(body: Any) -> int | None:
    if isinstance(body, dict):
        for key in ("probabilities", "logits"):
            rows = body.get(key)
            if isinstance(rows, list) and rows and isinstance(rows[0], list) and rows[0]:
                return len(rows[0])
    return None


def decode_response(raw: bytes, *, n: int, n_classes: int | None) -> ValidatedPrediction:
    """The contract check of a raw response for ``n`` requested rows.

    With ``n_classes`` known this is :func:`~redsim.ml.targets.endpoint_contract.validate_response_bytes`.
    Without it (a broker built before the class list is known) the column count of the first row
    is the width every row must have; the caller adopts it for the rest of the job.
    """
    if n_classes is not None:
        return validate_response_bytes(raw, n=n, n_classes=n_classes)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise EndpointSchemaMismatch(f"response is {len(raw)} bytes; the cap is {MAX_RESPONSE_BYTES}", field="body")
    try:
        body = json.loads(raw.decode("utf-8"), parse_constant=_refuse_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise EndpointSchemaMismatch(f"response is not valid JSON: {exc}", field="body") from None
    return parse_response(body, n=n, n_classes=_first_row_width(body) or 1, raw_size=len(raw))


def response_fingerprint(rows: list[list[float]], output_kind: str) -> str:
    """sha256 over the first response's shape, class ordering and probabilities rounded to 4 places."""
    payload = {
        "contract": CONTRACT_VERSION,
        "output_kind": output_kind,
        "shape": [len(rows), len(rows[0]) if rows else 0],
        "argmax": [max(range(len(r)), key=r.__getitem__) for r in rows],
        "rows": [[round(v, 4) for v in r] for r in rows],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


FINGERPRINT_LABEL = ("remote model identity: sha256 of the first response (shape, class ordering, probabilities "
                     "rounded to 4 places); not a weights digest, and a different value on a later job means the "
                     "remote model may have changed")


# ---------------------------------------------------------------------------
# Limits (ENDPOINT-08)
# ---------------------------------------------------------------------------

ENV_RPS = "REDSIM_ML_ENDPOINT_RPS"
ENV_BATCH_ROWS = "REDSIM_ML_ENDPOINT_BATCH_ROWS"
ENV_TIMEOUT_S = "REDSIM_ML_ENDPOINT_TIMEOUT_S"
ENV_MAX_ROWS = "REDSIM_ML_ENDPOINT_MAX_ROWS"
ENV_MAX_REQUESTS = "REDSIM_ML_ENDPOINT_MAX_REQUESTS"

DEFAULT_BATCH_ROWS: dict[str, int] = {"image": 32, "tabular": 256}


def _float_env(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _int_env(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class EndpointLimits:
    """Outbound rate limit and per-job query budget of one endpoint job, recorded in provenance."""

    rps: float = 10.0
    batch_rows: int = 32
    timeout_s: float = 30.0
    max_rows: int = 500_000
    max_requests: int = 20_000

    @classmethod
    def from_env(cls, modality: str = "image", environ: Mapping[str, str] | None = None) -> EndpointLimits:
        """Read ``REDSIM_ML_ENDPOINT_*``; malformed or non-positive values keep the defaults."""
        env = os.environ if environ is None else environ
        base = cls(batch_rows=DEFAULT_BATCH_ROWS.get(modality, 32))
        return cls(
            rps=_float_env(env, ENV_RPS, base.rps),
            batch_rows=min(_int_env(env, ENV_BATCH_ROWS, base.batch_rows), BATCH_ROWS_MAX),
            timeout_s=_float_env(env, ENV_TIMEOUT_S, base.timeout_s),
            max_rows=_int_env(env, ENV_MAX_ROWS, base.max_rows),
            max_requests=_int_env(env, ENV_MAX_REQUESTS, base.max_requests),
        )

    def merged(self, overrides: Mapping[str, Any] | None) -> EndpointLimits:
        """A copy with the positive numeric ``overrides`` applied (admission-computed caps); others ignored."""
        if not overrides:
            return self
        values: dict[str, Any] = {
            "rps": self.rps, "batch_rows": self.batch_rows, "timeout_s": self.timeout_s,
            "max_rows": self.max_rows, "max_requests": self.max_requests,
        }
        for key in values:
            raw = overrides.get(key)
            if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw <= 0:
                continue
            values[key] = float(raw) if key in {"rps", "timeout_s"} else int(raw)
        values["batch_rows"] = min(int(values["batch_rows"]), BATCH_ROWS_MAX)
        return EndpointLimits(**values)

    def as_dict(self) -> dict[str, float | int]:
        return {"rps": self.rps, "batch_rows": self.batch_rows, "timeout_s": self.timeout_s,
                "max_rows": self.max_rows, "max_requests": self.max_requests}


class TokenBucket:
    """Requests-per-second limiter: ``acquire()`` blocks until a token is available and returns the wait."""

    def __init__(self, rate: float, capacity: float | None = None, *,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else max(1.0, rate))
        self._tokens = self.capacity
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
        self._last = now

    def acquire(self) -> float:
        waited = 0.0
        with self._lock:
            self._refill()
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self.rate
                self._sleep(wait)
                waited = wait
                self._refill()
            self._tokens = max(0.0, self._tokens - 1.0)
        return waited


# ---------------------------------------------------------------------------
# Egress (ENDPOINT-07): the policy object lives in ``redsim.ml.endpoint_egress``.
# ---------------------------------------------------------------------------

#: Mirrors ``redsim.config.RedsimConfig.target_allowlist``'s default.
DEFAULT_ALLOWLIST: tuple[str, ...] = ("127.0.0.1", "localhost", "host.docker.internal")


def url_host(endpoint: ParsedEndpoint) -> str:
    """``host`` or ``host:port`` as recorded in provenance (the default port is dropped)."""
    host = f"[{endpoint.host}]" if endpoint.literal_ip and ":" in endpoint.host else endpoint.host
    return host if endpoint.port == DEFAULT_PORTS[endpoint.scheme] else f"{host}:{endpoint.port}"


def connect_url(endpoint: ParsedEndpoint, address: str) -> str:
    """The URL actually dialled: the pinned ``address`` in place of the host, same scheme, port and path."""
    host = f"[{address}]" if isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address) else address
    port = "" if endpoint.port == DEFAULT_PORTS[endpoint.scheme] else f":{endpoint.port}"
    return f"{endpoint.scheme}://{host}{port}{endpoint.path}"


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------


@dataclass
class BrokerStats:
    """What the broker did on one job; recorded in provenance, never containing the credential."""

    url_host: str = ""
    scheme: str = ""
    contract: str = CONTRACT_VERSION
    tls_mode: str | None = None
    plaintext_loopback: bool = False
    proxy_env_honoured: bool = False
    resolved_addresses: list[str] = field(default_factory=list)
    pinned_address: str | None = None
    limits: dict[str, float | int] = field(default_factory=dict)
    requests: int = 0
    rows: int = 0
    request_bytes: int = 0
    response_bytes: int = 0
    retries: int = 0
    failures: int = 0
    rate_limit_wait_s: float = 0.0
    latency_ms_total: float = 0.0
    http_status_last: int | None = None
    by_purpose: dict[str, dict[str, int]] = field(default_factory=dict)
    output_kind: str | None = None
    fingerprint_sha256: str | None = None
    fingerprint_label: str = FINGERPRINT_LABEL
    started_at: str | None = None
    stopped_at: str | None = None
    last_error: str | None = None
    egress_notes: list[str] = field(default_factory=list)

    def count(self, purpose: str, rows: int, request_bytes: int, response_bytes: int, latency_ms: float,
              status: int) -> None:
        self.requests += 1
        self.rows += rows
        self.request_bytes += request_bytes
        self.response_bytes += response_bytes
        self.latency_ms_total += latency_ms
        self.http_status_last = status
        bucket = self.by_purpose.setdefault(purpose, {"requests": 0, "rows": 0})
        bucket["requests"] += 1
        bucket["rows"] += rows

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "url_host": self.url_host, "scheme": self.scheme, "contract": self.contract,
            "tls_mode": self.tls_mode, "plaintext_loopback": self.plaintext_loopback,
            "proxy_env_honoured": self.proxy_env_honoured, "resolved_addresses": list(self.resolved_addresses),
            "pinned_address": self.pinned_address,
            "limits": dict(self.limits), "requests": self.requests, "rows": self.rows,
            "request_bytes": self.request_bytes, "response_bytes": self.response_bytes,
            "retries": self.retries, "failures": self.failures,
            "rate_limit_wait_s": round(self.rate_limit_wait_s, 6),
            "latency_ms_mean": (self.latency_ms_total / self.requests) if self.requests else None,
            "http_status_last": self.http_status_last,
            "by_purpose": {k: dict(v) for k, v in self.by_purpose.items()},
            "output_kind": self.output_kind, "fingerprint_sha256": self.fingerprint_sha256,
            "fingerprint_label": self.fingerprint_label, "started_at": self.started_at,
            "stopped_at": self.stopped_at, "last_error": self.last_error,
            "egress_notes": list(self.egress_notes),
        }
        return out


@dataclass(frozen=True)
class PredictResult:
    probabilities: list[list[float]]
    output_kind: str
    http_status: int
    latency_ms: float


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------

_RETRY_BACKOFF_S = (0.2, 0.5)


def _auth_headers(auth: Mapping[str, Any] | None) -> dict[str, str]:
    """Header for an AuthProfile resolution ``{"kind", "config", "secret"}``; ``None`` means anonymous."""
    if auth is None:
        return {}
    kind = str(auth.get("kind") or "")
    secret = auth.get("secret")
    if not isinstance(secret, str) or not secret:
        raise EgressRefused("credential",
                            "endpoint credential is empty; refusing to send an unauthenticated request in its place")
    if kind == "bearer":
        return {"Authorization": f"Bearer {secret}"}
    if kind == "header":
        raw_config = auth.get("config")
        config: Mapping[str, Any] = raw_config if isinstance(raw_config, Mapping) else {}
        name = str(config.get("header_name") or "").strip()
        if not name or any(ch in name for ch in " :\r\n"):
            raise EgressRefused("credential", "endpoint credential of kind 'header' needs a valid config.header_name")
        return {name: secret}
    raise EgressRefused("credential", f"endpoint credential kind {kind!r} is not supported (bearer or header)")


class HttpPredictTransport:
    """The outbound HTTP client. Built once per job in the worker parent; never in the child or the API.

    ``auth`` is the ``resolve_auth_for_scan`` shape; the secret lives only in the client's headers and is
    never written, logged or returned. ``verify`` defaults to :func:`redsim.llm.pythia.tls_verify`.
    ``modality`` (``image`` / ``tabular``) fixes the contract ``input_format``; without it the format is
    read from the rows' rank. ``input_shape`` (the registered shape) is enforced on every request when given.

    ``transport`` (an ``httpx.MockTransport`` in tests) bypasses TLS and, unless a ``resolver`` is injected
    too, the connect-time resolution and pin; the static URL rules always run.
    """

    def __init__(
        self,
        url: str,
        auth: Mapping[str, Any] | None,
        *,
        limits: EndpointLimits | None = None,
        n_classes: int | None = None,
        allowlist: list[str] | None = None,
        modality: str | None = None,
        input_shape: list[int] | tuple[int, ...] | None = None,
        verify: Any | None = None,
        transport: httpx.BaseTransport | None = None,
        trust_env: bool | None = None,
        resolver: Resolver | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        import httpx as _httpx

        self.limits = limits or EndpointLimits()
        self.n_classes = n_classes
        self._input_format: InputFormat | None = input_format_for(modality) if modality is not None else None
        self._input_shape: tuple[int, ...] | None = tuple(int(d) for d in input_shape) if input_shape else None
        allow = list(allowlist) if allowlist is not None else list(DEFAULT_ALLOWLIST)
        # ENDPOINT-07: the static rules (a-d on the URL) always run; resolution, classification and the pin
        # run whenever a real connection will be made (or a resolver is injected for an offline test).
        self._policy = EgressPolicy(allow, resolver=resolver)
        self._pinned: str | None = None
        if transport is None or resolver is not None:
            self.endpoint, resolved = self._policy.check_endpoint(url)
            self._pinned = resolved.pinned
            resolved_addresses = list(resolved.addresses)
        else:
            self.endpoint = self._policy.check_registration_url(url)
            resolved_addresses = []
        self.stats = BrokerStats(url_host=url_host(self.endpoint), scheme=self.endpoint.scheme,
                                 plaintext_loopback=self.endpoint.plaintext_loopback,
                                 resolved_addresses=resolved_addresses, pinned_address=self._pinned,
                                 limits=self.limits.as_dict(),
                                 started_at=datetime.now(UTC).isoformat())
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "redsim-endpoint-broker", **_auth_headers(auth)}
        honour_proxy = (not self.endpoint.plaintext_loopback and not is_loopback(self.endpoint.host)
                        if trust_env is None else bool(trust_env))
        self.stats.proxy_env_honoured = honour_proxy
        kwargs: dict[str, Any] = {
            "headers": headers, "timeout": self.limits.timeout_s, "follow_redirects": False,
            "trust_env": honour_proxy,
        }
        if transport is not None:
            kwargs["transport"] = transport
            self.stats.tls_mode = "transport"
        elif self.endpoint.scheme == "https":
            if verify is None:
                from redsim.llm.pythia import tls_verify

                verify, tls_mode = tls_verify()
            else:
                tls_mode = "explicit"
            kwargs["verify"] = verify
            self.stats.tls_mode = tls_mode
        else:
            self.stats.tls_mode = "plaintext"
            self.stats.egress_notes.append("plaintext http permitted: the host is a loopback or private literal "
                                           "on the allowlist (development endpoint)")
        if self._pinned is not None:
            self.stats.egress_notes.append(
                f"connections pinned to {self._pinned} for {self.endpoint.host!r} (the hostname travels as TLS SNI "
                "and Host header); a later resolution or connection elsewhere is refused as DNS rebinding")
        self.stats.egress_notes.append("redirects disabled")
        self._client = _httpx.Client(**kwargs)
        self._bucket = TokenBucket(self.limits.rps, clock=clock, sleep=sleep)
        self._sleep = sleep
        self._lock = threading.Lock()
        self._closed = False

    @property
    def policy(self) -> EgressPolicy:
        """The egress policy (allowlist and session pins) this transport connects under."""
        return self._policy

    @property
    def pinned_address(self) -> str | None:
        return self._pinned

    # -- request shape ---------------------------------------------------------------------------

    def _request_target(self) -> tuple[str, dict[str, str], dict[str, Any]]:
        """``(url, headers, extensions)`` for one request: the pinned address with the hostname as SNI / Host."""
        if self._pinned is None:
            return self.endpoint.url, {}, {}
        # verify_pin at connect (ENDPOINT-07): the address about to be dialled must be the session pin.
        self._policy.session.verify_pin(self.endpoint.host, self._pinned)
        headers = {"Host": url_host(self.endpoint)}
        extensions: dict[str, Any] = {}
        if self.endpoint.scheme == "https" and not self.endpoint.literal_ip:
            extensions["sni_hostname"] = self.endpoint.host
        return connect_url(self.endpoint, self._pinned), headers, extensions

    def _encode(self, inputs: list[Any]) -> bytes:
        input_format = self._input_format or input_format_for(None, inputs)
        try:
            body = encode_request(inputs, input_format=input_format, input_shape=self._input_shape)
        except ValidationError as exc:   # the contract model refused the rows: its first message names the leaf
            errors = exc.errors()
            message = str(errors[0].get("msg") or exc) if errors else str(exc)
            raise EndpointSchemaMismatch(message.removeprefix("Value error, "), field="inputs") from exc
        except ValueError as exc:        # a shape that disagrees with the registered input_shape
            raise EndpointSchemaMismatch(str(exc), field="inputs") from exc
        return json.dumps(body, separators=(",", ":")).encode("utf-8")

    # -- protocol -------------------------------------------------------------------------------

    def predict(self, inputs: list[Any], *, purpose: str = "predict") -> PredictResult:
        """One contract request for ``inputs`` (a list of rows); budget, rate limit and retries applied."""
        import httpx as _httpx

        if self._closed:
            raise EndpointUnreachable("endpoint transport is closed")
        if not isinstance(inputs, list) or not inputs:
            raise EndpointSchemaMismatch("a predict request needs a non-empty list of rows", field="inputs")
        n = len(inputs)
        if n > self.limits.batch_rows:
            raise EndpointSchemaMismatch(f"request batch of {n} rows exceeds batch_rows={self.limits.batch_rows}",
                                         field="inputs")
        body = self._encode(inputs)
        with self._lock:
            if self.stats.rows + n > self.limits.max_rows:
                self.stats.failures += 1
                raise QueryBudgetExceeded(
                    f"query budget exhausted: {self.stats.rows} rows served, {n} more would exceed "
                    f"max_rows={self.limits.max_rows} ({self.stats.requests} requests so far)",
                )
            if self.stats.requests + 1 > self.limits.max_requests:
                self.stats.failures += 1
                raise QueryBudgetExceeded(
                    f"query budget exhausted: {self.stats.requests} requests served; "
                    f"max_requests={self.limits.max_requests}",
                )
            attempt = 0
            while True:
                self.stats.rate_limit_wait_s += self._bucket.acquire()
                target, headers, extensions = self._request_target()
                request = self._client.build_request("POST", target, content=body, headers=headers,
                                                     extensions=extensions)
                t0 = time.perf_counter()
                try:
                    response = self._client.send(request)
                except (_httpx.TimeoutException, _httpx.TransportError) as exc:
                    if attempt < len(_RETRY_BACKOFF_S):
                        self.stats.retries += 1
                        self._sleep(_RETRY_BACKOFF_S[attempt])
                        attempt += 1
                        continue
                    self.stats.failures += 1
                    self.stats.last_error = f"{type(exc).__name__}"
                    raise EndpointUnreachable(
                        f"endpoint {self.stats.url_host} unreachable after {attempt + 1} attempts: "
                        f"{type(exc).__name__}: {exc}",
                    ) from exc
                latency_ms = (time.perf_counter() - t0) * 1000.0
                status = response.status_code
                if status >= 500 and attempt < len(_RETRY_BACKOFF_S):
                    self.stats.retries += 1
                    self._sleep(_RETRY_BACKOFF_S[attempt])
                    attempt += 1
                    continue
                break
            raw = response.content
            if status in {401, 403}:
                self.stats.failures += 1
                self.stats.http_status_last = status
                self.stats.last_error = f"http {status}"
                raise EndpointAuthFailed(f"endpoint {self.stats.url_host} answered {status} to the credential")
            if status >= 500:
                self.stats.failures += 1
                self.stats.http_status_last = status
                self.stats.last_error = f"http {status}"
                raise EndpointUnreachable(
                    f"endpoint {self.stats.url_host} answered {status} on {attempt + 1} attempts",
                )
            if status != 200:
                self.stats.failures += 1
                self.stats.http_status_last = status
                self.stats.last_error = f"http {status}"
                what = "redirect refused" if 300 <= status < 400 else "contract requires 200"
                raise EndpointSchemaMismatch(f"endpoint answered {status} ({what})", field="status")
            try:
                validated = decode_response(raw, n=n, n_classes=self.n_classes)
            except EndpointSchemaMismatch:
                self.stats.failures += 1
                self.stats.http_status_last = status
                raise
            rows, kind = validated.probabilities, validated.output_kind
            if self.n_classes is None:
                # Adopted from the first response: every later response must keep this width.
                self.n_classes = validated.n_classes
                self.stats.egress_notes.append(f"n_classes was not declared; {validated.n_classes} columns adopted "
                                               "from the first response and required from every later one")
            self.stats.count(purpose, n, len(body), len(raw), latency_ms, status)
            if self.stats.fingerprint_sha256 is None:
                self.stats.fingerprint_sha256 = response_fingerprint(rows, kind)
                self.stats.output_kind = kind
            elif self.stats.output_kind != kind:
                self.stats.egress_notes.append(f"output_kind changed from {self.stats.output_kind} to {kind}")
            return PredictResult(probabilities=rows, output_kind=kind, http_status=status, latency_ms=latency_ms)

    def stats_dict(self) -> dict[str, Any]:
        return self.stats.as_dict()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.stats.stopped_at = datetime.now(UTC).isoformat()
            self._client.close()


# ---------------------------------------------------------------------------
# Socket frames: 4-byte big-endian length + UTF-8 JSON.
# ---------------------------------------------------------------------------

_HEADER = struct.Struct("!I")
SOCKET_NAME = "predict.sock"
#: ``sun_path`` capacity minus the terminator (104 on Darwin/BSD, 108 on Linux).
_SUN_PATH_MAX = 103 if os.uname().sysname == "Darwin" else 107


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(min(remaining, 1 << 20))
        if not chunk:
            raise EndpointError("broker connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def write_frame(sock: socket.socket, payload: Any) -> int:
    """Send one JSON frame; returns the byte count. Frames over :data:`FRAME_MAX_BYTES` are refused."""
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(data) > FRAME_MAX_BYTES:
        raise EndpointSchemaMismatch(f"socket frame of {len(data)} bytes exceeds the {FRAME_MAX_BYTES} cap",
                                     field="frame")
    sock.sendall(_HEADER.pack(len(data)) + data)
    return len(data)


def read_frame(sock: socket.socket) -> Any:
    """Read one JSON frame; a malformed or oversized frame is :class:`EndpointSchemaMismatch`."""
    (length,) = _HEADER.unpack(_recv_exactly(sock, _HEADER.size))
    if length > FRAME_MAX_BYTES:
        raise EndpointSchemaMismatch(f"socket frame of {length} bytes exceeds the {FRAME_MAX_BYTES} cap",
                                     field="frame")
    data = _recv_exactly(sock, length)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EndpointSchemaMismatch(f"socket frame is not JSON: {exc}", field="frame") from exc


def error_frame(exc: BaseException) -> dict[str, Any]:
    """The typed error frame for ``exc``: an endpoint failure keeps its class, code and structured detail.

    ``detail`` is :func:`redsim.ml.errors.error_detail` (the egress rule / host / address, the contract
    field), never a credential or a URL with userinfo; :func:`error_from_frame` rebuilds the class from it.
    """
    if isinstance(exc, ENDPOINT_FAILURE_TYPES):
        code = getattr(exc, "code", EndpointError.code)
        frame: dict[str, Any] = {"ok": False, "error_class": type(exc).__name__,
                                 "code": code if isinstance(code, str) else EndpointError.code,
                                 "error": str(exc)[:4000]}
        detail = error_detail(exc)
        if detail:
            frame["detail"] = detail
        return frame
    return {"ok": False, "error_class": "EndpointError", "code": EndpointError.code,
            "error": f"{type(exc).__name__}: {exc}"[:4000]}


def error_from_frame(frame: Mapping[str, Any]) -> MLError:
    """The typed failure a broker error frame names, rebuilt by name (``redsim.ml.errors.rebuild_error``)."""
    name = str(frame.get("error_class") or "EndpointError")
    message = str(frame.get("error") or name)
    raw_detail = frame.get("detail")
    detail = dict(raw_detail) if isinstance(raw_detail, Mapping) else None
    if endpoint_error_class(name) is None:
        return EndpointError(message)
    return rebuild_error(name, message, detail) or EndpointError(message)


def choose_socket_path(work_dir: Path) -> Path:
    """``<work_dir>/predict.sock`` when it fits ``sun_path``; else a fresh 0700 directory under the temp root.

    The fallback exists because pytest and macOS temp roots are long; either way the socket's parent is a
    0700 directory owned by the worker, and :meth:`PredictBroker.stop` removes what was created.
    """
    preferred = Path(work_dir) / SOCKET_NAME
    if len(str(preferred).encode("utf-8")) <= _SUN_PATH_MAX:
        return preferred
    short = Path(tempfile.mkdtemp(prefix="rs-"))
    os.chmod(short, 0o700)
    return short / "p.sock"


# ---------------------------------------------------------------------------
# The broker
# ---------------------------------------------------------------------------


class PredictBroker:
    """Serve predict frames from the sandbox child over a unix socket; the only process that talks HTTP.

    ``start()`` binds the socket (mode 0600) and serves in a daemon thread; ``stop()`` shuts the server down,
    closes the HTTP client, unlinks the socket (and the fallback directory when one was made) and returns the
    final :class:`BrokerStats`. Both are idempotent and ``stop()`` is time-bounded so a killed child never
    leaves a broker thread behind.
    """

    def __init__(
        self,
        url: str,
        auth: Mapping[str, Any] | None,
        *,
        work_dir: Path,
        limits: EndpointLimits | None = None,
        n_classes: int | None = None,
        allowlist: list[str] | None = None,
        modality: str | None = None,
        input_shape: list[int] | tuple[int, ...] | None = None,
        socket_path: Path | None = None,
        verify: Any | None = None,
        transport: httpx.BaseTransport | None = None,
        trust_env: bool | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self.work_dir = Path(work_dir)
        self.socket_path = socket_path if socket_path is not None else choose_socket_path(self.work_dir)
        self._fallback_dir = self.socket_path.parent if self.socket_path.parent != self.work_dir else None
        self._transport = HttpPredictTransport(
            url, auth, limits=limits, n_classes=n_classes, allowlist=allowlist, modality=modality,
            input_shape=input_shape, verify=verify, transport=transport, trust_env=trust_env, resolver=resolver,
        )
        self._server: socketserver.ThreadingUnixStreamServer | None = None
        self._thread: threading.Thread | None = None
        self._stats: BrokerStats | None = None

    @property
    def stats(self) -> BrokerStats:
        return self._stats if self._stats is not None else self._transport.stats

    def start(self) -> Path:
        if self._server is not None:
            return self.socket_path
        transport = self._transport
        if self.socket_path.exists():
            self.socket_path.unlink()
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                sock: socket.socket = self.request
                sock.settimeout(transport.limits.timeout_s * 4 + 10)
                try:
                    frame = read_frame(sock)
                except (MLError, OSError) as exc:
                    logger.debug("predict broker dropped a bad frame: %s", exc)
                    return
                try:
                    reply = _dispatch(transport, frame)
                except Exception as exc:  # noqa: BLE001 - every failure travels typed to the child
                    reply = error_frame(exc)
                try:
                    write_frame(sock, reply)
                except (MLError, OSError) as exc:
                    logger.debug("predict broker could not answer the child: %s", exc)

        server = socketserver.ThreadingUnixStreamServer(str(self.socket_path), Handler)
        server.daemon_threads = True
        os.chmod(self.socket_path, 0o600)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1},
                                  name="redsim-predict-broker", daemon=True)
        thread.start()
        self._server, self._thread = server, thread
        return self.socket_path

    def stop(self, timeout_s: float = 5.0) -> BrokerStats:
        if self._stats is not None:
            return self._stats
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            if self._thread is not None:
                self._thread.join(timeout=timeout_s)
            self._server, self._thread = None, None
        self._transport.close()
        try:
            self.socket_path.unlink()
        except OSError:
            pass
        if self._fallback_dir is not None:
            try:
                self._fallback_dir.rmdir()
            except OSError:
                pass
        self._stats = self._transport.stats
        return self._stats

    def __enter__(self) -> PredictBroker:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


def _dispatch(transport: HttpPredictTransport, frame: Any) -> dict[str, Any]:
    if not isinstance(frame, dict):
        raise EndpointSchemaMismatch("socket frame is not an object", field="frame")
    op = frame.get("op")
    if op == "predict":
        inputs = frame.get("inputs")
        if not isinstance(inputs, list):
            raise EndpointSchemaMismatch("predict frame needs an 'inputs' list", field="frame")
        purpose = frame.get("purpose")
        result = transport.predict(inputs, purpose=str(purpose) if isinstance(purpose, str) and purpose else "predict")
        return {"ok": True, "probabilities": result.probabilities, "output_kind": result.output_kind,
                "http_status": result.http_status, "latency_ms": result.latency_ms}
    if op == "stats":
        return {"ok": True, "stats": transport.stats_dict()}
    if op == "ping":
        return {"ok": True}
    raise EndpointSchemaMismatch(f"unknown broker op {op!r}", field="frame")


__all__ = [
    "BATCH_ROWS_MAX",
    "CONTRACT_VERSION",
    "DEFAULT_ALLOWLIST",
    "ENDPOINT_ERRORS",
    "ENDPOINT_FAILURE_TYPES",
    "ENV_BATCH_ROWS",
    "ENV_MAX_REQUESTS",
    "ENV_MAX_ROWS",
    "ENV_RPS",
    "ENV_TIMEOUT_S",
    "FINGERPRINT_LABEL",
    "FRAME_MAX_BYTES",
    "RESPONSE_MAX_BYTES",
    "SOCKET_NAME",
    "BrokerStats",
    "EgressRefused",
    "EndpointAuthFailed",
    "EndpointError",
    "EndpointLimits",
    "EndpointNotAllowlisted",
    "EndpointSchemaMismatch",
    "EndpointUnreachable",
    "EndpointUrlInvalid",
    "HttpPredictTransport",
    "PredictBroker",
    "PredictResult",
    "QueryBudgetExceeded",
    "TokenBucket",
    "choose_socket_path",
    "connect_url",
    "decode_response",
    "endpoint_error_class",
    "error_frame",
    "error_from_frame",
    "input_format_for",
    "read_frame",
    "response_fingerprint",
    "url_host",
    "write_frame",
]
