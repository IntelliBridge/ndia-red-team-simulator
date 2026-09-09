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
  request and response per the ``endpoint-v1`` predict contract, batch-row and timeout
  caps, a token-bucket rate limit, a rows/requests/bytes counter per purpose (attack,
  control, explain, probe), bounded retries on 5xx / timeouts, and typed failures.
* :class:`PredictBroker` -- a ``ThreadingUnixStreamServer`` that turns length-prefixed
  JSON frames from the child (``redsim.ml.targets.endpoint.SocketPredictTransport``)
  into transport calls and answers with probabilities or a typed error frame.
* The typed failures :class:`EndpointUnreachable`, :class:`EndpointAuthFailed`,
  :class:`EndpointSchemaMismatch`, :class:`EgressRefused` and :class:`QueryBudgetExceeded`
  (spec 6.3: a transport failure is never a model outcome; the job fails with the
  evidence gathered so far, no row is ever invented).

The response fingerprint (sha256 of the first response's shape, class ordering and
rounded probabilities) is labelled *remote model identity*: it identifies what the
endpoint answered at that moment, not a weights digest, and a changed fingerprint on a
later job means the remote model may have changed (ENDPOINT-27 re-checks it).

Egress: the URL is checked before any request leaves the worker (scheme, no userinfo /
query / fragment, host on the target allowlist, plaintext only for a loopback or
private literal host, resolved addresses classified). ``redsim.ml.endpoint_egress``
(wave B0) is consulted when importable; the local checks stay as the floor.
"""

from __future__ import annotations

import hashlib
import importlib
import ipaddress
import json
import logging
import math
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
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from redsim.ml.errors import MLError
from redsim.safety import is_loopback, is_target_allowed

if TYPE_CHECKING:
    import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Typed failures (spec 6.3, 10.6): infrastructure states, never model outcomes.
# ---------------------------------------------------------------------------


class EndpointError(MLError):
    """Base of the endpoint transport failures; ``code`` maps onto the spec 17.3 table."""

    code = "endpoint_error"


class EndpointUnreachable(EndpointError):
    """Connection, DNS, timeout or persistent 5xx after the bounded retries."""

    code = "endpoint_unreachable"


class EndpointAuthFailed(EndpointError):
    """The endpoint answered 401 or 403 to the supplied AuthProfile credential."""

    code = "endpoint_auth_failed"


class EndpointSchemaMismatch(EndpointError):
    """The response violated the predict contract (status, shape, values, size); never coerced."""

    code = "endpoint_schema_mismatch"


class EgressRefused(EndpointError):
    """The URL or a resolved address failed the egress policy before any request left the worker."""

    code = "egress_refused"


class QueryBudgetExceeded(EndpointError):
    """The per-job rows or requests budget is spent; the job fails with the evidence gathered so far."""

    code = "query_budget_exceeded"


ENDPOINT_ERRORS: dict[str, type[EndpointError]] = {
    cls.__name__: cls
    for cls in (EndpointError, EndpointUnreachable, EndpointAuthFailed, EndpointSchemaMismatch,
                EgressRefused, QueryBudgetExceeded)
}


def endpoint_error_class(name: str) -> type[EndpointError] | None:
    """The typed class for an ``error_class`` name travelling in an envelope or a socket frame."""
    return ENDPOINT_ERRORS.get(name)


# ---------------------------------------------------------------------------
# The predict contract (endpoint-v1). Wave B0 lands the authoritative copy in
# ``redsim.ml.targets.endpoint_contract``; it is used when importable.
# ---------------------------------------------------------------------------

def _optional_module(name: str) -> Any | None:
    """Import a wave B0 module when present; ``None`` in a tree that predates it."""
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


_contract_mod = _optional_module("redsim.ml.targets.endpoint_contract")

#: Contract identifier sent in every request body and checked by the endpoint.
CONTRACT_VERSION: str = str(getattr(_contract_mod, "CONTRACT_VERSION", "endpoint-v1"))

#: Cap on a predict response (contract: anything larger is a violation, never read further).
RESPONSE_MAX_BYTES = 16 * 1024 * 1024
#: Cap on one socket frame between the child and the broker.
FRAME_MAX_BYTES = 64 * 1024 * 1024
#: Hard ceiling on rows per request whatever the environment says (ENDPOINT-08).
BATCH_ROWS_MAX = 1024


class _LocalPredictRequest(BaseModel):
    """TODO(wave B0): replace by ``redsim.ml.targets.endpoint_contract.PredictRequest`` after the rebase."""

    contract: str = CONTRACT_VERSION
    inputs: list[Any] = Field(min_length=1)
    encoding: str = "list"


class _LocalPredictResponse(BaseModel):
    """TODO(wave B0): replace by ``redsim.ml.targets.endpoint_contract.PredictResponse`` after the rebase."""

    probabilities: list[list[float]] | None = None
    logits: list[list[float]] | None = None


def _contract_model(name: str, local: type[BaseModel], required: str) -> type[BaseModel]:
    candidate = getattr(_contract_mod, name, None)
    fields = getattr(candidate, "model_fields", None)
    if isinstance(candidate, type) and isinstance(fields, dict) and required in fields:
        return candidate
    return local


PredictRequest: type[BaseModel] = _contract_model("PredictRequest", _LocalPredictRequest, "inputs")
PredictResponse: type[BaseModel] = _contract_model("PredictResponse", _LocalPredictResponse, "probabilities")


def build_predict_body(inputs: list[Any]) -> dict[str, Any]:
    """The request body of the contract for one batch of already-listified rows."""
    return PredictRequest(contract=CONTRACT_VERSION, inputs=inputs, encoding="list").model_dump(mode="json")


def _softmax_row(values: list[float]) -> list[float]:
    top = max(values)
    exps = [math.exp(v - top) for v in values]
    total = sum(exps)
    return [e / total for e in exps]


def validate_predict_response(body: Any, *, n_rows: int, n_classes: int | None) -> tuple[list[list[float]], str]:
    """Contract check of a decoded response body: ``(probability rows, output_kind)``.

    ``probabilities`` rows must be finite, in [0, 1] and sum to 1 within 1e-3; ``logits`` rows
    must be finite and are softmaxed here (``output_kind`` records which). Exactly ``n_rows``
    rows, a constant column count equal to ``n_classes`` when known. Anything else is
    :class:`EndpointSchemaMismatch` naming the field; nothing is coerced.
    """
    if not isinstance(body, dict):
        raise EndpointSchemaMismatch("response body is not a JSON object")
    if isinstance(body.get("probabilities"), list):
        kind, rows = "probabilities", body["probabilities"]
    elif isinstance(body.get("logits"), list):
        kind, rows = "logits", body["logits"]
    else:
        raise EndpointSchemaMismatch("response carries neither a 'probabilities' nor a 'logits' list")
    if len(rows) != n_rows:
        raise EndpointSchemaMismatch(f"response has {len(rows)} rows for a request of {n_rows}")
    width: int | None = None
    out: list[list[float]] = []
    for i, row in enumerate(rows):
        if not isinstance(row, list) or not row:
            raise EndpointSchemaMismatch(f"{kind}[{i}] is not a non-empty list")
        if width is None:
            width = len(row)
        elif len(row) != width:
            raise EndpointSchemaMismatch(f"{kind}[{i}] has {len(row)} columns, row 0 has {width}")
        values: list[float] = []
        for j, value in enumerate(row):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise EndpointSchemaMismatch(f"{kind}[{i}][{j}] is not a finite number")
            values.append(float(value))
        if kind == "probabilities":
            if any(v < -1e-6 or v > 1.0 + 1e-6 for v in values):
                raise EndpointSchemaMismatch(f"probabilities[{i}] has a value outside [0, 1]")
            if abs(sum(values) - 1.0) > 1e-3:
                raise EndpointSchemaMismatch(f"probabilities[{i}] sums to {sum(values):.4f}, not 1 within 1e-3")
        else:
            values = _softmax_row(values)
        out.append(values)
    if n_classes is not None and width != n_classes:
        raise EndpointSchemaMismatch(
            f"response has {width} columns; the target declares {n_classes} classes",
        )
    return out, kind


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
# Egress policy (ENDPOINT-07): the floor applied here; wave B0's module is consulted when present.
# ---------------------------------------------------------------------------

#: Mirrors ``redsim.config.RedsimConfig.target_allowlist``'s default.
DEFAULT_ALLOWLIST: tuple[str, ...] = ("127.0.0.1", "localhost", "host.docker.internal")


@dataclass(frozen=True)
class ParsedEndpoint:
    url: str
    scheme: str
    host: str
    port: int
    path: str
    plaintext_loopback: bool

    @property
    def url_host(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"


def _private_literal(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _b0_egress_call(name: str, value: str, allowlist: list[str]) -> None:
    """Call ``redsim.ml.endpoint_egress.<name>`` when the wave B0 module is importable; refusals propagate."""
    egress_mod = _optional_module("redsim.ml.endpoint_egress")
    if egress_mod is None:
        return
    fn = getattr(egress_mod, name, None)
    if not callable(fn):
        return
    try:
        try:
            fn(value, allowlist=allowlist)
        except TypeError:
            fn(value)
    except EndpointError:
        raise
    except Exception as exc:  # noqa: BLE001 - any refusal from the policy module is an egress refusal
        raise EgressRefused(f"{name}: {type(exc).__name__}: {exc}") from exc


def check_endpoint_url(url: str, allowlist: list[str] | None = None) -> ParsedEndpoint:
    """Static egress checks on the URL; :class:`EgressRefused` names the failing rule."""
    allow = list(allowlist) if allowlist is not None else list(DEFAULT_ALLOWLIST)
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise EgressRefused(f"endpoint_url_invalid: scheme {parts.scheme!r} is not http or https")
    if parts.username is not None or parts.password is not None:
        raise EgressRefused("endpoint_url_invalid: userinfo in the URL is refused")
    if parts.query or parts.fragment:
        raise EgressRefused("endpoint_url_invalid: query string and fragment are refused")
    host = (parts.hostname or "").strip()
    if not host:
        raise EgressRefused("endpoint_url_invalid: the URL has no host")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise EgressRefused(f"endpoint_url_invalid: {exc}") from exc
    if not is_target_allowed(host, allow):
        raise EgressRefused(f"endpoint_not_allowlisted: host {host!r} is not on the target allowlist")
    plaintext_loopback = False
    if parts.scheme == "http":
        if not (is_loopback(host) or _private_literal(host)):
            raise EgressRefused(f"endpoint_url_invalid: plaintext http to {host!r} is refused; use https")
        plaintext_loopback = True
    _b0_egress_call("check_registration_url", url, allow)
    return ParsedEndpoint(url=url, scheme=parts.scheme, host=host, port=int(port), path=parts.path or "/",
                          plaintext_loopback=plaintext_loopback)


def check_resolved_addresses(endpoint: ParsedEndpoint, allowlist: list[str] | None = None,
                             resolver: Callable[..., Any] = socket.getaddrinfo) -> list[str]:
    """Resolve the host and refuse a loopback / private / link-local / multicast / reserved address unless the
    allowlist names it (the literal IP, a CIDR containing it, or the loopback hostname itself)."""
    allow = list(allowlist) if allowlist is not None else list(DEFAULT_ALLOWLIST)
    try:
        infos = resolver(endpoint.host, endpoint.port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise EndpointUnreachable(f"dns resolution of {endpoint.host!r} failed: {exc}") from exc
    addresses: list[str] = []
    for info in infos:
        raw = info[4][0] if len(info) > 4 and info[4] else None
        if not isinstance(raw, str):
            continue
        try:
            ip = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            continue
        addresses.append(str(ip))
        special = (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast
                   or ip.is_reserved or ip.is_unspecified)
        exempt = is_target_allowed(str(ip), allow) or (endpoint.host in allow and is_loopback(endpoint.host))
        if special and not exempt:
            raise EgressRefused(
                f"egress_refused: {endpoint.host!r} resolves to {ip} (private or special-purpose address not on "
                "the allowlist)",
            )
    if not addresses:
        raise EndpointUnreachable(f"dns resolution of {endpoint.host!r} returned no address")
    _b0_egress_call("check_request_host", endpoint.host, allow)
    return addresses


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
        raise EgressRefused("endpoint credential is empty; refusing to send an unauthenticated request in its place")
    if kind == "bearer":
        return {"Authorization": f"Bearer {secret}"}
    if kind == "header":
        raw_config = auth.get("config")
        config: Mapping[str, Any] = raw_config if isinstance(raw_config, Mapping) else {}
        name = str(config.get("header_name") or "").strip()
        if not name or any(ch in name for ch in " :\r\n"):
            raise EgressRefused("endpoint credential of kind 'header' needs a valid config.header_name")
        return {name: secret}
    raise EgressRefused(f"endpoint credential kind {kind!r} is not supported (bearer or header)")


class HttpPredictTransport:
    """The outbound HTTP client. Built once per job in the worker parent; never in the child or the API.

    ``auth`` is the ``resolve_auth_for_scan`` shape; the secret lives only in the client's headers and is
    never written, logged or returned. ``verify`` defaults to :func:`redsim.llm.pythia.tls_verify`;
    ``transport`` (an ``httpx.MockTransport`` in tests) bypasses TLS and egress resolution.
    """

    def __init__(
        self,
        url: str,
        auth: Mapping[str, Any] | None,
        *,
        limits: EndpointLimits | None = None,
        n_classes: int | None = None,
        allowlist: list[str] | None = None,
        verify: Any | None = None,
        transport: httpx.BaseTransport | None = None,
        trust_env: bool | None = None,
        resolver: Callable[..., Any] = socket.getaddrinfo,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        import httpx as _httpx

        self.limits = limits or EndpointLimits()
        self.n_classes = n_classes
        self.endpoint = check_endpoint_url(url, allowlist)
        self.stats = BrokerStats(url_host=self.endpoint.url_host, scheme=self.endpoint.scheme,
                                 plaintext_loopback=self.endpoint.plaintext_loopback,
                                 limits=self.limits.as_dict(),
                                 started_at=datetime.now(UTC).isoformat())
        if transport is None:
            self.stats.resolved_addresses = check_resolved_addresses(self.endpoint, allowlist, resolver=resolver)
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
        self.stats.egress_notes.append("redirects disabled; no IP pinning (residual DNS-rebinding window recorded "
                                       "as a known limitation)")
        self._client = _httpx.Client(**kwargs)
        self._bucket = TokenBucket(self.limits.rps, clock=clock, sleep=sleep)
        self._sleep = sleep
        self._lock = threading.Lock()
        self._closed = False

    # -- protocol -------------------------------------------------------------------------------

    def predict(self, inputs: list[Any], *, purpose: str = "predict") -> PredictResult:
        """One contract request for ``inputs`` (a list of rows); budget, rate limit and retries applied."""
        import httpx as _httpx

        if self._closed:
            raise EndpointUnreachable("endpoint transport is closed")
        if not isinstance(inputs, list) or not inputs:
            raise EndpointSchemaMismatch("a predict request needs a non-empty list of rows")
        n = len(inputs)
        if n > self.limits.batch_rows:
            raise EndpointSchemaMismatch(f"request batch of {n} rows exceeds batch_rows={self.limits.batch_rows}")
        body = json.dumps(build_predict_body(inputs), separators=(",", ":")).encode("utf-8")
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
                t0 = time.perf_counter()
                try:
                    response = self._client.post(self.endpoint.url, content=body)
                except (_httpx.TimeoutException, _httpx.TransportError) as exc:
                    if attempt < len(_RETRY_BACKOFF_S):
                        self.stats.retries += 1
                        self._sleep(_RETRY_BACKOFF_S[attempt])
                        attempt += 1
                        continue
                    self.stats.failures += 1
                    self.stats.last_error = f"{type(exc).__name__}"
                    raise EndpointUnreachable(
                        f"endpoint {self.endpoint.url_host} unreachable after {attempt + 1} attempts: "
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
                raise EndpointAuthFailed(f"endpoint {self.endpoint.url_host} answered {status} to the credential")
            if status >= 500:
                self.stats.failures += 1
                self.stats.http_status_last = status
                self.stats.last_error = f"http {status}"
                raise EndpointUnreachable(
                    f"endpoint {self.endpoint.url_host} answered {status} on {attempt + 1} attempts",
                )
            if status != 200:
                self.stats.failures += 1
                self.stats.http_status_last = status
                self.stats.last_error = f"http {status}"
                what = "redirect refused" if 300 <= status < 400 else "contract requires 200"
                raise EndpointSchemaMismatch(f"endpoint answered {status} ({what})")
            if len(raw) > RESPONSE_MAX_BYTES:
                self.stats.failures += 1
                raise EndpointSchemaMismatch(f"response of {len(raw)} bytes exceeds the {RESPONSE_MAX_BYTES} cap")
            try:
                decoded = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                self.stats.failures += 1
                raise EndpointSchemaMismatch(f"response is not JSON: {exc}") from exc
            try:
                rows, kind = validate_predict_response(decoded, n_rows=n, n_classes=self.n_classes)
            except EndpointSchemaMismatch:
                self.stats.failures += 1
                self.stats.http_status_last = status
                raise
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
        raise EndpointSchemaMismatch(f"socket frame of {len(data)} bytes exceeds the {FRAME_MAX_BYTES} cap")
    sock.sendall(_HEADER.pack(len(data)) + data)
    return len(data)


def read_frame(sock: socket.socket) -> Any:
    """Read one JSON frame; a malformed or oversized frame is :class:`EndpointSchemaMismatch`."""
    (length,) = _HEADER.unpack(_recv_exactly(sock, _HEADER.size))
    if length > FRAME_MAX_BYTES:
        raise EndpointSchemaMismatch(f"socket frame of {length} bytes exceeds the {FRAME_MAX_BYTES} cap")
    data = _recv_exactly(sock, length)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EndpointSchemaMismatch(f"socket frame is not JSON: {exc}") from exc


def error_frame(exc: BaseException) -> dict[str, Any]:
    """The typed error frame for ``exc``: an :class:`EndpointError` keeps its class and code."""
    if isinstance(exc, EndpointError):
        return {"ok": False, "error_class": type(exc).__name__, "code": exc.code, "error": str(exc)[:4000]}
    return {"ok": False, "error_class": "EndpointError", "code": EndpointError.code,
            "error": f"{type(exc).__name__}: {exc}"[:4000]}


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
        socket_path: Path | None = None,
        verify: Any | None = None,
        transport: httpx.BaseTransport | None = None,
        trust_env: bool | None = None,
    ) -> None:
        self.work_dir = Path(work_dir)
        self.socket_path = socket_path if socket_path is not None else choose_socket_path(self.work_dir)
        self._fallback_dir = self.socket_path.parent if self.socket_path.parent != self.work_dir else None
        self._transport = HttpPredictTransport(
            url, auth, limits=limits, n_classes=n_classes, allowlist=allowlist, verify=verify,
            transport=transport, trust_env=trust_env,
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
                except (EndpointError, OSError) as exc:
                    logger.debug("predict broker dropped a bad frame: %s", exc)
                    return
                try:
                    reply = _dispatch(transport, frame)
                except Exception as exc:  # noqa: BLE001 - every failure travels typed to the child
                    reply = error_frame(exc)
                try:
                    write_frame(sock, reply)
                except (EndpointError, OSError) as exc:
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
        raise EndpointSchemaMismatch("socket frame is not an object")
    op = frame.get("op")
    if op == "predict":
        inputs = frame.get("inputs")
        if not isinstance(inputs, list):
            raise EndpointSchemaMismatch("predict frame needs an 'inputs' list")
        purpose = frame.get("purpose")
        result = transport.predict(inputs, purpose=str(purpose) if isinstance(purpose, str) and purpose else "predict")
        return {"ok": True, "probabilities": result.probabilities, "output_kind": result.output_kind,
                "http_status": result.http_status, "latency_ms": result.latency_ms}
    if op == "stats":
        return {"ok": True, "stats": transport.stats_dict()}
    if op == "ping":
        return {"ok": True}
    raise EndpointSchemaMismatch(f"unknown broker op {op!r}")


__all__ = [
    "BATCH_ROWS_MAX",
    "CONTRACT_VERSION",
    "DEFAULT_ALLOWLIST",
    "ENDPOINT_ERRORS",
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
    "EndpointSchemaMismatch",
    "EndpointUnreachable",
    "HttpPredictTransport",
    "ParsedEndpoint",
    "PredictBroker",
    "PredictRequest",
    "PredictResponse",
    "PredictResult",
    "QueryBudgetExceeded",
    "TokenBucket",
    "build_predict_body",
    "check_endpoint_url",
    "check_resolved_addresses",
    "choose_socket_path",
    "endpoint_error_class",
    "error_frame",
    "read_frame",
    "response_fingerprint",
    "validate_predict_response",
    "write_frame",
]
