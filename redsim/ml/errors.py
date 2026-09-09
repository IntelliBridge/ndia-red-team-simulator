"""Exceptions for the ML vertical. Callers map these to HTTP 4xx/5xx and to Job failure reasons.

Every class the sandbox child can name in its envelope (``{"ok": false, "error_class": ...}``)
and every class the predict broker can name in a socket frame resolves here by name, so
``redsim.ml.sandbox._typed_error`` and ``redsim.ml.targets.endpoint.SocketPredictTransport``
rebuild the typed failure with :func:`rebuild_error`. Four endpoint classes are defined by the
wave B0 modules that own their rules (``redsim.ml.endpoint_egress``: ``EgressRefused``,
``EndpointUrlInvalid``, ``EndpointNotAllowlisted``; ``redsim.ml.targets.endpoint_contract``:
``EndpointSchemaMismatch``). Both of those modules import :class:`MLError` from here, so they are
re-exported lazily through the module ``__getattr__`` (PEP 562) rather than imported at the top,
and this module stays free of imports (the sandbox worker's ``--help`` probe imports it).
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Final, cast

if TYPE_CHECKING:  # the re-exports, for type checkers; runtime resolution is __getattr__ below
    from redsim.ml.endpoint_egress import EgressRefused as EgressRefused
    from redsim.ml.endpoint_egress import EndpointNotAllowlisted as EndpointNotAllowlisted
    from redsim.ml.endpoint_egress import EndpointUrlInvalid as EndpointUrlInvalid
    from redsim.ml.targets.endpoint_contract import EndpointSchemaMismatch as EndpointSchemaMismatch


class MLError(Exception):
    """Base class."""


class TargetUnavailable(MLError):
    """The target is registered but not implemented / not loadable (HTTP 501 at the API)."""


class UnsupportedArtifact(MLError):
    """Refused model artifact: wrong format, pickle, missing architecture, hash mismatch (HTTP 422)."""


class AttackNotApplicable(MLError):
    """The attack does not apply to the target's domain or the requested parameters (HTTP 422)."""


class ExplainUnavailable(MLError):
    """SHAP could not run for this target/modality; evidence is recorded as unavailable, never faked."""


# --- Spec section 10.6 failure classes (infrastructure states, never model outcomes) ---
# Each carries a stable ``code`` that services map onto the section 17.3 error table and
# that ``Job.error`` records as the class name. None of these is a clean/adversarial/control
# accuracy result: reports and the UI render them as run states (sections 14 and 18).


class ModelLoadRefused(UnsupportedArtifact):
    """The artifact was refused before or during load (pickle, unknown architecture, checker failure)."""

    code = "model_load_refused"


class ArtifactDigestMismatch(UnsupportedArtifact):
    """The bytes handed to the loader do not match the sha256 recorded at registration."""

    code = "artifact_digest_mismatch"


class SandboxTimeout(MLError):
    """The sandbox child exceeded its wall clock; the process group was killed and partial files kept."""

    code = "sandbox_timeout"


class SandboxKilled(MLError):
    """The sandbox child died from a signal or resource limit before writing its envelope."""

    code = "sandbox_killed"


class EnvelopeInvalid(MLError):
    """The child's result envelope was missing, malformed or failed schema validation."""

    code = "envelope_invalid"


class DatasetUnavailable(MLError):
    """The evaluation slice named in the manifest is missing, tampered (digest) or incompatible."""

    code = "dataset_unavailable"


class MlExtraUnavailable(MLError):
    """The worker process lacks the ``ml`` extra (torch/ART/SHAP); the stage cannot run here."""

    code = "ml_extra_unavailable"


class ExplainerUnavailable(ExplainUnavailable):
    """SHAP failed for this target; attack measurements stand and S_expl is not computed."""

    code = "explainer_unavailable"


# --- Endpoint transport failures (spec 6.3, 9.1 rule 4; ENDPOINT-05) ---
# Raised by the worker-parent predict broker (``redsim.ml.endpoint_broker``) and rebuilt in the
# sandbox child from the broker's typed frame. A transport failure is never a model outcome: the
# job fails with the evidence gathered so far and no row is ever invented.


class EndpointError(MLError):
    """Base of the endpoint transport failures; ``code`` maps onto the spec 17.3 table."""

    code = "endpoint_error"


class EndpointUnreachable(EndpointError):
    """Connection, DNS, timeout or persistent 5xx after the bounded retries."""

    code = "endpoint_unreachable"


class EndpointAuthFailed(EndpointError):
    """The endpoint answered 401 or 403 to the supplied AuthProfile credential."""

    code = "endpoint_auth_failed"


class QueryBudgetExceeded(EndpointError):
    """The per-job rows or requests budget is spent; the job fails with the evidence gathered so far."""

    code = "query_budget_exceeded"


# --- Re-exports of the wave B0 endpoint classes (defined where their rules live) ---

#: Class name -> defining module, for the classes this module re-exports by name.
ENDPOINT_REEXPORTS: Final[dict[str, str]] = {
    "EgressRefused": "redsim.ml.endpoint_egress",
    "EndpointUrlInvalid": "redsim.ml.endpoint_egress",
    "EndpointNotAllowlisted": "redsim.ml.endpoint_egress",
    "EndpointSchemaMismatch": "redsim.ml.targets.endpoint_contract",
}


def _reexport(name: str) -> type[MLError]:
    cls = getattr(importlib.import_module(ENDPOINT_REEXPORTS[name]), name)
    if not (isinstance(cls, type) and issubclass(cls, MLError)):
        raise TypeError(f"{ENDPOINT_REEXPORTS[name]}.{name} is not an MLError subclass")
    return cls


def __getattr__(name: str) -> Any:
    """PEP 562: resolve the endpoint classes owned by ``endpoint_egress`` / ``endpoint_contract`` by name."""
    if name in ENDPOINT_REEXPORTS:
        return _reexport(name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def error_class(name: str) -> type[MLError] | None:
    """The ``redsim.ml.errors`` class called ``name`` (re-exports included), else ``None``."""
    cls = globals().get(name)
    if cls is None and name in ENDPOINT_REEXPORTS:
        cls = _reexport(name)
    if isinstance(cls, type) and issubclass(cls, MLError):
        return cls
    return None


def error_detail(exc: BaseException) -> dict[str, Any]:
    """Structured fields travelling beside an error message so :func:`rebuild_error` reproduces the class.

    ``EgressRefused`` carries ``rule`` / ``reason`` / ``host`` / ``address`` (its own ``detail()``),
    ``EndpointSchemaMismatch`` carries ``field`` / ``reason``; every other class travels as its message.
    Never a URL with userinfo or query, never a credential.
    """
    detail = getattr(exc, "detail", None)
    if callable(detail):
        out = detail()
        return dict(out) if isinstance(out, Mapping) else {}
    field = getattr(exc, "field", None)
    if isinstance(field, str):
        reason = getattr(exc, "reason", None)
        return {"field": field, "reason": reason if isinstance(reason, str) else str(exc)}
    return {}


def rebuild_error(name: str, message: str, detail: Mapping[str, Any] | None = None) -> MLError | None:
    """The typed failure ``name`` carrying ``message`` (and ``detail``), or ``None`` for an unknown name.

    The wave B0 classes have keyword constructors: an ``EgressRefused`` (or subclass) is rebuilt as
    ``cls(rule, reason, host=, address=)`` and an ``EndpointSchemaMismatch`` as ``cls(reason, field=)``;
    when the detail is missing the message stands in for the reason. Everything else is ``cls(message)``.
    """
    cls = error_class(name)
    if cls is None:
        return None
    given = dict(detail or {})
    reason = given.get("reason")
    text = reason if isinstance(reason, str) and reason else message
    egress_refused = cast("type[EgressRefused]", _reexport("EgressRefused"))
    if issubclass(cls, egress_refused):
        rule = given.get("rule")
        host = given.get("host")
        address = given.get("address")
        return cls(rule if isinstance(rule, str) and rule else "remote", text,
                   host=host if isinstance(host, str) else None,
                   address=address if isinstance(address, str) else None)
    schema_mismatch = cast("type[EndpointSchemaMismatch]", _reexport("EndpointSchemaMismatch"))
    if issubclass(cls, schema_mismatch):
        field = given.get("field")
        return cls(text, field=field if isinstance(field, str) and field else "response")
    return cls(message)
