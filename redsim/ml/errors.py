"""Exceptions for the ML vertical. Callers map these to HTTP 4xx/5xx and to Job failure reasons."""


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
