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
