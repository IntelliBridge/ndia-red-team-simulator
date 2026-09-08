"""LLM-domain / black-box endpoint stub (spec sections 6.6, 9.1 rule 4, D6).

Phase A has no endpoint or LLM target. The stub is registered so
``GET /v1/models`` can list the domain honestly as ``not_implemented`` with a
reason and the connection shape it will use; launching against it returns HTTP
501 upstream. Every method that would need a model raises ``TargetUnavailable``.
Nothing here reads a secret: the metadata names environment variables and says
whether they are set, never their values.
"""

from __future__ import annotations

import os
from typing import Any, NoReturn

import numpy as np

from redsim.ml.errors import TargetUnavailable
from redsim.ml.schema import TargetInfo
from redsim.ml.targets.base import Sample
from redsim.ml.targets.registry import TARGETS

PYTHIA_ENV = {
    "base_url": "PYTHIA_BASE_URL",
    "api_key": "PYTHIA_API_KEY",
    "persona": "PYTHIA_PERSONA",
    "timeout_s": "PYTHIA_TIMEOUT_S",
}
# The scaffold reads REDSIM_LLM_MODEL today; the spec renames it to REDSIM_ML_LLM_MODEL (section 20.3).
MODEL_ENV_CANDIDATES: tuple[str, ...] = ("REDSIM_ML_LLM_MODEL", "REDSIM_LLM_MODEL")
CHAT_PATH = "/v1/chat/completions"

REASON = (
    "Phase B: black-box endpoint and LLM targets are not implemented. When built, endpoint credentials reuse "
    "AuthProfile (Fernet-encrypted, decrypted worker-side only), the endpoint host must pass the target "
    "allowlist, and LLM red-teaming points garak's OpenAI-compatible generator at the Pythia gateway (D6). "
    "Launching a campaign against this target returns HTTP 501."
)


def pythia_connection() -> dict[str, Any]:
    """Connection shape for the Phase B LLM target: env var names, the chat path, and whether each is set."""
    present = {key: bool(os.environ.get(var, "").strip()) for key, var in PYTHIA_ENV.items()}
    model_var = next((v for v in MODEL_ENV_CANDIDATES if os.environ.get(v, "").strip()), None)
    return {
        "gateway": "pythia",
        "chat_path": CHAT_PATH,
        "auth": "Authorization: Bearer pk_... (PYTHIA_API_KEY)",
        "persona_header": "X-Pythia-Persona",
        "env": {**PYTHIA_ENV, "model": " | ".join(MODEL_ENV_CANDIDATES)},
        "set": {**present, "model": model_var is not None},
        "configured": present["base_url"] and present["api_key"] and model_var is not None,
    }


class LLMEndpointStub:
    """Registered placeholder for the ``llm`` domain. Satisfies the Target protocol, implements nothing."""

    id = "endpoint_stub"

    def info(self) -> TargetInfo:
        return TargetInfo(
            id=self.id,
            name="LLM / black-box endpoint (Phase B, not implemented)",
            domain="llm",
            status="not_implemented",
            reason=REASON,
            metadata={"phase": "B", "kind": "ml_model_endpoint", "connection": pythia_connection()},
        )

    def _refuse(self) -> NoReturn:
        raise TargetUnavailable(f"{self.id}: {REASON}")

    def load(self) -> None:
        self._refuse()

    def sample(self, n: int, seed: int) -> Sample:
        self._refuse()

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        self._refuse()

    def art_classifier(self) -> Any:
        self._refuse()

    def torch_model(self) -> Any:
        self._refuse()

    def manifest(self) -> dict[str, Any]:
        return {"id": self.id, "status": "not_implemented", "phase": "B", "reason": REASON,
                "connection": pythia_connection()}


ENDPOINT_STUB = LLMEndpointStub() if "endpoint_stub" not in TARGETS else TARGETS.get("endpoint_stub")
if "endpoint_stub" not in TARGETS:
    TARGETS.register(ENDPOINT_STUB)

__all__ = ["CHAT_PATH", "ENDPOINT_STUB", "MODEL_ENV_CANDIDATES", "PYTHIA_ENV", "REASON", "LLMEndpointStub",
           "pythia_connection"]
