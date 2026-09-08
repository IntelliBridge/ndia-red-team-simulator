"""Catalog entry for the deferred LLM evaluation domain."""

from redsim.targets.unavailable import UnavailableTarget


class LlmTarget(UnavailableTarget):
    id = "llm"
    name = "LLM assistant via Pythia"
    domain = "llm"
    reason = "LLM evaluation is outside the first milestone; this entry documents the future connection only."
    metadata = {
        "gateway": "Pythia",
        "protocol": "OpenAI-compatible",
        "base_url_env": "PYTHIA_BASE_URL",
        "api_key_env": "PYTHIA_API_KEY",
        "persona_env": "PYTHIA_PERSONA",
        "model_env": "REDSIM_LLM_MODEL",
        "model_id_format": "<vendor>/<model>",
        "launch_behavior": "HTTP 501 Not Implemented",
    }