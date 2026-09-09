"""Scanner/attack adapter registry.

The pentest scanner adapters that shipped with Redsim were removed for the
adversarial-ML red-team fork. The one built-in adapter is the ``ml-campaign``
facade (``redsim.ml.campaign_adapter.CampaignScannerAdapter``, capabilities
``adversarial_ml`` and ``explainability``), registered here at import so the
doctor roster, ``dispatch()`` and ``GET /v1/scanners`` see the ML vertical.
Third-party scanner adapters still load via the ``redsim.scanners`` entry-point
group when ``REDSIM_PLUGINS=1``, and third-party ART attack adapters via the
``redsim.ml.attacks`` group under the same flag, allowlist and signature gate
(``redsim.plugins.load_ml_attack_plugins``).
"""

from redsim.scanners.registry import (  # noqa: F401
    KNOWN_CAPABILITIES,
    ScannerAdapter,
    ScanOptions,
    ScanResult,
    dispatch,
    get,
    list_scanners,
    maybe_load_entry_points,
    register,
)


def _register_builtin_adapters() -> None:
    # Imported here, not at module top: ``redsim.ml.campaign_adapter`` imports
    # nothing from this package at module level, so either import order works.
    from redsim.ml.campaign_adapter import register_campaign_adapter

    register_campaign_adapter()


def maybe_load_ml_attack_entry_points() -> None:
    """Opt-in ``redsim.ml.attacks`` discovery; a no-op (and no ML import) unless ``REDSIM_PLUGINS=1``."""
    from redsim.plugins import load_ml_attack_plugins

    load_ml_attack_plugins()


_register_builtin_adapters()
maybe_load_entry_points()
maybe_load_ml_attack_entry_points()
