"""Scanner/attack adapter registry.

The pentest scanner adapters that shipped with Aegis were removed for the
adversarial-ML red-team fork. Adapters for ART attacks register through the
same registry (see ``aegis/ml/attacks``); third-party adapters still load via
the ``aegis.scanners`` entry-point group when ``AEGIS_PLUGINS=1``.
"""

from aegis.scanners.registry import (  # noqa: F401
    KNOWN_CAPABILITIES,
    ScanOptions,
    ScannerAdapter,
    ScanResult,
    dispatch,
    get,
    list_scanners,
    maybe_load_entry_points,
    register,
)

maybe_load_entry_points()
