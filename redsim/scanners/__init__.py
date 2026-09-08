"""Scanner/attack adapter registry.

The pentest scanner adapters that shipped with Redsim were removed for the
adversarial-ML red-team fork. Adapters for ART attacks register through the
same registry (see ``redsim/ml/attacks``); third-party adapters still load via
the ``redsim.scanners`` entry-point group when ``REDSIM_PLUGINS=1``.
"""

from redsim.scanners.registry import (  # noqa: F401
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
