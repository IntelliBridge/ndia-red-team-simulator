"""Supply-chain security primitives for Aegis.

Currently this package houses optional cryptographic *signature verification*
for third-party marketplace plugins (:mod:`aegis.supply_chain.signing`). The
signing seam layers onto the existing entry-point loader: when enforcement is
enabled (``AEGIS_PLUGINS_REQUIRE_SIGNATURE=1``) only plugins whose distribution
carries a valid Ed25519 signature from a trusted key are registered; unsigned or
invalid ones are rejected (never registered). Enforcement is off by default, so
the marketplace's existing behaviour is unchanged unless an operator opts in.
"""

from __future__ import annotations

from aegis.supply_chain.signing import (
    KeyringVerifier,
    PluginVerifier,
    SignatureResult,
    canonical_plugin_payload,
    compute_factory_digest,
    load_plugin_verifier,
    sign_plugin_distribution,
)

__all__ = [
    "KeyringVerifier",
    "PluginVerifier",
    "SignatureResult",
    "canonical_plugin_payload",
    "compute_factory_digest",
    "load_plugin_verifier",
    "sign_plugin_distribution",
]
