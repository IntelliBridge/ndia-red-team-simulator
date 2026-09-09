"""Community scanner/attack adapter marketplace: discovery + reporting.

The :class:`~redsim.registry.Registry` owns the scanner discovery code path
(:meth:`~redsim.registry.Registry.scan_entry_points`). This module layers the
public, read-only *report* on top of it: :func:`discover_all` scans the
``redsim.scanners`` entry-point group and returns a :class:`PluginInfo` per
third-party item, *without* mutating the global registry (``register=False``).
Built-ins never appear because they are registered eagerly in code, not via
entry points — discovery only ever walks the entry-point groups, so there is no
double-counting.

The adversarial-ML attack adapters have their own group, ``redsim.ml.attacks``
(spec 12.1). They are keyed by ``id`` and register into the id-keyed
``redsim.ml.attacks.registry.ATTACKS`` rather than the name-keyed scanner
registry, so :func:`scan_ml_attack_entry_points` walks that group with the same
gates the scanner path applies: the ``REDSIM_PLUGINS_ALLOW`` distribution
allowlist, structural conformance (``AttackAdapter`` protocol, a non-empty
``id``, capability tags inside ``KNOWN_ATTACK_CAPABILITIES``), and the optional
Ed25519 signature gate (``load_plugin_verifier``). :func:`discover_all` reports
that group too (``kind="attack"``); :func:`load_ml_attack_plugins` is the eager
loader the offline CLI and ``redsim.scanners`` call, and it never replaces a
built-in attack id.

Discovery is gated by ``REDSIM_PLUGINS=1`` and (optionally) the
``REDSIM_PLUGINS_ALLOW`` distribution allowlist; see the README/docs for the
full contract.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redsim.supply_chain.signing import PluginVerifier

logger = logging.getLogger(__name__)

SCANNERS_GROUP = "redsim.scanners"
ML_ATTACKS_GROUP = "redsim.ml.attacks"
PLUGINS_ENV = "REDSIM_PLUGINS"


@dataclass
class PluginInfo:
    """One row of the plugin-discovery report.

    ``status`` is ``"loaded"`` (conformant, registered/registrable),
    ``"rejected"`` (failed to load or non-conformant — never registered), or
    ``"skipped"`` (excluded by ``REDSIM_PLUGINS_ALLOW``). ``detail`` carries the
    reason for rejected/skipped rows and is ``""`` for loaded ones.

    ``signature`` is the verifying key_id (sha256 of the trusted public key)
    when optional signature enforcement is enabled and the plugin's signature
    verified, else ``None`` (enforcement off, or no/invalid signature). It
    defaults to ``None`` so the dataclass stays backward-compatible.
    """

    name: str
    kind: str            # "scanner" | "attack"
    group: str           # "redsim.scanners" | "redsim.ml.attacks"
    distribution: str | None
    version: str | None
    status: str          # "loaded" | "rejected" | "skipped"
    detail: str
    signature: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def plugins_enabled() -> bool:
    return os.environ.get(PLUGINS_ENV) == "1"


def discover_all() -> list[PluginInfo]:
    """Report third-party scanner and attack plugins without registering them.

    Returns ``[]`` when ``REDSIM_PLUGINS != 1`` (discovery disabled). Otherwise
    walks the scanner entry-point group through the shared
    :meth:`~redsim.registry.Registry.scan_entry_points` path and the
    ``redsim.ml.attacks`` group through :func:`scan_ml_attack_entry_points`,
    both with ``register=False`` so the registries are left untouched.
    """
    if not plugins_enabled():
        return []

    # Imported lazily so importing this module never drags in the scanner
    # subsystem (and its eager built-in registration) until discovery runs.
    from redsim.scanners.registry import _scanner_registry
    from redsim.supply_chain.signing import load_plugin_verifier

    # Same supply-chain gate as the eager loader: when enforcement is on the
    # report reflects which plugins would be rejected for a missing/invalid
    # signature (and surfaces the verifying key_id on the loaded rows).
    verifier = load_plugin_verifier()

    results: list[PluginInfo] = []
    results.extend(_scanner_registry.scan_entry_points(
        SCANNERS_GROUP, register=False, verifier=verifier))
    results.extend(scan_ml_attack_entry_points(register=False, verifier=verifier))
    return results


# ---------------------------------------------------------------------------
# redsim.ml.attacks group
# ---------------------------------------------------------------------------


def scan_ml_attack_entry_points(
    *,
    register: bool,
    verifier: PluginVerifier | None = None,
) -> Iterator[PluginInfo]:
    """Walk the ``redsim.ml.attacks`` entry points once, yielding a PluginInfo per item.

    Mirrors :meth:`redsim.registry.Registry.scan_entry_points` for the id-keyed
    attack registry: allowlist gate, factory load, conformance (``AttackAdapter``
    protocol, non-empty ``id``, capability tags in the known vocabulary), the
    optional signature gate, then registration through ``register_attack`` when
    ``register`` is true. A plugin whose ``id`` collides with a registered attack
    (a built-in or an earlier plugin) is rejected, never substituted. Every
    per-plugin failure is a ``rejected`` row, so one bad plugin cannot break the
    others. The caller owns the ``REDSIM_PLUGINS=1`` gate.
    """
    from redsim.registry import _allowlist, _dist_meta

    try:
        from importlib.metadata import entry_points
        eps = list(entry_points(group=ML_ATTACKS_GROUP))
    except Exception:  # noqa: BLE001  # pragma: no cover - importlib edge
        return
    if not eps:
        return

    # The attack registry imports numpy; only pay for it when the group is non-empty.
    from redsim.ml.attacks.base import AttackAdapter
    from redsim.ml.attacks.registry import ATTACKS, attack_capabilities, register_attack

    allow = _allowlist()
    for ep in eps:
        dist_name, version = _dist_meta(ep)

        def _info(name: str, status: str, detail: str, signature: str | None = None, *,
                  dist_name: str | None = dist_name, version: str | None = version) -> PluginInfo:
            return PluginInfo(name=name, kind="attack", group=ML_ATTACKS_GROUP, distribution=dist_name,
                              version=version, status=status, detail=detail, signature=signature)

        if allow is not None and (dist_name is None or dist_name not in allow):
            yield _info(ep.name, "skipped", "distribution not in REDSIM_PLUGINS_ALLOW")
            continue
        try:
            factory = ep.load()
            item = factory()
        except Exception as exc:  # noqa: BLE001 - third-party plugin failure is isolated
            yield _info(ep.name, "rejected", f"factory failed: {exc}")
            continue
        if not isinstance(item, AttackAdapter):
            yield _info(ep.name, "rejected", "does not satisfy AttackAdapter protocol")
            continue
        item_id = getattr(item, "id", None)
        if not isinstance(item_id, str) or not item_id:
            yield _info(ep.name, "rejected", "missing non-empty string 'id'")
            continue
        try:
            attack_capabilities(item)
        except Exception as exc:  # noqa: BLE001 - info() or the tag check failed inside plugin code
            yield _info(ep.name, "rejected", f"capability check failed: {exc}")
            continue
        signature: str | None = None
        if verifier is not None:
            result = verifier.verify(dist_name or ep.name, version, factory)
            if not result.verified:
                yield _info(ep.name, "rejected", f"signature rejected: {result.reason}")
                continue
            signature = result.key_id
        if item_id in ATTACKS:
            yield _info(item_id, "rejected", f"attack id {item_id!r} is already registered; plugins never "
                                             "replace a registered attack")
            continue
        if register:
            try:
                register_attack(item)
            except Exception as exc:  # noqa: BLE001 - registration refusal is reported, not raised
                yield _info(item_id, "rejected", f"registration failed: {exc}")
                continue
        yield _info(item_id, "loaded", "", signature=signature)


def load_ml_attack_plugins() -> list[PluginInfo]:
    """Discover and register third-party attack adapters, gated by ``REDSIM_PLUGINS=1``.

    Returns the discovery rows (empty when the flag is off, and then imports
    nothing from the ML packages). Rejected rows are logged at WARNING, as the
    scanner loader does.
    """
    if not plugins_enabled():
        return []
    from redsim.supply_chain.signing import load_plugin_verifier

    rows = list(scan_ml_attack_entry_points(register=True, verifier=load_plugin_verifier()))
    for info in rows:
        if info.status == "rejected":
            logger.warning("rejected attack plugin %r: %s", info.name, info.detail)
    return rows


__all__ = [
    "ML_ATTACKS_GROUP",
    "PLUGINS_ENV",
    "SCANNERS_GROUP",
    "PluginInfo",
    "discover_all",
    "load_ml_attack_plugins",
    "plugins_enabled",
    "scan_ml_attack_entry_points",
]
