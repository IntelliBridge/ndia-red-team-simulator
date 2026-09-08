"""``redsim plugins list`` — inspect the community adapter marketplace.

Surfaces :func:`redsim.plugins.discover_all` (the read-only discovery report) as
either a human-readable table or a ``--json`` array. Discovery is gated by
``REDSIM_PLUGINS=1``; when it's off this command prints a clear hint and exits 0
rather than silently returning nothing.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from redsim.cli import _console
from redsim.plugins import discover_all

if TYPE_CHECKING:
    import argparse

    from redsim.config import RedsimConfig


def cmd_plugins(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Dispatch the ``plugins`` subcommands (``list`` / ``sign``)."""
    action = getattr(args, "plugins_action", None)
    if action == "list":
        _cmd_plugins_list(args, config)
    elif action == "sign":
        _cmd_plugins_sign(args, config)
    else:  # pragma: no cover - argparse marks the subparser required
        _console._err(f"Unknown plugins action: {action}")
        raise SystemExit(2)


def _cmd_plugins_list(args: argparse.Namespace, config: RedsimConfig) -> None:
    discovery_on = os.environ.get("REDSIM_PLUGINS") == "1"
    plugins = discover_all()

    if getattr(args, "json", False):
        print(json.dumps([p.to_dict() for p in plugins], indent=2))
        return

    if not discovery_on:
        _console._warn(
            "plugin discovery is disabled; set REDSIM_PLUGINS=1 to enable "
            "third-party adapter discovery"
        )
        return

    if not plugins:
        _console._info("no third-party plugins discovered")
        return

    _console._info(f"{len(plugins)} third-party plugin(s) discovered")
    print()
    hdr_fmt = "{:<22}  {:<8}  {:<22}  {:<12}  {:<9}  {:<13}  {}"
    print(hdr_fmt.format(
        "NAME", "KIND", "DISTRIBUTION", "VERSION", "STATUS", "SIGNED", "DETAIL"))
    print("-" * 110)
    for p in plugins:
        print(hdr_fmt.format(
            _trunc(p.name, 22),
            _trunc(p.kind, 8),
            _trunc(p.distribution or "-", 22),
            _trunc(p.version or "-", 12),
            _trunc(p.status, 9),
            _signed_cell(p.signature),
            p.detail or "",
        ))


def _signed_cell(signature: str | None) -> str:
    """Render the SIGNED column: a short key_id prefix, or ``-`` when unsigned.

    Signature enforcement is opt-in, so most rows show ``-``. When a plugin was
    verified we show ``yes:<first-12-of-key_id>`` so the operator can tell which
    trusted key vouched for it without dumping the full digest.
    """
    if not signature:
        return "-"
    return f"yes:{signature[:12]}"


def _cmd_plugins_sign(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Sign a plugin distribution, producing the detached ``.sig`` file.

    Resolves the ``--entry-point GROUP:NAME`` to its factory, signs the
    canonical payload (dist/version + factory-module digest) with the Ed25519
    private key at ``--key``, and writes ``<dist>-<version>.sig`` under ``--out``
    (default: the current directory). Prints the output path + verifying key_id.
    """
    from redsim.supply_chain.signing import sign_plugin_distribution

    factory = _load_entry_point_factory(args.entry_point)
    out_dir = getattr(args, "out", None) or "."
    try:
        out_path = sign_plugin_distribution(
            args.key, args.dist, args.version, factory, out_dir,
        )
    except (OSError, ValueError) as exc:
        _console._err(f"signing failed: {exc}")
        raise SystemExit(1) from exc

    key_id = _public_key_id_for(args.key)
    _console._info(f"wrote signature: {out_path}")
    _console._info(f"signed by key_id: {key_id}")


def _load_entry_point_factory(spec: str) -> object:
    """Resolve a ``GROUP:NAME`` entry-point spec to its loaded factory callable.

    Exits 2 on a malformed spec and 1 when no matching entry point is found, so
    a plugin author gets a clear message rather than a traceback.
    """
    if ":" not in spec:
        _console._err("--entry-point must be GROUP:NAME (e.g. redsim.scanners:example)")
        raise SystemExit(2)
    group, _, name = spec.partition(":")
    from importlib.metadata import entry_points

    for ep in entry_points(group=group):
        if ep.name == name:
            factory: object = ep.load()
            return factory
    _console._err(f"no entry point {name!r} in group {group!r}")
    raise SystemExit(1)


def _public_key_id_for(private_key_pem_path: str) -> str:
    """Derive the trusted-key id (sha256 of the public key) from a private PEM."""
    import hashlib

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with open(private_key_pem_path, "rb") as fh:
        priv = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        return "unknown"
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def _trunc(value: str, width: int) -> str:
    if len(value) > width:
        return value[: width - 3] + "..."
    return value
