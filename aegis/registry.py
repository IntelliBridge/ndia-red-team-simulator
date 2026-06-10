"""Generic name-keyed registry shared by the scanner and agent subsystems.

Both subsystems were maintaining structurally identical ``_REGISTRY`` dicts
with their own ``register`` / ``get`` / ``list`` helpers. :class:`Registry`
collapses that duplication and adds an opt-in entry-point discovery hook
(:meth:`maybe_load_entry_points`) gated by ``AEGIS_PLUGINS=1`` so third-party
plugins can never perturb the offline test path.

Discovery is now a *single* code path. :meth:`scan_entry_points` walks the
entry points once and yields a :class:`~aegis.plugins.PluginInfo` per item,
deciding skip/reject/load against the allowlist, the registry's
``runtime_checkable`` Protocol, and a non-empty ``name``. Both the
side-effecting loader (:meth:`maybe_load_entry_points`, called eagerly from the
subsystem ``__init__`` modules) and the read-only reporter
(``aegis.plugins.discover_all``) consume that one generator, so there is no
duplicated scan logic and a single bad plugin can never crash discovery.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Callable, Generic, Iterator, Protocol, TypeVar, runtime_checkable

if TYPE_CHECKING:
    from aegis.plugins import PluginInfo

logger = logging.getLogger(__name__)


@runtime_checkable
class _Named(Protocol):
    name: str


T = TypeVar("T", bound=_Named)


def _allowlist() -> set[str] | None:
    """Parse ``AEGIS_PLUGINS_ALLOW`` into a set of distribution names.

    Returns ``None`` when unset/blank (no allowlist configured → every
    discovered plugin is eligible); otherwise the comma-separated names.
    """
    raw = os.environ.get("AEGIS_PLUGINS_ALLOW")
    if raw is None:
        return None
    names = {part.strip() for part in raw.split(",") if part.strip()}
    return names or None


def _dist_meta(ep: object) -> tuple[str | None, str | None]:
    """Best-effort ``(distribution_name, version)`` for an entry point.

    ``EntryPoint.dist`` is a ``Distribution`` (or ``None`` for fakes); reading
    its metadata is wrapped because third-party packaging is untrusted.
    """
    dist = getattr(ep, "dist", None)
    if dist is None:
        return None, None
    name = getattr(dist, "name", None)
    version = getattr(dist, "version", None)
    return name, version


class Registry(Generic[T]):
    """A ``name -> item`` table with an opt-in entry-point discovery hook.

    ``kind`` labels error messages and the discovery report (``"scanner"`` /
    ``"agent"``). ``protocol`` is the ``runtime_checkable`` Protocol every
    discovered item must structurally satisfy. ``validate`` is an optional hook
    invoked on each item at registration; it may log or raise, but a non-raising
    hook still registers the item (the open-vocabulary "warn but register"
    behaviour scanners rely on).
    """

    def __init__(
        self,
        kind: str,
        *,
        validate: Callable[[T], None] | None = None,
        protocol: type | None = None,
    ) -> None:
        self._kind = kind
        self._validate = validate
        self._protocol = protocol
        self._items: dict[str, T] = {}

    def register(self, item: T) -> None:
        if self._validate is not None:
            self._validate(item)
        self._items[item.name] = item

    def get(self, name: str) -> T:
        if name not in self._items:
            raise KeyError(f"unknown {self._kind}: {name!r}. "
                           f"available: {sorted(self._items)}")
        return self._items[name]

    def list_names(self) -> list[str]:
        return sorted(self._items)

    # -- discovery ---------------------------------------------------------

    def scan_entry_points(self, group: str, *, register: bool) -> Iterator[PluginInfo]:
        """Walk ``group``'s entry points once, yielding a PluginInfo per item.

        This is the single shared discovery path. ``register=True`` (the eager
        load path) also installs each ``loaded`` item into the registry;
        ``register=False`` (the report path) only inspects. Either way the
        allowlist gate, Protocol-conformance check, and non-empty-``name`` check
        are applied identically, and any per-plugin failure is captured as a
        ``rejected`` record rather than propagated — one bad plugin can never
        break the others or crash import.

        Caller is responsible for the ``AEGIS_PLUGINS=1`` gate; this method
        assumes discovery is enabled.
        """
        from aegis.plugins import PluginInfo

        try:
            from importlib.metadata import entry_points
            eps = list(entry_points(group=group))
        except Exception:  # pragma: no cover - importlib edge
            return

        allow = _allowlist()
        if allow is None:
            logger.warning(
                "AEGIS_PLUGINS=1 but no AEGIS_PLUGINS_ALLOW allowlist configured; "
                "loading third-party %s plugins is unrestricted", self._kind,
            )

        for ep in eps:
            dist_name, version = _dist_meta(ep)

            def _info(name: str, status: str, detail: str) -> PluginInfo:
                return PluginInfo(
                    name=name, kind=self._kind, group=group,
                    distribution=dist_name, version=version,
                    status=status, detail=detail,
                )

            if allow is not None and (dist_name is None or dist_name not in allow):
                yield _info(ep.name, "skipped",
                            "distribution not in AEGIS_PLUGINS_ALLOW")
                continue

            try:
                factory = ep.load()
                item = factory()
            except Exception as exc:  # third-party plugin failure
                yield _info(ep.name, "rejected", f"factory failed: {exc}")
                continue

            reason = self._conformance_error(item)
            if reason is not None:
                # Report the entry-point name; the adapter is untrusted.
                yield _info(ep.name, "rejected", reason)
                continue

            # Conformant: prefer the adapter's own ``name`` in the report.
            if register:
                try:
                    self.register(item)
                except Exception as exc:  # pragma: no cover - validate raised
                    yield _info(item.name, "rejected",
                                f"registration failed: {exc}")
                    continue
            yield _info(item.name, "loaded", "")

    def _conformance_error(self, item: object) -> str | None:
        """Return a concise reason string if ``item`` is non-conformant, else None."""
        if self._protocol is not None and not isinstance(item, self._protocol):
            return f"does not satisfy {self._protocol.__name__} protocol"
        name = getattr(item, "name", None)
        if not isinstance(name, str) or not name:
            return "missing non-empty string 'name'"
        return None

    def maybe_load_entry_points(self, group: str) -> None:
        """Discover and register third-party items, gated by AEGIS_PLUGINS=1.

        Side-effect-only: drains :meth:`scan_entry_points` with registration
        enabled. Kept as the eager-load entry point the subsystem ``__init__``
        modules call at import time.
        """
        if os.environ.get("AEGIS_PLUGINS") != "1":
            return
        for info in self.scan_entry_points(group, register=True):
            if info.status == "rejected":
                logger.warning(
                    "rejected %s plugin %r: %s", self._kind, info.name, info.detail,
                )
