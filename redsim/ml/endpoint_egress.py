"""Egress policy for black-box endpoint targets (register ENDPOINT-07). Standard library only.

One policy, applied at two moments:

* :func:`check_registration_url` — static. The API runs it at ``POST /v1/models``
  (``source="endpoint"``) and the worker runs it again before every ``model.load``
  (each campaign job). It parses the URL and refuses anything the worker would never
  be allowed to reach; nothing is resolved and nothing leaves the process.
* :func:`check_request_host` — connect time. The worker-parent ``PredictBroker``
  (ENDPOINT-05) runs it before a socket is opened: the host is resolved once, every
  address is classified, one address is pinned on the :class:`EgressSession` and the
  transport connects to that pinned address with the original hostname as SNI /
  ``Host`` and redirects disabled. A later resolution that no longer contains the
  pin, or an attempt to connect elsewhere (:meth:`EgressSession.verify_pin`), is
  refused as DNS rebinding.

Rules (spec 9.1 rule 4, 21.7, 20.4):

a. The host must match ``config.target_allowlist`` — exact host, literal IP or CIDR
   membership, the same semantics as ``redsim.safety.is_target_allowed`` (the
   positive egress allowlist; the default is loopback only). Otherwise
   ``endpoint_not_allowlisted``.
b. Userinfo, query strings and fragments are refused; so are schemes other than
   ``https`` / ``http``, malformed or non-ASCII hosts, IPv6 zone ids, ports outside
   ``1..65535``, whitespace and URLs over :data:`MAX_URL_LENGTH`. ``endpoint_url_invalid``.
c. ``https`` is required unless the host is loopback (``127.0.0.0/8``, ``::1``,
   ``localhost``, the compose alias ``host.docker.internal``) or a private /
   link-local literal IP the allowlist names as that literal or as a private CIDR
   (the dev / compose demo endpoint). Plaintext is recorded on
   :attr:`ParsedEndpoint.plaintext`; otherwise ``endpoint_url_invalid`` (rule ``plaintext``).
d. A literal or resolved address that is loopback, private, link-local, multicast,
   reserved or unspecified is refused unless the allowlist names it as that literal
   IP or as a CIDR that is itself private space and contains it (``0.0.0.0/0``
   exempts nothing); ``localhost`` / ``host.docker.internal`` may resolve to loopback
   or private space; any other hostname resolving to loopback is refused outright.
   Multicast, reserved and unspecified addresses are never exempt. ``egress_refused``.
e. Resolution failures, empty answers and rebinding are ``egress_refused``.

Every refusal is an :class:`EgressRefused` (or subclass) whose ``code`` is one of the
three spec 17.3 codes (added to ``redsim.api.errors`` by the actions-and-codes track
this wave) and whose ``rule`` names the clause. Messages carry the host and the rule,
never the URL's userinfo, query or fragment, so they are safe for audit rows.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from redsim.ml.errors import MLError

ENDPOINT_URL_INVALID: Final = "endpoint_url_invalid"
ENDPOINT_NOT_ALLOWLISTED: Final = "endpoint_not_allowlisted"
EGRESS_REFUSED: Final = "egress_refused"
EgressCode = Literal["endpoint_url_invalid", "endpoint_not_allowlisted", "egress_refused"]
EGRESS_CODES: Final[tuple[str, ...]] = (ENDPOINT_URL_INVALID, ENDPOINT_NOT_ALLOWLISTED, EGRESS_REFUSED)

#: Hostnames that stand for the local machine (mirrors ``redsim.safety._LOOPBACK_HOSTS``).
LOOPBACK_HOSTNAMES: Final = frozenset({"localhost", "host.docker.internal"})
MAX_URL_LENGTH: Final = 2048
DEFAULT_PORTS: Final[dict[str, int]] = {"https": 443, "http": 80}

AddressClass = Literal["public", "loopback", "private", "link_local", "multicast", "reserved", "unspecified"]
#: Address classes no allowlist entry can exempt: nothing legitimate listens there.
NEVER_EXEMPT: Final = frozenset({"multicast", "reserved", "unspecified"})

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
#: ``(host, port) -> addresses`` as strings; the default wraps ``socket.getaddrinfo``.
Resolver = Callable[[str, int], Sequence[str]]

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class EgressRefused(MLError):
    """Egress policy refusal. ``code`` is the spec 17.3 code, ``rule`` the clause that fired."""

    code: str = EGRESS_REFUSED

    def __init__(self, rule: str, message: str, *, host: str | None = None, address: str | None = None) -> None:
        super().__init__(f"{self.code} ({rule}): {message}")
        self.rule = rule
        self.reason = message
        self.host = host
        self.address = address

    def detail(self) -> dict[str, Any]:
        """Audit-row detail: code, rule, host and address only; never a URL with userinfo or query."""
        out: dict[str, Any] = {"code": self.code, "rule": self.rule, "reason": self.reason}
        if self.host is not None:
            out["host"] = self.host
        if self.address is not None:
            out["address"] = self.address
        return out


class EndpointUrlInvalid(EgressRefused):
    """Rule b or c: the URL's shape is not one the connector accepts (HTTP 422)."""

    code = ENDPOINT_URL_INVALID


class EndpointNotAllowlisted(EgressRefused):
    """Rule a: the host is not in ``config.target_allowlist`` (HTTP 403 after the failed audit row)."""

    code = ENDPOINT_NOT_ALLOWLISTED


@dataclass(frozen=True)
class ParsedEndpoint:
    """A registration URL that passed the static rules."""

    #: Normalised: lower-case host, default port dropped, no userinfo/query/fragment.
    url: str
    scheme: str
    #: Lower-case; IPv6 literals without brackets.
    host: str
    port: int
    path: str
    literal_ip: bool
    #: Class of a literal-IP host; ``"hostname"`` when the host must be resolved.
    address_class: str
    #: The ``target_allowlist`` entry that admitted the host.
    allowlist_entry: str
    #: ``http`` was accepted under rule c.
    plaintext: bool
    #: ``http`` to a loopback host specifically (the register's ``plaintext_loopback`` flag).
    plaintext_loopback: bool

    def address(self) -> IPAddress | None:
        return _literal_ip(self.host) if self.literal_ip else None


@dataclass(frozen=True)
class ResolvedHost:
    """A host that passed the connect-time rules; connect to ``pinned`` with ``host`` as SNI / ``Host``."""

    host: str
    addresses: tuple[str, ...]
    pinned: str
    literal_ip: bool
    allowlist_entry: str


@dataclass
class EgressSession:
    """Per-job pin store: the first permitted address of each host, kept for the session."""

    pins: dict[str, str] = field(default_factory=dict)

    def pinned(self, host: str) -> str | None:
        return self.pins.get(_normalise_host(host))

    def verify_pin(self, host: str, address: str) -> None:
        """Refuse a connection to any address other than the one pinned for ``host``."""
        host_n = _normalise_host(host)
        pin = self.pins.get(host_n)
        if pin is None:
            raise EgressRefused("dns_rebinding", f"no address is pinned for {host_n!r}; run check_request_host first",
                                host=host_n, address=address)
        if _canonical(address) != pin:
            raise EgressRefused("dns_rebinding", f"connection to {address} refused; {host_n!r} is pinned to {pin}",
                                host=host_n, address=address)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise_host(host: str) -> str:
    return host.strip().strip("[]").lower()


def _literal_ip(host: str) -> IPAddress | None:
    """The address a host literal denotes, or ``None`` for a hostname. Zone ids are refused."""
    if "%" in host:
        raise EndpointUrlInvalid("host", "IPv6 zone identifiers are not permitted", host=host)
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _canonical(address: str) -> str:
    try:
        return str(ipaddress.ip_address(address.strip().strip("[]")))
    except ValueError:
        return address


def _valid_hostname(host: str) -> bool:
    if not host or len(host) > 253 or not host.isascii() or host.endswith("."):
        return False
    labels = host.split(".")
    if labels[-1].isdigit():  # a numeric last label is not a DNS hostname; inet_aton would reinterpret it
        return False
    return all(_LABEL.match(label) for label in labels)


def classify_address(address: IPAddress | str) -> AddressClass:
    """Class of an address; IPv4 embedded in IPv6 (mapped, 6to4, Teredo) is classified by the IPv4."""
    ip = ipaddress.ip_address(address) if isinstance(address, str) else address
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if embedded is not None:
            inner = classify_address(embedded)
            if inner != "public":
                return inner
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private:
        return "private"
    if ip.is_global:
        return "public"
    return "reserved"


def _entry_ip(entry: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(entry.strip("[]"))
    except ValueError:
        return None


def _entry_network(entry: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if "/" not in entry:
        return None
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def allowlist_match(host: str, allowlist: Sequence[str]) -> tuple[str, str] | None:
    """``(entry, kind)`` for the first allowlist entry admitting ``host``; kind is ``host``, ``ip`` or ``cidr``.

    Same acceptance as ``redsim.safety.is_target_allowed``: exact host string, or CIDR
    membership when the host is a literal IP (a literal entry is a /32 or /128).
    """
    host_n = _normalise_host(host)
    ip = _literal_ip(host_n)
    for raw in allowlist:
        entry = str(raw).strip().lower()
        if not entry:
            continue
        if ip is not None:
            entry_ip = _entry_ip(entry)
            if entry_ip is not None:
                if entry_ip == ip:
                    return entry, "ip"
                continue
            network = _entry_network(entry)
            if network is not None:
                if ip.version == network.version and ip in network:
                    return entry, "cidr"
                continue
        if entry.strip("[]") == host_n:
            return entry, "host"
    return None


def _address_exempt(address: IPAddress, address_class: str, host: str, allowlist: Sequence[str]) -> bool:
    """Rule d exemption: the allowlist names this address literally, or as a private CIDR containing it."""
    if address_class in NEVER_EXEMPT:
        return False
    loopback_alias = host in LOOPBACK_HOSTNAMES and address_class in ("loopback", "private")
    for raw in allowlist:
        entry = str(raw).strip().lower()
        if not entry:
            continue
        entry_ip = _entry_ip(entry)
        if entry_ip is not None:
            if entry_ip == address:
                return True
            continue
        network = _entry_network(entry)
        if network is not None:
            if network.is_private and address.version == network.version and address in network:
                return True
            continue
        if loopback_alias and entry.strip("[]") == host:
            return True
    return False


def _system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


# ---------------------------------------------------------------------------
# Static check (registration and every model.load)
# ---------------------------------------------------------------------------


def check_registration_url(url: str, allowlist: Sequence[str]) -> ParsedEndpoint:
    """Rules a-d on the URL alone (no resolution). Raises :class:`EgressRefused` subclasses."""
    if not isinstance(url, str) or not url:
        raise EndpointUrlInvalid("url", "url must be a non-empty string")
    if len(url) > MAX_URL_LENGTH:
        raise EndpointUrlInvalid("url", f"url exceeds {MAX_URL_LENGTH} characters")
    if not url.isascii() or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        raise EndpointUrlInvalid("url", "url contains whitespace, control or non-ASCII characters")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise EndpointUrlInvalid("scheme", f"scheme must be https (http only for loopback), got {scheme or 'none'!r}")
    hostname = parts.hostname or ""
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise EndpointUrlInvalid("userinfo", "userinfo (user:password@) is not permitted in an endpoint URL",
                                 host=hostname or None)
    if parts.query or "?" in url:
        raise EndpointUrlInvalid("query", "query strings are not permitted in an endpoint URL",
                                 host=hostname or None)
    if parts.fragment or "#" in url:
        raise EndpointUrlInvalid("fragment", "fragments are not permitted in an endpoint URL",
                                 host=hostname or None)
    if not hostname:
        raise EndpointUrlInvalid("host", "url has no host")
    try:
        port = parts.port
    except ValueError:
        raise EndpointUrlInvalid("port", "port is not a valid integer", host=hostname) from None
    if port is None:
        port = DEFAULT_PORTS[scheme]
    if not 1 <= port <= 65535:
        raise EndpointUrlInvalid("port", f"port {port} is outside 1..65535", host=hostname)
    ip = _literal_ip(hostname)
    if ip is None and not _valid_hostname(hostname):
        raise EndpointUrlInvalid("host", f"{hostname!r} is not a valid hostname or IP literal", host=hostname)
    path = parts.path or "/"

    match = allowlist_match(hostname, allowlist)
    if match is None:
        raise EndpointNotAllowlisted("not_allowlisted", f"host {hostname!r} is not in target_allowlist", host=hostname)
    entry, _kind = match

    address_class: str = "hostname"
    if ip is not None:
        address_class = classify_address(ip)
        if address_class != "public" and not _address_exempt(ip, address_class, hostname, allowlist):
            raise EgressRefused(
                "address_class",
                f"literal address {hostname} is {address_class}; the allowlist must name it as that literal IP "
                f"or a private CIDR containing it" if address_class not in NEVER_EXEMPT
                else f"literal address {hostname} is {address_class}; no allowlist entry can permit it",
                host=hostname, address=str(ip),
            )

    loopback = hostname in LOOPBACK_HOSTNAMES or address_class == "loopback"
    plaintext = scheme == "http"
    if plaintext and not loopback and not (ip is not None and address_class in ("private", "link_local")):
        raise EndpointUrlInvalid(
            "plaintext",
            f"http is only permitted for loopback or allowlisted private literal addresses; {hostname!r} needs https",
            host=hostname,
        )

    host_repr = f"[{hostname}]" if ip is not None and ip.version == 6 else hostname
    port_repr = "" if port == DEFAULT_PORTS[scheme] else f":{port}"
    return ParsedEndpoint(
        url=f"{scheme}://{host_repr}{port_repr}{path}", scheme=scheme, host=hostname, port=port, path=path,
        literal_ip=ip is not None, address_class=address_class, allowlist_entry=entry, plaintext=plaintext,
        plaintext_loopback=plaintext and loopback,
    )


# ---------------------------------------------------------------------------
# Connect-time check (worker parent, before any socket is opened)
# ---------------------------------------------------------------------------


def resolve_and_check(host: str, allowlist: Sequence[str], *, port: int = 443,
                      resolver: Resolver | None = None) -> tuple[str, ...]:
    """Rule d and e for every address ``host`` resolves to. A literal IP resolves to itself.

    The allowlist is consulted only for exemptions here; :func:`check_request_host` adds
    the rule a host match and the session pin.
    """
    host_n = _normalise_host(host)
    ip = _literal_ip(host_n)
    addresses: list[IPAddress]
    if ip is not None:
        addresses = [ip]
    else:
        if not _valid_hostname(host_n):
            raise EndpointUrlInvalid("host", f"{host_n!r} is not a valid hostname or IP literal", host=host_n)
        try:
            raw = list((resolver or _system_resolver)(host_n, port))
        except (OSError, UnicodeError) as exc:  # socket.gaierror is an OSError
            raise EgressRefused("dns_failure", f"could not resolve {host_n!r}: {type(exc).__name__}",
                                host=host_n) from exc
        addresses = []
        for item in raw:
            try:
                parsed = ipaddress.ip_address(str(item).strip().strip("[]"))
            except ValueError:
                raise EgressRefused("dns_failure", f"resolver returned a non-address for {host_n!r}",
                                    host=host_n) from None
            if parsed not in addresses:
                addresses.append(parsed)
        if not addresses:
            raise EgressRefused("dns_empty", f"{host_n!r} resolved to no address", host=host_n)
    for address in addresses:
        address_class = classify_address(address)
        if address_class == "public":
            continue
        if address_class == "loopback" and ip is None and host_n not in LOOPBACK_HOSTNAMES:
            raise EgressRefused("address_class", f"{host_n!r} resolves to the loopback address {address}",
                                host=host_n, address=str(address))
        if not _address_exempt(address, address_class, host_n, allowlist):
            raise EgressRefused(
                "address_class",
                f"{host_n!r} resolves to {address} ({address_class}); the allowlist does not name it as a literal IP"
                f" or a private CIDR containing it" if address_class not in NEVER_EXEMPT
                else f"{host_n!r} resolves to {address} ({address_class}); no allowlist entry can permit it",
                host=host_n, address=str(address),
            )
    return tuple(str(address) for address in addresses)


def check_request_host(host: str, allowlist: Sequence[str], *, session: EgressSession | None = None,
                       port: int = 443, resolver: Resolver | None = None, recheck: bool = False) -> ResolvedHost:
    """Rules a, d and e at connect time, with the session pin.

    First call for a host: resolve once, check every address, pin the first one. Later
    calls return the pin without resolving again; with ``recheck=True`` the host is
    resolved again and a set that no longer contains the pin is refused (``dns_rebinding``).
    """
    host_n = _normalise_host(host)
    ip = _literal_ip(host_n)
    match = allowlist_match(host_n, allowlist)
    if match is None:
        raise EndpointNotAllowlisted("not_allowlisted", f"host {host_n!r} is not in target_allowlist", host=host_n)
    entry, _kind = match
    pin = session.pins.get(host_n) if session is not None else None
    if pin is not None and not recheck:
        return ResolvedHost(host=host_n, addresses=(pin,), pinned=pin, literal_ip=ip is not None,
                            allowlist_entry=entry)
    addresses = resolve_and_check(host_n, allowlist, port=port, resolver=resolver)
    if pin is not None:
        if pin not in addresses:
            raise EgressRefused("dns_rebinding", f"{host_n!r} no longer resolves to the pinned address {pin}",
                                host=host_n, address=pin)
        pinned = pin
    else:
        pinned = addresses[0]
        if session is not None:
            session.pins[host_n] = pinned
    return ResolvedHost(host=host_n, addresses=addresses, pinned=pinned, literal_ip=ip is not None,
                        allowlist_entry=entry)


class EgressPolicy:
    """The allowlist plus a session pin store; one per job in the broker, one per request in the API."""

    def __init__(self, allowlist: Sequence[str], *, resolver: Resolver | None = None) -> None:
        self.allowlist: tuple[str, ...] = tuple(str(entry) for entry in allowlist)
        self.session = EgressSession()
        self._resolver = resolver

    def check_registration_url(self, url: str) -> ParsedEndpoint:
        return check_registration_url(url, self.allowlist)

    def resolve_and_check(self, host: str, *, port: int = 443) -> tuple[str, ...]:
        return resolve_and_check(host, self.allowlist, port=port, resolver=self._resolver)

    def check_request_host(self, host: str, *, port: int = 443, recheck: bool = False) -> ResolvedHost:
        return check_request_host(host, self.allowlist, session=self.session, port=port,
                                  resolver=self._resolver, recheck=recheck)

    def check_endpoint(self, url: str) -> tuple[ParsedEndpoint, ResolvedHost]:
        """Both moments at once: the ``model.load`` re-check before the broker connects."""
        parsed = self.check_registration_url(url)
        resolved = self.check_request_host(parsed.host, port=parsed.port)
        return parsed, resolved


__all__ = [
    "EGRESS_CODES", "EGRESS_REFUSED", "ENDPOINT_NOT_ALLOWLISTED", "ENDPOINT_URL_INVALID", "LOOPBACK_HOSTNAMES",
    "MAX_URL_LENGTH", "NEVER_EXEMPT", "AddressClass", "EgressCode", "EgressPolicy", "EgressRefused",
    "EgressSession", "EndpointNotAllowlisted", "EndpointUrlInvalid", "ParsedEndpoint", "ResolvedHost",
    "Resolver", "allowlist_match", "check_registration_url", "check_request_host", "classify_address",
    "resolve_and_check",
]
