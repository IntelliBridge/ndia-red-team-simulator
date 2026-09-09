"""ENDPOINT-07: egress allowlist, private-address blocking and DNS pinning. Unit, no network.

``socket.getaddrinfo`` is monkeypatched wherever resolution happens; every other case
is a literal IP or refused before resolution.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from collections.abc import Sequence
from pathlib import Path

import pytest

from redsim import safety
from redsim.ml import endpoint_egress as eg
from redsim.ml.errors import MLError

pytestmark = pytest.mark.unit

DEFAULT = ["127.0.0.1", "localhost", "host.docker.internal"]  # config.target_allowlist default


def _fake(*addresses: str) -> eg.Resolver:
    def resolver(host: str, port: int) -> Sequence[str]:
        return list(addresses)
    return resolver


def _getaddrinfo(*addresses: str):
    def fake(host, port, family=0, type=0, proto=0, flags=0):
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
                for a in addresses]
    return fake


# --- codes and exception typing ----------------------------------------------

def test_codes_and_exception_hierarchy():
    assert eg.EGRESS_CODES == ("endpoint_url_invalid", "endpoint_not_allowlisted", "egress_refused")
    assert issubclass(eg.EndpointUrlInvalid, eg.EgressRefused)
    assert issubclass(eg.EndpointNotAllowlisted, eg.EgressRefused)
    assert issubclass(eg.EgressRefused, MLError)
    assert eg.EndpointUrlInvalid.code == "endpoint_url_invalid"
    assert eg.EndpointNotAllowlisted.code == "endpoint_not_allowlisted"
    assert eg.EgressRefused.code == "egress_refused"
    exc = eg.EgressRefused("address_class", "why", host="h", address="10.0.0.5")
    assert exc.rule == "address_class" and exc.reason == "why"
    assert exc.detail() == {"code": "egress_refused", "rule": "address_class", "reason": "why", "host": "h",
                            "address": "10.0.0.5"}
    assert str(exc) == "egress_refused (address_class): why"


# --- static check: register cases ---------------------------------------------

def test_public_https_host_in_allowlist_passes_statically():
    parsed = eg.check_registration_url("https://models.example.mil/predict", ["models.example.mil"])
    assert parsed == eg.ParsedEndpoint(
        url="https://models.example.mil/predict", scheme="https", host="models.example.mil", port=443,
        path="/predict", literal_ip=False, address_class="hostname", allowlist_entry="models.example.mil",
        plaintext=False, plaintext_loopback=False,
    )
    assert parsed.address() is None


def test_plaintext_loopback_passes_with_default_allowlist_and_is_recorded():
    parsed = eg.check_registration_url("http://127.0.0.1:8081/predict", DEFAULT)
    assert parsed.plaintext is True and parsed.plaintext_loopback is True
    assert parsed.host == "127.0.0.1" and parsed.port == 8081 and parsed.literal_ip is True
    assert parsed.address_class == "loopback" and parsed.allowlist_entry == "127.0.0.1"
    assert parsed.address() == ipaddress.ip_address("127.0.0.1")
    by_name = eg.check_registration_url("http://localhost:8081/predict", DEFAULT)
    assert by_name.plaintext_loopback is True and by_name.literal_ip is False
    compose = eg.check_registration_url("http://host.docker.internal:8081/predict", DEFAULT)
    assert compose.plaintext_loopback is True


@pytest.mark.parametrize("url, rule", [
    ("https://a:b@host/", "userinfo"),
    ("https://user@host/", "userinfo"),
    ("https://host/p?k=v", "query"),
    ("https://host/p?", "query"),
    ("https://host/p#frag", "fragment"),
    ("ftp://host", "scheme"),
    ("host/predict", "scheme"),
    ("", "url"),
    ("https://host/pre dict", "url"),
    ("https://host/\tpredict", "url"),
    ("https://höst/", "url"),
    ("https://" + "a" * 2050 + "/", "url"),
    ("https:///predict", "host"),
    ("https://host./", "host"),
    ("https://0x7f.1/", "host"),
    ("https://1.2.3/", "host"),
    ("https://-bad.example/", "host"),
    ("https://ex_ample.mil/", "host"),
    ("https://[fe80::1%25eth0]/", "host"),
    ("https://host:0/", "port"),
    ("https://host:70000/", "port"),
    ("https://host:abc/", "port"),
    ("http://models.example.mil/predict", "plaintext"),
])
def test_invalid_urls_are_endpoint_url_invalid(url: str, rule: str):
    allowlist = ["host", "models.example.mil", "host.", "0x7f.1", "1.2.3", "-bad.example", "ex_ample.mil", "fe80::1",
                 "a" * 2050]
    with pytest.raises(eg.EndpointUrlInvalid) as exc_info:
        eg.check_registration_url(url, allowlist)
    assert exc_info.value.code == "endpoint_url_invalid"
    assert exc_info.value.rule == rule, str(exc_info.value)


def test_refusal_messages_never_carry_userinfo_query_or_fragment():
    for url, secret in [("https://alice:hunter2@host/p", "hunter2"), ("https://host/p?token=abc123", "abc123"),
                        ("https://host/p#frag-secret", "frag-secret")]:
        with pytest.raises(eg.EgressRefused) as exc_info:
            eg.check_registration_url(url, ["host"])
        assert secret not in str(exc_info.value)
        assert secret not in json.dumps(exc_info.value.detail())
        assert exc_info.value.host == "host"


def test_host_not_in_allowlist_is_endpoint_not_allowlisted_and_authorize_writes_a_fail_row(tmp_path: Path):
    url = "https://other.example.mil/predict"
    with pytest.raises(eg.EndpointNotAllowlisted) as exc_info:
        eg.check_registration_url(url, ["models.example.mil"])
    assert exc_info.value.code == "endpoint_not_allowlisted"
    assert exc_info.value.rule == "not_allowlisted" and exc_info.value.host == "other.example.mil"
    # The same URL fails the platform gate the API will call, leaving allowlist_check == "fail" on the chain.
    with pytest.raises(safety.AuthorizationError):
        safety.authorize("model.register", url, allowlist=["models.example.mil"], run_path=tmp_path)
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert rows[-1]["allowlist_check"] == "fail" and rows[-1]["success"] is False
    assert rows[-1]["action"] == "model.register"


def test_default_allowlist_admits_only_loopback():
    for url in ["https://models.example.mil/p", "https://8.8.8.8/p", "https://10.0.0.5/p"]:
        with pytest.raises(eg.EgressRefused) as exc_info:
            eg.check_registration_url(url, DEFAULT)
        assert exc_info.value.code == "endpoint_not_allowlisted"


def test_allowlist_matching_is_case_insensitive_and_normalises_the_url():
    parsed = eg.check_registration_url("HTTPS://Models.Example.MIL:443/Predict", ["models.example.mil"])
    assert parsed.url == "https://models.example.mil/Predict"
    assert parsed.host == "models.example.mil" and parsed.port == 443
    parsed6 = eg.check_registration_url("https://[::1]:8443", ["::1"])
    assert parsed6.url == "https://[::1]:8443/" and parsed6.host == "::1" and parsed6.path == "/"


# --- static check: literal addresses (rule c and d) -----------------------------

def test_private_literal_over_http_is_allowed_only_when_named_literally_or_by_private_cidr():
    literal = eg.check_registration_url("http://172.18.0.5:8080/predict", ["172.18.0.5"])
    assert literal.plaintext is True and literal.plaintext_loopback is False
    assert literal.address_class == "private" and literal.allowlist_entry == "172.18.0.5"
    cidr = eg.check_registration_url("http://172.18.0.5:8080/predict", ["172.16.0.0/12"])
    assert cidr.allowlist_entry == "172.16.0.0/12"
    link_local = eg.check_registration_url("http://169.254.10.2/predict", ["169.254.0.0/16"])
    assert link_local.address_class == "link_local" and link_local.plaintext is True


def test_wide_open_cidr_admits_public_but_exempts_no_private_address():
    public = eg.check_registration_url("https://8.8.8.8/predict", ["0.0.0.0/0"])
    assert public.address_class == "public" and public.allowlist_entry == "0.0.0.0/0"
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.check_registration_url("https://10.0.0.5/predict", ["0.0.0.0/0"])
    assert exc_info.value.code == "egress_refused" and exc_info.value.rule == "address_class"
    assert exc_info.value.address == "10.0.0.5"
    with pytest.raises(eg.EgressRefused):
        eg.check_registration_url("https://[fc00::5]/predict", ["::/0"])


@pytest.mark.parametrize("url, entry, cls", [
    ("https://224.0.0.1/", "224.0.0.1", "multicast"),
    ("https://0.0.0.0/", "0.0.0.0", "unspecified"),
    ("https://255.255.255.255/", "255.255.255.255", "reserved"),
    ("https://240.0.0.1/", "240.0.0.0/4", "reserved"),
    ("https://[ff02::1]/", "ff02::1", "multicast"),
    ("https://[::]/", "::", "unspecified"),
])
def test_never_exempt_address_classes_are_refused_even_when_allowlisted(url: str, entry: str, cls: str):
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.check_registration_url(url, [entry])
    assert type(exc_info.value) is eg.EgressRefused
    assert exc_info.value.rule == "address_class" and cls in str(exc_info.value)


def test_ipv6_literals():
    assert eg.check_registration_url("https://[::1]:8443/p", ["::1"]).plaintext_loopback is False
    assert eg.check_registration_url("http://[::1]:8443/p", ["::1"]).plaintext_loopback is True
    # An IPv4-mapped address is classified by the embedded IPv4: private, so it needs a literal entry.
    mapped = eg.check_registration_url("https://[::ffff:10.0.0.5]/p", ["::ffff:10.0.0.5"])
    assert mapped.address_class == "private" and mapped.literal_ip is True
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.check_registration_url("https://[::ffff:10.0.0.5]/p", ["::/0"])
    assert exc_info.value.code == "egress_refused" and exc_info.value.rule == "address_class"


# --- classification -----------------------------------------------------------

@pytest.mark.parametrize("address, cls", [
    ("93.184.216.34", "public"),
    ("127.0.0.1", "loopback"),
    ("::1", "loopback"),
    ("10.0.0.5", "private"),
    ("172.16.0.1", "private"),
    ("192.168.1.1", "private"),
    ("fc00::1", "private"),
    ("169.254.1.1", "link_local"),
    ("fe80::1", "link_local"),
    ("224.0.0.1", "multicast"),
    ("ff02::1", "multicast"),
    ("0.0.0.0", "unspecified"),
    ("::", "unspecified"),
    ("255.255.255.255", "reserved"),
    ("100.64.0.1", "reserved"),
    ("::ffff:10.0.0.5", "private"),
    ("::ffff:127.0.0.1", "loopback"),
    ("2002:0a00:0005::", "private"),  # 6to4 embedding 10.0.0.5
    ("2001:4860:4860::8888", "public"),
])
def test_classify_address(address: str, cls: str):
    assert eg.classify_address(address) == cls
    assert eg.classify_address(ipaddress.ip_address(address)) == cls


# --- allowlist parity with redsim.safety ---------------------------------------

@pytest.mark.parametrize("host", ["models.example.mil", "other.example.mil", "127.0.0.1", "10.0.0.5", "10.1.2.3",
                                  "::1", "localhost", "192.168.0.9", "8.8.8.8"])
@pytest.mark.parametrize("allowlist", [DEFAULT, ["models.example.mil"], ["10.0.0.0/8"], ["10.0.0.5"],
                                       ["192.168.0.0/16", "localhost"], []])
def test_allowlist_match_agrees_with_safety_is_target_allowed(host: str, allowlist: list[str]):
    url = f"https://[{host}]/p" if ":" in host else f"https://{host}/p"
    assert (eg.allowlist_match(host, allowlist) is not None) == safety.is_target_allowed(url, allowlist)


def test_allowlist_match_reports_the_entry_kind():
    assert eg.allowlist_match("models.example.mil", ["models.example.mil"]) == ("models.example.mil", "host")
    assert eg.allowlist_match("127.0.0.1", DEFAULT) == ("127.0.0.1", "ip")
    assert eg.allowlist_match("10.0.0.5", ["10.0.0.0/8"]) == ("10.0.0.0/8", "cidr")
    assert eg.allowlist_match("[::1]", ["::1"]) == ("::1", "ip")
    assert eg.allowlist_match("10.0.0.5", ["", " ", "not a cidr/8", "10.0.0.0/8"]) == ("10.0.0.0/8", "cidr")
    assert eg.allowlist_match("10.0.0.5", ["fc00::/7"]) is None  # version mismatch never matches
    assert eg.allowlist_match("models.example.mil", DEFAULT) is None


# --- connect time: resolve_and_check --------------------------------------------

def test_public_hostname_resolving_to_private_is_refused_unless_private_cidr_allowlisted(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo("10.0.0.5"))
    # Statically fine ...
    eg.check_registration_url("https://models.example.mil/predict", ["models.example.mil"])
    # ... but the resolved address is private via a hostname.
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.resolve_and_check("models.example.mil", ["models.example.mil"])
    assert exc_info.value.code == "egress_refused" and exc_info.value.rule == "address_class"
    assert exc_info.value.address == "10.0.0.5" and exc_info.value.host == "models.example.mil"
    assert "private" in str(exc_info.value)
    # A private CIDR entry containing the address permits it.
    assert eg.resolve_and_check("models.example.mil", ["10.0.0.0/8"]) == ("10.0.0.5",)
    assert eg.resolve_and_check("models.example.mil", ["models.example.mil", "10.0.0.5"]) == ("10.0.0.5",)
    # A wide-open CIDR does not.
    with pytest.raises(eg.EgressRefused):
        eg.resolve_and_check("models.example.mil", ["0.0.0.0/0"])


def test_resolve_and_check_public_addresses_pass_and_are_deduplicated():
    resolver = _fake("93.184.216.34", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
    assert eg.resolve_and_check("models.example.mil", ["models.example.mil"], resolver=resolver) == (
        "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")


def test_resolve_and_check_refuses_when_any_answer_is_private():
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.resolve_and_check("models.example.mil", ["models.example.mil"],
                             resolver=_fake("93.184.216.34", "192.168.1.9"))
    assert exc_info.value.address == "192.168.1.9"


def test_resolve_and_check_refuses_loopback_via_a_public_hostname_even_with_the_default_allowlist():
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.resolve_and_check("models.example.mil", ["models.example.mil", *DEFAULT], resolver=_fake("127.0.0.1"))
    assert exc_info.value.rule == "address_class" and "loopback" in str(exc_info.value)


def test_loopback_hostnames_may_resolve_to_loopback_or_private_space():
    assert eg.resolve_and_check("localhost", DEFAULT, resolver=_fake("127.0.0.1", "::1")) == ("127.0.0.1", "::1")
    assert eg.resolve_and_check("host.docker.internal", DEFAULT, resolver=_fake("192.168.65.254")) == (
        "192.168.65.254",)
    assert eg.resolve_and_check("host.docker.internal", DEFAULT, resolver=_fake("172.17.0.1")) == ("172.17.0.1",)
    # Only while the allowlist names them.
    with pytest.raises(eg.EgressRefused):
        eg.resolve_and_check("localhost", ["models.example.mil"], resolver=_fake("127.0.0.1"))


@pytest.mark.parametrize("address", ["::ffff:10.0.0.5", "fe80::1", "224.0.0.1", "0.0.0.0", "100.64.0.1"])
def test_resolve_and_check_refuses_every_non_public_class(address: str):
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.resolve_and_check("models.example.mil", ["models.example.mil"], resolver=_fake(address))
    assert exc_info.value.rule == "address_class"


def test_literal_ip_hosts_skip_resolution():
    calls: list[str] = []

    def resolver(host: str, port: int) -> Sequence[str]:
        calls.append(host)
        return ["8.8.8.8"]

    assert eg.resolve_and_check("127.0.0.1", DEFAULT, resolver=resolver) == ("127.0.0.1",)
    assert eg.resolve_and_check("93.184.216.34", ["93.184.216.34"], resolver=resolver) == ("93.184.216.34",)
    assert eg.resolve_and_check("[::1]", ["::1"], resolver=resolver) == ("::1",)
    assert calls == []
    with pytest.raises(eg.EgressRefused):  # ::1 is not in the IPv4-only default allowlist
        eg.resolve_and_check("[::1]", DEFAULT, resolver=resolver)
    with pytest.raises(eg.EgressRefused):  # a private literal still needs its exemption
        eg.resolve_and_check("10.0.0.5", ["models.example.mil"], resolver=resolver)


def test_resolution_failures_are_egress_refused(monkeypatch):
    def boom(host, port, **kwargs):
        raise socket.gaierror(8, "nodename nor servname provided, or not known")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.resolve_and_check("models.example.mil", ["models.example.mil"])
    assert exc_info.value.rule == "dns_failure" and exc_info.value.code == "egress_refused"
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.resolve_and_check("models.example.mil", ["models.example.mil"], resolver=_fake())
    assert exc_info.value.rule == "dns_empty"
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.resolve_and_check("models.example.mil", ["models.example.mil"], resolver=_fake("not-an-ip"))
    assert exc_info.value.rule == "dns_failure"
    with pytest.raises(eg.EndpointUrlInvalid):
        eg.resolve_and_check("bad host", ["bad host"], resolver=_fake("8.8.8.8"))


# --- connect time: check_request_host and the session pin -------------------------

def test_check_request_host_requires_the_allowlist_match_then_pins():
    session = eg.EgressSession()
    with pytest.raises(eg.EndpointNotAllowlisted):
        eg.check_request_host("other.example.mil", ["models.example.mil"], session=session,
                              resolver=_fake("93.184.216.34"))
    resolved = eg.check_request_host("models.example.mil", ["models.example.mil"], session=session,
                                     resolver=_fake("93.184.216.34", "93.184.216.35"))
    assert resolved == eg.ResolvedHost(host="models.example.mil", addresses=("93.184.216.34", "93.184.216.35"),
                                       pinned="93.184.216.34", literal_ip=False,
                                       allowlist_entry="models.example.mil")
    assert session.pinned("models.example.mil") == "93.184.216.34"
    assert session.pinned("Models.Example.MIL") == "93.184.216.34"


def test_session_resolves_once_and_refuses_changes():
    session = eg.EgressSession()
    calls: list[str] = []

    def first(host: str, port: int) -> Sequence[str]:
        calls.append("first")
        return ["93.184.216.34"]

    def rebound(host: str, port: int) -> Sequence[str]:
        calls.append("rebound")
        return ["1.1.1.1"]

    eg.check_request_host("models.example.mil", ["models.example.mil"], session=session, resolver=first)
    # Resolve once: a second call returns the pin without touching the resolver.
    again = eg.check_request_host("models.example.mil", ["models.example.mil"], session=session, resolver=rebound)
    assert again.pinned == "93.184.216.34" and again.addresses == ("93.184.216.34",)
    assert calls == ["first"]
    # With recheck the new answer set must still contain the pin.
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.check_request_host("models.example.mil", ["models.example.mil"], session=session, resolver=rebound,
                              recheck=True)
    assert exc_info.value.rule == "dns_rebinding" and exc_info.value.address == "93.184.216.34"
    assert calls == ["first", "rebound"]
    # A recheck whose answers still include the pin keeps it.
    kept = eg.check_request_host("models.example.mil", ["models.example.mil"], session=session,
                                 resolver=_fake("1.1.1.1", "93.184.216.34"), recheck=True)
    assert kept.pinned == "93.184.216.34"
    # A rebind to a private address is refused by class before the pin comparison.
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.check_request_host("models.example.mil", ["models.example.mil"], session=session,
                              resolver=_fake("10.0.0.5"), recheck=True)
    assert exc_info.value.rule == "address_class"


def test_verify_pin_enforces_the_pinned_address_at_connect():
    session = eg.EgressSession()
    with pytest.raises(eg.EgressRefused) as exc_info:
        session.verify_pin("models.example.mil", "93.184.216.34")
    assert exc_info.value.rule == "dns_rebinding" and "no address is pinned" in str(exc_info.value)
    eg.check_request_host("models.example.mil", ["models.example.mil"], session=session,
                          resolver=_fake("93.184.216.34"))
    session.verify_pin("models.example.mil", "93.184.216.34")
    session.verify_pin("MODELS.example.mil", "93.184.216.034".replace(".034", ".34"))
    with pytest.raises(eg.EgressRefused) as exc_info:
        session.verify_pin("models.example.mil", "1.1.1.1")
    assert exc_info.value.rule == "dns_rebinding" and exc_info.value.address == "1.1.1.1"


def test_check_request_host_without_a_session_resolves_every_time():
    first = eg.check_request_host("models.example.mil", ["models.example.mil"], resolver=_fake("93.184.216.34"))
    second = eg.check_request_host("models.example.mil", ["models.example.mil"], resolver=_fake("1.1.1.1"))
    assert first.pinned == "93.184.216.34" and second.pinned == "1.1.1.1"


def test_check_request_host_literal_ip():
    session = eg.EgressSession()
    resolved = eg.check_request_host("127.0.0.1", DEFAULT, session=session, port=8081)
    assert resolved.literal_ip is True and resolved.pinned == "127.0.0.1" and resolved.allowlist_entry == "127.0.0.1"
    with pytest.raises(eg.EgressRefused) as exc_info:
        eg.check_request_host("10.0.0.5", ["0.0.0.0/0"], session=session)
    assert exc_info.value.rule == "address_class"


# --- EgressPolicy wrapper ---------------------------------------------------------

def test_egress_policy_wraps_both_moments():
    policy = eg.EgressPolicy(["models.example.mil", "127.0.0.1"], resolver=_fake("93.184.216.34"))
    parsed, resolved = policy.check_endpoint("https://models.example.mil/predict")
    assert parsed.host == "models.example.mil" and resolved.pinned == "93.184.216.34"
    assert policy.session.pinned("models.example.mil") == "93.184.216.34"
    assert policy.check_request_host("models.example.mil").pinned == "93.184.216.34"
    assert policy.resolve_and_check("127.0.0.1") == ("127.0.0.1",)
    with pytest.raises(eg.EndpointNotAllowlisted):
        policy.check_registration_url("https://other.example.mil/predict")
    with pytest.raises(eg.EndpointUrlInvalid):
        policy.check_endpoint("https://models.example.mil/predict?k=v")
    loop = eg.EgressPolicy(DEFAULT)
    parsed, resolved = loop.check_endpoint("http://127.0.0.1:8081/predict")
    assert parsed.plaintext_loopback is True and resolved.pinned == "127.0.0.1" and resolved.literal_ip is True


def test_egress_policy_rebinding_refused_across_the_session():
    answers = iter([["93.184.216.34"], ["1.1.1.1"]])
    policy = eg.EgressPolicy(["models.example.mil"], resolver=lambda host, port: next(answers))
    assert policy.check_request_host("models.example.mil").pinned == "93.184.216.34"
    with pytest.raises(eg.EgressRefused) as exc_info:
        policy.check_request_host("models.example.mil", recheck=True)
    assert exc_info.value.rule == "dns_rebinding"
