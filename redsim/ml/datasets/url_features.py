"""Lexical features of a URL string (spec section 11.3.3).

Everything here is a pure function of the string. No DNS lookup, no HTTP
request, no rendering, no third-party enrichment: URL strings from the
malicious-URLs dataset are data, never something to visit. The module imports
nothing that can open a socket, and ``tests/ml/test_url_features.py`` runs the
extractor over the committed sample with ``socket.socket`` patched to raise.

``FEATURE_NAMES`` is the column order of every feature matrix the URL
classifier sees; ``FEATURE_SPECS`` adds the dtype and the ``perturbable``
flag that the tabular attack path reads from the asset manifest. Bump
``EXTRACTOR_VERSION`` whenever a feature definition changes, because a model
trained on one version must not score features from another.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

if TYPE_CHECKING:
    import numpy as np

EXTRACTOR_VERSION = "1.0"

FeatureDType = Literal["int", "float", "bool"]


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    dtype: FeatureDType
    perturbable: bool
    description: str


FEATURE_SPECS: tuple[FeatureSpec, ...] = (
    FeatureSpec("url_length", "int", True, "Number of characters in the URL string."),
    FeatureSpec("digit_ratio", "float", True, "Share of characters that are decimal digits."),
    FeatureSpec("letter_ratio", "float", True, "Share of characters that are letters."),
    FeatureSpec("count_dot", "int", True, "Count of '.'."),
    FeatureSpec("count_hyphen", "int", True, "Count of '-'."),
    FeatureSpec("count_at", "int", True, "Count of '@'."),
    FeatureSpec("count_query", "int", True, "Count of '?'."),
    FeatureSpec("count_percent", "int", True, "Count of '%'."),
    FeatureSpec("count_equals", "int", True, "Count of '='."),
    FeatureSpec("subdomain_count", "int", True, "Host labels beyond the registrable domain (no public-suffix list)."),
    FeatureSpec("path_depth", "int", True, "Number of non-empty path segments."),
    FeatureSpec("has_ip_host", "bool", False, "Host is a dotted-quad IPv4 or a bracketed IPv6 literal."),
    FeatureSpec("is_shortener", "bool", False, "Host is a known URL-shortener domain."),
    FeatureSpec("has_https", "bool", False, "Scheme is https."),
    FeatureSpec("suspicious_tld", "bool", False, "Top-level domain is on the abuse-prone list."),
    FeatureSpec("shannon_entropy", "float", True, "Shannon entropy (bits) of the character distribution."),
)

FEATURE_NAMES: tuple[str, ...] = tuple(spec.name for spec in FEATURE_SPECS)
N_FEATURES = len(FEATURE_NAMES)

# Frozen lists: a change here is a feature-definition change (bump EXTRACTOR_VERSION).
SHORTENER_HOSTS: frozenset[str] = frozenset({
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly",
    "bit.do", "cutt.ly", "rebrand.ly", "tiny.cc", "shorte.st", "x.co", "lnkd.in", "tr.im",
    "cli.gs", "u.to", "j.mp", "v.gd", "qr.ae", "po.st", "bc.vc", "twitthis.com", "su.pr",
    "ity.im", "q.gs", "db.tt", "yourls.org", "prettylinkpro.com", "scrnch.me", "filoops.info",
    "vzturl.com", "qr.net", "1url.com", "tweez.me", "tinyarrows.com", "urlz.fr", "soo.gd",
})

SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link",
    "country", "kim", "cricket", "science", "party", "gdn", "review", "stream", "download",
    "racing", "win", "bid", "loan", "men", "accountant", "faith", "date", "trade", "webcam",
    "buzz", "icu", "cam", "rest", "surf", "monster", "quest", "cyou", "su", "pw", "cc",
})

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _split_url(url: str) -> tuple[str, str, str, str]:
    """Return ``(scheme, host, path, query)`` without ever raising.

    Strings without a scheme (most rows of the malicious-URLs file look like
    ``example.com/path``) are parsed as network-path references so the first
    segment is treated as the host.
    """
    text = url.strip()
    if "://" in text:
        candidate = text
    else:
        candidate = "//" + text.lstrip("/")
    try:
        parts = urlsplit(candidate)
        scheme = parts.scheme.lower()
        path = parts.path
        query = parts.query
        try:
            host = (parts.hostname or "").strip().lower()
        except ValueError:
            # Invalid IPv6 bracket forms: fall back to the raw netloc.
            host = parts.netloc.rsplit("@", 1)[-1].lower()
    except ValueError:
        # urlsplit itself refuses some malformed strings; treat everything as host.
        scheme, host, path, query = "", text.lower(), "", ""
    return scheme, host, path, query


def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    if ":" in host:
        return True  # bracketed IPv6 literal (urlsplit strips the brackets)
    return bool(_IPV4_RE.match(host))


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_features(url: str) -> dict[str, float]:
    """Lexical features of one URL string, keyed by ``FEATURE_NAMES``.

    Defined for every ``str`` input, including the empty string, malformed
    URLs and non-ASCII text. Booleans are encoded as 0.0 / 1.0.
    """
    if not isinstance(url, str):
        raise TypeError(f"url must be a str, got {type(url).__name__}")
    scheme, host, path, _query = _split_url(url)
    n = len(url)
    digits = sum(ch.isdigit() for ch in url)
    letters = sum(ch.isalpha() for ch in url)

    ip_host = _is_ip_host(host)
    labels = [label for label in host.split(".") if label]
    subdomain_count = 0 if ip_host else max(len(labels) - 2, 0)
    tld = labels[-1] if labels and not ip_host else ""
    bare_host = host.removeprefix("www.")
    path_depth = sum(1 for seg in path.split("/") if seg)

    return {
        "url_length": float(n),
        "digit_ratio": digits / n if n else 0.0,
        "letter_ratio": letters / n if n else 0.0,
        "count_dot": float(url.count(".")),
        "count_hyphen": float(url.count("-")),
        "count_at": float(url.count("@")),
        "count_query": float(url.count("?")),
        "count_percent": float(url.count("%")),
        "count_equals": float(url.count("=")),
        "subdomain_count": float(subdomain_count),
        "path_depth": float(path_depth),
        "has_ip_host": 1.0 if ip_host else 0.0,
        "is_shortener": 1.0 if bare_host in SHORTENER_HOSTS else 0.0,
        "has_https": 1.0 if scheme == "https" else 0.0,
        "suspicious_tld": 1.0 if tld in SUSPICIOUS_TLDS else 0.0,
        "shannon_entropy": _shannon_entropy(url),
    }


def feature_vector(url: str) -> list[float]:
    """Features of one URL as a list in ``FEATURE_NAMES`` order."""
    feats = extract_features(url)
    return [feats[name] for name in FEATURE_NAMES]


def featurize(urls: Iterable[str]) -> list[list[float]]:
    """Feature rows for many URLs (pure Python, no numpy needed)."""
    return [feature_vector(u) for u in urls]


def featurize_array(urls: Sequence[str]) -> np.ndarray:
    """Feature matrix of shape ``(len(urls), N_FEATURES)`` as float32."""
    import numpy as np  # local import keeps this module importable without the ml extra

    rows = featurize(urls)
    if not rows:
        return np.zeros((0, N_FEATURES), dtype=np.float32)
    return np.asarray(rows, dtype=np.float32)


def feature_bounds(name: str, url_length_max: float | None = None) -> tuple[float, float | None]:
    """Static lower / upper bound of a feature (``None`` upper = unbounded).

    Used by tests and by the manifest writer to sanity-check extracted values;
    training-split min / max are recorded separately at build time.
    """
    spec = next((s for s in FEATURE_SPECS if s.name == name), None)
    if spec is None:
        raise KeyError(name)
    if spec.dtype == "bool":
        return 0.0, 1.0
    if name in {"digit_ratio", "letter_ratio"}:
        return 0.0, 1.0
    if name == "shannon_entropy":
        return 0.0, (math.log2(url_length_max) if url_length_max and url_length_max > 1 else None)
    return 0.0, None
