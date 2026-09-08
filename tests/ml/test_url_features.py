"""The lexical URL feature extractor is a pure function of the string (spec 11.3.3, 22.3).

Unit tier: no torch, no scikit-learn, and no socket. The no-network test
patches ``socket`` to raise and runs the extractor over the whole committed
sample, which is how the "URL strings are data" rule is asserted as code.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import re
import socket
from pathlib import Path

import pytest

from redsim.ml.datasets import url_features as uf

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "malicious_urls_sample.csv"
SIDECAR = FIXTURES / "MANIFEST.json"
CLASSES = {"benign", "defacement", "phishing", "malware"}

EXPECTED_NAMES = (
    "url_length", "digit_ratio", "letter_ratio", "count_dot", "count_hyphen", "count_at", "count_query",
    "count_percent", "count_equals", "subdomain_count", "path_depth", "has_ip_host", "is_shortener",
    "has_https", "suspicious_tld", "shannon_entropy",
)

ODD_INPUTS = [
    "", "   ", "http://", "://", "[::1", "http://[::1]:80/x", "exämple.com/ünïcode/ñ", "user@host",
    "http://example-bank.test@192.0.2.77/login", "a" * 5000, "http://host:notaport/x", "%%%%%", "\x00\x01",
    "javascript:alert(1)", "mailto:someone@example.test", "//", "?", "=", "...", "http://exa mple.test/a b",
]


def _sample_rows() -> list[dict[str, str]]:
    with open(SAMPLE, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows, "committed sample is empty"
    return rows


def _assert_well_formed(feats: dict[str, float], url: str) -> None:
    assert tuple(feats) == uf.FEATURE_NAMES
    for spec in uf.FEATURE_SPECS:
        value = feats[spec.name]
        assert isinstance(value, float) and math.isfinite(value), (spec.name, url)
        lo, hi = uf.feature_bounds(spec.name, url_length_max=len(url))
        assert value >= lo - 1e-9, (spec.name, url, value)
        if hi is not None:
            assert value <= hi + 1e-9, (spec.name, url, value)
        if spec.dtype in {"int", "bool"}:
            assert value == int(value), (spec.name, url, value)
        if spec.dtype == "bool":
            assert value in (0.0, 1.0)


def test_feature_names_are_the_frozen_contract():
    assert uf.FEATURE_NAMES == EXPECTED_NAMES
    assert uf.N_FEATURES == 16
    assert tuple(s.name for s in uf.FEATURE_SPECS) == EXPECTED_NAMES
    assert {s.name for s in uf.FEATURE_SPECS if s.dtype == "bool"} == {
        "has_ip_host", "is_shortener", "has_https", "suspicious_tld"}
    assert all(not s.perturbable for s in uf.FEATURE_SPECS if s.dtype == "bool")
    assert uf.EXTRACTOR_VERSION


def test_extract_is_deterministic_and_complete():
    url = "http://a.b.example.test/p/q?x=1&y=2"
    first = uf.extract_features(url)
    second = uf.extract_features(url)
    assert first == second
    assert uf.feature_vector(url) == [first[name] for name in uf.FEATURE_NAMES]
    _assert_well_formed(first, url)


@pytest.mark.parametrize("url", ODD_INPUTS)
def test_defined_output_for_odd_inputs(url: str):
    _assert_well_formed(uf.extract_features(url), url)


def test_non_string_input_is_rejected():
    with pytest.raises(TypeError):
        uf.extract_features(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        uf.extract_features(b"http://example.test")  # type: ignore[arg-type]


def test_specific_feature_semantics():
    ip = uf.extract_features("http://192.0.2.10/login?a=1")
    assert ip["has_ip_host"] == 1.0 and ip["subdomain_count"] == 0.0
    assert ip["count_query"] == 1.0 and ip["count_equals"] == 1.0 and ip["path_depth"] == 1.0
    assert ip["has_https"] == 0.0

    sub = uf.extract_features("http://a.b.example.test/p/q/")
    assert sub["subdomain_count"] == 2.0 and sub["path_depth"] == 2.0 and sub["count_dot"] == 3.0

    plain = uf.extract_features("http://www.example.com/")
    assert plain["subdomain_count"] == 1.0 and plain["is_shortener"] == 0.0 and plain["suspicious_tld"] == 0.0

    assert uf.extract_features("https://bit.ly/abc")["is_shortener"] == 1.0
    assert uf.extract_features("https://bit.ly/abc")["has_https"] == 1.0
    assert uf.extract_features("http://www.bit.ly/abc")["is_shortener"] == 1.0
    assert uf.extract_features("files.example.zip")["suspicious_tld"] == 1.0
    assert uf.extract_features("files.example.zip/x")["path_depth"] == 1.0

    userinfo = uf.extract_features("http://example-bank.test@192.0.2.77/login")
    assert userinfo["has_ip_host"] == 1.0 and userinfo["count_at"] == 1.0

    schemeless = uf.extract_features("example-library.test/catalog/books/history")
    assert schemeless["path_depth"] == 3.0 and schemeless["subdomain_count"] == 0.0

    assert uf.extract_features("")["url_length"] == 0.0
    assert uf.extract_features("")["shannon_entropy"] == 0.0
    assert uf.extract_features("aaaa")["shannon_entropy"] == 0.0
    assert uf.extract_features("abcd")["shannon_entropy"] == pytest.approx(2.0)
    assert uf.extract_features("a1%")["digit_ratio"] == pytest.approx(1 / 3)
    assert uf.extract_features("a1%")["letter_ratio"] == pytest.approx(1 / 3)
    assert uf.extract_features("a1%")["count_percent"] == 1.0


def test_committed_sample_shape_classes_and_sidecar():
    rows = _sample_rows()
    with open(SAMPLE, newline="", encoding="utf-8") as fh:
        assert next(csv.reader(fh)) == ["url", "type"]
    assert 40 <= len(rows) <= 100
    labels = [r["type"] for r in rows]
    assert set(labels) == CLASSES
    for cls in CLASSES:
        assert labels.count(cls) >= 10, cls
    urls = [r["url"] for r in rows]
    assert len(set(urls)) == len(urls), "sample must not carry duplicate URL strings"

    sidecar = json.loads(SIDECAR.read_text(encoding="utf-8"))["files"]["malicious_urls_sample.csv"]
    assert sidecar["sha256"] == hashlib.sha256(SAMPLE.read_bytes()).hexdigest()
    assert sidecar["n_rows"] == len(rows)
    assert sidecar["per_class"] == {cls: labels.count(cls) for cls in sorted(CLASSES)}
    assert sidecar["synthetic"] is False
    assert sidecar["columns"] == ["url", "type"]


def test_committed_sample_is_a_cited_draw_from_the_kaggle_file():
    """Real rows, so the sidecar cites the source digest and row indices (details in test_fixture_sample).

    The strings are data: the no-network test below runs the extractor over
    every one of them with ``socket`` patched to raise.
    """
    sidecar = json.loads(SIDECAR.read_text(encoding="utf-8"))["files"]["malicious_urls_sample.csv"]
    assert sidecar["source_dataset_id"] == "kaggle:sid321axn/malicious-urls-dataset"
    assert re.fullmatch(r"[0-9a-f]{64}", sidecar["source_file_sha256"])
    assert len(sidecar["source_row_indices"]) == len(_sample_rows())


def test_extraction_over_sample_makes_no_network_call(monkeypatch: pytest.MonkeyPatch):
    def _boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted during URL feature extraction")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(socket, "gethostbyname", _boom)

    rows = _sample_rows()
    matrix = uf.featurize(r["url"] for r in rows)
    assert len(matrix) == len(rows)
    assert all(len(vec) == uf.N_FEATURES for vec in matrix)
    for row, vec in zip(rows, matrix, strict=True):
        _assert_well_formed(dict(zip(uf.FEATURE_NAMES, vec, strict=True)), row["url"])


def test_featurize_array_shape_and_dtype():
    np = pytest.importorskip("numpy")
    urls = [r["url"] for r in _sample_rows()]
    arr = uf.featurize_array(urls)
    assert arr.shape == (len(urls), uf.N_FEATURES)
    assert arr.dtype == np.float32
    assert np.isfinite(arr).all()
    assert uf.featurize_array([]).shape == (0, uf.N_FEATURES)
    assert uf.feature_bounds("shannon_entropy", url_length_max=1) == (0.0, None)
    with pytest.raises(KeyError):
        uf.feature_bounds("not_a_feature")
