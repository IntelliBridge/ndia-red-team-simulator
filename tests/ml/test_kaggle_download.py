"""Kaggle credentials never reach a log, and the download follows Kaggle's 302 to storage without them.

Unit tier with an ``httpx.MockTransport``: no network, no Kaggle account.
``redsim.ml.assets.datasets`` imports numpy, so the module is skipped without it.
"""

from __future__ import annotations

import base64
import io
import json
import zipfile

import httpx
import pytest

pytest.importorskip("numpy")

from redsim.ml.assets import datasets as ds
from redsim.ml.assets.manifest import sha256_bytes

TOKEN = "KGAT_test_token_value_never_logged"
CSV = b"url,type\nhttp://a.test/,benign\n,benign\nhttp://b.test/x,Phishing\nhttp://c.test/y,malware\n"
LOCATION = "https://storage.googleapis.com/kaggle-data-sets/archive.zip?X-Goog-Signature=sig"


def _zip(csv_bytes: bytes = CSV, member: str = "malicious_phish.csv") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(member, csv_bytes)
    return buf.getvalue()


def _env(tmp_path, **variables: str) -> dict[str, str]:
    """An explicit environment whose .env lookup finds nothing."""
    return {"REDSIM_ENV_FILE": str(tmp_path / "absent.env"), **variables}


def _transport(calls: list[httpx.Request], *, zip_bytes: bytes | None = None, first_status: int = 302,
               first_body: bytes | None = None, second_status: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.host == "www.kaggle.com":
            if first_status == 200:
                return httpx.Response(200, content=first_body or b"")
            if first_status in (401, 403):
                return httpx.Response(first_status, json={"message": "unauthorized"})
            return httpx.Response(first_status, headers={"location": LOCATION})
        assert request.url.host == "storage.googleapis.com", request.url
        return httpx.Response(second_status, content=zip_bytes or b"")

    return httpx.MockTransport(handler)


def _quiet(_: str) -> None:
    return None


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def test_no_credentials_when_nothing_is_set(tmp_path):
    assert ds.kaggle_credentials(_env(tmp_path)) is None
    assert ds.kaggle_credentials(_env(tmp_path, KAGGLE_USERNAME="u")) is None
    assert ds.kaggle_credentials(_env(tmp_path, KAGGLE_KEY="k")) is None
    assert ds.kaggle_credentials(_env(tmp_path, KAGGLE_API_TOKEN="   ")) is None


def test_bearer_token_wins_over_the_basic_pair_and_never_appears_in_repr(tmp_path):
    auth = ds.kaggle_credentials(_env(tmp_path, KAGGLE_API_TOKEN=TOKEN, KAGGLE_USERNAME="u", KAGGLE_KEY="k"))
    assert auth is not None and auth.kind == "bearer"
    assert auth.headers() == {"Authorization": f"Bearer {TOKEN}"}
    assert auth.source == "KAGGLE_API_TOKEN in the environment"
    assert TOKEN not in repr(auth) and TOKEN not in str(auth) and TOKEN not in f"{auth}"


def test_basic_pair_is_the_fallback(tmp_path):
    auth = ds.kaggle_credentials(_env(tmp_path, KAGGLE_USERNAME="user", KAGGLE_KEY="secret"))
    assert auth is not None and auth.kind == "basic" and auth.username == "user"
    assert auth.headers()["Authorization"] == "Basic " + base64.b64encode(b"user:secret").decode("ascii")
    assert "secret" not in repr(auth) and auth.source == "KAGGLE_KEY in the environment"


def test_token_is_read_from_the_env_file_and_the_environment_wins(tmp_path):
    env_file = tmp_path / "repo.env"
    env_file.write_text(f"# local secrets\nexport KAGGLE_API_TOKEN='{TOKEN}'\nOTHER=1\n", encoding="utf-8")
    auth = ds.kaggle_credentials({"REDSIM_ENV_FILE": str(env_file)})
    assert auth is not None and auth.kind == "bearer"
    assert auth.headers()["Authorization"] == f"Bearer {TOKEN}"
    assert auth.source == f"KAGGLE_API_TOKEN in {env_file}" and TOKEN not in auth.source
    over = ds.kaggle_credentials({"REDSIM_ENV_FILE": str(env_file), "KAGGLE_API_TOKEN": "from-env"})
    assert over is not None and over.headers()["Authorization"] == "Bearer from-env"
    assert over.source == "KAGGLE_API_TOKEN in the environment"


def test_process_environment_resolution_is_isolated_by_the_fixture(no_kaggle):
    assert ds.kaggle_credentials() is None
    assert ds.fetch_kaggle_malicious_urls(no_kaggle / "cache", transport=_transport([]), log=_quiet) is None
    assert not (no_kaggle / "cache").exists()


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def test_download_follows_the_redirect_without_the_token_and_records_both_digests(tmp_path):
    calls: list[httpx.Request] = []
    logs: list[str] = []
    zip_bytes = _zip()
    auth = ds.KaggleAuth(kind="bearer", source="KAGGLE_API_TOKEN in the environment", secret=TOKEN)

    dl = ds.fetch_kaggle_malicious_urls(tmp_path, auth=auth, transport=_transport(calls, zip_bytes=zip_bytes),
                                        log=logs.append)
    assert dl is not None
    assert [c.url.host for c in calls] == ["www.kaggle.com", "storage.googleapis.com"]
    assert calls[0].headers["authorization"] == f"Bearer {TOKEN}"
    assert calls[0].url.path == "/api/v1/datasets/download/sid321axn/malicious-urls-dataset"
    assert "authorization" not in calls[1].headers and str(calls[1].url) == LOCATION
    assert dl.csv_path == ds.kaggle_cache_dir(tmp_path) / "malicious_phish.csv"
    assert dl.csv_path.read_bytes() == CSV
    assert dl.archive is not None and dl.archive.sha256 == sha256_bytes(zip_bytes)
    assert dl.archive.size_bytes == len(zip_bytes) and dl.archive.path == ds.KAGGLE_ARCHIVE_NAME
    assert dl.file.sha256 == sha256_bytes(CSV) and dl.file.size_bytes == len(CSV) and dl.auth_kind == "bearer"
    assert (dl.csv_path.parent / ds.KAGGLE_ARCHIVE_NAME).read_bytes() == zip_bytes

    record = json.loads((dl.csv_path.parent / ds.KAGGLE_DOWNLOAD_RECORD).read_text(encoding="utf-8"))
    assert record["file"]["sha256"] == sha256_bytes(CSV) and record["archive"]["sha256"] == sha256_bytes(zip_bytes)
    assert record["slug"] == ds.MALICIOUS_URLS_SLUG and record["auth_kind"] == "bearer" and record["fetched_at"]
    assert TOKEN not in json.dumps(record) and all(TOKEN not in line for line in logs)
    assert any("bearer auth" in line for line in logs)

    # A second call is served from the cache without a request, and without credentials.
    calls.clear()
    again = ds.fetch_kaggle_malicious_urls(tmp_path, auth=None, transport=_transport(calls, zip_bytes=zip_bytes),
                                           log=logs.append)
    assert again is not None and calls == []
    assert again.file.sha256 == dl.file.sha256 and again.archive == dl.archive

    # A tampered cache is fetched again.
    dl.csv_path.write_bytes(b"url,type\n")
    third = ds.fetch_kaggle_malicious_urls(tmp_path, auth=auth, transport=_transport(calls, zip_bytes=zip_bytes),
                                           log=logs.append)
    assert third is not None and len(calls) == 2 and third.csv_path.read_bytes() == CSV

    # The dataset entry pins both digests and the row count; row indices cite the source rows.
    table = ds.kaggle_url_table(dl)
    assert table.dataset.revision == table.dataset.source_file_sha256 == sha256_bytes(CSV)
    assert table.dataset.archive_sha256 == sha256_bytes(zip_bytes) and table.dataset.n_rows == 3
    assert [f.path for f in table.dataset.source_files] == [ds.KAGGLE_ARCHIVE_NAME, "malicious_phish.csv"]
    assert table.row_indices == [0, 2, 3] and table.labels == ["benign", "phishing", "malware"]
    assert table.dataset.source == "kaggle" and table.dataset.fixture_only is False
    assert ds.kaggle_url_table(dl.csv_path).dataset.archive_sha256 is None


def test_bare_csv_response_is_accepted_with_basic_auth(tmp_path):
    calls: list[httpx.Request] = []
    auth = ds.KaggleAuth(kind="basic", source="KAGGLE_KEY in the environment", secret="k", username="u")
    dl = ds.fetch_kaggle_malicious_urls(tmp_path, auth=auth, log=_quiet,
                                        transport=_transport(calls, first_status=200, first_body=CSV))
    assert dl is not None and len(calls) == 1
    assert calls[0].headers["authorization"] == "Basic " + base64.b64encode(b"u:k").decode("ascii")
    assert dl.archive is None and dl.csv_path.read_bytes() == CSV and dl.auth_kind == "basic"
    assert not (dl.csv_path.parent / ds.KAGGLE_ARCHIVE_NAME).exists()
    assert ds.kaggle_url_table(dl).dataset.archive_sha256 is None


def test_refused_credentials_raise_without_the_secret(tmp_path):
    auth = ds.KaggleAuth(kind="bearer", source="KAGGLE_API_TOKEN in the environment", secret=TOKEN)
    with pytest.raises(ds.DatasetUnavailable, match="refused the credentials") as exc:
        ds.fetch_kaggle_malicious_urls(tmp_path, auth=auth, transport=_transport([], first_status=401), log=_quiet)
    assert TOKEN not in str(exc.value) and "KAGGLE_API_TOKEN in the environment" in str(exc.value)
    assert not (ds.kaggle_cache_dir(tmp_path) / "malicious_phish.csv").exists()


def test_redirect_without_location_and_storage_errors_raise(tmp_path):
    auth = ds.KaggleAuth(kind="bearer", source="test", secret=TOKEN)

    def no_location(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302)

    with pytest.raises(ds.DatasetUnavailable, match="without a Location header"):
        ds.fetch_kaggle_malicious_urls(tmp_path, auth=auth, transport=httpx.MockTransport(no_location), log=_quiet)
    with pytest.raises(ds.DatasetUnavailable, match="storage.googleapis.com returned HTTP 403"):
        ds.fetch_kaggle_malicious_urls(tmp_path, auth=auth, log=_quiet,
                                       transport=_transport([], zip_bytes=b"", second_status=403))
    with pytest.raises(ds.DatasetUnavailable, match="HTTP 500"):
        ds.fetch_kaggle_malicious_urls(tmp_path, auth=auth, transport=_transport([], first_status=500), log=_quiet)


def test_archive_without_the_file_is_rejected(tmp_path):
    auth = ds.KaggleAuth(kind="bearer", source="test", secret=TOKEN)
    with pytest.raises(ds.DatasetUnavailable, match="not malicious_phish.csv"):
        ds.fetch_kaggle_malicious_urls(tmp_path, auth=auth, log=_quiet,
                                       transport=_transport([], zip_bytes=_zip(member="other.csv")))


def test_missing_message_names_the_token_variable_and_the_sample():
    text = ds.kaggle_missing_message()
    assert "KAGGLE_API_TOKEN" in text and "KAGGLE_USERNAME / KAGGLE_KEY" in text
    assert "tests/ml/fixtures/malicious_urls_sample.csv" in text
