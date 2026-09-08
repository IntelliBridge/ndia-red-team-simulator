"""Hub file downloads survive the rate limit: 429 and 5xx are retried with backoff, other errors are not."""

from __future__ import annotations

import random

import httpx
import pytest

pytest.importorskip("numpy")

from redsim.ml.assets import datasets as ds


def test_retry_delay_prefers_retry_after_and_caps_backoff():
    assert ds.retry_delay("7", 0) == 7.0
    assert ds.retry_delay("9999", 0) == ds.MAX_RETRY_DELAY_S
    rng = random.Random(0)
    assert 1.0 <= ds.retry_delay(None, 0, rng=rng) <= 1.5
    assert 8.0 <= ds.retry_delay("soon", 3, rng=rng) <= 12.0
    assert ds.MAX_RETRY_DELAY_S <= ds.retry_delay(None, 40, rng=rng) <= 1.5 * ds.MAX_RETRY_DELAY_S


def test_download_retries_429_then_succeeds(tmp_path):
    statuses = [429, 503, 200]
    calls: list[httpx.Request] = []
    slept: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        status = statuses[len(calls) - 1]
        if status == 200:
            return httpx.Response(200, content=b"jpeg-bytes")
        return httpx.Response(status, headers={"retry-after": "3"} if status == 429 else {})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        dest = ds.download_hub_file(client, "org/repo", "abc", "train/Class A/1.jpg", tmp_path / "1.jpg",
                                    sleep=slept.append)
    assert dest.read_bytes() == b"jpeg-bytes" and len(calls) == 3
    assert str(calls[0].url) == "https://huggingface.co/datasets/org/repo/resolve/abc/train/Class%20A/1.jpg"
    assert slept[0] == 3.0 and 2.0 <= slept[1] <= 3.0
    assert not (tmp_path / "1.jpg.part").exists()


def test_download_gives_up_after_the_retry_budget_and_never_retries_404(tmp_path):
    slept: list[float] = []
    with (httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(429))) as client,
          pytest.raises(ds.DatasetUnavailable, match="HTTP 429 after 2 retries")):
        ds.download_hub_file(client, "org/repo", "abc", "x.jpg", tmp_path / "x.jpg", retries=2, sleep=slept.append)
    assert len(slept) == 2
    with (httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as client,
          pytest.raises(ds.DatasetUnavailable, match="HTTP 404$")):
        ds.download_hub_file(client, "org/repo", "abc", "y.jpg", tmp_path / "y.jpg", sleep=slept.append)
    assert len(slept) == 2 and not (tmp_path / "y.jpg").exists()
