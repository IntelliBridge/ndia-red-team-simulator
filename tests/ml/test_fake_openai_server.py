"""Gateway failure controls use counts, status codes and synthetic error bodies."""
from __future__ import annotations

import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from tests.ml.fake_openai_server import DEFAULT_TOKEN, FakeOpenAIServer


def request(server: FakeOpenAIServer, *, catalog: bool = False, authorized: bool = True):
    headers = {"Content-Type": "application/json"}
    if authorized:
        headers["Authorization"] = f"Bearer {DEFAULT_TOKEN}"
    data = None if catalog else json.dumps({"model": "test-model", "messages": []}).encode()
    req = Request(server.base_url + ("/v1/models" if catalog else "/v1/chat/completions"),
                  data=data, headers=headers)
    try:
        response = urlopen(req, timeout=5)
    except HTTPError as exc:
        response = exc
    with response:
        return response.status, json.load(response), response.headers.get("Retry-After")


@pytest.mark.parametrize("status,code", [(403, "persona_denied"), (429, "rate_limit"),
                                        (502, "provider_unavailable")])
def test_structured_failures_at_selected_completion_indices(status, code):
    body = {"error": {"code": code, "message": "synthetic gateway failure"}}
    with FakeOpenAIServer(fail_status=status, fail_body=body, fail_indices={2, 4},
                          retry_after=2, answered_model="served-test-model") as server:
        assert request(server, catalog=True)[0] == 200
        responses = [request(server) for _ in range(5)]
        assert [r[0] for r in responses] == [200, status, 200, status, 200]
        for i in [1, 3]:
            assert responses[i][1] == body
            assert responses[i][2] == ("2" if status == 429 else None)
        assert [r.get("served_model") for r in server.chat_requests] == [
            "served-test-model", None, "served-test-model", None, "served-test-model"]


def test_fail_first_excludes_catalog_requests_and_can_select_429():
    with FakeOpenAIServer(fail_status=429, fail_first=3, retry_after="2") as server:
        assert request(server, catalog=True)[0] == 200
        assert [request(server)[0] for _ in range(5)] == [429, 429, 429, 200, 200]


def test_existing_failure_modes_and_explicit_empty_selection():
    for kwargs, expected in [({"fail_status": 502}, [502, 502]),
                             ({"fail_first": 1}, [503, 200]),
                             ({"fail_status": 403, "fail_indices": set()}, [200, 200])]:
        with FakeOpenAIServer(**kwargs) as server:
            assert [request(server)[0] for _ in range(2)] == expected


def test_authentication_is_checked_before_failure_injection():
    with FakeOpenAIServer(fail_status=502) as server:
        assert request(server, authorized=False)[0] == 401
