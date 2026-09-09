"""A stdlib HTTP server wrapping ``TinyTarget`` behind ``POST /predict`` (the endpoint-v1 contract).

Test helper only (spec 22): it stands in for a registered inference endpoint so the broker, the
socket transport and ``EndpointTarget`` can be exercised offline on 127.0.0.1. It records every
request (method, path, which auth header it saw, row count) without storing the credential value
beyond an equality check, and can be made to misbehave on purpose:

* ``n_columns``   answer with that many columns (a contract violation when it is not 3);
* ``fail_status`` answer every request with that HTTP status and no body;
* ``logits``      answer with ``{"logits": ...}`` instead of probabilities;
* ``fail_first``  answer the first N requests with 503, then behave (exercises the retry path).

The token is a low-entropy fake (``tok-123``) by construction.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import numpy as np

from redsim.ml.endpoint_broker import CONTRACT_VERSION
from tests.ml.fakes import TinyTarget

DEFAULT_TOKEN = "tok-123"


class TinyEndpointServer:
    """``with TinyEndpointServer() as server: server.url`` -> ``http://127.0.0.1:<port>/predict``."""

    def __init__(
        self,
        target: Any | None = None,
        *,
        token: str = DEFAULT_TOKEN,
        auth_kind: str = "bearer",
        header_name: str = "X-Api-Key",
        n_columns: int | None = None,
        fail_status: int | None = None,
        logits: bool = False,
        fail_first: int = 0,
        path: str = "/predict",
    ) -> None:
        self.target = target if target is not None else TinyTarget(seed=0)
        self.token = token
        self.auth_kind = auth_kind
        self.header_name = header_name
        self.n_columns = n_columns
        self.fail_status = fail_status
        self.logits = logits
        self.fail_first = fail_first
        self.path = path
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.url = ""

    # -- bookkeeping ----------------------------------------------------------------------------

    @property
    def rows_total(self) -> int:
        return sum(int(r.get("rows") or 0) for r in self.requests if r.get("status") == 200)

    @property
    def n_requests(self) -> int:
        return len(self.requests)

    def _expected_header(self) -> tuple[str, str]:
        if self.auth_kind == "bearer":
            return "Authorization", f"Bearer {self.token}"
        return self.header_name, self.token

    # -- lifecycle ------------------------------------------------------------------------------

    def start(self) -> str:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:  # silence the default stderr log
                return None

            def _send(self, status: int, body: dict[str, Any] | None) -> None:
                data = json.dumps(body).encode("utf-8") if body is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if data:
                    self.wfile.write(data)

            def do_POST(self) -> None:  # noqa: N802 - http.server API
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                header, expected = outer._expected_header()
                seen = self.headers.get(header)
                entry: dict[str, Any] = {
                    "method": "POST", "path": self.path, "auth_header": header, "auth_present": seen is not None,
                    "auth_ok": seen == expected, "rows": 0, "status": None, "bytes": len(raw),
                }
                with outer._lock:
                    outer.requests.append(entry)
                    index = len(outer.requests)
                if self.path != outer.path:
                    entry["status"] = 404
                    self._send(404, {"error": "not found"})
                    return
                if not entry["auth_ok"]:
                    entry["status"] = 401
                    self._send(401, {"error": "unauthorized"})
                    return
                if outer.fail_status is not None:
                    entry["status"] = outer.fail_status
                    self._send(outer.fail_status, None)
                    return
                if index <= outer.fail_first:
                    entry["status"] = 503
                    self._send(503, {"error": "warming up"})
                    return
                try:
                    body = json.loads(raw.decode("utf-8"))
                except ValueError:
                    entry["status"] = 400
                    self._send(400, {"error": "bad json"})
                    return
                if not isinstance(body, dict) or body.get("contract") != CONTRACT_VERSION:
                    entry["status"] = 400
                    self._send(400, {"error": "unknown contract"})
                    return
                inputs = body.get("inputs")
                if not isinstance(inputs, list) or not inputs:
                    entry["status"] = 400
                    self._send(400, {"error": "inputs missing"})
                    return
                x = np.asarray(inputs, dtype=np.float32)
                proba = np.asarray(outer.target.predict_proba(x), dtype=np.float64)
                if outer.n_columns is not None and outer.n_columns != proba.shape[1]:
                    if outer.n_columns < proba.shape[1]:
                        proba = proba[:, : outer.n_columns]
                        proba = proba / proba.sum(axis=1, keepdims=True)
                    else:
                        pad = np.zeros((proba.shape[0], outer.n_columns - proba.shape[1]))
                        proba = np.concatenate([proba, pad], axis=1)
                entry["rows"] = int(x.shape[0])
                entry["status"] = 200
                if outer.logits:
                    self._send(200, {"logits": np.log(np.clip(proba, 1e-12, None)).tolist()})
                else:
                    self._send(200, {"probabilities": proba.tolist()})

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self._server, self._thread = server, thread
        self.url = f"http://127.0.0.1:{server.server_address[1]}{self.path}"
        return self.url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            if self._thread is not None:
                self._thread.join(timeout=5)
            self._server, self._thread = None, None

    def __enter__(self) -> TinyEndpointServer:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


__all__ = ["DEFAULT_TOKEN", "TinyEndpointServer"]
