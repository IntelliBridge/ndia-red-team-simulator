"""A stdlib fake of the Foundry Datasets v2 REST surface the push client uses (register INTEROP-25).

Test helper only. It serves, on 127.0.0.1 in a daemon thread:

* ``POST /api/v2/datasets/{rid}/transactions?transactionType=APPEND`` -> ``{"rid": ...}``
* ``POST /api/v2/datasets/{rid}/files/{path}/upload?transactionRid=...`` (body bytes)
* ``POST /api/v2/datasets/{rid}/transactions/{txn}/commit`` -> 204
* ``POST /api/v2/datasets/{rid}/transactions/{txn}/abort`` -> 204

It checks the bearer token (``Authorization: Bearer <token>``; anything else is
401) and records every request in memory: method, path, query, whether the
token matched, the content type and, for uploads, the raw body so a test can
parse the pushed payload. ``fail_at`` names a step (``create``, ``upload``,
``commit``) that answers ``fail_status`` instead, to prove that a 4xx / 5xx
fails the job honestly and that the client aborts the transaction.

The default token is a low-entropy **JWT-shaped** fake (three base64url
segments) so the redaction of JWT-shaped tokens in audit detail is exercised
without a real credential anywhere.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

#: JWT-shaped fake for the redaction test, not a credential. Assembled at import time from three low-entropy
#: segments (header ``{"alg":"none"}``, payload ``{"fake":"redsim"}``, a spelled-out fake signature) so the
#: value matches ``redsim.integrations.foundry.JWT_PATTERN`` at runtime while no JWT literal sits in the source.
DEFAULT_TOKEN = ".".join(["eyJhbGciOiJub25lIn0", "eyJmYWtlIjoicmVkc2ltIn0", "fakesignaturefakesignature"])
DEFAULT_DATASET_RID = "ri.foundry.main.dataset.0f2c9a4e-7b1d-4c3e-9a8f-1234567890ab"
API_PREFIX = "/api/v2/datasets/"


class FakeFoundryServer:
    """``with FakeFoundryServer() as server: server.base_url`` -> ``http://127.0.0.1:<port>``."""

    def __init__(self, *, token: str = DEFAULT_TOKEN, fail_at: str | None = None, fail_status: int = 503,
                 transaction_rid: str = "ri.foundry.main.transaction.00000000-0000-4000-8000-000000000001") -> None:
        self.token = token
        self.fail_at = fail_at
        self.fail_status = fail_status
        self.transaction_rid = transaction_rid
        self.requests: list[dict[str, Any]] = []
        self.committed: list[str] = []
        self.aborted: list[str] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.base_url = ""

    # -- bookkeeping ----------------------------------------------------------------------------

    def by_step(self, step: str) -> list[dict[str, Any]]:
        return [r for r in self.requests if r["step"] == step]

    @property
    def uploads(self) -> list[dict[str, Any]]:
        return self.by_step("upload")

    def uploaded_json(self, suffix: str) -> Any:
        """The parsed JSON body of the upload whose path ends with ``suffix``."""
        for row in self.uploads:
            if str(row["file_path"]).endswith(suffix):
                return json.loads(row["body"].decode("utf-8"))
        raise KeyError(suffix)

    # -- lifecycle ------------------------------------------------------------------------------

    def start(self) -> str:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:  # silence the default stderr log
                return None

            def _send(self, status: int, body: dict[str, Any] | None = None) -> None:
                data = json.dumps(body).encode("utf-8") if body is not None else b""
                self.send_response(status)
                if data:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if data:
                    self.wfile.write(data)

            def _authorized(self) -> bool:
                return self.headers.get("Authorization") == f"Bearer {outer.token}"

            def do_POST(self) -> None:  # noqa: N802 - http.server API
                parts = urlsplit(self.path)
                query = {k: v[0] for k, v in parse_qs(parts.query).items()}
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                segments = [unquote(s) for s in parts.path.split("/") if s]
                entry: dict[str, Any] = {
                    "method": "POST", "path": parts.path, "query": query, "status": None,
                    "auth_present": self.headers.get("Authorization") is not None, "auth_ok": self._authorized(),
                    "content_type": self.headers.get("Content-Type"), "body": body, "step": "unknown",
                    "dataset_rid": None, "file_path": None, "transaction_rid": None,
                }
                # /api/v2/datasets/{rid}/transactions | /files/{path}/upload | /transactions/{txn}/commit|abort
                if len(segments) >= 4 and segments[:3] == ["api", "v2", "datasets"]:
                    entry["dataset_rid"] = segments[3]
                    rest = segments[4:]
                    if rest == ["transactions"]:
                        entry["step"] = "create"
                    elif len(rest) >= 3 and rest[0] == "files" and rest[-1] == "upload":
                        entry["step"] = "upload"
                        entry["file_path"] = "/".join(rest[1:-1])
                        entry["transaction_rid"] = query.get("transactionRid")
                    elif len(rest) == 3 and rest[0] == "transactions" and rest[2] in ("commit", "abort"):
                        entry["step"] = rest[2]
                        entry["transaction_rid"] = rest[1]
                with outer._lock:
                    outer.requests.append(entry)
                if entry["step"] == "unknown":
                    entry["status"] = 404
                    self._send(404, {"errorCode": "NOT_FOUND", "errorName": "NotFound"})
                    return
                if not self._authorized():
                    entry["status"] = 401
                    self._send(401, {"errorCode": "UNAUTHORIZED", "errorName": "Unauthorized"})
                    return
                if outer.fail_at == entry["step"]:
                    entry["status"] = outer.fail_status
                    self._send(outer.fail_status, {"errorCode": "FORCED", "errorName": "ForcedFailure"})
                    return
                if entry["step"] == "create":
                    entry["status"] = 200
                    self._send(200, {"rid": outer.transaction_rid, "transactionType": query.get("transactionType"),
                                     "status": "OPEN"})
                elif entry["step"] == "upload":
                    entry["status"] = 200
                    self._send(200, {"path": entry["file_path"], "transactionRid": entry["transaction_rid"],
                                     "sizeBytes": len(body)})
                elif entry["step"] == "commit":
                    with outer._lock:
                        outer.committed.append(str(entry["transaction_rid"]))
                    entry["status"] = 204
                    self._send(204)
                else:
                    with outer._lock:
                        outer.aborted.append(str(entry["transaction_rid"]))
                    entry["status"] = 204
                    self._send(204)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        host, port = self._server.server_address[:2]
        self.base_url = f"http://{host}:{port}"
        self._thread = threading.Thread(target=self._server.serve_forever, name="fake-foundry-server", daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> FakeFoundryServer:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


__all__ = ["API_PREFIX", "DEFAULT_DATASET_RID", "DEFAULT_TOKEN", "FakeFoundryServer"]
