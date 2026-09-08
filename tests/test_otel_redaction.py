"""H3 regression: the OTel security pipeline scrubs secrets from the log body.

The ``redaction`` processor only masks attribute VALUES; host log lines land in
the record ``body`` (filelog/journald/syslog), so a ``transform/redact_body``
processor must scrub the body before export to Loki + the Postgres mirror.

These assert (a) the processor is wired into ``logs/security`` before ``batch``
and (b) its ``replace_pattern`` regexes actually mask representative secrets
while leaving benign lines intact. The regexes are OTTL string literals, so a
doubled backslash in YAML is unescaped to a single backslash before compiling
with ``re``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_CONFIG = Path(__file__).resolve().parents[1] / "deploy" / "otel" / "config.yaml"


def _load():
    with open(_CONFIG) as fh:
        return yaml.safe_load(fh)


def _body_patterns(cfg) -> list[re.Pattern]:
    stmts = cfg["processors"]["transform/redact_body"]["log_statements"][0]["statements"]
    pats = []
    for s in stmts:
        m = re.search(r'replace_pattern\(body, "(.+)", "\*\*\*REDACTED\*\*\*"\)', s)
        assert m, f"unexpected statement shape: {s}"
        pats.append(re.compile(m.group(1).replace("\\\\", "\\")))
    return pats


def test_redact_body_wired_into_security_pipeline():
    cfg = _load()
    procs = cfg["service"]["pipelines"]["logs/security"]["processors"]
    assert "transform/redact_body" in procs
    # Must run before batch/export, and after attribute redaction.
    assert procs.index("transform/redact_body") < procs.index("batch")
    assert procs.index("redaction") < procs.index("transform/redact_body")
    assert "transform/redact_body" in cfg["processors"]


@pytest.mark.parametrize("line,secret", [
    ("sshd: password=hunter2 for root", "hunter2"),
    ("Accepted publickey; Authorization: Bearer ab12.cd-34_EF", "ab12.cd-34_EF"),
    ("Authorization: Bearer eyJhbGciOi.JIUzI1Ni.s5cQ==", "eyJhbGciOi"),
    ("app log api_key: sk-live-9999 done", "sk-live-9999"),
    ("audit token=ghp_AAAA1111BBBB2222 used", "ghp_AAAA1111BBBB2222"),
    ("aws key AKIAIOSFODNN7EXAMPLE leaked", "AKIAIOSFODNN7EXAMPLE"),
])
def test_secrets_in_body_are_masked(line, secret):
    pats = _body_patterns(_load())
    for p in pats:
        line = p.sub("***REDACTED***", line)
    assert secret not in line
    assert "***REDACTED***" in line


def test_benign_line_is_unchanged():
    pats = _body_patterns(_load())
    benign = "sshd: Accepted publickey for alice from 10.0.0.1 port 22"
    out = benign
    for p in pats:
        out = p.sub("***REDACTED***", out)
    assert out == benign
