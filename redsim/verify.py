"""Verification: prove (or refute) that a finding has been remediated.

DAST strategy: replay the PoC against the (rebuilt) running target.
SAST strategy: grep the patched files for the original signature.
Dependency strategy: unavailable — the pentest re-scan engine (the Trivy
runner) was removed with the pentest domain; the ML attack adapters
(``redsim.ml.attacks``) will provide the replacement re-evaluation path.

Every verify returns a structured ``VerifyResult`` and persists
``<run_path>/verify/<finding_id>.json`` plus before/after evidence under
``<run_path>/artifacts/evidence/<finding_id>/``.
"""

from __future__ import annotations

import json
import re
import shlex
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from redsim.schema import RedsimFinding

if TYPE_CHECKING:
    from redsim.state import RunStateAPI

VerifyStatus = Literal["verified", "still_vulnerable", "inconclusive"]
VerifyStrategy = Literal[
    "dast_poc", "sast_grep", "dependency_rescan", "dast_poc+sast_grep", "unknown"
]


@dataclass
class VerifyResult:
    finding_id: str
    status: VerifyStatus
    strategy: VerifyStrategy
    evidence: dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    verified_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Runtime provenance check
# ---------------------------------------------------------------------------

def runtime_proves_post_patch(
    run_state: RunStateAPI,
    *,
    require_source_rebuild: bool = True,
) -> tuple[bool, str]:
    """Return (proven, reason) — True iff the running container can be
    proven to reflect a post-patch build/state.

    When ``require_source_rebuild`` is True (the default for verifying a
    code-patched finding), an upstream image-mode container does NOT
    satisfy provenance — there is no way for a code patch to be present
    in an upstream image. Source mode additionally requires
    ``last_rebuild_at`` to be set, meaning the container was rebuilt
    after the patch landed.

    Pass ``require_source_rebuild=False`` only when you are not validating
    a code patch (e.g., re-scanning the same target for scan-stability
    purposes).
    """
    path = run_state.run_path / "target" / "runtime.json"
    if not path.exists():
        return False, "target/runtime.json missing — cannot prove container provenance"
    data = json.loads(path.read_text())
    mode = data.get("mode")

    if mode == "image":
        if require_source_rebuild:
            return False, (
                "image mode container is the upstream build — a code patch "
                "cannot be present in an unpatched image"
            )
        return True, "image mode (no code patch under verification)"

    if mode == "source":
        if not data.get("last_rebuild_at"):
            return False, "source mode but no rebuild recorded since startup"
        if data.get("source_ref_after") == data.get("source_ref_before"):
            return True, "source mode rebuilt (same ref — likely fixture-assisted)"
        return True, "source mode rebuilt from updated ref"

    return False, f"unknown target mode: {mode}"


# ---------------------------------------------------------------------------
# DAST PoC replay
# ---------------------------------------------------------------------------

_CURL_FLAG_RE = re.compile(r"-[A-Za-z]+|--[a-zA-Z][\w-]*")


def parse_curl(poc: str) -> dict[str, Any] | None:
    """Crude best-effort curl parser.

    Extracts URL, method (-X), headers (-H), and body (-d / --data).
    Returns None when poc is unparseable.
    """
    if not poc or "curl" not in poc:
        return None
    try:
        tokens = shlex.split(poc.replace("\\\n", " "))
    except ValueError:
        return None
    if "curl" not in tokens:
        return None
    method = "GET"
    url: str | None = None
    headers: list[str] = []
    body: str | None = None
    it = iter(tokens[tokens.index("curl") + 1:])
    for tok in it:
        if tok in ("-X", "--request"):
            method = next(it, "GET")
        elif tok in ("-H", "--header"):
            headers.append(next(it, ""))
        elif tok in ("-d", "--data", "--data-raw", "--data-binary"):
            body = next(it, None)
            if method == "GET":
                method = "POST"
        elif tok.startswith("-"):
            # Skip unknown options' values when the option likely takes one
            continue
        elif url is None:
            url = tok
    if not url:
        return None
    return {"method": method, "url": url, "headers": headers, "body": body}


def replay_poc(parsed: dict[str, Any], *, timeout: float = 10.0) -> dict[str, Any]:
    """Execute the parsed PoC against the live target."""
    headers = {}
    for h in parsed.get("headers", []):
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    body_bytes = parsed["body"].encode("utf-8") if parsed.get("body") else None
    req = Request(parsed["url"], data=body_bytes, headers=headers, method=parsed["method"])
    started = time.monotonic()
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read(64 * 1024)
            return {
                "status": resp.status,
                "headers": {k: v for k, v in resp.getheaders()},
                "body_excerpt": raw[:4096].decode("utf-8", errors="replace"),
                "body_sha256": sha256(raw).hexdigest(),
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
    except HTTPError as e:
        body = b""
        try:
            body = e.read(64 * 1024)
        except Exception:  # noqa: BLE001, S110 - the error body is optional evidence
            pass
        return {
            "status": e.code,
            "headers": dict(e.headers.items()) if e.headers else {},
            "body_excerpt": body[:4096].decode("utf-8", errors="replace"),
            "body_sha256": sha256(body).hexdigest(),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    except URLError as e:
        return {"status": None, "error": str(e),
                "duration_ms": int((time.monotonic() - started) * 1000)}


_AUTH_TOKEN_MARKERS = ("authentication", "\"token\"", "bearer ", "access_token")


def classify_dast_remediation(before: dict[str, Any] | None, after: dict[str, Any]) -> tuple[VerifyStatus, str]:
    """Decide DAST verification status given before/after replay snapshots.

    Heuristic: success-ish before (200 with token-like body) AND post-patch
    response that either changes status (4xx) or strips the auth token.
    """
    after_status = after.get("status")
    body = (after.get("body_excerpt") or "").lower()
    has_token = any(m in body for m in _AUTH_TOKEN_MARKERS)

    if after_status is None:
        return "inconclusive", f"replay errored: {after.get('error')}"
    if after_status in (400, 401, 403, 404, 422):
        return "verified", f"post-patch returned {after_status}"
    if after_status == 200 and not has_token:
        return "verified", "post-patch returned 200 without auth-token markers"
    if after_status == 200 and has_token:
        return "still_vulnerable", "post-patch still returns 200 with auth-token markers"
    return "inconclusive", f"unexpected status {after_status}"


# ---------------------------------------------------------------------------
# SAST grep strategy
# ---------------------------------------------------------------------------

def _parse_semver(v: str | None) -> tuple[int, ...] | None:
    """Parse a permissive semver/pip version into a comparable tuple.

    Strips leading ``^``/``~``/``=``/``>=`` markers, then returns
    ``(major, minor, patch)`` truncated/padded. Returns None if the value
    is missing or doesn't start with a digit after stripping.
    """
    if not v:
        return None
    s = v.strip().lstrip("^~=<>!")
    if not s or not s[0].isdigit():
        return None
    parts: list[int] = []
    for chunk in s.replace("-", ".").split(".")[:3]:
        digits = ""
        for c in chunk:
            if c.isdigit():
                digits += c
            else:
                break
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _verify_dependency(
    finding: RedsimFinding,
    *,
    run_state: RunStateAPI,
    repo_path: Path | None,
    provenance: str,
) -> VerifyResult:
    """Dependency re-scan verification — engine unavailable in this build.

    The pentest dependency-rescan engine (the Trivy runner) was removed with
    the pentest domain. The adversarial-ML red-team vertical's attack adapters
    (``redsim.ml.attacks``) will provide the equivalent re-evaluation path.
    Until then this returns ``inconclusive`` with an explicit reason rather
    than silently succeeding or faking a re-scan.
    """
    return VerifyResult(
        finding_id=finding.id, status="inconclusive",
        strategy="dependency_rescan",
        evidence={
            "reason": ("dependency re-scan engine unavailable: the pentest "
                       "Trivy runner was removed; the ML attack adapters will "
                       "provide the replacement re-evaluation path"),
            "provenance": provenance,
        },
        verified_at=_now_iso(),
    )


def classify_sast_remediation(finding: RedsimFinding, repo_path: Path) -> tuple[VerifyStatus, dict[str, Any]]:
    """Walk finding.code_locations[*].file and grep the original snippet."""
    if not finding.code_locations:
        return "inconclusive", {"reason": "no code_locations on finding"}
    hits: list[dict[str, Any]] = []
    for loc in finding.code_locations:
        file_path = repo_path / loc.file
        if not file_path.exists():
            hits.append({"file": loc.file, "status": "missing"})
            continue
        text = file_path.read_text()
        snippet = (loc.fix_before or loc.snippet or "").strip()
        if not snippet:
            hits.append({"file": loc.file, "status": "no_snippet"})
            continue
        if snippet in text:
            hits.append({"file": loc.file, "status": "still_present"})
        else:
            hits.append({"file": loc.file, "status": "absent"})
    if any(h["status"] == "still_present" for h in hits):
        return "still_vulnerable", {"hits": hits}
    if all(h["status"] == "absent" for h in hits):
        return "verified", {"hits": hits}
    return "inconclusive", {"hits": hits}


# ---------------------------------------------------------------------------
# Top-level verify
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _persist(run_state: RunStateAPI, result: VerifyResult,
             before: dict[str, Any] | None, after: dict[str, Any] | None) -> Path:
    verify_dir = run_state.run_path / "verify"
    verify_dir.mkdir(parents=True, exist_ok=True)
    out = verify_dir / f"{result.finding_id}.json"
    out.write_text(json.dumps(result.to_dict(), indent=2))

    if before or after:
        evidence_dir = run_state.run_path / "artifacts" / "evidence" / result.finding_id
        evidence_dir.mkdir(parents=True, exist_ok=True)
        if before is not None:
            (evidence_dir / "before.json").write_text(json.dumps(before, indent=2))
        if after is not None:
            (evidence_dir / "after.json").write_text(json.dumps(after, indent=2))
    return out


def verify_finding(
    finding: RedsimFinding,
    *,
    run_state: RunStateAPI,
    repo_path: Path | None = None,
    require_rebuilt: bool = True,
    require_source_rebuild: bool = True,
) -> VerifyResult:
    """Verify a finding against the running target.

    ``require_rebuilt`` gates verification on the provenance check
    succeeding. ``require_source_rebuild`` (default True) demands that the
    target is a source-mode container that was rebuilt — without it,
    image mode would falsely pass when validating a code patch.
    """
    def _done(result: VerifyResult, after: dict[str, Any] | None = None) -> VerifyResult:
        _persist(run_state, result, None, after)
        return result

    proven, reason = runtime_proves_post_patch(
        run_state, require_source_rebuild=require_source_rebuild,
    )
    if require_rebuilt and not proven:
        result = VerifyResult(
            finding_id=finding.id, status="inconclusive",
            strategy="unknown", evidence={"provenance": reason},
            notes=reason, verified_at=_now_iso(),
        )
        return _done(result)

    if finding.finding_type == "dast":
        parsed = parse_curl(finding.poc_script_code or "")
        after: dict[str, Any] | None = None
        dast_status: VerifyStatus = "inconclusive"
        dast_note = "no parseable poc_script_code"
        if parsed is not None:
            after = replay_poc(parsed)
            dast_status, dast_note = classify_dast_remediation(None, after)

        # Fall back to SAST grep when the live replay was inconclusive
        # (typical in fixture-assisted runs with no real container) and the
        # finding carries code_locations we can grep.
        if dast_status == "inconclusive" and finding.code_locations and repo_path is not None:
            sast_status, sast_evidence = classify_sast_remediation(finding, repo_path)
            result = VerifyResult(
                finding_id=finding.id, status=sast_status,
                strategy="dast_poc+sast_grep",
                evidence={"poc": parsed, "after": after,
                          "sast": sast_evidence, "provenance": reason},
                notes=f"DAST inconclusive ({dast_note}); SAST grep fallback used",
                verified_at=_now_iso(),
            )
            return _done(result, after=after)

        result = VerifyResult(
            finding_id=finding.id, status=dast_status, strategy="dast_poc",
            evidence={"poc": parsed, "after": after, "provenance": reason},
            notes=dast_note, verified_at=_now_iso(),
        )
        return _done(result, after=after)

    if finding.finding_type in ("sast", "code"):
        if repo_path is None:
            result = VerifyResult(
                finding_id=finding.id, status="inconclusive",
                strategy="sast_grep",
                evidence={"reason": "repo_path required for SAST verification"},
                verified_at=_now_iso(),
            )
            return _done(result)
        status, evidence = classify_sast_remediation(finding, repo_path)
        result = VerifyResult(
            finding_id=finding.id, status=status, strategy="sast_grep",
            evidence={**evidence, "provenance": reason},
            verified_at=_now_iso(),
        )
        return _done(result)

    if finding.finding_type == "dependency":
        result = _verify_dependency(finding, run_state=run_state, repo_path=repo_path,
                                    provenance=reason)
        return _done(result)

    result = VerifyResult(
        finding_id=finding.id, status="inconclusive",
        strategy="unknown",
        evidence={"reason": f"no strategy for finding_type={finding.finding_type}"},
        verified_at=_now_iso(),
    )
    return _done(result)
