"""DeepsecAdapter — AI code-audit (whole-repo SAST) via the deepsec CLI.

deepsec (``vercel-labs/deepsec``) is a project-centric AI vulnerability
scanner. Its pipeline is three stages: ``scan`` runs regex matchers to find
candidate sites and stores them on disk (cheap, no AI); ``process`` investigates
candidates with an AI agent (the paid stage); ``export --format json`` reads the
stored findings and prints a **bare JSON array** of ``ExportedFinding`` objects
to stdout. This adapter drives ``scan`` → (optionally) ``process`` → ``export``
and converts each exported finding into a common ``AegisFinding`` under the
``code_audit`` capability.

Why this is a *custom* adapter (and not one of the shared-helper CLI adapters)
------------------------------------------------------------------------------
The other adapters are single-shot CLI tools: one ``subprocess.run`` whose
stdout is the findings payload. They therefore route ``scan()`` through
``run_cli_scan``, ``adapter_version()`` through ``cli_version`` (registry.py),
and ``health_check()`` through ``which_available`` (registry.py). deepsec cannot
reuse any of the three, for three distinct reasons:

1. **Multi-step scan → process → export flow.** A single deepsec run is *three*
   sequential subprocess invocations that share on-disk state: ``scan`` writes
   candidates, the optional ``process`` enriches them in place, and ``export``
   emits the JSON. ``run_cli_scan`` models exactly one ``subprocess.run`` and
   one stdout payload, so ``scan()`` is hand-written to sequence the stages and
   to persist a PII-sanitized copy of the export artifact (see the security note
   below). The AI ``process`` stage is **opt-in**: it runs only when
   ``config.deepsec_ai_process`` is set, ``config.deepsec_budget_usd > 0``, and
   an AI Gateway / model key is present in the environment. Otherwise the
   adapter runs ``scan`` + ``export`` only (regex candidates), so the
   offline/default path never spends money.

2. **``pnpm`` + config-driven cwd invocation.** deepsec is not a tool on
   ``PATH``; it is a workspace package run as ``pnpm deepsec <subcmd>`` from a
   checkout directory (``config.deepsec_path``, resolved via ``load_config()``).
   Every invocation needs ``cwd=config.deepsec_path``. The shared ``cli_version``
   helper builds a two-element argv (``[executable, subcommand]``) with no
   ``cwd``, so it cannot express ``["pnpm", "deepsec", "--version"]`` run from a
   specific directory — hence ``adapter_version()`` stays custom. Likewise the
   shared ``which_available`` helper is a pure OR over ``shutil.which`` lookups;
   deepsec's ``health_check()`` is an *AND* of a PATH probe for ``pnpm`` and a
   filesystem existence check for ``config.deepsec_path``, which that helper
   cannot represent — so ``health_check()`` stays custom too.

3. **``_convert`` returns ``AegisFinding | None`` for verdict filtering.** deepsec
   re-validates candidates and tags each with a ``metadata.revalidation.verdict``.
   ``_convert`` returns ``None`` for non-actionable verdicts (``false-positive``,
   ``fixed``, ``duplicate``) so the scan loop can drop them, whereas the
   shared-helper adapters' parsers map every record one-to-one. The ``| None``
   return is intentional and is consumed by both the live findings list and the
   sanitized-artifact build in ``scan()``.

Security note: deepsec enriches each finding with code-owner identities —
``metadata.owners`` (on-call/manager/contributor names, emails, GitHub handles,
Slack ids), a top-level ``assignee`` email, ``owning-team`` ``labels``, and a
pre-built ``description`` that *embeds those same identities as markdown*. This
adapter NEVER copies any of them. We synthesize our own description from the
technical fields only (file, line, slug) and drop ``owners`` / ``assignee`` /
``labels`` / deepsec's ``description`` entirely. ``evidence`` is always ``None``.
This mirrors the bumblebee/trufflehog redaction guarantee.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from aegis.config import load_config
from aegis.scanners.registry import ScanOptions, ScanResult, register
from aegis.schema import AegisFinding, CodeLocation, Confidence, Severity

if TYPE_CHECKING:
    from aegis.state import RunStateAPI

# deepsec Severity union (packages/core/src/types.ts) → Aegis severity.
# HIGH_BUG is a high-severity code-quality bug; BUG is a plain bug. We map the
# bug classes conservatively (high / low) and pass real vuln severities through.
_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "HIGH_BUG": "high",
    "MEDIUM": "medium",
    "BUG": "low",
    "LOW": "low",
}

# Revalidation verdicts that mean "not an actionable new finding" — dropped.
# "duplicate" was added in the pinned commit (9e3832d); a duplicate points at a
# primary finding, so surfacing it would double-count.
_DROP_VERDICTS = {"false-positive", "fixed", "duplicate"}

_CONFIDENCE_MAP: dict[str, Confidence] = {"high": "high", "medium": "medium", "low": "low"}

# export prefixes each title with "[SEVERITY] "; we track severity separately.
_TITLE_PREFIX = re.compile(r"^\[[^\]]*\]\s*")

_AI_KEY_ENVS = ("AI_GATEWAY_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY")


def _canon_severity(value: str) -> Severity:
    return _SEVERITY_MAP.get((value or "").strip().upper(), "low")


def _has_ai_key() -> bool:
    return any(os.environ.get(k) for k in _AI_KEY_ENVS)


def _extract_json_array(stdout: str) -> list:
    """Parse the export stdout into a list of finding dicts.

    ``export --format json`` (no ``--out``) writes a bare JSON array to stdout.
    We parse it directly, with a defensive fallback that slices out the
    outermost ``[...]`` in case a stray log line shares the stream.
    """
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end > start:
            try:
                data = json.loads(text[start:end + 1])
                return data if isinstance(data, list) else []
            except json.JSONDecodeError:
                return []
        return []


# deepsec enriches findings with code-owner identities; these keys (top-level
# and nested under ``metadata``) carry PII and must never be persisted — not in
# the AegisFinding and not in the raw artifact. See the module docstring.
_PII_TOP_KEYS = frozenset({"assignee", "labels", "description", "githubUrl"})
_PII_META_KEYS = frozenset({"owners"})


def _sanitize_for_artifact(item: dict) -> dict:
    """Strip code-owner PII from a raw deepsec finding before it is written to
    disk, mirroring the field-level redaction ``_convert`` applies."""
    clean = {k: v for k, v in item.items() if k not in _PII_TOP_KEYS}
    meta = clean.get("metadata")
    if isinstance(meta, dict):
        clean["metadata"] = {k: v for k, v in meta.items() if k not in _PII_META_KEYS}
    return clean


def _convert(finding: dict, run_id: str) -> AegisFinding | None:
    """Map one deepsec ``ExportedFinding`` to an ``AegisFinding``.

    Returns ``None`` for findings filtered out by revalidation verdict. Copies
    only known-safe technical fields — never owner identities, the assignee
    email, owning-team labels, or deepsec's PII-laden ``description``.
    """
    meta = finding.get("metadata") or {}

    verdict = (meta.get("revalidation") or {}).get("verdict")
    if verdict in _DROP_VERDICTS:
        return None

    severity = _canon_severity(finding.get("severity") or meta.get("severity") or "")
    file_path = meta.get("filePath")
    line_numbers = [n for n in (meta.get("lineNumbers") or []) if isinstance(n, int)]
    line0 = line_numbers[0] if line_numbers else None
    line_end = line_numbers[-1] if line_numbers else line0
    vuln_slug = meta.get("vulnSlug")

    raw_title = finding.get("title") or ""
    title = _TITLE_PREFIX.sub("", raw_title).strip() or (
        f"Code-audit finding: {vuln_slug}" if vuln_slug else "Code-audit finding"
    )

    conf = (meta.get("confidence") or "").lower()
    confidence = _CONFIDENCE_MAP.get(conf, "medium")

    finding_id = (
        f"deepsec:{vuln_slug or 'finding'}:{file_path or '?'}:{line0 if line0 is not None else '?'}"
    )

    # Synthesized, PII-free description — deepsec's own description embeds
    # owner names/emails and is never reused.
    desc = f"deepsec flagged a potential {vuln_slug or 'code'} issue"
    if file_path:
        desc += f" in {file_path}"
        if line0 is not None:
            desc += f" (line {line0})"
    desc += "."

    code_locations = None
    if file_path:
        code_locations = [CodeLocation(
            file=file_path,
            start_line=line0 if line0 is not None else 0,
            end_line=line_end if line_end is not None else (line0 or 0),
        )]

    now = datetime.now(timezone.utc).isoformat()
    return AegisFinding(
        id=finding_id,
        title=title,
        severity=severity,
        finding_type="code_audit",
        description=desc,
        source_tool="deepsec",
        source_run_id=run_id,
        affected_component=file_path or (vuln_slug or "unknown"),
        confidence=confidence,
        status="open",
        created_at=now,
        updated_at=now,
        references=[],
        code_locations=code_locations,
        remediation_steps=None,
        # NEVER copy owner identities, the assignee, labels, githubUrl, or
        # deepsec's pre-built (PII-laden) description into the finding.
        evidence=None,
    )


class DeepsecAdapter:
    name = "deepsec"
    capabilities = {"code_audit"}
    default_timeout = 1800

    def adapter_version(self) -> str:
        config = load_config()
        try:
            out = subprocess.run(
                ["pnpm", "deepsec", "--version"],
                cwd=str(config.deepsec_path), capture_output=True,
                text=True, timeout=10, check=False,
            )
            return (out.stdout or "").strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        config = load_config()
        return shutil.which("pnpm") is not None and Path(config.deepsec_path).exists()

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        config = load_config()
        target = options.target
        deepsec_dir = str(config.deepsec_path)
        base = ["pnpm", "deepsec"]
        scan_cmd = base + ["scan", "--root", str(target)]
        ai_on = bool(config.deepsec_ai_process and config.deepsec_budget_usd > 0 and _has_ai_key())
        process_cmd = base + ["process", "--root", str(target)] if ai_on else None
        export_cmd = base + ["export", "--format", "json"]
        command_str = " ".join(scan_cmd) + (
            " && " + " ".join(process_cmd) if process_cmd else ""
        ) + " && " + " ".join(export_cmd)

        started = time.monotonic()

        def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                cmd, cwd=deepsec_dir, capture_output=True,
                text=True, timeout=options.timeout,
            )

        try:
            _run(scan_cmd)
            if process_cmd:
                _run(process_cmd)
            export = _run(export_cmd)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            return ScanResult(
                findings=[], adapter_name=self.name,
                adapter_version=self.adapter_version(),
                command_str=command_str, exit_code=-1,
                duration_s=time.monotonic() - started, error=str(exc),
            )

        findings: list[AegisFinding] = []
        for item in _extract_json_array(export.stdout):
            if not isinstance(item, dict):
                continue
            converted = _convert(item, run_state.run_id)
            if converted is not None:
                findings.append(converted)

        # Persist a PII-sanitized copy of the export (never the raw stdout,
        # which embeds owner identities/emails in the metadata + description).
        raw_dir = Path(run_state.run_path) / "deepsec"
        raw_dir.mkdir(parents=True, exist_ok=True)
        sanitized = [
            _sanitize_for_artifact(item)
            for item in _extract_json_array(export.stdout)
            if isinstance(item, dict)
        ]
        (raw_dir / "export.json").write_text(json.dumps(sanitized, indent=2))

        return ScanResult(
            findings=findings, adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=command_str, exit_code=export.returncode,
            duration_s=time.monotonic() - started,
        )


register(DeepsecAdapter())
