"""Multi-format finding ingestion — normalize third-party vulnerability
reports into Aegis's internal :class:`~aegis.schema.AegisFinding` model.

Aegis aggregates findings from many sources. In addition to our own scanner
adapters (which shell out to CLIs), users frequently already have a report on
disk from a tool they run elsewhere: a Snyk JSON export, a Veracode Findings
JSON, a Trivy JSON, or any SARIF 2.1.0 file. This module converts each of those
into ``AegisFinding`` objects so they flow through the same downstream pipeline.

This is **offline, deterministic, fixture-driven parsing**: no network, no
subprocess, no AI, no new dependencies. It mirrors the house style of the
scanner adapters (e.g. :mod:`aegis.scanners.grype_adapter`,
:mod:`aegis.scanners.codeql_adapter`): a per-format ``_SEVERITY_MAP`` with a
safe ``low`` default, a deterministically synthesized ``id``, ``created_at`` /
``updated_at`` from ``datetime.now(timezone.utc).isoformat()``,
``status="open"``, ``references=[]``, and ``evidence=None`` — we never copy raw
report blobs or credential-bearing values into a finding.

Defensive contract: malformed / empty / ``None`` input returns ``[]`` and never
raises. Array entries that are not dicts are skipped.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from aegis.schema import AegisFinding, CodeLocation

# --- severity maps (one per source vocabulary) -----------------------------

# Snyk emits lowercase severities (critical|high|medium|low).
_SNYK_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

# Trivy / SARIF dependency-style vocab is UPPERCASE; mirror the trivy_runner /
# grype_adapter map exactly (NEGLIGIBLE/UNKNOWN collapse to low).
_TRIVY_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NEGLIGIBLE": "low",
    "UNKNOWN": "low",
}

# SARIF result.level vocab; mirror codeql_adapter (error|warning|note). Note the
# default here is "low" to honor the module-wide safe-default contract; the
# explicit levels are exhaustive for well-formed SARIF.
_SARIF_LEVEL_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "low",
}

# Veracode severity is a 0–5 integer: 5 Very High, 4 High, 3 Medium, 2 Low,
# 1 Very Low, 0 Informational.
_VERACODE_SEVERITY_MAP = {
    5: "critical",
    4: "high",
    3: "medium",
    2: "low",
    1: "low",
    0: "low",
}

_DEFAULT_SEVERITY = "low"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_dict(data: dict | str | None) -> dict | None:
    """Return a dict from a dict or JSON string; ``None`` if uncoercible.

    JSON strings are parsed with ``json.loads``. Anything that does not resolve
    to a dict (a list, a scalar, malformed JSON, ``None``) yields ``None`` so
    the caller can return ``[]`` without raising.
    """
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, ValueError):
            return None
    return data if isinstance(data, dict) else None


def _str_or_none(value) -> str | None:
    """Return a non-empty string, else ``None`` (preserves the optional split)."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


# --- Snyk -------------------------------------------------------------------

def ingest_snyk(data: dict) -> list[AegisFinding]:
    """Normalize a ``snyk test --json`` document into ``AegisFinding`` objects.

    Reads the top-level ``vulnerabilities`` array. Each entry maps to a
    ``dependency`` finding carrying ``cve`` / ``cwe`` (first identifier),
    ``package_name``, ``installed_version`` and ``fixed_version`` when present.
    """
    doc = _coerce_dict(data)
    if doc is None:
        return []
    now = _iso_now()
    findings: list[AegisFinding] = []
    for vuln in doc.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        snyk_id = _str_or_none(vuln.get("id")) or "SNYK-UNKNOWN"
        package = _str_or_none(vuln.get("packageName"))
        version = _str_or_none(vuln.get("version"))
        severity = _SNYK_SEVERITY_MAP.get(
            (vuln.get("severity") or "").strip().lower(), _DEFAULT_SEVERITY
        )
        identifiers = vuln.get("identifiers") or {}
        cve_list = identifiers.get("CVE") or []
        cwe_list = identifiers.get("CWE") or []
        fixed_in = vuln.get("fixedIn") or []
        title = _str_or_none(vuln.get("title")) or snyk_id
        findings.append(AegisFinding(
            id=f"snyk:{snyk_id}:{package or '?'}@{version or '?'}",
            title=title,
            severity=severity,
            finding_type="dependency",
            description=_str_or_none(vuln.get("description")) or title,
            source_tool="snyk",
            source_run_id=doc.get("_source_run_id", "ingest"),
            affected_component=package or snyk_id,
            confidence="high",
            status="open",
            created_at=now,
            updated_at=now,
            cve=_str_or_none(cve_list[0]) if cve_list else None,
            cwe=_str_or_none(cwe_list[0]) if cwe_list else None,
            package_name=package,
            installed_version=version,
            fixed_version=_str_or_none(fixed_in[0]) if fixed_in else None,
            references=[],
            evidence=None,
        ))
    return findings


# --- Veracode ---------------------------------------------------------------

def _veracode_findings(doc: dict) -> list:
    """Locate the findings array in either the flat or ``_embedded`` shape.

    The Veracode Findings REST API nests the array under ``_embedded.findings``;
    some exports place a ``findings`` array at the top level. We accept either.
    """
    embedded = doc.get("_embedded")
    if isinstance(embedded, dict) and isinstance(embedded.get("findings"), list):
        return embedded["findings"]
    top = doc.get("findings")
    return top if isinstance(top, list) else []


def ingest_veracode(data: dict) -> list[AegisFinding]:
    """Normalize a Veracode Findings JSON document into ``AegisFinding`` objects.

    Each finding maps to a ``sast`` finding. Severity is the numeric 0–5
    ``finding_details.severity``; ``cwe`` is carried as ``CWE-<id>`` and a file
    location becomes a ``CodeLocation`` when both path and line are present.
    """
    doc = _coerce_dict(data)
    if doc is None:
        return []
    now = _iso_now()
    findings: list[AegisFinding] = []
    for item in _veracode_findings(doc):
        if not isinstance(item, dict):
            continue
        details = item.get("finding_details") or {}
        issue_id = item.get("issue_id")
        issue_id_s = _str_or_none(issue_id) or "UNKNOWN"
        sev_raw = details.get("severity")
        severity = _VERACODE_SEVERITY_MAP.get(sev_raw, _DEFAULT_SEVERITY) \
            if isinstance(sev_raw, int) else _DEFAULT_SEVERITY

        cwe = details.get("cwe") or {}
        cwe_id = cwe.get("id")
        cwe_str = f"CWE-{cwe_id}" if cwe_id is not None else None
        category = (details.get("finding_category") or {}).get("name")

        file_path = _str_or_none(details.get("file_path") or details.get("file_name"))
        line = details.get("file_line_number")

        code_locations = None
        if file_path and isinstance(line, int):
            code_locations = [CodeLocation(
                file=file_path, start_line=line, end_line=line,
            )]

        title = _str_or_none(category) or (cwe.get("name") if isinstance(cwe.get("name"), str) else None) \
            or f"Veracode finding {issue_id_s}"
        findings.append(AegisFinding(
            id=f"veracode:{issue_id_s}",
            title=title,
            severity=severity,
            finding_type="sast",
            description=_str_or_none(item.get("description")) or title,
            source_tool="veracode",
            source_run_id=doc.get("_source_run_id", "ingest"),
            affected_component=file_path or title,
            confidence="high",
            status="open",
            created_at=now,
            updated_at=now,
            cwe=cwe_str,
            code_locations=code_locations,
            references=[],
            evidence=None,
        ))
    return findings


# --- Trivy ------------------------------------------------------------------

def ingest_trivy(data: dict) -> list[AegisFinding]:
    """Normalize a Trivy JSON document into ``AegisFinding`` objects.

    Walks ``Results[*].Vulnerabilities[*]`` like ``trivy_runner.parse_trivy_json``
    and produces ``dependency`` findings carrying ``cve`` / ``cwe`` /
    ``package_name`` / ``installed_version`` / ``fixed_version``.
    """
    doc = _coerce_dict(data)
    if doc is None:
        return []
    now = _iso_now()
    findings: list[AegisFinding] = []
    for result in doc.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = _str_or_none(result.get("Target")) or ""
        for v in result.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            vuln_id = _str_or_none(v.get("VulnerabilityID")) or "TRIVY-UNKNOWN"
            package = _str_or_none(v.get("PkgName"))
            severity = _TRIVY_SEVERITY_MAP.get(
                (v.get("Severity") or "").strip().upper(), _DEFAULT_SEVERITY
            )
            cwe_ids = v.get("CweIDs") or []
            references = [r for r in (v.get("References") or []) if isinstance(r, str)]
            component = f"{package} ({target})" if target else (package or vuln_id)
            title = _str_or_none(v.get("Title")) or vuln_id
            findings.append(AegisFinding(
                id=f"trivy:{vuln_id}:{package or '?'}",
                title=title,
                severity=severity,
                finding_type="dependency",
                description=_str_or_none(v.get("Description")) or title,
                source_tool="trivy",
                source_run_id=doc.get("_source_run_id", "ingest"),
                affected_component=component,
                confidence="high",
                status="open",
                created_at=now,
                updated_at=now,
                cve=vuln_id if vuln_id.upper().startswith("CVE") else None,
                cwe=_str_or_none(cwe_ids[0]) if cwe_ids else None,
                package_name=package,
                installed_version=_str_or_none(v.get("InstalledVersion")),
                fixed_version=_str_or_none(v.get("FixedVersion")),
                references=references,
                evidence=None,
            ))
    return findings


# --- SARIF ------------------------------------------------------------------

def ingest_sarif(data: dict) -> list[AegisFinding]:
    """Normalize a SARIF 2.1.0 document into ``AegisFinding`` objects.

    Walks ``runs[*].results[*]`` like ``codeql_adapter``. Each result maps to a
    ``sast`` finding; ``level`` selects severity, and the first
    ``physicalLocation`` (``artifactLocation.uri`` + ``region.startLine``)
    becomes a ``CodeLocation``.
    """
    doc = _coerce_dict(data)
    if doc is None:
        return []
    now = _iso_now()
    run_id = doc.get("_source_run_id", "ingest")
    findings: list[AegisFinding] = []
    for run in doc.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = _str_or_none(result.get("ruleId")) or "sarif.rule"
            severity = _SARIF_LEVEL_MAP.get(
                (result.get("level") or "").strip().lower(), _DEFAULT_SEVERITY
            )
            message = _str_or_none((result.get("message") or {}).get("text")) or rule_id

            locations = result.get("locations") or []
            phys = {}
            if locations and isinstance(locations[0], dict):
                phys = locations[0].get("physicalLocation") or {}
            uri = _str_or_none((phys.get("artifactLocation") or {}).get("uri"))
            region = phys.get("region") or {}
            start_line = region.get("startLine")

            code_locations = None
            if uri is not None:
                start = start_line if isinstance(start_line, int) else 0
                end = region.get("endLine")
                end = end if isinstance(end, int) else start
                code_locations = [CodeLocation(file=uri, start_line=start, end_line=end)]

            line_part = start_line if isinstance(start_line, int) else "?"
            findings.append(AegisFinding(
                id=f"sarif:{rule_id}:{uri or '?'}:{line_part}",
                title=rule_id,
                severity=severity,
                finding_type="sast",
                description=message,
                source_tool="sarif",
                source_run_id=run_id,
                affected_component=uri or rule_id,
                confidence="high",
                status="open",
                created_at=now,
                updated_at=now,
                code_locations=code_locations,
                references=[],
                evidence=None,
            ))
    return findings


# --- auto-detection + dispatch ----------------------------------------------

_PARSERS = {
    "snyk": ingest_snyk,
    "veracode": ingest_veracode,
    "trivy": ingest_trivy,
    "sarif": ingest_sarif,
}


def detect_format(doc: dict) -> str | None:
    """Infer the report format from a parsed document's shape.

    Decision order (most specific structural marker first):

    * **SARIF** — has ``$schema`` containing ``sarif`` OR a top-level ``runs``
      list (the SARIF root object).
    * **Trivy** — has ``SchemaVersion`` OR a top-level ``Results`` list (the
      capitalized Trivy keys are distinctive).
    * **Veracode** — has a findings array under ``_embedded.findings`` or a
      top-level ``findings`` list.
    * **Snyk** — has a top-level ``vulnerabilities`` list.

    Returns the format name, or ``None`` if nothing matches.
    """
    if not isinstance(doc, dict):
        return None
    schema = doc.get("$schema")
    if (isinstance(schema, str) and "sarif" in schema.lower()) \
            or isinstance(doc.get("runs"), list):
        return "sarif"
    if "SchemaVersion" in doc or isinstance(doc.get("Results"), list):
        return "trivy"
    if _veracode_findings(doc):
        return "veracode"
    if isinstance(doc.get("vulnerabilities"), list):
        return "snyk"
    return None


def ingest_report(
    data: dict | str,
    fmt: str | None = None,
    *,
    source_run_id: str = "ingest",
) -> list[AegisFinding]:
    """Normalize any supported report into ``AegisFinding`` objects.

    ``data`` may be a parsed dict or a JSON string (parsed with ``json.loads``).
    If ``fmt`` is ``None`` the format is auto-detected from the document shape
    via :func:`detect_format`. ``source_run_id`` is threaded onto every emitted
    finding.

    Returns ``[]`` (never raises) for malformed / empty / ``None`` input or an
    undetectable / unknown format.
    """
    doc = _coerce_dict(data)
    if doc is None:
        return []

    chosen = (fmt or "").strip().lower() or detect_format(doc)
    parser = _PARSERS.get(chosen) if chosen else None
    if parser is None:
        return []

    # Thread source_run_id through without mutating the caller's dict.
    enriched = dict(doc)
    enriched["_source_run_id"] = source_run_id
    return parser(enriched)
