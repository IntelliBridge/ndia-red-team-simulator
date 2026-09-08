"""Compliance evidence pack generator.

Bundles audit + controls evidence into a self-contained directory a SOC 2 /
ISO 27001 / FedRAMP reviewer can inspect offline:

    <out_dir>/
      audit/<chain_id>.jsonl   one file per hash-chained audit chain
      verification.json        per-chain verify_chain() verdicts
      controls.json            curated controls matrix (SOC2 / ISO / FedRAMP)
      system.json              Redsim version + enabled-features summary
      manifest.json            sha256 of every file + the overall pack hash

The pack is deliberately **honest**: it only maps a control to a feature
Redsim genuinely ships, and marks anything incomplete ``"partial"``. It is
also **secret-free** — ``system.json`` records only backend names and
booleans derived from config/env, never tokens, URLs with credentials, or
key material.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redsim import __version__
from redsim.audit.chain import resolve_writer, verify_chain

logger = logging.getLogger(__name__)


@dataclass
class EvidenceManifest:
    """Returned by :func:`generate_evidence_pack`.

    ``files`` maps each pack-relative path to its sha256 hex digest.
    ``pack_hash`` is the sha256 over the sorted ``path\\0sha256`` lines, so it
    changes if any file is added, removed, or mutated.
    """
    out_dir: str
    generated_at: str
    redsim_version: str
    chains: list[str] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    pack_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "out_dir": self.out_dir,
            "generated_at": self.generated_at,
            "redsim_version": self.redsim_version,
            "chains": self.chains,
            "files": self.files,
            "pack_hash": self.pack_hash,
        }


# ---------------------------------------------------------------------------
# Controls matrix
#
# Static, hand-curated map from representative compliance controls to the
# concrete Redsim features that supply evidence. Only controls Redsim genuinely
# supports are listed; partial coverage is flagged ``status="partial"`` with a
# note on the gap. This is the auditor-facing crosswalk — keep claims honest.
# ---------------------------------------------------------------------------

def build_controls_matrix() -> dict[str, Any]:
    """Return the SOC 2 / ISO 27001 / FedRAMP controls crosswalk."""
    return {
        "soc2": {
            # SOC 2 Trust Services Criteria (Common Criteria).
            "CC6.1": {
                "name": "Logical access — least privilege & RBAC",
                "status": "supported",
                "evidence": [
                    "RBAC role checks on API routes",
                    "OPA/Cedar policy engine evaluation",
                    "per-tenant Postgres row-level security (RLS) isolation",
                ],
            },
            "CC6.6": {
                "name": "Boundary protection of authorized scope",
                "status": "supported",
                "evidence": [
                    "target allowlist enforcement",
                    "explicit --i-understand-this-target-is-authorized override audited",
                ],
            },
            "CC7.2": {
                "name": "Security monitoring & anomaly detection",
                "status": "partial",
                "evidence": [
                    "registry-dispatched scanner / attack adapter runs, each "
                    "on its own hash-chained audit chain",
                    "OpenTelemetry collector wiring",
                ],
                "note": "monitoring covers scan activity; org-wide SIEM "
                        "alerting is deployment-specific.",
            },
            "CC7.3": {
                "name": "Tamper-evident audit trail",
                "status": "supported",
                "evidence": [
                    "hash-chained append-only audit log",
                    "WORM export + verify_chain integrity proof",
                ],
            },
        },
        "iso27001": {
            # ISO/IEC 27001:2022 Annex A controls.
            "A.5.15": {
                "name": "Access control",
                "status": "supported",
                "evidence": ["RBAC", "policy engine", "RLS tenant isolation"],
            },
            "A.8.15": {
                "name": "Logging",
                "status": "supported",
                "evidence": [
                    "hash-chained append-only audit log",
                    "per-(project,run) chain segregation",
                ],
            },
            "A.8.16": {
                "name": "Monitoring activities",
                "status": "partial",
                "evidence": ["registry-dispatched adapter runs",
                             "OpenTelemetry traces/metrics"],
                "note": "continuous monitoring depends on the operator's "
                        "telemetry backend.",
            },
            "A.8.8": {
                "name": "Management of technical vulnerabilities",
                "status": "partial",
                "evidence": [
                    "registry-dispatched scanner / attack adapter findings",
                    "PoC-replay verification of findings (verify.replay)",
                ],
                "note": "dependency scanning, automated remediation and the "
                        "CI gate are not part of this build (removed with "
                        "the pentest domain); findings are tracked, not "
                        "auto-remediated.",
            },
        },
        "fedramp": {
            # FedRAMP / NIST 800-53 control families.
            "AC-3": {
                "name": "Access enforcement",
                "status": "supported",
                "evidence": ["RBAC", "policy engine", "RLS tenant isolation"],
            },
            "AC-6": {
                "name": "Least privilege",
                "status": "supported",
                "evidence": [
                    "scoped RBAC roles",
                    "scoped worker signing keys",
                ],
            },
            "AU-9": {
                "name": "Protection of audit information",
                "status": "supported",
                "evidence": [
                    "hash-chained append-only audit log",
                    "database-enforced append-only audit_events",
                    "WORM export",
                ],
            },
            "AU-10": {
                "name": "Non-repudiation",
                "status": "supported",
                "evidence": [
                    "per-event sha256 chaining (prev_hash || record)",
                    "verify_chain tamper detection",
                ],
            },
            "SI-2": {
                "name": "Flaw remediation",
                "status": "partial",
                "evidence": [
                    "finding lifecycle + PoC-replay verification (verify.replay)",
                    "hash-chained audit of every scan / verify decision",
                ],
                "note": "automated patch generation and the CI gate are not "
                        "part of this build (removed with the pentest domain); "
                        "remediation is tracked, not automated.",
            },
            "SI-7": {
                "name": "Software, firmware & information integrity",
                "status": "supported",
                "evidence": [
                    "Ed25519-signed plugins (redsim.supply_chain) + out-of-process "
                    "plugin sandbox",
                    "cosign-signed release images with CycloneDX SBOM + SLSA "
                    "provenance",
                    "hash-chained audit integrity",
                ],
            },
            "SI-10": {
                "name": "Information input validation / LLM guardrails",
                "status": "partial",
                "evidence": [
                    "LLM guardrails: PII scrubbing + prompt-injection / "
                    "output filtering",
                    "audit-detail redaction",
                ],
                "note": "guardrails apply to LLM I/O; coverage scales with "
                        "enabled guardrail policies.",
            },
        },
    }


# ---------------------------------------------------------------------------
# System summary (secret-free)
# ---------------------------------------------------------------------------

def _enabled_features(config: Any) -> dict[str, Any]:
    """Derive a secret-free enabled-features summary from config + env.

    Records only backend *names* and booleans — never tokens, credentials, or
    URLs that might embed credentials.
    """
    db_url = os.environ.get("REDSIM_DB_URL")
    return {
        "mode": os.environ.get("REDSIM_MODE", "filesystem"),
        "env": os.environ.get("REDSIM_ENV", "dev"),
        "state_backend": "postgres" if db_url else "filesystem",
        "audit_backend": "postgres-chain" if db_url else "jsonl",
        "blob_backend": os.environ.get("REDSIM_BLOB_BACKEND", "fs"),
        "auth_mode": os.environ.get("REDSIM_AUTH_MODE", "dev"),
        "oidc_configured": bool(os.environ.get("REDSIM_OIDC_ISSUER")),
        "tenancy_rls": bool(db_url),
        # RBAC policy engine (static role table / OPA / Cedar) ships in-tree.
        "policy_engine": True,
        "llm_enabled": not _truthy(os.environ.get("REDSIM_DISABLE_LLM")),
        "guardrails": not _truthy(os.environ.get("REDSIM_DISABLE_LLM")),
        "offline_vendor_host": bool(getattr(config, "offline_vendor_host", None)),
        "model": getattr(config, "model", None),
    }


def _truthy(value: str | None) -> bool:
    if not value:
        return False
    return value.lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n"
    )


# ---------------------------------------------------------------------------
# Pack generation
# ---------------------------------------------------------------------------

def generate_evidence_pack(
    out_dir: str | Path,
    *,
    config: Any = None,
    project: str | None = None,
    timestamp: datetime | None = None,
) -> EvidenceManifest:
    """Generate a compliance evidence pack under ``out_dir``.

    Exports every audit chain, verifies each one, writes the controls matrix,
    a secret-free system summary, and a manifest of per-file + overall hashes.
    Returns the :class:`EvidenceManifest`.
    """
    if config is None:
        from redsim.config import load_config
        config = load_config()

    logger.info("generate_evidence_pack start out_dir=%s project=%s", out_dir, project)
    out = Path(out_dir)
    audit_dir = out / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    generated_at = (timestamp or datetime.now(timezone.utc)).isoformat()

    # --- export + verify each audit chain ---------------------------------
    writer = resolve_writer(config)
    verification: dict[str, Any] = {}
    chains: list[str] = []
    for chain_id in sorted(writer.iter_chain_ids()):
        # ``project`` filters to that project's chain plus any of its runs if
        # callers want a scoped pack; otherwise every chain is exported.
        if project is not None and not _chain_in_project(chain_id, project):
            continue
        records = list(writer.read_chain(chain_id))
        safe = chain_id.replace(":", "__").replace("/", "_")
        chain_path = audit_dir / f"{safe}.jsonl"
        chain_path.write_text(
            "".join(json.dumps(r, default=str) + "\n" for r in records)
        )
        result = verify_chain(iter(records))
        verification[chain_id] = {
            "verified": result.verified,
            "count": result.count,
            "broken_at": result.broken_at,
            "reason": result.reason,
        }
        chains.append(chain_id)

    _write_json(out / "verification.json", verification)
    _write_json(out / "controls.json", build_controls_matrix())
    _write_json(
        out / "system.json",
        {
            "redsim_version": __version__,
            "generated_at": generated_at,
            "project": project,
            "features": _enabled_features(config),
        },
    )

    # --- manifest: hash every file in the pack ----------------------------
    files: dict[str, str] = {}
    for path in sorted(out.rglob("*")):
        if not path.is_file():
            continue
        if path.name == "manifest.json":
            continue  # don't hash the manifest we're about to write
        rel = path.relative_to(out).as_posix()
        files[rel] = _sha256_file(path)

    pack_hash = _compute_pack_hash(files)

    manifest = EvidenceManifest(
        out_dir=str(out),
        generated_at=generated_at,
        redsim_version=__version__,
        chains=chains,
        files=files,
        pack_hash=pack_hash,
    )
    _write_json(out / "manifest.json", manifest.to_dict())
    logger.info("generate_evidence_pack finished out_dir=%s chains=%d files=%d",
                out_dir, len(chains), len(files))
    return manifest


def _chain_in_project(chain_id: str, project: str) -> bool:
    """Match a chain to a project scope: its own ``project:<p>`` chain or any
    ``run:<...>`` chain (runs aren't keyed by project in the chain id, so a
    project filter keeps the project chain and the system chain out)."""
    return chain_id == f"project:{project}"


def _compute_pack_hash(files: dict[str, str]) -> str:
    """sha256 over the sorted ``path\\0sha256`` lines — order-independent and
    sensitive to any file add/remove/change."""
    digest = hashlib.sha256()
    for rel in sorted(files):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(files[rel].encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()
