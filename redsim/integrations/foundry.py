"""Palantir Foundry push: settings, the scorecard payload with its D9 / D3 guard, and the REST client (spec 27.3).

Plan 12 wave B3, ``atlas-foundry`` track (register INTEROP-23, -25, -28, -29,
-31). The integration is **off by default** and holds **no standing
credential**:

* :class:`FoundrySettings` is read from the process environment only (never a
  ``.env`` file): ``REDSIM_INTEGRATION_FOUNDRY_URL`` unset means *disabled*.
  A set URL must pass the B0 egress rules (``https`` except loopback, no
  userinfo, no query, host in ``target_allowlist``) and the operator must have
  confirmed the target instance is an enterprise or non-operational one
  (``REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL=1``, spec 27.3 last sentence,
  the D3 bound). A URL that fails either check is *misconfigured*, reported by
  rule, never by value. The settings hold no token: the bearer token comes
  from an ``AuthProfile`` named at push time and is decrypted on the worker
  only, immediately before the request.
* :func:`build_scorecard_payload` projects a ``CampaignRecord`` into the rows
  Foundry receives: one row per (attack, ε) input carrying ``n`` and
  ``n_correct_clean``, the five subscores, the MRI beside them, the grade with
  the spec 15.5 sentence, ``settings_hash`` and ``computed_at``; plus the
  per-family accuracy table, the ε curve, the ATLAS technique per attack and
  the run's limitations verbatim. Nothing is recomputed.
* :func:`validate_push_payload` is the guard every payload passes before it
  leaves (D9(ii), D9(iii), D3, spec 21.8): no bare MRI (an ``mri`` or ``grade``
  key without its subscores, denominators, ε grid, settings hash and the grade
  sentence beside it), no expected gain, no credential-shaped key or value, no
  URL string, no model bytes or model file name, no reviewer notes, no user
  identifier, no banned readiness word.
* :class:`FoundryClient` is the one transport class: the Foundry Datasets v2
  REST flow (open a transaction, upload files, commit) over ``httpx`` with the
  truststore TLS helper of ``redsim.llm.pythia``. A 4xx / 5xx at any step is a
  :class:`FoundryPushFailed` with the step and status; nothing is retried into
  a fake success. The client never logs a response body or a URL.

This module imports ``httpx`` and pure redsim modules only; the API process
imports it for the roster and the admission checks and it never reaches an ML
library (``tests/test_api_process_has_no_ml.py``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from redsim.audit.redact import _is_sensitive_key, redact_audit_detail
from redsim.ml import atlas_data
from redsim.ml.atlas import technique_for_attack
from redsim.ml.endpoint_egress import EgressRefused, check_registration_url
from redsim.ml.schema import GRADE_STATEMENT, CampaignRecord, contains_banned_score_word

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vocabulary and environment (spec 20.3 addendum, 27.4)
# ---------------------------------------------------------------------------

INTEGRATION = "foundry"
#: Base URL of the Foundry instance. Unset means the integration is disabled.
FOUNDRY_URL_ENV = "REDSIM_INTEGRATION_FOUNDRY_URL"
#: Default target dataset rid (``ri.foundry.main.dataset.<uuid>``); a push may name another.
FOUNDRY_DATASET_RID_ENV = "REDSIM_INTEGRATION_FOUNDRY_DATASET_RID"
#: Operator attestation that the instance is enterprise or non-operational (spec 27.3, D3).
FOUNDRY_ATTESTATION_ENV = "REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL"
#: Per-request timeout in seconds (default 30).
FOUNDRY_TIMEOUT_ENV = "REDSIM_INTEGRATION_FOUNDRY_TIMEOUT_S"
DEFAULT_TIMEOUT_S = 30.0
#: Every Foundry setting name, for the child-environment assertion (they all carry the ``REDSIM_`` prefix
#: the sandbox strips) and for the docs.
FOUNDRY_ENV_NAMES: tuple[str, ...] = (FOUNDRY_URL_ENV, FOUNDRY_DATASET_RID_ENV, FOUNDRY_ATTESTATION_ENV,
                                      FOUNDRY_TIMEOUT_ENV)
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})

#: The payload schema id every pushed scorecard file carries.
PAYLOAD_SCHEMA = "redsim-foundry-scorecard-1"
#: File names under the run prefix inside the Foundry dataset.
SCORECARD_FILE = "scorecard.json"
ROWS_FILE = "rows.jsonl"
#: Foundry Datasets v2 API root.
API_ROOT = "/api/v2/datasets"

#: Reasons the roster reports per egress rule, without the configured value (spec 27.5, D3).
MISCONFIGURED_REASONS: dict[str, str] = {
    "url": f"{FOUNDRY_URL_ENV} is not a well-formed URL",
    "scheme": f"{FOUNDRY_URL_ENV} must be https (http only for a loopback host)",
    "userinfo": f"{FOUNDRY_URL_ENV} must not carry userinfo",
    "query": f"{FOUNDRY_URL_ENV} must not carry a query string",
    "fragment": f"{FOUNDRY_URL_ENV} must not carry a fragment",
    "host": f"{FOUNDRY_URL_ENV} has no valid host",
    "port": f"{FOUNDRY_URL_ENV} has an invalid port",
    "not_allowlisted": f"the {FOUNDRY_URL_ENV} host is not in target_allowlist (redsim.yaml)",
    "address_class": f"the {FOUNDRY_URL_ENV} host is a literal address the egress policy refuses",
    "plaintext": f"{FOUNDRY_URL_ENV} uses http for a non-loopback host",
    "attestation": (f"{FOUNDRY_ATTESTATION_ENV}=1 is required: the operator confirms the Foundry instance is an "
                    "enterprise or non-operational one (spec 27.3, D3 bound)"),
    "dataset_rid": f"{FOUNDRY_DATASET_RID_ENV} is not a Foundry resource identifier",
}


def _truthy(raw: str | None) -> bool:
    return (raw or "").strip().lower() in _TRUE_VALUES


class FoundryMisconfigured(RuntimeError):
    """The Foundry URL is set but unusable; ``rule`` names the check, the message never carries the value."""

    def __init__(self, rule: str) -> None:
        self.rule = rule
        self.reason = MISCONFIGURED_REASONS.get(rule, f"{FOUNDRY_URL_ENV} was refused by the egress rules ({rule})")
        super().__init__(self.reason)


#: ``ri.<service>.<instance>.<type>.<locator>``; the locator is a UUID or a similar token.
_RID_PATTERN = re.compile(r"^ri\.[a-z][a-z0-9-]*\.[a-z0-9-]*\.[a-z][a-z0-9-]*\.[A-Za-z0-9._-]{8,128}$")
MAX_TARGET_REF_LEN = 256


def validate_target_ref(value: Any) -> str | None:
    """A Foundry dataset rid or ``None``; ``ValueError`` names the problem without echoing a URL."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > MAX_TARGET_REF_LEN or "://" in text or any(ch.isspace() for ch in text):
        raise ValueError("target_ref must be a Foundry resource identifier (ri.foundry.main.dataset.<id>), "
                         "never a URL")
    if not _RID_PATTERN.match(text):
        raise ValueError("target_ref must be a Foundry resource identifier of the form ri.<service>.<instance>."
                         "<type>.<locator>")
    return text


@dataclass(frozen=True)
class FoundrySettings:
    """The Foundry connection as configured on the worker pool: a base URL and a default target. No token."""

    base_url: str
    host: str
    scheme: str
    port: int
    plaintext_loopback: bool
    attested: bool
    dataset_rid: str | None = None
    timeout_s: float = DEFAULT_TIMEOUT_S

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None, *,
                 allowlist: Sequence[str]) -> FoundrySettings | None:
        """``None`` when ``REDSIM_INTEGRATION_FOUNDRY_URL`` is unset (disabled); :class:`FoundryMisconfigured`
        when it is set but refused by the egress rules, the attestation is missing or the default rid is
        malformed. Reads the process environment only, never a ``.env`` file."""
        env = os.environ if environ is None else environ
        raw_url = (env.get(FOUNDRY_URL_ENV) or "").strip()
        if not raw_url:
            return None
        try:
            parsed = check_registration_url(raw_url, list(allowlist))
        except EgressRefused as exc:
            raise FoundryMisconfigured(exc.rule) from None
        attested = _truthy(env.get(FOUNDRY_ATTESTATION_ENV))
        if not attested:
            raise FoundryMisconfigured("attestation")
        try:
            dataset_rid = validate_target_ref(env.get(FOUNDRY_DATASET_RID_ENV))
        except ValueError:
            raise FoundryMisconfigured("dataset_rid") from None
        raw_timeout = (env.get(FOUNDRY_TIMEOUT_ENV) or "").strip()
        try:
            timeout_s = float(raw_timeout) if raw_timeout else DEFAULT_TIMEOUT_S
        except ValueError:
            timeout_s = DEFAULT_TIMEOUT_S
        if timeout_s <= 0:
            timeout_s = DEFAULT_TIMEOUT_S
        return cls(base_url=parsed.url.rstrip("/"), host=parsed.host, scheme=parsed.scheme, port=parsed.port,
                   plaintext_loopback=parsed.plaintext_loopback, attested=attested, dataset_rid=dataset_rid,
                   timeout_s=timeout_s)

    def redacted(self) -> dict[str, Any]:
        """Audit-row view: host, scheme, whether a default target is configured. Never the URL, never a token."""
        return {"integration": INTEGRATION, "host": self.host, "scheme": self.scheme,
                "dataset_rid_configured": self.dataset_rid is not None, "attested": self.attested,
                "timeout_s": self.timeout_s}


def foundry_status(environ: Mapping[str, str] | None = None, *, allowlist: Sequence[str]) -> dict[str, Any]:
    """The roster block for ``GET /v1/integrations``: status strings and booleans only, no value.

    ``disabled`` when the URL is unset (the default), ``misconfigured`` with the
    rule when it is set but refused, ``configured`` otherwise. The host and the
    URL never appear here (``host_configured`` is a boolean).
    """
    env = os.environ if environ is None else environ
    block: dict[str, Any] = {
        "integration": INTEGRATION,
        "route": "POST /v1/runs/{run_id}/integrations/foundry",
        "gate": "integration.push (admin)",
        "queue": "default",
        "credential": "a bearer AuthProfile named in the push request; no standing credential is held",
        "settings": list(FOUNDRY_ENV_NAMES),
        "payload": "campaign scorecard: subscores with denominators, per-family table, eps grid, settings_hash, "
                   "the grade sentence and the run's limitations as rows of one dataset with the MRI",
    }
    try:
        settings = FoundrySettings.from_env(env, allowlist=allowlist)
    except FoundryMisconfigured as exc:
        block.update({"status": "misconfigured", "rule": exc.rule, "reason": exc.reason,
                      "host_configured": True, "target_ref_configured": False, "attested": False})
        return block
    if settings is None:
        block.update({"status": "disabled", "reason": f"{FOUNDRY_URL_ENV} is unset; the integration is off by "
                                                      "default (spec 27 rule 1)",
                      "host_configured": False, "target_ref_configured": False, "attested": False})
        return block
    block.update({"status": "configured", "host_configured": True,
                  "target_ref_configured": settings.dataset_rid is not None, "attested": settings.attested,
                  "tls": "plaintext loopback" if settings.plaintext_loopback else "https"})
    return block


# ---------------------------------------------------------------------------
# Redaction (INTEROP-28): what an integration row may carry
# ---------------------------------------------------------------------------

#: JWT-shaped bearer tokens (three base64url segments); Foundry tokens are commonly this shape.
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
#: ``Bearer <anything>`` inside a string value.
BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
#: Foundry-style long opaque tokens (``eyJ`` is covered above; this catches other 40+ character opaque tokens
#: that sit after a ``token=`` or ``Authorization:`` marker).
_TOKEN_MARKER_PATTERN = re.compile(r"(?i)\b(token|authorization)\s*[=:]\s*[A-Za-z0-9._~+/=-]{16,}")
REDACTED = "<REDACTED>"


#: A URL-shaped string value; an integration row carries hosts and ids, never a URL (spec 21.8, D3).
_URL_VALUE_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+")
URL_REDACTED = "<URL_REDACTED>"


def _scrub_string(value: str) -> str:
    out = JWT_PATTERN.sub(REDACTED, value)
    out = BEARER_PATTERN.sub(f"Bearer {REDACTED}", out)
    out = _TOKEN_MARKER_PATTERN.sub(lambda m: f"{m.group(1)}={REDACTED}", out)
    return _URL_VALUE_PATTERN.sub(URL_REDACTED, out)


def scrub_detail(detail: Any) -> Any:
    """``redact_audit_detail`` plus the JWT / bearer shapes and URL strings, for every integration audit row.

    Sensitive keys (``token``, ``secret``, ``authorization`` and friends, so
    ``foundry_token`` and ``x-foundry-token`` too) are blanked by the shared
    redactor; string values then lose any JWT-shaped or ``Bearer ...`` token and
    any URL (a row names a host, a rid, a digest, never a URL string).
    """
    cleaned = redact_audit_detail(detail)

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: (REDACTED if _is_sensitive_key(str(k)) else walk(v)) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, str):
            return _scrub_string(value)
        return value

    return walk(cleaned)


# ---------------------------------------------------------------------------
# The payload (spec 27.3 Foundry row; D9(ii), D9(iii))
# ---------------------------------------------------------------------------


class PayloadRefused(ValueError):
    """The payload failed :func:`validate_push_payload`; ``problems`` lists every reason."""

    code = "payload_refused"

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = list(problems)
        super().__init__("push payload refused: " + "; ".join(self.problems))


def _record(record: Any) -> CampaignRecord:
    if isinstance(record, CampaignRecord):
        return record
    return CampaignRecord.model_validate(record)


def atlas_release_block() -> dict[str, str]:
    """The pinned ATLAS release for a payload: ids, digests and dates only (no URL string may leave, spec 21.8).

    ``redsim.ml.atlas.release_citation`` carries the attribution sentence with the
    repository URL for the API views; the push payload cites the repository by
    name and the release by tag and digest instead.
    """
    return {
        "repo": atlas_data.ATLAS_REPO, "release": atlas_data.ATLAS_RELEASE, "version": atlas_data.ATLAS_VERSION,
        "format_version": atlas_data.ATLAS_FORMAT_VERSION, "published": atlas_data.ATLAS_RELEASE_PUBLISHED,
        "checked_on": atlas_data.ATLAS_CHECKED_ON, "data_file": atlas_data.ATLAS_DATA_FILE,
        "data_sha256": atlas_data.ATLAS_DATA_SHA256, "license": atlas_data.ATLAS_LICENSE,
        "license_sha256": atlas_data.ATLAS_LICENSE_SHA256,
        "attribution": (f"MITRE ATLAS technique ids and names reproduced from the {atlas_data.ATLAS_REPO} data "
                        f"release {atlas_data.ATLAS_RELEASE} ({atlas_data.ATLAS_LICENSE}); descriptions are not."),
    }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _row_eps(row: Any) -> float | None:
    value = row.params.get("eps")
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def build_scorecard_payload(record: Any, *, generated_at: datetime | None = None) -> dict[str, Any]:
    """The Foundry scorecard payload of a terminal campaign record (spec 27.3 Foundry row).

    Rows are one per (attack, ε) input of the ``MRIRecord`` (or, when no score
    was computed, one per evasion measurement row) and each carries ``n``,
    ``n_correct_clean``, the five subscores, the MRI, the grade, the grade
    sentence, ``settings_hash`` and ``computed_at``, so no row is ever a bare
    MRI column. Everything is copied from the record; nothing is recomputed.
    Recommendations, interpretation text, artifact locations, the model
    manifest, the host name and every Pythia setting are left out by
    construction.
    """
    rec = _record(record)
    stamp = (generated_at or datetime.now(UTC)).isoformat()
    config = rec.config
    score = rec.score
    provenance = rec.provenance
    model_sha256 = provenance.model_sha256 if provenance is not None else None
    settings_hash = rec.settings_hash or (score.settings_hash if score is not None else None) or (
        provenance.settings_hash if provenance is not None else None)
    subscores: dict[str, float | None] = (score.subscores.model_dump() if score is not None
                                          else {"S_acc": None, "S_asr": None, "S_eps": None, "S_conf": None,
                                                "S_expl": None})
    if score is not None:
        mri, grade, reading = score.mri, score.grade, score.reading
        completeness, missing, computed_at = score.completeness, list(score.missing), _iso(score.computed_at)
    else:
        mri, grade, reading = None, None, None
        completeness, computed_at = "partial", None
        status_reason = rec.score_status.reason if rec.score_status is not None else None
        missing = [f"MRI not computed: {status_reason or 'no score record on this run'}"]

    atlas: dict[str, dict[str, str] | None] = {}
    for attack_id in dict.fromkeys(config.attack_ids):
        tag = technique_for_attack(attack_id)
        atlas[attack_id] = tag.model_dump(mode="json") if tag is not None else None

    def atlas_fields(attack_id: str) -> dict[str, str | None]:
        tag = atlas.get(attack_id)
        return {"atlas_technique_id": tag["id"] if tag else None,
                "atlas_technique_name": tag["name"] if tag else None,
                "atlas_version": tag["atlas_version"] if tag else None}

    common = {
        "run_id": rec.run_id, "campaign_kind": rec.kind, "settings_hash": settings_hash,
        "model_sha256": model_sha256, "norm": config.norm, "reference_eps": config.reference_eps,
        "subscores": dict(subscores), "mri": mri, "grade": grade, "grade_statement": GRADE_STATEMENT,
        "reading": reading, "completeness": completeness, "computed_at": computed_at,
    }
    rows: list[dict[str, Any]] = []
    if score is not None and score.inputs:
        for inp in score.inputs:
            rows.append({
                **common, "attack_id": inp.attack_id, **atlas_fields(inp.attack_id), "eps": inp.eps,
                "is_reference_eps": inp.eps == config.reference_eps,
                "acc_clean": inp.acc_clean, "acc_adv": inp.acc_adv, "asr": inp.asr, "pert": inp.pert,
                "conf_gap": inp.conf_gap, "expl_shift": inp.expl_shift, "queries": inp.queries,
                "n": inp.n, "n_correct_clean": inp.n_correct_clean, "n_attacked": inp.n_attacked,
                "n_explained": inp.n_explained,
            })
    else:
        clean = next((m for m in rec.measurements if m.family == "clean"), None)
        for m in rec.measurements:
            eps = _row_eps(m)
            if m.family != "evasion" or m.attack_id is None or eps is None:
                continue
            rows.append({
                **common, "attack_id": m.attack_id, **atlas_fields(m.attack_id), "eps": eps,
                "is_reference_eps": eps == config.reference_eps,
                "acc_clean": clean.accuracy if clean is not None else None, "acc_adv": m.accuracy,
                "asr": m.attack_success_rate, "pert": m.pert_first_success_mean, "conf_gap": m.conf_gap_mean,
                "expl_shift": m.expl_shift_mean, "queries": m.queries_mean,
                "n": m.n, "n_correct_clean": m.n_clean_correct if m.n_clean_correct is not None else (
                    clean.n_correct if clean is not None else None),
                "n_attacked": m.n, "n_explained": m.expl_shift_n,
            })

    families = [{
        "measurement_id": m.id, "family": m.family, "attack_id": m.attack_id, "eps": _row_eps(m),
        "n": m.n, "n_correct": m.n_correct, "accuracy": m.accuracy,
        "n_clean_correct": m.n_clean_correct, "n_flipped_from_clean": m.n_flipped_from_clean,
        "attack_success_rate": m.attack_success_rate, "linf_norm_mean": m.linf_norm_mean,
        "l2_norm_mean": m.l2_norm_mean, "queries_mean": m.queries_mean,
    } for m in rec.measurements]

    curve = [{
        "attack_id": c.attack_id, "norm": c.norm, "eps_grid": list(c.eps_grid), "reference_eps": c.reference_eps,
        "clean": c.clean.model_dump(mode="json"),
        "points": [p.model_dump(mode="json") for p in c.points],
        "control": [p.model_dump(mode="json") for p in c.control],
    } for c in rec.curve]

    scorecard: dict[str, Any] = {
        "mri": mri, "grade": grade, "reading": reading, "grade_statement": GRADE_STATEMENT,
        "completeness": completeness, "missing": missing, "subscores": dict(subscores),
        "eps_grid": list(config.eps_grid), "reference_eps": config.reference_eps, "norm": config.norm,
        "attack_ids": list(config.attack_ids), "finding_asr_threshold": config.finding_asr_threshold,
        "settings_hash": settings_hash, "computed_at": computed_at,
        "weights": score.weights.as_dict() if score is not None else config.scoring.weights.as_dict(),
        "scoring_version": score.scoring_version if score is not None else None,
        "inputs": [i.model_dump(mode="json") for i in score.inputs] if score is not None else [],
        "per_attack": ({k: v.model_dump(mode="json") for k, v in score.per_attack.items()}
                       if score is not None else {}),
        "delta": score.delta.model_dump(mode="json") if score is not None and score.delta is not None else None,
    }

    prov: dict[str, Any] | None = None
    if provenance is not None:
        prov = {
            "redsim_version": provenance.redsim_version, "python": provenance.python, "torch": provenance.torch,
            "art": provenance.art, "shap": provenance.shap, "numpy": provenance.numpy,
            "onnxruntime": provenance.onnxruntime, "sklearn": provenance.sklearn, "xgboost": provenance.xgboost,
            "dataset": provenance.dataset, "dataset_revision": provenance.dataset_revision,
            "dataset_split": provenance.dataset_split, "sample_indices_sha256": provenance.sample_indices_sha256,
            "settings_hash": provenance.settings_hash, "baseline_run_id": provenance.baseline_run_id,
            "parent_run_id": provenance.parent_run_id, "device": provenance.device,
            "nondeterminism": list(provenance.nondeterminism),
            "started_at": _iso(provenance.started_at), "finished_at": _iso(provenance.finished_at),
        }

    return {
        "schema": PAYLOAD_SCHEMA,
        "run_id": rec.run_id,
        "campaign_kind": rec.kind,
        "campaign_status": rec.status,
        "baseline_run_id": rec.baseline_run_id,
        "target": {"id": rec.target.id, "name": rec.target.name, "domain": rec.target.domain,
                   "status": rec.target.status},
        "model_sha256": model_sha256,
        "settings_hash": settings_hash,
        "dataset": {"id": config.dataset_id, "revision": config.dataset_revision, "split": config.dataset_split,
                    "n_samples": config.n_samples, "seed": config.seed, "include_control": config.include_control,
                    "explain_k": config.explain_k},
        "defense": config.defense.model_dump(mode="json") if config.defense is not None else None,
        "scorecard": scorecard,
        "rows": rows,
        "families": families,
        "curve": curve,
        "atlas": atlas,
        "atlas_release": atlas_release_block(),
        "limitations": list(rec.limitations),
        "provenance": prov,
        "generated": {"generated_at": stamp, "record_schema_version": rec.schema_version,
                      "payload_schema": PAYLOAD_SCHEMA},
    }


def payload_bytes(payload: Mapping[str, Any]) -> bytes:
    """Canonical JSON bytes of a payload (sorted keys, one trailing newline)."""
    return (json.dumps(payload, sort_keys=True, indent=2, default=str) + "\n").encode("utf-8")


def rows_jsonl(payload: Mapping[str, Any]) -> bytes:
    """The ``rows`` of a payload as JSON Lines, one dataset row per line."""
    return "".join(json.dumps(row, sort_keys=True, default=str) + "\n" for row in payload.get("rows") or []
                   ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- the guard ------------------------------------------------------------------------------------------------

URL_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
MODEL_FILE_PATTERN = re.compile(r"\.(onnx|pt|pth|safetensors|pkl|pickle|joblib|h5|ckpt|npz|npy)\b", re.IGNORECASE)
_BASE64_BLOB_PATTERN = re.compile(r"^[A-Za-z0-9+/=_-]{256,}$")
MAX_STRING_LENGTH = 4096
#: Keys that never leave the platform (D9(iv) expected gain, reviewer notes, user identifiers, model bytes,
#: URL-bearing fields). Credential-shaped keys are caught by the shared redactor's rule.
FORBIDDEN_KEYS: frozenset[str] = frozenset({
    "expected_gain", "expected_robustness_gain", "reviewer_notes", "notes", "reviewer", "actor", "requested_by",
    "created_by", "email", "user", "user_id", "principal", "model_bytes", "state_dict", "weights_bytes",
    "artifact_path", "location", "url", "base_url", "gateway_url", "endpoint_url", "contentUrl", "hostname",
    "headers",
})
#: The five subscores a scorecard carries.
SUBSCORE_KEYS: tuple[str, ...] = ("S_acc", "S_asr", "S_eps", "S_conf", "S_expl")


def _mri_context_problems(mapping: Mapping[str, Any], path: str) -> list[str]:
    """A mapping that names ``mri`` or ``grade`` must carry the D9 context beside it."""
    problems: list[str] = []
    subscores = mapping.get("subscores")
    if not isinstance(subscores, Mapping) or set(SUBSCORE_KEYS) - set(subscores):
        problems.append(f"{path}: bare MRI: no subscores block with the five dimensions beside mri/grade")
    elif mapping.get("mri") is not None and any(subscores.get(k) is None for k in SUBSCORE_KEYS):
        problems.append(f"{path}: mri is set while a subscore is missing")
    if mapping.get("grade_statement") != GRADE_STATEMENT:
        problems.append(f"{path}: the grade sentence (GRADE_STATEMENT) is missing beside mri/grade")
    if not mapping.get("settings_hash"):
        problems.append(f"{path}: settings_hash is missing beside mri/grade")
    has_grid = isinstance(mapping.get("eps_grid"), list) and bool(mapping.get("eps_grid"))
    has_point = isinstance(mapping.get("eps"), (int, float)) and not isinstance(mapping.get("eps"), bool)
    if not (has_grid or has_point):
        problems.append(f"{path}: no eps grid or eps point beside mri/grade")
    inputs = mapping.get("inputs")
    if isinstance(inputs, list):
        if inputs and any(not (isinstance(i, Mapping) and i.get("n") is not None and "n_correct_clean" in i)
                          for i in inputs):
            problems.append(f"{path}: an inputs row lacks its denominators (n, n_correct_clean)")
        if not inputs and mapping.get("mri") is not None:
            problems.append(f"{path}: mri is set with no inputs rows")
    elif mapping.get("n") is None or "n_correct_clean" not in mapping:
        problems.append(f"{path}: no denominators (n, n_correct_clean) beside mri/grade")
    if mapping.get("mri") is not None and mapping.get("grade") is None:
        problems.append(f"{path}: mri without its grade")
    if mapping.get("mri") is None and mapping.get("grade") is not None:
        problems.append(f"{path}: grade without an mri")
    return problems


def _walk(value: Any, path: str, problems: list[str]) -> None:
    if isinstance(value, Mapping):
        if "mri" in value or "grade" in value:
            problems.extend(_mri_context_problems(value, path or "<root>"))
        for key, inner in value.items():
            name = str(key)
            here = f"{path}.{name}" if path else name
            if name in FORBIDDEN_KEYS:
                problems.append(f"{here}: forbidden key")
            elif _is_sensitive_key(name):
                problems.append(f"{here}: credential-shaped key")
            _walk(inner, here, problems)
        return
    if isinstance(value, (list, tuple)):
        for index, inner in enumerate(value):
            _walk(inner, f"{path}[{index}]", problems)
        return
    if isinstance(value, (bytes, bytearray, memoryview)):
        problems.append(f"{path}: raw bytes never leave the platform")
        return
    if isinstance(value, str):
        if URL_PATTERN.search(value):
            problems.append(f"{path}: URL string")
        if JWT_PATTERN.search(value) or BEARER_PATTERN.search(value):
            problems.append(f"{path}: credential-shaped value")
        if redact_audit_detail(value) != value:
            problems.append(f"{path}: token-shaped value")
        if MODEL_FILE_PATTERN.search(value):
            problems.append(f"{path}: model or tensor file name")
        if len(value) > MAX_STRING_LENGTH or _BASE64_BLOB_PATTERN.match(value):
            problems.append(f"{path}: oversized or base64 blob (model bytes never leave the platform)")
        if contains_banned_score_word(value):
            problems.append(f"{path}: banned readiness word")


def validate_push_payload(payload: Any) -> list[str]:
    """Every problem with a payload that is about to leave the platform; ``[]`` means it may go.

    Structural rules: the payload is a mapping with ``schema``, ``run_id`` and
    ``settings_hash``, non-empty ``rows`` (each with ``n`` and
    ``n_correct_clean``), a ``scorecard`` with ``subscores``, ``eps_grid``,
    ``inputs`` and the grade sentence, and non-empty ``limitations``. Content
    rules: see the module docstring. A payload is refused on any problem;
    nothing is trimmed to make it pass.
    """
    problems: list[str] = []
    if not isinstance(payload, Mapping):
        return ["payload is not a mapping"]
    if payload.get("schema") != PAYLOAD_SCHEMA:
        problems.append(f"schema must be {PAYLOAD_SCHEMA!r}")
    if not payload.get("run_id"):
        problems.append("run_id is missing")
    if not payload.get("settings_hash"):
        problems.append("settings_hash is missing")
    rows = payload.get("rows")
    if not isinstance(rows, list) or not rows:
        problems.append("rows is empty: nothing measured, nothing to push")
    scorecard = payload.get("scorecard")
    if not isinstance(scorecard, Mapping):
        problems.append("scorecard block is missing")
    else:
        if not scorecard.get("eps_grid"):
            problems.append("scorecard.eps_grid is empty")
        if scorecard.get("mri") is not None and not scorecard.get("inputs"):
            problems.append("scorecard carries an mri without its inputs table")
        if scorecard.get("mri") is None and not scorecard.get("missing"):
            problems.append("scorecard has no mri and does not say what is missing")
    limitations = payload.get("limitations")
    if not isinstance(limitations, list) or not limitations:
        problems.append("limitations is empty: a scorecard never leaves without the run's limitations")
    _walk(payload, "", problems)
    return problems


def assert_push_payload(payload: Any) -> None:
    """:func:`validate_push_payload`, raising :class:`PayloadRefused` on the first non-empty result."""
    problems = validate_push_payload(payload)
    if problems:
        raise PayloadRefused(problems)


# ---------------------------------------------------------------------------
# The REST client (Foundry Datasets v2: transaction, files, commit)
# ---------------------------------------------------------------------------


class FoundryPushFailed(RuntimeError):
    """A push step failed; ``step``, ``http_status`` and ``error_class`` are what the audit row records."""

    code = "foundry_push_failed"

    def __init__(self, step: str, http_status: int | None, message: str, *, error_class: str | None = None,
                 aborted: bool | None = None) -> None:
        self.step = step
        self.http_status = http_status
        self.error_class = error_class
        self.aborted = aborted
        super().__init__(f"{step}: {message}")

    def outcome(self) -> dict[str, Any]:
        """Audit detail of the failure: step, status, class; never a body, a URL or a token."""
        return {"outcome": "failed", "step": self.step, "http_status": self.http_status,
                "error_class": self.error_class, "transaction_aborted": self.aborted}


@dataclass(frozen=True)
class PushedFile:
    path: str
    sha256: str
    size_bytes: int
    http_status: int


@dataclass
class PushReceipt:
    """What a completed push records: identifiers, digests, sizes and statuses only."""

    host: str
    dataset_rid: str
    transaction_rid: str
    files: list[PushedFile] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)
    tls_mode: str = "default"
    pushed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    outcome: str = "pushed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "integration": INTEGRATION, "host": self.host, "dataset_rid": self.dataset_rid,
            "transaction_rid": self.transaction_rid, "outcome": self.outcome, "pushed_at": self.pushed_at,
            "tls_mode": self.tls_mode, "http_statuses": list(self.statuses), "n_files": len(self.files),
            "bytes_total": sum(f.size_bytes for f in self.files),
            "files": [{"path": f.path, "sha256": f.sha256, "size_bytes": f.size_bytes, "http_status": f.http_status}
                      for f in self.files],
        }


def _tls_verify(settings: FoundrySettings) -> tuple[ssl.SSLContext | bool, str]:
    if settings.plaintext_loopback:
        return False, "plaintext-loopback"
    from redsim.llm.pythia import tls_verify

    return tls_verify()


class FoundryClient:
    """The one Foundry transport: ``httpx`` against the Datasets v2 REST API with a caller-supplied token.

    ``transport`` (an ``httpx.MockTransport``) bypasses the network in tests;
    otherwise TLS verification is the truststore helper of ``redsim.llm.pythia``
    (a plaintext loopback URL, allowed only for a loopback host, skips it). The
    token is held on the client instance for the client's lifetime only and is
    never logged; response bodies are read for the transaction rid and nothing
    else.
    """

    def __init__(self, settings: FoundrySettings, token: str, *, transport: httpx.BaseTransport | None = None,
                 verify: ssl.SSLContext | bool | None = None) -> None:
        if not token or any(ch.isspace() for ch in token):
            raise FoundryPushFailed("credential", None, "the bearer token is empty or malformed",
                                    error_class="ValueError")
        from redsim import __version__

        self.settings = settings
        kwargs: dict[str, Any] = {
            "base_url": settings.base_url, "timeout": settings.timeout_s,
            "headers": {"Authorization": f"Bearer {token}", "Accept": "application/json",
                        "User-Agent": f"redsim/{__version__} integration.push"},
        }
        if transport is not None:
            kwargs["transport"] = transport
            self.tls_mode = "transport"
        else:
            if verify is None:
                verify, self.tls_mode = _tls_verify(settings)
            else:
                self.tls_mode = "explicit"
            kwargs["verify"] = verify
        self._client = httpx.Client(**kwargs)

    # -- lifecycle ----------------------------------------------------------------------------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> FoundryClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- one step -----------------------------------------------------------------------------

    def _request(self, step: str, method: str, path: str, *, params: Mapping[str, str] | None = None,
                 content: bytes | None = None, content_type: str | None = None) -> httpx.Response:
        headers = {"Content-Type": content_type} if content_type else None
        try:
            response = self._client.request(method, path, params=params, content=content, headers=headers)
        except httpx.HTTPError as exc:
            # httpx messages can carry the request URL; only the class name travels.
            raise FoundryPushFailed(step, None, f"transport error ({type(exc).__name__})",
                                    error_class=type(exc).__name__) from None
        if response.status_code >= 400:
            raise FoundryPushFailed(step, response.status_code, f"HTTP {response.status_code}",
                                    error_class="HTTPStatusError")
        return response

    @staticmethod
    def _rid_path(dataset_rid: str) -> str:
        return f"{API_ROOT}/{quote(dataset_rid, safe='')}"

    def create_transaction(self, dataset_rid: str, *, transaction_type: str = "APPEND") -> tuple[str, int]:
        """Open a transaction; ``(transaction rid, status)``."""
        response = self._request("create_transaction", "POST", f"{self._rid_path(dataset_rid)}/transactions",
                                 params={"transactionType": transaction_type}, content=b"{}",
                                 content_type="application/json")
        try:
            body = response.json()
        except ValueError:
            raise FoundryPushFailed("create_transaction", response.status_code,
                                    "response carried no JSON transaction", error_class="ValueError") from None
        rid = body.get("rid") if isinstance(body, Mapping) else None
        if not isinstance(rid, str) or not rid:
            raise FoundryPushFailed("create_transaction", response.status_code, "response carried no transaction rid",
                                    error_class="ValueError")
        return rid, response.status_code

    def upload_file(self, dataset_rid: str, transaction_rid: str, path: str, data: bytes, *,
                    content_type: str = "application/octet-stream") -> int:
        """Upload one file into the open transaction; the HTTP status."""
        response = self._request(
            "upload_file", "POST", f"{self._rid_path(dataset_rid)}/files/{quote(path, safe='')}/upload",
            params={"transactionRid": transaction_rid}, content=data, content_type=content_type,
        )
        return response.status_code

    def commit_transaction(self, dataset_rid: str, transaction_rid: str) -> int:
        response = self._request(
            "commit_transaction", "POST",
            f"{self._rid_path(dataset_rid)}/transactions/{quote(transaction_rid, safe='')}/commit",
        )
        return response.status_code

    def abort_transaction(self, dataset_rid: str, transaction_rid: str) -> int | None:
        """Best-effort abort after a failed upload or commit; ``None`` when the abort itself failed."""
        try:
            response = self._client.request(
                "POST", f"{self._rid_path(dataset_rid)}/transactions/{quote(transaction_rid, safe='')}/abort",
            )
        except httpx.HTTPError:
            return None
        return response.status_code

    # -- the push -----------------------------------------------------------------------------

    def push_files(self, dataset_rid: str, files: Sequence[tuple[str, bytes, str]]) -> PushReceipt:
        """Open a transaction, upload every ``(path, bytes, content type)``, commit; a receipt or a failure.

        A failure after the transaction is open aborts it (best effort) and is
        raised as :class:`FoundryPushFailed` carrying the step, the status and
        whether the abort answered. Nothing is retried.
        """
        target = validate_target_ref(dataset_rid)
        if target is None:
            raise FoundryPushFailed("target_ref", None, "no dataset rid to push to", error_class="ValueError")
        if not files:
            raise FoundryPushFailed("files", None, "nothing to push", error_class="ValueError")
        transaction_rid, status = self.create_transaction(target)
        receipt = PushReceipt(host=self.settings.host, dataset_rid=target, transaction_rid=transaction_rid,
                              statuses=[status], tls_mode=self.tls_mode)
        try:
            for path, data, content_type in files:
                upload_status = self.upload_file(target, transaction_rid, path, data, content_type=content_type)
                receipt.statuses.append(upload_status)
                receipt.files.append(PushedFile(path=path, sha256=sha256_hex(data), size_bytes=len(data),
                                                http_status=upload_status))
            receipt.statuses.append(self.commit_transaction(target, transaction_rid))
        except FoundryPushFailed as exc:
            aborted = self.abort_transaction(target, transaction_rid)
            raise FoundryPushFailed(exc.step, exc.http_status, str(exc).split(": ", 1)[-1],
                                    error_class=exc.error_class, aborted=aborted is not None) from None
        return receipt


def scorecard_files(payload: Mapping[str, Any], *, prefix: str | None = None) -> list[tuple[str, bytes, str]]:
    """The two files a scorecard push writes under ``redsim/scorecards/<run_id>/``: the payload and its rows."""
    run_id = str(payload.get("run_id") or "run")
    base = prefix.rstrip("/") if prefix else f"redsim/scorecards/{run_id}"
    return [
        (f"{base}/{SCORECARD_FILE}", payload_bytes(payload), "application/json"),
        (f"{base}/{ROWS_FILE}", rows_jsonl(payload), "application/x-ndjson"),
    ]


__all__ = [
    "API_ROOT",
    "BEARER_PATTERN",
    "DEFAULT_TIMEOUT_S",
    "FORBIDDEN_KEYS",
    "FOUNDRY_ATTESTATION_ENV",
    "FOUNDRY_DATASET_RID_ENV",
    "FOUNDRY_ENV_NAMES",
    "FOUNDRY_TIMEOUT_ENV",
    "FOUNDRY_URL_ENV",
    "INTEGRATION",
    "JWT_PATTERN",
    "MISCONFIGURED_REASONS",
    "MODEL_FILE_PATTERN",
    "PAYLOAD_SCHEMA",
    "REDACTED",
    "ROWS_FILE",
    "SCORECARD_FILE",
    "SUBSCORE_KEYS",
    "URL_PATTERN",
    "URL_REDACTED",
    "FoundryClient",
    "FoundryMisconfigured",
    "FoundryPushFailed",
    "FoundrySettings",
    "PayloadRefused",
    "PushReceipt",
    "PushedFile",
    "assert_push_payload",
    "atlas_release_block",
    "build_scorecard_payload",
    "foundry_status",
    "payload_bytes",
    "rows_jsonl",
    "scorecard_files",
    "scrub_detail",
    "sha256_hex",
    "validate_push_payload",
    "validate_target_ref",
]
