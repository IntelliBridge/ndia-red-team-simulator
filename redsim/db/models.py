"""SQLAlchemy 2.x models for the Phase 3 schema.

Tenancy is in from day one: every domain row carries a ``project_id`` (or
the chain row carries a nullable project_id for system-scope chains).

``findings.schema_blob`` is the RedsimFinding dict — the downstream
contract. New columns may be added; renames are migrations with a
deprecation cycle.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import NotRequired, TypedDict

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    slug: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    # Per-tenant LLM cost + routing (migration 0006). monthly cap in cents
    # (NULL == uncapped); llm_model_overrides is a {task: model} map that wins
    # over the RedsimConfig default in redsim.llm.router.route().
    monthly_llm_budget_cents: Mapped[int | None] = mapped_column(Integer, nullable=True)
    llm_model_overrides: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    slug: Mapped[str] = mapped_column(String(128), nullable=False)
    daily_llm_budget_cents: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Phase B (migration 0011_phase_b_platform), all nullable and additive.
    # ``ml_scoring`` holds a full ``ScoringConfig`` (redsim/ml/schema.py) as
    # the per-project override; NULL means the deployment default. It is
    # validated at the settings route, never renormalised, and read at
    # campaign admission. ``ml_max_concurrent_runs`` caps concurrent ML runs
    # per project and ``ml_daily_run_budget`` caps ML admissions per UTC day;
    # NULL means the deployment default (``REDSIM_ML_MAX_CONCURRENT_RUNS_PER_PROJECT``)
    # or uncapped (``REDSIM_ML_PROJECT_DAILY_RUN_BUDGET`` unset).
    ml_scoring: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    ml_max_concurrent_runs: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ml_daily_run_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # 0013_foundry_auto_push (2026-09-10): ``{"foundry": {dataset_rid, auth_profile_id,
    # auto_push, updated_at, updated_by}}`` as redsim.services.ml_integrations reads
    # and writes it. NULL means nothing configured. The host, attestation and
    # allowlist stay operator-set in the environment (spec 27.3).
    ml_integrations: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (UniqueConstraint("org_id", "slug"),)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    sub: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(256), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ProjectMembership(Base):
    __tablename__ = "project_memberships"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    # Denormalized tenant key for Postgres RLS (migration 0005). Nullable on
    # the ORM because a BEFORE INSERT trigger backfills it from the row's
    # project — app code never sets it. See redsim/db/session.py for the GUC.
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)   # url|github_repo|image
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    # Adversarial-ML manifest, validation state, and source metadata. Migration
    # 0010 adds the nullable JSONB column so existing non-ML targets remain
    # unchanged.
    detail: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    allowlist_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    installation_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuthProfile(Base):
    """Authenticated-DAST credential profile (Phase 5).

    ``config`` carries only NON-secret fields (login_url, username_field,
    password_field, username, header_name, cookie_name, …). The secret
    itself is Fernet-encrypted at rest in ``secret_ciphertext``
    (``redsim.security_utils.secrets``) and is only decrypted by
    ``services.auth_profiles.resolve_auth_for_scan`` for the worker —
    no API response ever includes it.
    """
    __tablename__ = "auth_profiles"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # form|bearer|header|cookie
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    secret_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (
        UniqueConstraint("project_id", "name", name="uq_auth_profiles_project_name"),
    )


class Run(Base):
    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    # Denormalized tenant key for RLS (0005); trigger-backfilled, see Target.
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    target_id: Mapped[str | None] = mapped_column(ForeignKey("targets.id"), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(256))
    mode: Mapped[str] = mapped_column(String(32), default="live")
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    scanner: Mapped[str | None] = mapped_column(String(64))
    stage_table: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    # Denormalized tenant key for RLS (0005); trigger-backfilled, see Target.
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    celery_task_id: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[str | None] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)


class FixJobDetail(TypedDict):
    """Shape of ``Job.detail`` for ``fix.generate`` jobs.

    The admission service (``services.fixes.create_fix_job``) writes the
    required keys. The worker (``workers.tasks.fix``) additionally reads
    the ``NotRequired`` keys, which admission never sets — so they fall
    back to ``generate_fix`` defaults. Marking them ``NotRequired`` makes
    that read-without-write seam explicit instead of silently drifting.
    """

    finding_id: str
    strategy: str
    apply: bool
    open_pr: bool
    repo: str | None
    branch: NotRequired[str | None]
    allow_dirty: NotRequired[bool]
    push: NotRequired[bool]
    use_golden_patch: NotRequired[bool]
    override_authorized: NotRequired[bool]


class Finding(Base):
    """Phase 4 v0.3.1 F9: ``id`` is now an internal UUID; the scanner's
    upstream identifier lives in ``scanner_finding_id`` and is uniquely
    constrained per-run, not globally. This prevents PK collisions when
    two runs independently emit findings with the same scanner-side ID
    (e.g. both emit ``vuln-0001`` from Strix).

    The ``schema_blob.id`` field still carries the scanner's original
    identifier for downstream contract stability — vulnfixer export,
    report HTML, deps_workflow continue to see what they expect.
    """
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # UUID
    scanner_finding_id: Mapped[str] = mapped_column(String(256), nullable=False)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    # Denormalized tenant key for RLS (0005); trigger-backfilled, see Target.
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    schema_blob: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    source_tool: Mapped[str | None] = mapped_column(String(64), index=True)
    dedup_key: Mapped[str | None] = mapped_column(String(256), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (
        UniqueConstraint("run_id", "scanner_finding_id",
                         name="uq_findings_run_scanner_id"),
        Index("ix_findings_scanner_finding_id", "scanner_finding_id"),
    )


class FindingTicket(Base):
    """External-tracker ticket synced from a finding (Jira/ServiceNow/Linear).

    One row per ``(finding_id, provider)``: re-syncing the same finding to
    the same provider upserts this row rather than creating duplicates. The
    ``external_id`` is the tracker's own identifier (Jira key, ServiceNow
    sys_id, Linear issue id); ``status`` is refreshed from the tracker on a
    bidirectional pull. No secret/credential is ever stored here.
    """
    __tablename__ = "finding_tickets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # UUID
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    external_id: Mapped[str] = mapped_column(String(256), nullable=False)
    url: Mapped[str | None] = mapped_column(String(1024))
    status: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (
        UniqueConstraint("finding_id", "provider",
                         name="uq_finding_tickets_finding_provider"),
    )


class LLMUsage(Base):
    __tablename__ = "llm_usage"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    # Denormalized tenant key for RLS (0005); trigger-backfilled, see Target.
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    task: Mapped[str] = mapped_column(String(64), nullable=False)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_cents: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (Index("ix_llm_usage_project_created", "project_id", "created_at"),)


class Artifact(Base):
    __tablename__ = "artifacts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    # Denormalized tenant key for RLS (0005); trigger-backfilled, see Target.
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    location: Mapped[str] = mapped_column(String(1024), nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (UniqueConstraint("run_id", "kind", "sha256"),)


class RemediationAttempt(Base):
    __tablename__ = "remediation_attempts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    # Denormalized tenant key for RLS (0005); trigger-backfilled, see Target.
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    branch: Mapped[str | None] = mapped_column(String(256))
    commit_hash: Mapped[str | None] = mapped_column(String(64))
    ref_before: Mapped[str | None] = mapped_column(String(64))
    diff_sha256: Mapped[str | None] = mapped_column(String(64))
    pr_url: Mapped[str | None] = mapped_column(String(1024))
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chain_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    actor: Mapped[str] = mapped_column(String(256), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str | None] = mapped_column(String(1024))
    allowlist_check: Mapped[str] = mapped_column(String(16), nullable=False)
    override: Mapped[bool] = mapped_column(Boolean, default=False)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    schema_version: Mapped[int] = mapped_column(Integer, default=1)
    prev_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    this_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (
        UniqueConstraint("chain_id", "seq", name="uq_audit_events_chain_seq"),
        UniqueConstraint("chain_id", "this_hash", name="uq_audit_events_chain_hash"),
    )


class AuditChainHead(Base):
    __tablename__ = "audit_chain_heads"
    chain_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    head_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    head_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class GitHubInstallation(Base):
    __tablename__ = "github_installations"
    installation_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_login: Mapped[str] = mapped_column(String(256), nullable=False)
    account_type: Mapped[str] = mapped_column(String(32), default="Organization")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ApplicationLog(Base):
    """Phase 4 v0.4.1 F20c — Postgres mirror of the OTel log stream.

    The Collector exporter fans out to Loki / Elasticsearch under the
    ``obs`` and ``obs-search`` compose profiles; the always-on
    Postgres path lands here via ``redsim-log-ingest``. The schema
    intentionally carries every correlation key the API + worker +
    scanner emit so a single ``WHERE run_id = …`` returns the full
    trace of a request across services.
    """
    __tablename__ = "application_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    service: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    run_id: Mapped[str | None] = mapped_column(String(64), index=True)
    job_id: Mapped[str | None] = mapped_column(String(64), index=True)
    project_id: Mapped[str | None] = mapped_column(String(64), index=True)
    # Denormalized tenant key for RLS (0005); trigger-backfilled, see Target.
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    actor: Mapped[str | None] = mapped_column(String(256))
    request_id: Mapped[str | None] = mapped_column(String(128), index=True)
    trace_id: Mapped[str | None] = mapped_column(String(64), index=True)
    span_id: Mapped[str | None] = mapped_column(String(32))
    attrs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)


# --------------------------------------------------------------------------- Phase B
# Migration ``0011_phase_b_platform``. Every table below carries the Phase 6
# tenant rails of ``ml_campaigns`` (0010): a denormalized ``org_id`` that a
# BEFORE INSERT trigger backfills from the project, a BEFORE UPDATE drift
# guard, ``FORCE ROW LEVEL SECURITY`` and the ``redsim_tenant_isolation``
# policy. Application code never sets ``org_id``. ``ml_campaigns`` itself stays
# migration-owned (reflected by the services, no ORM model) so the hand-written
# sqlite mirrors in the test harnesses keep working; 0011 only adds its
# ``batch_id`` column.


class ReportSnapshot(Base):
    """One immutable row per rendered report (spec F007, REVIEW_REPORTS-20).

    The bytes live in the content-addressed ``artifacts`` rows named by
    ``artifact_ids``; ``record_sha256`` is the digest of the ``CampaignRecord``
    the render was projected from, so a snapshot can be checked against the
    run record it claims to show. ``archived`` hides a snapshot from listings
    without deleting evidence.
    """
    __tablename__ = "report_snapshots"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    # Denormalized tenant key for RLS (0011); trigger-backfilled, see Target.
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    artifact_ids: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'"))
    record_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    rendered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, server_default=func.now())
    archived: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false"))
    created_by: Mapped[str | None] = mapped_column(String(256))


class IdempotencyKey(Base):
    """Stored request identity for ``Idempotency-Key`` on mutating routes
    (spec F004 US1, REVIEW_REPORTS-31).

    The primary key is ``(project_id, key)``: the same key replayed within a
    project returns the stored ``response_status`` and ``response_body`` when
    ``route`` and ``request_sha256`` (canonical JSON body) match, and is
    refused when they do not. Expiry is derived from ``created_at`` by the
    middleware and the reaper; nothing here is a secret.
    """
    __tablename__ = "idempotency_keys"
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), primary_key=True)
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    # Denormalized tenant key for RLS (0011); trigger-backfilled, see Target.
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    route: Mapped[str] = mapped_column(String(256), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    response_status: Mapped[int] = mapped_column(Integer, nullable=False)
    response_body: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, server_default=func.now())
    __table_args__ = (
        PrimaryKeyConstraint("project_id", "key", name="pk_idempotency_keys"),
    )


class MlBatch(Base):
    """A bulk operation (BULK-01): N linked runs or uploads under one id.

    ``kind`` is ``campaign`` (one ``CampaignConfig`` over N models) or
    ``upload`` (bulk model upload). ``config`` is
    the request as admitted (target ids, campaign body, refused members and
    their reasons). ``status`` is the batch's own lifecycle (``accepted``,
    then ``cancelled`` once ``cancelled_at`` is stamped); the member roll-up
    is derived from the linked runs (``ml_campaigns.batch_id``) so no single
    word hides a failed member. ``idempotency_key`` and ``request_sha256``
    let a replayed batch request return the same batch.
    """
    __tablename__ = "ml_batches"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    # Denormalized tenant key for RLS (0011); trigger-backfilled, see Target.
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # campaign|upload
    config: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'"))
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="accepted", server_default="accepted")
    created_by: Mapped[str | None] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, server_default=func.now())
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    request_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)


class MlDataset(Base):
    """A consumed evaluation slice registered through ``POST /v1/datasets``
    (spec 27.1 consume side, INTEROP-14).

    ``status`` moves ``validating`` -> ``available`` | ``refused`` on the
    worker after the sandbox child parses the files; ``refusal_reason`` is the
    typed reason. ``manifest_sha256`` is the dataset revision. ``detail``
    carries what the parse reports (declared schema, per-file sha256s,
    ``n_rows``, per-class counts) so the frozen ``redsim/ml/schema.py`` is
    untouched. Bytes never live here: ``blob_location`` names the artifact
    store prefix.
    """
    __tablename__ = "ml_datasets"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    # Denormalized tenant key for RLS (0011); trigger-backfilled, see Target.
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(  # validating | available | refused
        String(16), nullable=False, default="validating", server_default="validating")
    refusal_reason: Mapped[str | None] = mapped_column(Text)
    license: Mapped[str | None] = mapped_column(String(256))
    modality: Mapped[str | None] = mapped_column(String(16))
    class_names: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    manifest_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    blob_location: Mapped[str | None] = mapped_column(String(1024))
    detail: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, server_default=func.now())


class DatasetRegisterJobDetail(TypedDict):
    """Shape of ``Job.detail`` for ``dataset.register`` jobs (INTEROP-14).

    Admission writes every key: the ``ml_datasets`` row to update, where the
    uploaded bytes were stored, and what the uploader declared about them.
    The worker verifies the declaration inside the sandbox child and moves
    the row's ``status``.
    """

    dataset_id: str
    blob_location: str
    declared_format: str
    declared_sha256: str
