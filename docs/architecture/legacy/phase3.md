# Aegis Phase 3 architecture

> Canonical source: see `PLAN_PHASE3.md` at the repo root and the approved
> wave plan at `/Users/noah.behrick/.claude/plans/take-the-plan-document-splendid-zephyr.md`.
> This document is a stable summary intended for new contributors.

## Layering

```
┌───────────────────────────────────────────────────────────────────┐
│                          aegis/cli.py                             │
│   Offline filesystem mode (default) ─ thin argparse + UX layer    │
└─────┬───────────────────────────────────────────────┬─────────────┘
      │                                               │
      │ same service calls                            │ same service calls
      ▼                                               ▼
┌────────────────────────┐                ┌──────────────────────────┐
│ aegis/services/*       │◄──────────────►│ aegis/workers/* (Celery) │
│  - start_scan          │                │ - scan_start             │
│  - generate_fix        │                │ - fix_generate           │
│  - verify              │                │ - verify_replay          │
│  - render_reports      │                │ - report_render          │
│  - run_kali_tool       │                │ - ci_gate                │
└─────┬──────────────────┘                └─────────┬────────────────┘
      │                                              │
      │ persistence (sync SQLAlchemy)                │ blob put/get
      ▼                                              ▼
┌────────────────────────────────────┐  ┌──────────────────────────┐
│ aegis/db, aegis/state_pg,          │  │ aegis/blobs.py           │
│ aegis/state_facade.RunStateAPI     │  │ - FilesystemBlobStore    │
│ - FilesystemRunState (offline)     │  │ - S3BlobStore (MinIO/S3) │
│ - PostgresRunState (API/worker)    │  └──────────────────────────┘
└────────────────────────────────────┘
      │
      │ ↑ audit emitted at service boundaries
      ▼
┌────────────────────────────────────┐
│ aegis/audit/chain.py               │
│ - JsonlAuditWriter (offline)       │
│ - PostgresAuditWriter (API/worker) │
│ - verify_chain()                   │
└────────────────────────────────────┘
```

## Tenancy

Every domain row carries a `project_id`. A `project` belongs to an `organization`.
Users are members of one or more projects with a role
(`scanner` / `remediator` / `approver` / `admin`). RBAC is resource-scoped:
a user may hold different roles on different projects.

## API mode is opt-in

`AEGIS_MODE=api` (or `aegis --api`) routes CLI commands through the FastAPI
service. Without that, `aegis` continues to write directly to
`aegis_output/runs/<run_id>/` and the existing 121 offline tests must stay
green at every Phase 3 commit.

## Audit chain scope

- **Per-run chain**: `chain_id = run:<run_id>`. One ordered sequence per run.
- **Per-project chain**: `chain_id = project:<project_id>`. Project-level
  events with no specific run.
- **System chain**: `chain_id = system`. Install-wide events.

`aegis audit verify --run <id>` walks one chain; `--all` walks every chain
the writer knows about.

## Why sync SQLAlchemy

The worker bodies invoke subprocesses (Strix, Trivy, git apply) and the
existing Phase 2 functions are synchronous. Mixing async ORM into that path
buys nothing and complicates testability. FastAPI handles async at its own
edge; everything below the service boundary is sync.

## Compose stack

`deploy/docker-compose.yml` brings up: `postgres`, `redis`, `keycloak`,
`minio`, `kali` (built from `project_repos/mcp-kali-server`), `aegis-api`,
`aegis-worker`, `aegis-web`, and optionally `jaeger` (profile-gated).
`make up` + `make seed` is the canonical local stack bring-up.
