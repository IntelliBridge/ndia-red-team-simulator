# Adversarial ML Red-Team Simulator (aegis/ml)

This repository is `aegis-platform`, a fork of the IntelliBridge `aegis`
codebase. The adversarial-ML red-team work is one new vertical, `aegis/ml/`,
added to that platform. An earlier attempt stripped the platform down to a
standalone `redsim/` package; that split was reverted on 2026-09-08 and
`redsim/` is gone. Ignore any remaining "redsim" names except as history.

## What is authoritative

1. `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md` — the
   product spec. Its decisions D1-D13 (section 4) are final and override every
   other source. It supersedes the older `docs/adversarial-ml-redteam-spec.md`
   and `docs/superpowers/specs/2026-09-08-redsim-design.md`.
2. `specs/F001`-`F008` — the Spec Kit feature layer beneath the product spec.
   Where a feature file conflicts with the product spec, the product spec wins.
3. `docs/plans/` — the parallel-execution plan (a master plan plus per-phase
   plans mapped to milestones M0-M7 and features F001-F008). Start with
   `docs/plans/EXECUTION-CONTEXT.md`, then `docs/plans/00-master-plan.md`.

## State of the code

The aegis platform (FastAPI API, Celery workers, Postgres, Redis, S3/MinIO,
Keycloak/NextAuth, RBAC, RLS, hash-chained audit, LLM routing via Pythia) is
restored and present. The ML vertical is **contracts only**:

| Module | What it holds |
|---|---|
| `aegis/ml/schema.py` | The evidence model: `RunConfig`, `RunRecord`, `RunSummary`, `Observation`, `Measurement`, `CandidateRecommendation`, `TargetInfo`, `AttackInfo` |
| `aegis/ml/targets/base.py` | `Target` Protocol, `Sample` |
| `aegis/ml/attacks/base.py` | `AttackAdapter` Protocol, `AttackOutput` |

Not written yet: concrete targets, attacks, explainers, `aegis/ml/scoring.py`,
`aegis/ml/campaign.py`, the ML Celery tasks, the ML routers under
`aegis/api/v1/`, the `aegis ml build-assets` CLI, and the `0010_ml_vertical`
migration. `tests/ml/` covers only the test double `TinyTarget`.

## Adding the backend

The API factory is `aegis/api/app.py:create_app(settings)`. New ML routers mount
on it under `/v1`. A campaign starts with `POST /v1/models/{id}/attacks`, not a
generic `POST /v1/runs`. Jobs run on Celery workers governed by
`aegis/workers/job_state.py`, with model loading in a sandboxed child
subprocess. Run and evidence state lives in Postgres (`runs`, `jobs`,
`findings`, `artifacts`, a new `ml_campaigns` table) plus S3/MinIO for bytes;
the run record is written as a sha256-addressed Artifact and projected onto
`ml_campaigns` and `Finding.schema_blob.ml`. See the canonical spec sections 6,
8, 10, and 17, and `docs/plans/00-master-plan.md` section 5.

## Development

`make install`, then `make dev`. `make check` runs lint, typecheck, and tests.
The venv is pinned to Python 3.12 because `torch` and
`adversarial-robustness-toolbox` do not publish 3.14 wheels. CI runs in
`.github/workflows/aegis-ci.yml`; the AWS build-and-deploy pipeline is
`.github/workflows/deploy-aws.yml`. Operational facts (AWS state, the Zscaler
CA, known bugs, key rotation) are in `docs/plans/EXECUTION-CONTEXT.md`.

## Conventions

Commits are `type(topic): description`. Branch before committing; do not commit
to `main` directly. Prose in docs and comments avoids em dashes and semicolons.

## Not authoritative

`README.md`, `.env.example`, and `deploy/docker-compose.yml` carry a mix of
current and inherited-aegis content; trust the canonical spec and the plans over
them. Interoperability (Croissant export, MITRE ATLAS, Palantir/Lattice) is not
in the canonical spec and is deferred; `docs/plans/07-p6-interoperability.md` is
out of scope until it is re-proposed as a feature.
