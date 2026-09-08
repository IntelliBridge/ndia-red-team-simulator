# Execution context — cold-start guide

Read this before executing any phase plan in a fresh session. It carries the
operational facts that are not in the phase files, and the order to read things.

## Read order

1. **This file.**
2. **Canonical spec** — `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`.
   It is authoritative. Decisions D1-D13 (section 4) are final and override every
   other source.
3. **Master plan** — `docs/plans/00-master-plan.md`. The parallel-execution
   overlay: workstreams mapped to milestones M0-M7 and features F001-F008, the
   shared contracts, and the build waves.
4. **Your phase file** — `docs/plans/0N-*.md`. The bodies are v2, rebased on the
   aegis substrate.
5. **Feature detail** — `specs/F001`-`F008` (`spec.md`, `plan.md`, `tasks.md`).
   Where a feature file conflicts with the canonical spec, the spec wins.
6. **The code you will touch** — `aegis/ml/`, `aegis/api/v1/`, `aegis/workers/`,
   `aegis/services/`, `aegis/db/`.

## Repo ground truth

- The package is `aegis-platform` (a fork of aegis). The ML vertical lives in
  `aegis/ml/` and is **contracts only** today: `schema.py` (the evidence model),
  `targets/base.py` (`Target` Protocol), `attacks/base.py` (`AttackAdapter`
  Protocol). No concrete targets, attacks, explainers, or ML routes exist yet.
- The console script is `aegis = aegis.cli:main`. `redsim` is retired.
- The API factory is `aegis/api/app.py:create_app(settings)`. ML routers mount
  on it under `/v1`. There is no separate ML app.
- Python is pinned to 3.12 (torch and ART have no 3.14 wheels).
- Dev flow: `make install`, then `make dev`. `make check` runs lint, typecheck,
  and tests. CI is real now: `.github/workflows/aegis-ci.yml`.
- Corporate proxy: a Zscaler root CA sits at
  `/Users/john.sasser/.certs/zscaler-root-ca.pem`. Export `AWS_CA_BUNDLE` and
  `NODE_EXTRA_CA_CERTS` to that path for `aws` and Node egress.

## Conventions

- Branch before committing. Do not commit to `main` directly.
- Commit messages are `type(topic): description`.
- Prose in docs and comments avoids em dashes and semicolons.

## AWS and CI already provisioned

Account `140381642432`, region `us-east-1`:

- A GitHub OIDC provider and IAM role `ndia-red-team-gha-deploy` (ECR push, ECS
  deploy, and PassRole to `ndia-red-team-*` task roles).
- ECR repositories `ndia-red-team/{api,web,worker}`.
- Repo variables set: `AWS_ACCOUNT_ID`, `AWS_REGION`, `AWS_DEPLOY_ROLE_ARN`,
  `ECR_REGISTRY`.
- `.github/workflows/deploy-aws.yml` builds the api and web images on push to
  `main` via OIDC. Its deploy job is dormant until `ECS_CLUSTER`,
  `ECS_SERVICE_API`, and `ECS_SERVICE_WEB` are set, and it fails loudly rather
  than reporting a false-positive green deploy. The pipeline needs extending for
  the worker image (see P7).
- **Action: rotate the bootstrap AWS access keys.** Keys were pasted in
  plaintext during setup and must be treated as compromised. The pipeline uses
  OIDC, not static keys.

## Scope decisions that bite

- The substrate is aegis: Postgres with RLS, Celery on Redis, Keycloak auth, the
  hash-chained audit log, and S3 (no EFS). See master plan section 2.
- **Interoperability is deferred.** Croissant dataset export, MITRE ATLAS
  tagging, and Palantir/Lattice are absent from the canonical spec.
  `docs/plans/07-p6-interoperability.md` is out of scope until re-proposed as a
  feature.
- Demo data is `leibnitz-lab/military_vehicles` (image) and
  `lacg030175/UNSW-NB15` (tabular). CIFAR-10 is a CI fixture only.
- The MRI is per-campaign only. Never show it without its five subscores, the
  per-family accuracy table, and the ε curve. The words "hardened",
  "deployment-ready", "certified", and "safe" are banned in score text.

## Known live bugs to fix in passing

- The `/audit` web page expects a `{chains:[...]}` shape, but the API returns a
  single-chain shape.
- The `audit_events` table is not under RLS.
- Verify the Makefile lint targets after the aegis restore; they were historically
  broken (`ruff` aimed at a stale path, `next lint` with no ESLint config).

## Test doubles

- `tests/ml/fakes.py` holds `TinyTarget` (id `tiny`): a random-weight one-conv
  net, 8x8x3 inputs, three synthetic classes. There is no attack fake yet; add
  one. Note `AttackOutput` carries no predictions, so the pipeline computes
  adversarial predictions itself.
