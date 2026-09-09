# Fargate foundation handoff

## Ownership boundary

This handoff exposes reusable infrastructure contracts only. The foundation
owner manages the ECS cluster, network boundaries, private AWS endpoints,
ALB shell, target groups, data services, storage, logs, and per-service IAM
roles. The runtime owner must not infer that an application is deployed from
these resources or outputs.

PR #16 and PR #19 are merged. The runtime now lives in `../runtime`; read
its README for current deployment instructions. This document describes the
original foundation contracts, not current service health.

## Stable service-role contract

The service keys are:

`api`, `web`, `scans`, `default`, `beat`, `migration`, `assets`, and
`identity`.

Each key has a dedicated ECS execution role and a dedicated application task
role. Runtime task definitions must use the matching pair. They must not
share a broad role or add wildcard secret, KMS, ECR, S3, or log permissions.

Execution roles provide only image pull where an image family is mapped,
service-specific log writes, configured external secret reads, and configured
secret KMS decrypt. Migration alone also receives the RDS-managed master
secret ARN.

Business S3 access is denied by default.
`artifact_prefixes_by_service` defaults to an empty map, so no application
role receives an artifact policy. Only `api`, `scans`, `default`, and `assets`
are eligible for an owner-approved prefix map. If configured, object read and
write plus bucket listing are limited to the exact supplied prefixes.

No prefix is a foundation default. In particular, this handoff does not
invent or approve `assets`, `model`, `runs`, or any static ML storage layout.
The runtime owner must confirm the real storage contract against actual code
and an updated approved plan before supplying the map. Configurability does
not claim application compatibility. No application role can write the audit
bucket. Future audit export requires a separately reviewed writer role and
retention policy.

## Runtime environment contract

Terraform creates no task environment or task definitions. A future runtime
owner must define an explicit, reviewed environment-variable matrix from the
actual application code. Values that authenticate or authorize must be
external Secrets Manager references. Secret values must not be passed through
Terraform variables, plain task environment, outputs, or state.

Foundation outputs may be used as metadata inputs for database host and port,
Redis endpoints and port, bucket names, log group names, security group IDs,
target group ARNs, cluster ARN, and matching role ARNs. Outputs are not
credentials or proof of reachability. The RDS master secret is for migration
execution only, not normal API, worker, scheduler, asset, or identity runtime
use.

Runtime application secrets must be pre-created externally and listed by
service in `runtime_secret_arns`. Customer-managed key ARNs belong in
`runtime_secret_kms_key_arns` only when those external secrets require them.
Redis must use the externally managed user group supplied as
`redis_user_group_id`. Authentication material must remain outside state.

## Ports, queues, and network contract

Reserved ingress paths are:

| Service | Port | Current source |
| --- | ---: | --- |
| `api` | 8000 | ALB security group and API target group |
| `web` | 3000 | ALB security group and web target group |
| `identity` | 8080 | ALB security group, plus API and web security groups |
| PostgreSQL | 5432 | Enumerated database-client service groups |
| Redis | 6379 | `api`, `scans`, `default`, and `beat` service groups |

There is no listener, target attachment, ECS service, or service discovery in
this foundation. TLS, authentication routes, API routes, web routes, health
behavior, and WebSocket routing remain runtime decisions.

The names `scans`, `default`, and `beat` reserve distinct worker boundaries.
Terraform does not declare Celery queue names, command lines, concurrency, or
schedules. The runtime owner must derive those values from the actual redsim
code and an updated approved plan. Queue routing must keep the default worker
as the only service eligible for optional Pythia CIDR egress. Exactly one beat
scheduler must be enforced.

Private workloads have no direct Internet gateway route and receive no public
IP. No NAT gateway is created. ECR API, ECR Docker, Logs, Secrets Manager, and
ECR S3 layer transport have private paths. Approved Pythia CIDRs still require
existing route support. DNS resolver enforcement is not provided by security
groups.

## Storage contract

The artifacts bucket is versioned, encrypted, TLS-only, public-access blocked,
and protected from routine destroy. It has no approved business prefix layout
in this foundation. The runtime owner must document the code-backed storage
contract, obtain approval, and then provide only the required prefixes.

The audit bucket is separate, versioned, encrypted, TLS-only,
public-access blocked, protected, and Object Lock capable. It has no default
retention and no export writer grant. No WORM retention, write IAM, or export
capability is activated. A seven-year retention requirement is not approved
by this task. Named WORM retention, legal and operational approval, export
behavior, and least-privilege writer permissions must be completed later.

Lifecycle safeguards do not make deletion impossible if code or cloud policy
is changed. Do not add deletion automation or automatic old-worktree pruning.

## Runtime owner's required gates

Network inventory must confirm exactly one selected subnet per AZ in each
tier, explicit subnet/route-table associations, and no conflicting existing
interface endpoints or private DNS zones. The route-table lookup intentionally
fails if a private subnet only implicitly uses the VPC main table. Use
dedicated private route tables or obtain the network owner's approval before
attaching the S3 gateway endpoint. Its scoped policy can affect other S3
consumers sharing those routes, including unrelated buckets. Do not silently
take existing endpoints into state or change shared network policy.

The CI template under `ci/` stays inactive pending CI-owner approval.

Before adding or activating runtime resources, the runtime owner must:

1. Coordinate PR 16 and agree architecture and CI ownership.
2. Obtain explicit budget and change approval.
3. Verify the live VPC, two public subnets, two private subnets, two-AZ
   placement, routes, DNS settings, ECR repositories, deploy role, Redis user
   group, and external secret ARNs.
4. Bootstrap the existing encrypted S3 backend with native lockfile support
   and review state ownership.
5. Select pinned image digests for API, worker, and web. Confirm the web build
   URL matches the intended public URL.
6. Supply an ACM certificate and define reviewed TLS, authentication, API,
   web, and WebSocket routing.
7. Define task environment, commands, queues, ports, health checks, desired
   counts, autoscaling, and deployment controls from current application code.
   Confirm and approve the real artifact-prefix contract before granting
   business S3 access.
8. Run migration before service rollout, seed required worker assets, and
   ensure a singleton beat scheduler.
9. Resolve authentication, authorization, row-level security, and audit gaps.
10. Obtain named approval for WORM retention and audit-export permissions.
11. Capture live image identity, service health, and tabular deployment
    evidence before enabling deployment automation.

No runtime service, secret creation, OIDC, ECR creation, listener, target
attachment, or workflow activation belongs in this foundation task. Existing
CI already builds API, worker, and web images, and the worker Dockerfile
already carries worker ML dependencies.

## Review evidence

Foundation review evidence is limited to Terraform formatting, validation,
synthetic mock-provider plans, and the static policy guard produced by
`./validate.sh`. It is not AWS verification. Do not claim live health,
resource existence, cloud test counts, or successful deployment from this
handoff.