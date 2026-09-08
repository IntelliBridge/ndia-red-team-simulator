# P7 Fargate foundation

This directory defines the code-only AWS foundation for a future canonical
Fargate runtime. It is based on
`2fca7a7197945c0750746605c763278252ec8b19` on
`feat/p7-fargate-foundation`.

It does not activate an application runtime. It creates no ECS task
definitions or services, listeners, target attachments, TLS certificates,
OIDC resources, ECR repositories, runtime secrets, deployment workflow, or
application routing. Existing CI already builds the API, worker, and web
images. The existing worker Dockerfile already includes the worker ML
requirements. Neither is changed by this foundation.

Open PR 16 removes the previous AWS workflow and core. Coordinate with that
work before coupling any runtime implementation to this foundation. CLAUDE
material can be stale or namespace-specific. Use the actual redsim code and
updated approved plans as the source for future runtime contracts.

## Toolchain and validation

Terraform `1.16.1` and HashiCorp AWS provider `6.63.0` are pinned exactly.
The lock file is committed.

Run the credential-free local checks from this directory:

```sh
./validate.sh
```

Terraform may instead be supplied explicitly:

```sh
TERRAFORM_BIN=/path/to/terraform ./validate.sh
```

The validation tool may be available on `PATH`. The locally validated
temporary tool was an official HashiCorp Terraform binary, not a Replit
Terraform configuration. The script checks formatting, initializes with
`-backend=false`, validates, runs Terraform tests using synthetic mock
provider plans, and runs the static policy guard. It performs no cloud
mutation.

Expected review evidence is formatting, validation, synthetic mock plans, and
the static policy guard. These checks are not live AWS inventory, service
health, or deployment evidence. Record actual test counts from the final run
rather than copying a count into documentation.

`ci/p7-infra-checks.yml.example` is an **inactive review template**, not an
installed GitHub workflow. After CI-owner approval, it can be installed as
`.github/workflows/p7-infra-checks.yml`. It is Terraform-only, has root
`contents: read` permissions, and never configures cloud credentials.
Existing CI and deployment workflows are unchanged. No GitHub CI result is
claimed for this template.

The validator rejects local `.tfvars`, JSON/override configuration, provider
aliases, credential/profile/endpoint overrides, and remote execution blocks.
Run it on a clean checkout before creating real deployment inputs. It uses a
fresh backend data directory and empty HOME, clears inherited credentials,
and disables EC2 metadata credential discovery. Its bounded source guard is
also regression-tested. It is not a sandbox for arbitrary untrusted code.

## Existing infrastructure contract

The configuration is reuse-only for networking. Operators provide one
existing VPC and at least two existing public and two existing private
subnets. Both tiers must span at least two Availability Zones. The checks
confirm that every subnet is in the selected VPC, private subnets disable
public IP assignment, and private subnet route tables do not point directly
to an Internet gateway.

This configuration creates no VPC, subnet, Internet gateway, or NAT gateway.
Private routing still needs to support every approved destination. VPC DNS
support and hostnames must be enabled for private endpoint DNS. Security
groups cannot enforce which DNS resolver a workload uses, so resolver policy
is an external control.

Private connectivity includes interface endpoints for ECR API, ECR Docker,
CloudWatch Logs, and Secrets Manager. An S3 gateway endpoint is scoped to
artifact bucket access and ECR layer reads. ECR repository names and the CI
deployment role are existing-resource references only. Their generated ARNs
and URLs are metadata, not evidence that those resources exist.

Optional Pythia HTTPS egress is empty by default. When approved CIDRs are
provided, only the `default` worker security group receives TCP 443 egress to
them. CIDRs do not create the required route and do not prove TLS or service
reachability.

## Managed foundation resources

The configuration declares:

* An ECS cluster with Container Insights, but no workloads
* Per-service CloudWatch log groups with 30-day retention
* An internet-facing ALB with deletion protection and no listener
* IP target groups for API port 8000 and web port 3000, with no attachments
* Per-service network boundaries for `api`, `web`, `scans`, `default`,
  `beat`, `migration`, `assets`, and `identity`
* PostgreSQL 16 on RDS with encryption, backups, Multi-AZ by default,
  deletion protection, a final snapshot requirement, and a managed master
  password
* Encrypted Redis 7 with Multi-AZ failover and an existing user group
* A protected versioned artifacts bucket
* A separate protected versioned audit bucket with Object Lock capability
* Separate ECS execution and application IAM roles for every service name

RDS creates and manages its master secret. Only the migration execution role
is wired to that managed secret. The migration must use it only while
executing an approved schema migration. Application runtime secrets remain
external Secrets Manager ARNs supplied through `runtime_secret_arns`. Secret
values must never enter variables or state.

Redis authentication is also external. `redis_user_group_id` must identify a
pre-existing, managed Redis user group. This configuration neither creates
the group nor stores its authentication material.

The audit bucket enables Object Lock capability but defines no default
retention and receives no audit-export role grants. No WORM retention, write
IAM, or export capability is activated. A seven-year policy has not been
approved. Export, named WORM retention, and writer permissions are future
reviewed work.

`prevent_destroy`, service deletion protection, versioning, and
`force_destroy = false` are safeguards. They do not make destruction
impossible after code or policy is changed. This repository does not provide
deletion commands and operators must not automatically prune old worktrees.

## IAM and storage scope

Execution roles can pull only their mapped image family, write only their own
log group, and read only explicitly configured secret ARNs. Optional KMS
decrypt access is limited to listed same-account keys through Secrets Manager.
The `identity` execution role has no ECR pull permission because no identity
image family is currently declared.

Business S3 access is denied by default because
`artifact_prefixes_by_service` defaults to an empty map. The storage contract
must be confirmed from the actual application code and an updated owner
approval. No `assets`, `model`, `runs`, or other prefix is assumed by this
foundation.

Only `api`, `scans`, `default`, and `assets` are eligible for an explicitly
configured prefix map. When an owner supplies approved prefixes, the matching
application role receives read and write object access plus listing limited
to those prefixes. All other application roles have no artifact policy. This
mechanism is not a claim that any proposed prefix is compatible with the
application. No role has audit bucket write permission. Future task
definitions must preserve the separate execution and application roles
rather than combining them.

## Configuration

Copy `terraform.tfvars.example` to an untracked operator-specific file and
replace every synthetic identifier using approved live inventory. Do not
commit real account, network, secret, or authentication values.

Required values are `account_id`, `environment`, `network`,
`reviewer_ipv4_cidrs`, and `redis_user_group_id`. Database sizing, Redis
sizing, Pythia CIDRs, existing ECR names, existing deployment role name,
external runtime secret ARNs, and optional secret KMS key ARNs are reviewed
inputs or constrained defaults. The current region is restricted to
`us-east-1`. Artifact prefixes must remain empty until the runtime owner
confirms the real storage contract.

The S3 backend uses an existing, separately approved bucket. It has
encryption enabled and native S3 state locking through `use_lockfile`. No
DynamoDB lock table is used. Copy `backend.tfbackend.example` to an untracked
backend file and replace synthetic values only after state bootstrap and
inventory review. The backend is never the audit bucket.

There is intentionally no provisioning command in this document. Before any
cloud execution, operators must obtain an explicit budget and change
approval, verify live inventory, bootstrap and review remote state, resolve
architecture and CI coordination, and review the plan artifact in the
approved account and region.

## Cost and operational boundaries

Material cost drivers include the ALB, the RDS instance and Multi-AZ standby,
the Redis primary and standby nodes, eight interface endpoint ENIs across two
private subnets, S3 and database storage, backups, and CloudWatch logs. Usage,
retention, subnet count, and data transfer affect cost. No price estimate is
claimed here. Review current AWS pricing and an approved plan before cloud
execution.

Outputs contain resource IDs, ARNs, DNS names, endpoints, and ports for
future wiring. They contain no credentials. An ALB DNS output is not a
working, secured, or authenticated URL.

## Runtime activation gates

Runtime implementation is outside this task. It remains blocked until all of
the following are reviewed and evidenced:

1. Explicit budget and change approval, live inventory, and remote state
   bootstrap are complete before cloud execution.
2. PR 16, architecture, CI ownership, and canonical Fargate coupling are
   coordinated.
3. An ACM certificate and reviewed TLS routing cover API, web, authentication,
   and WebSocket behavior.
4. Immutable image references are pinned, and the web build URL matches the
   deployed public URL.
5. An approved migration runs successfully before service rollout.
6. Worker assets are seeded before consumers start.
7. Exactly one beat scheduler is enforced.
8. Authentication, authorization, row-level security, and audit gaps are
   resolved.
9. Named WORM retention, approval, audit export, and writer permissions are
   implemented separately.
10. Service health, live image identity, and tabular deployment evidence are
    captured before deployment activation.

See `HANDOFF.md` for the reusable boundary between this foundation and a
future runtime owner.