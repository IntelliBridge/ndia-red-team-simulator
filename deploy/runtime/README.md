# Fargate runtime

This root adds the ECS runtime to the foundation in `../terraform`. The
bootstrap root in `../bootstrap` supplies a dedicated VPC and remote-state
bucket. All three roots pin Terraform 1.16.1 and AWS provider 6.63.0.

The demo uses `https://redsim.ndia.agiledefense.xyz`, account `140381642432`,
and `us-east-1`. The ALB accepts public HTTPS. PostgreSQL, Redis and the
Fargate tasks remain private, with no public task IPs or NAT gateway.
Keycloak sign-in is required. Public reachability does not create user accounts
or project memberships.

## Initial live verification (2026-09-08)

The foundation and runtime were applied in the account above. ALB ingress is
`0.0.0.0/0` on TCP 443. The public `/health` and `/login` return 200; OIDC
discovery returns the correct public issuer, and NextAuth redirects successfully
to the Keycloak login form. An unauthenticated `/v1/models` returns 401.
Alembic completed through `0010_ml_vertical`. Keycloak receives a 600-second
startup grace period for first-time schema initialization.

This verifies infrastructure and the start of sign-in, not a completed user
session or campaign. Demo users, project memberships and real model assets
remain to be configured; scans/default/beat remain stopped.

## State and inputs

The encrypted, versioned, TLS-only bucket
`ndia-red-team-demo-140381642432-tfstate` stores:

- `bootstrap/terraform.tfstate`: dedicated VPC, four subnets, routes, state bucket.
- `foundation/terraform.tfstate`: data services, cluster, ALB, endpoints, S3 and IAM.
- `runtime/terraform.tfstate`: certificate/DNS, listeners, task definitions and services.

Native S3 lockfiles protect every root. Operator inputs and plan files stay
outside Git, under `~/.local/state/redsim/demo/` on the initial operator's
machine. Inputs contain ARNs and connection metadata, not credential values.
Use `AWS_PROFILE=MIL` and `AWS_REGION=us-east-1` locally; CI uses OIDC.

To bootstrap a new environment, initially keep `../bootstrap/backend.tf`
outside the Terraform root, apply the bootstrap using local state, then restore
that backend block and run `terraform init -migrate-state` with the new bucket
and `key=bootstrap/terraform.tfstate`. Preserve the local state until migration
is verified. Existing environments must initialize against their existing S3
state; never recreate or import the deployed resources casually.

## Deployment sequence

1. Apply bootstrap, then migrate bootstrap state into its protected bucket.
2. Run `scripts/prepare_secrets.py` using Python 3.12+ and boto3. It generates
   credentials in memory and writes external, service-specific Secrets Manager
   secrets. It also creates an authenticated Redis user group with its default
   user disabled. Existing bootstrap credentials are reused on reruns.
3. Feed the bootstrap's `network` output and secret ARN references to the
   foundation root. Use `allow_public_https=true` and
   `reviewer_ipv4_cidrs=["0.0.0.0/0"]` only for an explicitly public deployment.
   The initial demo uses single-AZ `db.t4g.small` and two `cache.t4g.micro` nodes.
4. Apply foundation and export `terraform output -json`. Run
   `scripts/configure_connections.py --foundation-outputs <file>` to store
   database/Redis URLs inside the per-service secrets and emit ECS `valueFrom`
   references. TLS is required for database and Redis connections.
5. Build and publish the identity image from `deploy/Dockerfile.identity`.
   The realm has no default users/passwords. Its confidential client secret
   and public redirect origin are injected at task start. Set the web build
   argument `NEXT_PUBLIC_REDSIM_API_URL` to the HTTPS origin. The web Dockerfile
   now fails on a failed Next.js build.
6. Pin all four ECR image digests in `images`. Apply this root with
   `enable_services=false`. The TLS validation resources can be staged while
   foundation provisioning completes; always follow that targeted plan with
   a full plan/apply.
7. Export runtime outputs, then run the migration task:

   ```sh
   AWS_PROFILE=MIL uv run --no-project --with boto3 python \
     deploy/runtime/scripts/run_task.py \
     --runtime-outputs ~/.local/state/redsim/demo/runtime-outputs.json \
     --task migration
   ```

   The runner requires a zero container exit code. `scripts/migrate.py` creates
   non-superuser database roles, runs Alembic with the RDS-managed master
   secret, grants runtime DML while keeping audit events append-only, and
   checks that the application role has no superuser/RLS bypass. Serving API
   tasks start Uvicorn directly and never run migrations.
8. Apply with `enable_services=true` to start API, web and Keycloak. Verify
   `/health`, `/login`, the OIDC discovery document and an unauthenticated API
   request. Inspect ECS target health and CloudWatch logs.
9. Configure Keycloak users and application project memberships. The temporary
   Keycloak bootstrap administrator is `redsim-admin`; its password is the
   `KC_BOOTSTRAP_ADMIN_PASSWORD` field in `ndia-red-team/demo/identity` in
   Secrets Manager. Retrieve it privately using your operator identity.

`Dockerfile.web-reconfigure` can rebuild the browser bundle from a verified CI
web image while retaining its installed dependencies. Supply `BASE_IMAGE` as
an immutable ECR digest. It copies the current web source and performs a full,
strict Next.js build; it does not suppress type errors.

## Worker assets

No model weights or evaluation datasets were present in this checkout. Workers
remain at desired count zero until a real, approved asset tree is supplied.
The infrastructure does not label fixture data as demo evidence.

Build the asset tree with the application's `redsim ml build-assets` tooling
on a permitted build host. It writes local files, so a one-off training task
cannot magically share them with later Fargate tasks. Upload that tree with:

```sh
AWS_PROFILE=MIL uv run --no-project --with boto3 python \
  deploy/runtime/scripts/upload_assets.py --directory /path/to/assets \
  --bucket ndia-red-team-demo-140381642432-us-east-1-artifacts
```

The script emits an `asset_bundle` input with a content-addressed S3 key and
SHA-256. Set that input, run the `assets` one-off task to validate loading, then
set `enable_workers=true`. API/scans/default tasks use an initialization
container to verify and extract that exact archive into shared task-local
storage before the main container starts. It imports no ML modules, refuses
traversal/symlinks and mounts the completed tree read-only in consumers.

Grant the real project-specific artifact prefixes in the foundation before
launching campaigns. The current foundation grants only `assets` to the
artifact-using roles; it grants no wildcard access to arbitrary projects.
Campaign storage keys start with the project ID (`DatabaseArtifactSink.put`).
Confirm upload/report prefixes against the application for each project.

Beat has desired count one only when workers are enabled. Its deployment
minimum/maximum percentages are 0/100 so a rollout cannot overlap schedulers.
ML workers have no internet egress. Pythia narratives and WORM exports remain
off; the audit bucket has no mandatory retention or export writer.

## Validation

```sh
TERRAFORM_BIN=/path/to/terraform-1.16.1 deploy/terraform/validate.sh
terraform -chdir=deploy/runtime init -backend=false
terraform -chdir=deploy/runtime validate
terraform -chdir=deploy/runtime test
uv run --no-project --python 3.12 python -m unittest discover \
  -s deploy/runtime/tests -p 'test_*.py'
```

Mock plans cover staged activation, private tasks, migration separation,
immutable image references and singleton beat. Python tests cover archive path
and link rejection. These checks complement live migration and service health;
they do not prove campaign, tenant or audit acceptance.

## CI and operating costs

The image workflow builds API, worker, web and identity images. The repository
variable `NEXT_PUBLIC_REDSIM_API_URL` supplies the browser build URL.
Automatic ECS rollout remains disabled: the older workflow only forces a
redeployment, which does not advance task definitions pinned to image digests.
Before enabling it, add image-digest registration, migration-before-rollout,
and the default-worker/beat/identity service lifecycle. Continue using reviewed
Terraform image updates and the one-off migration runner in the meantime.

The initial core sizing is roughly $200/month before variable storage, log,
request and data-transfer charges. Worker activation adds compute cost. The
2026-09-08 AWS price lookup returned $0.032/hour for the chosen PostgreSQL
instance and $0.016/hour per Redis node; interface endpoints, ALB and Fargate
are the other standing costs. This is an estimate, not a billing cap. Resources
remain billable after this setup session ends.
