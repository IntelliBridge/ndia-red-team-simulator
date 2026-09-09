# Fargate runtime

**Retired on 2026-09-09.** The demo runs on a single EC2 host; see
`deploy/ec2/README.md`. Every ECS service in this root is at desired count
zero (`enable_services=false`, `enable_workers=false`) and the DNS record
`aws_route53_record.runtime` was removed from this root's state, so an apply
here must not be expected to manage the hostname. The foundation
(`../terraform`) stays in use by the EC2 host. The rest of this page is the
record of the Fargate runtime as it was operated.

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
9. Configure Keycloak users and their project memberships as described under
   [Project membership claim](#project-membership-claim). The temporary
   Keycloak bootstrap administrator is `redsim-admin`; its password is the
   `KC_BOOTSTRAP_ADMIN_PASSWORD` field in `ndia-red-team/demo/identity` in
   Secrets Manager. Retrieve it privately using your operator identity.

`Dockerfile.web-reconfigure` can rebuild the browser bundle from a verified CI
web image while retaining its installed dependencies. Supply `BASE_IMAGE` as
an immutable ECR digest. It copies the current web source and performs a full,
strict Next.js build; it does not suppress type errors.

## Bringing the demo to a running campaign (operator sequence, 2026-09-09)

The steps below complete the runtime after the initial verification: the
Phase B images and migration, the project artifact prefix, the asset bundle,
the seeded project and models, the Keycloak claim and demo users, and the
workers. Every input the runtime root needs can be reconstructed from the
remote state when the original operator inputs are not at hand: the image
digests and Secrets Manager references are attributes of the task
definitions in `runtime/terraform.tfstate`, the FQDN and zone are on the
certificate and the alias record. A plan with the reconstructed inputs must
report no changes before anything else is done.

Terraform 1.16.1 is pinned. Behind a TLS-inspecting proxy set
`AWS_CA_BUNDLE` for the AWS CLI and `SSL_CERT_FILE` for Python. Keep the
inputs file (`*.tfvars.json`) and plan files outside the repository.

1. **Images and migration.** Set `images` to the ECR digests of the `main`
   commit to deploy (the `Deploy to AWS` workflow pushes them, tagged with
   the commit sha; `aws ecr describe-images --repository-name
   ndia-red-team/<family>`). Apply the migration task definition first and
   run it, then apply the rest, so the serving API never runs ahead of the
   schema:

   ```sh
   terraform -chdir=deploy/runtime apply -target='aws_ecs_task_definition.runtime["migration"]' -var-file=<inputs>
   terraform -chdir=deploy/runtime output -json > <runtime-outputs.json>
   python deploy/runtime/scripts/run_task.py --runtime-outputs <runtime-outputs.json> --task migration
   terraform -chdir=deploy/runtime apply -var-file=<inputs>
   ```

   The full apply rolls api, web and identity to the new task definitions
   (circuit breaker with rollback) and adds the project artifact policies
   of step 2.
2. **Project artifact prefix.** Campaign evidence and uploaded models are
   stored under `<project_id>/...` in the artifacts bucket, and the
   foundation grants only `assets/`. Name the demo project in
   `project_artifact_prefixes = ["demo"]`; `artifacts.tf` grants that
   prefix to the api, scans, default and assets task roles. Nothing wider
   is granted, and an empty list grants nothing.
3. **Asset bundle.** Build the tree with `redsim ml build-assets` on a
   permitted host (it is the only step with network access to the dataset
   sources), then upload it with `scripts/upload_assets.py` and put the
   emitted `asset_bundle` object in the inputs. Apply: every bundle
   consumer (api, scans, default and the one-off assets task) gains a
   `load-assets` init container that verifies the SHA-256 and extracts the
   archive into a task-local volume mounted read-only at `/app/assets`.
   Then validate it: `run_task.py --task assets` runs `redsim doctor
   --worker-mode` on the mounted tree (manifest digests, the ml extra, a
   sandbox child launch) and requires exit 0.
4. **Seed the project and the models.** Both run through the assets task
   definition with a command override, so they see the mounted bundle and
   the assets role's database and S3 access:

   ```sh
   python deploy/runtime/scripts/run_task.py --runtime-outputs <outputs> --task assets \
     --command "$(python -c 'import json,sys; print(json.dumps(["python","-c",open("deploy/runtime/scripts/seed_project.py").read(),"demo-org","demo","Demo"]))')"
   python deploy/runtime/scripts/run_task.py --runtime-outputs <outputs> --task assets \
     --command '["redsim","ml","seed","--project","demo"]'
   ```

   `seed_project.py` creates the organisation and project rows and is a
   no-op when they exist. `redsim ml seed` registers every non-fixture
   bundled model audit-first and reports `already present` on a rerun.
5. **Keycloak claim, CLI client and demo users.** `scripts/seed_identity.py`
   adds the `redsim_project_roles` mapper and user-profile attribute to the
   live realm (the `--import-realm` gap described under
   [Project membership claim](#project-membership-claim)), optionally a
   public direct-grant client `redsim-cli` whose tokens carry the API
   audience, and the users of a JSON file, each with the memberships object
   as the attribute value and a generated password stored in Secrets Manager
   (`ndia-red-team/demo/demo-users`, never printed). A second run changes
   nothing.

   ```sh
   SSL_CERT_FILE=<ca.pem> python deploy/runtime/scripts/seed_identity.py --cli-client redsim-cli --users <users.json>
   ```

6. **Workers.** Set `enable_workers = true` and apply: scans, default and
   beat go to desired count one. Then `make smoke-live` with a demo user
   (`REDSIM_SMOKE_USER`, `REDSIM_SMOKE_PASSWORD`, `REDSIM_SMOKE_CAMPAIGN=1`)
   runs one FGSM campaign through the deployed path and requires it to
   reach `succeeded` with a report.

Pythia stays off on this runtime (`REDSIM_DISABLE_LLM=1` on every pool):
the ML workers have no internet egress, and the narrative would need the
gateway CIDR opened in the foundation (`pythia_ipv4_cidrs`) plus the
`PYTHIA_*` values as `service_secrets` on the pool that runs
`redsim.ml_campaign_run` (the scans pool, where the narrative is written in
the worker parent). Recommendations then carry `narrative_source: rules`.

## Rolling a release

`scripts/roll.sh <commit> <inputs.tfvars.json> [terraform]` is the one
command per release: it pins the four ECR digests tagged with the commit,
applies this root, runs the migration task, waits for Keycloak to answer,
forces a new web deployment and prints the rollout state. The web redeploy
is deliberate: Keycloak restarts with no overlap on every release, and a web
task that boots during that window used to lose its sign-in provider until
restarted. The web image now sets the Keycloak endpoints explicitly
(`KEYCLOAK_PUBLIC_ISSUER` for the browser redirect, `KEYCLOAK_ISSUER` for
the server calls), so the redeploy is a belt-and-braces step rather than
the fix. Roll only commits whose `Deploy to AWS` run has finished.

## Scale to zero and teardown

Between demos, stop the workers first and then the serving tier; both are
inputs of this root, so the state stays accurate:

```sh
terraform -chdir=deploy/runtime apply -var-file=<inputs> -var enable_workers=false
terraform -chdir=deploy/runtime apply -var-file=<inputs> -var enable_services=false
```

With `enable_services=false` every ECS service has desired count zero. The
ALB, the RDS instance, the Redis nodes and the interface endpoints keep
billing (the standing costs in the next section); stopping RDS from the
console pauses it for up to seven days. Bring the stack back in the same
order reversed: services, then workers.

Teardown destroys the roots in reverse order of creation. Each root reads
the previous root's state, so the order is fixed:

```sh
terraform -chdir=deploy/runtime destroy -var-file=<runtime inputs>
terraform -chdir=deploy/terraform destroy -var-file=<foundation inputs>
terraform -chdir=deploy/bootstrap destroy
```

The runtime destroy removes the certificate, DNS records, listeners, task
definitions and services; the foundation destroy removes the data services
(RDS deletion protection and final-snapshot settings apply as configured
there), the cluster, the ALB, the endpoints, the buckets and the roles; the
bootstrap destroy removes the VPC and finally the state bucket, which must
be emptied of the other two state files first. The audit bucket carries
Object Lock; objects under retention cannot be deleted before it expires,
so a bucket with locked objects fails the foundation destroy until then.
Secrets Manager secrets created outside Terraform
(`ndia-red-team/demo/demo-users`) are deleted by hand.

## Project membership claim

The application does not authorise from Keycloak realm roles. The browser
path (NextAuth copies the claim from the Keycloak profile into the API
session cookie) and the CLI bearer path both read project memberships from
the `redsim_project_roles` token claim: a JSON object that maps a project ID
to one role, `{"<project_id>": "approver"}`. Roles are `viewer`, `scanner`,
`remediator`, `approver` and `admin` (`redsim/api/policy.py`). A user whose
token lacks the claim signs in successfully and has access to no project.

`identity/realm.json` therefore gives the `redsim-web` client a User
Attribute protocol mapper (`oidc-usermodel-attribute-mapper`) that copies the
user attribute `redsim_project_roles` into the ID token, access token and
userinfo response with claim JSON type `JSON`. The mapper is defined on the
client itself (its dedicated scope), so every token issued to the client
carries it and the realm keeps Keycloak's built-in default client scopes.
The realm's user profile declares `redsim_project_roles` as an attribute that
only administrators can view or edit, so users cannot grant themselves
memberships through the account console. The realm roles in the file remain
informational only.

To grant memberships, open the user in the admin console and set the
**Project memberships (redsim_project_roles)** field on the Details tab to a
single JSON object. Keys are project IDs (`projects.id`, as listed by
`GET /v1/projects`) and values are role names:

```json
{"proj-demo": "approver", "proj-eval": "viewer"}
```

Store the whole object in one attribute value, not one value per project.
A user who is already signed in receives the new claim at the next sign-in.
Verify with **Clients -> redsim-web -> Client scopes -> Evaluate**, choose the
user, and confirm the generated ID token contains `redsim_project_roles`.

Keycloak's `--import-realm` skips a realm that already exists, so the realm
applied on 2026-09-08 does not pick up this change when the identity task is
redeployed with the new image. Update the live realm once, either way:

- Admin console: **Clients -> redsim-web -> Client scopes ->
  redsim-web-dedicated -> Add mapper -> By configuration -> User Attribute**.
  Set the name and token claim name to `redsim_project_roles`, the user
  attribute to `redsim_project_roles`, the claim JSON type to `JSON`, and
  enable *Add to ID token*, *Add to access token* and *Add to userinfo*.
  Then **Realm settings -> User profile -> Create attribute**
  `redsim_project_roles` with *Who can edit* and *Who can view* limited to
  Admin, so the field appears on user forms.
- Re-import: delete the `redsim` realm and restart the identity service so
  `--import-realm` recreates it from the pinned image. This removes every
  user in the realm; use it only before demo users exist.

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
Identity rolls the same way: one Keycloak task with `KC_CACHE=local` cannot
overlap itself, so every identity rollout is a login outage. The identity
target group bounds it with a 15s deregistration delay and a 10s health check
that passes after two hits, so the window is Keycloak's boot time (about 45s)
plus roughly 30s, rather than the eight minutes the ALB defaults produced on
2026-09-09. The web app retries OIDC discovery while the window is open and
answers 503 with `Retry-After` on its auth routes, instead of dropping the
Keycloak provider for the life of the process.
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
