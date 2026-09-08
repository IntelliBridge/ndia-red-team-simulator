# Phase P7 · Milestone M7 · Features F001/F008 · AWS ECS (v2, aegis substrate)

Owner: Dev D or the backend lead. Workstream WS7. Wave: starts day 0, runs in
parallel. Delivers milestone M7 and the deploy half of features F001 (auth) and
F008 (audit). Feeds the live demo (master-plan section 8).

Read `docs/plans/00-master-plan.md` sections 2, 5, and 7 first. Then read the
canonical spec `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`
section 20 (deployment), section 21 (security and trust), and section 23
milestone M7. This file rebuilds the phase onto the aegis platform. It replaces
the v1 body that described a two-image stack with EFS. There is no EFS.

The aegis platform already carries auth (F001) and the hash-chained audit
(F008). Both are reused, not built. The new work in this phase is the runtime
that runs the aegis service set on Fargate, the Secrets Manager wiring, the
task roles, the one-off asset seed, the pipeline extension for the worker image,
and the three repo variables that switch the dormant deploy job on.

This phase does not re-provision what already exists. The account, the region,
the OIDC role, the ECR repos, and the non-ECS repo variables are done (see
section 3).

---

## 1. Objective

Stand up the AWS runtime that serves the demo live on ECS Fargate, then activate
the existing pipeline against it.

Deliverables:

- An ECS Fargate cluster in `us-east-1`, account `140381642432`.
- The aegis service set behind one ALB: `aegis-api` (port 8000, health check
  `GET /health`), `aegis-web` (port 3000), `aegis-worker` (`-Q scans`),
  `aegis-worker-default` (`-Q default`), `aegis-beat` (`celery beat`, one task),
  and `aegis-log-ingest` (optional). Section 20.4 permits one worker service on
  `scans,default` for the demo, split into two when long attacks starve
  bookkeeping.
- RDS PostgreSQL 16 with row-level security forced on the tenant tables and
  `pgaudit` enabled through the parameter group.
- ElastiCache for Redis as the Celery broker (`/0`) and result backend (`/1`).
- Two S3 buckets: an artifacts bucket and a second bucket created with Object
  Lock for the WORM audit export.
- Secrets Manager entries for `PYTHIA_API_KEY`, `AEGIS_ML_LLM_MODEL`,
  `AEGIS_WORKER_SIGNING_KEY`, `AEGIS_AUTH_PROFILES_KEY`, `NEXTAUTH_SECRET`, and
  the DB and Redis credentials, injected as task secrets.
- Keycloak on Fargate (realm import from `deploy/keycloak/`), or Cognito through
  OIDC, as the F001 identity provider.
- IAM task execution and task roles named `ndia-red-team-*`, so the existing
  `PassRole` grant on `ndia-red-team-gha-deploy` already covers them. The task
  roles grant S3 through the role, with no static keys.
- The three bundled models and two evaluation datasets seeded into the artifacts
  bucket by one run of `aegis ml build-assets` as a one-off ECS task.
- The pipeline extended to build the worker image, and the ECR path
  `ndia-red-team/worker` used.
- The repo variables `ECS_CLUSTER`, `ECS_SERVICE_API`, and `ECS_SERVICE_WEB`
  set, so a push to `main` rolls the services.

The done bar is section 26 and the section 20.4 smoke test: a campaign started
from `/models` against the bundled vehicle-imagery CNN and the UNSW-NB15 tabular
model runs on Fargate end to end, the MRI scorecard renders, `/audit` shows the
tamper-evident chain, `aegis audit verify --all` passes, and a push to `main`
deploys green.

---

## 2. Scope

### In scope

- Infrastructure as code under `deploy/terraform/` (Terraform recommended).
- ECS task definitions and services for `aegis-api`, `aegis-web`,
  `aegis-worker`, `aegis-worker-default`, `aegis-beat`, and the optional
  `aegis-log-ingest`.
- The ALB, target groups, listeners, and security groups.
- RDS PostgreSQL 16 with the parameter group for `pgaudit`, and the migrations
  that force row-level security applied through the one-off migration task.
- ElastiCache for Redis.
- The artifacts S3 bucket and the Object-Lock WORM S3 bucket, both with public
  access blocked and versioning on.
- IAM task execution role and task roles, all named `ndia-red-team-*`.
- Secrets Manager entries and their injection as task secrets.
- Keycloak on Fargate with realm import, or Cognito through OIDC.
- The one-off migration task (`alembic upgrade head`) and the one-off
  `aegis ml build-assets` task.
- The worker image added to the `build-and-push` matrix in `deploy-aws.yml`, and
  the `deploy/Dockerfile.worker` change that removes the deleted `project_repos/`
  install lines and installs `.[worker,ml]`.
- Setting the three ECS repo variables to activate the deploy job.

### Out of scope

- The OIDC provider, the `ndia-red-team-gha-deploy` role, and its policy. Done.
- The three ECR repos `ndia-red-team/{api,web,worker}`. Done. The `worker` repo
  is currently unused. This phase starts using it.
- The repo variables `AWS_ACCOUNT_ID`, `AWS_REGION`, `AWS_DEPLOY_ROLE_ARN`,
  `ECR_REGISTRY`. Done.
- Any ML application code in `aegis/ml/`, `aegis/api/v1/`, or `web/`. This phase
  touches deploy assets, the two worker Dockerfile lines, and the pipeline only.
  The two application bugs in section 9 are flagged for the code fix-up, not
  fixed here.
- The audit chain, the WORM export, and the auth stack themselves. F008
  (`aegis/audit/chain.py`, `aegis/storage/worm.py`) and F001 (Keycloak,
  NextAuth) are reused aegis foundation. The new F008 work, emitting ML audit
  events on the existing chain, lives in the ML workstreams, not here. This
  phase only enables Object Lock and the WORM export flag.
- A custom domain. The demo runs on the ALB DNS name. Add ACM and a domain if
  time allows. Dev-token auth mode is acceptable for the demo only when the ALB
  is restricted to the team's addresses (D002/D11), and is refused when
  `AEGIS_ENV=prod`.

---

## 3. Prerequisites and dependencies

- **A booting aegis api image.** This phase proves the ALB health check against
  `GET /health` on `aegis-api`. The restored aegis image answers `/health`
  without the ML vertical, so this phase starts day 0 on the infrastructure that
  does not need the ML code (network, ALB, RDS, Redis, S3, roles, secrets), and
  proves `/health` behind the ALB the moment a green api image is pushed. The
  api image never installs the `ml` extra. A test asserts the api process
  imports no `torch`, `art`, `shap`, or `onnxruntime` (section 22).
- **The migration must run before the api rollout.** Run `alembic upgrade head`
  as a one-off ECS task before each rollout, not from every api task entrypoint,
  so concurrent tasks never race the migration (section 20.4). The migration
  `0010_ml_vertical` is additive and runs through the api image.
- **The bundled assets must be seeded once.** `GET /v1/models` lists the bundled
  targets as `available` only after `aegis ml build-assets` has run. This phase
  runs that CLI as a one-off ECS task on the worker image (see step 9). The
  manifests it writes are the only source of clean-accuracy numbers.
- **Provisioned already this session. Do not recreate any of these.** Account
  `140381642432`, region `us-east-1`, the GitHub OIDC provider, the role
  `ndia-red-team-gha-deploy` (trust scoped to this repo, policy allows ECR push,
  ECS deploy, and `PassRole` to `ndia-red-team-*` task roles), the ECR repos
  `ndia-red-team/{api,web,worker}`, and the repo variables `AWS_ACCOUNT_ID`,
  `AWS_REGION`, `AWS_DEPLOY_ROLE_ARN`, `ECR_REGISTRY`.
- **Compromised bootstrap keys.** The AWS access keys pasted to bootstrap this
  session are compromised. Rotate them (section 9, key rotation). Do not use
  them for the first `terraform apply`.
- **Terraform state.** Decide where state lives before the first apply. An S3
  backend with a DynamoDB lock is the durable choice. A local state file is
  acceptable for a single operator during the hackathon. Record the choice in
  `deploy/terraform/README.md`.
- **Deployer identity for the first apply.** The `terraform apply` runs from a
  developer machine or a bootstrap CI run, not from the dormant deploy job. Use
  short-lived credentials, never the compromised bootstrap keys.

---

## 4. Interfaces consumed and exposed

### Consumed

- **The environment contract, master-plan section 5 and spec section 20.3.**
  Reuse the Helm chart's variable names (`deploy/helm/aegis/values.yaml` →
  `templates/configmap.yaml` / `templates/secret.yaml`) as task-definition
  environment, so compose, Helm, and Fargate agree.

  | Variable | Consumer | Source in this phase |
  |---|---|---|
  | `AEGIS_DB_URL` | api, worker, beat | plain env, the RDS endpoint |
  | `AEGIS_BROKER_URL` | api, worker, beat | plain env, ElastiCache `/0` |
  | `AEGIS_RESULT_BACKEND` | api, worker | plain env, ElastiCache `/1` |
  | `AEGIS_BLOB_BACKEND=s3` | api, worker | plain env |
  | `AEGIS_S3_BUCKET` / `AEGIS_S3_REGION` | api, worker | plain env, artifacts bucket |
  | `AEGIS_S3_ENDPOINT` | api, worker | unset on AWS (native S3, not MinIO) |
  | `AEGIS_S3_ACCESS_KEY_ID` / `AEGIS_S3_SECRET_ACCESS_KEY` | api, worker | unset, the task role grants S3 |
  | `AEGIS_OIDC_ISSUER` / `AEGIS_OIDC_JWKS_URL` | api, web | plain env, Keycloak or Cognito |
  | `AEGIS_CORS_ORIGINS` | api | plain env, the web ALB URL |
  | `AEGIS_WORM_EXPORT=1` / `AEGIS_WORM_BUCKET` | beat, worker-default | plain env, the Object-Lock bucket |
  | `AEGIS_WORM_RETENTION_DAYS` / `AEGIS_WORM_LOCK_MODE` | beat | plain env (default 2555, `COMPLIANCE`) |
  | `AEGIS_ML_WORK_DIR` | worker | plain env, a path on Fargate ephemeral storage |
  | `AEGIS_ML_DATASET_CACHE` | worker | plain env, a path on Fargate ephemeral storage |
  | `NEXT_PUBLIC_AEGIS_API_URL` / `NEXTAUTH_URL` | web | plain env, the ALB URLs |
  | `PYTHIA_BASE_URL` / `PYTHIA_PERSONA` | worker-default | plain env |
  | `PYTHIA_API_KEY` | worker-default | Secrets Manager, task `secrets` |
  | `AEGIS_ML_LLM_MODEL` | worker-default | Secrets Manager, task `secrets` |
  | `AEGIS_WORKER_SIGNING_KEY` / `AEGIS_AUTH_PROFILES_KEY` | api, worker | Secrets Manager, task `secrets` |
  | `NEXTAUTH_SECRET` | web | Secrets Manager, task `secrets` |
  | DB password | one-off migration, api, worker | Secrets Manager, task `secrets` |

  The narrative writer stays off unless `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, and
  `AEGIS_ML_LLM_MODEL` all resolve. With any missing, `PythiaSettings.from_env()`
  returns `None`, recommendations render from the rule layer, and
  `narrative_source = "rules"` (section 20.3). The workers set `AEGIS_DISABLE_LLM`
  by default. Unset it on `aegis-worker-default` when the narrative should run.
  There is no model-provider key anywhere in the deployment (D5). Pythia holds
  them. The Pythia egress path is from the worker security group only.

- **The existing pipeline, `.github/workflows/deploy-aws.yml`.** The
  `build-and-push` job pushes `${ECR_REGISTRY}/ndia-red-team/{name}:${sha}` and
  `:latest` for each image in a matrix. Today the matrix is `api` and `web`
  only. This phase adds `worker`. The `deploy` job is gated on
  `vars.ECS_CLUSTER != ''` and rolls each configured service with
  `aws ecs update-service --force-new-deployment` then
  `aws ecs wait services-stable`. Its guard fails loudly if `ECS_CLUSTER` is set
  but both service names are empty.

### Exposed

- The three activation repo variables, set once the runtime exists:

  | Repo variable | Value |
  |---|---|
  | `ECS_CLUSTER` | the cluster name, e.g. `ndia-red-team` |
  | `ECS_SERVICE_API` | the api service name, e.g. `ndia-red-team-api` |
  | `ECS_SERVICE_WEB` | the web service name, e.g. `ndia-red-team-web` |

  Set all three together so the deploy job's guard passes. The deploy job rolls
  the api and web services. Roll the worker, worker-default, and beat services
  with the same forced-deployment pattern, either by extending the deploy job's
  service loop or by a separate one-off command after the migration task.

- The api ALB URL and the web ALB URL. The api URL feeds the web task's
  `NEXT_PUBLIC_AEGIS_API_URL` and `AEGIS_CORS_ORIGINS`, and is the base URL a
  judge drives.

---

## 5. Ordered implementation steps

Apply order follows the dependency chain: network and ALB, then RDS and Redis,
then S3, then roles, then secrets, then task defs, then the one-off tasks, then
services, then the repo variables.

1. **Terraform skeleton.** Create `deploy/terraform/` with `versions.tf`
   (provider `aws ~> 5`, region `us-east-1`, the state backend), `variables.tf`
   (account id, region, name prefix `ndia-red-team`, image tag), and
   `outputs.tf`. Pin the provider. Namespace every resource with the
   `ndia-red-team` prefix so the `PassRole` policy matches.

2. **Network and ALB (`network.tf`, `alb.tf`).** Reuse the default VPC and its
   public subnets for speed, or create a small VPC with public subnets across
   two AZs plus the S3 gateway endpoint and the ECR and Secrets Manager
   interface endpoints. Create the ALB in the public subnets. Create target
   groups: `api` (port 8000, health check path `/health`, matcher 200) and
   `web` (port 3000, health check path `/`). Add one HTTP listener on port 80.
   Route `/v1/*` and `/health` to the api target group and the default to the
   web target group. Security groups: the ALB accepts 80 from the allowed
   addresses, the tasks accept 8000 and 3000 from the ALB security group only,
   and the worker security group has HTTPS egress to Pythia. Prove `/health`
   here first with a booting api image.

3. **RDS PostgreSQL 16 (`rds.tf`).** Create the instance in the task subnets,
   reachable from the task security group on 5432 only. Attach a parameter group
   that enables `pgaudit` to match what `deploy/Dockerfile.postgres` adds
   locally. Store the password in Secrets Manager (step 6). Row-level security
   is forced by the existing migrations, so no RDS-level config is needed for
   it. Note the audit-events RLS gap in section 9.

4. **ElastiCache for Redis (`redis.tf`).** Create the Redis replication group in
   the task subnets, reachable from the task security group on 6379 only. It is
   the Celery broker (`/0`) and result backend (`/1`).

5. **S3 (`s3.tf`).** Create two buckets. The artifacts bucket holds models,
   adversarial examples, SHAP outputs, robustness curves, reports, and the
   bundled assets. The WORM bucket is created with Object Lock enabled, which
   must be set at bucket creation, and holds the audit chains that
   `aegis.export_chains_to_worm` writes with `COMPLIANCE` retention. Block all
   public access and enable versioning on both. Grant access through the task
   roles in step 6, never through a bucket policy with keys and never through
   static credentials. `aegis/storage/s3.py` refuses a WORM put to a bucket
   without Object Lock, so the bucket must be right at creation.

6. **IAM roles and secrets (`iam.tf`, `secrets.tf`).** Create the roles, all
   prefixed `ndia-red-team-` so the existing `PassRole` grant covers them:
   - **Task execution role** `ndia-red-team-exec`: attach
     `AmazonECSTaskExecutionRolePolicy` (ECR pull, CloudWatch Logs) plus
     `secretsmanager:GetSecretValue` on the secret ARNs, so the agent injects
     them at task start.
   - **Worker task role** `ndia-red-team-worker-task`: grant `s3:GetObject`,
     `s3:PutObject`, and `s3:ListBucket` scoped to the artifacts bucket prefix,
     and `s3:PutObject` with the Object-Lock parameters on the WORM bucket. This
     is the only S3 grant path for the worker. No static keys.
   - **API task role** `ndia-red-team-api-task`: grant read and write on the
     artifacts bucket prefix. It streams uploads to S3 and reads artifacts. It
     never loads a model.
   - **Web task role** `ndia-red-team-web-task`: minimal, no S3.
   Create the Secrets Manager entries for `PYTHIA_API_KEY`, `AEGIS_ML_LLM_MODEL`,
   `AEGIS_WORKER_SIGNING_KEY`, `AEGIS_AUTH_PROFILES_KEY` (Fernet), `NEXTAUTH_SECRET`,
   and the DB password. Seed the Pythia values empty for a rules-only baseline,
   or real for the narrative. No model-provider key exists anywhere (D5).

7. **Keycloak or Cognito (`auth.tf`).** Run Keycloak on Fargate with the realm
   import from `deploy/keycloak/` (add the `viewer` realm role, section 7.2), or
   create a Cognito user pool and point `AEGIS_OIDC_ISSUER` and
   `AEGIS_OIDC_JWKS_URL` at it. Dev-token mode (`AEGIS_AUTH_MODE=dev`) is
   acceptable for the demo only behind a restricted ALB and is refused when
   `AEGIS_ENV=prod`. F001 is otherwise reused aegis (NextAuth, session cookie,
   JWKS bearer). No new auth code lands here.

8. **Task definitions (`ecs.tf`).** All Fargate. `executionRoleArn` the exec
   role on every task. There is no EFS volume on any task. `AEGIS_ML_WORK_DIR`
   and `AEGIS_ML_DATASET_CACHE` point at Fargate ephemeral storage. Raise
   ephemeral storage above the 20 GiB default if the dataset cache and uploaded
   models need it.
   - **api:** `taskRoleArn` the api task role. Image
     `${ECR_REGISTRY}/ndia-red-team/api:latest`. Container port 8000. Plain env
     and the `secrets` block per section 4. The `ml` extra is never installed
     here.
   - **web:** `taskRoleArn` the web task role. Image `.../web:latest`. Container
     port 3000. `NEXT_PUBLIC_AEGIS_API_URL` and `NEXTAUTH_URL` set to the ALB
     URLs.
   - **worker (`-Q scans`) and worker-default (`-Q default`):** `taskRoleArn`
     the worker task role. Image `.../worker:latest`, installed with
     `.[worker,ml]`. Size the task for CPU torch, ART, and SHAP. The sandbox
     rlimits (`AEGIS_ML_SANDBOX_*`, section 20.3) must fit inside the task memory
     limit. worker-default carries the Pythia env and runs the narrative,
     reaper, WORM export, and reports. One combined worker on `scans,default` is
     acceptable for the demo (section 20.4).
   - **beat:** `celery beat`, exactly one task. It fires
     `aegis.reap_stale_jobs` and `aegis.export_chains_to_worm`. Never scale it.
   - **log-ingest (optional):** the Postgres log mirror. Skip for the demo if
     time is short.
   - **one-off migration:** `alembic upgrade head` on the api image, run before
     each rollout.
   - **one-off build-assets:** `aegis ml build-assets` on the worker image.

9. **Apply and seed.** Run `terraform apply` with short-lived credentials.
   Confirm the ALB `/health` returns ok against the api image. Run the one-off
   migration task. Then run `aegis ml build-assets` once as a one-off ECS task
   on the worker image to seed the three bundled models (the image CNN on the
   vehicle-imagery dataset, the tabular tree ensemble on UNSW-NB15 with its PGD
   surrogate, and the ONNX export of the image CNN) and the two evaluation
   datasets into the artifacts bucket, each with its `MANIFEST.json`. The
   manifests are the only source of clean-accuracy numbers.

10. **Create the services (`ecs.tf`).** Create the api and web services attached
    to their target groups, plus the worker, worker-default, and beat services,
    desired count 1 each, in the task subnets with the task security group. Name
    the api and web services `ndia-red-team-api` and `ndia-red-team-web`.

11. **Extend the pipeline for the worker image (`deploy-aws.yml`).** Add a
    `worker` row to the `build-and-push` matrix (`dockerfile:
    deploy/Dockerfile.worker`), so the pipeline pushes
    `ndia-red-team/worker:${sha}` and `:latest`. Change `deploy/Dockerfile.worker`
    to install `.[worker,ml]` and to drop the `COPY project_repos/` line and the
    `strix`/`cai` editable installs, which fail the build now that the submodules
    are deleted. Extend the deploy job's service loop, or add a step, to roll the
    worker, worker-default, and beat services after the one-off migration task.

12. **Set the activation variables.** With the services running, set the three
    repo variables:
    ```
    gh variable set ECS_CLUSTER     --body ndia-red-team
    gh variable set ECS_SERVICE_API --body ndia-red-team-api
    gh variable set ECS_SERVICE_WEB --body ndia-red-team-web
    ```
    Set all three, so the deploy job's guard passes.

13. **Prove the pipeline.** Push a trivial change to a matched path on `main`,
    or run the workflow with `workflow_dispatch`. Confirm `build-and-push`
    pushes the api, web, and worker images and `deploy` rolls the services to
    stable.

14. **Rotate the compromised keys.** Deactivate and delete the pasted bootstrap
    keys in IAM. Confirm no static AWS keys live in the repo, in GitHub secrets,
    in the task definitions, or in the compose files. OIDC drives the pipeline
    and the task role drives S3.

---

## 6. Files to create and modify

### Create

- `deploy/terraform/versions.tf` — provider, region, state backend.
- `deploy/terraform/variables.tf` — account id, region, name prefix, image tag.
- `deploy/terraform/network.tf` — VPC or default-VPC data, subnets, endpoints,
  security groups.
- `deploy/terraform/alb.tf` — ALB, target groups, listeners.
- `deploy/terraform/rds.tf` — PostgreSQL 16 instance and the `pgaudit`
  parameter group.
- `deploy/terraform/redis.tf` — ElastiCache for Redis.
- `deploy/terraform/s3.tf` — the artifacts bucket and the Object-Lock WORM
  bucket.
- `deploy/terraform/iam.tf` — `ndia-red-team-exec` and the api, worker, and web
  task roles and policies.
- `deploy/terraform/secrets.tf` — the Secrets Manager entries.
- `deploy/terraform/auth.tf` — Keycloak on Fargate, or the Cognito user pool.
- `deploy/terraform/ecs.tf` — cluster, the task definitions, the services, and
  the two one-off tasks.
- `deploy/terraform/outputs.tf` — the api and web ALB URLs, the two bucket
  names, the cluster and service names.
- `deploy/terraform/README.md` — state backend, apply order, and the one-off
  migration and asset tasks.

### Modify

- `.github/workflows/deploy-aws.yml` — add the `worker` row to the
  `build-and-push` matrix, and extend the deploy job to roll the worker,
  worker-default, and beat services after the one-off migration task.
- `deploy/Dockerfile.worker` — install `.[worker,ml]`, and remove the
  `COPY project_repos/` line and the `strix`/`cai` editable installs that fail
  the build now that the submodules are gone. Pin `torch` (CPU wheel index),
  `adversarial-robustness-toolbox`, `shap`, `onnxruntime`, `onnx2torch`, and
  `safetensors` to exact versions.
- Repo variables `ECS_CLUSTER`, `ECS_SERVICE_API`, `ECS_SERVICE_WEB` — set once
  the runtime exists.

### Do not modify

- `aegis/audit/chain.py`, `aegis/storage/worm.py`, `aegis/storage/s3.py`. F008
  is reused. This phase enables Object Lock and sets `AEGIS_WORM_EXPORT=1`, and
  does not touch the audit code.
- `aegis/api/app.py` and the aegis auth stack. F001 is reused.
- `deploy/docker-compose.yml`. It is the developer stack. This phase mirrors its
  service names and env onto Fargate but does not edit it.

---

## 7. Testing and validation

1. **ALB health.** `curl http://<api-alb>/health` returns ok and the api target
   group shows healthy. Do this against the api image before the ML paths land.
2. **A push deploys green.** A push to `main` on a matched path builds the api,
   web, and worker images, and the deploy job rolls the services to stable. The
   guard passes because all three service variables are set.
3. **Sign-in.** The web ALB URL reaches Keycloak or Cognito, and a realm user or
   dev token signs in and lists only member projects (`GET /v1/projects`).
4. **RLS enforced.** A cross-org read of a run, finding, artifact, or the score
   record (`ml_campaigns`) returns nothing (`tests/test_tenant_rls.py` against
   the RDS instance). Confirm `FORCE ROW LEVEL SECURITY` is active on the tenant
   tables.
5. **S3 receives a dataset.** After `aegis ml build-assets`, the bundled models
   and the two evaluation datasets exist under the artifacts bucket, each with
   its `MANIFEST.json`, and `GET /v1/models` lists the bundled targets as
   `available`. Confirm no static keys were used, only the task role.
6. **Secrets resolve.** With the three Pythia values seeded, the narrative turns
   on. With them empty, the pipeline runs rules-only and
   `narrative_source = "rules"`.
7. **Audit verify passes.** Run one FGSM campaign on the bundled image model.
   Then `aegis audit verify --all` passes, and `/audit` shows the chain. The
   WORM export writes the chain to the Object-Lock bucket on the beat schedule.
8. **Full demo path (the gate).** A campaign started from `/models` against the
   bundled vehicle-imagery CNN and the UNSW-NB15 tabular model runs FGSM and PGD
   with the noise control and eps sweep on Fargate. `/runs/[id]` shows the MRI
   scorecard with subscores, the per-family table, and the robustness curve.
   `/findings/[id]` shows the three panes and a measured ΔMRI after Verify.

---

## 8. Acceptance criteria / definition of done

This phase is done when section 26 holds on the deployed stack:

1. `GET /health` behind the api ALB returns ok, and the api and web target
   groups are healthy.
2. A campaign started from `/models` against the bundled vehicle-imagery CNN and
   the UNSW-NB15 tabular model runs FGSM and PGD with the noise control and eps
   sweep on Fargate.
3. `/runs/[id]` shows the MRI scorecard with its subscores, per-family table,
   and robustness curve.
4. `/findings/[id]` shows the three panes and a measured ΔMRI after Verify.
5. Every action is on the audit chain, `aegis audit verify --all` passes, and
   the WORM export lands the chain in the Object-Lock bucket.
6. Access is gated by Keycloak (or Cognito) with RLS forced on the tenant
   tables.
7. A push to `main` builds the api, web, and worker images and the deploy job
   rolls the services green, its guard passing because the three service
   variables are set.
8. The bundled assets are seeded to the artifacts bucket by the one-off
   `aegis ml build-assets` task, and `GET /v1/models` lists them as `available`.
9. No static AWS keys anywhere in the runtime. OIDC drives the pipeline, the
   task roles drive S3, no model-provider key exists (D5), and the compromised
   bootstrap keys are rotated.
10. There is no EFS. `AEGIS_ML_WORK_DIR` and `AEGIS_ML_DATASET_CACHE` are on
    Fargate ephemeral storage. The README records the measured clone-to-first-run
    time (section 26).

---

## 9. Effort estimate and special considerations

**Effort.** Roughly 3 to 4 developer-days for one operator familiar with
Terraform and ECS. The network, ALB, RDS, Redis, S3, IAM, secrets, and services
are about two days. Keycloak on Fargate, the worker image and the seed task, and
proving the full demo path are the rest. This phase starts day 0 and runs in
parallel, so wall-clock cost overlaps the ML build.

**No EFS. S3 is content-addressed.** The v1 plan mounted EFS for a filesystem
run store. That store is gone. Persistence is RDS plus S3. The run record is a
sha256-addressed Artifact, and blobs are keyed by project and run. Nothing on the
task's disk needs to survive a restart. `AEGIS_ML_WORK_DIR` and
`AEGIS_ML_DATASET_CACHE` are scratch on Fargate ephemeral storage. Do not add an
EFS volume to any task.

**Image size and build time.** The worker image carries CPU torch, torchvision,
ART, SHAP, onnxruntime, and scikit-learn. It is multi-GB and is the slowest to
build. Pin the CPU wheel index and exact versions early, and use the GHA layer
cache the pipeline already sets (`cache-from` / `cache-to` in `deploy-aws.yml`).
The api and web images stay small because the `ml` extra installs only on the
worker. Size the worker task memory to hold torch plus SHAP on CPU, and keep the
sandbox rlimits inside that limit.

**Cost and teardown.** Fargate tasks, the ALB, RDS, ElastiCache, and any NAT
bill by the hour. Keep desired count at 1 per service and beat at exactly 1.
Reuse the default VPC public subnets and the S3 gateway endpoint to avoid NAT.
After the demo, `terraform destroy` tears down the runtime. The ECR repos, the
OIDC role, and the repo variables persist, so re-provisioning is another
`terraform apply` plus resetting the three service variables. Empty the
artifacts bucket before destroy. The Object-Lock WORM bucket cannot be emptied
before its retention expires, so plan its lifecycle deliberately and set
`AEGIS_WORM_RETENTION_DAYS` on purpose rather than inherit the default 2555.

**Key rotation (security).** The bootstrap AWS keys pasted to provision this
session are compromised. Deactivate and delete them in IAM now. The pipeline
uses OIDC through `ndia-red-team-gha-deploy`, not static keys. The task roles,
not keys, grant S3. The only long-lived trust is the OIDC provider scoped to
this repo, and the Pythia key, which lives only in Secrets Manager and reaches
only `aegis-worker-default`.

**Two live bugs to fix in the code fix-up, not here.** Both are in the F008
surface and are flagged for the concurrent platform fix-up, so they do not block
the deploy:
- The `/audit` page (`web/src/app/audit/page.tsx`) fetches
  `/v1/audit/verify?all=1` and reads `data.chains` as an array, but
  `aegis/api/v1/audit.py` verifies one chain and returns the single-chain shape
  `{chain_id, verified, count, broken_at, reason}` and ignores the `all` param.
  The page renders an empty "No audit chains found" state against a healthy
  chain until the route returns a `chains` array or the page reads the
  single-chain shape.
- `audit_events` is not among the tables migration `0006_tenant_rls` places
  under row-level security (`projects`, `targets`, `runs`, `jobs`, `findings`,
  `llm_usage`, `artifacts`, `remediation_attempts`, `application_logs`). Cross-
  project isolation of audit reads rests on the `check(user, Action.AUDIT_VERIFY,
  project_id)` role gate and chain-id scoping, not on RLS. A future revision
  should place `audit_events` under RLS or the browse endpoint must resolve the
  run chain's project through `ensure_run_access` before returning event
  content.
