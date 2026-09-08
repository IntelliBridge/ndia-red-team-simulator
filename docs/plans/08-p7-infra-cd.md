> **SUPERSEDED / RECONCILED (2026-09-08 spec update).** This file was written for v1 against the deleted `redsim/` package. It now maps to: **Milestone M7**; features **F001 auth** + **F008 audit** on Fargate.
>
> Substrate corrections (see `00-master-plan.md` §2 and the canonical spec): deploy the **aegis multi-service stack** (api, worker, beat, web, log-ingest), not a two-image redsim stack; **no EFS** — storage is RDS PostgreSQL 16 + ElastiCache Redis + two S3 buckets (one Object-Lock WORM); Keycloak on Fargate; Secrets Manager; the existing OIDC deploy pipeline still applies.
>
> Use this file for the parallel-execution shape only, not the literal paths, signatures, or mechanisms below.

# P7 — Infrastructure & CD to AWS ECS

Owner: Dev D or the backend lead. Wave: 1 (parallel from day 0). Depends on: P0
booting image. Feeds: the live demo (master-plan section 10).

Read `docs/plans/00-master-plan.md` section 6.8 (the environment contract) and
section 10 (the done bar) first. Read `docs/adversarial-ml-redteam-spec.md`
section 12 for the ECS framing, but ignore its Postgres, Redis, Keycloak, and
Celery services. redsim drops all of them. Persistence is the filesystem
`RunStore` on EFS. Datasets and reports go to S3. Jobs run in-process.

This phase does not re-provision what already exists. The account, the region,
the OIDC role, the ECR repos, and the non-ECS repo variables are done. P7 adds
the runtime that the dormant deploy job waits for, then switches it on.

---

## 1. Objective

Stand up the AWS runtime that serves the demo live, and activate the existing
pipeline against it.

Deliverables:

- An ECS Fargate cluster in `us-east-1`, account `140381642432`.
- Two Fargate services behind one ALB: `api` (port 8000, health check
  `GET /health`) and `web` (port 3000).
- Task execution and task roles named `ndia-red-team-*`, so the existing
  `PassRole` grant on `ndia-red-team-gha-deploy` already covers them.
- An S3 bucket for datasets and reports (`REDSIM_S3_BUCKET`), reachable through
  the task role, with no static keys.
- An EFS filesystem mounted at `REDSIM_OUTPUT_DIR`, so the filesystem
  `RunStore` survives task restarts.
- Secrets Manager entries for `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, and
  `REDSIM_LLM_MODEL`, injected as task secrets.
- The CIFAR-10 model asset baked into the `api` image.
- The GitHub repo variables `ECS_CLUSTER`, `ECS_SERVICE_API`, and
  `ECS_SERVICE_WEB` set, so a push to `main` rolls the services.
- A redsim local `docker-compose` for dev parity, replacing the stale aegis one.

The done bar is master-plan section 10: `POST /v1/runs` against the deployed
stack runs the full pipeline, the web UI renders it, and a push to `main`
deploys green.

---

## 2. Scope

### In scope

- Infrastructure as code under `deploy/terraform/` (Terraform recommended).
- ECS task definitions and services for `api` and `web`.
- The ALB, target groups, listeners, and security groups.
- EFS filesystem, mount targets, and access point.
- The S3 bucket and its bucket policy.
- IAM task execution role and task role, both named `ndia-red-team-*`.
- Secrets Manager entries and their injection as task secrets.
- Baking the P1 model asset into the `api` image (Dockerfile change).
- Setting the three ECS repo variables to activate the deploy job.
- `deploy/docker-compose.redsim.yml` for local dev.

### Out of scope

- The OIDC provider, the `ndia-red-team-gha-deploy` role, and its policy. Done.
- The three ECR repos `ndia-red-team/{api,web,worker}`. Done.
- The repo variables `AWS_ACCOUNT_ID`, `AWS_REGION`, `AWS_DEPLOY_ROLE_ARN`,
  `ECR_REGISTRY`. Done.
- The `build-and-push` job in `deploy-aws.yml`. It already builds both images.
  P7 does not edit the build job.
- A worker service. redsim runs jobs in-process (master-plan section 2). The
  `worker` ECR repo stays unused for Phase A.
- Postgres, Redis, ElastiCache, Keycloak, RDS. Not in the redsim architecture.
- Any application code in `redsim/` or `web/`. P7 only touches deploy assets and
  the two Dockerfiles.
- HTTPS and a custom domain. The demo runs on the ALB DNS name over HTTP. Add
  ACM and a domain later if time allows.

---

## 3. Prerequisites & dependencies

- **P0 booting image.** P7 needs `redsim.api.app:create_app` to answer
  `GET /health` with `{status:"ok", version}` (master-plan section 6.7). Until
  P0 lands, the `api` image builds but crashes on start, so the ALB health
  check never passes. P7 starts day 0 on the infrastructure that does not need
  the app (network, ALB, EFS, S3, roles), and proves `/health` behind the ALB
  the moment the P0 skeleton is pushed, before any ML lands.
- **P1 model asset.** The image target needs `assets/cifar10_smallcnn.pt` and
  `assets/MANIFEST.json`, built once by `python -m redsim.setup_assets`
  (P1 plan, steps 2-4). The weights are gitignored, so P7 does not get them from
  the checkout. P7 coordinates with P1 on how the asset reaches the image. See
  step 8.
- **Provisioned already this session.** Account `140381642432`, region
  `us-east-1`, the OIDC provider, the role `ndia-red-team-gha-deploy` (trust
  scoped to this repo, policy allows ECR push, ECS deploy, and `PassRole` to
  `ndia-red-team-*` task roles), ECR repos `ndia-red-team/{api,web,worker}`, and
  the four non-ECS repo variables. Do not recreate any of these.
- **Terraform state.** Decide where state lives before the first apply. An S3
  backend with a DynamoDB lock is the durable choice. A local state file is
  acceptable for a single operator during the hackathon. Record the choice in
  `deploy/terraform/README.md`.
- **Deployer identity for the first apply.** The `terraform apply` runs from a
  developer machine or a bootstrap CI run, not from the dormant deploy job. Use
  short-lived credentials. Do not use the compromised bootstrap keys (see
  section 9, key rotation).

---

## 4. Interfaces consumed and exposed

### Consumed

- **The environment contract, master-plan section 6.8.** All services read
  these. P7 is the sole provider.

  | Variable | Consumer | Source in P7 |
  |---|---|---|
  | `REDSIM_OUTPUT_DIR` | api task | EFS mount path in the task def |
  | `REDSIM_S3_BUCKET` | api task | plain task env, name of the P7 bucket |
  | `PYTHIA_BASE_URL` | api task | Secrets Manager, task `secrets` |
  | `PYTHIA_API_KEY` | api task | Secrets Manager, task `secrets` |
  | `REDSIM_LLM_MODEL` | api task | Secrets Manager, task `secrets` |
  | `NEXT_PUBLIC_REDSIM_API_URL` | web task | plain task env, the api ALB URL |

  Narrative recommendations stay off unless all three Pythia values resolve
  (master-plan section 6.8). Leave the secrets empty for the baseline demo and
  the pipeline still runs rules-only.

- **The existing pipeline, `deploy-aws.yml`.** The `build-and-push` job pushes
  `${ECR_REGISTRY}/ndia-red-team/{api,web}:${sha}` and `:latest`. The `deploy`
  job is gated on `vars.ECS_CLUSTER != ''` and then rolls each configured
  service with `aws ecs update-service --force-new-deployment` followed by
  `aws ecs wait services-stable`. P7 makes the task defs pull `:latest`, or
  pins the sha, so the forced deployment lands the new image.

### Exposed

- The three activation variables, set once the runtime exists:

  | Repo variable | Value |
  |---|---|
  | `ECS_CLUSTER` | the cluster name, e.g. `ndia-red-team` |
  | `ECS_SERVICE_API` | the api service name, e.g. `ndia-red-team-api` |
  | `ECS_SERVICE_WEB` | the web service name, e.g. `ndia-red-team-web` |

  The deploy job's guard fails loudly if `ECS_CLUSTER` is set but both service
  names are empty. Set all three together so the guard passes.

- The api ALB URL. Feeds the web task's `NEXT_PUBLIC_REDSIM_API_URL` and is the
  base URL a judge drives.

---

## 5. Ordered implementation steps

Apply order follows the dependency chain: network and ALB, then EFS, then S3,
then roles, then task defs, then services, then the repo variables.

1. **Terraform skeleton.** Create `deploy/terraform/` with `versions.tf`
   (provider `aws ~> 5`, region `us-east-1`, the state backend), `variables.tf`
   (account id, region, name prefix `ndia-red-team`, image tag), and
   `outputs.tf`. Pin the provider. Namespace every resource with the
   `ndia-red-team` prefix so the `PassRole` policy matches.

2. **Network and ALB (`network.tf`, `alb.tf`).** Reuse the default VPC and its
   public subnets for speed, or create a small VPC with two public subnets
   across two AZs. Create the ALB in the public subnets. Create two target
   groups: `api` (port 8000, health check path `/health`, matcher 200) and
   `web` (port 3000, health check path `/`). Add one HTTP listener on port 80.
   Route `/v1/*` and `/health` to the api target group and the default to the
   web target group, or run two listeners on 80 and 3000. Security groups: the
   ALB accepts 80 from the internet; the tasks accept 8000 and 3000 from the ALB
   security group only. Prove `/health` here first with the P0 image.

3. **EFS (`efs.tf`).** Create the filesystem, a mount target in each task subnet,
   and an access point that owns the run directory. The mount-target security
   group accepts NFS 2049 from the api task security group only. This is the
   fiddly, on-critical-path piece (master-plan section 9), so wire it early and
   test it in isolation. If it runs long, fall back to a single api task with an
   ephemeral local volume (section 9).

4. **S3 (`s3.tf`).** Create the datasets and reports bucket. Block all public
   access. Enable versioning. Its name is `REDSIM_S3_BUCKET`. Grant access
   through the task role in step 5, not through a bucket policy with keys and not
   through static credentials.

5. **IAM roles (`iam.tf`).** Create two roles, both prefixed `ndia-red-team-` so
   the existing `PassRole` grant covers them:
   - **Task execution role** `ndia-red-team-exec`: attach
     `AmazonECSTaskExecutionRolePolicy` (ECR pull, CloudWatch Logs) plus
     `secretsmanager:GetSecretValue` on the three P7 secret ARNs, so the agent
     can inject them.
   - **Task role** `ndia-red-team-api-task`: grant `s3:GetObject`,
     `s3:PutObject`, and `s3:ListBucket` scoped to the P7 bucket. Grant EFS
     client mount and write on the filesystem. No static keys. This role is the
     only S3 grant path.
   The web task needs only a minimal task role (no S3, no EFS).

6. **Secrets (`secrets.tf`).** Create three Secrets Manager entries for
   `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, and `REDSIM_LLM_MODEL`. Seed empty or
   placeholder values for the baseline demo. The task def references them by ARN
   in the container `secrets` block. The execution role reads them at task
   start.

7. **Task definitions (`ecs.tf`, `taskdef-api.json`, `taskdef-web.json`).**
   - **api task def:** Fargate, CPU 1024 or 2048 and memory 4096 or 8192 (torch,
     ART, and SHAP are heavy). Container port 8000. `executionRoleArn` the exec
     role, `taskRoleArn` the api task role. Mount the EFS access point at
     `REDSIM_OUTPUT_DIR`. Plain env: `REDSIM_OUTPUT_DIR`, `REDSIM_S3_BUCKET`.
     `secrets`: the three Pythia ARNs. Image
     `${ECR_REGISTRY}/ndia-red-team/api:latest`. CloudWatch Logs. Health check
     on the container maps to the ALB target group `/health`.
   - **web task def:** Fargate, CPU 512 and memory 1024. Container port 3000.
     Plain env `NEXT_PUBLIC_REDSIM_API_URL` set to the api ALB URL from step 2.
     Image `${ECR_REGISTRY}/ndia-red-team/web:latest`. CloudWatch Logs.

8. **Bake the CIFAR-10 asset (Dockerfile.api).** Prefer baked over fetch at
   start, so the running task needs no network for the model. The weights are
   gitignored, so a plain `COPY assets/ ./assets/` fails in CI. Two workable
   ways, decided with P1:
   - **Preferred: fetch the prebuilt asset from S3 during the image build.** P1
     (or a one-time bootstrap) uploads `cifar10_smallcnn.pt` and `MANIFEST.json`
     to `s3://<bucket>/assets/`. Add a build stage to `Dockerfile.api` that
     pulls them into `/app/assets/` using build-time credentials, so the final
     image ships the weights in a layer.
   - **Alternative: build the asset in CI before the image build**, then
     `COPY assets/ ./assets/`. This runs `python -m redsim.setup_assets` in the
     workflow, which downloads CIFAR-10 and trains the CNN. Slower, and it edits
     the build job, so it is the second choice.
   Coordinate the `assets/` path with P1 (P1 plan, step 4). Never train at
   container start (master-plan section 9).

9. **Apply.** Run `terraform apply` with short-lived credentials. Confirm the
   ALB `/health` returns ok against the P0 image before continuing.

10. **Create the services (`ecs.tf`).** Create the `api` and `web` Fargate
    services in the cluster, each attached to its target group, desired count 1,
    in the task subnets with the task security group. Name them
    `ndia-red-team-api` and `ndia-red-team-web`.

11. **Set the activation variables.** With the services running, set the three
    repo variables:
    ```
    gh variable set ECS_CLUSTER     --body ndia-red-team
    gh variable set ECS_SERVICE_API --body ndia-red-team-api
    gh variable set ECS_SERVICE_WEB --body ndia-red-team-web
    ```
    Set all three, so the deploy job's guard (both service names empty is a hard
    error) passes.

12. **Prove the pipeline.** Push a trivial change to a matched path on `main`, or
    run the workflow with `workflow_dispatch`. Confirm `build-and-push` pushes
    both images and `deploy` rolls both services to stable.

13. **Local dev parity.** Add `deploy/docker-compose.redsim.yml` with `api` and
    `web` only. No Postgres, no Keycloak, no Celery, no MinIO. See section 6.

---

## 6. Files to create and modify

### Create

- `deploy/terraform/versions.tf` — provider, region, state backend.
- `deploy/terraform/variables.tf` — account id, region, name prefix, image tag.
- `deploy/terraform/network.tf` — VPC or default-VPC data, subnets, security
  groups.
- `deploy/terraform/alb.tf` — ALB, target groups, listeners.
- `deploy/terraform/efs.tf` — filesystem, mount targets, access point.
- `deploy/terraform/s3.tf` — datasets and reports bucket.
- `deploy/terraform/iam.tf` — `ndia-red-team-exec` and `ndia-red-team-api-task`
  roles and policies.
- `deploy/terraform/secrets.tf` — the three Secrets Manager entries.
- `deploy/terraform/ecs.tf` — cluster, task defs, services.
- `deploy/terraform/outputs.tf` — the api ALB URL, the web ALB URL, the bucket
  name, the cluster and service names.
- `deploy/terraform/README.md` — state backend, apply order, and the one-time
  asset upload.
- `deploy/docker-compose.redsim.yml` — local `api` plus `web`, described below.

### Modify

- `deploy/Dockerfile.api` — add the asset-bake step (section 5, step 8). No
  change to the entrypoint.
- Repo variables `ECS_CLUSTER`, `ECS_SERVICE_API`, `ECS_SERVICE_WEB` — set once
  the runtime exists.

### Do not modify

- `.github/workflows/deploy-aws.yml`. The build job and the deploy job already
  do the right thing. P7 only supplies the variables the deploy job reads.
- `deploy/docker-compose.yml`. It is the stale aegis topology. Leave it or
  delete it, but the redsim compose is a new, separate file so a bad merge does
  not resurrect the aegis services.

### The redsim compose

`deploy/docker-compose.redsim.yml`, two services:

```yaml
services:
  api:
    build:
      context: ..
      dockerfile: deploy/Dockerfile.api
    environment:
      REDSIM_OUTPUT_DIR: /data/runs
      # REDSIM_S3_BUCKET, PYTHIA_* unset: S3 and narrative off locally
    volumes:
      - redsim-runs:/data/runs
    ports: ["8000:8000"]
  web:
    build:
      context: ..
      dockerfile: deploy/Dockerfile.web
    depends_on: [api]
    environment:
      NEXT_PUBLIC_REDSIM_API_URL: http://localhost:8000
    ports: ["3000:3000"]

volumes:
  redsim-runs:
```

A local volume stands in for EFS. No S3 and no Pythia locally, which matches the
"narrative off unless all set" contract. This gives dev parity with the ECS
task shape without any of the aegis backing services.

---

## 7. Testing & validation

1. **ALB health.** `curl http://<api-alb>/health` returns
   `{status:"ok", version:...}` and the api target group shows healthy. Do this
   with the P0 image before any ML lands.
2. **Web reaches the api.** Load the web ALB URL. The app calls the api at
   `NEXT_PUBLIC_REDSIM_API_URL` and `/v1/targets` returns without a CORS or
   network error.
3. **Pipeline green.** A push to `main` on a matched path builds both images and
   the deploy job rolls both services to stable. The deploy job's guard passes
   because all three service variables are set.
4. **EFS persistence.** Start a run, note its `run_id`, force a new api
   deployment (`aws ecs update-service --force-new-deployment`), then
   `GET /v1/runs/{id}` after the new task starts. The run survives the restart,
   which proves the filesystem `RunStore` is on EFS and not on the task's
   ephemeral disk.
5. **S3 receives a dataset.** `POST /v1/runs/{id}/dataset` (P6) writes under
   `s3://<bucket>/datasets/<run-id>/`. Confirm the object exists and that no
   static keys were used, only the task role.
6. **Secrets resolve.** Seed the three Pythia secrets with real values, redeploy,
   and confirm the api reads them from the task environment and narrative turns
   on. With them empty, confirm the pipeline still runs rules-only.
7. **Full demo path (the gate).** `POST /v1/runs` for the CIFAR-10 image target
   with FGSM and PGD against the deployed stack. Poll, then `GET /v1/runs/{id}`
   shows measurements, an MRI `scoring` block, SHAP observations, interpretation,
   and recommendations, each attack carrying its ATLAS technique. The web UI
   renders the two-column `/runs/[id]`.

---

## 8. Acceptance criteria / definition of done

P7 is done when master-plan section 10 holds for the deployed stack:

1. `GET /health` behind the api ALB returns ok, and both target groups are
   healthy.
2. `POST /v1/runs` against the deployed ECS stack runs the full pipeline for the
   CIFAR-10 image target and a tabular target with FGSM and PGD.
3. `GET /v1/runs/{id}` returns measurements, an MRI `scoring` block, SHAP
   observations, interpretation, and recommendations, with ATLAS techniques.
4. The web UI served from ECS renders `/targets`, `/runs`, `/runs/new`, and the
   two-column `/runs/[id]`.
5. `POST /v1/runs/{id}/dataset` writes a Croissant plus Parquet dataset to the
   P7 S3 bucket, and `GET /v1/datasets/{id}` returns its manifest.
6. A run persists across an api task restart (EFS proven).
7. A push to `main` builds both images and the deploy job rolls the services
   green, its guard passing because the three service variables are set.
8. The three Pythia secrets resolve from Secrets Manager into the api task, and
   the pipeline runs rules-only when they are empty.
9. `deploy/docker-compose.redsim.yml` brings up `api` plus `web` locally with no
   aegis services.
10. No static AWS keys anywhere in the runtime. OIDC drives the pipeline, the
    task role drives S3, and the compromised bootstrap keys are rotated
    (section 9).

---

## 9. Effort estimate & special considerations

**Effort.** Roughly 2 to 3 developer-days for one operator familiar with
Terraform and ECS. The network, ALB, S3, IAM, and services are about a day. EFS
plus Fargate wiring and the asset bake are the risk budget, another day. Proving
the full demo path and tuning task sizes is the remainder. P7 starts day 0 and
runs in parallel, so wall-clock cost overlaps the ML build.

**EFS plus Fargate wiring risk, and the single-task fallback.** This is the
known hard part (master-plan section 9). Mount targets, the access point, the
NFS security group, and the task volume must all line up, and a wrong security
group shows up only as a task that hangs on start. Mitigate by wiring EFS on
day 0 with the P0 image and testing the mount in isolation before ML lands. If
it runs long, fall back to a single api task with an ephemeral local volume for
`REDSIM_OUTPUT_DIR`, desired count fixed at 1. The demo still runs. The only
loss is persistence across a task restart, which the demo does not require.
Return to EFS once the demo path is green.

**Image size and build time.** The api image carries CPU torch, torchvision,
ART, and SHAP (master-plan section 9, spec section 17). It is multi-GB.
Mitigate: the CPU wheel index is already pinned in `Dockerfile.api`, versions
are pinned, and the build job already uses GHA layer cache
(`cache-from`/`cache-to` scope in `deploy-aws.yml`). Bake the trained weights as
a layer, never train at container start. Size the api task memory (4 to 8 GB) to
hold torch plus SHAP on images.

**Cost and teardown.** Fargate tasks, the ALB, EFS, and NAT if a private VPC is
used all bill by the hour. Keep desired count at 1 per service. Reuse the
default VPC public subnets to avoid NAT. After the demo, `terraform destroy`
tears down the runtime. The ECR repos, the OIDC role, and the repo variables
persist, so re-provisioning is another `terraform apply` plus resetting the
three service variables. Empty the S3 bucket and delete non-empty EFS before
destroy, or Terraform blocks.

**Key rotation (security).** The bootstrap AWS keys used to provision this
session are compromised and must be rotated. Deactivate and delete them in IAM
now. The pipeline uses OIDC through `ndia-red-team-gha-deploy`, not static keys.
The task role, not keys, grants S3. Confirm no static AWS keys live in the repo,
in GitHub secrets, in the task definitions, or in the compose files. The only
long-lived trust is the OIDC provider scoped to this repo.

**No worker service.** redsim runs jobs in-process (master-plan section 2), so
Phase A ships no worker task. The `ndia-red-team/worker` ECR repo stays unused.
Do not add a worker service or a Celery broker. If long jobs later starve the
api, revisit, but not for this demo.
