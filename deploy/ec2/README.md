# Single-host EC2 runtime

The demo runs on one EC2 instance since 2026-09-09. The ECS runtime in
`../runtime` is retired: every ECS service is at desired count zero and the
DNS record is no longer managed by that Terraform root. The foundation
(`../terraform`: RDS PostgreSQL, Redis, the artifacts and audit buckets, the
IAM roles, the VPC) stays and is what the host uses.

| Item | Value |
|---|---|
| Instance | `i-0cc7eb0ee0880ea3b`, `t3.xlarge`, Ubuntu 24.04, us-east-1a, public subnet `ndia-red-team-demo-public-a` |
| Elastic IP | `100.61.75.31` (`eipalloc-0de107af31e9bf3aa`), A record `redsim.ndia.agiledefense.xyz`, TTL 60 |
| Security groups | `redsim-ec2` (443 and 80 from anywhere, 22 from the operator's IP), plus the foundation's `api` and `identity` groups, which the RDS and Redis groups already admit |
| Instance role | `redsim-ec2`: SSM core, ECR read, `secretsmanager:GetSecretValue` on `ndia-red-team/demo/*`, read and write on the artifacts bucket |
| Key pair | `redsim-ec2` (the operator holds the private key; SSM works without it) |
| Images | ECR `ndia-red-team/{api,worker,web,identity}` at a `main` commit sha, pulled by the host |
| TLS | Caddy with Let's Encrypt on the hostname (ports 80 and 443) |

## What runs on the host

`deploy/ec2/user-data.sh` is the cloud-init script, with its placeholders
filled by the launcher. It installs Docker and the AWS CLI, fetches the
per-service secrets from Secrets Manager (`ndia-red-team/demo/{api,scans,
default,beat,web,identity}` and, when present, `ndia-red-team/demo/pythia`)
into `/opt/redsim/env/*.secret.env` (mode 0600, JSON-quoted so PEM values
survive), writes the non-secret environment that the ECS task definitions
carried, downloads and verifies the pinned asset bundle into
`/opt/redsim/assets`, and starts `/opt/redsim/docker-compose.yml`:

| Container | Image | Role |
|---|---|---|
| `caddy` | `caddy:2` | TLS and routing: `/v1/*`, `/health`, `/ws/*` to the API; `/auth/*` to Keycloak; the rest to the web app |
| `identity` | identity | Keycloak (`start --import-realm`) on the existing `redsim_identity` database |
| `api` | api | `uvicorn redsim.api.app:create_app`, bundle mounted read-only |
| `web` | web | Next.js with Better Auth (`BETTER_AUTH_URL`, `KEYCLOAK_PUBLIC_ISSUER`, `REDSIM_API_URL=http://api:8000`) |
| `scans`, `default` | worker | Celery pools, bundle mounted, Pythia variables when the secret exists |
| `beat` | worker | Celery beat |

Keycloak's realm, the demo users and the application data are in RDS, so
nothing was re-seeded for the move.

## Releases

Every push to `main` builds the four images (`.github/workflows/deploy-aws.yml`,
`build-and-push`) and then the `deploy-ec2` job runs one SSM command on the
host: `redsim-roll <sha>`, which re-tags the compose file, pulls the images
of that commit and recreates the containers. The job waits for the command
result, fails on a non-zero exit, and then requires `/health` to answer 200
on the public hostname. The deploy role `ndia-red-team-gha-deploy` holds
`ssm:SendCommand` on this one instance; the repository variable
`EC2_INSTANCE_ID` names it. Roughly two minutes after the images exist.

By hand, from a machine with the hackathon profile:

```bash
export AWS_PROFILE=ndia-hackathon AWS_CA_BUNDLE=$HOME/.aws/Zscaler_Root_CA.pem AWS_REGION=us-east-1
aws ssm send-command --instance-ids i-0cc7eb0ee0880ea3b --document-name AWS-RunShellScript \
  --parameters 'commands=["sudo redsim-roll <sha-or-latest>"]'
# or interactively
aws ssm start-session --target i-0cc7eb0ee0880ea3b
ssh -i ~/.ssh/redsim-ec2.pem ubuntu@100.61.75.31
```

On the host: `cd /opt/redsim && docker compose ps`, `docker compose logs -f
api`, `/var/log/redsim-bootstrap.log` for the first boot.

## Environment

Non-secret values live in `/opt/redsim/env/{common,web,identity}.env` and
are written by the bootstrap. Secrets come from Secrets Manager at boot; to
change one, update the secret and re-run the render loop from the bootstrap
(or relaunch). `REDSIM_DISABLE_LLM` is `0` when the Pythia secret exists and
`1` otherwise. `BETTER_AUTH_URL` is the public origin
(`https://redsim.ndia.agiledefense.xyz`), never a callback path or
localhost: Better Auth derives the callback from it and the tRPC layer
compares request origins against it.

## Launching a replacement host

1. `deploy/ec2/user-data.sh`: fill `__REGION__`, `__ACCOUNT__`,
   `__IMAGE_TAG__` (a `main` sha with images in ECR), `__ORIGIN__`,
   `__HOST__`, `__BUCKET__`, `__BUNDLE_KEY__`, `__BUNDLE_SHA__`, `__DB_HOST__`.
2. `aws ec2 run-instances` with the Ubuntu 24.04 AMI from SSM parameter
   `/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id`,
   the public subnet, the three security groups, `--iam-instance-profile
   Name=redsim-ec2`, `--metadata-options HttpTokens=required,HttpPutResponseHopLimit=2`
   (the containers read the instance role through IMDS), an 80 GB gp3 root
   and the user data.
3. `aws ec2 associate-address --allocation-id eipalloc-0de107af31e9bf3aa
   --instance-id <new id>`, then set the repository variable
   `EC2_INSTANCE_ID` and the deploy role's `ssm:SendCommand` resource to the
   new instance.
4. Wait for `/var/log/redsim-bootstrap.log` to end with `redsim bootstrap
   finished`; Caddy obtains the certificate within a minute of the EIP
   pointing at the host.

## Known limits

- One host, no redundancy; a reboot restarts every container
  (`restart: unless-stopped`).
- The ECR login is refreshed by a systemd timer every six hours; a pull
  more than twelve hours after the last refresh runs `redsim-ecr-login`
  first (`redsim-roll` does).
- The ACM certificate of the ECS runtime is unused; Caddy holds its own.
- Port 22 admits only the operator IP recorded at launch; SSM needs no port.
