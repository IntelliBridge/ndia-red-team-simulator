# Single-host EC2 runtime (native processes)

The demo runs on one EC2 instance as native processes under systemd since
2026-09-09. No containers, no image build, no registry. The ECS runtime in
`../runtime` is retired (services at zero, DNS record unmanaged there). The
foundation (`../terraform`: RDS PostgreSQL, Redis, the artifacts bucket, the
IAM roles, the VPC) stays and is what the host uses.

| Item | Value |
|---|---|
| Instance | `i-0cc7eb0ee0880ea3b`, `t3.xlarge`, Ubuntu 24.04, us-east-1a, subnet `ndia-red-team-demo-public-a` |
| Elastic IP | `100.61.75.31` (`eipalloc-0de107af31e9bf3aa`), A record `redsim.ndia.agiledefense.xyz`, TTL 60 |
| Security groups | `redsim-ec2` (443 and 80 public, 22 from the operator IP) plus the foundation's `api` and `identity` groups, which RDS and Redis admit |
| Instance role | `redsim-ec2`: SSM core, ECR read, `secretsmanager:GetSecretValue` on `ndia-red-team/demo/*`, the artifacts bucket |
| Checkout | `/opt/redsim/src` (a clone of this repository, detached at the deployed commit) |
| Python | `/opt/redsim/venv` (3.12, `.[api,worker,ml]` with CPU torch, editable install of the checkout) |
| Node | Node 20, pnpm 10 through corepack, `node_modules` in the checkout |
| Keycloak | `/opt/keycloak` (26.7.3, Java 21), realm import from `deploy/runtime/identity/realm.json` |
| TLS | Caddy from the apt package, Let's Encrypt on the hostname (`/etc/caddy/Caddyfile`) |

## Processes

| Unit | Command | Listens |
|---|---|---|
| `redsim-identity` | `kc.sh start --import-realm` | 127.0.0.1:8080 (`/auth`) |
| `redsim-api` | `uvicorn redsim.api.app:create_app --factory` | 127.0.0.1:8000 |
| `redsim-scans`, `redsim-default` | `celery worker -Q scans` / `-Q default` | none |
| `redsim-beat` | `celery beat` | none |
| `redsim-web` | `pnpm --filter @redsim/web dev` (Next.js dev server on the checkout) | 127.0.0.1:3000 |
| `caddy` | routes `/v1/*`, `/health`, `/ws/*` to the API, `/auth/*` to Keycloak, the rest to the web app | 80, 443 |

Every unit starts through `/usr/local/bin/redsim-run <service> <command>`,
which assembles the environment from `/opt/redsim/env/common.env` (or
`web.env`, `identity.env`) and the Secrets Manager JSON `/opt/redsim/env/<service>.json`
(plus `pythia.json` for the workers, which turns the narrative on), then
execs the command. JSON keeps PEM values intact; nothing secret reaches the
command line or the journal. Keycloak's realm, the users and the application
data are in RDS.

Logs: `journalctl -u redsim-api -f` (or any unit), `/var/log/redsim-native-bootstrap.log`.

## Releases: a push to main is a deploy

`.github/workflows/deploy-host.yml` runs on every push to `main`: one SSM
command on the instance named by the repository variable `EC2_INSTANCE_ID`
runs `redsim-deploy`, which fast-forwards the checkout, reinstalls only what
the diff touched (venv when `pyproject.toml` changed, node modules when the
lockfile changed, realm when it changed), restarts the units and requires
`/health` 200. Under a minute. The web dev server reloads by itself.

From a laptop, without waiting for GitHub:

```bash
export AWS_PROFILE=ndia-hackathon AWS_CA_BUNDLE=$HOME/.aws/Zscaler_Root_CA.pem AWS_REGION=us-east-1
make deploy-host            # origin/main
make deploy-host REF=my-branch
aws ssm start-session --target i-0cc7eb0ee0880ea3b        # a shell on the host
ssh -i ~/.ssh/redsim-ec2.pem ubuntu@100.61.75.31          # from the operator IP
```

`deploy-aws.yml` (the ECR image build) is manual only and not part of any deploy.

## Environment

Non-secret values: `/opt/redsim/env/{common,web,identity}.env`, written by
the bootstrap. Secrets: fetched from `ndia-red-team/demo/*` at bootstrap
into `/opt/redsim/env/*.json` (0600, owner `redsim`). To change one, update
the secret and re-run the secrets block of the bootstrap (or the whole
bootstrap, it is idempotent), then restart the unit. `BETTER_AUTH_URL` is the
public origin, never a callback path or localhost. `REDSIM_DISABLE_LLM` is
`0` on the workers when `pythia.json` exists.

Schema migrations are not run by the deploy. When `redsim/db/migrations`
changes, run Alembic once with the migration credentials
(`ndia-red-team/demo/migration` plus the RDS master secret, as
`deploy/runtime/scripts/migrate.py` does).

## Building or rebuilding a host

1. Launch Ubuntu 24.04 (`t3.xlarge` or larger) in the public subnet with the
   three security groups, `--iam-instance-profile Name=redsim-ec2`,
   `--metadata-options HttpTokens=required,HttpPutResponseHopLimit=2`, an
   80 GB gp3 root, and associate the Elastic IP.
2. On the host: `git clone https://github.com/IntelliBridge/ndia-red-team-simulator.git /opt/redsim/src`,
   write `/opt/redsim/deploy.env` with `REDSIM_PUBLIC_ORIGIN=https://redsim.ndia.agiledefense.xyz`
   and `REDSIM_DB_HOST=<rds host>`, download and extract the asset bundle
   into `/opt/redsim/assets` (`assets/bundles/<sha>.tar.gz` in the artifacts
   bucket, verify the SHA-256), then
   `bash /opt/redsim/src/deploy/ec2/native/bootstrap-native.sh`.
3. Point `EC2_INSTANCE_ID` and the deploy role's `ssm:SendCommand` resource at
   the new instance.

## Known limits

- One host, no redundancy; units restart on failure and on reboot.
- The web app runs the Next.js dev server for instant reloads; first page
  loads compile on demand and take a few seconds.
- Port 22 admits only the operator IP recorded at launch; SSM needs no port.
