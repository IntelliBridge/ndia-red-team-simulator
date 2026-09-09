#!/usr/bin/env bash
# redsim single-host bootstrap (EC2, Ubuntu 24.04). The __PLACEHOLDERS__ are filled by
# the launcher (deploy/ec2/README.md). Applied to i-0cc7eb0ee0880ea3b on 2026-09-09.
set -euxo pipefail
exec > >(tee -a /var/log/redsim-bootstrap.log) 2>&1

REGION="__REGION__"
ACCOUNT="__ACCOUNT__"
IMAGE_TAG="__IMAGE_TAG__"
ORIGIN="__ORIGIN__"
HOST="__HOST__"
BUCKET="__BUCKET__"
BUNDLE_KEY="__BUNDLE_KEY__"
BUNDLE_SHA="__BUNDLE_SHA__"
DB_HOST="__DB_HOST__"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/ndia-red-team"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg jq unzip
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker
usermod -aG docker ubuntu || true
curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
unzip -q -o /tmp/awscliv2.zip -d /tmp && /tmp/aws/install --update

mkdir -p /opt/redsim/env /opt/redsim/assets /opt/redsim/caddy
cd /opt/redsim

# --- host scripts. The canonical copies are deploy/ec2/redsim-render-env.sh and
# deploy/ec2/redsim-roll.sh; the deploy-ec2 job re-installs both from the commit it
# deploys before calling redsim-roll, so the copies embedded here only have to carry
# the first boot. Keep them identical to the repository files when editing.
cat > /usr/local/bin/redsim-render-env <<'RENDER_ENV'
#!/usr/bin/env bash
# Render the redsim host environment from Secrets Manager (see deploy/ec2/redsim-render-env.sh).
set -euo pipefail
REGION="${AWS_REGION:-${REGION:-us-east-1}}"
ENV_DIR="${REDSIM_ENV_DIR:-/opt/redsim/env}"
mkdir -p "$ENV_DIR"
umask 077
render_secret() {  # <secret name> <target file>; JSON-quoted values so PEM blocks survive
  aws secretsmanager get-secret-value --region "$REGION" --secret-id "$1" --query SecretString --output text \
    | jq -r 'to_entries[] | "\(.key)=\(.value|@json)"' > "$2"
  chmod 0600 "$2"
}
for svc in api scans default beat web identity; do
  render_secret "ndia-red-team/demo/${svc}" "${ENV_DIR}/${svc}.secret.env"
done
# Better Auth reads BETTER_AUTH_SECRET; the web secret carries it as NEXTAUTH_SECRET.
if ! grep -q '^BETTER_AUTH_SECRET=' "${ENV_DIR}/web.secret.env"; then
  grep '^NEXTAUTH_SECRET=' "${ENV_DIR}/web.secret.env" | sed 's/^NEXTAUTH_SECRET=/BETTER_AUTH_SECRET=/' >> "${ENV_DIR}/web.secret.env"
fi
# Pythia (optional). Present: api and workers get it, LLM probes are on, the gateway
# host joins the allowlist. Absent: REDSIM_DISABLE_LLM=1 and rules-only narratives.
DISABLE_LLM=1
PYTHIA_HOST=""
if render_secret "ndia-red-team/demo/pythia" "${ENV_DIR}/pythia.env" 2>/dev/null && [ -s "${ENV_DIR}/pythia.env" ]; then
  DISABLE_LLM=0
  PYTHIA_HOST="$(grep '^PYTHIA_BASE_URL=' "${ENV_DIR}/pythia.env" | cut -d= -f2- | tr -d '"' \
    | sed -E 's#^[A-Za-z]+://##; s#[/:].*$##')"
else
  : > "${ENV_DIR}/pythia.env"
  chmod 0600 "${ENV_DIR}/pythia.env"
fi
ALLOWLIST="127.0.0.1,localhost,host.docker.internal"
if [ -n "$PYTHIA_HOST" ]; then
  ALLOWLIST="${ALLOWLIST},${PYTHIA_HOST}"
fi
cat > "${ENV_DIR}/llm.env" <<EOT
REDSIM_DISABLE_LLM=${DISABLE_LLM}
REDSIM_TARGET_ALLOWLIST=${ALLOWLIST}
EOT
chmod 0600 "${ENV_DIR}/llm.env"
echo "redsim-render-env: llm_disabled=${DISABLE_LLM} pythia_host=${PYTHIA_HOST:-none} allowlist=${ALLOWLIST}"
RENDER_ENV
chmod 0755 /usr/local/bin/redsim-render-env

# --- secrets: fetched by the instance role, written as env files (mode 0600), never logged.
# Also writes env/pythia.env and env/llm.env (REDSIM_DISABLE_LLM, REDSIM_TARGET_ALLOWLIST).
set +x
REGION="$REGION" /usr/local/bin/redsim-render-env
set -x

cat > /opt/redsim/env/common.env <<EOF
REDSIM_ENV=prod
REDSIM_AUTH_MODE=oidc
REDSIM_BLOB_BACKEND=s3
REDSIM_S3_BUCKET=${BUCKET}
REDSIM_S3_REGION=${REGION}
AWS_DEFAULT_REGION=${REGION}
AWS_REGION=${REGION}
REDSIM_WORM_EXPORT=0
REDSIM_WEB_ORIGIN=${ORIGIN}
REDSIM_CORS_ORIGINS=${ORIGIN}
REDSIM_OIDC_ISSUER=${ORIGIN}/auth/realms/redsim
REDSIM_OIDC_JWKS_URL=http://identity:8080/auth/realms/redsim/protocol/openid-connect/certs
REDSIM_ML_ASSETS_DIR=/app/assets
REDSIM_ML_WORK_DIR=/tmp/redsim-ml
REDSIM_ML_DATASET_CACHE=/tmp/redsim-cache
REDSIM_ML_SANDBOX_MEMORY_MB=4096
EOF
cat > /opt/redsim/env/web.env <<EOF
REDSIM_ENV=prod
BETTER_AUTH_URL=${ORIGIN}
REDSIM_API_URL=http://api:8000
KEYCLOAK_CLIENT_ID=redsim-web
KEYCLOAK_ISSUER=http://identity:8080/auth/realms/redsim
KEYCLOAK_PUBLIC_ISSUER=${ORIGIN}/auth/realms/redsim
EOF
cat > /opt/redsim/env/identity.env <<EOF
KC_DB=postgres
KC_DB_URL=jdbc:postgresql://${DB_HOST}:5432/redsim_identity?sslmode=require
KC_DB_USERNAME=redsim_identity
KC_HTTP_ENABLED=true
KC_HTTP_RELATIVE_PATH=/auth
KC_HOSTNAME=${ORIGIN}/auth
KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true
KC_PROXY_HEADERS=xforwarded
KC_BOOTSTRAP_ADMIN_USERNAME=redsim-admin
REDSIM_PUBLIC_ORIGIN=${ORIGIN}
KC_CACHE=local
EOF

# --- asset bundle (digest-checked, extracted once)
aws s3 cp --region "$REGION" "s3://${BUCKET}/${BUNDLE_KEY}" /tmp/bundle.tar.gz
echo "${BUNDLE_SHA}  /tmp/bundle.tar.gz" | sha256sum -c -
tar -xzf /tmp/bundle.tar.gz -C /opt/redsim/assets
test -f /opt/redsim/assets/MANIFEST.json

# --- TLS terminator and router (Let's Encrypt on the hostname)
cat > /opt/redsim/caddy/Caddyfile <<EOF
${HOST} {
  encode gzip
  handle /v1/* {
    reverse_proxy api:8000
  }
  handle /health {
    reverse_proxy api:8000
  }
  handle /ws/* {
    reverse_proxy api:8000
  }
  handle /metrics {
    respond 404
  }
  handle /auth/* {
    reverse_proxy identity:8080
  }
  handle {
    reverse_proxy web:3000
  }
}
EOF

cat > /opt/redsim/docker-compose.yml <<EOF
name: redsim
services:
  caddy:
    image: caddy:2
    restart: unless-stopped
    ports: ["80:80", "443:443"]
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
    depends_on: [api, web, identity]
  identity:
    image: ${REGISTRY}/identity:${IMAGE_TAG}
    restart: unless-stopped
    command: ["start", "--import-realm"]
    env_file: [env/identity.env, env/identity.secret.env]
    healthcheck:
      test: ["CMD-SHELL", "bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080 && printf \"GET /auth/realms/redsim HTTP/1.0\\r\\n\\r\\n\" >&3 && grep -q \" 200 \" <&3'"]
      interval: 15s
      timeout: 5s
      retries: 40
      start_period: 120s
  api:
    image: ${REGISTRY}/api:${IMAGE_TAG}
    restart: unless-stopped
    command: ["uvicorn", "redsim.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
    env_file: [env/common.env, env/llm.env, env/pythia.env, env/api.secret.env]
    volumes: ["./assets:/app/assets:ro"]
    depends_on:
      identity: { condition: service_healthy }
  web:
    image: ${REGISTRY}/web:${IMAGE_TAG}
    restart: unless-stopped
    env_file: [env/web.env, env/web.secret.env]
    depends_on:
      identity: { condition: service_healthy }
      api: { condition: service_started }
  scans:
    image: ${REGISTRY}/worker:${IMAGE_TAG}
    restart: unless-stopped
    command: ["celery", "-A", "redsim.workers.celery_app", "worker", "-Q", "scans", "--concurrency=1", "--loglevel=info"]
    env_file: [env/common.env, env/llm.env, env/pythia.env, env/scans.secret.env]
    volumes: ["./assets:/app/assets:ro"]
  default:
    image: ${REGISTRY}/worker:${IMAGE_TAG}
    restart: unless-stopped
    command: ["celery", "-A", "redsim.workers.celery_app", "worker", "-Q", "default", "--concurrency=1", "--loglevel=info"]
    env_file: [env/common.env, env/llm.env, env/pythia.env, env/default.secret.env]
    volumes: ["./assets:/app/assets:ro"]
  beat:
    image: ${REGISTRY}/worker:${IMAGE_TAG}
    restart: unless-stopped
    command: ["celery", "-A", "redsim.workers.celery_app", "beat", "--schedule=/tmp/celerybeat-schedule", "--loglevel=info"]
    env_file: [env/common.env, env/llm.env, env/beat.secret.env]
volumes:
  caddy-data: {}
  caddy-config: {}
EOF

# --- pull and start; ECR login refreshes every 6 h through a systemd timer
cat > /usr/local/bin/redsim-ecr-login <<EOF
#!/usr/bin/env bash
set -euo pipefail
aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com
EOF
chmod +x /usr/local/bin/redsim-ecr-login
/usr/local/bin/redsim-ecr-login
cat > /etc/systemd/system/redsim-ecr-login.service <<'EOF'
[Unit]
Description=Refresh the ECR login for the redsim containers
[Service]
Type=oneshot
ExecStart=/usr/local/bin/redsim-ecr-login
EOF
cat > /etc/systemd/system/redsim-ecr-login.timer <<'EOF'
[Unit]
Description=Refresh the ECR login every six hours
[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload && systemctl enable --now redsim-ecr-login.timer

# A release roll on this host: /usr/local/bin/redsim-roll <image-tag>
# (canonical copy: deploy/ec2/redsim-roll.sh, re-installed by every deploy-ec2 run)
cat > /usr/local/bin/redsim-roll <<'ROLL'
#!/usr/bin/env bash
# Roll every redsim container to the ECR images of one tag (a main commit sha or "latest").
set -euo pipefail
TAG="${1:?image tag}"
cd /opt/redsim
sed -i -E "s#(ndia-red-team/(api|web|worker|identity)):[A-Za-z0-9._-]+#\1:${TAG}#g" docker-compose.yml
/usr/local/bin/redsim-render-env
# Idempotent env_file repairs for compose files written by an older bootstrap.
if ! grep -q 'env/llm.env' docker-compose.yml; then
  sed -i -E 's#env_file: \[env/common\.env, env/api\.secret\.env\]#env_file: [env/common.env, env/llm.env, env/pythia.env, env/api.secret.env]#' docker-compose.yml
  sed -i -E 's#env_file: \[env/common\.env, env/pythia\.env, env/(scans|default)\.secret\.env\]#env_file: [env/common.env, env/llm.env, env/pythia.env, env/\1.secret.env]#' docker-compose.yml
  sed -i -E 's#env_file: \[env/common\.env, env/beat\.secret\.env\]#env_file: [env/common.env, env/llm.env, env/beat.secret.env]#' docker-compose.yml
fi
sed -i '/^REDSIM_DISABLE_LLM=/d' env/common.env
/usr/local/bin/redsim-ecr-login
docker compose pull
docker compose up -d --remove-orphans
docker compose ps
ROLL
chmod 0755 /usr/local/bin/redsim-roll

docker compose pull
docker compose up -d
docker compose ps
echo "redsim bootstrap finished"
