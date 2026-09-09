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

# --- secrets: fetched by the instance role, written as env files (mode 0600), never logged
set +x
for svc in api scans default beat web identity; do
  aws secretsmanager get-secret-value --region "$REGION" --secret-id "ndia-red-team/demo/${svc}" --query SecretString --output text \
    | jq -r 'to_entries[] | "\(.key)=\(.value|@json)"' > "/opt/redsim/env/${svc}.secret.env"   # JSON-quoted: PEM values span lines
  chmod 0600 "/opt/redsim/env/${svc}.secret.env"
done
# Better Auth reads BETTER_AUTH_SECRET; the web secret carries it as NEXTAUTH_SECRET.
grep '^NEXTAUTH_SECRET=' /opt/redsim/env/web.secret.env | sed 's/^NEXTAUTH_SECRET=/BETTER_AUTH_SECRET=/' >> /opt/redsim/env/web.secret.env
# Pythia (optional): PYTHIA_API_KEY, PYTHIA_BASE_URL, PYTHIA_PERSONA, REDSIM_ML_LLM_MODEL in one
# secret. Present: the workers get it and the narrative is on. Absent: rules only.
DISABLE_LLM=1
if aws secretsmanager get-secret-value --region "$REGION" --secret-id "ndia-red-team/demo/pythia" --query SecretString --output text 2>/dev/null \
    | jq -r 'to_entries[] | "\(.key)=\(.value|@json)"' > /opt/redsim/env/pythia.env && [ -s /opt/redsim/env/pythia.env ]; then
  DISABLE_LLM=0
else
  : > /opt/redsim/env/pythia.env
fi
chmod 0600 /opt/redsim/env/pythia.env
set -x

cat > /opt/redsim/env/common.env <<EOF
REDSIM_ENV=prod
REDSIM_AUTH_MODE=oidc
REDSIM_BLOB_BACKEND=s3
REDSIM_S3_BUCKET=${BUCKET}
REDSIM_S3_REGION=${REGION}
AWS_DEFAULT_REGION=${REGION}
AWS_REGION=${REGION}
REDSIM_DISABLE_LLM=${DISABLE_LLM}
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
    env_file: [env/common.env, env/api.secret.env]
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
    env_file: [env/common.env, env/pythia.env, env/scans.secret.env]
    volumes: ["./assets:/app/assets:ro"]
  default:
    image: ${REGISTRY}/worker:${IMAGE_TAG}
    restart: unless-stopped
    command: ["celery", "-A", "redsim.workers.celery_app", "worker", "-Q", "default", "--concurrency=1", "--loglevel=info"]
    env_file: [env/common.env, env/pythia.env, env/default.secret.env]
    volumes: ["./assets:/app/assets:ro"]
  beat:
    image: ${REGISTRY}/worker:${IMAGE_TAG}
    restart: unless-stopped
    command: ["celery", "-A", "redsim.workers.celery_app", "beat", "--schedule=/tmp/celerybeat-schedule", "--loglevel=info"]
    env_file: [env/common.env, env/beat.secret.env]
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
cat > /usr/local/bin/redsim-roll <<'EOF'
#!/usr/bin/env bash
# Roll every redsim container to the ECR images of one tag (a main commit sha or "latest").
set -euo pipefail
TAG="${1:?image tag}"
cd /opt/redsim
sed -i -E "s#(ndia-red-team/(api|web|worker|identity)):[A-Za-z0-9._-]+#\1:${TAG}#g" docker-compose.yml
/usr/local/bin/redsim-ecr-login
docker compose pull
docker compose up -d --remove-orphans
docker compose ps
EOF
chmod +x /usr/local/bin/redsim-roll

docker compose pull
docker compose up -d
docker compose ps
echo "redsim bootstrap finished"
