#!/usr/bin/env bash
#
# Turn the EC2 host into a native (no containers) redsim runtime.
#
# Run as root from a checkout: `bash /opt/redsim/src/deploy/ec2/native/bootstrap-native.sh`.
# Idempotent: re-running updates packages, the venv, the node modules and the
# units, then restarts everything. Reads /opt/redsim/deploy.env for
# REDSIM_PUBLIC_ORIGIN and the asset bundle location, and fetches the service
# secrets from Secrets Manager ndia-red-team/demo/* with the instance role.
set -euo pipefail
exec > >(tee -a /var/log/redsim-native-bootstrap.log) 2>&1

HOST_DIR=/opt/redsim
SRC=$HOST_DIR/src
# Helpers and unit files come from this script's own directory, so a deploy that
# moves the checkout while the bootstrap runs cannot break it.
NATIVE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV=$HOST_DIR/venv
KC_VERSION=26.7.3
REGION=us-east-1
# shellcheck disable=SC1091
source $HOST_DIR/deploy.env
ORIGIN="${REDSIM_PUBLIC_ORIGIN:?}"
HOSTNAME_FQDN="${ORIGIN#https://}"
DB_HOST="${REDSIM_DB_HOST:?set REDSIM_DB_HOST in deploy.env}"
export DEBIAN_FRONTEND=noninteractive

echo "== packages"
apt-get update -y
apt-get install -y python3.12 python3.12-venv python3-pip git curl jq unzip ca-certificates gnupg \
  openjdk-21-jre-headless debian-keyring debian-archive-keyring apt-transport-https
if ! command -v node >/dev/null || [[ "$(node -v)" != v20* ]]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi
corepack enable && corepack prepare pnpm@10 --activate
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y && apt-get install -y caddy
fi
command -v aws >/dev/null || { curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip && unzip -q -o /tmp/awscliv2.zip -d /tmp && /tmp/aws/install --update; }

echo "== secrets and environment"
mkdir -p $HOST_DIR/env
set +x
for svc in api scans default beat web identity; do
  aws secretsmanager get-secret-value --region $REGION --secret-id "ndia-red-team/demo/${svc}" --query SecretString --output text > "$HOST_DIR/env/${svc}.json"
  chmod 0600 "$HOST_DIR/env/${svc}.json"
done
# Better Auth reads BETTER_AUTH_SECRET; the web secret carries NEXTAUTH_SECRET.
python3 - "$HOST_DIR/env/web.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
d.setdefault("BETTER_AUTH_SECRET", d.get("NEXTAUTH_SECRET", ""))
json.dump(d, open(p, "w"))
PY
if aws secretsmanager get-secret-value --region $REGION --secret-id ndia-red-team/demo/pythia --query SecretString --output text > "$HOST_DIR/env/pythia.json" 2>/dev/null; then
  chmod 0600 "$HOST_DIR/env/pythia.json"
else
  rm -f "$HOST_DIR/env/pythia.json"
fi
BUCKET="$(aws secretsmanager get-secret-value --region $REGION --secret-id ndia-red-team/demo/api --query SecretString --output text | jq -r '.REDSIM_S3_BUCKET // empty')"
BUCKET="${BUCKET:-${REDSIM_S3_BUCKET:-ndia-red-team-demo-140381642432-us-east-1-artifacts}}"

cat > $HOST_DIR/env/common.env <<EOF
REDSIM_ENV=prod
REDSIM_AUTH_MODE=oidc
REDSIM_BLOB_BACKEND=s3
REDSIM_S3_BUCKET=${BUCKET}
REDSIM_S3_REGION=${REGION}
AWS_DEFAULT_REGION=${REGION}
AWS_REGION=${REGION}
REDSIM_DISABLE_LLM=1
REDSIM_WORM_EXPORT=0
REDSIM_WEB_ORIGIN=${ORIGIN}
REDSIM_CORS_ORIGINS=${ORIGIN}
REDSIM_OIDC_ISSUER=${ORIGIN}/auth/realms/redsim
REDSIM_OIDC_JWKS_URL=http://127.0.0.1:8080/auth/realms/redsim/protocol/openid-connect/certs
REDSIM_ML_ASSETS_DIR=${HOST_DIR}/assets
REDSIM_ML_WORK_DIR=/var/tmp/redsim-ml
REDSIM_ML_DATASET_CACHE=/var/tmp/redsim-cache
REDSIM_ML_SANDBOX_MEMORY_MB=4096
EOF
cat > $HOST_DIR/env/web.env <<EOF
REDSIM_ENV=prod
NEXT_TELEMETRY_DISABLED=1
BETTER_AUTH_URL=${ORIGIN}
REDSIM_API_URL=http://127.0.0.1:8000
NEXT_PUBLIC_REDSIM_API_URL=${ORIGIN}
KEYCLOAK_CLIENT_ID=redsim-web
KEYCLOAK_ISSUER=http://127.0.0.1:8080/auth/realms/redsim
KEYCLOAK_PUBLIC_ISSUER=${ORIGIN}/auth/realms/redsim
EOF
cat > $HOST_DIR/env/identity.env <<EOF
KC_DB=postgres
KC_DB_URL=jdbc:postgresql://${DB_HOST}:5432/redsim_identity?sslmode=require
KC_DB_USERNAME=redsim_identity
KC_HTTP_ENABLED=true
KC_HTTP_HOST=127.0.0.1
KC_HTTP_RELATIVE_PATH=/auth
KC_HOSTNAME=${ORIGIN}/auth
KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true
KC_PROXY_HEADERS=xforwarded
KC_BOOTSTRAP_ADMIN_USERNAME=redsim-admin
REDSIM_PUBLIC_ORIGIN=${ORIGIN}
KC_CACHE=local
EOF
set -x
install -m 0755 "$NATIVE_DIR/redsim-run" /usr/local/bin/redsim-run
install -m 0755 "$NATIVE_DIR/redsim-deploy" /usr/local/bin/redsim-deploy

echo "== python venv"
[ -x $VENV/bin/python ] || python3.12 -m venv $VENV
$VENV/bin/pip install --quiet --upgrade pip
$VENV/bin/pip install --quiet --index-url https://download.pytorch.org/whl/cpu "torch>=2.3" "torchvision>=0.18"
(cd $SRC && $VENV/bin/pip install --quiet -e ".[api,worker,ml]")
$VENV/bin/python -c "import redsim, torch, art; print('venv ok', torch.__version__)"

echo "== web dependencies"
(cd $SRC && CI=true pnpm install --frozen-lockfile)   # CI=true: no TTY prompt when node_modules is replaced

echo "== keycloak ${KC_VERSION}"
if [ ! -x /opt/keycloak/bin/kc.sh ]; then
  curl -fsSL "https://github.com/keycloak/keycloak/releases/download/${KC_VERSION}/keycloak-${KC_VERSION}.tar.gz" -o /tmp/keycloak.tar.gz
  rm -rf /opt/keycloak && mkdir -p /opt/keycloak && tar -xzf /tmp/keycloak.tar.gz -C /opt/keycloak --strip-components=1
fi
mkdir -p /opt/keycloak/data/import
cp $SRC/deploy/runtime/identity/realm.json /opt/keycloak/data/import/redsim-realm.json
id -u redsim >/dev/null 2>&1 || useradd --system --home $HOST_DIR --shell /usr/sbin/nologin redsim
chown -R redsim:redsim /opt/keycloak $HOST_DIR/env
mkdir -p /var/tmp/redsim-ml /var/tmp/redsim-cache && chown redsim:redsim /var/tmp/redsim-ml /var/tmp/redsim-cache
chown -R redsim:redsim $SRC $HOST_DIR/assets

echo "== systemd units"
for unit in "$NATIVE_DIR"/systemd/*.service; do
  install -m 0644 "$unit" /etc/systemd/system/
done
cat > /etc/caddy/Caddyfile <<EOF
${HOSTNAME_FQDN} {
  encode gzip
  handle /v1/* {
    reverse_proxy 127.0.0.1:8000
  }
  handle /health {
    reverse_proxy 127.0.0.1:8000
  }
  handle /ws/* {
    reverse_proxy 127.0.0.1:8000
  }
  handle /metrics {
    respond 404
  }
  handle /auth/* {
    reverse_proxy 127.0.0.1:8080
  }
  handle {
    reverse_proxy 127.0.0.1:3000
  }
}
EOF
systemctl daemon-reload

echo "== cut over: containers off, native services on"
if command -v docker >/dev/null; then
  (cd $HOST_DIR && docker compose -f $SRC/deploy/ec2/compose.host.yml --project-directory $HOST_DIR down --remove-orphans 2>/dev/null || true)
  docker ps -q | xargs -r docker stop
  systemctl disable --now docker docker.socket 2>/dev/null || true
fi
systemctl enable --now redsim-identity
for _ in $(seq 1 60); do curl -sf -o /dev/null http://127.0.0.1:8080/auth/realms/redsim && break; sleep 5; done
systemctl enable --now redsim-api redsim-scans redsim-default redsim-beat redsim-web
systemctl enable caddy && systemctl restart caddy
for _ in $(seq 1 30); do curl -sf -o /dev/null http://127.0.0.1:8000/health && break; sleep 3; done
systemctl --no-pager --plain list-units 'redsim-*' caddy | head -12
echo "native bootstrap finished"
