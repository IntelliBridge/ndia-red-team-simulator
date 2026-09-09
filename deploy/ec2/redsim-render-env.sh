#!/usr/bin/env bash
# Render the redsim host environment from Secrets Manager.
#
# Installed on the EC2 host as /usr/local/bin/redsim-render-env by the bootstrap
# (deploy/ec2/user-data.sh) and refreshed from this file by every deploy-ec2 run,
# then called by redsim-roll before the containers are recreated. Adding or
# rotating a secret therefore takes effect on the next merge to main, not the
# next host launch.
#
# Writes, under /opt/redsim/env (mode 0600, never logged):
#   {api,scans,default,beat,web,identity}.secret.env   one per service secret
#   pythia.env   PYTHIA_API_KEY, PYTHIA_BASE_URL, PYTHIA_PERSONA, REDSIM_ML_LLM_MODEL
#                from ndia-red-team/demo/pythia when that secret exists, else empty
#   llm.env      REDSIM_DISABLE_LLM (0 when the Pythia secret exists, else 1) and
#                REDSIM_TARGET_ALLOWLIST (the loopback/docker hosts plus the Pythia
#                gateway host, so an LLM target registration passes the egress check)
#
# The api container needs pythia.env and llm.env as much as the workers do: the
# gateway model picker (GET /v1/llm/models), the LLM capability flags and the
# default gateway_url of POST /v1/models {endpoint_kind: llm} all read them.
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
cat > "${ENV_DIR}/llm.env" <<EOF
REDSIM_DISABLE_LLM=${DISABLE_LLM}
REDSIM_TARGET_ALLOWLIST=${ALLOWLIST}
EOF
chmod 0600 "${ENV_DIR}/llm.env"
echo "redsim-render-env: llm_disabled=${DISABLE_LLM} pythia_host=${PYTHIA_HOST:-none} allowlist=${ALLOWLIST}"
