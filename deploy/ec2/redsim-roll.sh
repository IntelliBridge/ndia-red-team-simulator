#!/usr/bin/env bash
# Roll every redsim container on the EC2 host to the ECR images of one tag
# (a main commit sha or "latest").
#
# Installed as /usr/local/bin/redsim-roll by the bootstrap (deploy/ec2/user-data.sh)
# and refreshed from this file by every deploy-ec2 run before it is invoked, so the
# host always rolls with the script of the commit being deployed.
#
# Steps: pin the tag in docker-compose.yml, re-render the environment from Secrets
# Manager (redsim-render-env), make sure every service layers env/llm.env and that
# the api container also reads env/pythia.env (hosts bootstrapped before 2026-09-09
# evening gave Pythia to the workers only, which left the gateway model picker,
# the LLM capability flags and LLM target registration dark in the UI), refresh the
# ECR login, pull, recreate.
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
# The flag now comes from env/llm.env (rendered per roll); drop a stale copy from common.env.
sed -i '/^REDSIM_DISABLE_LLM=/d' env/common.env

/usr/local/bin/redsim-ecr-login
docker compose pull
docker compose up -d --remove-orphans
docker compose ps
