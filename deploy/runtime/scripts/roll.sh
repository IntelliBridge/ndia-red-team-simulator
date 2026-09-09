#!/usr/bin/env bash
#
# Roll the live Fargate runtime to the images of one commit on main.
#
# One command per release, in short steps that each return on their own:
#   1. read the four ECR digests tagged with the commit and pin them in the
#      inputs file (JSON, kept outside the repository),
#   2. terraform apply the runtime root,
#   3. run the migration task (idempotent) and wait for it,
#   4. wait for the identity (Keycloak) rollout and the realm to answer,
#   5. force a new web deployment, because the web image discovers the
#      Keycloak issuer once at boot and a web task that started while
#      Keycloak was restarting has no sign-in provider,
#   6. print the rollout state of every service.
#
# Usage:
#   deploy/runtime/scripts/roll.sh <commit-sha> <inputs.tfvars.json> [terraform-binary]
#
# Environment: AWS_PROFILE (and AWS_CA_BUNDLE behind a proxy), TF_DATA_DIR
# outside the repository, PYTHON pointing at an interpreter with boto3
# (default: the repository venv, then python3). The `Deploy to AWS` workflow must have pushed the
# images of <commit-sha> first (about three minutes after the merge).
set -euo pipefail

SHA="${1:?commit sha}"
INPUTS="${2:?inputs tfvars json}"
TF="${3:-terraform}"
REGION="${AWS_REGION:-us-east-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/../../.venv/bin/python}"
[ -x "$PYTHON" ] || PYTHON=python3
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/ndia-red-team"
FULL="$(git rev-parse "$SHA")"

echo "== 1. pin images of ${FULL:0:7}"
python3 - "$INPUTS" "$FULL" "$REGISTRY" <<'EOF'
import json, subprocess, sys
inputs, full, registry = sys.argv[1:4]
v = json.load(open(inputs))
for fam in ("api", "worker", "web", "identity"):
    digest = subprocess.check_output([
        "aws", "ecr", "describe-images", "--repository-name", f"ndia-red-team/{fam}",
        "--image-ids", f"imageTag={full}", "--query", "imageDetails[0].imageDigest", "--output", "text",
    ]).decode().strip()
    if not digest.startswith("sha256:"):
        raise SystemExit(f"no {fam} image tagged {full}: has Deploy to AWS finished?")
    v["images"][fam] = f"{registry}/{fam}@{digest}"
    print(f"   {fam} {digest[:19]}")
json.dump(v, open(inputs, "w"), indent=2)
EOF

echo "== 2. terraform apply"
"$TF" -chdir="$ROOT" apply -auto-approve -var-file="$INPUTS" -no-color | grep -E "Plan:|Apply complete|Error" || true
OUT="$(mktemp -t redsim-runtime-outputs)"
"$TF" -chdir="$ROOT" output -json > "$OUT"

echo "== 3. migration task"
"$PYTHON" "$ROOT/scripts/run_task.py" --runtime-outputs "$OUT" --task migration | tail -1

CLUSTER="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["runtime"]["value"]["cluster_arn"])' "$OUT")"
URL="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["runtime"]["value"]["url"])' "$OUT")"
NAME="$(basename "$CLUSTER")"

echo "== 4. wait for identity"
for _ in $(seq 1 40); do
  state="$(aws ecs describe-services --cluster "$CLUSTER" --services "${NAME}-identity" \
    --query 'services[0].deployments[0].rolloutState' --output text)"
  realm="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$URL/auth/realms/redsim" || true)"
  [ "$state" = "COMPLETED" ] && [ "$realm" = "200" ] && break
  sleep 15
done
echo "   identity rollout=$state realm=$realm"
[ "$realm" = "200" ] || { echo "Keycloak is not answering; stop here and inspect /redsim/*/identity" >&2; exit 1; }

echo "== 5. redeploy web after Keycloak is up"
aws ecs update-service --cluster "$CLUSTER" --service "${NAME}-web" --force-new-deployment \
  --query 'service.deployments[0].rolloutState' --output text

echo "== 6. rollouts (web finishes in two to four minutes)"
aws ecs describe-services --cluster "$CLUSTER" \
  --services "${NAME}-api" "${NAME}-web" "${NAME}-identity" "${NAME}-scans" "${NAME}-default" "${NAME}-beat" \
  --query 'services[].[serviceName,runningCount,deployments[0].rolloutState]' --output text | sed "s#${NAME}-##"
rm -f "$OUT"
