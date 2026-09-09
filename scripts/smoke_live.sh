#!/usr/bin/env bash
#
# API-level smoke against a live redsim runtime (remaining-work brief E8).
#
# Unauthenticated checks always run: /health is 200, the OIDC discovery
# document names the public issuer, and an API call without a token is 401.
# With a bearer token the authenticated checks run: the caller's projects,
# the model roster, and, when REDSIM_SMOKE_CAMPAIGN=1, one FGSM campaign on
# the first available bundled image model, polled to a terminal state and
# required to succeed with a campaign record. Nothing here is a robustness
# claim; the script proves the deployed path works.
#
# Usage:
#   scripts/smoke_live.sh                       # unauthenticated checks only
#   REDSIM_SMOKE_TOKEN=<jwt> scripts/smoke_live.sh
#   REDSIM_SMOKE_USER=demo-scanner REDSIM_SMOKE_PASSWORD=... scripts/smoke_live.sh
#
# Environment:
#   REDSIM_SMOKE_URL        public origin (default https://redsim.ndia.agiledefense.xyz)
#   REDSIM_SMOKE_TOKEN      bearer token; or
#   REDSIM_SMOKE_USER / REDSIM_SMOKE_PASSWORD  a password grant against the
#                           public direct-grant client REDSIM_SMOKE_CLIENT
#                           (default redsim-cli, created by seed_identity.py)
#   REDSIM_SMOKE_PROJECT    project id for the campaign (default demo)
#   REDSIM_SMOKE_CAMPAIGN   1 to run the campaign (needs scanner or above)
#   REDSIM_SMOKE_TIMEOUT_S  campaign poll budget (default 1200)
#   CURL_CA_BUNDLE          set behind a TLS-inspecting proxy
#
# Requires curl, python3 (JSON handling). Exits non-zero on the first failure.
set -euo pipefail

URL="${REDSIM_SMOKE_URL:-https://redsim.ndia.agiledefense.xyz}"
URL="${URL%/}"
CLIENT="${REDSIM_SMOKE_CLIENT:-redsim-cli}"
PROJECT="${REDSIM_SMOKE_PROJECT:-demo}"
TIMEOUT_S="${REDSIM_SMOKE_TIMEOUT_S:-1200}"
TOKEN="${REDSIM_SMOKE_TOKEN:-}"

pass() { printf '  ok    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; exit 1; }
# jget KEY...: print the value at a key path of the JSON on stdin ("" when absent).
jget() { python3 -c '
import json, sys
d = json.load(sys.stdin)
for key in sys.argv[1:]:
    d = d.get(key) if isinstance(d, dict) else None
print("" if d is None else d)' "$@"; }
# jrows: the list in a list-or-envelope response ("items" / "projects" / "models").
jcount() { python3 -c '
import json, sys
d = json.load(sys.stdin)
rows = d if isinstance(d, list) else (d.get("items") or d.get("projects") or d.get("models") or [])
print(len(rows))'; }
jfirst_image_model() { python3 -c '
import json, sys
d = json.load(sys.stdin)
rows = d if isinstance(d, list) else (d.get("items") or d.get("models") or [])
print(next((r["id"] for r in rows if r.get("modality") == "image" and r.get("status") == "available" and r.get("id")), ""))'; }
code() { curl -sS -o /dev/null -w '%{http_code}' --max-time 30 "$@"; }

echo "redsim live smoke: $URL"

[ "$(code "$URL/health")" = "200" ] && pass "/health 200" || fail "/health is not 200"

issuer="$(curl -sS --max-time 30 "$URL/auth/realms/redsim/.well-known/openid-configuration" | jget issuer)"
[ "$issuer" = "$URL/auth/realms/redsim" ] && pass "OIDC discovery issuer $issuer" || fail "OIDC issuer is '$issuer'"

[ "$(code "$URL/v1/projects")" = "401" ] && pass "unauthenticated /v1/projects 401" || fail "unauthenticated /v1/projects is not 401"

if [ -z "$TOKEN" ] && [ -n "${REDSIM_SMOKE_USER:-}" ]; then
  [ -n "${REDSIM_SMOKE_PASSWORD:-}" ] || fail "REDSIM_SMOKE_PASSWORD is required with REDSIM_SMOKE_USER"
  TOKEN="$(curl -sS --max-time 30 -X POST "$URL/auth/realms/redsim/protocol/openid-connect/token" \
    --data-urlencode "grant_type=password" --data-urlencode "client_id=$CLIENT" \
    --data-urlencode "username=$REDSIM_SMOKE_USER" --data-urlencode "password=$REDSIM_SMOKE_PASSWORD" \
    | jget access_token)"
  [ -n "$TOKEN" ] && pass "password grant for $REDSIM_SMOKE_USER on client $CLIENT" || fail "no access token from the password grant"
fi

if [ -z "$TOKEN" ]; then
  echo "no token: authenticated checks skipped (set REDSIM_SMOKE_TOKEN or REDSIM_SMOKE_USER/PASSWORD)"
  exit 0
fi
auth=(-H "Authorization: Bearer $TOKEN")

projects="$(curl -sS --max-time 30 "${auth[@]}" "$URL/v1/projects")"
count="$(printf '%s' "$projects" | jcount)"
[ "$count" -ge 1 ] && pass "/v1/projects lists $count project(s)" || fail "/v1/projects lists no project for this token"

models="$(curl -sS --max-time 30 "${auth[@]}" "$URL/v1/models?project=$PROJECT")"
model_id="$(printf '%s' "$models" | jfirst_image_model)"
pass "/v1/models?project=$PROJECT answered (first available image model: ${model_id:-none})"

caps="$(code "${auth[@]}" "$URL/v1/ml/capabilities")"
[ "$caps" = "200" ] && pass "/v1/ml/capabilities 200" || fail "/v1/ml/capabilities is $caps"

if [ "${REDSIM_SMOKE_CAMPAIGN:-0}" != "1" ]; then
  echo "REDSIM_SMOKE_CAMPAIGN is not 1: campaign skipped"
  exit 0
fi
[ -n "$model_id" ] || fail "no available image model in project $PROJECT to attack"

handle="$(curl -sS --max-time 60 "${auth[@]}" -H 'Content-Type: application/json' \
  -X POST "$URL/v1/models/$model_id/attacks?project=$PROJECT" \
  -d '{"attack_ids": ["fgsm"], "n_samples": 64, "seed": 0, "explain_k": 4}')"
run_id="$(printf '%s' "$handle" | jget run_id)"
[ -n "$run_id" ] && pass "campaign admitted: run $run_id" || fail "campaign refused: $handle"

deadline=$((SECONDS + TIMEOUT_S))
status="queued"
while [ "$SECONDS" -lt "$deadline" ]; do
  status="$(curl -sS --max-time 30 "${auth[@]}" "$URL/v1/runs/$run_id" | jget status)"
  case "$status" in
    succeeded|failed|cancelled|partial) break ;;
  esac
  sleep 15
done
[ "$status" = "succeeded" ] && pass "run $run_id $status" || fail "run $run_id ended as '$status' (budget ${TIMEOUT_S}s)"

record="$(curl -sS --max-time 60 "${auth[@]}" "$URL/v1/runs/$run_id/campaign")"
score_status="$(printf '%s' "$record" | jget score_status)"
pass "campaign record read (score_status: ${score_status:-unreported})"
[ "$(code "${auth[@]}" "$URL/v1/runs/$run_id/report.md")" = "200" ] && pass "report.md 200" || fail "report.md is not 200"
echo "smoke passed"
