#!/usr/bin/env bash
# Scripted walkthrough of the spec section 24 demo, without the web UI.
#
# Runs against a compose stack that `make up` already started
# (deploy/docker-compose.yml, redsim-api on http://localhost:8000 with
# REDSIM_AUTH_MODE=dev). Steps, printing every id:
#
#   1. `redsim ml seed --project default` inside the redsim-api container
#      registers the bundled, non-fixture models (audit-first, one commit per
#      model, "already present" on a rerun).
#   2. GET /v1/models, pick the first registered, available image model.
#   3. POST /v1/models/{id}/attacks with fgsm and pgd, 64 samples, seed 0.
#   4. Poll GET /v1/runs/{id} to a terminal status.
#   5. GET /v1/findings?project=default, read the first finding.
#   6. GET /v1/runs/{id}/report.md for the campaign run, save it to a file.
#   7. `redsim audit verify --all` inside the redsim-api container.
#
# Every run is a measurement in its own right. The script applies no defense
# and runs no verify campaign (product owner decision of 2026-09-09).
#
# Environment:
#   REDSIM_DEMO_API        API base URL (default http://localhost:8000)
#   REDSIM_DEMO_TOKEN      bearer token (default dev:admin@example.com, the
#                          dev-mode token that is admin on project `default`)
#   REDSIM_DEMO_PROJECT    project id (default `default`)
#   REDSIM_DEMO_OUT        directory for the report (default ./redsim_output/demo)
#   REDSIM_DEMO_TIMEOUT_S  seconds to wait per run (default 1800)
#   REDSIM_DEMO_COMPOSE    compose file (default deploy/docker-compose.yml)
#
# Needs bash, curl, python3 (JSON parsing, no jq) and docker compose.
# Numbers printed by the report are from the run in hand and are illustrative.
# No readiness or certification reading is made here or anywhere else.
#
# STATUS 2026-09-09: written for package C item C9 of
# docs/plans/10-remaining-work-brief.md and checked with `bash -n` only. It
# has NOT been run against a live stack yet. Run it against `make up` and
# record the result in that brief before quoting it as evidence.

set -euo pipefail

API="${REDSIM_DEMO_API:-http://localhost:8000}"
TOKEN="${REDSIM_DEMO_TOKEN:-dev:admin@example.com}"
PROJECT="${REDSIM_DEMO_PROJECT:-default}"
OUT_DIR="${REDSIM_DEMO_OUT:-./redsim_output/demo}"
TIMEOUT_S="${REDSIM_DEMO_TIMEOUT_S:-1800}"
COMPOSE_FILE="${REDSIM_DEMO_COMPOSE:-deploy/docker-compose.yml}"
POLL_S=10

say() { printf '\n== %s\n' "$*"; }
die() { printf 'demo: %s\n' "$*" >&2; exit 1; }

for tool in curl python3 docker; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

# JSON helpers. python3 reads the document on stdin and walks a key path
# given on argv (dict keys, or a decimal index into a list). No eval, no jq.
json_get() {
    # json_get KEY [KEY ...] <<< "$json"   -> the value, "" when absent
    python3 - "$@" <<'PY'
import json, sys
v = json.load(sys.stdin)
for key in sys.argv[1:]:
    if isinstance(v, list) and key.isdigit():
        v = v[int(key)] if int(key) < len(v) else None
    elif isinstance(v, dict):
        v = v.get(key)
    else:
        v = None
    if v is None:
        break
if v is None:
    print("")
elif isinstance(v, (dict, list)):
    print(json.dumps(v))
else:
    print(v)
PY
}

pick_image_model() {
    # pick_image_model <<< "$models"  -> id of the first registered, available image model
    python3 - <<'PY'
import json, sys
d = json.load(sys.stdin)
for m in d.get("models", []):
    if m.get("registered") and m.get("modality") == "image" and m.get("status") == "available":
        print(m["id"])
        break
PY
}

api() {
    # api METHOD PATH [JSON_BODY]  -> body on stdout, status in $HTTP_STATUS
    local method="$1" path="$2" body="${3:-}"
    local tmp
    tmp="$(mktemp)"
    if [ -n "$body" ]; then
        HTTP_STATUS="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" \
            -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
            --data "$body" "$API$path")"
    else
        HTTP_STATUS="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" \
            -H "Authorization: Bearer $TOKEN" "$API$path")"
    fi
    cat "$tmp"
    rm -f "$tmp"
}

expect_status() {
    # expect_status <want> <what> <body>
    case "$HTTP_STATUS" in
        "$1") ;;
        *) printf '%s\n' "$3" >&2; die "$2 answered HTTP $HTTP_STATUS, wanted $1" ;;
    esac
}

wait_terminal() {
    # wait_terminal <run_id>  -> prints the final status
    local run_id="$1" waited=0 status=""
    while :; do
        local body
        body="$(api GET "/v1/runs/$run_id")"
        expect_status 200 "GET /v1/runs/$run_id" "$body"
        status="$(json_get status <<< "$body")"
        case "$status" in
            succeeded|failed|cancelled) printf '%s\n' "$status"; return 0 ;;
        esac
        if [ "$waited" -ge "$TIMEOUT_S" ]; then
            die "run $run_id still '$status' after ${TIMEOUT_S}s"
        fi
        printf '   run %s: %s (%ss)\n' "$run_id" "${status:-unknown}" "$waited" >&2
        sleep "$POLL_S"
        waited=$((waited + POLL_S))
    done
}

compose_exec() {
    docker compose -f "$COMPOSE_FILE" exec -T redsim-api "$@"
}

mkdir -p "$OUT_DIR"

say "0. API health at $API"
health="$(api GET /health)"
expect_status 200 "GET /health" "$health"
printf '%s\n' "$health"

say "1. Seed the bundled models into project '$PROJECT' (redsim ml seed)"
compose_exec redsim ml seed --project "$PROJECT"

say "2. List models and pick the first registered, available image model"
models="$(api GET "/v1/models?project=$PROJECT")"
expect_status 200 "GET /v1/models" "$models"
MODEL_ID="$(pick_image_model <<< "$models")"
[ -n "$MODEL_ID" ] || { printf '%s\n' "$models" >&2; die "no registered, available image model in project '$PROJECT'"; }
printf 'model_id=%s\n' "$MODEL_ID"

say "3. Start the image campaign (fgsm, pgd, n_samples 64, seed 0)"
campaign_body='{"attack_ids":["fgsm","pgd"],"n_samples":64,"seed":0}'
handle="$(api POST "/v1/models/$MODEL_ID/attacks?project=$PROJECT" "$campaign_body")"
expect_status 202 "POST /v1/models/$MODEL_ID/attacks" "$handle"
RUN_ID="$(json_get run_id <<< "$handle")"
[ -n "$RUN_ID" ] || die "campaign handle carried no run_id: $handle"
printf 'run_id=%s\n' "$RUN_ID"
printf 'job_ids=%s\n' "$(json_get job_ids <<< "$handle")"

say "4. Wait for the campaign run"
RUN_STATUS="$(wait_terminal "$RUN_ID")"
printf 'run_id=%s status=%s\n' "$RUN_ID" "$RUN_STATUS"
[ "$RUN_STATUS" = "succeeded" ] || die "campaign run $RUN_ID ended '$RUN_STATUS'"

say "5. List findings and read the first one from this run"
findings="$(api GET "/v1/findings?project=$PROJECT&run=$RUN_ID")"
expect_status 200 "GET /v1/findings" "$findings"
FINDING_COUNT="$(json_get count <<< "$findings")"
printf 'finding_count=%s\n' "$FINDING_COUNT"
FINDING_ID="$(json_get findings 0 id <<< "$findings")"
if [ -z "$FINDING_ID" ]; then
    printf 'No finding crossed the threshold on this run. That is a valid result, not an error.\n'
else
    finding="$(api GET "/v1/findings/$FINDING_ID")"
    expect_status 200 "GET /v1/findings/$FINDING_ID" "$finding"
    printf 'finding_id=%s status=%s severity=%s\n' "$FINDING_ID" \
        "$(json_get status <<< "$finding")" "$(json_get severity <<< "$finding")"
fi

say "6. Download the campaign report (Markdown)"
REPORT_PATH="$OUT_DIR/$RUN_ID-report.md"
HTTP_STATUS="$(curl -sS -o "$REPORT_PATH" -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" "$API/v1/runs/$RUN_ID/report.md")"
expect_status 200 "GET /v1/runs/$RUN_ID/report.md" "$(head -c 400 "$REPORT_PATH")"
printf 'report_path=%s\n' "$REPORT_PATH"

say "7. Verify every audit chain (redsim audit verify --all)"
compose_exec redsim audit verify --all

say "Done"
printf 'model_id=%s\nrun_id=%s\n' "$MODEL_ID" "$RUN_ID"
if [ -n "${FINDING_ID:-}" ]; then
    printf 'finding_id=%s\n' "$FINDING_ID"
fi
printf 'report_path=%s\n' "$REPORT_PATH"
