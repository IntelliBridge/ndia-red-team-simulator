#!/usr/bin/env bash
#
# Phase B completion gate (docs/plans/12-phase-b-plan.md wave B4, register row
# TESTS_DOCS-36). `make check-phase-b` runs this script.
#
# The gate runs the checks of plan 12 section 6 in order and stops at the first
# failure, printing the spec 26 criterion the failed step is the evidence for
# (docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md, section 26):
#
#   1. ruff             ruff check --select E4,E7,E9,F,I redsim tests          26.27
#   2. mypy             mypy redsim                                            26.27
#   3. unit             pytest -q -p no:cacheprovider --ignore=tests/e2e       26.27
#   4. ml               pytest -q -m ml tests/ml                               26.27
#   5. garak            pytest -q -m garak tests (exit 5 = nothing selected,   26.20
#                       counts as a pass with a notice)
#   6. e2e              REDSIM_E2E=1 pytest -q -m e2e tests/e2e; when          26.2 to 26.24
#                       REDSIM_E2E_POSTGRES_URL is set the Postgres RLS lane
#                       runs inside the same invocation and the step fails if
#                       the harness still reports "Postgres lane is off"
#   7. docs             mkdocs build --strict                                  26.11
#   8. docs-consistency pytest -q tests/test_docs_phase_b_consistency.py       26.11, 26.24
#   9. probes           HTTP probes against a running stack, only when         26.9, 26.17,
#                       REDSIM_API_URL and REDSIM_API_TOKEN are set, then      26.22, 26.24
#                       `redsim audit verify --all` (needs REDSIM_DB_URL)
#
# Every step prints its command. A step that fails ends the run with that
# step's exit code and a line of the form
#   FAIL: step <name> ... -> spec 26 criterion <n>
# so the operator knows which completion criterion is not yet met.
#
# Environment:
#   PY                       interpreter to use (default: $VENV/bin/python, else python3)
#   VENV                     venv directory (default .venv)
#   REDSIM_E2E_POSTGRES_URL  a migrated Postgres for the e2e RLS lane (optional)
#   PHASE_B_PYTEST_ARGS      extra pytest arguments for the e2e step (CI passes
#                            --durations and --basetemp here)
#   REDSIM_API_URL           base URL of a running stack, e.g. http://localhost:8000
#   REDSIM_API_TOKEN         bearer token for that stack (dev mode: dev:<email>,
#                            admin on project "default")
#   REDSIM_API_PROJECT       project id the endpoint probe registers into
#                            (default: the first project GET /v1/projects lists)
#   REDSIM_API_RUN_ID        a run whose report.pdf the PDF probe reads (default:
#                            the newest succeeded run with a rendered PDF)
#   REDSIM_DB_URL            the stack's database, read by `redsim audit verify --all`
#
# The test tiers (steps 3 to 6 and 8) run with REDSIM_DB_URL, the broker
# variables, REDSIM_API_URL, REDSIM_API_TOKEN and every PYTHIA_* variable
# removed from the environment, exactly as the CI lanes run them: the tiers are
# offline by contract and a gateway or database variable left in a developer
# shell must not change what they prove.
#
# Usage:
#   scripts/phase_b_gate.sh              run every step in order
#   scripts/phase_b_gate.sh --list       print the steps and their criteria
#   scripts/phase_b_gate.sh --only NAME  run one step (CI calls --only e2e,
#                                        --only docs-consistency and --only garak)
#
# The HTTP probe program lives between the PHASE_B_PROBES markers below.
# tests/test_docs_phase_b_consistency.py extracts and runs it against a fake
# HTTP layer, so a change to the probe logic is covered by the default tier.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

VENV="${VENV:-.venv}"
if [[ -z "${PY:-}" ]]; then
  if [[ -x "$VENV/bin/python" ]]; then
    PY="$VENV/bin/python"
  else
    PY="python3"
  fi
fi

# Step registry: name | spec 26 criterion | description. Order is the gate order.
STEPS=(
  "ruff|26.27|ruff check --select E4,E7,E9,F,I redsim tests"
  "mypy|26.27|mypy redsim"
  "unit|26.27|pytest -q -p no:cacheprovider --ignore=tests/e2e (default tier)"
  "ml|26.27|pytest -q -p no:cacheprovider -m ml tests/ml"
  "garak|26.20|pytest -q -p no:cacheprovider -m garak tests (exit 5 = nothing selected, passes with a notice)"
  "e2e|26.2 to 26.24|REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e (Postgres RLS lane on when REDSIM_E2E_POSTGRES_URL is set)"
  "docs|26.11|mkdocs build --strict"
  "docs-consistency|26.11, 26.24|pytest -q -p no:cacheprovider tests/test_docs_phase_b_consistency.py"
  "probes|26.9, 26.17, 26.22, 26.24|HTTP probes against REDSIM_API_URL with REDSIM_API_TOKEN, then redsim audit verify --all"
)

# Variables scrubbed from the test-tier environment (see the header).
SCRUB=(
  REDSIM_DB_URL REDSIM_BROKER_URL REDSIM_RESULT_BACKEND
  REDSIM_API_URL REDSIM_API_TOKEN REDSIM_API_PROJECT REDSIM_API_RUN_ID
  PYTHIA_BASE_URL PYTHIA_API_KEY PYTHIA_PERSONA PYTHIA_TIMEOUT_S
  REDSIM_ML_LLM_MODEL AEGIS_ML_LLM_MODEL REDSIM_LLM_MODEL
)

usage() {
  # The comment block at the top of this file, up to the first non-comment line.
  awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
}

list_steps() {
  local i=0 entry name criterion desc
  for entry in "${STEPS[@]}"; do
    i=$((i + 1))
    IFS='|' read -r name criterion desc <<<"$entry"
    printf '%2d. %-17s spec 26 criterion %-20s %s\n' "$i" "$name" "$criterion" "$desc"
  done
}

step_field() {
  # step_field NAME INDEX -> the INDEXth '|' field of the step named NAME
  local entry name
  for entry in "${STEPS[@]}"; do
    name="${entry%%|*}"
    if [[ "$name" == "$1" ]]; then
      echo "$entry" | cut -d'|' -f"$2"
      return 0
    fi
  done
  return 1
}

scrubbed_env() {
  # scrubbed_env CMD... : run CMD with the stack and gateway variables removed
  local args=()
  local var
  for var in "${SCRUB[@]}"; do
    args+=(-u "$var")
  done
  env "${args[@]}" "$@"
}

say() { printf '\n==> %s\n' "$*"; }
show() { printf '    $ %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Steps. Each prints its command and returns the command's exit code.
# ---------------------------------------------------------------------------

step_ruff() {
  show "$PY -m ruff check --select E4,E7,E9,F,I redsim tests"
  "$PY" -m ruff check --select E4,E7,E9,F,I redsim tests
}

step_mypy() {
  show "$PY -m mypy redsim"
  "$PY" -m mypy redsim
}

step_unit() {
  show "$PY -m pytest -q -p no:cacheprovider --ignore=tests/e2e"
  scrubbed_env "$PY" -m pytest -q -p no:cacheprovider --ignore=tests/e2e
}

step_ml() {
  show "$PY -m pytest -q -p no:cacheprovider -m ml tests/ml"
  scrubbed_env "$PY" -m pytest -q -p no:cacheprovider -m ml tests/ml
}

step_garak() {
  local rc
  show "$PY -m pytest -q -p no:cacheprovider -m garak tests"
  scrubbed_env "$PY" -m pytest -q -p no:cacheprovider -m garak tests
  rc=$?
  if [[ $rc -eq 5 ]]; then
    echo "    notice: no garak-marked tests were collected; this step proves only that the marker selects" \
         "cleanly and the extra (when installed) imports, nothing more"
    return 0
  fi
  return $rc
}

step_e2e() {
  local rc log
  # shellcheck disable=SC2206  # PHASE_B_PYTEST_ARGS is a space-separated argument list by contract
  local extra=(${PHASE_B_PYTEST_ARGS:-})
  log="$(mktemp "${TMPDIR:-/tmp}/phase-b-e2e.XXXXXX")"
  # ${extra[@]+"${extra[@]}"} expands to nothing for an empty array under set -u on bash 3.2 (macOS /bin/bash).
  if [[ -n "${REDSIM_E2E_POSTGRES_URL:-}" ]]; then
    echo "    Postgres RLS lane: on (REDSIM_E2E_POSTGRES_URL is set; the database must be migrated)"
    show "REDSIM_E2E=1 REDSIM_E2E_POSTGRES_URL=... $PY -m pytest -q -p no:cacheprovider -rs -m e2e tests/e2e ${extra[*]-}"
    scrubbed_env REDSIM_E2E=1 REDSIM_E2E_POSTGRES_URL="$REDSIM_E2E_POSTGRES_URL" \
      "$PY" -m pytest -q -p no:cacheprovider -rs -m e2e tests/e2e ${extra[@]+"${extra[@]}"} | tee "$log"
    rc=$?
    if [[ $rc -eq 0 ]] && grep -q "Postgres lane is off" "$log"; then
      echo "    the harness skipped its Postgres lane although REDSIM_E2E_POSTGRES_URL is set"
      rc=1
    fi
  else
    echo "    Postgres RLS lane: skipped (set REDSIM_E2E_POSTGRES_URL to a migrated database to run it)"
    show "REDSIM_E2E=1 $PY -m pytest -q -p no:cacheprovider -rs -m e2e tests/e2e ${extra[*]-}"
    scrubbed_env -u REDSIM_E2E_POSTGRES_URL REDSIM_E2E=1 \
      "$PY" -m pytest -q -p no:cacheprovider -rs -m e2e tests/e2e ${extra[@]+"${extra[@]}"} | tee "$log"
    rc=$?
  fi
  rm -f "$log"
  return $rc
}

step_docs() {
  local site
  site="$(mktemp -d "${TMPDIR:-/tmp}/phase-b-site.XXXXXX")"
  show "$PY -m mkdocs build --strict --site-dir $site"
  "$PY" -m mkdocs build --strict --site-dir "$site"
  local rc=$?
  rm -rf "$site"
  return $rc
}

step_docs_consistency() {
  show "$PY -m pytest -q -p no:cacheprovider tests/test_docs_phase_b_consistency.py"
  scrubbed_env "$PY" -m pytest -q -p no:cacheprovider tests/test_docs_phase_b_consistency.py
}

step_probes() {
  if [[ -z "${REDSIM_API_URL:-}" || -z "${REDSIM_API_TOKEN:-}" ]]; then
    echo "    SKIPPED: REDSIM_API_URL and REDSIM_API_TOKEN are not both set; the stack probes did not run" \
         "and this gate run is partial (plan 12 section 6 asks for them against a running stack)"
    PROBES_SKIPPED=1
    return 0
  fi
  show "$PY - (the PHASE_B_PROBES program below) against $REDSIM_API_URL"
  "$PY" - <<'PY'
# --- BEGIN PHASE_B_PROBES ---
"""HTTP probes of the Phase B gate against a running redsim stack (plan 12 section 6).

Read from the environment: ``REDSIM_API_URL``, ``REDSIM_API_TOKEN``, optional
``REDSIM_API_PROJECT`` and ``REDSIM_API_RUN_ID``. Each probe names the spec 26
criterion it is the evidence for; the first failing probe ends the program with
exit code 1 and a ``FAIL`` line naming that criterion. Only the standard
library is used so the program runs from any interpreter that can reach the
stack.

The probes are deliberately narrow and read-only, with one exception: the
endpoint probe posts an invalid ``source: endpoint`` body, which the API
refuses with a ``422`` and records as one ``success=False`` ``model.register``
row on the project chain (spec 9.3 step 2). Nothing else is written.

``run_probes`` is the unit of test: ``tests/test_docs_phase_b_consistency.py``
executes this block with a fake ``http`` callable and asserts that a stack whose
Phase B routes still answer ``501 not_implemented`` fails the gate.
"""

import json
import os
import sys
import urllib.error
import urllib.request

PDF_MAGIC = b"%PDF-"
CAPABILITY_KEYS = ("text", "detection", "llm")
TEXT_ATTACK = "word_substitution"


class ProbeFailure(Exception):
    """One probe did not hold; ``criterion`` is the spec 26 item it is the evidence for."""

    def __init__(self, probe, criterion, message):
        super().__init__(message)
        self.probe = probe
        self.criterion = criterion
        self.message = message

    def __str__(self):
        return f"probe {self.probe}: {self.message} -> spec 26 criterion {self.criterion}"


def default_http(method, url, headers=None, body=None, timeout=60.0):
    """``(status, headers, bytes)`` for one request over urllib; HTTP errors are answers, not exceptions."""
    data = None
    request_headers = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()


class Api:
    """A thin client: base URL, bearer token and an injectable ``http`` callable."""

    def __init__(self, base_url, token, http=default_http):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.http = http

    def call(self, method, path, body=None):
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "*/*"}
        return self.http(method, f"{self.base_url}{path}", headers, body)

    def json(self, method, path, body=None):
        """``(status, parsed_json_or_None, raw_bytes)``."""
        status, _headers, raw = self.call(method, path, body)
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, ValueError):
            parsed = None
        return status, parsed, raw


def _detail(parsed):
    return parsed.get("detail") if isinstance(parsed, dict) else None


def _code(parsed):
    detail = _detail(parsed)
    return detail.get("code") if isinstance(detail, dict) else None


def _refused(probe, criterion, status, parsed, what):
    if status in (401, 403):
        return ProbeFailure(probe, criterion, f"{what} answered {status}: the token is refused or below the "
                                              f"role the route needs ({_detail(parsed)!r})")
    return None


def probe_capabilities(api):
    """26.24: text, detection, llm and the endpoint connector are no longer unsupported paths."""
    status, parsed, raw = api.json("GET", "/v1/ml/capabilities")
    refused = _refused("capabilities", "26.24", status, parsed, "GET /v1/ml/capabilities")
    if refused:
        raise refused
    if status != 200 or not isinstance(parsed, dict):
        raise ProbeFailure("capabilities", "26.24", f"GET /v1/ml/capabilities answered {status}: {raw[:200]!r}")
    modalities = parsed.get("modalities") if isinstance(parsed.get("modalities"), dict) else {}
    missing = []
    for key in CAPABILITY_KEYS:
        entry = modalities.get(key) if isinstance(modalities.get(key), dict) else {}
        if entry.get("status") != "available":
            missing.append(f"modalities.{key}.status={entry.get('status')!r}")
    connector = parsed.get("endpoint_connector") if isinstance(parsed.get("endpoint_connector"), dict) else {}
    if connector.get("status") != "available":
        missing.append(f"endpoint_connector.status={connector.get('status')!r}")
    if missing:
        raise ProbeFailure("capabilities", "26.24",
                           "GET /v1/ml/capabilities does not report every Phase B capability as available: "
                           + ", ".join(missing))
    return "text, detection, llm and endpoint_connector are available"


def probe_text_attacks(api):
    """26.24: the text modality has its attack in the catalog."""
    status, parsed, raw = api.json("GET", "/v1/attacks?modality=text")
    refused = _refused("attacks-text", "26.24", status, parsed, "GET /v1/attacks?modality=text")
    if refused:
        raise refused
    if status != 200 or not isinstance(parsed, dict):
        raise ProbeFailure("attacks-text", "26.24", f"GET /v1/attacks?modality=text answered {status}: {raw[:200]!r}")
    rows = parsed.get("attacks") if isinstance(parsed.get("attacks"), list) else []
    ids = [row.get("id") for row in rows if isinstance(row, dict)]
    if TEXT_ATTACK not in ids:
        raise ProbeFailure("attacks-text", "26.24",
                           f"GET /v1/attacks?modality=text lists {ids!r}, not {TEXT_ATTACK!r}")
    return f"{TEXT_ATTACK} is listed for modality=text ({len(ids)} text attack(s))"


def resolve_project(api, requested=None):
    """The project the endpoint probe registers into: the operator's choice, else the first listed, else 'default'."""
    if requested:
        return requested
    status, parsed, _raw = api.json("GET", "/v1/projects")
    rows = parsed.get("projects") if isinstance(parsed, dict) and isinstance(parsed.get("projects"), list) else []
    for row in rows:
        if isinstance(row, dict) and row.get("id"):
            return str(row["id"])
    return "default"


def probe_endpoint_registration(api, project_id):
    """26.17 and 26.24: ``POST /v1/models`` with ``source: endpoint`` is admitted, not a 501 stub."""
    body = {"source": "endpoint", "project_id": project_id}
    status, parsed, raw = api.json("POST", "/v1/models", body)
    refused = _refused("endpoint-registration", "26.17, 26.24", status, parsed, "POST /v1/models source=endpoint")
    if refused:
        raise refused
    code = _code(parsed)
    if status == 501 or code == "not_implemented":
        raise ProbeFailure("endpoint-registration", "26.17, 26.24",
                           f"POST /v1/models source=endpoint still answers {status} {code!r}: "
                           "the endpoint connector is not admitted on this stack")
    if status != 422:
        raise ProbeFailure("endpoint-registration", "26.17, 26.24",
                           f"POST /v1/models source=endpoint with an invalid body answered {status} {code!r}, "
                           f"expected a 422 refusal: {raw[:200]!r}")
    return f"an invalid endpoint body is refused with 422 {code!r} (never 501)"


def candidate_runs(api, run_id=None, limit=25):
    """Run ids the PDF probe tries: the operator's, else the newest succeeded runs."""
    if run_id:
        return [run_id]
    status, parsed, _raw = api.json("GET", f"/v1/runs?limit={limit}")
    if status != 200 or not isinstance(parsed, dict):
        return []
    rows = parsed.get("runs") if isinstance(parsed.get("runs"), list) else []
    return [str(row["id"]) for row in rows
            if isinstance(row, dict) and row.get("id") and row.get("status") == "succeeded"]


def probe_report_pdf(api, run_id=None):
    """26.9 and 26.24: ``report.pdf`` is a rendered projection of the record, never a 501."""
    runs = candidate_runs(api, run_id)
    if not runs:
        raise ProbeFailure("report-pdf", "26.9, 26.24",
                           "no succeeded run to read report.pdf from (set REDSIM_API_RUN_ID to a run whose PDF "
                           "was rendered, or complete a campaign and POST /v1/runs/{id}/report.render first)")
    seen = []
    for candidate in runs:
        status, headers, raw = api.call("GET", f"/v1/runs/{candidate}/report.pdf")
        if status == 501:
            raise ProbeFailure("report-pdf", "26.9, 26.24",
                               f"GET /v1/runs/{candidate}/report.pdf still answers 501: {raw[:200]!r}")
        if status in (401, 403):
            raise ProbeFailure("report-pdf", "26.9, 26.24",
                               f"GET /v1/runs/{candidate}/report.pdf answered {status}: the token is below "
                               "report.export (scanner) or not a member")
        if status == 200:
            if not raw.startswith(PDF_MAGIC):
                raise ProbeFailure("report-pdf", "26.9, 26.24",
                                   f"GET /v1/runs/{candidate}/report.pdf answered 200 but the body does not start "
                                   f"with {PDF_MAGIC!r}: {raw[:16]!r}")
            return f"run {candidate}: report.pdf is {len(raw)} bytes starting with {PDF_MAGIC!r}"
        seen.append(f"{candidate}: {status}")
    raise ProbeFailure("report-pdf", "26.9, 26.24",
                       "no succeeded run has a rendered report.pdf (" + "; ".join(seen[:5]) + "); render one with "
                       "POST /v1/runs/{id}/report.render or set REDSIM_API_RUN_ID")


def probe_integrations(api):
    """26.24: the Lattice push stays visible as not implemented with its D3 reason."""
    status, parsed, raw = api.json("GET", "/v1/integrations")
    refused = _refused("integrations", "26.24", status, parsed, "GET /v1/integrations")
    if refused:
        raise refused
    if status != 200 or not isinstance(parsed, dict):
        raise ProbeFailure("integrations", "26.24", f"GET /v1/integrations answered {status}: {raw[:200]!r}")
    roster = parsed.get("integrations") if isinstance(parsed.get("integrations"), dict) else {}
    lattice = roster.get("lattice") if isinstance(roster.get("lattice"), dict) else {}
    if lattice.get("status") != "not_implemented" or not lattice.get("reason"):
        raise ProbeFailure("integrations", "26.24",
                           f"GET /v1/integrations must show lattice as not_implemented with a reason, got {lattice!r}")
    return "lattice is not_implemented with a reason; foundry status " + repr(
        (roster.get("foundry") or {}).get("status") if isinstance(roster.get("foundry"), dict) else None)


def run_probes(api, *, project_id=None, run_id=None, out=print):
    """Run every probe in order; return ``(passed, failure)`` where ``failure`` is the first ``ProbeFailure`` or None."""
    passed = []
    plan = [
        ("capabilities", lambda: probe_capabilities(api)),
        ("attacks-text", lambda: probe_text_attacks(api)),
        ("endpoint-registration", lambda: probe_endpoint_registration(api, resolve_project(api, project_id))),
        ("report-pdf", lambda: probe_report_pdf(api, run_id)),
        ("integrations", lambda: probe_integrations(api)),
    ]
    for name, func in plan:
        try:
            detail = func()
        except ProbeFailure as failure:
            out(f"    FAIL  {failure}")
            return passed, failure
        out(f"    ok    {name}: {detail}")
        passed.append(name)
    return passed, None


def main(argv=None, environ=None, http=default_http):
    env = os.environ if environ is None else environ
    base_url = env.get("REDSIM_API_URL", "").strip()
    token = env.get("REDSIM_API_TOKEN", "").strip()
    if not base_url or not token:
        print("REDSIM_API_URL and REDSIM_API_TOKEN must both be set", file=sys.stderr)
        return 2
    api = Api(base_url, token, http=http)
    _passed, failure = run_probes(api, project_id=env.get("REDSIM_API_PROJECT") or None,
                                  run_id=env.get("REDSIM_API_RUN_ID") or None)
    return 1 if failure else 0


if __name__ == "__main__":
    sys.exit(main())
# --- END PHASE_B_PROBES ---
PY
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    return $rc
  fi
  # 26.22: the chain of the running stack verifies. The CLI walks the writer
  # REDSIM_DB_URL selects; without it the CLI would read an empty local JSONL
  # directory and exit 0 without having verified anything about the stack.
  if [[ -z "${REDSIM_DB_URL:-}" ]]; then
    echo "    FAIL  audit-verify: REDSIM_DB_URL is not set, so 'redsim audit verify --all' cannot walk the" \
         "stack's chains (export the stack's database URL) -> spec 26 criterion 26.22"
    return 1
  fi
  show "$PY -m redsim.cli audit verify --all"
  local out
  out="$("$PY" -m redsim.cli audit verify --all 2>&1)"
  rc=$?
  printf '%s\n' "$out" | sed 's/^/    /'
  if [[ $rc -ne 0 ]]; then
    echo "    FAIL  audit-verify: redsim audit verify --all exited $rc -> spec 26 criterion 26.22"
    return $rc
  fi
  if ! printf '%s\n' "$out" | grep -q "events verified"; then
    echo "    FAIL  audit-verify: the CLI verified no chain (no 'events verified' line); a stack that has run" \
         "a campaign carries at least one run chain -> spec 26 criterion 26.22"
    return 1
  fi
  echo "    ok    audit-verify: every chain verified"
  return 0
}

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

ONLY=""
case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  --list) list_steps; exit 0 ;;
  --only)
    ONLY="${2:-}"
    if [[ -z "$ONLY" ]] || ! step_field "$ONLY" 1 >/dev/null; then
      echo "error: --only needs one of: $(for e in "${STEPS[@]}"; do printf '%s ' "${e%%|*}"; done)" >&2
      exit 2
    fi
    ;;
  "") ;;
  *) echo "error: unknown argument '$1' (try --help)" >&2; exit 2 ;;
esac

if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
  echo "error: $PY is not a Python 3.12+ interpreter (set PY or VENV; 'make install' creates .venv)" >&2
  exit 2
fi

PROBES_SKIPPED=0
total=${#STEPS[@]}
index=0
ran=0
started=$(date +%s)
for entry in "${STEPS[@]}"; do
  index=$((index + 1))
  IFS='|' read -r name criterion desc <<<"$entry"
  if [[ -n "$ONLY" && "$name" != "$ONLY" ]]; then
    continue
  fi
  say "[$index/$total] $name (spec 26 criterion $criterion): $desc"
  step_started=$(date +%s)
  "step_${name//-/_}"
  rc=$?
  elapsed=$(( $(date +%s) - step_started ))
  if [[ $rc -ne 0 ]]; then
    printf '\nFAIL: step %s exited %d after %ds -> spec 26 criterion %s is not met (%s)\n' \
      "$name" "$rc" "$elapsed" "$criterion" "$desc"
    exit "$rc"
  fi
  printf '    PASS %s (%ds)\n' "$name" "$elapsed"
  ran=$((ran + 1))
done

total_elapsed=$(( $(date +%s) - started ))
if [[ $PROBES_SKIPPED -eq 1 ]]; then
  printf '\nPASS (partial): %d step(s) in %ds; the stack probes were skipped because REDSIM_API_URL and REDSIM_API_TOKEN are unset\n' \
    "$ran" "$total_elapsed"
else
  printf '\nPASS: %d step(s) in %ds\n' "$ran" "$total_elapsed"
fi
