# Observability

Aegis emits three telemetry streams — **logs**, **traces**, and
**metrics** — and ships them through one OpenTelemetry Collector. The
log path additionally has an always-on Postgres mirror so
`SELECT * FROM application_logs WHERE run_id = '…'` works even when
Loki / Elasticsearch aren't up.

```mermaid
flowchart LR
  subgraph apps["Aegis processes"]
    api["aegis-api"]
    worker["aegis-worker"]
    web["@aegis/web"]
    scan["scanner subprocesses"]
  end

  subgraph p_default["default compose profile"]
    li["aegis-log-ingest"]
    pg[("Postgres<br/>application_logs")]
    li --> pg
  end

  subgraph obs["+ profile: obs"]
    col["otel-collector"]
    loki[("Loki")]
    jaeger["Jaeger"]
    col -. "logs" .-> loki
    col -. "logs" .-> li
    col -. "traces" .-> jaeger
  end

  subgraph search["+ profile: obs-search"]
    es[("Elasticsearch")]
    kibana["Kibana"]
    col2["otel-collector"]
    col2 -. "logs" .-> es
    kibana --- es
  end

  apps -. "OTLP logs + traces" .-> col
  apps -. "POST /ingest" .-> li
  worker -. "tail stderr" .-> apps
  scan -. "stderr" .-> worker
```

The default profile gives you in-app queries with zero ops overhead;
adding `obs` brings ad-hoc query (Loki) + traces (Jaeger) without
adding a new datastore. `obs-search` is for full-text search workloads
where Loki's label model isn't enough.

---

## Logs

Every log line carries a structlog payload that's auto-enriched with:

- `request_id` — propagated via the `X-Aegis-Request-ID` header
  (request_id_middleware). Set on the API; forwarded by the worker
  via the Job's detail row.
- `trace_id` / `span_id` — from the active OTel span when one is
  active.
- `severity`, `service`, plus whatever structured kwargs the caller
  passed.

The structlog processor that does the enrichment lives in
`aegis.observability._inject_correlation_ids`. The OTel handler that
ships the events to the Collector is wired by
`_configure_otel_logs(service_name)` and only activates when
`OTEL_EXPORTER_OTLP_ENDPOINT` is set — so the Phase 2 offline path
continues to log to stdout.

```mermaid
sequenceDiagram
    autonumber
    participant code as logger.info call
    participant SL as structlog
    participant OTEL as OTel Logs SDK
    participant COL as otel-collector
    participant LI as aegis-log-ingest
    participant PG as Postgres

    code->>SL: event_dict
    SL->>SL: _inject_correlation_ids<br/>request_id, trace_id, span_id
    SL->>OTEL: LoggingHandler.emit
    OTEL->>COL: OTLP logs batched
    COL->>LI: otlphttp aegis-ingest<br/>POST /v1/logs
    LI->>LI: parse OTLP envelope<br/>buffer 500 per 2s
    LI->>PG: INSERT application_logs
```

### `application_logs` table

Indexed for the queries that actually happen:

| Index                     | Query it supports                          |
|---------------------------|--------------------------------------------|
| `ix_logs_run_ts`          | per-run timeline (newest first)            |
| `ix_logs_project_ts`      | per-project tail                           |
| `ix_logs_request`         | correlate API + worker + scanner by request_id |
| `ix_logs_trace`           | correlate with a Jaeger trace              |
| `ix_logs_severity_ts`     | filter (e.g. severity=error) + newest first |
| `ix_logs_service`         | service name filter                        |
| `ix_logs_ts`              | global timeline                            |

Schema lives in `aegis/db/models.py::ApplicationLog`; the Alembic
migration that creates it is `0003_application_logs`.

### Ingress paths

```mermaid
flowchart LR
  apiA["aegis-api"] -- "default: POST /ingest" --> LI["aegis-log-ingest"]
  workerA["aegis-worker"] -- "default: POST /ingest" --> LI

  apiB["aegis-api"] -- "obs profile: OTLP logs" --> COL["otel-collector"]
  workerB["aegis-worker"] -- "obs profile: OTLP logs" --> COL
  COL -- "otlphttp/aegis-ingest" --> LI

  LI --> pg[("application_logs")]
```

Two paths converge on the same `LogIngestWriter`:

- `POST /ingest` — JSON batch (`{ "records": [...] }`). Used by the
  default profile when no Collector is up. Easy to hand-test.
- `POST /v1/logs` — OTLP/Logs over HTTP-JSON. What the Collector's
  `otlphttp/aegis-ingest` exporter posts. The receiver decodes the
  `resourceLogs → scopeLogs → logRecords` envelope without pulling in
  the protobuf SDK.

The writer batches `~500 records / 2s` and exposes counters via
`/metrics` (`aegis_log_ingest_buffered`, `…_inserted_total`,
`…_last_flush_ms`).

### Querying logs

| Where      | How                                                                 |
|------------|---------------------------------------------------------------------|
| In-app     | `GET /v1/logs?run=…&severity=…&since=…` (admin); web `/logs` page    |
| Postgres   | `SELECT … FROM application_logs WHERE …`                            |
| Loki       | `{service="aegis-api"} \| json` (under `obs`)                       |
| Kibana     | Discover, index pattern `aegis-*` (under `obs-search`)              |

Every `/v1/logs` query emits a `logs.queried` audit event so a
forensic review can answer "who looked at what" — see
[`audit-chain.md`](audit-chain.md).

---

## Traces

The Collector receives OTLP/Traces from the API + worker and exports
to Jaeger (`obs` profile). Spans carry the same `request_id` as the
log stream, so a slow API call ⇒ Jaeger trace ⇒ Postgres log query
chains together by a single id.

Wired in `aegis.observability.configure_otel`:

```python
configure_otel(service_name="aegis-api")
```

— invoked from API + worker bootstrap. No-op when
`OTEL_EXPORTER_OTLP_ENDPOINT` is unset.

---

## Metrics

Prometheus exposition format on `/metrics`. The current counters /
gauges (defined in `aegis.observability._make_counters`):

| Metric                      | Type    | Labels         | Owner                  |
|-----------------------------|---------|----------------|------------------------|
| `aegis_scans_total`         | Counter | `status`       | admission              |
| `aegis_fix_success_total`   | Counter | —              | execution              |
| `aegis_verify_status_total` | Counter | `status`       | execution              |
| `aegis_jobs_active`         | Gauge   | —              | bootstrap              |
| `aegis_rate_limited_total`  | Counter | —              | rate-limit middleware  |
| `aegis_log_ingest_buffered` | Gauge   | —              | log-ingest             |
| `aegis_log_ingest_inserted_total` | Counter | —          | log-ingest             |
| `aegis_log_ingest_last_flush_ms`  | Gauge   | —           | log-ingest             |

When `prometheus_client` isn't installed (Phase 2 offline path),
`/metrics` returns `{"detail": "prometheus_client not installed"}`
so a curl probe doesn't crash.

---

## Run events & worker queues

Beyond the three telemetry streams, the worker emits a **live
job-lifecycle event stream** the dashboard consumes, and runs its tasks
across two Celery queues so a 30-minute scan can't block a CI gate.

### Live run events (Redis pub/sub → WebSocket)

```mermaid
sequenceDiagram
    autonumber
    participant W as aegis-worker
    participant DB as Postgres
    participant R as Redis pub/sub
    participant API as aegis-api (WS)
    participant Web as @aegis/web

    Note over W: task_context runs the job body
    W->>R: publish run:{run_id}:events<br/>{type:job, status:"running"}
    W->>DB: UPDATE jobs … (succeeded / failed)
    Note over W,DB: terminal event published AFTER the commit
    W->>R: publish {type:job, status:"succeeded"|"failed"}
    Web->>API: WS GET /v1/runs/{run_id}/events
    API->>R: SUBSCRIBE run:{run_id}:events
    R-->>API: event frames
    API-->>Web: send_json(event)
    Note over Web: useRunEvents → mutate(); SWR poll is the fallback
```

The worker publishes a job-transition frame
(`running` / `succeeded` / `failed`) to the Redis channel
`run:{run_id}:events` via `publish_job_event` in
`aegis/workers/events.py`. The WebSocket endpoint
`GET /v1/runs/{run_id}/events` (`aegis/api/ws.py`) subscribes to that
channel and streams each frame to the frontend; the web `useRunEvents`
hook (`web/src/hooks/useRunEvents.ts`) consumes them live and revalidates
its SWR data, with the existing SWR poll as the fallback when the socket
is down. Heartbeat frames (emitted when no broker is configured) are
ignored.

Two load-bearing details:

- **Publishing is best-effort.** A broker hiccup must never fail or retry
  the job that triggered the event — Postgres stays the source of truth
  for status; the event stream is a real-time convenience on top of it.
  Every publish failure is swallowed and logged.
- **Terminal events are published after the DB commit.** The worker's
  `task_context` (`aegis/workers/bootstrap.py`) emits the `succeeded` /
  `failed` frame only once `get_session()` has committed the status row,
  so a consumer reacting to the event always sees a durable row.

### Celery queue routing

`aegis/workers/celery_app.py` routes tasks across two queues so the
worker pools don't contend:

| Queue | Tasks | Why |
|-------|-------|-----|
| `scans` | `scan_start`, `fix_generate`, `verify_replay`, `agent_run` | Long offensive / remediation work (minutes). |
| `default` | `ci_gate`, `report_render`, `vulnfixer_render`, `parallel_fix`, `reap_stale_jobs` | Fast bookkeeping — kept off the `scans` pool so a long scan can't starve it. (`parallel_fix` blocks on its `fix_generate` children, so the waiter stays off the pool it waits on.) |

[`deploy/docker-compose.yml`](https://github.com/IntelliBridge/aegis/blob/main/deploy/docker-compose.yml)
runs **a dedicated worker pool per queue** — `aegis-worker`
(`-Q scans`) and `aegis-worker-default` (`-Q default`) — plus a separate
**`aegis-beat`** scheduler service (`celery … beat`). The beat process is
what actually fires `app.conf.beat_schedule`, i.e. the stale-job reaper
every 5 minutes; previously the schedule was defined but no beat process
ran, so it never fired.

### Durable status on failure

A crashed or failed task must leave a **durable** terminal row, but
`get_session()` rolls back its session on exception — a naive
`job.status = "failed"` written on that session would be discarded. So
`task_context` rolls back first (releasing the job-row lock), then
re-loads the `Job` and writes `status="failed"` + the error on a *fresh*
commit so it survives. The periodic `reap_stale_jobs` reaper is the
backstop: a task that dies hard (process killed, never reaching the
`except`) is left `status="running"` forever, so the reaper sweeps rows
past their TTL to `failed`.

---

## Correlation: a worked example

A user hits `POST /v1/scans`. The full chain of ids that lets you
follow that one call across services:

```mermaid
sequenceDiagram
    autonumber
    participant U as Caller
    participant API as aegis-api
    participant DB as Postgres
    participant W as aegis-worker
    participant T as Jaeger

    U->>API: POST /v1/scans<br/>X-Aegis-Request-ID req-abc
    Note over API: middleware sets ContextVar<br/>OTel span trace_id t1
    API->>DB: INSERT audit_events<br/>action scan.start<br/>request_id req-abc
    API->>DB: INSERT application_logs<br/>request_id req-abc trace_id t1
    API-->>U: run_id, job_id

    W->>DB: SELECT FROM jobs<br/>request_id req-abc lifted
    Note over W: bootstrap sets the same ContextVar
    W->>DB: INSERT audit_events<br/>action scan.execute.strix<br/>request_id req-abc
    W->>DB: INSERT application_logs<br/>request_id req-abc trace_id t2
    W->>T: emit traces for both spans
```

Operationally: drop `request_id=req-abc` into the Logs page and you
get the API row, the worker row, and the scanner stderr tail
chronologically. Drop `trace_id=t1` into Jaeger and you get the
upstream-vs-downstream span timing. Drop the same into
`application_logs.trace_id` and the same time-ordered log slice
appears in Postgres.

---

## Configuration reference

Env vars, all read by `aegis.observability` + `aegis.log_ingest`:

| Env var                                  | What it does                                                   |
|------------------------------------------|----------------------------------------------------------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT`            | Activates the OTel SDK. Without it, logs go to stdout only.    |
| `OTEL_RESOURCE_ATTRIBUTES`               | Free-form `key=value,key=value` for the OTel Resource.         |
| `AEGIS_LOG_INGEST_URL`                   | Direct-mode endpoint (default `http://aegis-log-ingest:4319`). |
| `AEGIS_LOG_INGEST_BATCH_SIZE`            | Writer batch size (default `500`).                             |
| `AEGIS_LOG_INGEST_FLUSH_SECONDS`         | Writer flush interval (default `2`).                           |

Collector config lives in `deploy/otel/config.yaml`; pipelines:

- `logs/loki` → Loki
- `logs/aegis-ingest` → aegis-log-ingest (always)
- `traces` → Jaeger
- `logs/security` → aegis-log-ingest + Loki (host/OS audit sources)

The first three carry the application's own OTLP signal. `logs/security`
is a separate ingestion path for **host/OS audit telemetry** —
`filelog` (`/var/log/auth.log`, `/var/log/secure`), `journald`
(sshd/sudo/kernel), `rfc5424` syslog over tcp, and the `k8sobjects`
event watcher. Its records pass through **two** redaction stages before
any batching or export: a `redaction` processor that masks secret-like
attribute **values**, followed by a `transform/redact_body` processor
that scrubs the same secret patterns (passwords, api keys, tokens,
bearer/auth headers, AWS keys) from the raw log **body** — where host
log lines actually land. Then a `filter` stage drops debug/health-probe
noise and sub-`INFO` records. Both redaction stages run ahead of the
exporters, so scrubbed values never reach Postgres or Loki. The `osquery` receiver and `isolationforest` anomaly processor are
left commented — they are not standard collector-contrib components and
would fail Collector startup unless your distro ships them.

The Elasticsearch exporter in the Collector config is commented; un-
comment when `obs-search` is permanently in your deployment shape.

---

## Operational concerns

- **Ingest lag**: watch `aegis_log_ingest_buffered`. Steady-state
  should be under one batch; persistent growth ⇒ Postgres write
  contention or a flooding producer.
- **Postgres retention**: not enforced by the platform — wire up
  `pg_cron` or `pg_partman` if you need it. Loki defaults to 7 days
  retention via `deploy/loki/config.yaml`.
- **Backpressure**: the writer is fire-and-forget by design (the
  producer doesn't block on Postgres). If `application_logs` is
  unreachable, rows stay buffered up to the batch size, then drop —
  the metric counter exposes the drop rate.
- **Sensitive data**: Aegis already runs `redact_audit_detail` on
  audit detail before write. The application OTLP log path
  (`logs/loki`, `logs/aegis-ingest`) does **not** auto-redact — treat
  `attrs` like any other JSON field and avoid logging tokens. The
  `logs/security` host-audit pipeline is the exception: a `redaction`
  processor masks secret-like attribute values and a
  `transform/redact_body` processor scrubs secrets from the raw log body
  before export, since host log lines (e.g. a password or token captured
  in `/var/log/auth.log`) are outside the app's control.

For the production deployment runbook (Dockerfile, image build,
service registration) see [`docs/ops/deploy.md`](../ops/deploy.md).
