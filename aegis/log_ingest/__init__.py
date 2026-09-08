"""aegis-log-ingest — in-tree service that mirrors the OTel log stream
into the ``application_logs`` Postgres table.

Two ingress paths:

- **HTTP** (always-on): ``POST /ingest`` with a JSON batch payload.
  Used by the default compose profile when no Collector is up — API
  and worker post directly. Easy to test, easy to debug.
- **gRPC OTLP/Logs** (under the ``obs`` compose profile): the Collector
  exporter writes OTLP/Logs records here, alongside its Loki / ES
  fan-out.

Both paths converge on the same writer (`writer.insert_batch`).
"""

from aegis.log_ingest.writer import LogIngestRow, LogIngestWriter

__all__ = ["LogIngestRow", "LogIngestWriter"]
