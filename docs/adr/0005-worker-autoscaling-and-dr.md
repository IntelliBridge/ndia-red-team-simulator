# ADR 0005 — Worker autoscaling + multi-region DR

> Inherited from the upstream `IntelliBridge/aegis` project and kept as history. Names below are the upstream `aegis` identifiers at the time of the decision. In this fork the package is `redsim/`, environment variables are `REDSIM_*`, the console script is `redsim` and the chart is `deploy/helm/redsim`.

- **Status:** Proposed (spike)
- **Date:** 2026-06-18
- **Scope:** the worker/queue layer (`aegis/workers/`, `AEGIS_BROKER_URL` /
  Redis), the deploy chart (`deploy/helm/aegis/`), and the data plane
  (Postgres + the object store)

## Context

Aegis runs scans, agents, and remediation on **Celery workers** backed by
**Redis** as broker + result backend. Worker replica count is fixed in the
Helm values, so a burst of queued scans waits on a static pool while idle
workers sit warm off-peak. There is also **no disaster-recovery story**: a
single Postgres and a single object-store bucket in one region mean a
regional outage takes the platform — and the hash-chained audit history —
offline.

## Options considered

- **KEDA-based autoscaling.** A `ScaledObject` scales worker replicas on
  Redis queue depth (the Celery list length), down to zero when idle. Pure
  Kubernetes-native, no engine change.
- **Celery → Temporal migration.** Replace the Celery+Redis task layer with
  Temporal for durable, retryable, observable workflows — a larger rewrite of
  the admission/execution seam (ADR-0003) but stronger long-running-workflow
  guarantees.
- **Multi-region active/passive DR.** A standby region with streaming
  Postgres replication and cross-region object-store (WORM bucket) replication;
  promote the standby on a regional failure.

## Decision

**Spike KEDA queue-depth autoscaling** against the existing Celery+Redis
broker (a `ScaledObject` behind a `autoscaling.enabled` chart toggle, default
off) and run a **Temporal evaluation** as a parallel, non-committing spike —
no engine swap until the evaluation justifies the rewrite cost. **Full
multi-region DR is deferred**: it needs real cloud infrastructure
(cross-region Postgres replication + bucket replication) that isn't available
in this environment.

## Consequences / follow-up

- KEDA gives elastic, scale-to-zero workers without touching task code; it
  adds a cluster operator dependency and a metric-source (Redis) the chart
  must document.
- The Temporal evaluation is throwaway by design — it informs a future ADR,
  it does not commit Aegis off Celery.
- DR remains a tracked roadmap gap; the WORM Object-Lock export (`SECURITY.md`
  § "Audit chain") already protects the audit history off-DB in the interim,
  but it is not a regional failover.
