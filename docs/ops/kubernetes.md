# Kubernetes (Helm)

The Helm chart at `deploy/helm/redsim/` deploys the full Redsim stack to a
real Kubernetes cluster. It mirrors the service topology in
`deploy/docker-compose.yml` — the four Redsim services (`api`, `worker`,
`web`, `log-ingest`) plus the optional stateful dependencies
(Postgres, Redis, Keycloak, MinIO) and the Kali tool shim — but adds the
production hardening that compose doesn't carry: non-root pods, dropped
capabilities, seccomp, resource limits, and liveness/readiness probes.

This page is the deploy guide. For the env vars, key generation, and the
rotation runbook that apply regardless of orchestrator, see
[Production deployment](deploy.md). For the auditor-facing evidence
bundle, see [Compliance evidence pack](compliance-evidence.md).

!!! note "Not a local-dev path"
    This chart targets a real cluster. It is **not** run on a laptop —
    manifests are validated for YAML/template correctness only (a
    `helm-lint` CI job runs `helm lint` + `helm template`). For day-1
    local development use the [local stack](../dev/local-stack.md).

---

## Install / upgrade

The chart lives in-repo; install it by path.

```bash
# First install into its own namespace.
helm install redsim deploy/helm/redsim \
  --namespace redsim --create-namespace \
  -f prod-values.yaml

# Subsequent upgrades.
helm upgrade redsim deploy/helm/redsim \
  --namespace redsim \
  -f prod-values.yaml
```

`values.yaml` ships **dev placeholders** — the secret-bearing values
(`config.secret.*`) are throwaway defaults. In production, supply real
values via `--set`, a sealed values file, or wire an external secret
store by setting `config.secret.existingSecret` (which short-circuits the
rendered Secret). Never deploy the in-repo defaults to a real cluster.

After install, `helm` prints a NOTES summary (component Service names,
which deps are enabled, the Keycloak replica count, whether the sandbox
is on, and how to reach the UI). When `ingress.enabled=false` the notes
hand you the `kubectl port-forward` command for the web Service.

---

## Key `values.yaml` knobs

### Images

Every service image resolves through the optional `global.imageRegistry`
prefix, so you point the whole stack at your registry once:

```yaml
global:
  imageRegistry: "ghcr.io/intellibridge/"   # trailing slash matters
  imagePullPolicy: IfNotPresent
  imagePullSecrets:
    - name: ghcr-pull
```

Per-service `*.image.repository` / `*.image.tag` override individual
images (default tags track the chart's `appVersion`). Leave
`imageRegistry` blank for local dev image names (`redsim-api:dev`, …).

### Replicas

`api`, `worker`, and `web` default to `replicaCount: 2`; `log-ingest`
and `kali` to `1`. Keycloak has its own `keycloak.replicas` (see
[HA Keycloak](#ha-keycloak) below). Tune per service:

```yaml
api: { replicaCount: 3 }
worker: { replicaCount: 4 }
```

### Dependency toggles (`*.enabled`)

Each stateful dependency is gated by an `enabled` flag. Leave it `true`
to run the dependency in-cluster, or set it `false` and point the
matching `config.*` URL at a managed equivalent (RDS, ElastiCache, a
hosted IdP, S3):

```yaml
postgres: { enabled: false }
redis:    { enabled: false }
minio:    { enabled: false }
keycloak: { enabled: true }

config:
  dbUrl: postgresql+psycopg://redsim_app:…@rds.internal:5432/redsim
  brokerUrl: redis://elasticache.internal:6379/0
  s3Endpoint: https://s3.us-gov-west-1.amazonaws.com
  oidcIssuer: https://idp.example.com/realms/redsim
```

When `postgres.enabled=true` the chart still expects you to provision the
`redsim_app` / `redsim_owner` role split and run migrations as the owner —
see the [first-deploy checklist](deploy.md#first-deploy-checklist).

### Ingress

Disabled by default. Enable it and route the web UI + the api:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
  hosts:
    - host: redsim.example.com
      paths:
        - { path: /,    pathType: Prefix, service: web }
        - { path: /api, pathType: Prefix, service: api }
  tls:
    - secretName: redsim-tls
      hosts: [redsim.example.com]
```

---

## Security hardening defaults

Every Redsim pod renders with a hardened security posture out of the box
(see `templates/_helpers.tpl`):

- **Non-root.** Pod `securityContext` sets `runAsNonRoot: true`,
  `runAsUser/runAsGroup/fsGroup: 1000`.
- **All capabilities dropped.** Container `securityContext` drops `ALL`
  Linux capabilities and sets `allowPrivilegeEscalation: false`.
- **seccomp.** `seccompProfile.type: RuntimeDefault` at both the pod and
  container level.
- **Resource requests + limits** on every service (CPU/memory), so the
  scheduler can bin-pack and a runaway pod can't starve a node.
- **Liveness + readiness probes** on every service — HTTP `/health` for
  api/web/log-ingest, a TCP socket for kali, and a Celery `inspect ping`
  for the worker (so a worker with a dead broker connection reads as
  unready rather than false-healthy).
- **`readOnlyRootFilesystem`** is on where the workload allows it
  (log-ingest) and off where a writable workdir is required (api runs
  `alembic upgrade head` before uvicorn; worker, web, kali). Each is a
  per-service `readOnlyRootFilesystem` knob.

These are defaults, not options — there is no flag to drop to root.

---

## Sandbox isolation

The `worker` and `kali` pods execute **untrusted** scan/tool workloads.
The chart can run them under a [gVisor](https://gvisor.dev/) sandbox so a
compromised tool can't escape to the node kernel.

```yaml
sandbox:
  enabled: true
  runtimeClassName: gvisor   # the RuntimeClass object name
  handler: runsc             # must match the node's containerd runtime
```

When `sandbox.enabled=true`:

1. The chart renders a `RuntimeClass` (`templates/runtimeclass.yaml`)
   named `sandbox.runtimeClassName` with the `sandbox.handler`.
2. The **worker** and **kali** Deployments — and only those two — set
   `runtimeClassName: <runtimeClassName>` on their pod spec. The api,
   web, and log-ingest pods stay on the default runtime.

!!! warning "gVisor must be installed on the nodes"
    The chart only *declares* the RuntimeClass — it cannot install
    gVisor. Every node that schedules the worker / kali pods must have
    gVisor installed and the `runsc` handler wired into its containerd
    config (`runtimes.runsc`). If the handler is absent on a node, those
    pods won't schedule there. gVisor is a node/infra dependency, not a
    code dependency.

When `sandbox.enabled=false` (the default) no RuntimeClass is rendered
and the worker/kali pods fall back to the default OCI runtime.

---

## HA Keycloak

`keycloak.replicas` defaults to `2`. Running more than one replica is
only genuinely HA if Keycloak is backed by shared state:

```yaml
keycloak:
  enabled: true
  replicas: 2
```

!!! warning "Shared DB + distributed cache required for real HA"
    The bundled Keycloak runs `start-dev` for parity with the compose
    stack, which uses an **embedded H2 database and a local cache** — that
    is **not** HA-safe across replicas (sessions/tokens won't be
    consistent). For real HA, switch the command to `start --optimized`,
    point `KC_DB` at a **shared external Postgres**, and configure a
    **distributed Infinispan cache** (`KC_CACHE=ispn` with a jgroups
    discovery stack) so sessions and tokens stay consistent across
    replicas. See the inline comment in `templates/keycloak.yaml` and
    `values.yaml` for the exact knobs.

If you front Redsim with an external/managed IdP instead, set
`keycloak.enabled=false` and point `config.oidcIssuer` /
`config.oidcJwksUrl` at it.

---

## CI

A `helm-lint` job in `.github/workflows/redsim-ci.yml` runs `helm lint`
on the chart and `helm template` twice — once with default values and
once with `--set sandbox.enabled=true --set ingress.enabled=true` — so
the gated RuntimeClass and Ingress paths are exercised on every PR.
