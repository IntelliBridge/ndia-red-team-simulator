# Kubernetes (Helm)

The Helm chart at `deploy/helm/redsim/` deploys the full redsim stack to a
real Kubernetes cluster. It mirrors the service topology in
`deploy/docker-compose.yml` (the four redsim services `api`, `worker`, `web`
and `log-ingest`, plus the optional stateful dependencies Postgres, Redis,
Keycloak and MinIO) and adds the production hardening compose does not
carry: non-root pods, dropped capabilities, seccomp, resource limits, and
liveness and readiness probes.

This page is the deploy guide. For the env vars, key generation and the
rotation runbook that apply regardless of orchestrator, see
[Production deployment](deploy.md). For the LLM gateway see
[Pythia access](pythia.md). For the auditor-facing evidence bundle, see
[Compliance evidence pack](compliance-evidence.md).

!!! note "Not a local-dev path"
    This chart targets a real cluster. It is not run on a laptop. Manifests
    are validated for YAML and template correctness only (the `helm-lint`
    CI job). For day-1 local development use the
    [local stack](../dev/local-stack.md).

---

## Install / upgrade

```bash
helm install redsim deploy/helm/redsim \
  --namespace redsim --create-namespace \
  -f prod-values.yaml

helm upgrade redsim deploy/helm/redsim \
  --namespace redsim \
  -f prod-values.yaml
```

`values.yaml` ships **dev placeholders**. The secret-bearing values
(`config.secret.*`) are throwaway defaults. In production, supply real values
via `--set`, a sealed values file, or wire an external secret store by
setting `config.secret.existingSecret` (which short-circuits the rendered
Secret) or the chart's `externalSecrets` support. A `config.env=prod` render
that still carries the dev placeholders is rejected by the chart's guard.
Never deploy the in-repo defaults to a real cluster.

After install, `helm` prints a NOTES summary (component Service names, which
deps are enabled, the Keycloak replica count, whether the sandbox is on, and
how to reach the UI). When `ingress.enabled=false` the notes hand you the
`kubectl port-forward` command for the web Service.

---

## Key `values.yaml` knobs

### Images

Every service image resolves through the optional `global.imageRegistry`
prefix:

```yaml
global:
  imageRegistry: "ghcr.io/intellibridge/"   # trailing slash matters
  imagePullPolicy: IfNotPresent
  imagePullSecrets:
    - name: ghcr-pull
```

Per-service `*.image.repository` / `*.image.tag` override individual images
(default tags track the chart's `appVersion`). Leave `imageRegistry` blank
for local dev image names (`redsim-api:dev`, …). The worker image is the
only one that carries the `ml` extra.

### Replicas

`api`, `worker` and `web` default to `replicaCount: 2`, `log-ingest` to `1`.
Keycloak has its own `keycloak.replicas` (see [HA Keycloak](#ha-keycloak)).

The worker Deployment sets no command, so every replica runs the image CMD
(`celery … worker -Q scans,default`): one combined pool, not the
`scans` / `default` split of the compose file. The chart ships **no
`celery beat` Deployment**, so under Helm the stale-job reaper, the hourly
tenant-integrity check and the WORM export never fire until a one-replica
beat Deployment (same image, `celery -A redsim.workers.celery_app beat`) is
added. Treat that as a gap to close before a real install, and never run more
than one beat.

```yaml
api: { replicaCount: 3 }
worker: { replicaCount: 4 }
```

### Dependency toggles (`*.enabled`)

Each stateful dependency is gated by an `enabled` flag. Leave it `true` to
run in-cluster, or set it `false` and point the matching `config.*` URL at a
managed equivalent (RDS, ElastiCache, a hosted IdP, S3):

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
`redsim_app` / `redsim_owner` role split and run migrations as the owner
(see the [first-deploy checklist](deploy.md#first-deploy-checklist)).

### Ingress

Disabled by default. Enable it and route the web UI and the api:

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

Every redsim pod renders with a hardened posture out of the box
(`templates/_helpers.tpl`):

- **Non-root.** `runAsNonRoot: true`, `runAsUser/runAsGroup/fsGroup: 1000`.
- **All capabilities dropped**, `allowPrivilegeEscalation: false`.
- **seccomp.** `seccompProfile.type: RuntimeDefault` at pod and container
  level.
- **Resource requests and limits** on every service. Size the worker for
  torch, ART and SHAP on CPU, and make sure the sandbox child's rlimits fit
  inside the container limit.
- **Liveness and readiness probes** on every service: HTTP `/health` for
  api, web and log-ingest, a Celery `inspect ping` for the worker.
- **`readOnlyRootFilesystem`** is on where the workload allows it
  (log-ingest) and off where a writable workdir is required (api runs
  `alembic upgrade head` before uvicorn, worker needs its per-job work
  directories, web).

These are defaults, not options. There is no flag to drop to root.

---

## Sandbox isolation

The `worker` pods are the only pods that load models and run attacks. The
chart can run them under a [gVisor](https://gvisor.dev/) sandbox so a
compromised loader or adapter cannot escape to the node kernel.

```yaml
sandbox:
  enabled: true
  runtimeClassName: gvisor   # the RuntimeClass object name
  handler: runsc             # must match the node's containerd runtime
```

When `sandbox.enabled=true`:

1. The chart renders a `RuntimeClass` (`templates/runtimeclass.yaml`) named
   `sandbox.runtimeClassName` with the `sandbox.handler`.
2. The **worker** Deployment, and only it, sets `runtimeClassName` on its pod
   spec. The api, web and log-ingest pods stay on the default runtime.

!!! warning "gVisor must be installed on the nodes"
    The chart only declares the RuntimeClass. Every node that schedules the
    worker pods must have gVisor installed and the `runsc` handler wired
    into its containerd config. If the handler is absent on a node, those
    pods will not schedule there.

When `sandbox.enabled=false` (the default) no RuntimeClass is rendered and
the worker pods use the default OCI runtime. The in-process sandbox child
(rlimits, process group, minimal env) applies either way, gVisor adds the
kernel boundary on top.

---

## HA Keycloak

`keycloak.replicas` defaults to `2`. Running more than one replica is only
genuinely HA if Keycloak is backed by shared state.

!!! warning "Shared DB and distributed cache required for real HA"
    The bundled Keycloak runs `start-dev` for parity with the compose
    stack, which uses an embedded H2 database and a local cache. That is
    not HA-safe across replicas. For real HA, switch the command to
    `start --optimized`, point `KC_DB` at a shared external Postgres, and
    configure a distributed Infinispan cache (`KC_CACHE=ispn` with a
    jgroups discovery stack). See the inline comments in
    `templates/keycloak.yaml` and `values.yaml`.

If you front redsim with an external or managed IdP instead, set
`keycloak.enabled=false` and point `config.oidcIssuer` / `config.oidcJwksUrl`
at it.

---

## Pythia and the worker

Set the Pythia variables (`PYTHIA_BASE_URL`, `PYTHIA_API_KEY` as a secret,
`PYTHIA_PERSONA`, `REDSIM_ML_LLM_MODEL`) on the worker Deployment and leave
`REDSIM_DISABLE_LLM` unset there. The api and web pods need no route to the
gateway. Behind an inspecting proxy the worker image needs the proxy root in
its trust store (`deploy/certs/` at build time), the client verifies against
the container's distro bundle by default.

---

## CI

The `helm-lint` job in `.github/workflows/redsim-ci.yml` runs `helm lint`
and six `helm template` renders: default values, `sandbox.enabled=true` plus
`ingress.enabled=true`, a `config.env=prod` render with dev placeholders
(must fail with the "shipped DEV placeholders" guard), a prod render with
`externalSecrets.enabled=true` (must render an `ExternalSecret`), and a prod
render with real secret values (must succeed). The chart's CI values files
live under `deploy/helm/redsim/ci/`.
