# ADR 0006 — Firecracker per-scan microVM isolation

- **Status:** Proposed (spike)
- **Date:** 2026-06-18
- **Scope:** the untrusted scan/tool workloads (the worker + kali pods), the
  Helm sandbox toggle (`deploy/helm/aegis/`), and the plugin sandbox
  (`AEGIS_PLUGINS_SANDBOX`)

## Context

The untrusted offensive workloads — scanner subprocesses, Kali tools, and
third-party plugin scanners — run today behind two **process-level** controls:
an optional gVisor (`runsc` `RuntimeClass`) sandbox on the worker/kali pods
(see `SECURITY.md` § "Deployment hardening"), and the in-process plugin
sandbox (out-of-process child + POSIX rlimits + minimal env). Both share the
**host kernel**. For genuine multi-tenant isolation of code that is *designed*
to attack things, a shared-kernel boundary is a weaker guarantee than a VM
boundary.

## Options considered

- **Stay on gVisor.** `runsc` intercepts syscalls in userspace — strong, but
  still one kernel, and not every workload is gVisor-clean.
- **Firecracker microVM per scan / per plugin.** Each untrusted scan or plugin
  invocation runs in its own short-lived KVM microVM with a dedicated guest
  kernel, so a container/plugin escape stops at the VM boundary, not the node.
- **Full bare-VM-per-tenant.** Strongest isolation, highest cost; rejected as
  disproportionate for short-lived scan jobs.

## Decision

**Spike a Firecracker runner** — a microVM-per-scan/per-plugin executor behind
the existing sandbox toggle, evaluated as a stronger drop-in for the gVisor
`RuntimeClass`. The work is **deferred pending infrastructure**: Firecracker
needs KVM-capable, bare-metal-or-nested-virt nodes that aren't available here,
and a microVM image-build + boot path that doesn't yet exist.

## Consequences / follow-up

- A microVM boundary is the kernel-level isolation the plugin sandbox
  explicitly is *not* (`SECURITY.md` § "Plugin sandbox" names this ADR as the
  upgrade path) — it would let a hostile plugin open sockets and touch files
  inside a disposable guest, contained from the node.
- It raises per-scan latency (VM boot) and a node-provisioning requirement the
  Helm chart must surface.
- Until it ships, gVisor + the process-level plugin sandbox remain the
  shipped controls; Firecracker stays a tracked roadmap gap.
