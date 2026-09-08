# ADR 0008 — Nix reproducible builds

> Inherited from the upstream `IntelliBridge/aegis` project and kept as history. Names below are the upstream `aegis` identifiers at the time of the decision. In this fork the package is `redsim/`, environment variables are `REDSIM_*`, the console script is `redsim` and the chart is `deploy/helm/redsim`.

- **Status:** Proposed (spike)
- **Date:** 2026-06-18
- **Scope:** the build/release pipeline (`deploy/Dockerfile.*`, the release
  signing workflow) and the supply-chain attestations
  (`docs/security/supply-chain.md`)

## Context

Aegis's supply-chain story already attests **what shipped**: release images
are keyless **cosign**-signed by digest, carry a **CycloneDX SBOM** (Syft), and
ship **SLSA-3 provenance** (see `SECURITY.md` § "Supply-chain integrity"). What
none of that proves is that an **independent rebuild** from source produces a
**bit-identical** artifact. The Docker builds pull a moving base image and
resolve dependencies at build time, so two builds of the same commit can
differ byte-for-byte — provenance says who built it and from what inputs, but
not that anyone else can reproduce it.

## Options considered

- **Stay on Docker + SBOM/SLSA.** Strong provenance and a signed bill of
  materials; no bit-reproducibility guarantee.
- **Nix-built, bit-reproducible images.** A Nix flake pins every input down to
  the hash and produces a deterministic, content-addressed artifact a third
  party can rebuild and compare bit-for-bit — closing the gap from "attested"
  to "independently reproducible."

## Decision

**Spike a Nix flake** for one service image as a complement to (not a
replacement for) cosign/SBOM/SLSA-3, proving the bit-reproducible rebuild
end-to-end. Full migration of the release pipeline to Nix is **deferred** — it
is a large pipeline change, and the existing attestations already cover the
near-term supply-chain requirements.

## Consequences / follow-up

- Nix would let an auditor *reproduce* the artifact, not merely verify a
  signature over it — the strongest rung of the supply-chain ladder.
- It is additive: cosign signatures, the SBOM, and SLSA-3 provenance stay; Nix
  adds bit-reproducibility on top.
- Reproducible builds are already named as the remaining supply-chain gap in
  `SECURITY.md` and ADR-0001 (§ "Out of scope"); this ADR is where that gap
  gets a concrete spike. Until it ships, it stays a tracked roadmap gap.
