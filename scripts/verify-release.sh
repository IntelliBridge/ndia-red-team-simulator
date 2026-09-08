#!/usr/bin/env bash
#
# Verify a released Redsim image before deploy.
#
# These checks run against artifacts produced by
# .github/workflows/release-sign.yml: a keyless cosign signature, a
# CycloneDX SBOM attestation, and SLSA-3 build provenance. They confirm
# the image was built and signed by THIS repo's release workflow on a
# version tag — not by an attacker or an untagged build.
#
# Usage:
#   scripts/verify-release.sh <service> <digest>
#
#   <service>  one of: api | worker | web | log_ingest
#   <digest>   the sha256 image digest, e.g. sha256:abc123...
#
# Requires: cosign (>= v2) on PATH. Nothing here runs in CI; it is the
# operator-side counterpart to the release workflow.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <service: api|worker|web|log_ingest> <digest: sha256:...>" >&2
  exit 2
fi

SERVICE="$1"
DIGEST="$2"

case "$SERVICE" in
  api | worker | web | log_ingest) ;;
  *)
    echo "error: unknown service '$SERVICE' (want api|worker|web|log_ingest)" >&2
    exit 2
    ;;
esac

if [[ "$DIGEST" != sha256:* ]]; then
  echo "error: digest must look like 'sha256:...'" >&2
  exit 2
fi

# GHCR rejects upper-case path segments, so the pushed name is lower-cased.
IMAGE="ghcr.io/intellibridge/redsim/${SERVICE}@${DIGEST}"

# Identity of THIS repo's release workflow, signing on a version tag.
IDENTITY='^https://__UPSTREAM_REDSIM_URL__/.github/workflows/release-sign.yml@refs/tags/v.*$'
# The SLSA generator signs provenance under its own identity.
SLSA_IDENTITY='^https://github.com/slsa-framework/slsa-github-generator/.*$'
ISSUER='https://token.actions.githubusercontent.com'

echo "==> Verifying image signature: ${IMAGE}"
cosign verify \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE"

echo "==> Verifying SBOM attestation (CycloneDX)"
cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE"

echo "==> Verifying SLSA provenance attestation"
cosign verify-attestation --type slsaprovenance \
  --certificate-identity-regexp "$SLSA_IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE"

echo "OK: ${IMAGE} is signed, has an SBOM, and carries SLSA provenance."
