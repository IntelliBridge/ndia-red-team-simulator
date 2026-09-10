#!/usr/bin/env bash
# Run a command with the local API session keypair exported for compose.
#
# redsim-web signs the redsim_api_session cookie with
# REDSIM_API_SESSION_PRIVATE_KEY and redsim-api verifies it with
# REDSIM_API_SESSION_PUBLIC_KEY (docs/architecture/auth.md). Neither is
# committed, and without both the web app completes the Keycloak login but
# mints no cookie and every API call answers 401. So the first `make up` on a
# machine generates an RSA keypair, PKCS8 private half and SubjectPublicKeyInfo
# public half (the same shapes deploy/runtime/scripts/prepare_secrets.py
# produces for the Fargate runtime), into deploy/certs/, and every later run
# reuses it.
#
# The two files are gitignored and dockerignored on purpose: deploy/certs/ is
# copied into every image as a CA trust directory, and the private key must
# never land in an image layer. A .env file is not used because a multi-line
# PEM does not survive one; the values go straight from the files into the
# environment of the command this script execs, so the compose file keeps its
# `${VAR:-}` contract. A value already exported in the calling shell wins, so
# an operator can supply a keypair of their own.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
certs="$here/../certs"
private="$certs/redsim-api-session.key"
public="$certs/redsim-api-session.pub"

if [ ! -s "$private" ] || [ ! -s "$public" ]; then
  if ! command -v openssl >/dev/null 2>&1; then
    echo "with-session-keypair: openssl is required to generate $private" >&2
    exit 1
  fi
  mkdir -p "$certs"
  (
    umask 077
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$private" 2>/dev/null
    openssl pkey -in "$private" -pubout -out "$public"
  )
  echo "with-session-keypair: generated a new API session keypair under deploy/certs/" >&2
fi

export REDSIM_API_SESSION_PRIVATE_KEY="${REDSIM_API_SESSION_PRIVATE_KEY:-$(cat "$private")}"
export REDSIM_API_SESSION_PUBLIC_KEY="${REDSIM_API_SESSION_PUBLIC_KEY:-$(cat "$public")}"
exec "$@"
