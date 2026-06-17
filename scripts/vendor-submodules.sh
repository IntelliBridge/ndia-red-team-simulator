#!/usr/bin/env bash
#
# vendor-submodules.sh — point Aegis' git submodules at an internal mirror
# for air-gapped installs, then fetch them.
#
# When AEGIS_OFFLINE_VENDOR_HOST is set (e.g. "git.internal.example.com"),
# every submodule URL in .gitmodules is rewritten to that host, preserving
# the <org>/<repo>.git path, via:
#
#     https://github.com/org/repo.git   -> https://<host>/org/repo.git
#     git@github.com:org/repo.git       -> https://<host>/org/repo.git
#
# The rewrite mirrors aegis.vendor.mirror_url() exactly. The script is
# idempotent: re-running it just re-applies the same set-url and re-syncs.
# When the var is unset it leaves URLs untouched and only updates submodules.
#
# Usage:
#     AEGIS_OFFLINE_VENDOR_HOST=mirror.internal ./scripts/vendor-submodules.sh
#     ./scripts/vendor-submodules.sh        # online: just `submodule update`

set -euo pipefail

# Resolve the repo root from this script's location so it works from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

GITMODULES="${REPO_ROOT}/.gitmodules"

if [[ ! -f "${GITMODULES}" ]]; then
  echo "[!] no .gitmodules at ${GITMODULES}; nothing to vendor" >&2
  exit 1
fi

# mirror_url <original-url> <host> -> echoes the rewritten https URL.
# Pure bash parameter expansion; matches aegis.vendor.mirror_url().
mirror_url() {
  local original="$1" host="$2" path bare_host

  # Strip scheme + host for "scheme://host/path" forms (https, ssh, git, …).
  if [[ "${original}" == *"://"* ]]; then
    path="${original#*://}"   # drop "scheme://"
    path="${path#*/}"         # drop "host[:port]/"
  elif [[ "${original}" == *":"* ]]; then
    # SCP-like "[user@]host:org/repo.git" — drop everything up to the colon.
    path="${original#*:}"
  else
    path="${original}"        # already a bare path
  fi

  # Normalise a single trailing ".git" and any stray leading slash.
  path="${path%.git}"
  path="${path#/}"

  # Allow the host to carry a scheme / trailing slash; strip both.
  bare_host="${host#*://}"
  bare_host="${bare_host%/}"

  echo "https://${bare_host}/${path}.git"
}

if [[ -n "${AEGIS_OFFLINE_VENDOR_HOST:-}" ]]; then
  HOST="${AEGIS_OFFLINE_VENDOR_HOST}"
  echo "[*] AEGIS_OFFLINE_VENDOR_HOST=${HOST} — rewriting submodule URLs to the mirror"

  # Iterate over every submodule path declared in .gitmodules.
  while IFS= read -r sub_path; do
    [[ -z "${sub_path}" ]] && continue
    original="$(git config --file .gitmodules --get "submodule.${sub_path}.url" || true)"
    if [[ -z "${original}" ]]; then
      echo "[!] ${sub_path}: no url in .gitmodules; skipping" >&2
      continue
    fi
    mirrored="$(mirror_url "${original}" "${HOST}")"
    echo "    ${sub_path}: ${original} -> ${mirrored}"
    # set-url updates .gitmodules; git config updates the active .git/config.
    git submodule set-url -- "${sub_path}" "${mirrored}"
    git config "submodule.${sub_path}.url" "${mirrored}"
  done < <(git config --file .gitmodules --get-regexp '^submodule\..*\.path$' | awk '{print $2}')

  echo "[*] syncing submodule URLs into .git/config"
  git submodule sync
else
  echo "[*] AEGIS_OFFLINE_VENDOR_HOST not set — using upstream URLs as-is"
fi

echo "[*] fetching submodules (git submodule update --init)"
git submodule update --init

echo "[*] done."
