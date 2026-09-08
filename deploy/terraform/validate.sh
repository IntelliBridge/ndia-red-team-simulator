#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
tf="$(command -v "${TERRAFORM_BIN:-terraform}")"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/home" "$scratch/data"

# This process receives no caller AWS credentials, shared credential files,
# Terraform cloud credentials, TF_VAR values, or configured production backend.
clean_tf() {
  env -i \
    PATH="$PATH" \
    HOME="$scratch/home" \
    CHECKPOINT_DISABLE=1 \
    AWS_EC2_METADATA_DISABLED=true \
    AWS_CONFIG_FILE=/dev/null \
    AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    TF_IN_AUTOMATION=1 \
    TF_INPUT=0 \
    TF_DATA_DIR="$scratch/data" \
    "$tf" -chdir="$root" "$@"
}

version="$(clean_tf version -json | python3 -c 'import json,sys; print(json.load(sys.stdin)["terraform_version"])')"
if [[ "$version" != "1.16.1" ]]; then
  printf 'Expected Terraform 1.16.1, got %s\n' "$version" >&2
  exit 1
fi

python3 "$root/check_foundation.py"
python3 -m unittest discover -s "$root/tests" -p 'test_*.py'
clean_tf fmt -check -recursive -no-color

# Reuse an already locked provider binary if present, but never reuse its
# TF_DATA_DIR/backend configuration. Fresh CI fetches the signed locked provider.
plugin_args=()
if [[ -d "$root/.terraform/providers" ]]; then
  plugin_args+=("-plugin-dir=$root/.terraform/providers")
fi
clean_tf init -backend=false -lockfile=readonly -input=false -no-color "${plugin_args[@]}"
clean_tf validate -no-color
clean_tf test -no-color