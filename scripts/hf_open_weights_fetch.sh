#!/usr/bin/env bash
# Download the open-weights Hugging Face checkpoints the upload demo registers, at pinned revisions.
#
#   scripts/hf_open_weights_fetch.sh [DEST]      # default DEST=assets/hf (gitignored)
#
# Writes DEST/<owner>_<repo>/{<weights>,config.json,README.md}, DEST/REVISIONS.txt (repo and commit sha)
# and DEST/SHA256SUMS. Behind a TLS-inspecting proxy export SSL_CERT_FILE / CURL_CA_BUNDLE first.
# The files are model weights only: no dataset row, no credential, nothing executed.
set -euo pipefail

DEST="${1:-assets/hf}"
mkdir -p "$DEST"

# repo | weights file | licence (model card)
MODELS=(
  "SamAdamDay/resnet18_cifar10|model.safetensors|MIT"
  "FredMell/resnet18-cifar10|model.safetensors|Apache-2.0"
  "ketiswp/mlcommons-ResNet8-CIFAR10-fp32-onnx|model.onnx|Apache-2.0"
  "edadaltocg/resnet18_cifar10|pytorch_model.bin|MIT"
)

: > "$DEST/REVISIONS.txt"
for entry in "${MODELS[@]}"; do
  IFS='|' read -r repo file license <<< "$entry"
  sha=$(curl -sSfL "https://huggingface.co/api/models/$repo" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')
  dir="$DEST/${repo//\//_}"
  mkdir -p "$dir"
  echo "$repo $sha $license" >> "$DEST/REVISIONS.txt"
  for f in "$file" config.json README.md; do
    curl -sSfL "https://huggingface.co/$repo/resolve/$sha/$f" -o "$dir/$f" || echo "  $repo has no $f"
  done
  echo "fetched $repo @ ${sha:0:12} ($license): $file"
done

(cd "$DEST" && shasum -a 256 */model.safetensors */model.onnx */pytorch_model.bin > SHA256SUMS)
cat "$DEST/REVISIONS.txt"
