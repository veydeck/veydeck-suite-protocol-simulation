#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_MANIFEST="${ROOT_DIR}/crates/protocol-simulation-engine/Cargo.toml"
IMAGE_REPOSITORY="${IMAGE_REPOSITORY:-veydeck/protocol-simulation-engine}"

read_crate_version() {
  awk '
    /^\[package\]/ { in_package = 1; next }
    /^\[/ && in_package { exit }
    in_package && /^[[:space:]]*version[[:space:]]*=/ {
      value = $0
      sub(/^[[:space:]]*version[[:space:]]*=[[:space:]]*/, "", value)
      gsub(/["[:space:]\r]/, "", value)
      print value
      exit
    }
  ' "$CRATE_MANIFEST"
}

TAG="${1:-$(read_crate_version)}"
if [ -z "$TAG" ]; then
  echo "Error: could not read version from $CRATE_MANIFEST" >&2
  exit 1
fi

IMAGE="${IMAGE_REPOSITORY}:${TAG}"
echo "Building ${IMAGE}"
docker build -f "${ROOT_DIR}/Dockerfile.engine" -t "${IMAGE}" "${ROOT_DIR}"
