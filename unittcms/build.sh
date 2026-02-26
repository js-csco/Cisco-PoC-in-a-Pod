#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# build.sh  –  Build the custom PIAP UnitTCMS image and load it into k3s
#
# Usage:
#   cd /path/to/piap-k3s
#   bash unittcms/build.sh
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

IMAGE_NAME="piap-unittcms"
IMAGE_TAG="latest"
FULL_TAG="${IMAGE_NAME}:${IMAGE_TAG}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "──────────────────────────────────────────"
echo "  Building PIAP UnitTCMS Docker image"
echo "  Tag: ${FULL_TAG}"
echo "──────────────────────────────────────────"

docker build \
  --no-cache \
  -t "${FULL_TAG}" \
  "${SCRIPT_DIR}"

echo ""
echo "──────────────────────────────────────────"
echo "  Importing image into k3s containerd"
echo "──────────────────────────────────────────"

docker save "${FULL_TAG}" | sudo k3s ctr images import -

echo ""
echo "✓ Image '${FULL_TAG}' is ready in k3s."
echo ""
echo "Next steps:"
echo "  kubectl apply -f k8s/unittcms-deployment.yaml"
echo "  kubectl apply -f k8s/unittcms-service.yaml"
echo ""
echo "  Or to replace Kanboard:"
echo "  kubectl delete -f k8s/kanboard-deployment.yaml -f k8s/kanboard-service.yaml"
echo "  kubectl apply  -f k8s/unittcms-deployment.yaml -f k8s/unittcms-service.yaml"
