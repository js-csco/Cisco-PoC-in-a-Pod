#!/usr/bin/env bash
# ============================================================
# Podman + Podman Compose environment installer
# Tested on: Ubuntu 24.04.x LTS
# ============================================================

set -e

echo "🔹 Updating package index..."
sudo apt update -y

echo "🔹 Installing core container stack..."
sudo apt install -y podman-compose buildah skopeo

echo "🔹 Installing networking and overlay dependencies..."
sudo apt install -y \
  slirp4netns fuse-overlayfs containernetworking-plugins

echo "🔹 Installing useful tools and utilities..."
sudo apt install -y curl git jq tar gzip htop make podman-docker

echo "🔹 Installing core flask stack..."
sudo apt install -y python3-flask python3-requests

echo "✅ Installation complete."

# ------------------------------------------------------------
# Verification section
# ------------------------------------------------------------
echo
echo "🔍 Verifying installations..."
echo "------------------------------------------------------------"

for tool in podman podman-compose buildah skopeo curl git jq make; do
  if command -v $tool >/dev/null 2>&1; then
    printf "✅ %-16s : %s\n" "$tool" "$($tool --version 2>/dev/null | head -n1)"
  else
    printf "❌ %-16s : Not found!\n" "$tool"
  fi
done

echo "------------------------------------------------------------"
echo "🔹 Testing Podman basic functionality..."
if podman run --rm hello-world >/dev/null 2>&1; then
  echo "✅ Podman test container ran successfully!"
else
  echo "⚠️  Podman test container failed — check networking or image pull."
fi

echo
echo "🎉 All done! Your system is now ready for Podman Compose projects."
echo "You can verify networking with:  podman info | grep -A2 network"
echo "To start your project:          podman-compose up -d --build"

