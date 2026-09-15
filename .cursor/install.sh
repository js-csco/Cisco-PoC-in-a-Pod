#!/usr/bin/env bash
#
# Idempotent Cloud Agent bootstrap for the "PoC in a Pod" repository.
#
# The full lab (K3s + Cilium + Tetragon + Splunk + Secure Access connector)
# requires a dedicated, privileged Ubuntu VM plus live Cisco Secure Access / Duo
# tenants, so it is out of scope for a Cloud Agent. This script instead sets up
# the runnable web components so they can be developed and previewed locally:
#
#   - poc-dashboard : Flask app (port 8080)
#   - saml-app      : Flask SAML SP demo (port 9400)
#   - playbook      : static HTML guide (served on port 30250)
#   - sse-check     : static HTML page (served on port 30550)
#
# It is safe to run repeatedly.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Installing system dependencies (xmlsec for python3-saml, venv support)"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  python3-venv \
  python3-dev \
  pkg-config \
  gcc \
  libxml2-dev \
  libxmlsec1-dev \
  libxmlsec1-openssl

# Create (or refresh) a virtual environment and install requirements for an app.
setup_venv() {
  local app_dir="$1"
  echo "==> Setting up venv for ${app_dir}"
  python3 -m venv "${app_dir}/.venv"
  "${app_dir}/.venv/bin/pip" install --upgrade pip --quiet
  "${app_dir}/.venv/bin/pip" install --quiet -r "${app_dir}/requirements.txt"
}

setup_venv "poc-dashboard"
setup_venv "saml-app"

echo "==> Install complete."
echo "    poc-dashboard -> http://localhost:8080"
echo "    saml-app      -> http://localhost:9400"
echo "    playbook      -> http://localhost:30250"
echo "    sse-check     -> http://localhost:30550"
