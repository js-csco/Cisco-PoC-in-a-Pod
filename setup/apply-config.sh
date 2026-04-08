#!/bin/bash
# apply-config.sh — re-apply IP configuration after a git pull
#
# Run this whenever you pull new commits to the server.
# It re-patches sse-check connector IP and ensures the required
# symlinks exist — WITHOUT doing a full reinstall.
#
# Usage: sudo ./setup/apply-config.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo: sudo ./setup/apply-config.sh"
    exit 1
fi

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

SERVER_IP=$(hostname -I | awk '{print $1}')
echo "Server IP: $SERVER_IP"

# ── 0. Configure k3s Docker Hub registry mirror ─────────────────────────────
echo ""
echo "Step 0: Configuring k3s Docker Hub registry mirror..."
REGISTRIES_FILE="/etc/rancher/k3s/registries.yaml"
if [ ! -f "$REGISTRIES_FILE" ]; then
    cat > "$REGISTRIES_FILE" <<'EOF'
mirrors:
  docker.io:
    endpoint:
      - "https://mirror.gcr.io"
EOF
    systemctl restart k3s 2>/dev/null || true
    echo "  ✓ Docker Hub mirror configured (mirror.gcr.io) — k3s restarted"
elif ! grep -q "mirror.gcr.io" "$REGISTRIES_FILE"; then
    # File exists (e.g. has credentials) but mirrors section is missing — prepend it
    EXISTING=$(cat "$REGISTRIES_FILE")
    cat > "$REGISTRIES_FILE" <<EOF
mirrors:
  docker.io:
    endpoint:
      - "https://mirror.gcr.io"
$EXISTING
EOF
    systemctl restart k3s 2>/dev/null || true
    echo "  ✓ mirrors section added to existing registries.yaml — k3s restarted"
else
    echo "  ✓ registries.yaml already has mirror configured, skipping"
fi

# ── 1. Ensure symlinks exist ────────────────────────────────────────────────
echo ""
echo "Step 1: Ensuring symlinks..."
ln -sfn "$REPO_ROOT/sse-check"        /sse-check       && echo "  ✓ /sse-check"
ln -sfn "$REPO_ROOT/playbook"         /playbook        && echo "  ✓ /playbook"
ln -sfn "$REPO_ROOT/poc-dashboard" /poc-dashboard && echo "  ✓ /poc-dashboard"
ln -sfn "$REPO_ROOT/saml-app"         /saml-app        && echo "  ✓ /saml-app"

# ── 2. Detect connector IP ──────────────────────────────────────────────────
echo ""
echo "Step 2: Detecting connector IP..."

CONNECTOR_NAME=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i connector | head -1 || true)

if [ -n "$CONNECTOR_NAME" ]; then
    CONNECTOR_IP=$(docker inspect "$CONNECTOR_NAME" \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null \
        | tr ' ' '\n' | grep -v '^$' | grep -v '^172\.17\.' | head -1)
fi

if [ -z "$CONNECTOR_IP" ]; then
    CONNECTOR_IP=$(hostname -I | tr ' ' '\n' \
        | grep -v "^$SERVER_IP$" | grep -v '^127\.' | grep -v '^::' | head -1)
fi

CONNECTOR_IP=${CONNECTOR_IP:-$SERVER_IP}
echo "  Connector IP: $CONNECTOR_IP"

# ── 3. Patch sse-check ConfigMap ────────────────────────────────────────────
echo ""
echo "Step 3: Patching sse-check-config ConfigMap with connector IP..."
if kubectl get configmap sse-check-config -n piap &>/dev/null; then
    # Use kubectl create --dry-run | apply to avoid JSON escape issues with $connector_ip
    kubectl create configmap sse-check-config -n piap \
        --from-literal=default.conf="$(printf 'server {\n    listen 80;\n    root /usr/share/nginx/html;\n    index index.html;\n    ssi on;\n    ssi_silent_errors on;\n    set $connector_ip "%s";\n}\n' "$CONNECTOR_IP")" \
        --dry-run=client -o yaml | kubectl apply -f -
    kubectl rollout restart deployment/sse-check -n piap
    echo "  ✓ sse-check connector IP set to $CONNECTOR_IP"
else
    echo "  ⚠ sse-check-config ConfigMap not found — deploy manifests first, then re-run this script"
fi

echo ""
echo "Done. Access Automagic at: http://$SERVER_IP:30200"
echo "      SSE Check at:        http://$SERVER_IP:30550"
