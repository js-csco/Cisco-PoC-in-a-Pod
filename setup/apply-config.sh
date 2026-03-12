#!/bin/bash
# apply-config.sh — re-apply IP configuration after a git pull
#
# Run this whenever you pull new commits to the server.
# It re-patches dashy/conf.yml, sse-check connector IP, and
# ensures the required symlinks exist — WITHOUT doing a full reinstall.
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
ln -sfn "$REPO_ROOT/dashy"            /dashy           && echo "  ✓ /dashy"
ln -sfn "$REPO_ROOT/sse-check"        /sse-check       && echo "  ✓ /sse-check"
ln -sfn "$REPO_ROOT/testcases"        /testcases       && echo "  ✓ /testcases"
ln -sfn "$REPO_ROOT/automagic-server" /automagic-server && echo "  ✓ /automagic-server"

# ── 2. Patch dashy conf.yml ─────────────────────────────────────────────────
echo ""
echo "Step 2: Patching Dashy config with server IP ($SERVER_IP)..."
# Reset to the template version first (in case it was already patched), then apply
git -C "$REPO_ROOT" checkout -- dashy/conf.yml 2>/dev/null || true
sed -i "s/SERVER_IP/$SERVER_IP/g" "$REPO_ROOT/dashy/conf.yml"
echo "  ✓ dashy/conf.yml updated"

# ── 3. Detect connector IP ──────────────────────────────────────────────────
echo ""
echo "Step 3: Detecting connector IP..."

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

# ── 4. Patch sse-check ConfigMap ────────────────────────────────────────────
echo ""
echo "Step 4: Patching sse-check-config ConfigMap with connector IP..."
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

# ── 5. Restart dashy to pick up conf.yml changes ────────────────────────────
echo ""
echo "Step 5: Restarting Dashy pod to reload config..."
if kubectl get deployment dashy -n piap &>/dev/null; then
    kubectl rollout restart deployment/dashy -n piap
    echo "  ✓ Dashy restarted"
else
    echo "  ⚠ Dashy deployment not found — deploy manifests first"
fi

echo ""
echo "Done. Access Dashy at: http://$SERVER_IP:30100"
echo "      SSE Check at:    http://$SERVER_IP:30550"
