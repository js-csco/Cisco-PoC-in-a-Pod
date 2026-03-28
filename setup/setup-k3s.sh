#!/bin/bash
set -e

echo "================================================"
echo "  K3s + Cilium + Hubble + Tetragon Setup"
echo "================================================"
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
echo "Script directory: $SCRIPT_DIR"
echo "Repository root: $REPO_ROOT"
echo ""

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo: sudo ./setup.sh"
    exit 1
fi

# Get the actual user (not root when using sudo)
ACTUAL_USER=${SUDO_USER:-$USER}
echo "Running as user: $ACTUAL_USER"
echo ""

# Resolve server IP early — used in Cilium install, config updates, and status output.
SERVER_IP=$(hostname -I | awk '{print $1}')
echo "Server IP: $SERVER_IP"

# Detect the primary network interface (the one with the default route).
# Cilium needs this plus docker0 so that NodePort eBPF programs are attached on
# both interfaces — without docker0, connections from the Cisco connector
# container (which exits via docker0) to K3s NodePorts are silently dropped
# because Cilium's kube-proxy replacement only hooks the devices it knows about.
PRIMARY_IFACE=$(ip route | awk '/^default/{print $5; exit}')
echo "Primary interface: $PRIMARY_IFACE"
echo ""

# ============================================================
#  Phase 1: Cisco Resource Connector (BEFORE K3s)
#
#  setup_connector.sh installs Docker and the connector
#  infrastructure.  We then launch the connector as a plain
#  Docker container (managed by daemontools) alongside — not
#  inside — the K3s cluster.
#
#  Running it outside K3s avoids the containerd / Docker
#  conflict on Linux 4.4 kernels and keeps the connector's
#  privileged networking completely separate from the K8s
#  network stack.
# ============================================================

echo "================================================"
echo "  Cisco Secure Access Resource Connector Setup"
echo "================================================"
echo ""

echo "Please enter your connector credentials from Secure Access dashboard:"
echo "(Connect > Network Connection > Connector Groups > *Table*)"
read -p "Enter Connector Name: " CONNECTOR_NAME
read -p "Enter Connector Key: " CONNECTOR_KEY
echo ""

if [ -z "$CONNECTOR_NAME" ] || [ -z "$CONNECTOR_KEY" ]; then
    echo "❌ Connector name and key are required!"
    exit 1
fi

# Step 1: System prep — create symlinks and remove the system containerd package
# so Docker (installed next) can use its own bundled containerd without conflicts.
echo "Step 1: Creating symlinks and preparing system..."
ln -sf "$REPO_ROOT/automagic-server" /automagic-server && echo "  ✓ /automagic-server"
ln -sf "$REPO_ROOT/sse-check" /sse-check && echo "  ✓ /sse-check"
ln -sf "$REPO_ROOT/playbook" /playbook && echo "  ✓ /playbook"
ln -sf "$REPO_ROOT/saml-app" /saml-app && echo "  ✓ /saml-app"

echo "  Removing system containerd package (Docker brings its own)..."
apt-get remove -y containerd 2>/dev/null || true
# Kill any running containerd processes and remove stale sockets so Docker's
# bundled containerd.io can start cleanly on the next systemd invocation.
pkill -f '/usr/bin/containerd' 2>/dev/null || true
rm -f /run/containerd/containerd.sock 2>/dev/null || true
echo "  ✓ System prepared"
echo ""

# Step 2: Download Cisco setup script
echo "Step 2: Downloading Cisco Resource Connector setup script..."
CONNECTOR_SETUP_SCRIPT="/tmp/setup_connector.sh"
curl -o "$CONNECTOR_SETUP_SCRIPT" https://us.repo.acgw.sse.cisco.com/scripts/latest/setup_connector.sh

if [ ! -f "$CONNECTOR_SETUP_SCRIPT" ]; then
    echo "❌ Failed to download setup_connector.sh"
    exit 1
fi

chmod +x "$CONNECTOR_SETUP_SCRIPT"
echo "  ✓ Setup script downloaded"
echo ""

# Step 3: Run the Cisco setup script
# This installs Docker, pulls the connector image, installs AppArmor/seccomp
# profiles, and starts the connector as a Docker container.
# We tolerate a non-zero exit (e.g. the connector health check fails for some
# reason) and verify Docker + image are available ourselves below.
echo "Step 3: Running Cisco Resource Connector installation..."
echo "  This installs Docker, pulls the connector image, and configures security profiles..."
echo ""

"$CONNECTOR_SETUP_SCRIPT" || true

# Verify Docker is installed — hard fail if not (nothing we can do without it).
if ! command -v docker &>/dev/null; then
    echo "❌ Docker was not installed by setup_connector.sh"
    exit 1
fi

# Ensure the docker group exists — docker.socket chowns the socket to this group
# and will fail with status 216/GROUP if the group is missing. The Cisco installer
# does not always create it (e.g. on first-time installs on this kernel).
getent group docker &>/dev/null || groupadd docker

# The Cisco installer can leave Docker in any state: running, stopped, or
# rate-limit-failed. Rather than trying to detect which state we're in (a race —
# Docker may be up when we check but stop a moment later), always do a clean
# restart under our control.
#
# Key details for Linux 4.4 / Ubuntu 24.04:
#   • docker.socket has PartOf=docker.service: stopping the service also stops
#     the socket. Systemd's Restart= then tries to bring back docker.service
#     without a socket fd, fails 3×, and locks the service in "failed" state.
#   • dockerd uses -H fd:// (socket activation), so docker.socket MUST be
#     started before docker.service.
#   • The systemd cgroup driver requires cgroup v2; use cgroupfs on 4.4 kernels.
echo "  Applying Linux 4.4 kernel compatibility settings and restarting Docker..."

# 1. Switch to cgroupfs cgroup driver and configure the Docker bridge.
#
# bip=240.0.0.1/29  — assigns a dedicated, non-internet-routable /29 subnet to
#                     docker0 so the connector gets a stable 240.0.0.x address.
#                     Cilium's fromCIDR: 240.0.0.0/29 policy matches this directly.
# ip-masq=false     — disables Docker's blanket POSTROUTING MASQUERADE rule.
#                     Connector → k8s NodePort traffic keeps its 240.0.0.x source,
#                     so Cilium can enforce identity-based policy without guessing
#                     the cilium_host IP.  Internet-bound traffic (connector →
#                     Cisco cloud) is handled by a single targeted masquerade rule
#                     installed in Step 19.1.
if [ -f /etc/docker/daemon.json ]; then
    python3 -c "
import json
try:
    cfg = json.load(open('/etc/docker/daemon.json'))
except Exception:
    cfg = {}
opts = cfg.get('exec-opts', [])
opts = [o for o in opts if 'cgroupdriver' not in o]
opts.append('native.cgroupdriver=cgroupfs')
cfg['exec-opts'] = opts
cfg['bip'] = '240.0.0.1/29'
cfg['ip-masq'] = False
json.dump(cfg, open('/etc/docker/daemon.json', 'w'), indent=2)
" 2>/dev/null || true
else
    echo '{"exec-opts": ["native.cgroupdriver=cgroupfs"], "bip": "240.0.0.1/29", "ip-masq": false}' > /etc/docker/daemon.json
fi

# 2. Reload unit files, then bring everything to a known-stopped state.
systemctl daemon-reload
systemctl stop docker.service docker.socket 2>/dev/null || true
systemctl reset-failed docker.service docker.socket 2>/dev/null || true
sleep 1

# 3. Start socket first (so systemd holds the fd), then the service.
systemctl start containerd 2>/dev/null || true
systemctl start docker.socket
sleep 1
systemctl start docker.service
sleep 3

if ! docker info &>/dev/null; then
    echo "❌ Docker daemon is not running — cannot continue"
    echo "   Run: journalctl -xe -u docker -u containerd | tail -40"
    exit 1
fi
echo "  ✓ Docker daemon running"

# Read the image name written by setup_connector.sh.
# If setup_connector.sh failed to pull (Docker wasn't up then) but Docker is up
# now after recovery, pull the image ourselves.
CONNECTOR_IMAGE=$(cat /opt/connector/image_name 2>/dev/null || echo "")
if [ -z "$CONNECTOR_IMAGE" ]; then
    echo "  /opt/connector/image_name missing — pulling connector image now..."
    CONNECTOR_IMAGE="ciscosecure/resource-connector:latest"
    docker pull "$CONNECTOR_IMAGE"
    mkdir -p /opt/connector
    echo "$CONNECTOR_IMAGE" > /opt/connector/image_name
fi
echo "  ✓ Connector image: $CONNECTOR_IMAGE"

echo "Step 3.1: Verifying daemontools installation..."
if ! command -v svc &>/dev/null; then
    echo "  ⚠ Warning: daemontools 'svc' not found — connector service management may differ"
else
    echo "  ✓ daemontools installed"
fi
echo ""

# Step 4: Launch the Resource Connector as a Docker container
# The connector runs alongside K3s (not inside it) so its privileged networking
# stays fully separate from the Kubernetes network stack.
echo "Step 4: Launching Resource Connector as Docker container..."

# Stop any connector that setup_connector.sh may have already started so
# connector.sh can do a clean first-boot with the right name and key.
CONNECTOR_SH="/opt/connector/install/connector.sh"

for svc_dir in /etc/service/*connector*; do
    [ -e "$svc_dir" ] || continue
    svc -d "$svc_dir" 2>/dev/null || true
    echo "  ✓ Daemontools service paused: $svc_dir"
done

docker ps -aq --filter name=connector | xargs -r docker rm -f 2>/dev/null || true
echo "  ✓ Any previously running connector container removed"

if [ ! -x "$CONNECTOR_SH" ]; then
    echo "❌ connector.sh not found at $CONNECTOR_SH — was setup_connector.sh run successfully?"
    exit 1
fi

"$CONNECTOR_SH" launch --name "$CONNECTOR_NAME" --key "$CONNECTOR_KEY"
echo "  ✓ Resource Connector running as Docker container (managed by daemontools)"
echo ""

# Install the internet masquerade rule immediately after the connector starts.
# The Docker bridge is configured with ip-masq=false so connector → k8s traffic
# keeps its 240.0.0.x source for Cilium policy matching.  The connector still
# needs to reach Cisco's cloud (registration + keepalives), which requires
# masquerade because 240.0.0.x is non-internet-routable.  Installing this rule
# now prevents any gap between connector launch and the end of setup.
# (Step 19.1 later installs the systemd service that persists this across reboots.)
iptables -t nat -C POSTROUTING -s 240.0.0.0/29 ! -d 10.0.0.0/8 -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 240.0.0.0/29 ! -d 10.0.0.0/8 -j MASQUERADE
echo "  ✓ Connector internet masquerade rule active"
echo ""

# ============================================================
#  Phase 2: K3s + CNI stack
# ============================================================

# Step 5: Install k3s
echo "Step 5: Installing k3s (without default CNI and kube-proxy)..."
if command -v k3s &>/dev/null; then
    echo "  k3s already installed, skipping..."
else
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy --disable-kube-proxy" sh -
    echo "  ✓ k3s installed"
fi
echo ""

# Step 5.1: Configure Docker Hub registry authentication
# Prevents unauthenticated pull rate-limit errors (429) on Docker Hub images
# (nginx:alpine, ubuntu:22.04, busybox, python:3.11-slim, etc.)
echo "Step 5.1: Configuring Docker Hub registry authentication..."
echo ""
echo "Docker Hub credentials are required to avoid pull rate limits."
echo "If you don't have an account, create a free one at https://hub.docker.com"
echo "(Leave empty to use a mirror instead — less reliable)"
echo ""
read -p "Docker Hub Username (or Enter to skip): " DOCKERHUB_USER
if [ -n "$DOCKERHUB_USER" ]; then
    read -s -p "Docker Hub Password or Access Token: " DOCKERHUB_PASSWORD
    echo ""
fi

mkdir -p /etc/rancher/k3s
if [ -n "$DOCKERHUB_USER" ] && [ -n "$DOCKERHUB_PASSWORD" ]; then
    cat > /etc/rancher/k3s/registries.yaml <<EOF
mirrors:
  docker.io:
    endpoint:
      - "https://mirror.gcr.io"
configs:
  "registry-1.docker.io":
    auth:
      username: ${DOCKERHUB_USER}
      password: ${DOCKERHUB_PASSWORD}
EOF
    echo "  ✓ Docker Hub credentials configured (with mirror.gcr.io as fallback)"
else
    cat > /etc/rancher/k3s/registries.yaml <<'EOF'
mirrors:
  docker.io:
    endpoint:
      - "https://mirror.gcr.io"
EOF
    echo "  ✓ Docker Hub mirror configured (mirror.gcr.io) — no credentials"
fi
# k3s reads registries.yaml at startup; restart to apply before any image pulls.
systemctl restart k3s
echo "  Waiting for k3s API server after restart..."
sleep 5
echo ""

# Step 6: Configure kubectl access
echo "Step 6: Configuring kubectl access..."
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
chmod 644 /etc/rancher/k3s/k3s.yaml

mkdir -p /home/$ACTUAL_USER/.kube
cp /etc/rancher/k3s/k3s.yaml /home/$ACTUAL_USER/.kube/config
chown -R $ACTUAL_USER:$ACTUAL_USER /home/$ACTUAL_USER/.kube
echo "  ✓ kubectl configured for user $ACTUAL_USER"
echo ""

# Step 7: Wait for k3s API server
echo "Step 7: Waiting for k3s API server..."
until kubectl get nodes &>/dev/null; do
    echo "  Waiting for k3s API server to respond..."
    sleep 5
done
echo "  ✓ k3s API server is ready (node will become Ready after Cilium is installed)"
echo ""

# Step 8: Install Helm
echo "Step 8: Installing Helm..."
if command -v helm &>/dev/null; then
    echo "  Helm already installed"
else
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    echo "  ✓ Helm installed"
fi
echo ""

# Step 9: Clean up any old Cilium iptables rules
echo "Step 9: Cleaning up any old Cilium iptables rules..."
iptables -t nat -F OLD_CILIUM_POST_nat    2>/dev/null || true
iptables -t nat -F OLD_CILIUM_PRE_nat     2>/dev/null || true
iptables -t nat -F OLD_CILIUM_OUTPUT_nat  2>/dev/null || true
iptables -t nat -X OLD_CILIUM_POST_nat    2>/dev/null || true
iptables -t nat -X OLD_CILIUM_PRE_nat     2>/dev/null || true
iptables -t nat -X OLD_CILIUM_OUTPUT_nat  2>/dev/null || true
echo "  ✓ Cleanup complete"
echo ""

# Step 10: Install Cilium CLI
echo "Step 10: Installing Cilium CLI..."
if command -v cilium &>/dev/null; then
    echo "  Cilium CLI already installed"
else
    CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
    CLI_ARCH=amd64
    if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
    curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
    sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
    tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
    rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
    echo "  ✓ Cilium CLI installed"
fi
echo ""

# Step 11: Install Cilium CNI
echo "Step 11: Installing Cilium CNI with native routing and masquerade..."
echo "  Using API server IP: $SERVER_IP"

cilium install --version 1.16.5 \
  --set routingMode=native \
  --set autoDirectNodeRoutes=true \
  --set ipv4NativeRoutingCIDR=10.0.0.0/8 \
  --set bpf.masquerade=true \
  --set enableIPv4Masquerade=true \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=$SERVER_IP \
  --set k8sServicePort=6443 \
  --set devices="${PRIMARY_IFACE} docker0"

echo "  ✓ Cilium installation started"
echo ""

# Step 12: Wait for Cilium
echo "Step 12: Waiting for Cilium to be ready..."
cilium status --wait
echo "  ✓ Cilium is ready"
echo ""

# Step 12.1: Ensure docker0 is in Cilium's device list.
# This is a no-op on a fresh install (the cilium install command above already
# passes --set devices=...), but is needed when re-running the script against an
# already-running cluster so existing deployments pick up the change.
echo "Step 12.1: Ensuring Cilium watches docker0 for NodePort (connector → K3s)..."
CURRENT_DEVICES=$(kubectl get configmap cilium-config -n kube-system \
  -o jsonpath='{.data.devices}' 2>/dev/null || true)
WANT_DEVICES="${PRIMARY_IFACE} docker0"
if [ "$CURRENT_DEVICES" != "$WANT_DEVICES" ]; then
    kubectl patch configmap cilium-config -n kube-system \
        --type merge \
        -p "{\"data\":{\"devices\":\"${WANT_DEVICES}\"}}"
    echo "  Restarting Cilium daemonset to apply new device list..."
    kubectl rollout restart daemonset/cilium -n kube-system
    kubectl rollout status daemonset/cilium -n kube-system --timeout=120s || true
    echo "  ✓ Cilium device list updated: ${WANT_DEVICES}"
else
    echo "  ✓ Cilium device list already correct: ${CURRENT_DEVICES}"
fi
echo ""

# Step 13: Enable Hubble
echo "Step 13: Enabling Hubble..."
cilium hubble enable --ui
echo "  Waiting for Hubble to be ready..."
kubectl wait --for=condition=Ready pod -l k8s-app=hubble-relay -n kube-system --timeout=120s || true
kubectl wait --for=condition=Ready pod -l k8s-app=hubble-ui   -n kube-system --timeout=120s || true
echo "  Exposing Hubble UI on NodePort 30800..."
kubectl patch svc hubble-ui -n kube-system -p '{"spec":{"type":"NodePort","ports":[{"port":80,"targetPort":8081,"nodePort":30800}]}}'
echo "  ✓ Hubble enabled and accessible on port 30800"
echo ""

# Step 14: Install Tetragon
echo "Step 14: Installing Tetragon..."
helm repo add cilium https://helm.cilium.io 2>/dev/null || true
helm repo update
helm install tetragon cilium/tetragon -n kube-system --create-namespace || echo "  Tetragon already installed"
echo "  Waiting for Tetragon to be ready..."
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=tetragon -n kube-system --timeout=120s || true
echo "  ✓ Tetragon installed"
echo ""

# Step 15: Verify DNS and connectivity
echo "Step 15: Verifying DNS and internet connectivity..."
kubectl run test-dns --image=busybox --rm -i --restart=Never --timeout=30s -- nslookup google.com > /dev/null 2>&1 \
    && echo "  ✓ DNS is working" \
    || echo "  ⚠ DNS test failed (you may need to check your network)"
echo ""

# ============================================================
#  Phase 3: Deploy K8s applications (connector excluded)
# ============================================================

# Step 16: Prompt for Splunk admin password (optional)
echo "  Splunk will be deployed from the Automagic dashboard (requires a valid license)."
echo ""

# Step 17: Update configuration files with server IP
echo "Step 17: Updating configuration files..."

# Detect the connector's source IP as seen by apps inside the cluster.
# Try docker inspect first; if the connector uses host-networking or a
# non-bridge network, fall back to the secondary host NIC IP.
CONNECTOR_IP=$(docker inspect "$CONNECTOR_NAME" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null \
    | tr ' ' '\n' | grep -v '^$' | grep -v '^172\.17\.' | head -1)
if [ -z "$CONNECTOR_IP" ]; then
    CONNECTOR_IP=$(hostname -I | tr ' ' '\n' \
        | grep -v "^$SERVER_IP$" | grep -v '^127\.' | grep -v '^::' | head -1)
fi
CONNECTOR_IP=${CONNECTOR_IP:-$SERVER_IP}
echo "  Connector source IP (as seen by apps): $CONNECTOR_IP"

# sse-check uses a stable /sse-check symlink — no path replacement needed.
# Patch the sse-check ConfigMap live with the real connector IP after deployment.
echo "  Connector IP will be patched into sse-check ConfigMap after deploy."

if [ -d "$REPO_ROOT/automagic-server/templates" ]; then
    echo "  Updating automagic templates with server IP..."
    find "$REPO_ROOT/automagic-server/templates" -name "*.html" -exec sed -i "s/SERVER_IP/$SERVER_IP/g" {} \;
fi
echo ""

# Step 17.1: Build automagic image and import into k3s containerd
# The automagic deployment uses ghcr.io/js-csco/piap-k3s-automagic:latest which is
# built by CI. On a fresh install without that image, build it locally instead.
echo "Step 17.1: Building automagic image..."
docker build -t ghcr.io/js-csco/piap-k3s-automagic:latest "$REPO_ROOT/automagic-server/"
docker save ghcr.io/js-csco/piap-k3s-automagic:latest | k3s ctr images import -
echo "  ✓ automagic image built and imported into k3s"
echo ""

# Step 17.2: Pre-pull images that k3s containerd may struggle to fetch
# GHCR images and Docker Hub images can hit rate limits or mirror issues.
# Pulling via Docker (which has its own credential chain) and importing
# into k3s containerd is more reliable than letting k3s pull directly.
echo "Step 17.2: Pre-pulling container images via Docker..."
for img in "louislam/uptime-kuma:1" "aquasec/trivy:latest"; do
    echo "  Pulling $img ..."
    docker pull "$img" && docker save "$img" | k3s ctr images import - \
        && echo "  ✓ $img imported into k3s" \
        || echo "  ⚠ Failed to pull $img — k3s will retry on its own"
done
echo ""

# Step 18: Deploy Kubernetes applications
echo "Step 18: Deploying applications to Kubernetes..."

kubectl create namespace piap --dry-run=client -o yaml | kubectl apply -f -

for manifest in "$REPO_ROOT/k8s/"*.yaml; do
    case "$manifest" in
        *splunk*)
            echo "  Skipping $(basename $manifest) — deploy from the Automagic dashboard with a license"
            ;;
        *caldera*)
            echo "  Skipping $(basename $manifest) — deploy from the Automagic dashboard"
            ;;
        *uptime-kuma-seed*)
            echo "  Skipping $(basename $manifest) — will run after pods are ready"
            ;;
        *)
            kubectl apply -f "$manifest" -n piap
            ;;
    esac
done
echo "  ✓ Applications deployed to namespace 'piap'"

# Patch the sse-check ConfigMap with the real connector IP now that the CM exists.
echo "  Patching sse-check-config with connector IP: $CONNECTOR_IP"
kubectl create configmap sse-check-config -n piap \
    --from-literal=default.conf="$(printf 'server {\n    listen 80;\n    root /usr/share/nginx/html;\n    index index.html;\n    ssi on;\n    ssi_silent_errors on;\n    set $connector_ip "%s";\n}\n' "$CONNECTOR_IP")" \
    --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment/sse-check -n piap
echo "  ✓ sse-check connector IP updated"
echo ""

# Step 19: Wait for pods to be ready
echo "Step 19: Waiting for pods to be ready..."
kubectl wait --for=condition=Ready pods --all -n piap --timeout=120s || true
kubectl get pods -n piap
echo ""

# Step 19a: Wait for Uptime-Kuma specifically before seeding
echo "Step 19a: Waiting for Uptime-Kuma to be fully ready..."
kubectl wait --for=condition=Ready pod -l app=uptime-kuma -n piap --timeout=120s || true
# Uptime-Kuma needs extra time after the pod is "Ready" for Socket.IO to initialize
sleep 10

# Step 19b: Seed Uptime-Kuma monitors
echo "Step 19b: Seeding Uptime-Kuma monitors (dark mode, disable auth, add monitors)..."
kubectl delete job uptime-kuma-seed -n piap --ignore-not-found=true
kubectl apply -f "$REPO_ROOT/k8s/uptime-kuma-seed-job.yaml" -n piap
echo "  Waiting for seed job to complete (up to 5 min)..."
if kubectl wait --for=condition=Complete job/uptime-kuma-seed -n piap --timeout=300s; then
    echo "  ✓ Uptime-Kuma monitors seeded successfully"
else
    echo "  ✗ Uptime-Kuma seed job failed. Logs:"
    kubectl logs -n piap -l app=uptime-kuma-seed --tail=30 2>/dev/null || true
    echo ""
    echo "  You can retry manually: kubectl delete job uptime-kuma-seed -n piap && kubectl apply -f k8s/uptime-kuma-seed-job.yaml -n piap"
fi
echo ""

# Step 19.1: Install the connector internet masquerade rule.
#
# Docker is configured with ip-masq=false (daemon.json) so its default blanket
# POSTROUTING MASQUERADE rule is absent.  Cilium's TC hook on docker0 handles
# connector → K8s NodePort traffic directly in eBPF, preserving the 240.0.0.x
# source IP so the fromCIDR: 240.0.0.0/29 policy can match it.
#
# The connector still needs outbound internet access (Cisco cloud registration
# and keepalives).  240.0.0.x is non-internet-routable, so we install ONE
# targeted rule: masquerade only traffic leaving to non-local destinations.
# K8s traffic (10.0.0.0/8) is explicitly excluded, so the source IP is always
# preserved for pod-bound connections.
echo "Step 19.1: Installing connector internet masquerade rule..."

# Apply immediately (idempotent: -C checks first, -A appends only if absent).
iptables -t nat -C POSTROUTING -s 240.0.0.0/29 ! -d 10.0.0.0/8 -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 240.0.0.0/29 ! -d 10.0.0.0/8 -j MASQUERADE

# Persist across reboots via a minimal systemd oneshot service.
cat > /etc/systemd/system/piap-connector-masquerade.service << 'MASQ_EOF'
[Unit]
Description=Connector internet masquerade rule (240.0.0.0/29 to internet)
After=network.target docker.service
Wants=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -t nat -C POSTROUTING -s 240.0.0.0/29 ! -d 10.0.0.0/8 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 240.0.0.0/29 ! -d 10.0.0.0/8 -j MASQUERADE'
ExecStop=/bin/sh -c 'iptables -t nat -D POSTROUTING -s 240.0.0.0/29 ! -d 10.0.0.0/8 -j MASQUERADE 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
MASQ_EOF

systemctl daemon-reload
systemctl enable --now piap-connector-masquerade.service
echo "  ✓ Connector internet masquerade rule installed (static, boot-persistent)"
echo ""

# Step 20: Show access information
echo "================================================"
echo "  Setup Complete!"
echo "================================================"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Cisco Resource Connector Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Status: Running as Docker container (alongside K3s)"
echo "  Name:   $CONNECTOR_NAME"
echo "  Image:  $CONNECTOR_IMAGE"
echo ""
echo "  Check connector container:"
echo "    docker ps --filter name=$CONNECTOR_NAME"
echo ""
echo "  Follow connector logs:"
echo "    docker logs -f $CONNECTOR_NAME"
echo ""
echo "  Manage connector:"
echo "    /opt/connector/install/connector.sh stop"
echo "    /opt/connector/install/connector.sh start"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Your Services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
kubectl get svc -n piap -o wide
echo ""
echo "Hubble UI: http://$SERVER_IP:30800"
echo ""
echo "  Splunk: Deploy from the Automagic dashboard with your Enterprise license."
echo ""
echo "================================================"
echo "  Useful Commands"
echo "================================================"
echo ""
echo "Kubernetes:"
echo "  kubectl get pods -n piap              # Check pod status"
echo "  kubectl get svc -n piap               # Check services"
echo "  kubectl logs <pod-name> -n piap       # View logs"
echo ""
echo "Cilium:"
echo "  cilium status                         # Check Cilium status"
echo "  cilium hubble ui                      # Open Hubble UI"
echo "  kubectl get ciliumnetworkpolicy       # Check network policies"
echo ""
echo "Connector (Docker):"
echo "  docker ps --filter name=$CONNECTOR_NAME     # Check connector container"
echo "  docker logs -f $CONNECTOR_NAME              # Follow connector logs"
echo "  /opt/connector/install/connector.sh stop    # Stop connector"
echo "  /opt/connector/install/connector.sh start   # Start connector"
echo ""
echo "Cleanup:"
echo "  sudo /usr/local/bin/k3s-uninstall.sh  # Uninstall K3s"
echo ""
