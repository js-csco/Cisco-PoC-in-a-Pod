#!/bin/bash
set -e

echo "================================================"
echo "  K3s + Cilium + Hubble + Tetragon + Cisco Resource Connector Setup"
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
echo ""

# ============================================================
#  Phase 1: Cisco Resource Connector (BEFORE K3s)
#
#  setup_connector.sh installs Docker and starts the connector
#  as a Docker container.  We MUST do this before installing
#  K3s because K3s's embedded containerd conflicts with the
#  Docker daemon start-up on Linux 4.4 kernels.
#
#  After setup_connector.sh succeeds we immediately stop the
#  Docker-managed connector so that K8s (started in Phase 2)
#  becomes the sole owner of the container.
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
ln -sf "$REPO_ROOT/dashy" /dashy && echo "  ✓ /dashy"
ln -sf "$REPO_ROOT/web" /web && echo "  ✓ /web"

echo "  Removing system containerd package (Docker brings its own)..."
apt-get remove -y containerd 2>/dev/null || true
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

# Verify Docker is installed and running — hard fail if not.
if ! command -v docker &>/dev/null; then
    echo "❌ Docker was not installed by setup_connector.sh"
    exit 1
fi
if ! docker info &>/dev/null; then
    echo "❌ Docker daemon is not running after setup_connector.sh"
    exit 1
fi

# Read the image name written by setup_connector.sh.
CONNECTOR_IMAGE=$(cat /opt/connector/image_name 2>/dev/null || echo "")
if [ -z "$CONNECTOR_IMAGE" ]; then
    echo "❌ /opt/connector/image_name not found — setup_connector.sh may have failed"
    exit 1
fi
echo "  ✓ Connector image: $CONNECTOR_IMAGE"

echo "Step 3.1: Verifying daemontools installation..."
if ! command -v svc &>/dev/null; then
    echo "  ⚠ Warning: daemontools 'svc' not found — connector service management may differ"
else
    echo "  ✓ daemontools installed"
fi
echo ""

# Step 4: Stop the Docker-managed connector
# K8s will own the connector from here on.  Remove the daemontools service entry
# first so supervise cannot restart the container, then stop the container itself.
echo "Step 4: Stopping Docker connector (K8s will manage it instead)..."

for svc_dir in /etc/service/*connector*; do
    [ -e "$svc_dir" ] || continue
    svc -d "$svc_dir" 2>/dev/null || true
    rm -rf "$svc_dir"
    echo "  ✓ Daemontools service removed: $svc_dir"
done

docker ps -q --filter name=connector | xargs -r docker stop 2>/dev/null || true
docker ps -aq --filter name=connector | xargs -r docker rm  2>/dev/null || true
echo "  ✓ Docker connector container stopped and removed"
echo ""

# Step 5: Initialize connector data (replicates connector.sh first_boot)
# The K8s pod reads these files on startup — they must exist before the pod launches.
echo "Step 5: Initializing connector data (first boot)..."

if [ ! -c /dev/net/tun ]; then
    echo "  /dev/net/tun not found — loading tun kernel module..."
    modprobe tun
fi

mkdir -p /opt/connector/etc
mkdir -p /opt/connector/data/init
mkdir -p /opt/connector/data/anyconnect_logs
touch /opt/connector/etc/hosts
touch /opt/connector/etc/resolv.conf

cp /etc/machine-id /opt/connector/data/init/

resolvectl dns > /opt/connector/data/init/resolvectl.output 2>/dev/null || true

ACAD_VM_LOCAL_IP=$(ip addr show | grep global | grep -v docker | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -n1)

echo "KEY=$CONNECTOR_KEY"                      > /opt/connector/data/init/user-data
echo "ACAD_VM_LOCAL_IP=$ACAD_VM_LOCAL_IP"     >> /opt/connector/data/init/user-data
echo "CNTR_DATA=/opt/connector"                > /opt/connector/data/init/common_config.sh

echo "  ✓ Connector data initialised (KEY written, local IP: $ACAD_VM_LOCAL_IP)"
echo ""

# ============================================================
#  Phase 2: K3s + CNI stack
# ============================================================

# Step 6: Install k3s
echo "Step 6: Installing k3s (without default CNI and kube-proxy)..."
if command -v k3s &>/dev/null; then
    echo "  k3s already installed, skipping..."
else
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy --disable-kube-proxy" sh -
    echo "  ✓ k3s installed"
fi
echo ""

# Step 7: Configure kubectl access
echo "Step 7: Configuring kubectl access..."
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
chmod 644 /etc/rancher/k3s/k3s.yaml

mkdir -p /home/$ACTUAL_USER/.kube
cp /etc/rancher/k3s/k3s.yaml /home/$ACTUAL_USER/.kube/config
chown -R $ACTUAL_USER:$ACTUAL_USER /home/$ACTUAL_USER/.kube
echo "  ✓ kubectl configured for user $ACTUAL_USER"
echo ""

# Step 8: Wait for k3s API server
echo "Step 8: Waiting for k3s API server..."
sleep 15
until kubectl get nodes &>/dev/null; do
    echo "  Waiting for k3s API server to respond..."
    sleep 5
done
echo "  ✓ k3s API server is ready (node will become Ready after Cilium is installed)"
echo ""

# Step 9: Install Helm
echo "Step 9: Installing Helm..."
if command -v helm &>/dev/null; then
    echo "  Helm already installed"
else
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    echo "  ✓ Helm installed"
fi
echo ""

# Step 10: Clean up any old Cilium iptables rules
echo "Step 10: Cleaning up any old Cilium iptables rules..."
iptables -t nat -F OLD_CILIUM_POST_nat    2>/dev/null || true
iptables -t nat -F OLD_CILIUM_PRE_nat     2>/dev/null || true
iptables -t nat -F OLD_CILIUM_OUTPUT_nat  2>/dev/null || true
iptables -t nat -X OLD_CILIUM_POST_nat    2>/dev/null || true
iptables -t nat -X OLD_CILIUM_PRE_nat     2>/dev/null || true
iptables -t nat -X OLD_CILIUM_OUTPUT_nat  2>/dev/null || true
echo "  ✓ Cleanup complete"
echo ""

# Step 11: Install Cilium CLI
echo "Step 11: Installing Cilium CLI..."
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

# Step 12: Install Cilium CNI
echo "Step 12: Installing Cilium CNI with native routing and masquerade..."
echo "  Using API server IP: $SERVER_IP"

cilium install --version 1.16.5 \
  --set routingMode=native \
  --set autoDirectNodeRoutes=true \
  --set ipv4NativeRoutingCIDR=10.0.0.0/8 \
  --set bpf.masquerade=false \
  --set enableIPv4Masquerade=true \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=$SERVER_IP \
  --set k8sServicePort=6443

echo "  ✓ Cilium installation started"
echo ""

# Step 13: Wait for Cilium
echo "Step 13: Waiting for Cilium to be ready..."
cilium status --wait
echo "  ✓ Cilium is ready"
echo ""

# Step 14: Enable Hubble
echo "Step 14: Enabling Hubble..."
cilium hubble enable --ui
echo "  Waiting for Hubble to be ready..."
kubectl wait --for=condition=Ready pod -l k8s-app=hubble-relay -n kube-system --timeout=120s || true
kubectl wait --for=condition=Ready pod -l k8s-app=hubble-ui   -n kube-system --timeout=120s || true
echo "  Exposing Hubble UI on NodePort 30800..."
kubectl patch svc hubble-ui -n kube-system -p '{"spec":{"type":"NodePort","ports":[{"port":80,"targetPort":8081,"nodePort":30800}]}}'
echo "  ✓ Hubble enabled and accessible on port 30800"
echo ""

# Step 15: Install Tetragon
echo "Step 15: Installing Tetragon..."
helm repo add cilium https://helm.cilium.io 2>/dev/null || true
helm repo update
helm install tetragon cilium/tetragon -n kube-system --create-namespace || echo "  Tetragon already installed"
echo "  Waiting for Tetragon to be ready..."
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=tetragon -n kube-system --timeout=120s || true
echo "  ✓ Tetragon installed"
echo ""

# Step 16: Verify DNS and connectivity
echo "Step 16: Verifying DNS and internet connectivity..."
kubectl run test-dns --image=busybox --rm -i --restart=Never --timeout=30s -- nslookup google.com > /dev/null 2>&1 \
    && echo "  ✓ DNS is working" \
    || echo "  ⚠ DNS test failed (you may need to check your network)"
echo ""

# ============================================================
#  Phase 3: Wire connector image into K3s and deploy
# ============================================================

# Step 17: Import connector image from Docker into K3s containerd
# K3s's containerd cache is separate from Docker's — import avoids a registry pull.
echo "Step 17: Importing connector image into K3s containerd..."
echo "  Image: $CONNECTOR_IMAGE"
docker save "$CONNECTOR_IMAGE" | k3s ctr images import -
echo "  ✓ Image imported to K3s"

# Copy the seccomp profile to the K3s kubelet seccomp directory.
mkdir -p /var/lib/rancher/k3s/agent/seccomp
if [ -f /opt/connector/install/connector-seccomp.json ]; then
    cp /opt/connector/install/connector-seccomp.json /var/lib/rancher/k3s/agent/seccomp/
    echo "  ✓ Seccomp profile copied to /var/lib/rancher/k3s/agent/seccomp/"
else
    echo "  ⚠ connector-seccomp.json not found — pod will use RuntimeDefault seccomp"
fi
echo ""

# Step 18: Prompt for Splunk admin password (optional)
echo "================================================"
echo "  Splunk Configuration (optional)"
echo "================================================"
echo ""
echo "Splunk requires a Splunk Enterprise or Free license accepted on first login."
echo "Leave empty and press Enter to skip Splunk — all other services will still deploy."
echo ""
read -s -p "Splunk Admin Password (min 8 chars, or Enter to skip): " SPLUNK_PASSWORD
echo ""

DEPLOY_SPLUNK=false
if [ -n "$SPLUNK_PASSWORD" ]; then
    read -s -p "Confirm Splunk Admin Password: " SPLUNK_PASSWORD_CONFIRM
    echo ""

    if [ "$SPLUNK_PASSWORD" != "$SPLUNK_PASSWORD_CONFIRM" ]; then
        echo "❌ Passwords do not match!"
        exit 1
    fi

    if [ ${#SPLUNK_PASSWORD} -lt 8 ]; then
        echo "❌ Password must be at least 8 characters long!"
        exit 1
    fi

    DEPLOY_SPLUNK=true
    echo "✓ Splunk password set — Splunk will be deployed"
else
    echo "  Skipping Splunk — running without Splunk"
fi
echo ""

# Step 19: Update configuration files with server IP
echo "Step 19: Updating configuration files..."

if [ -f "$REPO_ROOT/dashy/conf.yml" ]; then
    echo "  Updating Dashy config with server IP..."
    sed -i "s/SERVER_IP/$SERVER_IP/g" "$REPO_ROOT/dashy/conf.yml"
fi

if [ -f "$REPO_ROOT/web/index.html" ]; then
    echo "  Updating web files with server IP..."
    sed -i "s/SERVER_IP/$SERVER_IP/g" "$REPO_ROOT/web/index.html"
fi

if [ -d "$REPO_ROOT/automagic-server/templates" ]; then
    echo "  Updating automagic templates with server IP..."
    find "$REPO_ROOT/automagic-server/templates" -name "*.html" -exec sed -i "s/SERVER_IP/$SERVER_IP/g" {} \;
fi
echo ""

# Step 20: Deploy Kubernetes applications
echo "Step 20: Deploying applications to Kubernetes..."

kubectl create namespace piap --dry-run=client -o yaml | kubectl apply -f -

echo "  Creating Connector credentials secret..."
kubectl create secret generic connector-creds -n piap \
  --from-literal=connector-name="$CONNECTOR_NAME" \
  --from-literal=connector-key="$CONNECTOR_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -

if [ "$DEPLOY_SPLUNK" = "true" ]; then
    echo "  Creating Splunk credentials secret..."
    kubectl create secret generic splunk-creds -n piap \
      --from-literal=password="$SPLUNK_PASSWORD" \
      --dry-run=client -o yaml | kubectl apply -f -
fi

for manifest in "$REPO_ROOT/k8s/"*.yaml; do
    case "$manifest" in
        *splunk*)
            if [ "$DEPLOY_SPLUNK" = "true" ]; then
                kubectl apply -f "$manifest" -n piap
            else
                echo "  Skipping $(basename $manifest) (Splunk not configured)"
            fi
            ;;
        *connector-deployment*)
            # K8s spec.hostname must be a valid DNS label (lowercase only).
            # CONNECTOR_NAME is used as-is for Cisco SSE identity; only the
            # K8s hostname gets lowercased.
            CONNECTOR_HOSTNAME=$(echo "$CONNECTOR_NAME" | tr '[:upper:]' '[:lower:]')
            sed \
                -e "s|CONNECTOR_HOSTNAME_PLACEHOLDER|$CONNECTOR_HOSTNAME|g" \
                -e "s|CONNECTOR_IMAGE_PLACEHOLDER|$CONNECTOR_IMAGE|g" \
                "$manifest" | kubectl apply -f - -n piap
            echo "  ✓ connector-deployment applied (hostname: $CONNECTOR_HOSTNAME, image: $CONNECTOR_IMAGE)"
            ;;
        *)
            kubectl apply -f "$manifest" -n piap
            ;;
    esac
done
echo "  ✓ Applications deployed to namespace 'piap'"
echo ""

# Step 21: Wait for pods to start
echo "Step 21: Waiting for pods to start..."
sleep 10
kubectl get pods -n piap
echo ""

# Step 22: Show access information
echo "================================================"
echo "  Setup Complete!"
echo "================================================"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Cisco Resource Connector Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Status: Running as K8s pod in namespace 'piap'"
echo "  Name:   $CONNECTOR_NAME"
echo "  Image:  $CONNECTOR_IMAGE"
echo ""
echo "  ✓ Provisioning data written to /opt/connector/data/init/"
echo "  ✓ Image imported to K3s containerd"
echo "  ✓ AppArmor profile: docker_secure (installed by setup_connector.sh)"
echo ""
echo "  Check connector pod:"
echo "    kubectl get pod -n piap -l app=connector"
echo ""
echo "  Follow connector logs:"
echo "    kubectl logs -n piap -l app=connector -f"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Your Services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
kubectl get svc -n piap -o wide
echo ""
echo "Hubble UI: http://$SERVER_IP:30800"
echo "Dashy: http://$SERVER_IP:30100"
echo ""
if [ "$DEPLOY_SPLUNK" = "true" ]; then
echo "================================================"
echo "  IMPORTANT: Splunk Setup Required"
echo "================================================"
echo ""
echo "To complete your Splunk setup, follow these steps:"
echo ""
echo "1. Access Splunk Web UI at: http://$SERVER_IP:30500"
echo "   Username: admin"
echo "   Password: (the password you just set)"
echo ""
echo "2. Accept the Splunk Free License:"
echo "   - Go to Settings > Licensing"
echo "   - Click 'Add license' or accept the Free license"
echo ""
echo "3. Install required apps from Splunkbase:"
echo "   a) Cisco Security Cloud App:"
echo "      - Go to Apps > Find More Apps"
echo "      - Search for 'Cisco Security Cloud'"
echo "      - Click 'Install' (requires Splunk.com login)"
echo ""
echo "   b) Splunk MCP Server:"
echo "      - Go to Apps > Find More Apps"
echo "      - Search for 'Splunk MCP Server'"
echo "      - Click 'Install'"
echo ""
echo "4. Configure the apps according to their documentation"
echo ""
fi
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
echo "Connector:"
echo "  kubectl get pod -n piap -l app=connector          # Check connector pod"
echo "  kubectl logs -n piap -l app=connector -f          # Follow connector logs"
echo "  kubectl describe pod -n piap -l app=connector     # Debug pod events"
echo ""
echo "Cleanup:"
echo "  sudo /usr/local/bin/k3s-uninstall.sh  # Uninstall K3s"
echo "  kubectl delete pod -n piap -l app=connector       # Restart connector pod"
echo ""
