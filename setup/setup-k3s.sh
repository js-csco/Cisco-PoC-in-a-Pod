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

# Step 1: Create symlinks for volume mounts
echo "Step 1: Creating symlinks for application directories..."
ln -sf "$REPO_ROOT/automagic-server" /automagic-server && echo "  ✓ /automagic-server"
ln -sf "$REPO_ROOT/kanboard" /kanboard && echo "  ✓ /kanboard"
ln -sf "$REPO_ROOT/dashy" /dashy && echo "  ✓ /dashy"
ln -sf "$REPO_ROOT/web" /web && echo "  ✓ /web"
echo ""

# Step 2: Install k3s
echo "Step 2: Installing k3s (without default CNI)..."
if command -v k3s &> /dev/null; then
    echo "  k3s already installed, skipping..."
else
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy" sh -
    echo "  ✓ k3s installed"
fi
echo ""

# Step 3: Configure kubectl access
echo "Step 3: Configuring kubectl access..."
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
chmod 644 /etc/rancher/k3s/k3s.yaml

# Create .kube config for the user
mkdir -p /home/$ACTUAL_USER/.kube
cp /etc/rancher/k3s/k3s.yaml /home/$ACTUAL_USER/.kube/config
chown -R $ACTUAL_USER:$ACTUAL_USER /home/$ACTUAL_USER/.kube
echo "  ✓ kubectl configured for user $ACTUAL_USER"
echo ""

# Wait for k3s to be ready
echo "Step 4: Waiting for k3s API server..."
sleep 15
until kubectl get nodes &> /dev/null; do
    echo "  Waiting for k3s API server to respond..."
    sleep 5
done
echo "  ✓ k3s API server is ready (node will become Ready after Cilium is installed)"
echo ""

# Step 5: Install Helm if not present
echo "Step 5: Installing Helm..."
if command -v helm &> /dev/null; then
    echo "  Helm already installed"
else
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    echo "  ✓ Helm installed"
fi
echo ""

# Step 6: Install Cilium CLI if not present
echo "Step 6: Installing Cilium CLI..."
if command -v cilium &> /dev/null; then
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

# Step 6: Install Cilium
echo "Step 6: Installing Cilium CNI..."
cilium install --version 1.16.5
echo "  ✓ Cilium installation started"
echo ""

# Step 7: Wait for Cilium to be ready
echo "Step 7: Waiting for Cilium to be ready..."
cilium status --wait
echo "  ✓ Cilium is ready"
echo ""

# Step 8: Enable Hubble
echo "Step 8: Enabling Hubble..."
cilium hubble enable --ui
echo "  Waiting for Hubble to be ready..."
kubectl wait --for=condition=Ready pod -l k8s-app=hubble-relay -n kube-system --timeout=120s || true
kubectl wait --for=condition=Ready pod -l k8s-app=hubble-ui -n kube-system --timeout=120s || true
echo "  Exposing Hubble UI on NodePort 30800..."
kubectl patch svc hubble-ui -n kube-system -p '{"spec":{"type":"NodePort","ports":[{"port":80,"targetPort":8081,"nodePort":30800}]}}'
echo "  ✓ Hubble enabled and accessible on port 30800"
echo ""

# Step 9: Install Tetragon
echo "Step 9: Installing Tetragon..."
helm repo add cilium https://helm.cilium.io 2>/dev/null || true
helm repo update
helm install tetragon cilium/tetragon -n kube-system --create-namespace || echo "  Tetragon already installed"
echo "  Waiting for Tetragon to be ready..."
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=tetragon -n kube-system --timeout=120s || true
echo "  ✓ Tetragon installed"
echo ""

# Step 10: Create namespace and deploy applications
echo "Step 10: Deploying applications..."

# Get the server's primary IP address
SERVER_IP=$(hostname -I | awk '{print $1}')
echo "  Server IP detected: $SERVER_IP"

# Prompt for Cisco Connector credentials
echo ""
echo "=== Connector Configuration ==="
echo "Please enter your connector credentials from Secure Access dashboard:"
echo "(Connect > Network Connection > Connector Groups > *Table*)"
read -p "Enter Connector Name: " CONNECTOR_NAME
read -p "Enter Connector Key: " CONNECTOR_KEY
echo ""

# Update Dashy config with actual server IP
if [ -f "$REPO_ROOT/dashy/conf.yml" ]; then
    echo "  Updating Dashy config with server IP..."
    sed -i "s/SERVER_IP/$SERVER_IP/g" "$REPO_ROOT/dashy/conf.yml"
fi

# Update HTML files with server IP
if [ -f "$REPO_ROOT/web/index.html" ]; then
    echo "  Updating web files with server IP..."
    sed -i "s/SERVER_IP/$SERVER_IP/g" "$REPO_ROOT/web/index.html"
fi

# Update automagic templates if they exist
if [ -d "$REPO_ROOT/automagic-server/templates" ]; then
    echo "  Updating automagic templates with server IP..."
    find "$REPO_ROOT/automagic-server/templates" -name "*.html" -exec sed -i "s/SERVER_IP/$SERVER_IP/g" {} \;
fi

# Create namespace
kubectl create namespace piap --dry-run=client -o yaml | kubectl apply -f -

# Create Connector Secret with user-provided credentials
echo "  Creating Connector credentials..."
kubectl create secret generic connector-creds -n piap \
  --from-literal=connector-name="$CONNECTOR_NAME" \
  --from-literal=connector-key="$CONNECTOR_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -

# Apply all manifests
kubectl apply -f "$REPO_ROOT/k8s/" -n piap
echo "  ✓ Applications deployed to namespace 'piap'"
echo ""

# Step 11: Wait for pods to be ready
echo "Step 11: Waiting for pods to start..."
sleep 10
kubectl get pods -n piap
echo ""

# Step 12: Show access information
echo "================================================"
echo "  Setup Complete!"
echo "================================================"
echo ""
echo "Your services are now accessible at:"
echo ""
kubectl get svc -n piap -o wide
echo ""
echo "Hubble UI: http://$SERVER_IP:30800"
echo ""
echo "Access your services using the NodePort shown above."
echo "Get Started with Dashy: http://$SERVER_IP:30100"
echo ""
echo "Useful commands:"
echo "  kubectl get pods -n piap           # Check pod status"
echo "  kubectl get svc -n piap            # Check services"
echo "  kubectl logs <pod-name> -n piap    # View logs"
echo "  cilium status                      # Check Cilium status"
echo "  cilium hubble ui                   # Open Hubble UI"
echo ""
echo "Note: If you need to uninstall, run: sudo /usr/local/bin/k3s-uninstall.sh"
echo ""