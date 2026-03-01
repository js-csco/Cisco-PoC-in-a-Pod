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

# Step 1: Create symlinks for volume mounts
echo "Step 1: Creating symlinks for application directories..."
ln -sf "$REPO_ROOT/automagic-server" /automagic-server && echo "  ✓ /automagic-server"
ln -sf "$REPO_ROOT/dashy" /dashy && echo "  ✓ /dashy"
mkdir -p /unittcms/data && echo "  ✓ /unittcms/data"
ln -sf "$REPO_ROOT/unittcms/entrypoint.js" /unittcms/entrypoint.js && echo "  ✓ /unittcms/entrypoint.js"
ln -sf "$REPO_ROOT/web" /web && echo "  ✓ /web"
echo ""

# Step 2: Install k3s
echo "Step 2: Installing k3s (without default CNI and kube-proxy)..."
if command -v k3s &> /dev/null; then
    echo "  k3s already installed, skipping..."
else
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy --disable-kube-proxy" sh -
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

# Step 5.5: Clean up any old Cilium iptables rules
echo "Step 5.5: Cleaning up any old Cilium iptables rules..."
iptables -t nat -F OLD_CILIUM_POST_nat 2>/dev/null || true
iptables -t nat -F OLD_CILIUM_PRE_nat 2>/dev/null || true
iptables -t nat -F OLD_CILIUM_OUTPUT_nat 2>/dev/null || true
iptables -t nat -X OLD_CILIUM_POST_nat 2>/dev/null || true
iptables -t nat -X OLD_CILIUM_PRE_nat 2>/dev/null || true
iptables -t nat -X OLD_CILIUM_OUTPUT_nat 2>/dev/null || true
echo "  ✓ Cleanup complete"
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

# Step 7: Install Cilium with proper configuration
echo "Step 7: Installing Cilium CNI with native routing and masquerade..."
# Get the server's primary IP address for API server configuration
SERVER_IP=$(hostname -I | awk '{print $1}')
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

# Step 8: Wait for Cilium to be ready
echo "Step 8: Waiting for Cilium to be ready..."
cilium status --wait
echo "  ✓ Cilium is ready"
echo ""

# Step 9: Enable Hubble
echo "Step 9: Enabling Hubble..."
cilium hubble enable --ui
echo "  Waiting for Hubble to be ready..."
kubectl wait --for=condition=Ready pod -l k8s-app=hubble-relay -n kube-system --timeout=120s || true
kubectl wait --for=condition=Ready pod -l k8s-app=hubble-ui -n kube-system --timeout=120s || true
echo "  Exposing Hubble UI on NodePort 30800..."
kubectl patch svc hubble-ui -n kube-system -p '{"spec":{"type":"NodePort","ports":[{"port":80,"targetPort":8081,"nodePort":30800}]}}'
echo "  ✓ Hubble enabled and accessible on port 30800"
echo ""

# Step 10: Install Tetragon
echo "Step 10: Installing Tetragon..."
helm repo add cilium https://helm.cilium.io 2>/dev/null || true
helm repo update
helm install tetragon cilium/tetragon -n kube-system --create-namespace || echo "  Tetragon already installed"
echo "  Waiting for Tetragon to be ready..."
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=tetragon -n kube-system --timeout=120s || true
echo "  ✓ Tetragon installed"
echo ""

# Step 11: Verify DNS and connectivity
echo "Step 11: Verifying DNS and internet connectivity..."
echo "  Testing DNS resolution..."
kubectl run test-dns --image=busybox --rm -i --restart=Never --timeout=30s -- nslookup google.com > /dev/null 2>&1 && echo "  ✓ DNS is working" || echo "  ⚠ DNS test failed (you may need to check your network)"
echo ""

# Step 12: Deploy Cisco Secure Access Resource Connector
echo "================================================"
echo "  Cisco Secure Access Resource Connector Setup"
echo "================================================"
echo ""

# Prompt for Cisco Connector credentials
echo "Please enter your connector credentials from Secure Access dashboard:"
echo "(Connect > Network Connection > Connector Groups > *Table*)"
read -p "Enter Connector Name: " CONNECTOR_NAME
read -p "Enter Connector Key: " CONNECTOR_KEY
echo ""

# Validate inputs
if [ -z "$CONNECTOR_NAME" ] || [ -z "$CONNECTOR_KEY" ]; then
    echo "❌ Connector name and key are required!"
    exit 1
fi

echo "Step 12.1: Preparing system for Cisco Resource Connector..."
echo "  Removing conflicting containerd package (Docker will install its own)..."
apt-get remove -y containerd 2>/dev/null || true
echo "  ✓ System prepared"
echo ""

echo "Step 12.2: Downloading Cisco Resource Connector setup script..."
CONNECTOR_SETUP_SCRIPT="/tmp/setup_connector.sh"
curl -o "$CONNECTOR_SETUP_SCRIPT" https://us.repo.acgw.sse.cisco.com/scripts/latest/setup_connector.sh

if [ ! -f "$CONNECTOR_SETUP_SCRIPT" ]; then
    echo "❌ Failed to download setup_connector.sh"
    exit 1
fi

chmod +x "$CONNECTOR_SETUP_SCRIPT"
echo "  ✓ Setup script downloaded"
echo ""

echo "Step 12.3: Running Cisco Resource Connector installation..."
echo "  This will install Docker, download the connector image, and configure security policies..."
echo ""

# Run the Cisco setup script
"$CONNECTOR_SETUP_SCRIPT"

if [ $? -ne 0 ]; then
    echo "❌ Connector installation failed!"
    exit 1
fi

echo "  ✓ Connector installed successfully"
echo ""

echo "Step 12.4: Verifying daemontools installation..."
if ! command -v svc &> /dev/null; then
    echo "  ⚠ Warning: daemontools 'svc' command not found"
    echo "  This may cause issues with connector service management"
else
    echo "  ✓ daemontools installed correctly"
fi
echo ""

echo "Step 12.5: Launching Resource Connector..."
# Launch the connector with provided credentials
sudo /opt/connector/install/connector.sh launch --name "$CONNECTOR_NAME" --key "$CONNECTOR_KEY"

if [ $? -ne 0 ]; then
    echo "❌ Connector launch failed!"
    exit 1
fi

echo "  ✓ Resource Connector launched"
echo ""

echo "Step 12.6: Verifying connector status..."
sleep 10

# Fix: Use the actual connector name, not "resource-connector"
CONNECTOR_CONTAINER=$(docker ps --format "{{.Names}}" | grep -i connector | head -n 1)
if [ -z "$CONNECTOR_CONTAINER" ]; then
    echo "⚠ Warning: Could not find running connector container"
    echo "  Checking all containers..."
    docker ps -a
    CONNECTOR_IP=$SERVER_IP
else
    echo "  ✓ Connector container running: $CONNECTOR_CONTAINER"
    
    # Check connector logs for errors
    echo "  Checking connector logs..."
    docker logs "$CONNECTOR_CONTAINER" 2>&1 | tail -n 20
    
    # Get connector IP
    CONNECTOR_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONNECTOR_CONTAINER")
    if [ -z "$CONNECTOR_IP" ]; then
        # If no bridge IP, it might be using host network
        CONNECTOR_IP=$SERVER_IP
        echo "  Connector using host network"
    fi
    echo "  Connector IP: $CONNECTOR_IP"
fi
echo ""

# Step 13: Register Connector with Cilium (Simple approach)
echo "Step 13: Creating Kubernetes Service for Resource Connector..."

# Detect connector ports
CONNECTOR_PORTS=$(docker port "$CONNECTOR_CONTAINER" 2>/dev/null || echo "")
if [ -n "$CONNECTOR_PORTS" ]; then
    echo "  Detected connector ports: $CONNECTOR_PORTS"
else
    echo "  Could not detect ports (connector may use host network or custom config)"
fi

# Create Service and Endpoints
cat > /tmp/connector-service.yaml <<EOF
apiVersion: v1
kind: Service
metadata:
  name: connector
  namespace: default
  labels:
    app: connector
spec:
  type: ClusterIP
  clusterIP: None
  ports:
  - port: 443
    protocol: TCP
    name: https
  - port: 80
    protocol: TCP
    name: http
---
apiVersion: v1
kind: Endpoints
metadata:
  name: connector
  namespace: default
subsets:
- addresses:
  - ip: ${CONNECTOR_IP}
  ports:
  - port: 443
    name: https
  - port: 80
    name: http
EOF

kubectl apply -f /tmp/connector-service.yaml
echo "  ✓ Service created: connector.default.svc.cluster.local"
echo ""

# Step 13.1: Create permissive Network Policy
echo "Step 13.1: Creating Network Policy (permissive - allows all traffic)..."
cat > /tmp/connector-netpol.yaml <<EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-to-connector
  namespace: default
spec:
  description: "Allow all pods to reach connector"
  endpointSelector: {}
  egress:
  - toCIDR:
    - ${CONNECTOR_IP}/32
  - toFQDNs:
    - matchName: "connector.default.svc.cluster.local"
  - toFQDNs:
    - matchName: "connector"
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-from-connector
  namespace: default
spec:
  description: "Allow traffic from connector to cluster"
  endpointSelector: {}
  ingress:
  - fromCIDR:
    - ${CONNECTOR_IP}/32
EOF

kubectl apply -f /tmp/connector-netpol.yaml
echo "  ✓ Network policies created (CIDR-based, permissive mode)"
echo "  Note: All traffic to/from connector is allowed"
echo ""

# Step 14: Prompt for Splunk admin password (optional)
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

# Step 15: Update configuration files with server IP
echo "Step 15: Updating configuration files..."

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
echo ""

# Step 16: Deploy Kubernetes applications
echo "Step 16: Deploying applications to Kubernetes..."

# Create namespace
kubectl create namespace piap --dry-run=client -o yaml | kubectl apply -f -

# Create Connector Secret (for reference in K8s, even though connector runs externally)
echo "  Creating Connector credentials reference..."
kubectl create secret generic connector-creds -n piap \
  --from-literal=connector-name="$CONNECTOR_NAME" \
  --from-literal=connector-key="$CONNECTOR_KEY" \
  --from-literal=connector-ip="$CONNECTOR_IP" \
  --dry-run=client -o yaml | kubectl apply -f -

# Create Splunk Secret and deploy Splunk only if a password was provided
if [ "$DEPLOY_SPLUNK" = "true" ]; then
    echo "  Creating Splunk credentials..."
    kubectl create secret generic splunk-creds -n piap \
      --from-literal=password="$SPLUNK_PASSWORD" \
      --dry-run=client -o yaml | kubectl apply -f -
fi

# Apply manifests — skip Splunk files if not deploying Splunk
for manifest in "$REPO_ROOT/k8s/"*.yaml; do
    case "$manifest" in
        *splunk*)
            if [ "$DEPLOY_SPLUNK" = "true" ]; then
                kubectl apply -f "$manifest" -n piap
            else
                echo "  Skipping $(basename $manifest) (Splunk not configured)"
            fi
            ;;
        *)
            kubectl apply -f "$manifest" -n piap
            ;;
    esac
done
echo "  ✓ Applications deployed to namespace 'piap'"
echo ""

# Step 17: Wait for pods to be ready
echo "Step 17: Waiting for pods to start..."
sleep 10
kubectl get pods -n piap
echo ""

# Step 18: Show access information
echo "================================================"
echo "  Setup Complete!"
echo "================================================"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🎯 Cisco Resource Connector Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Status: Running as external service"
echo "  Container: ${CONNECTOR_CONTAINER:-Not found}"
echo "  IP Address: $CONNECTOR_IP"
echo "  Service DNS: connector.default.svc.cluster.local"
echo ""
echo "  ✓ Service and Endpoints created"
echo "  ✓ Network policies: PERMISSIVE (all traffic allowed)"
echo "  ✓ Pods can reach connector via: connector.default.svc.cluster.local"
echo ""
echo "  Check connector logs:"
echo "    docker logs ${CONNECTOR_CONTAINER:-<container-name>}"
echo ""
echo "  Verify connector is reaching cloud:"
echo "    docker logs ${CONNECTOR_CONTAINER:-<container-name>} | grep -i 'connect\|auth\|error'"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🌐 Your Services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
kubectl get svc -n piap -o wide
echo ""
echo "Hubble UI: http://$SERVER_IP:30800"
echo "Dashy: http://$SERVER_IP:30100"
echo ""
echo "================================================"
echo "  IMPORTANT: Splunk Setup Required"
echo "================================================"
echo ""
echo "To complete your Splunk setup, follow these steps:"
echo ""
echo "1. Access Splunk Web UI at: http://$SERVER_IP:30200"
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
echo "================================================"
echo "  Useful Commands"
echo "================================================"
echo ""
echo "Kubernetes:"
echo "  kubectl get pods -n piap              # Check pod status"
echo "  kubectl get svc -n piap               # Check services"
echo "  kubectl get svc connector             # Check connector service"
echo "  kubectl logs <pod-name> -n piap       # View logs"
echo ""
echo "Cilium:"
echo "  cilium status                         # Check Cilium status"
echo "  cilium hubble ui                      # Open Hubble UI"
echo "  kubectl get ciliumnetworkpolicy       # Check network policies"
echo ""
echo "Connector:"
echo "  docker ps | grep connector            # Check connector container"
echo "  docker logs ${CONNECTOR_CONTAINER:-<container>}     # View connector logs"
echo "  docker logs -f ${CONNECTOR_CONTAINER:-<container>}  # Follow connector logs"
echo ""
echo "Test connectivity from a pod:"
echo "  kubectl run test --image=nicolaka/netshoot -it --rm -- bash"
echo "  # Inside pod:"
echo "  curl http://connector.default.svc.cluster.local"
echo "  nslookup connector.default.svc.cluster.local"
echo ""
echo "Cleanup:"
echo "  sudo /usr/local/bin/k3s-uninstall.sh  # Uninstall K3s"
echo "  docker rm -f ${CONNECTOR_CONTAINER:-<container>}    # Stop connector"
echo ""