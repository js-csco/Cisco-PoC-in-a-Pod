#!/bin/bash
set -e

echo "================================================"
echo "  Complete K3s + Cilium + Connector Cleanup"
echo "================================================"
echo ""

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo: sudo ./cleanup.sh"
    exit 1
fi

echo "WARNING: This will remove:"
echo "  - K3s cluster and all workloads"
echo "  - Cilium and all networking components"
echo "  - Cisco Resource Connector (container and installation)"
echo "  - All Kubernetes resources (piap namespace, secrets, services)"
echo "  - All iptables rules"
echo "  - All symlinks created for applications"
echo "  - Temporary setup files"
echo "  - Python packages (duo-client)"
echo ""
read -p "Are you sure you want to continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Cleanup cancelled."
    exit 0
fi

# Get the actual user (not root when using sudo)
ACTUAL_USER=${SUDO_USER:-$USER}

echo ""
echo "Step 1: Stopping and removing Cisco Resource Connector..."
# Stop connector if it's running (handles Docker container case)
if [ -f "/opt/connector/install/connector.sh" ]; then
    /opt/connector/install/connector.sh stop 2>/dev/null || true
    echo "  ✓ Connector stopped"
fi

# Remove daemontools service symlink (created by connector.sh launch)
if [ -L "/etc/service/connector_svc" ] || [ -d "/etc/service/connector_svc" ]; then
    rm -rf /etc/service/connector_svc
    echo "  ✓ Daemontools service symlink removed"
fi

# Find and remove connector containers (handles any leftover Docker containers)
CONNECTOR_CONTAINERS=$(docker ps -a --filter "name=resource-connector" --format "{{.Names}}" 2>/dev/null || true)
if [ -n "$CONNECTOR_CONTAINERS" ]; then
    echo "  Removing connector containers..."
    docker rm -f $CONNECTOR_CONTAINERS 2>/dev/null || true
    echo "  ✓ Connector containers removed"
fi

# Remove connector images from Docker
CONNECTOR_IMAGES=$(docker images --filter "reference=*connector*" --format "{{.ID}}" 2>/dev/null || true)
if [ -n "$CONNECTOR_IMAGES" ]; then
    echo "  Removing connector images..."
    docker rmi -f $CONNECTOR_IMAGES 2>/dev/null || true
    echo "  ✓ Connector images removed"
fi

# Unload and remove AppArmor profile installed by setup_connector.sh
if [ -f "/etc/apparmor.d/connector-apparmor.cfg" ]; then
    apparmor_parser -R /etc/apparmor.d/connector-apparmor.cfg 2>/dev/null || true
    rm -f /etc/apparmor.d/connector-apparmor.cfg
    echo "  ✓ AppArmor profile removed"
fi

# Remove packages installed by setup_connector.sh
echo "  Removing packages installed by setup_connector.sh..."
apt-get remove -y daemontools daemontools-run 2>/dev/null || true
echo "  ✓ daemontools removed"

# Remove connector installation directory
if [ -d "/opt/connector" ]; then
    rm -rf /opt/connector
    echo "  ✓ Connector installation directory removed"
fi
echo ""

echo "Step 2: Removing Kubernetes resources..."
if command -v kubectl &> /dev/null; then
    # Set kubeconfig
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    
    # Delete piap namespace (this removes all resources within it)
    kubectl delete namespace piap --ignore-not-found=true 2>/dev/null || true
    echo "  ✓ Namespace 'piap' deleted"
    
    # Delete connector service and endpoints from default namespace
    kubectl delete service connector -n default --ignore-not-found=true 2>/dev/null || true
    kubectl delete endpoints connector -n default --ignore-not-found=true 2>/dev/null || true
    echo "  ✓ Connector service and endpoints deleted"
    
    # Delete Cilium Network Policies
    kubectl delete ciliumnetworkpolicy allow-to-connector -n default --ignore-not-found=true 2>/dev/null || true
    kubectl delete ciliumnetworkpolicy allow-from-connector -n default --ignore-not-found=true 2>/dev/null || true
    echo "  ✓ Cilium network policies deleted"
    
    # Delete Tetragon
    if command -v helm &> /dev/null; then
        helm uninstall tetragon -n kube-system 2>/dev/null || true
        echo "  ✓ Tetragon uninstalled"
    fi
else
    echo "  kubectl not available, skipping Kubernetes resource cleanup..."
fi
echo ""

echo "Step 3: Uninstalling K3s..."
if command -v k3s-uninstall.sh &> /dev/null; then
    /usr/local/bin/k3s-uninstall.sh
    echo "  ✓ K3s uninstalled"
else
    echo "  K3s not found, skipping..."
fi
echo ""

echo "Step 4: Removing Cilium CLI..."
if command -v cilium &> /dev/null; then
    rm -f /usr/local/bin/cilium
    echo "  ✓ Cilium CLI removed"
else
    echo "  Cilium CLI not found, skipping..."
fi
echo ""

echo "Step 5: Cleaning up Cilium iptables rules..."
# Remove Cilium chains
iptables -t nat -F CILIUM_POST_nat 2>/dev/null || true
iptables -t nat -F CILIUM_PRE_nat 2>/dev/null || true
iptables -t nat -F CILIUM_OUTPUT_nat 2>/dev/null || true
iptables -t nat -X CILIUM_POST_nat 2>/dev/null || true
iptables -t nat -X CILIUM_PRE_nat 2>/dev/null || true
iptables -t nat -X CILIUM_OUTPUT_nat 2>/dev/null || true

# Remove old Cilium chains
iptables -t nat -F OLD_CILIUM_POST_nat 2>/dev/null || true
iptables -t nat -F OLD_CILIUM_PRE_nat 2>/dev/null || true
iptables -t nat -F OLD_CILIUM_OUTPUT_nat 2>/dev/null || true
iptables -t nat -X OLD_CILIUM_POST_nat 2>/dev/null || true
iptables -t nat -X OLD_CILIUM_PRE_nat 2>/dev/null || true
iptables -t nat -X OLD_CILIUM_OUTPUT_nat 2>/dev/null || true

# Remove Cilium filter chains
iptables -t filter -F CILIUM_FORWARD 2>/dev/null || true
iptables -t filter -F CILIUM_INPUT 2>/dev/null || true
iptables -t filter -F CILIUM_OUTPUT 2>/dev/null || true
iptables -t filter -X CILIUM_FORWARD 2>/dev/null || true
iptables -t filter -X CILIUM_INPUT 2>/dev/null || true
iptables -t filter -X CILIUM_OUTPUT 2>/dev/null || true

echo "  ✓ Cilium iptables rules cleaned"
echo ""

echo "Step 6: Removing application symlinks..."
rm -f /automagic-server && echo "  ✓ /automagic-server removed" || true
rm -f /kanboard && echo "  ✓ /kanboard removed" || true
rm -f /dashy && echo "  ✓ /dashy removed" || true
rm -f /web && echo "  ✓ /web removed" || true
echo ""

echo "Step 7: Cleaning up Cilium BPF filesystem..."
rm -rf /sys/fs/bpf/cilium 2>/dev/null || true
echo "  ✓ Cilium BPF filesystem cleaned"
echo ""

echo "Step 8: Removing CNI configuration..."
rm -rf /etc/cni/net.d/* 2>/dev/null || true
rm -rf /opt/cni/bin/cilium* 2>/dev/null || true
echo "  ✓ CNI configuration removed"
echo ""

echo "Step 9: Cleaning up systemd services..."
systemctl stop k3s 2>/dev/null || true
systemctl disable k3s 2>/dev/null || true
rm -f /etc/systemd/system/k3s.service 2>/dev/null || true
systemctl daemon-reload
echo "  ✓ Systemd services cleaned"
echo ""

echo "Step 10: Removing temporary setup files..."
rm -f /tmp/setup_connector.sh 2>/dev/null || true
rm -f /tmp/connector-service.yaml 2>/dev/null || true
rm -f /tmp/connector-netpol.yaml 2>/dev/null || true
echo "  ✓ Temporary files removed"
echo ""

echo "Step 11: Removing Python packages..."
if command -v pip3 &> /dev/null; then
    pip3 uninstall -y duo-client 2>/dev/null || true
    echo "  ✓ duo-client removed"
else
    echo "  pip3 not found, skipping..."
fi
echo ""

echo "Step 12: Removing Helm (optional)..."
if command -v helm &> /dev/null; then
    read -p "Remove Helm? (yes/no): " REMOVE_HELM
    if [ "$REMOVE_HELM" = "yes" ]; then
        rm -f /usr/local/bin/helm
        # Remove helm cache and config
        rm -rf /home/$ACTUAL_USER/.cache/helm 2>/dev/null || true
        rm -rf /home/$ACTUAL_USER/.config/helm 2>/dev/null || true
        rm -rf /root/.cache/helm 2>/dev/null || true
        rm -rf /root/.config/helm 2>/dev/null || true
        echo "  ✓ Helm removed"
    else
        echo "  Helm kept"
    fi
else
    echo "  Helm not found, skipping..."
fi
echo ""

echo "Step 13: Docker cleanup (optional)..."
if command -v docker &> /dev/null; then
    read -p "Remove Docker (installed by connector setup)? (yes/no): " REMOVE_DOCKER
    if [ "$REMOVE_DOCKER" = "yes" ]; then
        # Stop docker service
        systemctl stop docker 2>/dev/null || true
        systemctl disable docker 2>/dev/null || true
        
        # Remove docker packages (Ubuntu/Debian)
        apt-get remove -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null || true
        apt-get purge -y docker-ce docker-ce-cli containerd.io 2>/dev/null || true
        apt-get autoremove -y 2>/dev/null || true
        
        # Remove docker directories
        rm -rf /var/lib/docker 2>/dev/null || true
        rm -rf /var/lib/containerd 2>/dev/null || true
        rm -rf /etc/docker 2>/dev/null || true
        rm -rf /root/.docker 2>/dev/null || true
        
        # Remove docker group
        groupdel docker 2>/dev/null || true
        
        echo "  ✓ Docker removed"
    else
        echo "  Docker kept (only connector containers/images were removed)"
    fi
else
    echo "  Docker not found, skipping..."
fi
echo ""

echo "Step 14: Cleaning up kubectl config..."
rm -rf /home/$ACTUAL_USER/.kube 2>/dev/null || true
echo "  ✓ kubectl config removed"
echo ""

echo "Step 15: Removing leftover directories..."
rm -rf /var/lib/rancher 2>/dev/null || true
rm -rf /var/lib/cni 2>/dev/null || true
rm -rf /run/cilium 2>/dev/null || true
rm -rf /etc/rancher 2>/dev/null || true
echo "  ✓ Leftover directories removed"
echo ""

echo "================================================"
echo "  Configuration Files Notice"
echo "================================================"
echo ""
echo "⚠️  Note: The setup script modified the following files"
echo "    by replacing SERVER_IP placeholders:"
echo ""
echo "    - dashy/conf.yml"
echo "    - web/index.html"
echo "    - automagic-server/templates/*.html"
echo ""
echo "    These files were NOT restored to their original state."
echo "    If you have these backed up (e.g., in Git), you can restore them:"
echo ""
echo "    git checkout dashy/conf.yml web/index.html automagic-server/templates/"
echo ""

echo "================================================"
echo "  Cleanup Complete!"
echo "================================================"
echo ""
echo "What was removed:"
echo "  ✓ K3s cluster and all workloads"
echo "  ✓ Cilium CNI and network policies"
echo "  ✓ Cisco Resource Connector (pod, data, AppArmor profile, daemontools service)"
echo "  ✓ All Kubernetes resources (piap namespace, secrets, services)"
echo "  ✓ Tetragon security observability"
echo "  ✓ All iptables rules"
echo "  ✓ Application symlinks"
echo "  ✓ Temporary files"
echo "  ✓ kubectl configuration"
echo "  ✓ daemontools packages"
echo "  ✓ Python packages (duo-client if selected)"
echo ""
echo "Your system is now clean. You can:"
echo "  1. Review your configuration files (check for SERVER_IP placeholders)"
echo "  2. Run the setup.sh script again when ready"
echo ""
echo "Reboot recommended to ensure all network changes take effect:"
echo "  sudo reboot"
echo ""