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

echo "Step 5: Cleaning up iptables rules..."
# Remove the connector internet masquerade rule (240.0.0.0/29 → internet).
iptables -t nat -D POSTROUTING -s 240.0.0.0/29 ! -d 10.0.0.0/8 -j MASQUERADE 2>/dev/null || true
echo "  ✓ piap iptables rules removed"

# Remove Cilium iptables rules
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
rm -f /poc-dashboard && echo "  ✓ /poc-dashboard removed" || true
rm -f /saml-app && echo "  ✓ /saml-app removed" || true
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
systemctl stop piap-connector-masquerade.service 2>/dev/null || true
systemctl disable piap-connector-masquerade.service 2>/dev/null || true
rm -f /etc/systemd/system/piap-connector-masquerade.service
echo "  ✓ piap connector masquerade service removed"
systemctl stop k3s 2>/dev/null || true
systemctl disable k3s 2>/dev/null || true
rm -f /etc/systemd/system/k3s.service 2>/dev/null || true
systemctl daemon-reload
echo "  ✓ Systemd services cleaned"
echo ""

echo "Step 10: Removing temporary setup files..."
rm -f /tmp/setup_connector.sh 2>/dev/null || true
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
echo "Restoring config files modified by setup (SERVER_IP substitution)..."
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
git -C "$REPO_ROOT" checkout -- web/index.html poc-dashboard/templates/ 2>/dev/null \
    && echo "  ✓ Config files restored from git" \
    || echo "  ⚠ Could not restore config files — restore manually: git checkout web/index.html poc-dashboard/templates/"
echo ""

echo "================================================"
echo "  Cleanup Complete!"
echo "================================================"
echo ""
echo "What was removed:"
echo "  ✓ K3s cluster and all workloads"
echo "  ✓ Cilium CNI and network policies"
echo "  ✓ Cisco Resource Connector (Docker container, data, AppArmor profile, daemontools service)"
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