#!/bin/bash

echo "================================================"
echo "  Complete PoC in a Pod Cleanup"
echo "================================================"
echo ""

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo: sudo ./cleanup.sh"
    exit 1
fi

echo "This will permanently delete:"
echo ""
echo "  • K3s cluster and all workloads"
echo "  • Cilium CNI and all network policies"
echo "  • Cisco Resource Connector (container + installation)"
echo "  • All Kubernetes resources (piap namespace, secrets, services)"
echo "  • Tetragon, Hubble, iptables rules, BPF maps"
echo "  • Helm, Docker, Python packages"
echo "  • Application symlinks and temporary files"
echo ""
read -p "Type 'yes' to delete everything: " CONFIRM

case "$CONFIRM" in
    yes|y|YES|Y) ;;
    *)
        echo ""
        echo "Cleanup cancelled."
        exit 0
        ;;
esac

echo ""

# Get the actual user (not root when using sudo)
ACTUAL_USER=${SUDO_USER:-$USER}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Step 1: Cisco Resource Connector ────────────────────────────────────────
echo "Step 1: Removing Cisco Resource Connector..."
if [ -f "/opt/connector/install/connector.sh" ]; then
    /opt/connector/install/connector.sh stop 2>/dev/null || true
    echo "  ✓ Connector stopped"
fi
if [ -L "/etc/service/connector_svc" ] || [ -d "/etc/service/connector_svc" ]; then
    rm -rf /etc/service/connector_svc
    echo "  ✓ Daemontools service symlink removed"
fi
CONNECTOR_IMAGES=$(docker images --filter "reference=*connector*" --format "{{.ID}}" 2>/dev/null || true)
if [ -n "$CONNECTOR_IMAGES" ]; then
    docker rmi -f $CONNECTOR_IMAGES 2>/dev/null || true
    echo "  ✓ Connector images removed"
fi
if [ -f "/etc/apparmor.d/connector-apparmor.cfg" ]; then
    apparmor_parser -R /etc/apparmor.d/connector-apparmor.cfg 2>/dev/null || true
    rm -f /etc/apparmor.d/connector-apparmor.cfg
    echo "  ✓ AppArmor profile removed"
fi
apt-get remove -y daemontools daemontools-run 2>/dev/null || true
echo "  ✓ daemontools removed"
rm -rf /opt/connector
echo "  ✓ Connector installation directory removed"
echo ""

# ── Step 2: Kubernetes resources ────────────────────────────────────────────
echo "Step 2: Removing Kubernetes resources..."
if command -v kubectl &>/dev/null; then
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    kubectl delete namespace piap --ignore-not-found=true 2>/dev/null || true
    echo "  ✓ Namespace 'piap' deleted"
    if command -v helm &>/dev/null; then
        helm uninstall tetragon -n kube-system 2>/dev/null || true
        echo "  ✓ Tetragon uninstalled"
    fi
else
    echo "  kubectl not available, skipping..."
fi
echo ""

# ── Step 3: K3s ─────────────────────────────────────────────────────────────
echo "Step 3: Uninstalling K3s..."
if command -v k3s-uninstall.sh &>/dev/null; then
    /usr/local/bin/k3s-uninstall.sh
    echo "  ✓ K3s uninstalled"
else
    echo "  K3s not found, skipping..."
fi
echo ""

# ── Step 4: Cilium CLI ───────────────────────────────────────────────────────
echo "Step 4: Removing Cilium CLI..."
rm -f /usr/local/bin/cilium && echo "  ✓ Cilium CLI removed" || true
echo ""

# ── Step 5: iptables ─────────────────────────────────────────────────────────
echo "Step 5: Cleaning up iptables rules..."
iptables -t nat -D POSTROUTING -s 240.0.0.0/29 ! -d 10.0.0.0/8 -j MASQUERADE 2>/dev/null || true
for chain in CILIUM_POST_nat CILIUM_PRE_nat CILIUM_OUTPUT_nat \
             OLD_CILIUM_POST_nat OLD_CILIUM_PRE_nat OLD_CILIUM_OUTPUT_nat; do
    iptables -t nat -F "$chain" 2>/dev/null || true
    iptables -t nat -X "$chain" 2>/dev/null || true
done
for chain in CILIUM_FORWARD CILIUM_INPUT CILIUM_OUTPUT; do
    iptables -t filter -F "$chain" 2>/dev/null || true
    iptables -t filter -X "$chain" 2>/dev/null || true
done
echo "  ✓ iptables rules cleaned"
echo ""

# ── Step 6: Application symlinks ────────────────────────────────────────────
echo "Step 6: Removing application symlinks..."
rm -f /poc-dashboard /saml-app /playbook /sse-check
echo "  ✓ Symlinks removed"
echo ""

# ── Step 7: Cilium BPF filesystem ───────────────────────────────────────────
echo "Step 7: Cleaning up Cilium BPF filesystem..."
rm -rf /sys/fs/bpf/cilium 2>/dev/null || true
echo "  ✓ Cilium BPF filesystem cleaned"
echo ""

# ── Step 8: CNI configuration ───────────────────────────────────────────────
echo "Step 8: Removing CNI configuration..."
rm -rf /etc/cni/net.d/* 2>/dev/null || true
rm -rf /opt/cni/bin/cilium* 2>/dev/null || true
echo "  ✓ CNI configuration removed"
echo ""

# ── Step 9: Systemd services ─────────────────────────────────────────────────
echo "Step 9: Removing systemd services..."
for svc in piap-connector-masquerade k3s; do
    systemctl stop   "$svc.service" 2>/dev/null || true
    systemctl disable "$svc.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/$svc.service"
done
systemctl daemon-reload
echo "  ✓ Systemd services removed"
echo ""

# ── Step 10: Helm ────────────────────────────────────────────────────────────
echo "Step 10: Removing Helm..."
rm -f /usr/local/bin/helm
rm -rf /home/$ACTUAL_USER/.cache/helm /home/$ACTUAL_USER/.config/helm \
       /root/.cache/helm /root/.config/helm 2>/dev/null || true
echo "  ✓ Helm removed"
echo ""

# ── Step 11: Docker ──────────────────────────────────────────────────────────
echo "Step 11: Removing Docker..."
if command -v docker &>/dev/null; then
    systemctl stop docker 2>/dev/null || true
    systemctl disable docker 2>/dev/null || true
    apt-get remove -y docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin 2>/dev/null || true
    apt-get purge -y docker-ce docker-ce-cli containerd.io 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true
    rm -rf /var/lib/docker /var/lib/containerd /etc/docker /root/.docker 2>/dev/null || true
    groupdel docker 2>/dev/null || true
    echo "  ✓ Docker removed"
else
    echo "  Docker not found, skipping..."
fi
echo ""

# ── Step 12: Python packages ─────────────────────────────────────────────────
echo "Step 12: Removing Python packages..."
if command -v pip3 &>/dev/null; then
    pip3 uninstall -y duo-client 2>/dev/null || true
    echo "  ✓ duo-client removed"
fi
echo ""

# ── Step 13: kubectl config ──────────────────────────────────────────────────
echo "Step 13: Removing kubectl config..."
rm -rf /home/$ACTUAL_USER/.kube 2>/dev/null || true
rm -rf /tmp/setup_connector.sh 2>/dev/null || true
echo "  ✓ kubectl config removed"
echo ""

# ── Step 14: Leftover directories ────────────────────────────────────────────
echo "Step 14: Removing leftover directories..."
rm -rf /var/lib/rancher /var/lib/cni /run/cilium /etc/rancher 2>/dev/null || true
echo "  ✓ Leftover directories removed"
echo ""

# ── Step 15: Restore config files ───────────────────────────────────────────
echo "Step 15: Restoring config files modified during setup..."
git -C "$REPO_ROOT" checkout -- poc-dashboard/templates/ 2>/dev/null \
    && echo "  ✓ Config files restored from git" \
    || echo "  ⚠ Could not restore config files — run: git checkout poc-dashboard/templates/"
echo ""

echo "================================================"
echo "  Cleanup Complete!"
echo "================================================"
echo ""
echo "Everything has been removed. Reboot recommended:"
echo "  sudo reboot"
echo ""
