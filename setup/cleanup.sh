#!/bin/bash
set -e

echo "================================================"
echo "  Complete K3s + Cilium Cleanup"
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
echo "  - All iptables rules"
echo "  - All symlinks created for applications"
echo ""
read -p "Are you sure you want to continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Cleanup cancelled."
    exit 0
fi

echo ""
echo "Step 1: Uninstalling K3s..."
if command -v k3s-uninstall.sh &> /dev/null; then
    /usr/local/bin/k3s-uninstall.sh
    echo "  ✓ K3s uninstalled"
else
    echo "  K3s not found, skipping..."
fi
echo ""

echo "Step 2: Removing Cilium CLI..."
if command -v cilium &> /dev/null; then
    rm -f /usr/local/bin/cilium
    echo "  ✓ Cilium CLI removed"
else
    echo "  Cilium CLI not found, skipping..."
fi
echo ""

echo "Step 3: Cleaning up Cilium iptables rules..."
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

echo "Step 4: Removing application symlinks..."
rm -f /automagic-server && echo "  ✓ /automagic-server removed" || true
rm -f /kanboard && echo "  ✓ /kanboard removed" || true
rm -f /dashy && echo "  ✓ /dashy removed" || true
rm -f /web && echo "  ✓ /web removed" || true
echo ""

echo "Step 5: Cleaning up Cilium BPF filesystem..."
rm -rf /sys/fs/bpf/cilium 2>/dev/null || true
echo "  ✓ Cilium BPF filesystem cleaned"
echo ""

echo "Step 6: Removing CNI configuration..."
rm -rf /etc/cni/net.d/* 2>/dev/null || true
rm -rf /opt/cni/bin/cilium* 2>/dev/null || true
echo "  ✓ CNI configuration removed"
echo ""

echo "Step 7: Cleaning up systemd services..."
systemctl stop k3s 2>/dev/null || true
systemctl disable k3s 2>/dev/null || true
rm -f /etc/systemd/system/k3s.service 2>/dev/null || true
systemctl daemon-reload
echo "  ✓ Systemd services cleaned"
echo ""

echo "Step 8: Removing Helm if installed..."
if command -v helm &> /dev/null; then
    read -p "Remove Helm? (yes/no): " REMOVE_HELM
    if [ "$REMOVE_HELM" = "yes" ]; then
        rm -f /usr/local/bin/helm
        echo "  ✓ Helm removed"
    else
        echo "  Helm kept"
    fi
else
    echo "  Helm not found, skipping..."
fi
echo ""

echo "Step 9: Cleaning up kubectl config..."
ACTUAL_USER=${SUDO_USER:-$USER}
rm -rf /home/$ACTUAL_USER/.kube 2>/dev/null || true
echo "  ✓ kubectl config removed"
echo ""

echo "Step 10: Removing leftover directories..."
rm -rf /var/lib/rancher 2>/dev/null || true
rm -rf /var/lib/cni 2>/dev/null || true
rm -rf /run/cilium 2>/dev/null || true
echo "  ✓ Leftover directories removed"
echo ""

echo "================================================"
echo "  Cleanup Complete!"
echo "================================================"
echo ""
echo "Your system is now clean. You can:"
echo "  1. Clone your repo from GitHub"
echo "  2. Run the updated setup.sh script"
echo ""
echo "Reboot recommended to ensure all network changes take effect:"
echo "  sudo reboot"
echo ""