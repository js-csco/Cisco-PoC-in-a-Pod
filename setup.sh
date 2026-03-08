#!/usr/bin/env bash
# PoC in a Pod — full cluster setup
# Run once on a fresh k3s node: bash setup.sh
#
# NodePort map (access via http://<NODE_IP>:<PORT>)
#   30022  ssh-server    (SSH  – user: remote_user / pass: ssh_access)
#   30050  kubectl-mcp   (MCP server for kubectl)
#   30100  dashy         (dashboard)
#   30200  automagic     (this server)
#   30389  rdp-server    (RDP  – user: remote_user / pass: rdp_access)
#   30400  nginx         (victim web server)
#   30500  splunk        (web UI – admin / piap)
#   30501  splunk HEC    (HTTP Event Collector, token: piap-hec-token)
#   30600  caldera       (C2   – admin / admin)

set -euo pipefail

K8S=k8s

log() { echo "▶  $*"; }

# ── 1. Namespace ──────────────────────────────────────────────────────────────
log "Creating namespace..."
kubectl apply -f "$K8S/namespace.yaml"

# ── 2. RBAC (must exist before Deployments reference ServiceAccounts) ─────────
log "Applying RBAC..."
kubectl apply -f "$K8S/automagic-rbac.yaml"
kubectl apply -f "$K8S/kubectl-mcp-rbac.yaml"

# ── 3. Infrastructure: nginx, dashy, SSH, RDP, SSE check ─────────────────────
log "Deploying infrastructure services..."
kubectl apply -f "$K8S/nginx-deployment.yaml"
kubectl apply -f "$K8S/nginx-service.yaml"
kubectl apply -f "$K8S/dashy-deployment.yaml"
kubectl apply -f "$K8S/dashy-service.yaml"
kubectl apply -f "$K8S/ssh-server-deployment.yaml"
kubectl apply -f "$K8S/ssh-server-service.yaml"
kubectl apply -f "$K8S/rdp-server-deployment.yaml"
kubectl apply -f "$K8S/rdp-server-service.yaml"
kubectl apply -f "$K8S/sse-check-deployment.yaml"
kubectl apply -f "$K8S/sse-check-service.yaml"

# ── 4. kubectl MCP server ─────────────────────────────────────────────────────
log "Deploying kubectl MCP server..."
kubectl apply -f "$K8S/kubectl-mcp-deployment.yaml"
kubectl apply -f "$K8S/kubectl-mcp-service.yaml"

# ── 5. Automagic server ───────────────────────────────────────────────────────
log "Deploying automagic server..."
kubectl apply -f "$K8S/automagic-deployment.yaml"
kubectl apply -f "$K8S/automagic-service.yaml"

# ── 6. Caldera adversary emulation ───────────────────────────────────────────
log "Deploying Caldera + victim..."
kubectl apply -f "$K8S/caldera-deployment.yaml"
kubectl apply -f "$K8S/caldera-victim-deployment.yaml"

# ── 7. Splunk + Fluent Bit log forwarder ─────────────────────────────────────
# splunk-deployment.yaml bundles the splunk-creds Secret at the top,
# so it must be applied before fluent-bit-daemonset.yaml.
log "Deploying Splunk + Fluent Bit..."
kubectl apply -f "$K8S/splunk-deployment.yaml"
kubectl apply -f "$K8S/splunk-service.yaml"
kubectl apply -f "$K8S/fluent-bit-daemonset.yaml"

# ── Done ──────────────────────────────────────────────────────────────────────
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo ""
echo "✅  All manifests applied."
echo ""
echo "   Automagic server → http://${NODE_IP}:30200"
echo "   Dashy dashboard  → http://${NODE_IP}:30100"
echo "   Splunk UI        → http://${NODE_IP}:30500  (admin / piap, boots in ~5 min)"
echo "   Caldera C2       → http://${NODE_IP}:30600  (admin / admin)"
echo ""
echo "   Tip: watch pods with:  kubectl get pods -n piap -w"
