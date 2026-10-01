#!/usr/bin/env bash
#
# Install the Splunk Distribution of the OpenTelemetry Collector into the PoC
# k3s cluster, pointed at Splunk Observability Cloud (SaaS).
#
# This gives you the *infrastructure* view of "PoC in a Pod" in Observability
# Cloud — k3s node / pod / cluster metrics and events, plus an in-cluster OTLP
# endpoint (ports 4317/4318) that the AI Agent (and anything else) can send
# traces to. It complements:
#   - the existing in-cluster OTel collectors, which ship to the Splunk
#     Enterprise SIEM via HEC (see k8s/otel-collector-*.yaml), and
#   - Splunk Agent Observability, which receives the agent's GenAI traces.
#
# We install the official, Splunk-maintained Helm chart rather than a hand-rolled
# manifest so the collector config stays correct and supported.
#
# Usage:
#   export SPLUNK_O11Y_REALM="us1"                 # your O11y realm, e.g. us1/eu0
#   export SPLUNK_O11Y_ACCESS_TOKEN="<org-access-token>"   # API/ingest token
#   # optional:
#   export CLUSTER_NAME="piap-k3s"
#   export DEPLOY_ENVIRONMENT="piap-poc"
#   sudo -E ./install_splunk_o11y_collector.sh
#
# Re-running is safe (helm upgrade --install).
set -euo pipefail

REALM="${SPLUNK_O11Y_REALM:-}"
TOKEN="${SPLUNK_O11Y_ACCESS_TOKEN:-}"
CLUSTER_NAME="${CLUSTER_NAME:-piap-k3s}"
DEPLOY_ENVIRONMENT="${DEPLOY_ENVIRONMENT:-piap-poc}"
RELEASE="splunk-otel-collector"
NAMESPACE="splunk-otel"
CHART_REPO="https://signalfx.github.io/splunk-otel-collector-chart"

if [[ -z "$REALM" || -z "$TOKEN" ]]; then
  echo "ERROR: set SPLUNK_O11Y_REALM and SPLUNK_O11Y_ACCESS_TOKEN first." >&2
  echo "  Realm: Observability Cloud -> Settings -> (your name) -> Organizations" >&2
  echo "  Token: Observability Cloud -> Settings -> Access Tokens -> New Token (API scope)" >&2
  exit 1
fi

# kubectl must be able to reach the k3s cluster.
if ! command -v kubectl >/dev/null 2>&1; then
  echo "ERROR: kubectl not found. Run this on the PoC k3s host." >&2
  exit 1
fi
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

# Install Helm if it is not already available.
if ! command -v helm >/dev/null 2>&1; then
  echo "==> Installing Helm..."
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

echo "==> Adding the Splunk OpenTelemetry Collector Helm repo..."
helm repo add splunk-otel-collector-chart "$CHART_REPO" >/dev/null 2>&1 || true
helm repo update splunk-otel-collector-chart >/dev/null

echo "==> Installing/upgrading the collector (realm=$REALM, cluster=$CLUSTER_NAME)..."
helm upgrade --install "$RELEASE" splunk-otel-collector-chart/splunk-otel-collector \
  --namespace "$NAMESPACE" --create-namespace \
  --set "clusterName=$CLUSTER_NAME" \
  --set "environment=$DEPLOY_ENVIRONMENT" \
  --set "splunkObservability.realm=$REALM" \
  --set "splunkObservability.accessToken=$TOKEN" \
  --set "splunkObservability.infrastructureMonitoringEventsEnabled=true" \
  --set "agent.discovery.enabled=true"

echo ""
echo "==> Done. Verify with:"
echo "    kubectl get pods -n $NAMESPACE"
echo ""
echo "    Infrastructure metrics appear in Observability Cloud under"
echo "    Infrastructure -> Kubernetes (cluster: $CLUSTER_NAME)."
echo "    The agent's OTLP endpoint is:"
echo "      http://${RELEASE}-agent.${NAMESPACE}.svc.cluster.local:4318  (HTTP)"
echo "      http://${RELEASE}-agent.${NAMESPACE}.svc.cluster.local:4317  (gRPC)"
