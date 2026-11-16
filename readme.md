# Cisco Zero Trust — PoC in a Pod

A single-script lab that deploys a full Zero Trust demo stack on one Ubuntu VM.

**Stack:** K3s, Cilium, Hubble, Tetragon, Cisco Secure Access Resource Connector, and target workloads.

---

## VM Requirements

Runs on [Ubuntu Server 24.04 LTS](https://ubuntu.com/download/server). Use **Bridged** networking (not NAT) so services are reachable from your browser.

|  | Core | With AI Agent |
|--|------|---------------|
| CPU | 4 cores (6 rec.) | 6 cores (8 rec.) |
| RAM | 8 GB (12 rec.) | 10 GB (16 rec.) |
| Disk | 40 GB (60 rec.) | 40 GB (60 rec.) |

- Internet access required (~8-12 GB downloads)
- Disable ufw or open NodePorts: `sudo ufw disable`

---

## Quick Start

### Pre-requisites

Have these ready before running the script:

- **Cisco Secure Access & Cisco Duo tenants** — contact your Cisco team

### Create a Resource Connector in Secure Access

The setup script deploys and registers a Resource Connector during installation. You must create the connector in Secure Access **before** running the script so you have the credentials ready when prompted.

1. Log in to the [Secure Access dashboard](https://dashboard.sse.cisco.com)
2. Navigate to **Connect → Resource Connectors**
3. Click **Add** and follow the prompts to create a new connector
4. Copy the **Connector Name** and **Key** — you will be prompted for these during setup

### Deployment

```bash
# Install dependencies
sudo apt-get update && sudo apt-get install -y git curl

# Clone the repository
git clone https://github.com/js-csco/piap-k3s.git

# Run the setup script (~10-20 min, interactive)
cd piap-k3s/setup
chmod +x setup-k3s.sh
sudo ./setup-k3s.sh
```

---

## Services & Ports

| Port | Service | What it does | Tier |
|------|---------|-------------|------|
| 30200 | PoC Dashboard | Central demo dashboard + CSA automation | Core |
| 30022 | SSH Server | SSH target workload | Core |
| 30389 | RDP Server | RDP target workload | Core |
| 30250 | PoC Playbook | Guided test playbook | Core |
| 30400 | SAML Demo | Duo SSO SAML demo app | Core |
| 30550 | SSE Check | SSE access path verification | Core |
| 30800 | Hubble UI | Network flow observability (Cilium) | Core |
| 31789 | AI Agent | DefenseClaw AI agent (deploy from PoC Dashboard) | Optional |

Access any service at `http://<server-ip>:<port>`

---

## After Setup

```bash
# Find your server IP
hostname -I | awk '{print $1}'

# Check pods are running
kubectl get pods -n piap

# Check Cilium + Hubble
cilium status

# Check connector
docker ps | grep connector
```

### AI Agent (OpenClaw + DefenseClaw, optional)

Deploy it from **PoC Dashboard › AI Agents** after saving an LLM provider key.
The pod runs OpenClaw 2026.10.9 with DefenseClaw 1.0.9 in action mode
(blocks at HIGH and above) and needs about 3-5 minutes to install on first start.

- Each new browser that opens the WebChat UI (port 31789) must be paired once:
  click **Approve Browser Pairing** on the AI Agents page, or run
  `kubectl exec -n defenseclaw deploy/ai-agent -- openclaw devices list` and then
  `kubectl exec -n defenseclaw deploy/ai-agent -- openclaw devices approve <requestId>`.
- DefenseClaw decisions appear under **Security Events** on the AI Agents page, or via
  `kubectl exec -n defenseclaw deploy/ai-agent -- defenseclaw alerts`.

### Splunk Observability Cloud (optional)

To see the k3s cluster (nodes, pods, events) and the AI agent's traces in
**Splunk Observability Cloud**, install the Splunk Distribution of the
OpenTelemetry Collector. It ships to your Observability Cloud realm (SaaS).

```bash
export SPLUNK_O11Y_REALM="us1"                      # your realm, e.g. us1 / eu0
export SPLUNK_O11Y_ACCESS_TOKEN="<org-access-token>"  # Settings → Access Tokens (API scope)
cd ~/piap-k3s/setup
sudo -E ./install_splunk_o11y_collector.sh
```

The collector also exposes an in-cluster OTLP endpoint
(`splunk-otel-collector-agent.splunk-otel.svc.cluster.local:4317/4318`).

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Pods stuck in `Pending` | Cilium still starting — run `cilium status --wait` |
| Connector not connecting | Check `docker logs $(docker ps --format '{{.Names}}' \| grep connector)` |
| NodePorts unreachable | Check `sudo ufw status` or switch to bridged networking |
| Cilium not Ready | Some hypervisors need bridged mode for native routing |

---

## Useful Commands

```bash
kubectl get pods -n piap          # Pod status
kubectl get svc -n piap           # Service endpoints
kubectl logs <pod> -n piap        # Pod logs
cilium status                     # Cilium health
kubectl get ciliumnetworkpolicy -n piap   # Network policies
kubectl get tracingpolicy         # Tetragon policies
```
