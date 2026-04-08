# Cisco Zero Trust — PoC in a Pod

A single-script lab that deploys a full Zero Trust demo stack on one Ubuntu VM.

**Stack:** K3s, Cilium, Hubble, Tetragon, Cisco Secure Access Resource Connector, and target workloads.

---

## VM Requirements

Runs on [Ubuntu Server 24.04 LTS](https://ubuntu.com/download/server). Use **Bridged** networking (not NAT) so services are reachable from your browser.

|  | Without Splunk | With Splunk |
|--|----------------|-------------|
| CPU | 4 cores (6 rec.) | 6 cores (8 rec.) |
| RAM | 8 GB (12 rec.) | 16 GB (20 rec.) |
| Disk | 40 GB (60 rec.) | 80 GB (100 rec.) |

- Internet access required (~8-12 GB downloads)
- Disable ufw or open NodePorts: `sudo ufw disable`
- Deploying the AI Agent alongside Splunk requires at least 20 GB RAM

---

## Quick Start

### Pre-requisites

Have these ready before running the script:

- **Cisco Secure Access & Cisco Duo tenants** — contact your Cisco team
- **Cisco Secure Access** — Connector Name + Key (from SSE dashboard → Connect → Resource Connectors)
- **Splunk password** *(optional)* — press Enter during setup to skip Splunk

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
| 30050 | Kubectl MCP | Kubernetes MCP server (read-only) | Core |
| 30250 | PoC Playbook | Guided test playbook | Core |
| 30400 | SAML Demo | Duo SSO SAML demo app | Core |
| 30550 | SSE Check | SSE access path verification | Core |
| 30300 | Uptime Kuma | Status monitoring (login: admin / C1scoPoC!) | Core |
| 30800 | Hubble UI | Network flow observability (Cilium) | Core |
| 30500 | Splunk Web | SIEM (deploy on setup) | Optional |
| 30501 | Splunk HEC | HTTP Event Collector | Optional |
| 30600 | Caldera C2 | MITRE Caldera (deploy from PoC Dashboard) | Optional |
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

### Splunk post-setup (optional)

1. Open `http://<server-ip>:30500` → login with `admin` / your password
2. Accept Splunk Free License: Settings → Licensing
3. Install **Cisco Security Cloud** app from Splunkbase

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Pods stuck in `Pending` | Cilium still starting — run `cilium status --wait` |
| Splunk `OOMKilled` | VM needs more RAM (16 GB min for Splunk) |
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
