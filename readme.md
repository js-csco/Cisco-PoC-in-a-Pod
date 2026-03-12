# Cisco PoC in a Pod (PiAP)

A single-script lab that deploys a full Zero Trust demo stack on one Ubuntu VM.

**Stack:** K3s, Cilium, Hubble, Tetragon, Cisco Secure Access Resource Connector, and target workloads.

---

## Quick Start

```bash
sudo apt-get update && sudo apt-get install -y git curl
git clone https://github.com/js-csco/piap-k3s.git
cd piap-k3s/setup
chmod +x setup-k3s.sh
sudo ./setup-k3s.sh
```

The script is interactive and takes ~10-20 minutes. Have these ready:

1. **Cisco Secure Access** — Connector Name + Key (from SSE dashboard → Connect → Resource Connectors)
2. **Splunk password** *(optional)* — press Enter to skip Splunk

---

## VM Requirements

|  | Without Splunk | With Splunk |
|--|----------------|-------------|
| CPU | 4 cores (6 rec.) | 6 cores (8 rec.) |
| RAM | 8 GB (12 rec.) | 16 GB (20 rec.) |
| Disk | 40 GB (60 rec.) | 80 GB (100 rec.) |
| OS | Ubuntu 24.04 LTS | Ubuntu 24.04 LTS |

- Internet access required (~8-12 GB downloads)
- Disable ufw or open NodePorts: `sudo ufw disable`
- Use **Bridged** networking (not NAT) so NodePorts are reachable from your browser

---

## Services & Ports

| Port | Service | What it does |
|------|---------|-------------|
| 30200 | Automagic | Central demo dashboard + CSA automation |
| 30300 | Uptime Kuma | Status monitoring (login: admin / piap) |
| 30022 | SSH Server | SSH target workload |
| 30389 | RDP Server | RDP target workload |
| 30050 | Kubectl MCP | Kubernetes MCP server (read-only) |
| 30250 | PoC Playbook | Guided test playbook |
| 30400 | SAML Demo | Duo SSO SAML demo app |
| 30550 | SSE Check | SSE access path verification |
| 30600 | Caldera C2 | MITRE Caldera (deploy from Automagic) |
| 30800 | Hubble UI | Network flow observability |
| 30500 | Splunk Web | SIEM (optional) |
| 30501 | Splunk HEC | HTTP Event Collector (optional) |

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
