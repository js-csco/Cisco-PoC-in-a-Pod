# Cisco PoC in a Pod (PiAP)

A single-script lab environment that deploys a full Zero Trust demonstration stack on a single Ubuntu VM:
K3s · Cilium (CNI + network policies) · Hubble (observability) · Tetragon (runtime security) · Cisco Secure Access Resource Connector · Splunk · and a set of target workloads (nginx, SSH, RDP, Kanboard, Dashy).

---

## VM Requirements

### Hardware

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU cores | 4 | 8 |
| RAM | 8 GB | 16 GB |
| Disk | 60 GB | 100 GB |
| Architecture | x86-64 (amd64) | x86-64 (amd64) |

> **Why so much RAM?**
> Splunk alone needs ~4 GB. Add K3s, Cilium, Tetragon, the Docker-based Resource Connector, and several workload pods and you will hit 8 GB quickly. Running below 12 GB will result in Splunk being OOMKilled.

### Operating System

- **Ubuntu 24.04 LTS** (Server or Desktop) — the only tested and supported OS
- Fresh install preferred — the setup script assumes no prior Docker, k3s, or Cilium installation

### Network

- **Internet access required** — the script downloads k3s, Cilium, Helm, Tetragon, Docker, the Cisco connector, and all container images during setup (~5–10 GB total)
- The VM must be reachable from your browser on the following ports after setup:

| Port | Service |
|------|---------|
| 30100 | Dashy dashboard |
| 30200 | Splunk Web |
| 30800 | Hubble UI |
| 30900 | Automagic server |

- If **ufw** is active, open those ports or disable it before running setup:
  ```bash
  sudo ufw disable
  # or selectively:
  sudo ufw allow 30100,30200,30800,30900/tcp
  ```

- **Hypervisor network mode**: use **Bridged** or a mode that gives the VM its own routable IP on your LAN. NAT-only mode works for the lab itself but means you cannot reach the NodePorts from your host browser.

---

## Prerequisites

Install these **before** cloning the repo:

```bash
sudo apt-get update
sudo apt-get install -y git curl
```

> `git` is not included in Ubuntu 24 minimal installs. The setup script assumes `curl` is present. Run the two commands above first on any fresh VM.

---

## Credentials You Need Before Starting

The setup script is **interactive** and will pause twice to ask for credentials. Have these ready:

### 1. Cisco Secure Access — Resource Connector credentials
- Log in to your Cisco Secure Access dashboard
- Navigate to **Connect → Network Connections → Resource Connectors**
- Create or select a Connector Group and copy the **Connector Name** and **Connector Key**

### 2. Splunk admin password
- Choose a password (minimum 8 characters) — you will set this during setup
- You will use it to log in to Splunk at `http://<server-ip>:30200` with username `admin`

---

## Installation

```bash
git clone https://github.com/js-csco/piap-k3s.git
cd piap-k3s/setup
chmod +x setup-k3s.sh
sudo ./setup-k3s.sh
```

The script runs fully automated (~10–20 minutes depending on internet speed) and will:

1. Create required directory symlinks
2. Install K3s (without default CNI)
3. Install Helm
4. Install Cilium 1.16.5 with native routing and kube-proxy replacement
5. Enable Hubble UI (exposed on NodePort 30800)
6. Install Tetragon
7. **Prompt for Cisco Connector credentials** → download and launch the Resource Connector via Docker
8. Register the Connector as a Kubernetes service
9. **Prompt for Splunk password**
10. Deploy all workload pods to the `piap` namespace

---

## After Setup

### Access your services

| Service | URL |
|---------|-----|
| Automagic dashboard | `http://<server-ip>:30900` |
| Dashy | `http://<server-ip>:30100` |
| Splunk | `http://<server-ip>:30200` |
| Hubble UI | `http://<server-ip>:30800/?namespace=piap` |

> Find your server IP with: `hostname -I | awk '{print $1}'`

### Check that everything is running

```bash
# All piap pods should reach Running state
kubectl get pods -n piap

# Cilium and Hubble should be OK
cilium status

# Connector container should be up
docker ps | grep connector
```

### Splunk post-setup steps (manual)

Splunk requires a few manual steps after first login:

1. Open `http://<server-ip>:30200` → login with `admin` / your chosen password
2. Accept the Splunk Free License: **Settings → Licensing**
3. Install the **Cisco Security Cloud** app from Splunkbase (Apps → Find More Apps)
4. Install the **Splunk MCP Server** app from Splunkbase

---

## Useful Commands

```bash
# Kubernetes
kubectl get pods -n piap
kubectl get svc -n piap
kubectl logs <pod-name> -n piap

# Cilium
cilium status
kubectl get ciliumnetworkpolicy -n piap

# Tetragon
kubectl get tracingpolicy

# Connector
docker ps | grep connector
docker logs $(docker ps --format '{{.Names}}' | grep connector)
```

---

## Troubleshooting

**Pods stuck in `Pending`**
→ Cilium may still be starting. Run `cilium status --wait` and retry.

**Splunk pod in `OOMKilled`**
→ The VM needs more RAM. 16 GB recommended. Splunk needs at least 4 GB headroom.

**Connector not reaching Cisco cloud**
→ Check `docker logs <connector-container>`. Ensure the VM has outbound HTTPS access. Verify the Connector Name and Key are correct in the Cisco SSE dashboard.

**NodePorts not reachable from browser**
→ Check `sudo ufw status`. Disable ufw or open the required ports.

**Cilium not reaching Ready**
→ On some hypervisors, `routingMode=native` requires the VM NIC to be in bridged mode. Check `cilium status` output for details.
