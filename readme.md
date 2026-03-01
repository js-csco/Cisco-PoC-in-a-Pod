# Cisco PoC in a Pod (PiAP)

A single-script lab environment that deploys a full Zero Trust demonstration stack on a single Ubuntu VM:
K3s · Cilium (CNI + network policies) · Hubble (observability) · Tetragon (runtime security) · Cisco Secure Access Resource Connector · and a set of target workloads (nginx, SSH, RDP, Dashy).

Splunk is **optional** — skip it by pressing Enter at the password prompt if you do not have a Splunk license or do not need it for the demo.

---

## Setup Profiles

### Profile 1 — Without Splunk (base stack)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU cores | 4 | 6 |
| RAM | 8 GB | 12 GB |
| Disk | 40 GB | 60 GB |
| Architecture | x86-64 (amd64) | x86-64 (amd64) |

**What gets deployed:**

| Pod / Service | Image | Purpose |
|---------------|-------|---------|
| automagic | python:3.11-slim | Central demo dashboard |
| nginx | nginx | Web target workload |
| ssh-server | linuxserver/openssh-server | SSH target workload |
| rdp-server | linuxserver/rdesktop:ubuntu-xfce | RDP target workload |
| dashy | lissy93/dashy | Service overview page |
| kubectl-mcp | kubernetes_mcp_server | MCP server for K8s |
| connector | ciscosecure/resource-connector (Docker) | Cisco Secure Access tunnel |
| cilium agent | (DaemonSet, kube-system) | CNI + network policy enforcement |
| hubble-relay + UI | (kube-system) | Network flow observability |
| tetragon | (kube-system) | Kernel-level runtime security |

**Accessible ports:**

| Port | Service | Protocol |
|------|---------|----------|
| 30022 | SSH server | SSH |
| 30050 | kubectl-mcp | HTTP (MCP) |
| 30100 | Dashy | HTTP |
| 30200 | Automagic dashboard | HTTP |
| 30389 | RDP server | RDP |
| 30400 | nginx | HTTP |
| 30800 | Hubble UI | HTTP |

---

### Profile 2 — With Splunk (full stack)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU cores | 6 | 8 |
| RAM | 16 GB | 20 GB |
| Disk | 80 GB | 100 GB |
| Architecture | x86-64 (amd64) | x86-64 (amd64) |

Everything from Profile 1 **plus**:

| Pod / Service | Image | Purpose |
|---------------|-------|---------|
| splunk | splunk/splunk:latest | SIEM + log aggregation |

Splunk resource allocation:
- Memory request: 2 GB / limit: 4 GB
- CPU request: 1 core / limit: 2 cores
- Persistent data stored on host at `/opt/splunk-data` (grows over time with events)

**Additional ports (Splunk only):**

| Port | Service | Protocol |
|------|---------|----------|
| 30500 | Splunk Web UI | HTTP |
| 30501 | Splunk HEC (HTTP Event Collector) | HTTP |
| 30502 | Splunk API (splunkd) | HTTPS |

---

## VM Requirements (common to both profiles)

### Operating System

- **Ubuntu 24.04 LTS** (Server or Desktop) — the only tested and supported OS
- Fresh install preferred — the script assumes no prior Docker, k3s, or Cilium

### Network

- **Internet access required** — the script downloads k3s, Cilium, Helm, Tetragon, Docker, the Cisco connector, and all container images (~8 GB for Profile 1, ~12 GB for Profile 2)
- If **ufw** is active, open NodePorts or disable it before running setup:
  ```bash
  sudo ufw disable
  # or selectively — Profile 1:
  sudo ufw allow 30022,30050,30100,30200,30389,30400,30800/tcp
  # add these for Profile 2 (Splunk):
  sudo ufw allow 30500,30501,30502/tcp
  ```
- **Hypervisor network mode**: use **Bridged** or any mode that gives the VM a routable IP on your LAN. NAT-only mode means you cannot reach NodePorts from your host browser.

---

## Prerequisites

Install these **before** cloning the repo:

```bash
sudo apt-get update
sudo apt-get install -y git curl
```

> `git` is not included in Ubuntu 24 minimal installs.

---

## Credentials You Need Before Starting

The setup script is interactive and will pause to ask for credentials. Have these ready:

### 1. Cisco Secure Access — Resource Connector credentials
- Log in to your Cisco Secure Access dashboard
- Navigate to **Connect → Network Connections → Resource Connectors**
- Create or select a Connector Group and copy the **Connector Name** and **Connector Key**

### 2. Splunk admin password *(Profile 2 only)*
- Choose any password with minimum 8 characters
- Leave **empty** (press Enter) to skip Splunk and run Profile 1 instead

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
5. Enable Hubble UI (NodePort 30800)
6. Install Tetragon
7. **Prompt for Cisco Connector credentials** → download and launch the Resource Connector via Docker
8. Register the Connector as a Kubernetes service
9. **Prompt for Splunk password** — leave empty to skip Splunk (Profile 1)
10. Deploy all workload pods to the `piap` namespace

---

## After Setup

### Find your server IP

```bash
hostname -I | awk '{print $1}'
```

### Check that everything is running

```bash
# All piap pods should reach Running state
kubectl get pods -n piap

# Cilium and Hubble should be OK
cilium status

# Connector container should be up
docker ps | grep connector
```

### Splunk post-setup steps (Profile 2 only, manual)

1. Open `http://<server-ip>:30500` → login with `admin` / your chosen password
2. Accept the Splunk Free License: **Settings → Licensing**
3. Install **Cisco Security Cloud** from Splunkbase (Apps → Find More Apps)
4. Install **Splunk MCP Server** from Splunkbase

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
→ The VM needs more RAM. 16 GB minimum for Profile 2. Splunk needs at least 4 GB headroom.

**Connector not reaching Cisco cloud**
→ Check `docker logs <connector-container>`. Ensure the VM has outbound HTTPS access. Verify the Connector Name and Key in the Cisco SSE dashboard.

**NodePorts not reachable from browser**
→ Check `sudo ufw status`. Disable ufw or open the required ports.

**Cilium not reaching Ready**
→ On some hypervisors, `routingMode=native` requires the VM NIC to be in bridged mode. Check `cilium status` output for details.
