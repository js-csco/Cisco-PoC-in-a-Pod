#!/usr/bin/env bash

# make executable sudo chmod +x setup-cluster.sh
# sudo ./setup-cluster.sh

# Takes up to 5 min to prepare everything - be patient.

# relevant namespaces:
# kube-system: what Cilium, Tetragon, Hubble run in and communicate
# default: where your apps will run

set -e

echo "[1/7] Checking system..."
sudo apt update && sudo apt install -y curl wget tar git jq apt-transport-https ca-certificates gnupg lsb-release 
sudo snap install helm --classic
sudo mount bpffs /sys/fs/bpf -t bpf || true

echo "[2/7] Installing kind and kubectl..."
curl -Lo ./kind https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

#### Docker install
echo "[3A] Installing Docker engine (required for KIND)..."
sudo apt update
sudo apt install -y ca-certificates curl gnupg lsb-release
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o -y /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# enable & start docker
sudo systemctl enable docker
sudo systemctl start docker

# ensure current user can access Docker without sudo
if ! groups $USER | grep -q '\bdocker\b'; then
  echo "⚙️  Adding $USER to the docker group..."
  sudo usermod -aG docker $USER
  echo "✅ Added $USER to the docker group. Please log out and back in (or run 'newgrp docker') to apply."
fi


echo "[3/7] Creating KIND cluster..."
kind create cluster --config ./kind-config.yaml --name pod

echo "[4/7] Installing Cilium CLI..."
CILIUM_VER=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
curl -L --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_VER}/cilium-linux-amd64.tar.gz
tar xzvf cilium-linux-amd64.tar.gz && sudo mv cilium /usr/local/bin/ && rm cilium-linux-amd64.tar.gz

echo "[5/7] Installing Cilium + Hubble..."
cilium install --version 1.16.2 \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set prometheus.enabled=true \
  --set operator.replicas=1
cilium status --wait

echo "[6/7] Installing Tetragon..."
helm repo add cilium https://helm.cilium.io/
helm repo update
helm install tetragon cilium/tetragon -n kube-system

echo "[7/7] Create Namespace piap and make it default..."
#create namespace piap & set as default
kubectl create namespace piap
kubectl config set-context --current --namespace=piap

## setup complete
echo "✅ Setup complete!"
