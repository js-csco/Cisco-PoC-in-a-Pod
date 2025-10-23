#!/bin/bash

set -e

echo "=== Installing Cisco Secure Access Connector ==="

export DOCKER_HOST=unix:///run/podman/podman.sock

curl -fsSL -o setup_connector.sh https://us.repo.acgw.sse.cisco.com/scripts/latest/setup_connector.sh
chmod +x setup_connector.sh
sudo ./setup_connector.sh

sudo chmod +x install_connector.sh
sudo ./install_connector.sh

cd /opt/connector/install

### Input Required: Connector Name & Provisioning Key ###
echo "INPUT REQUIRED: Please enter Connector Name & Connector Key."
echo "You find this information in the Secure Access dashboard: Connect > Network Connection > Connector Groups > *Table*"
echo "Use your before defined connector name & copy the key."
read -p "Enter Connector Name: " CONNECTOR_NAME
read -p "Enter Connector Key: " CONNECTOR_KEY
# start
sudo ./connector.sh launch --name "$CONNECTOR_NAME" --key "$CONNECTOR_KEY"

echo "=== Cisco connector installation complete ==="