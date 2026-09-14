#!/usr/bin/env bash
#
# Install & configure a Splunk Universal Forwarder (UF) on the Ubuntu VM host.
#
# The UF ships *host-level* telemetry that the in-cluster collectors don't see:
#   - Host OS logs: /var/log/syslog, /var/log/auth.log (SSH logins), journald  -> index=piap_host
#   - Secure Access Resource Connector (Docker) logs                            -> index=piap_connector
#
# It forwards over splunktcp to the in-cluster Splunk indexer's 9997 NodePort.
# This complements (does not replace) the OTel metrics + Fluent Bit + HEC/API
# collectors — the goal is to showcase every Splunk ingestion method.
#
# Idempotent, and safe to run before Splunk is deployed (events simply queue on
# the UF / are dropped until the indexer's receiver is up — that's fine for the PoC).
#
# The indexes (piap_host, piap_connector) and the 9997 receiver are provisioned
# from the PoC Dashboard Splunk tab ("Provision indexes & UF receiver").
set -euo pipefail

SPLUNK_UF_VERSION="${SPLUNK_UF_VERSION:-9.3.2}"
# NOTE: Splunk .deb download URLs include a per-build hash. If you change the
# version, update this URL from https://www.splunk.com/en_us/download/universal-forwarder.html
SPLUNK_UF_DEB_URL="${SPLUNK_UF_DEB_URL:-https://download.splunk.com/products/universalforwarder/releases/9.3.2/linux/splunkforwarder-9.3.2-d8bb32809498-linux-amd64.deb}"
# UF forwards to the Splunk indexer's splunktcp receiver. Splunk runs in k3s and
# exposes 9997 as NodePort 30997, reachable on the host as 127.0.0.1:30997.
SPLUNK_INDEXER="${SPLUNK_INDEXER:-127.0.0.1:30997}"
UF_HOME="${UF_HOME:-/opt/splunkforwarder}"
UF_ADMIN_PW="${UF_ADMIN_PW:-C1scoPoC!}"

echo "==> Installing Splunk Universal Forwarder ${SPLUNK_UF_VERSION}"
if [ -x "${UF_HOME}/bin/splunk" ]; then
    echo "    UF already installed at ${UF_HOME}"
else
    tmp="$(mktemp /tmp/splunkuf-XXXXXX.deb)"
    curl -fsSL -o "${tmp}" "${SPLUNK_UF_DEB_URL}"
    dpkg -i "${tmp}" || apt-get -f install -y
    rm -f "${tmp}"
fi

# First-time start: accept the license and seed the admin password non-interactively.
if [ ! -f "${UF_HOME}/etc/passwd" ]; then
    "${UF_HOME}/bin/splunk" start --accept-license --answer-yes --no-prompt \
        --seed-passwd "${UF_ADMIN_PW}" || true
fi

mkdir -p "${UF_HOME}/etc/system/local"

# ── inputs: host OS logs -> piap_host, Docker/connector -> piap_connector ──
cat > "${UF_HOME}/etc/system/local/inputs.conf" <<'EOF'
[default]
host = piap-vm

[monitor:///var/log/syslog]
index = piap_host
sourcetype = syslog

[monitor:///var/log/auth.log]
index = piap_host
sourcetype = linux_secure

[journald://host-journal]
index = piap_host

# Secure Access Resource Connector (and other host Docker) container logs
[monitor:///var/lib/docker/containers/*/*-json.log]
index = piap_connector
sourcetype = docker:json
EOF

# ── outputs: forward to the in-cluster indexer's 9997 NodePort ──
cat > "${UF_HOME}/etc/system/local/outputs.conf" <<EOF
[tcpout]
defaultGroup = piap-indexers

[tcpout:piap-indexers]
server = ${SPLUNK_INDEXER}
EOF

"${UF_HOME}/bin/splunk" restart || true
"${UF_HOME}/bin/splunk" enable boot-start -user root || true

echo "✅ Splunk UF configured — forwarding to ${SPLUNK_INDEXER}"
echo "   Host OS logs  -> index=piap_host"
echo "   Docker/connector logs -> index=piap_connector"
echo "   (Provision the indexes + 9997 receiver from the dashboard Splunk tab.)"
