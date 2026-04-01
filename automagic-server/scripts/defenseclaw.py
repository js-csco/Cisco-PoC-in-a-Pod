"""
DefenseClaw + OpenClaw — AI Agent security governance for the k3s cluster.

Deploys a single Pod with two containers:
  1. OpenClaw  — AI agent + WebChat UI (Node.js, port 18789)
  2. DefenseClaw — security gateway + guardrail proxy (Go+Python, ports 18790 + 4000)

Both share localhost inside the Pod so DefenseClaw can intercept OpenClaw traffic.
"""
import os, json, textwrap
import requests as http_requests
import urllib3
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cilium policy constants
_CILIUM_GROUP = "cilium.io"
_CILIUM_VERSION = "v2"
_CILIUM_PLURAL = "ciliumnetworkpolicies"
_ISOLATION_POLICY_NAME = "ai-agent-isolation"

NAMESPACE = "defenseclaw"
DEPLOYMENT_NAME = "ai-agent"

# DefenseClaw v0.2.0 release artifacts
DEFENSECLAW_VERSION = "0.2.0"
DEFENSECLAW_TARBALL = (
    f"https://github.com/cisco-ai-defense/defenseclaw/releases/download/"
    f"{DEFENSECLAW_VERSION}/defenseclaw_{DEFENSECLAW_VERSION}_linux_amd64.tar.gz"
)
DEFENSECLAW_WHEEL = (
    f"https://github.com/cisco-ai-defense/defenseclaw/releases/download/"
    f"{DEFENSECLAW_VERSION}/defenseclaw-{DEFENSECLAW_VERSION}-py3-none-any.whl"
)

# Splunk HEC for audit event forwarding
SPLUNK_HEC_URL = os.environ.get(
    "SPLUNK_HEC_URL", "http://splunk.piap.svc.cluster.local:8088"
)
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "piap-hec-token")


def _core():
    config.load_incluster_config()
    return client.CoreV1Api()


def _apps():
    config.load_incluster_config()
    return client.AppsV1Api()


def get_status():
    """Return status dict for the ai-agent Deployment."""
    status = {
        "namespace_exists": False,
        "api_key_set": False,
        "gateway": {"ready": 0, "desired": 0, "state": "not deployed"},
        "openclaw": {"ready": 0, "desired": 0, "state": "not deployed"},
    }
    try:
        core = _core()
        core.read_namespace(NAMESPACE)
        status["namespace_exists"] = True
    except ApiException:
        return status

    # Check if the API key secret exists
    try:
        core.read_namespaced_secret("anthropic-api-key", NAMESPACE)
        status["api_key_set"] = True
    except ApiException:
        pass

    # Check the single Deployment with two containers
    try:
        apps = _apps()
        dep = apps.read_namespaced_deployment(DEPLOYMENT_NAME, NAMESPACE)
        desired = dep.spec.replicas or 1
        ready = dep.status.ready_replicas or 0
        overall = "running" if ready >= desired else "starting"

        # Both containers live in the same pod — report per-container status
        # from the pod's container statuses if available.
        pod_list = core.list_namespaced_pod(
            NAMESPACE, label_selector=f"app={DEPLOYMENT_NAME}", limit=1
        )
        if pod_list.items:
            pod = pod_list.items[0]
            for cs in (pod.status.container_statuses or []):
                key = "openclaw" if cs.name == "openclaw" else "gateway"
                if cs.ready:
                    status[key] = {"ready": 1, "desired": 1, "state": "running"}
                elif cs.state and cs.state.waiting:
                    reason = cs.state.waiting.reason or "waiting"
                    status[key] = {"ready": 0, "desired": 1, "state": reason}
                else:
                    status[key] = {"ready": 0, "desired": 1, "state": overall}
        else:
            for key in ("gateway", "openclaw"):
                status[key] = {"ready": ready, "desired": desired, "state": overall}
    except ApiException:
        pass

    return status


def save_api_key(api_key: str):
    """Store the Anthropic API key as a Kubernetes Secret."""
    config.load_incluster_config()
    core = client.CoreV1Api()

    # Ensure namespace exists
    try:
        core.create_namespace(
            client.V1Namespace(metadata=client.V1ObjectMeta(name=NAMESPACE))
        )
    except ApiException as e:
        if e.status != 409:
            raise

    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name="anthropic-api-key", namespace=NAMESPACE),
        string_data={"ANTHROPIC_API_KEY": api_key},
    )
    try:
        core.create_namespaced_secret(NAMESPACE, secret)
    except ApiException as e:
        if e.status == 409:
            core.patch_namespaced_secret("anthropic-api-key", NAMESPACE, secret)
        else:
            raise


def deploy_environment():
    """Create the namespace and deploy the ai-agent Pod (OpenClaw + DefenseClaw)."""
    config.load_incluster_config()
    core = client.CoreV1Api()
    apps = client.AppsV1Api()

    # ── 1. Namespace ─────────────────────────────────────────────────────
    try:
        core.create_namespace(
            client.V1Namespace(metadata=client.V1ObjectMeta(name=NAMESPACE))
        )
    except ApiException as e:
        if e.status != 409:
            raise

    # ── 2. OpenClaw config as a ConfigMap ────────────────────────────────
    openclaw_config = json.dumps({
        "gateway": {"mode": "local"},
        "agents": {
            "defaults": {
                "model": {"primary": "anthropic/claude-sonnet-4-6"},
                "models": {
                    "anthropic/claude-sonnet-4-6": {"alias": "Sonnet"},
                    "anthropic/claude-opus-4-6": {"alias": "Opus"},
                },
            }
        }
    }, indent=2)

    # DefenseClaw config
    defenseclaw_config = textwrap.dedent("""\
        claw:
          mode: openclaw
        gateway:
          host: "localhost"
          port: 18789
          api_port: 18790
          api_bind: "0.0.0.0"
        guardrail:
          host: "0.0.0.0"
          port: 4000
        siem:
          splunk:
            hec_url: {hec_url}/services/collector/event
            hec_token: {hec_token}
            index: defenseclaw
            sourcetype: "defenseclaw:json"
            enabled: true
    """).format(hec_url=SPLUNK_HEC_URL, hec_token=HEC_TOKEN)

    cm = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name="ai-agent-config", namespace=NAMESPACE),
        data={
            "openclaw.json": openclaw_config,
            "config.yaml": defenseclaw_config,
        },
    )
    try:
        core.create_namespaced_config_map(NAMESPACE, cm)
    except ApiException as e:
        if e.status == 409:
            core.patch_namespaced_config_map("ai-agent-config", NAMESPACE, cm)
        else:
            raise

    # ── 3. Deployment: two containers in one Pod ─────────────────────────
    # Shared volume for configs
    config_volume = client.V1Volume(
        name="config",
        config_map=client.V1ConfigMapVolumeSource(name="ai-agent-config"),
    )
    # Shared emptyDir so DefenseClaw can discover OpenClaw's home
    data_volume = client.V1Volume(name="data", empty_dir=client.V1EmptyDirVolumeSource())

    # Secret reference for the API key
    api_key_env = client.V1EnvVar(
        name="ANTHROPIC_API_KEY",
        value_from=client.V1EnvVarSource(
            secret_key_ref=client.V1SecretKeySelector(
                name="anthropic-api-key", key="ANTHROPIC_API_KEY", optional=True,
            )
        ),
    )

    # ── Container 1: OpenClaw ────────────────────────────────────────────
    openclaw_container = client.V1Container(
        name="openclaw",
        image="node:24-slim",
        command=["/bin/sh", "-c"],
        args=[textwrap.dedent("""\
            set -e
            echo "[openclaw] Installing OpenClaw..."
            npm install -g openclaw@latest 2>&1 | tail -5

            # Write config
            mkdir -p /root/.openclaw
            cp /config/openclaw.json /root/.openclaw/openclaw.json

            echo "[openclaw] Starting gateway on port 18789..."
            exec openclaw gateway --bind lan --port 18789
        """)],
        ports=[
            client.V1ContainerPort(container_port=18789, name="webchat"),
        ],
        env=[api_key_env],
        volume_mounts=[
            client.V1VolumeMount(name="config", mount_path="/config", read_only=True),
            client.V1VolumeMount(name="data", mount_path="/data"),
        ],
        resources=client.V1ResourceRequirements(
            requests={"memory": "512Mi", "cpu": "200m"},
            limits={"memory": "1Gi", "cpu": "1"},
        ),
    )

    # ── Container 2: DefenseClaw ─────────────────────────────────────────
    defenseclaw_container = client.V1Container(
        name="defenseclaw",
        image="python:3.12-slim",
        command=["/bin/sh", "-c"],
        args=[textwrap.dedent("""\
            set -e
            apt-get update -qq && apt-get install -y -qq curl >/dev/null 2>&1

            echo "[defenseclaw] Downloading binary v{version}..."
            mkdir -p /tmp/defenseclaw-release
            curl -fsSL "{tarball}" | tar xz -C /tmp/defenseclaw-release
            cp /tmp/defenseclaw-release/defenseclaw /usr/local/bin/defenseclaw-gw
            chmod +x /usr/local/bin/defenseclaw-gw

            echo "[defenseclaw] Installing CLI..."
            pip install --quiet "{wheel}"

            # Write config
            mkdir -p /root/.defenseclaw
            cp /config/config.yaml /root/.defenseclaw/config.yaml

            echo "[defenseclaw] Initializing..."
            defenseclaw init 2>&1 || true

            # Wait for OpenClaw to be ready (shares localhost in the pod)
            echo "[defenseclaw] Waiting for OpenClaw gateway on localhost:18789..."
            for i in $(seq 1 30); do
                if curl -sf http://localhost:18789/ >/dev/null 2>&1; then
                    echo "[defenseclaw] OpenClaw is ready."
                    break
                fi
                sleep 2
            done

            echo "[defenseclaw] Starting gateway..."
            exec defenseclaw-gw
        """.format(
            version=DEFENSECLAW_VERSION,
            tarball=DEFENSECLAW_TARBALL,
            wheel=DEFENSECLAW_WHEEL,
        ))],
        ports=[
            client.V1ContainerPort(container_port=18790, name="api"),
            client.V1ContainerPort(container_port=4000, name="guardrail"),
        ],
        env=[
            api_key_env,
            client.V1EnvVar(name="DEFENSECLAW_HEC_URL",
                            value=f"{SPLUNK_HEC_URL}/services/collector/event"),
            client.V1EnvVar(name="DEFENSECLAW_HEC_TOKEN", value=HEC_TOKEN),
            client.V1EnvVar(name="DEFENSECLAW_INDEX", value="defenseclaw"),
            client.V1EnvVar(name="DEFENSECLAW_SOURCETYPE", value="defenseclaw:json"),
            client.V1EnvVar(name="DEFENSECLAW_INTEGRATION_ENABLED", value="true"),
        ],
        volume_mounts=[
            client.V1VolumeMount(name="config", mount_path="/config", read_only=True),
            client.V1VolumeMount(name="data", mount_path="/data"),
        ],
        resources=client.V1ResourceRequirements(
            requests={"memory": "256Mi", "cpu": "100m"},
            limits={"memory": "768Mi", "cpu": "500m"},
        ),
    )

    dep = client.V1Deployment(
        metadata=client.V1ObjectMeta(name=DEPLOYMENT_NAME, namespace=NAMESPACE),
        spec=client.V1DeploymentSpec(
            replicas=1,
            selector=client.V1LabelSelector(match_labels={"app": DEPLOYMENT_NAME}),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": DEPLOYMENT_NAME}),
                spec=client.V1PodSpec(
                    containers=[openclaw_container, defenseclaw_container],
                    volumes=[config_volume, data_volume],
                ),
            ),
        ),
    )
    try:
        apps.create_namespaced_deployment(NAMESPACE, dep)
    except ApiException as e:
        if e.status == 409:
            apps.patch_namespaced_deployment(DEPLOYMENT_NAME, NAMESPACE, dep)
        else:
            raise

    # ── 4. Services ──────────────────────────────────────────────────────
    svc = client.V1Service(
        metadata=client.V1ObjectMeta(name="ai-agent", namespace=NAMESPACE),
        spec=client.V1ServiceSpec(
            type="NodePort",
            selector={"app": DEPLOYMENT_NAME},
            ports=[
                client.V1ServicePort(
                    name="webchat", port=18789, target_port=18789, node_port=31789,
                ),
                client.V1ServicePort(
                    name="gateway-api", port=18790, target_port=18790, node_port=31790,
                ),
            ],
        ),
    )
    try:
        core.create_namespaced_service(NAMESPACE, svc)
    except ApiException as e:
        if e.status == 409:
            core.patch_namespaced_service("ai-agent", NAMESPACE, svc)
        else:
            raise


# ═══════════════════════════════════════════════════════════════════════════
# Network isolation via CiliumNetworkPolicy
# ═══════════════════════════════════════════════════════════════════════════

def _custom_api():
    config.load_incluster_config()
    return client.CustomObjectsApi()


def _build_isolation_policy():
    """
    CiliumNetworkPolicy that isolates the AI agent pod:
      - Ingress: allow from anywhere (users need to reach the WebChat UI)
      - Egress:  allow DNS (kube-dns) + Splunk HEC + external HTTPS (Anthropic API)
      - Egress to all other cluster pods is BLOCKED
    """
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": _ISOLATION_POLICY_NAME, "namespace": NAMESPACE},
        "spec": {
            "endpointSelector": {
                "matchLabels": {"app": DEPLOYMENT_NAME}
            },
            "ingress": [
                {}  # allow all ingress (WebChat UI must be reachable)
            ],
            "egress": [
                # Allow DNS resolution (kube-dns in kube-system)
                {
                    "toEndpoints": [
                        {"matchLabels": {"k8s:io.kubernetes.pod.namespace": "kube-system",
                                         "k8s-app": "kube-dns"}}
                    ],
                    "toPorts": [
                        {"ports": [{"port": "53", "protocol": "UDP"},
                                   {"port": "53", "protocol": "TCP"}]}
                    ],
                },
                # Allow Splunk HEC (audit event forwarding)
                {
                    "toEndpoints": [
                        {"matchLabels": {"k8s:io.kubernetes.pod.namespace": "piap",
                                         "io.kompose.service": "splunk"}}
                    ],
                    "toPorts": [
                        {"ports": [{"port": "8088", "protocol": "TCP"}]}
                    ],
                },
                # Allow external HTTPS only (Anthropic API, GitHub for install)
                {
                    "toEntities": ["world"],
                    "toPorts": [
                        {"ports": [{"port": "443", "protocol": "TCP"}]}
                    ],
                },
            ],
        },
    }


def get_isolation_status():
    """Check if the isolation policy is active."""
    try:
        api = _custom_api()
        api.get_namespaced_custom_object(
            _CILIUM_GROUP, _CILIUM_VERSION, NAMESPACE, _CILIUM_PLURAL,
            _ISOLATION_POLICY_NAME,
        )
        return True
    except ApiException:
        return False


def isolate_agent():
    """Apply CiliumNetworkPolicy to isolate the AI agent from the cluster."""
    api = _custom_api()
    policy = _build_isolation_policy()
    try:
        api.create_namespaced_custom_object(
            _CILIUM_GROUP, _CILIUM_VERSION, NAMESPACE, _CILIUM_PLURAL, policy,
        )
    except ApiException as e:
        if e.status == 409:
            existing = api.get_namespaced_custom_object(
                _CILIUM_GROUP, _CILIUM_VERSION, NAMESPACE, _CILIUM_PLURAL,
                _ISOLATION_POLICY_NAME,
            )
            policy["metadata"]["resourceVersion"] = existing["metadata"]["resourceVersion"]
            api.replace_namespaced_custom_object(
                _CILIUM_GROUP, _CILIUM_VERSION, NAMESPACE, _CILIUM_PLURAL,
                _ISOLATION_POLICY_NAME, policy,
            )
        else:
            raise


def unisolate_agent():
    """Remove the isolation policy — agent can reach cluster services again."""
    try:
        api = _custom_api()
        api.delete_namespaced_custom_object(
            _CILIUM_GROUP, _CILIUM_VERSION, NAMESPACE, _CILIUM_PLURAL,
            _ISOLATION_POLICY_NAME,
        )
    except ApiException as e:
        if e.status != 404:
            raise


# ═══════════════════════════════════════════════════════════════════════════
# Splunk Dashboard
# ═══════════════════════════════════════════════════════════════════════════

DASHBOARD_XML = textwrap.dedent("""\
<dashboard version="1.1" theme="light">
  <label>DefenseClaw — AI Agent Security</label>
  <description>Audit trail and security posture for the AI agent protected by DefenseClaw.</description>

  <row>
    <panel>
      <title>Decisions Over Time</title>
      <chart>
        <search>
          <query>index=defenseclaw sourcetype="defenseclaw:json"
| timechart span=5m count by action</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.fieldColors">{"block": "#d32f2f", "warn": "#f57c00", "allow": "#2e7d32"}</option>
      </chart>
    </panel>
    <panel>
      <title>Blocked vs Allowed</title>
      <chart>
        <search>
          <query>index=defenseclaw sourcetype="defenseclaw:json"
| stats count by action</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.fieldColors">{"block": "#d32f2f", "warn": "#f57c00", "allow": "#2e7d32"}</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>Blocks by Category</title>
      <chart>
        <search>
          <query>index=defenseclaw sourcetype="defenseclaw:json" action=block
| stats count by category
| sort -count</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <title>Top Blocked Tools</title>
      <chart>
        <search>
          <query>index=defenseclaw sourcetype="defenseclaw:json" action=block
| stats count by tool_name
| sort -count
| head 10</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>Severity Distribution</title>
      <chart>
        <search>
          <query>index=defenseclaw sourcetype="defenseclaw:json"
| stats count by severity
| sort -count</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.fieldColors">{"CRITICAL": "#b71c1c", "HIGH": "#d32f2f", "MEDIUM": "#f57c00", "LOW": "#fbc02d", "INFO": "#2e7d32"}</option>
      </chart>
    </panel>
    <panel>
      <title>Guardrail Proxy — Prompt Inspection</title>
      <chart>
        <search>
          <query>index=defenseclaw sourcetype="defenseclaw:json" category="guardrail"
| timechart span=10m count by action</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>Recent Audit Events</title>
      <table>
        <search>
          <query>index=defenseclaw sourcetype="defenseclaw:json"
| table _time, action, category, severity, tool_name, description, agent
| sort -_time
| head 50</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="count">20</option>
      </table>
    </panel>
  </row>
</dashboard>
""")


def create_splunk_dashboard():
    """Create or update the DefenseClaw dashboard in Splunk via REST API."""
    from scripts.splunk import SPLUNK_API_URL, SPLUNK_PASSWORD

    mgmt_url = SPLUNK_API_URL.replace("http://", "https://")
    dashboard_name = "defenseclaw_ai_agent_security"
    endpoint = f"{mgmt_url}/servicesNS/admin/search/data/ui/views"

    resp = http_requests.post(
        endpoint,
        auth=("admin", SPLUNK_PASSWORD),
        data={"name": dashboard_name, "eai:data": DASHBOARD_XML},
        verify=False,
        timeout=15,
    )

    if resp.status_code == 409:
        resp = http_requests.post(
            f"{endpoint}/{dashboard_name}",
            auth=("admin", SPLUNK_PASSWORD),
            data={"eai:data": DASHBOARD_XML},
            verify=False,
            timeout=15,
        )

    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Failed to create dashboard ({resp.status_code}): {resp.text[:300]}")

    return f"/app/search/{dashboard_name}"
