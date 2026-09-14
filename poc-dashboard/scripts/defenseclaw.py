"""
DefenseClaw + OpenClaw — AI Agent security governance for the k3s cluster.

Deploys a single Pod with two containers:
  1. OpenClaw  — AI agent + WebChat UI (Node.js, port 18789)
  2. DefenseClaw — security gateway + guardrail proxy (Go+Python, ports 18790 + 4000)

Both share localhost inside the Pod so DefenseClaw can intercept OpenClaw traffic.
"""
import os, json, textwrap, secrets
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

# DefenseClaw is installed via its official install script, which lays down the
# Go gateway (defenseclaw-gateway), the Python CLI, and — with
# `--connector openclaw` — the OpenClaw runtime and the DefenseClaw plugin.
# Leave DEFENSECLAW_VERSION empty to install the latest release (the container
# resolves the latest tag from the GitHub API at deploy time).
DEFENSECLAW_VERSION = os.environ.get("DEFENSECLAW_VERSION", "")  # "" => latest
DEFENSECLAW_INSTALL_URL = os.environ.get(
    "DEFENSECLAW_INSTALL_URL",
    "https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.sh",
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

        # OpenClaw and DefenseClaw now run co-located in a single "ai-agent"
        # container (matching DefenseClaw's supported single-host install flow).
        # Report both logical components from that one container's status.
        state, ready_n = overall, ready
        pod_list = core.list_namespaced_pod(
            NAMESPACE, label_selector=f"app={DEPLOYMENT_NAME}", limit=1
        )
        if pod_list.items:
            css = pod_list.items[0].status.container_statuses or []
            cs = next((c for c in css if c.name == DEPLOYMENT_NAME),
                      (css[0] if css else None))
            if cs is not None:
                if cs.ready:
                    state, ready_n = "running", 1
                elif cs.state and cs.state.waiting:
                    state, ready_n = (cs.state.waiting.reason or "waiting"), 0
                else:
                    state, ready_n = overall, 0
        status["openclaw"] = {"ready": ready_n, "desired": 1, "state": state}
        status["gateway"] = {"ready": ready_n, "desired": 1, "state": state}
    except ApiException:
        pass

    # Read the shared auth token from the ConfigMap so the UI can build
    # a working URL with ?token=<value>
    try:
        cm = core.read_namespaced_config_map("ai-agent-config", NAMESPACE)
        oc_cfg = json.loads(cm.data.get("openclaw.json", "{}"))
        status["auth_token"] = oc_cfg.get("gateway", {}).get("auth", {}).get("token", "")
    except Exception:
        status["auth_token"] = ""

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

    # ── 2. Pre-generate a shared auth token ────────────────────────────
    # OpenClaw auto-generates a token on first start. DefenseClaw needs
    # the same token to connect via WebSocket. Pre-generate one and
    # inject it into the config so both containers share it.
    shared_token = secrets.token_hex(32)

    openclaw_config = json.dumps({
        "gateway": {
            "mode": "local",
            "bind": "lan",
            "port": 18789,
            "auth": {"token": shared_token},
            "controlUi": {
                "allowedOrigins": ["*"],
                "allowInsecureAuth": True,
                "dangerouslyDisableDeviceAuth": True,
            },
        },
        "agents": {
            "defaults": {
                "model": {"primary": "anthropic/claude-sonnet-5"},
                "models": {
                    "anthropic/claude-sonnet-5": {"alias": "Sonnet"},
                    "anthropic/claude-opus-5": {"alias": "Opus"},
                },
            }
        }
    }, indent=2)

    # DefenseClaw config — includes the shared token for OpenClaw WS auth
    defenseclaw_config = textwrap.dedent("""\
        claw:
          mode: openclaw
        gateway:
          host: "localhost"
          port: 18789
          token: "{token}"
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
    """).format(token=shared_token, hec_url=SPLUNK_HEC_URL, hec_token=HEC_TOKEN)

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

    # ── 3. Deployment: single co-located "ai-agent" container ────────────
    # DefenseClaw's supported flow is single-host: its installer lays down the
    # Go gateway, the Python CLI and the OpenClaw plugin, and
    # `defenseclaw init --enable-guardrail` patches openclaw.json so OpenClaw's
    # LLM traffic is routed through the guardrail proxy. We run OpenClaw and
    # DefenseClaw together in one container so that config patching and the
    # localhost wiring (guardrail proxy + gateway REST) work exactly as
    # documented — the two logical components still live in one Pod.
    config_volume = client.V1Volume(
        name="config",
        config_map=client.V1ConfigMapVolumeSource(name="ai-agent-config"),
    )
    data_volume = client.V1Volume(name="data", empty_dir=client.V1EmptyDirVolumeSource())

    api_key_env = client.V1EnvVar(
        name="ANTHROPIC_API_KEY",
        value_from=client.V1EnvVarSource(
            secret_key_ref=client.V1SecretKeySelector(
                name="anthropic-api-key", key="ANTHROPIC_API_KEY", optional=True,
            )
        ),
    )

    env = [
        api_key_env,
        client.V1EnvVar(name="OPENCLAW_AUTH_TOKEN", value=shared_token),
        client.V1EnvVar(name="DEFENSECLAW_VERSION", value=DEFENSECLAW_VERSION),
        client.V1EnvVar(name="DEFENSECLAW_INSTALL_URL", value=DEFENSECLAW_INSTALL_URL),
        client.V1EnvVar(name="DEFENSECLAW_HEC_URL",
                        value=f"{SPLUNK_HEC_URL}/services/collector/event"),
        client.V1EnvVar(name="DEFENSECLAW_HEC_TOKEN", value=HEC_TOKEN),
        client.V1EnvVar(name="DEFENSECLAW_INDEX", value="defenseclaw"),
        client.V1EnvVar(name="DEFENSECLAW_SOURCETYPE", value="defenseclaw:json"),
        client.V1EnvVar(name="DEFENSECLAW_INTEGRATION_ENABLED", value="true"),
    ]

    # Pure-shell startup (values come from env vars, so no Python interpolation).
    startup_script = textwrap.dedent("""\
        set -e
        export DEBIAN_FRONTEND=noninteractive
        echo "[ai-agent] Installing OS dependencies..."
        apt-get update -qq
        apt-get install -y -qq python3 python3-venv python3-pip curl ca-certificates tar git >/dev/null 2>&1

        export HOME=/root
        export OPENCLAW_HOME=/data/openclaw-home
        mkdir -p "$OPENCLAW_HOME" "$HOME/.defenseclaw"
        export PATH="$HOME/.local/bin:$PATH"

        # Resolve the DefenseClaw version to install (default: latest release).
        VERSION="$DEFENSECLAW_VERSION"
        if [ -z "$VERSION" ]; then
            VERSION="$(curl -fsSL https://api.github.com/repos/cisco-ai-defense/defenseclaw/releases/latest \\
                | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)"
        fi
        echo "[ai-agent] Installing DefenseClaw ${VERSION:-latest} + OpenClaw runtime + plugin..."

        # Official installer: Go gateway (~/.local/bin/defenseclaw-gateway) + Python CLI +
        # (with --connector openclaw) the OpenClaw runtime and the DefenseClaw plugin.
        curl -LsSf "$DEFENSECLAW_INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector openclaw </dev/null

        # Activate the DefenseClaw CLI venv if the installer created one.
        [ -f "$HOME/.defenseclaw/.venv/bin/activate" ] && . "$HOME/.defenseclaw/.venv/bin/activate" || true

        # Configure the OpenClaw gateway (shared auth token, LAN bind, control UI, model).
        echo "[ai-agent] Configuring OpenClaw gateway..."
        openclaw config set gateway.mode local
        openclaw config set gateway.bind lan
        openclaw config set gateway.port 18789
        openclaw config set gateway.auth.token "$OPENCLAW_AUTH_TOKEN"
        openclaw config set gateway.controlUi.allowedOrigins '["*"]'
        openclaw config set gateway.controlUi.allowInsecureAuth true
        openclaw config set gateway.controlUi.dangerouslyDisableDeviceAuth true
        openclaw config set agents.defaults.model.primary anthropic/claude-sonnet-5 || true

        # Initialize DefenseClaw + enable the guardrail: installs the OpenClaw plugin
        # and patches openclaw.json to route LLM calls through the guardrail proxy.
        echo "[ai-agent] Initializing DefenseClaw guardrail + plugin..."
        defenseclaw init --enable-guardrail --yes 2>&1 || true

        # Apply our gateway config (Splunk SIEM + shared token) after init.
        cp /config/config.yaml "$HOME/.defenseclaw/config.yaml" 2>/dev/null || true

        # Start the DefenseClaw gateway sidecar (REST 18790 + guardrail proxy) in the
        # background, then run the OpenClaw gateway in the foreground.
        echo "[ai-agent] Starting DefenseClaw gateway sidecar..."
        ( defenseclaw-gateway 2>&1 | sed 's/^/[gateway] /' ) &

        echo "[ai-agent] Starting OpenClaw gateway..."
        exec openclaw gateway
    """)

    ai_agent_container = client.V1Container(
        name=DEPLOYMENT_NAME,
        image="node:22-bookworm-slim",
        command=["/bin/sh", "-c"],
        args=[startup_script],
        ports=[
            client.V1ContainerPort(container_port=18789, name="webchat"),
            client.V1ContainerPort(container_port=18790, name="api"),
        ],
        env=env,
        volume_mounts=[
            client.V1VolumeMount(name="config", mount_path="/config", read_only=True),
            client.V1VolumeMount(name="data", mount_path="/data"),
        ],
        resources=client.V1ResourceRequirements(
            requests={"memory": "768Mi", "cpu": "300m"},
            limits={"memory": "2Gi", "cpu": "1500m"},
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
                    containers=[ai_agent_container],
                    volumes=[config_volume, data_volume],
                ),
            ),
        ),
    )
    try:
        apps.create_namespaced_deployment(NAMESPACE, dep)
    except ApiException as e:
        if e.status == 409:
            # The container shape changed (was two containers): delete and recreate
            # rather than strategic-merge patch, which would leave stale containers.
            import time as _time
            apps.delete_namespaced_deployment(DEPLOYMENT_NAME, NAMESPACE)
            for _ in range(30):
                try:
                    apps.read_namespaced_deployment(DEPLOYMENT_NAME, NAMESPACE)
                    _time.sleep(1)
                except ApiException:
                    break
            apps.create_namespaced_deployment(NAMESPACE, dep)
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
                # Allow Splunk HEC (audit event forwarding).
                # NOTE: the Splunk pods are labelled `app: splunk` (see
                # k8s/splunk-deployment.yaml) — matching the wrong label here
                # would silently block HEC egress whenever the agent is isolated.
                {
                    "toEndpoints": [
                        {"matchLabels": {"k8s:io.kubernetes.pod.namespace": "piap",
                                         "app": "splunk"}}
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
    """Create the defenseclaw index and dashboard in Splunk via REST API."""
    from scripts.splunk import SPLUNK_API_URL, SPLUNK_PASSWORD

    mgmt_url = SPLUNK_API_URL.replace("http://", "https://")

    # ── Create the defenseclaw index if it doesn't exist ─────────────
    idx_endpoint = f"{mgmt_url}/servicesNS/admin/search/data/indexes"
    http_requests.post(
        idx_endpoint,
        auth=("admin", SPLUNK_PASSWORD),
        data={"name": "defenseclaw", "datatype": "event"},
        verify=False,
        timeout=15,
    )  # 409 = already exists, that's fine

    # ── Create or update the dashboard ───────────────────────────────
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
