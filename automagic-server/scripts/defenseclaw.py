"""
DefenseClaw + OpenClaw — AI Agent security governance for the k3s cluster.

Deploys a single Pod with two containers:
  1. OpenClaw  — AI agent + WebChat UI (Node.js, port 18789)
  2. DefenseClaw — security gateway + guardrail proxy (Go+Python, ports 18790 + 4000)

Both share localhost inside the Pod so DefenseClaw can intercept OpenClaw traffic.
"""
import os, json, textwrap
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

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
            exec openclaw gateway --host 0.0.0.0 --port 18789
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
            requests={"memory": "256Mi", "cpu": "100m"},
            limits={"memory": "512Mi", "cpu": "500m"},
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

            echo "[defenseclaw] Downloading gateway binary v{version}..."
            curl -fsSL "{tarball}" | tar xz -C /usr/local/bin/

            echo "[defenseclaw] Installing CLI..."
            pip install --quiet "{wheel}"

            # Write config
            mkdir -p /root/.defenseclaw
            cp /config/config.yaml /root/.defenseclaw/config.yaml

            echo "[defenseclaw] Initializing (non-interactive)..."
            defenseclaw init --enable-guardrail -y 2>&1 || true

            echo "[defenseclaw] Starting gateway on port 18790..."
            exec defenseclaw-gateway
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
            limits={"memory": "512Mi", "cpu": "500m"},
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
