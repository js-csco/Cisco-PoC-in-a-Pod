"""
Splunk helper — availability checks, HEC health, on-demand deployment,
and Splunkbase app installation from the dashboard.

Log sources: Cisco Duo / Identity Intelligence, Cisco Secure Access.
"""
import os
import subprocess
import requests
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

SPLUNK_PASSWORD = "piap-admin"

SPLUNK_URL     = os.environ.get("SPLUNK_URL",      "http://splunk.piap.svc.cluster.local:8000")
SPLUNK_HEC_URL = os.environ.get("SPLUNK_HEC_URL",  "http://splunk.piap.svc.cluster.local:8088")
SPLUNK_API_URL = os.environ.get("SPLUNK_API_URL",  "http://splunk.piap.svc.cluster.local:8089")
HEC_TOKEN      = os.environ.get("SPLUNK_HEC_TOKEN", "piap-hec-token")

# Splunkbase apps managed by this dashboard
SPLUNKBASE_APPS = [
    {
        "id":          7404,
        "folder_name": "cisco_security_cloud",
        "display":     "Cisco Security Cloud",
        "description": "Dashboards and searches for Cisco Duo, Identity Intelligence, and Secure Access events.",
        "url":         "https://splunkbase.splunk.com/app/7404",
    },
    {
        "id":          7931,
        "folder_name": "splunk_mcp_server",
        "display":     "Splunk MCP Server",
        "description": "Expose Splunk search as an MCP tool for Claude and other AI agents via the /services/mcp endpoint.",
        "url":         "https://splunkbase.splunk.com/app/7931",
    },
]

NAMESPACE = "piap"


def _core():
    config.load_incluster_config()
    return client.CoreV1Api()


def _apps():
    config.load_incluster_config()
    return client.AppsV1Api()


def is_available():
    try:
        r = requests.get(f"{SPLUNK_URL}/en-US/account/login", timeout=5, allow_redirects=True)
        return r.status_code in (200, 303)
    except Exception:
        return False


def hec_is_healthy():
    try:
        r = requests.get(
            f"{SPLUNK_HEC_URL}/services/collector/health",
            headers={"Authorization": f"Splunk {HEC_TOKEN}"},
            timeout=5,
        )
        return r.status_code == 200
    except Exception:
        return False


def deploy_splunk(license_content: str = "") -> bool:
    """
    Create (or idempotently re-apply) the Splunk Secret, Deployment, and Service.

    If license_content is provided it is stored as a Secret and mounted into the
    container at /licenses/enterprise.lic; SPLUNK_LICENSE_URI is set accordingly
    so Splunk loads the Enterprise license on startup.

    Without a license the container starts a 60-day Enterprise trial, after which
    it degrades to Splunk Free (500 MB/day, authentication disabled — the admin
    password is then effectively ignored).

    Returns True if an Enterprise license was provided, False for trial mode.
    """
    core = _core()
    apps_api = _apps()
    has_license = bool(license_content.strip())

    # ── 1. splunk-creds Secret (password + HEC token) ────────────────────────
    creds_secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name="splunk-creds", namespace=NAMESPACE),
        string_data={"password": SPLUNK_PASSWORD, "hec_token": HEC_TOKEN},
    )
    try:
        core.create_namespaced_secret(NAMESPACE, creds_secret)
    except ApiException as e:
        if e.status == 409:
            core.patch_namespaced_secret("splunk-creds", NAMESPACE, creds_secret)
        else:
            raise

    # ── 2. Optional Enterprise license Secret ────────────────────────────────
    if has_license:
        lic_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(name="splunk-license", namespace=NAMESPACE),
            string_data={"enterprise.lic": license_content.strip()},
        )
        try:
            core.create_namespaced_secret(NAMESPACE, lic_secret)
        except ApiException as e:
            if e.status == 409:
                core.patch_namespaced_secret("splunk-license", NAMESPACE, lic_secret)
            else:
                raise

    # ── 3. Build Deployment ───────────────────────────────────────────────────
    env = [
        client.V1EnvVar(name="SPLUNK_START_ARGS", value="--accept-license --no-prompt"),
        client.V1EnvVar(name="SPLUNK_GENERAL_TERMS", value="--accept-sgt-current-at-splunk-com"),
        client.V1EnvVar(
            name="SPLUNK_PASSWORD",
            value_from=client.V1EnvVarSource(
                secret_key_ref=client.V1SecretKeySelector(name="splunk-creds", key="password")
            ),
        ),
        client.V1EnvVar(
            name="SPLUNK_HEC_TOKEN",
            value_from=client.V1EnvVarSource(
                secret_key_ref=client.V1SecretKeySelector(name="splunk-creds", key="hec_token")
            ),
        ),
        client.V1EnvVar(name="TZ",                        value="Europe/Berlin"),
        client.V1EnvVar(name="SPLUNK_HOME_OWNERSHIP_ENFORCEMENT", value="false"),
        client.V1EnvVar(name="SPLUNK_ENABLE_KVSTORE",     value="true"),
        client.V1EnvVar(name="SPLUNK_ROLE",               value="splunk_standalone"),
    ]
    if has_license:
        env.append(client.V1EnvVar(name="SPLUNK_LICENSE_URI", value="/licenses/enterprise.lic"))

    volume_mounts = [client.V1VolumeMount(name="splunk-data", mount_path="/opt/splunk/var")]
    volumes = [
        client.V1Volume(
            name="splunk-data",
            host_path=client.V1HostPathVolumeSource(path="/opt/splunk-data", type="DirectoryOrCreate"),
        )
    ]
    if has_license:
        volume_mounts.append(client.V1VolumeMount(name="splunk-license", mount_path="/licenses"))
        volumes.append(client.V1Volume(
            name="splunk-license",
            secret=client.V1SecretVolumeSource(secret_name="splunk-license"),
        ))

    container = client.V1Container(
        name="splunk",
        image="splunk/splunk:latest",
        env=env,
        ports=[
            client.V1ContainerPort(name="web",     container_port=8000),
            client.V1ContainerPort(name="hec",     container_port=8088),
            client.V1ContainerPort(name="splunkd", container_port=8089),
            client.V1ContainerPort(name="kvstore", container_port=8191),
        ],
        volume_mounts=volume_mounts,
        resources=client.V1ResourceRequirements(
            requests={"memory": "2Gi", "cpu": "1000m"},
            limits={"memory": "4Gi", "cpu": "2000m"},
        ),
        liveness_probe=client.V1Probe(
            http_get=client.V1HTTPGetAction(path="/en-US/account/login", port=8000),
            initial_delay_seconds=300, period_seconds=30, timeout_seconds=10, failure_threshold=5,
        ),
        readiness_probe=client.V1Probe(
            http_get=client.V1HTTPGetAction(path="/en-US/account/login", port=8000),
            initial_delay_seconds=240, period_seconds=10, timeout_seconds=5, failure_threshold=10,
        ),
        startup_probe=client.V1Probe(
            http_get=client.V1HTTPGetAction(path="/en-US/account/login", port=8000),
            initial_delay_seconds=60, period_seconds=10, timeout_seconds=5, failure_threshold=30,
        ),
    )

    deployment = client.V1Deployment(
        metadata=client.V1ObjectMeta(name="splunk", namespace=NAMESPACE, labels={"app": "splunk"}),
        spec=client.V1DeploymentSpec(
            replicas=1,
            selector=client.V1LabelSelector(match_labels={"app": "splunk"}),
            strategy=client.V1DeploymentStrategy(type="Recreate"),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": "splunk"}),
                spec=client.V1PodSpec(containers=[container], volumes=volumes),
            ),
        ),
    )
    try:
        apps_api.create_namespaced_deployment(NAMESPACE, deployment)
    except ApiException as e:
        if e.status == 409:
            existing = apps_api.read_namespaced_deployment("splunk", NAMESPACE)
            deployment.metadata.resource_version = existing.metadata.resource_version
            apps_api.replace_namespaced_deployment("splunk", NAMESPACE, deployment)
        else:
            raise

    # ── 4. Service (idempotent — skip patch if it already exists) ────────────
    service = client.V1Service(
        metadata=client.V1ObjectMeta(name="splunk", namespace=NAMESPACE, labels={"app": "splunk"}),
        spec=client.V1ServiceSpec(
            type="NodePort",
            selector={"app": "splunk"},
            ports=[
                client.V1ServicePort(name="web",     port=8000, target_port=8000, node_port=30500),
                client.V1ServicePort(name="hec",     port=8088, target_port=8088, node_port=30501),
                client.V1ServicePort(name="splunkd", port=8089, target_port=8089, node_port=30502),
                client.V1ServicePort(name="kvstore", port=8191, target_port=8191),
            ],
        ),
    )
    try:
        core.create_namespaced_service(NAMESPACE, service)
    except ApiException as e:
        if e.status != 409:
            raise

    return has_license


def get_splunkbase_app_status() -> dict:
    """
    Return install status for each Splunkbase app managed by this dashboard.
    Returns {folder_name: bool} — True if installed, False otherwise.
    """
    status = {app["folder_name"]: False for app in SPLUNKBASE_APPS}
    try:
        for app in SPLUNKBASE_APPS:
            r = requests.get(
                f"{SPLUNK_API_URL}/services/apps/local/{app['folder_name']}",
                auth=("admin", SPLUNK_PASSWORD),
                timeout=5,
            )
            status[app["folder_name"]] = (r.status_code == 200)
    except Exception:
        pass
    return status


def install_splunkbase_app(app_id: int, splunkbase_username: str, splunkbase_password: str) -> str:
    """
    Install a Splunkbase app by numeric ID using the Splunk CLI inside the pod.
    Returns stdout on success, raises RuntimeError on failure.
    """
    # Resolve the pod name
    pod_result = subprocess.run(
        ["kubectl", "get", "pods", "-n", NAMESPACE, "-l", "app=splunk",
         "-o", "jsonpath={.items[0].metadata.name}"],
        capture_output=True, text=True, timeout=15,
    )
    pod_name = pod_result.stdout.strip()
    if not pod_name:
        raise RuntimeError("Splunk pod not found — is Splunk deployed?")

    result = subprocess.run(
        [
            "kubectl", "exec", "-n", NAMESPACE, pod_name, "--",
            "/opt/splunk/bin/splunk", "install", "app",
            f"https://splunkbase.splunk.com/app/{app_id}/release/latest/download",
            "-auth", f"admin:{SPLUNK_PASSWORD}",
            "-splunkbase_username", splunkbase_username,
            "-splunkbase_password", splunkbase_password,
            "-update", "true",
        ],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def get_pod_status() -> dict:
    """
    Check the Splunk pod status in Kubernetes.
    Returns a dict with:
      - state: "not_found" | "running" | "pending" | "crash_loop" | "error" | "starting"
      - message: human-readable status
      - restart_count: number of container restarts
      - logs: last few log lines (if crashed)
    """
    try:
        core = _core()
        pods = core.list_namespaced_pod(
            NAMESPACE, label_selector="app=splunk"
        )
    except Exception:
        return {"state": "not_found", "message": "Cannot reach Kubernetes API", "restart_count": 0, "logs": ""}

    if not pods.items:
        return {"state": "not_found", "message": "No Splunk pod found", "restart_count": 0, "logs": ""}

    pod = pods.items[0]
    phase = pod.status.phase or "Unknown"

    if not pod.status.container_statuses:
        return {"state": "pending", "message": f"Pod phase: {phase}", "restart_count": 0, "logs": ""}

    cs = pod.status.container_statuses[0]
    restarts = cs.restart_count or 0

    # Running and ready
    if cs.ready and cs.state.running:
        return {"state": "running", "message": "Splunk is running", "restart_count": restarts, "logs": ""}

    # CrashLoopBackOff or Error
    if cs.state.waiting:
        reason = cs.state.waiting.reason or ""
        msg = cs.state.waiting.message or reason
        if "CrashLoopBackOff" in reason or "Error" in reason or restarts >= 2:
            # Grab recent logs to show the user what went wrong
            logs = ""
            try:
                logs = core.read_namespaced_pod_log(
                    pod.metadata.name, NAMESPACE,
                    container="splunk", tail_lines=15, previous=True,
                )
            except Exception:
                try:
                    logs = core.read_namespaced_pod_log(
                        pod.metadata.name, NAMESPACE,
                        container="splunk", tail_lines=15,
                    )
                except Exception:
                    pass
            return {"state": "crash_loop", "message": msg, "restart_count": restarts, "logs": logs}
        return {"state": "starting", "message": f"Waiting: {msg}", "restart_count": restarts, "logs": ""}

    # Container running but not ready yet (still starting up)
    if cs.state.running and not cs.ready:
        return {"state": "starting", "message": "Splunk is starting up...", "restart_count": restarts, "logs": ""}

    # Terminated
    if cs.state.terminated:
        reason = cs.state.terminated.reason or "Terminated"
        logs = ""
        try:
            logs = core.read_namespaced_pod_log(
                pod.metadata.name, NAMESPACE,
                container="splunk", tail_lines=15, previous=True,
            )
        except Exception:
            pass
        return {"state": "error", "message": reason, "restart_count": restarts, "logs": logs}

    return {"state": "pending", "message": f"Pod phase: {phase}", "restart_count": restarts, "logs": ""}
