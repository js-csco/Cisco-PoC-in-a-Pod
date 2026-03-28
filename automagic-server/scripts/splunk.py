"""
Splunk helper — availability checks, HEC health, on-demand deployment,
and Splunkbase app installation from the dashboard.

Log sources: Cisco Duo / Identity Intelligence, Cisco Secure Access.
"""
import os
import requests
import urllib3
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
            verify=False,
            timeout=5,
        )
        if r.status_code == 200:
            return True
    except Exception:
        pass
    # HEC may be listening on HTTPS instead of HTTP
    try:
        hec_https = SPLUNK_HEC_URL.replace("http://", "https://")
        r = requests.get(
            f"{hec_https}/services/collector/health",
            headers={"Authorization": f"Splunk {HEC_TOKEN}"},
            verify=False,
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
        client.V1EnvVar(name="SPLUNK_START_ARGS", value="--accept-license"),
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
        image="splunk/splunk:9.3.2",
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

    init_container = client.V1Container(
        name="init-dirs",
        image="busybox",
        command=["sh", "-c",
                 "mkdir -p /opt/splunk/var/log/splunk "
                 "/opt/splunk/var/lib/splunk "
                 "/opt/splunk/var/run/splunk "
                 "/opt/splunk/var/spool/splunk "
                 "&& chown -R 41812:41812 /opt/splunk/var"],
        volume_mounts=[client.V1VolumeMount(name="splunk-data", mount_path="/opt/splunk/var")],
    )

    deployment = client.V1Deployment(
        metadata=client.V1ObjectMeta(name="splunk", namespace=NAMESPACE, labels={"app": "splunk"}),
        spec=client.V1DeploymentSpec(
            replicas=1,
            selector=client.V1LabelSelector(match_labels={"app": "splunk"}),
            strategy=client.V1DeploymentStrategy(type="Recreate"),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": "splunk"}),
                spec=client.V1PodSpec(
                    init_containers=[init_container],
                    containers=[container],
                    volumes=volumes,
                ),
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

    # ── 4. Service (delete-then-create to avoid stale NodePort allocations) ──
    try:
        core.delete_namespaced_service("splunk", NAMESPACE)
    except ApiException:
        pass  # not found — that's fine

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
    core.create_namespaced_service(NAMESPACE, service)

    return has_license


def get_splunkbase_app_status() -> dict:
    """
    Return install status for each Splunkbase app managed by this dashboard.
    Returns {folder_name: bool} — True if installed, False otherwise.

    First tries the configured folder_name. If that misses, fetches the full
    app list and matches by Splunkbase update URL (contains the app ID) so
    we detect apps regardless of their actual folder name.
    """
    mgmt_url = SPLUNK_API_URL.replace("http://", "https://")
    status = {app["folder_name"]: False for app in SPLUNKBASE_APPS}

    # Quick check by known folder name
    try:
        for app in SPLUNKBASE_APPS:
            r = requests.get(
                f"{mgmt_url}/services/apps/local/{app['folder_name']}",
                auth=("admin", SPLUNK_PASSWORD),
                verify=False,
                timeout=5,
            )
            if r.status_code == 200:
                status[app["folder_name"]] = True
    except Exception:
        pass

    # If any are still missing, scan the full app list for matching Splunkbase IDs
    missing = [a for a in SPLUNKBASE_APPS if not status[a["folder_name"]]]
    if missing:
        try:
            r = requests.get(
                f"{mgmt_url}/services/apps/local",
                auth=("admin", SPLUNK_PASSWORD),
                params={"output_mode": "json", "count": "0"},
                verify=False,
                timeout=10,
            )
            if r.status_code == 200:
                entries = r.json().get("entry", [])
                # Build a set of Splunkbase app IDs found in the installed apps
                installed_ids = set()
                for entry in entries:
                    details = entry.get("content", {})
                    update_url = details.get("update.checkout.url", "")
                    # update.checkout.url looks like /app/7404/... or similar
                    for app in missing:
                        if f"/app/{app['id']}" in update_url or f"/{app['id']}/" in update_url:
                            installed_ids.add(app["id"])
                    # Also check the label (display name) as a fallback
                    label = details.get("label", "")
                    for app in missing:
                        if label and label.lower() == app["display"].lower():
                            installed_ids.add(app["id"])
                for app in missing:
                    if app["id"] in installed_ids:
                        status[app["folder_name"]] = True
        except Exception:
            pass

    return status


def restart_splunk():
    """Restart the Splunk deployment by rolling out a new pod."""
    apps_api = _apps()
    apps_api.patch_namespaced_deployment(
        "splunk", NAMESPACE,
        body={"spec": {"template": {"metadata": {"annotations": {
            "piap/restartedAt": __import__("datetime").datetime.utcnow().isoformat()
        }}}}},
    )


def install_splunkbase_app(app_id: int, splunkbase_username: str, splunkbase_password: str) -> str:
    """
    Install a Splunkbase app via Splunk's REST API.

    1. Authenticate with Splunkbase to get session cookies.
    2. Resolve the latest version (Splunkbase has no "latest" alias).
    3. Download the app tarball.
    4. Upload to Splunk's /services/apps/local endpoint.
    """
    mgmt_url = SPLUNK_API_URL.replace("http://", "https://")

    # ── 1. Authenticate with Splunkbase ──────────────────────────────────────
    session = requests.Session()
    login_resp = session.post(
        "https://splunkbase.splunk.com/api/account:login/",
        data={"username": splunkbase_username, "password": splunkbase_password},
        timeout=30,
    )
    if login_resp.status_code != 200:
        raise RuntimeError(f"Splunkbase login failed ({login_resp.status_code}): check username/password")

    # ── 2. Resolve latest version ────────────────────────────────────────────
    releases_resp = session.get(
        f"https://splunkbase.splunk.com/api/v1/app/{app_id}/release",
        timeout=15,
    )
    if releases_resp.status_code != 200 or not releases_resp.json():
        raise RuntimeError(f"Could not find releases for app {app_id}")
    latest_version = releases_resp.json()[0].get("name", "")
    if not latest_version:
        raise RuntimeError(f"No version found for app {app_id}")

    # ── 3. Download the app tarball (follows 302 redirect to CDN) ────────────
    download_resp = session.get(
        f"https://splunkbase.splunk.com/app/{app_id}/release/{latest_version}/download/",
        timeout=180,
    )
    if download_resp.status_code != 200:
        raise RuntimeError(f"Download failed ({download_resp.status_code}) for v{latest_version}")

    # ── 4. Write tarball to shared hostPath volume ─────────────────────────
    #   automagic mounts /opt/splunk-data at /splunk-data
    #   Splunk   mounts /opt/splunk-data at /opt/splunk/var
    staging_path = "/splunk-data/splunkbase_app.tgz"
    with open(staging_path, "wb") as f:
        f.write(download_resp.content)

    # ── 5. Tell Splunk to install from its local filesystem ──────────────────
    install_resp = requests.post(
        f"{mgmt_url}/services/apps/local",
        auth=("admin", SPLUNK_PASSWORD),
        data={
            "name": "/opt/splunk/var/splunkbase_app.tgz",
            "update": "true",
            "filename": "true",
        },
        verify=False,
        timeout=120,
    )
    if install_resp.status_code not in (200, 201):
        raise RuntimeError(f"Splunk install failed ({install_resp.status_code}): {install_resp.text[:500]}")
    return f"App v{latest_version} installed successfully"


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


# ── Collectord (Outcold Solutions — Monitoring Kubernetes) ────────────────────

COLLECTORD_NAMESPACE = "collectorforkubernetes"
COLLECTORD_IMAGE = "docker.io/outcoldsolutions/collectord:latest"


def deploy_collectord(outcold_license: str) -> None:
    """
    Deploy the Collectord DaemonSet for Kubernetes monitoring.

    Creates:
      - Namespace collectorforkubernetes
      - ServiceAccount + ClusterRole + ClusterRoleBinding
      - Secret with HEC token and Outcold license
      - ConfigMap with Collectord configuration
      - DaemonSet running Collectord on every node
    """
    core = _core()
    apps_api = _apps()
    rbac = client.RbacAuthorizationV1Api()

    # ── 1. Namespace ──────────────────────────────────────────────────────────
    ns = client.V1Namespace(metadata=client.V1ObjectMeta(name=COLLECTORD_NAMESPACE))
    try:
        core.create_namespace(ns)
    except ApiException as e:
        if e.status != 409:
            raise

    # ── 2. ServiceAccount ─────────────────────────────────────────────────────
    sa = client.V1ServiceAccount(
        metadata=client.V1ObjectMeta(name=COLLECTORD_NAMESPACE, namespace=COLLECTORD_NAMESPACE),
    )
    try:
        core.create_namespaced_service_account(COLLECTORD_NAMESPACE, sa)
    except ApiException as e:
        if e.status != 409:
            raise

    # ── 3. ClusterRole ────────────────────────────────────────────────────────
    cr = client.V1ClusterRole(
        metadata=client.V1ObjectMeta(name=COLLECTORD_NAMESPACE),
        rules=[
            client.V1PolicyRule(
                api_groups=[""], resources=["pods", "nodes", "events", "namespaces",
                                            "services", "endpoints", "persistentvolumes",
                                            "persistentvolumeclaims", "componentstatuses"],
                verbs=["get", "list", "watch"],
            ),
            client.V1PolicyRule(
                api_groups=["apps"], resources=["deployments", "replicasets", "daemonsets", "statefulsets"],
                verbs=["get", "list", "watch"],
            ),
            client.V1PolicyRule(
                api_groups=["batch"], resources=["jobs", "cronjobs"],
                verbs=["get", "list", "watch"],
            ),
            client.V1PolicyRule(
                api_groups=[""], resources=["nodes/stats"],
                verbs=["get"],
            ),
        ],
    )
    try:
        rbac.create_cluster_role(cr)
    except ApiException as e:
        if e.status == 409:
            rbac.patch_cluster_role(COLLECTORD_NAMESPACE, cr)
        else:
            raise

    # ── 4. ClusterRoleBinding ─────────────────────────────────────────────────
    crb = client.V1ClusterRoleBinding(
        metadata=client.V1ObjectMeta(name=COLLECTORD_NAMESPACE),
        role_ref=client.V1RoleRef(api_group="rbac.authorization.k8s.io", kind="ClusterRole", name=COLLECTORD_NAMESPACE),
        subjects=[client.RbacV1Subject(kind="ServiceAccount", name=COLLECTORD_NAMESPACE, namespace=COLLECTORD_NAMESPACE)],
    )
    try:
        rbac.create_cluster_role_binding(crb)
    except ApiException as e:
        if e.status == 409:
            rbac.patch_cluster_role_binding(COLLECTORD_NAMESPACE, crb)
        else:
            raise

    # ── 5. Secret (HEC token + Outcold license) ──────────────────────────────
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name=COLLECTORD_NAMESPACE, namespace=COLLECTORD_NAMESPACE),
        string_data={
            "splunk-token": f"output.splunk__token={HEC_TOKEN}",
            "license": f"general__lic={outcold_license.strip()}",
        },
    )
    try:
        core.create_namespaced_secret(COLLECTORD_NAMESPACE, secret)
    except ApiException as e:
        if e.status == 409:
            core.patch_namespaced_secret(COLLECTORD_NAMESPACE, COLLECTORD_NAMESPACE, secret)
        else:
            raise

    # ── 6. ConfigMap ──────────────────────────────────────────────────────────
    hec_url = f"http://splunk.{NAMESPACE}.svc.cluster.local:8088/services/collector/event"
    config_ini = (
        "[general]\n"
        "acceptLicense = true\n"
        "\n"
        "[output.splunk]\n"
        f"url = {hec_url}\n"
        "insecure = true\n"
    )
    cm = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name=COLLECTORD_NAMESPACE, namespace=COLLECTORD_NAMESPACE),
        data={"collectord.conf": config_ini},
    )
    try:
        core.create_namespaced_config_map(COLLECTORD_NAMESPACE, cm)
    except ApiException as e:
        if e.status == 409:
            core.patch_namespaced_config_map(COLLECTORD_NAMESPACE, COLLECTORD_NAMESPACE, cm)
        else:
            raise

    # ── 7. DaemonSet ──────────────────────────────────────────────────────────
    container = client.V1Container(
        name="collectord",
        image=COLLECTORD_IMAGE,
        env=[
            client.V1EnvVar(
                name="KUBERNETES_NODENAME",
                value_from=client.V1EnvVarSource(
                    field_ref=client.V1ObjectFieldSelector(field_path="spec.nodeName"),
                ),
            ),
        ],
        env_from=[
            client.V1EnvFromSource(secret_ref=client.V1SecretEnvSource(name=COLLECTORD_NAMESPACE)),
        ],
        volume_mounts=[
            client.V1VolumeMount(name="config", mount_path="/etc/collectord/"),
            client.V1VolumeMount(name="varlog", mount_path="/var/log", read_only=True),
            client.V1VolumeMount(name="varlibdockercontainers", mount_path="/var/lib/docker/containers", read_only=True),
            client.V1VolumeMount(name="runcontainerd", mount_path="/run/containerd", read_only=True),
            client.V1VolumeMount(name="varlogpods", mount_path="/var/log/pods", read_only=True),
        ],
        resources=client.V1ResourceRequirements(
            requests={"memory": "128Mi", "cpu": "100m"},
            limits={"memory": "256Mi", "cpu": "200m"},
        ),
        security_context=client.V1SecurityContext(privileged=True),
    )

    ds = client.V1DaemonSet(
        metadata=client.V1ObjectMeta(name="collectord", namespace=COLLECTORD_NAMESPACE, labels={"app": "collectord"}),
        spec=client.V1DaemonSetSpec(
            selector=client.V1LabelSelector(match_labels={"app": "collectord"}),
            update_strategy=client.V1DaemonSetUpdateStrategy(type="RollingUpdate"),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": "collectord"}),
                spec=client.V1PodSpec(
                    service_account_name=COLLECTORD_NAMESPACE,
                    host_network=True,
                    dns_policy="ClusterFirstWithHostNet",
                    tolerations=[
                        client.V1Toleration(effect="NoSchedule", operator="Exists"),
                        client.V1Toleration(effect="NoExecute", operator="Exists"),
                    ],
                    containers=[container],
                    volumes=[
                        client.V1Volume(name="config", config_map=client.V1ConfigMapVolumeSource(name=COLLECTORD_NAMESPACE)),
                        client.V1Volume(name="varlog", host_path=client.V1HostPathVolumeSource(path="/var/log")),
                        client.V1Volume(name="varlibdockercontainers", host_path=client.V1HostPathVolumeSource(path="/var/lib/docker/containers")),
                        client.V1Volume(name="runcontainerd", host_path=client.V1HostPathVolumeSource(path="/run/containerd")),
                        client.V1Volume(name="varlogpods", host_path=client.V1HostPathVolumeSource(path="/var/log/pods")),
                    ],
                ),
            ),
        ),
    )
    try:
        apps_api.create_namespaced_daemon_set(COLLECTORD_NAMESPACE, ds)
    except ApiException as e:
        if e.status == 409:
            existing = apps_api.read_namespaced_daemon_set("collectord", COLLECTORD_NAMESPACE)
            ds.metadata.resource_version = existing.metadata.resource_version
            apps_api.replace_namespaced_daemon_set("collectord", COLLECTORD_NAMESPACE, ds)
        else:
            raise


def get_collectord_status() -> dict:
    """
    Check Collectord DaemonSet status.
    Returns dict with state, desired, ready, message.
    """
    try:
        apps_api = _apps()
        ds = apps_api.read_namespaced_daemon_set("collectord", COLLECTORD_NAMESPACE)
    except ApiException as e:
        if e.status == 404:
            return {"state": "not_deployed", "desired": 0, "ready": 0, "message": "Collectord not deployed"}
        return {"state": "error", "desired": 0, "ready": 0, "message": str(e)}
    except Exception as e:
        return {"state": "error", "desired": 0, "ready": 0, "message": str(e)}

    desired = ds.status.desired_number_scheduled or 0
    ready = ds.status.number_ready or 0

    if desired == 0:
        return {"state": "pending", "desired": desired, "ready": ready, "message": "DaemonSet scheduled on 0 nodes"}
    if ready == desired:
        return {"state": "running", "desired": desired, "ready": ready, "message": f"All {ready} pod(s) ready"}
    if ready > 0:
        return {"state": "partial", "desired": desired, "ready": ready, "message": f"{ready}/{desired} pod(s) ready"}
    return {"state": "starting", "desired": desired, "ready": ready, "message": f"0/{desired} pod(s) ready — starting up"}
