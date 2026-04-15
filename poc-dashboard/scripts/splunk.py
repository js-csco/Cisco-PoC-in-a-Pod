"""
Splunk helper — availability checks, HEC health, on-demand deployment,
and Splunkbase app installation from the dashboard.

Log sources: Cisco Duo / Identity Intelligence, Cisco Secure Access,
             OpenTelemetry Collector (k8s node/pod metrics + cluster events).
"""
import os
import textwrap
import requests
import urllib3
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_PASSWORD = "C1scoPoC!"

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
        "id":          5558,
        "folder_name": "cisco_secure_access",
        "display":     "Cisco Secure Access App for Splunk",
        "description": "Dashboards and visibility for Cisco Secure Access and Umbrella cloud security data.",
        "url":         "https://splunkbase.splunk.com/app/5558",
        "bundle":      "cisco_secure_access",
    },
    {
        "id":          7569,
        "folder_name": "cisco_secure_access_add_on",
        "display":     "Cisco Secure Access Add-on for Splunk",
        "description": "Ingest Cisco Secure Access and Umbrella event logs into Splunk.",
        "url":         "https://splunkbase.splunk.com/app/7569",
        "bundle":      "cisco_secure_access",
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

OTEL_IMAGE = "otel/opentelemetry-collector-contrib:0.140.0"

# OTel DaemonSet collector config (node CPU/memory/disk + kubelet pod metrics)
OTEL_DS_CONFIG = textwrap.dedent("""\
receivers:
  hostmetrics:
    root_path: /hostfs
    collection_interval: 30s
    scrapers:
      cpu:
      memory:
      disk:
      load:
      paging:
      network:
      filesystem:
        exclude_mount_points:
          mount_points:
            - /dev/.*
            - /proc/.*
            - /sys/.*
            - /run/k3s/.*
            - /var/lib/docker/.*
            - /var/lib/kubelet/.*
            - /snap/.*
          match_type: regexp

  kubeletstats:
    collection_interval: 30s
    auth_type: serviceAccount
    endpoint: "https://${env:K8S_NODE_IP}:10250"
    insecure_skip_verify: true
    metric_groups:
      - node
      - pod
      - container

processors:
  batch:
    timeout: 10s
    send_batch_size: 1000

exporters:
  splunk_hec/node:
    token: "piap-hec-token"
    endpoint: "http://splunk.piap.svc.cluster.local:8088/services/collector"
    source: "otel-k8s-node"
    sourcetype: "otel:metrics:node"

service:
  pipelines:
    metrics:
      receivers: [hostmetrics, kubeletstats]
      processors: [batch]
      exporters: [splunk_hec/node]
""")

# OTel Deployment collector config (cluster metrics + k8s events)
OTEL_DEPLOY_CONFIG = textwrap.dedent("""\
receivers:
  k8s_cluster:
    collection_interval: 30s
    node_conditions_to_report:
      - Ready
      - MemoryPressure
      - DiskPressure
      - PIDPressure
    allocatable_types_to_report:
      - cpu
      - memory
      - ephemeral-storage

  k8sobjects:
    auth_type: serviceAccount
    objects:
      - name: events
        mode: watch

processors:
  batch:
    timeout: 10s
    send_batch_size: 1000

exporters:
  splunk_hec/cluster:
    token: "piap-hec-token"
    endpoint: "http://splunk.piap.svc.cluster.local:8088/services/collector"
    source: "otel-k8s-cluster"
    sourcetype: "otel:metrics:cluster"

  splunk_hec/events:
    token: "piap-hec-token"
    endpoint: "http://splunk.piap.svc.cluster.local:8088/services/collector"
    source: "otel-k8s-events"
    sourcetype: "otel:k8s:events"

service:
  pipelines:
    metrics:
      receivers: [k8s_cluster]
      processors: [batch]
      exporters: [splunk_hec/cluster]
    logs:
      receivers: [k8sobjects]
      processors: [batch]
      exporters: [splunk_hec/events]
""")


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

    # ── 5. OTel Collector (always deployed alongside Splunk) ─────────────────
    # Errors are intentionally non-fatal: Splunk is already running at this
    # point, and the OTel status card on the dashboard will show the real state.
    try:
        _deploy_otel_collector()
    except Exception:
        pass

    return has_license


def _deploy_otel_collector():
    """
    Idempotently create the OpenTelemetry Collector stack in the piap namespace:
      - ServiceAccount + ClusterRole + ClusterRoleBinding (read-only k8s access)
      - DaemonSet  (hostmetrics + kubeletstats — one pod per node)
      - Deployment (k8s_cluster + k8sobjects — single cluster-wide instance)
    Called automatically by deploy_splunk(); safe to call multiple times.
    """
    config.load_incluster_config()
    core     = client.CoreV1Api()
    apps_api = client.AppsV1Api()
    rbac_api = client.RbacAuthorizationV1Api()

    def _apply_namespaced(create_fn, patch_fn, name, obj):
        try:
            create_fn(NAMESPACE, obj)
        except ApiException as e:
            if e.status == 409:
                patch_fn(name, NAMESPACE, obj)
            else:
                raise

    def _apply_cluster(create_fn, patch_fn, name, obj):
        try:
            create_fn(obj)
        except ApiException as e:
            if e.status == 409:
                patch_fn(name, obj)
            else:
                raise

    # ── ServiceAccount ──────────────────────────────────────────────────────
    _apply_namespaced(
        core.create_namespaced_service_account,
        core.patch_namespaced_service_account,
        "otel-collector",
        client.V1ServiceAccount(
            metadata=client.V1ObjectMeta(name="otel-collector", namespace=NAMESPACE),
        ),
    )

    # ── ClusterRole ─────────────────────────────────────────────────────────
    _apply_cluster(
        rbac_api.create_cluster_role,
        rbac_api.patch_cluster_role,
        "otel-collector",
        client.V1ClusterRole(
            metadata=client.V1ObjectMeta(name="otel-collector"),
            rules=[
                client.V1PolicyRule(
                    api_groups=[""],
                    resources=["events", "endpoints", "namespaces", "namespaces/status",
                               "nodes", "nodes/proxy", "nodes/stats", "pods", "pods/status",
                               "replicationcontrollers", "replicationcontrollers/status",
                               "resourcequotas", "services"],
                    verbs=["get", "list", "watch"],
                ),
                client.V1PolicyRule(
                    api_groups=["apps"],
                    resources=["daemonsets", "deployments", "replicasets", "statefulsets"],
                    verbs=["get", "list", "watch"],
                ),
                client.V1PolicyRule(
                    api_groups=["batch"],
                    resources=["jobs", "cronjobs"],
                    verbs=["get", "list", "watch"],
                ),
                client.V1PolicyRule(
                    api_groups=["autoscaling"],
                    resources=["horizontalpodautoscalers"],
                    verbs=["get", "list", "watch"],
                ),
            ],
        ),
    )

    # ── ClusterRoleBinding ──────────────────────────────────────────────────
    _apply_cluster(
        rbac_api.create_cluster_role_binding,
        rbac_api.patch_cluster_role_binding,
        "otel-collector",
        client.V1ClusterRoleBinding(
            metadata=client.V1ObjectMeta(name="otel-collector"),
            subjects=[client.V1Subject(
                kind="ServiceAccount", name="otel-collector", namespace=NAMESPACE,
            )],
            role_ref=client.V1RoleRef(
                kind="ClusterRole", name="otel-collector",
                api_group="rbac.authorization.k8s.io",
            ),
        ),
    )

    # ── DaemonSet ConfigMap ─────────────────────────────────────────────────
    _apply_namespaced(
        core.create_namespaced_config_map,
        core.patch_namespaced_config_map,
        "otel-collector-ds-config",
        client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name="otel-collector-ds-config", namespace=NAMESPACE),
            data={"config.yaml": OTEL_DS_CONFIG},
        ),
    )

    # ── DaemonSet ───────────────────────────────────────────────────────────
    _apply_namespaced(
        apps_api.create_namespaced_daemon_set,
        apps_api.patch_namespaced_daemon_set,
        "otel-collector-ds",
        client.V1DaemonSet(
            metadata=client.V1ObjectMeta(
                name="otel-collector-ds", namespace=NAMESPACE,
                labels={"app": "otel-collector-ds"},
            ),
            spec=client.V1DaemonSetSpec(
                selector=client.V1LabelSelector(match_labels={"app": "otel-collector-ds"}),
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(labels={"app": "otel-collector-ds"}),
                    spec=client.V1PodSpec(
                        service_account_name="otel-collector",
                        tolerations=[client.V1Toleration(operator="Exists")],
                        containers=[client.V1Container(
                            name="otel-collector",
                            image=OTEL_IMAGE,
                            args=["--config=/conf/config.yaml"],
                            env=[
                                client.V1EnvVar(
                                    name="K8S_NODE_NAME",
                                    value_from=client.V1EnvVarSource(
                                        field_ref=client.V1ObjectFieldSelector(field_path="spec.nodeName"),
                                    ),
                                ),
                                client.V1EnvVar(
                                    name="K8S_NODE_IP",
                                    value_from=client.V1EnvVarSource(
                                        field_ref=client.V1ObjectFieldSelector(field_path="status.hostIP"),
                                    ),
                                ),
                            ],
                            resources=client.V1ResourceRequirements(
                                requests={"cpu": "50m", "memory": "128Mi"},
                                limits={"cpu": "200m", "memory": "256Mi"},
                            ),
                            volume_mounts=[
                                client.V1VolumeMount(name="config", mount_path="/conf"),
                                client.V1VolumeMount(
                                    name="hostfs", mount_path="/hostfs",
                                    read_only=True, mount_propagation="HostToContainer",
                                ),
                            ],
                        )],
                        volumes=[
                            client.V1Volume(
                                name="config",
                                config_map=client.V1ConfigMapVolumeSource(name="otel-collector-ds-config"),
                            ),
                            client.V1Volume(
                                name="hostfs",
                                host_path=client.V1HostPathVolumeSource(path="/"),
                            ),
                        ],
                    ),
                ),
            ),
        ),
    )

    # ── Deployment ConfigMap ────────────────────────────────────────────────
    _apply_namespaced(
        core.create_namespaced_config_map,
        core.patch_namespaced_config_map,
        "otel-collector-deploy-config",
        client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name="otel-collector-deploy-config", namespace=NAMESPACE),
            data={"config.yaml": OTEL_DEPLOY_CONFIG},
        ),
    )

    # ── Deployment ──────────────────────────────────────────────────────────
    _apply_namespaced(
        apps_api.create_namespaced_deployment,
        apps_api.patch_namespaced_deployment,
        "otel-collector",
        client.V1Deployment(
            metadata=client.V1ObjectMeta(
                name="otel-collector", namespace=NAMESPACE,
                labels={"app": "otel-collector"},
            ),
            spec=client.V1DeploymentSpec(
                replicas=1,
                selector=client.V1LabelSelector(match_labels={"app": "otel-collector"}),
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(labels={"app": "otel-collector"}),
                    spec=client.V1PodSpec(
                        service_account_name="otel-collector",
                        containers=[client.V1Container(
                            name="otel-collector",
                            image=OTEL_IMAGE,
                            args=["--config=/conf/config.yaml"],
                            resources=client.V1ResourceRequirements(
                                requests={"cpu": "50m", "memory": "128Mi"},
                                limits={"cpu": "200m", "memory": "256Mi"},
                            ),
                            volume_mounts=[
                                client.V1VolumeMount(name="config", mount_path="/conf"),
                            ],
                        )],
                        volumes=[
                            client.V1Volume(
                                name="config",
                                config_map=client.V1ConfigMapVolumeSource(name="otel-collector-deploy-config"),
                            ),
                        ],
                    ),
                ),
            ),
        ),
    )


def otel_collector_running() -> bool:
    """Return True if the OTel DaemonSet exists and has at least one ready pod."""
    try:
        config.load_incluster_config()
        ds = client.AppsV1Api().read_namespaced_daemon_set("otel-collector-ds", NAMESPACE)
        return (ds.status.number_ready or 0) > 0
    except Exception:
        return False


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
    #   poc-dashboard mounts /opt/splunk-data at /splunk-data
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


# ── Kubernetes Infrastructure Dashboard ──────────────────────────────────────

K8S_DASHBOARD_NAME = "k8s_infrastructure"

K8S_DASHBOARD_XML = textwrap.dedent("""\
<dashboard version="1.1" theme="light">
  <label>Kubernetes Infrastructure</label>
  <description>Powered by OpenTelemetry Collector — cluster events, node health, and pod activity from k3s.</description>

  <row>
    <panel>
      <title>Cluster Events (Last 1h)</title>
      <single>
        <search>
          <query>source="otel-k8s-events" | stats count</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
      </single>
    </panel>
    <panel>
      <title>Warning Events (Last 1h)</title>
      <single>
        <search>
          <query>source="otel-k8s-events" | spath | search type=Warning | stats count</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="colorBy">value</option>
        <option name="colorMode">block</option>
        <option name="rangeColors">["0x53a051","0xd93f3c"]</option>
        <option name="rangeValues">[1]</option>
      </single>
    </panel>
    <panel>
      <title>Active Namespaces (Last 1h)</title>
      <single>
        <search>
          <query>source="otel-k8s-events" | spath | stats dc("involvedObject.namespace") as namespaces</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
      </single>
    </panel>
  </row>

  <row>
    <panel>
      <title>Events Over Time (24h)</title>
      <chart>
        <search>
          <query>source="otel-k8s-events" | spath
| eval event_type=if(type="Warning","Warning","Normal")
| timechart span=10m count by event_type</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.fieldColors">{"Warning": "#d32f2f", "Normal": "#2e7d32"}</option>
      </chart>
    </panel>
    <panel>
      <title>Top Event Reasons (24h)</title>
      <chart>
        <search>
          <query>source="otel-k8s-events" | spath
| stats count by reason
| sort -count
| head 10</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.axisTitleX.visibility">collapsed</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>Events by Namespace (24h)</title>
      <chart>
        <search>
          <query>source="otel-k8s-events" | spath
| stats count by "involvedObject.namespace"
| sort -count
| rename "involvedObject.namespace" as Namespace</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
    <panel>
      <title>Events by Object Kind (24h)</title>
      <chart>
        <search>
          <query>source="otel-k8s-events" | spath
| stats count by "involvedObject.kind"
| sort -count
| rename "involvedObject.kind" as Kind</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>Warning Events (Last 24h)</title>
      <table>
        <search>
          <query>source="otel-k8s-events" | spath | search type=Warning
| table _time, "involvedObject.namespace", "involvedObject.kind", "involvedObject.name", reason, message
| rename "involvedObject.namespace" as Namespace, "involvedObject.kind" as Kind,
         "involvedObject.name" as Object, reason as Reason, message as Message
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

  <row>
    <panel>
      <title>All Recent Events (Last 1h)</title>
      <table>
        <search>
          <query>source="otel-k8s-events" | spath
| table _time, type, "involvedObject.namespace", "involvedObject.kind", "involvedObject.name", reason, message
| rename "involvedObject.namespace" as Namespace, "involvedObject.kind" as Kind,
         "involvedObject.name" as Object, reason as Reason, type as Type, message as Message
| sort -_time
| head 100</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="count">25</option>
      </table>
    </panel>
  </row>
</dashboard>
""")


def k8s_dashboard_exists() -> bool:
    """Return True if the k8s infrastructure dashboard has been provisioned in Splunk."""
    try:
        mgmt_url = SPLUNK_API_URL.replace("http://", "https://")
        r = requests.get(
            f"{mgmt_url}/servicesNS/admin/search/data/ui/views/{K8S_DASHBOARD_NAME}",
            auth=("admin", SPLUNK_PASSWORD),
            verify=False,
            timeout=5,
        )
        return r.status_code == 200
    except Exception:
        return False


def provision_k8s_dashboard() -> str:
    """
    Create (or update) the Kubernetes Infrastructure dashboard in Splunk.
    Returns the relative URL path to open the dashboard.
    """
    mgmt_url = SPLUNK_API_URL.replace("http://", "https://")
    endpoint = f"{mgmt_url}/servicesNS/admin/search/data/ui/views"

    resp = requests.post(
        endpoint,
        auth=("admin", SPLUNK_PASSWORD),
        data={"name": K8S_DASHBOARD_NAME, "eai:data": K8S_DASHBOARD_XML},
        verify=False,
        timeout=15,
    )

    if resp.status_code == 409:
        # Already exists — update it
        resp = requests.post(
            f"{endpoint}/{K8S_DASHBOARD_NAME}",
            auth=("admin", SPLUNK_PASSWORD),
            data={"eai:data": K8S_DASHBOARD_XML},
            verify=False,
            timeout=15,
        )

    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Failed to provision dashboard ({resp.status_code}): {resp.text[:300]}")

    return f"/app/search/{K8S_DASHBOARD_NAME}"
