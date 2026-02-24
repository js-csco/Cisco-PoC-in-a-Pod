import json
import datetime
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

NAMESPACE = "piap"
GROUP = "cilium.io"
VERSION = "v1alpha1"
PLURAL = "tracingpolicies"

POLICY_NAMES = ["detect-sensitive-file-read", "detect-shell-execution"]

# TracingPolicy: alert when any process opens /etc/shadow or /etc/passwd
POLICY_SENSITIVE_FILES = {
    "apiVersion": "cilium.io/v1alpha1",
    "kind": "TracingPolicy",
    "metadata": {
        "name": "detect-sensitive-file-read",
    },
    "spec": {
        "kprobes": [
            {
                "call": "fd_install",
                "syscall": False,
                "args": [
                    {"index": 0, "type": "int"},
                    {"index": 1, "type": "file"},
                ],
                "selectors": [
                    {
                        "matchArgs": [
                            {
                                "index": 1,
                                "operator": "Prefix",
                                "values": ["/etc/shadow", "/etc/passwd"],
                            }
                        ]
                    }
                ],
            }
        ]
    },
}

# TracingPolicy: alert when a shell binary is executed inside a pod
POLICY_SHELL_EXEC = {
    "apiVersion": "cilium.io/v1alpha1",
    "kind": "TracingPolicy",
    "metadata": {
        "name": "detect-shell-execution",
    },
    "spec": {
        "kprobes": [
            {
                "call": "security_bprm_check",
                "syscall": False,
                "args": [
                    {"index": 0, "type": "linux_binprm"},
                ],
                "selectors": [
                    {
                        "matchArgs": [
                            {
                                "index": 0,
                                "operator": "Postfix",
                                "values": ["/sh", "/bash", "/dash", "/ash"],
                            }
                        ]
                    }
                ],
            }
        ]
    },
}


def _get_clients():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CustomObjectsApi(), client.CoreV1Api(), client.BatchV1Api()


def deploy_policies():
    """Create or replace both TracingPolicies (cluster-scoped)."""
    api, _, _ = _get_clients()
    results = []
    for policy in [POLICY_SENSITIVE_FILES, POLICY_SHELL_EXEC]:
        name = policy["metadata"]["name"]
        try:
            api.create_cluster_custom_object(GROUP, VERSION, PLURAL, policy)
            results.append(f"Created TracingPolicy: {name}")
        except ApiException as e:
            if e.status == 409:
                api.replace_cluster_custom_object(GROUP, VERSION, PLURAL, name, policy)
                results.append(f"Updated TracingPolicy: {name}")
            else:
                raise
    return results


def remove_policies():
    """Delete both TracingPolicies."""
    api, _, _ = _get_clients()
    results = []
    for name in POLICY_NAMES:
        try:
            api.delete_cluster_custom_object(GROUP, VERSION, PLURAL, name)
            results.append(f"Deleted TracingPolicy: {name}")
        except ApiException as e:
            if e.status == 404:
                results.append(f"TracingPolicy not found (already removed): {name}")
            else:
                raise
    return results


def get_active_policies():
    """Return list of active TracingPolicy names. Returns [] if CRD not installed."""
    api, _, _ = _get_clients()
    try:
        result = api.list_cluster_custom_object(GROUP, VERSION, PLURAL)
        return [item["metadata"]["name"] for item in result.get("items", [])]
    except ApiException as e:
        if e.status in (404, 405):
            return []  # Tetragon CRD not installed yet
        raise
    except Exception:
        return []


def get_tetragon_events(max_lines=100):
    """
    Read recent Tetragon JSON events from the export-stdout sidecar container.
    Returns a list of parsed event dicts, newest last.
    """
    _, core_v1, _ = _get_clients()
    events = []

    # Tetragon runs as a DaemonSet in kube-system; grab the first pod we find
    for label_selector in [
        "app.kubernetes.io/name=tetragon",
        "app=tetragon",
        "k8s-app=tetragon",
    ]:
        try:
            pods = core_v1.list_namespaced_pod(
                namespace="kube-system",
                label_selector=label_selector,
            )
            if pods.items:
                pod_name = pods.items[0].metadata.name
                break
        except Exception:
            continue
    else:
        return events  # Tetragon not found

    # Try export-stdout first, fall back to main tetragon container
    for container in ["export-stdout", "tetragon"]:
        try:
            logs = core_v1.read_namespaced_pod_log(
                name=pod_name,
                namespace="kube-system",
                container=container,
                tail_lines=max_lines,
            )
            for line in logs.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    events.append(event)
                except json.JSONDecodeError:
                    continue
            if events:
                break
        except Exception:
            continue

    return events


def simulate_attack():
    """
    Launch a short-lived Kubernetes Job that performs suspicious actions
    (reading /etc/shadow and /etc/passwd) so Tetragon can detect them.
    Returns the job name.
    """
    _, _, batch_v1 = _get_clients()
    ts = datetime.datetime.utcnow().strftime("%H%M%S")
    job_name = f"attack-sim-{ts}"

    job_manifest = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_name,
            "namespace": NAMESPACE,
            "labels": {"app": "tetragon-attack-sim"},
        },
        "spec": {
            "ttlSecondsAfterFinished": 120,
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "attacker",
                            "image": "busybox",
                            "command": [
                                "sh",
                                "-c",
                                "echo '[SIM] Reading sensitive files...'; "
                                "cat /etc/shadow 2>/dev/null || true; "
                                "cat /etc/passwd 2>/dev/null || true; "
                                "echo '[SIM] Spawning shell...'; "
                                "sh -c 'id; whoami' 2>/dev/null || true; "
                                "echo '[SIM] Attack simulation complete.'",
                            ],
                        }
                    ],
                    "restartPolicy": "Never",
                }
            },
            "backoffLimit": 0,
        },
    }

    batch_v1.create_namespaced_job(namespace=NAMESPACE, body=job_manifest)
    return job_name
