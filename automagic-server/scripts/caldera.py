"""
Caldera C2 API helper.
All calls use the red-team API key (ADMIN123 by default).
"""
import os
import requests

CALDERA_URL = os.environ.get("CALDERA_URL", "http://caldera.piap.svc.cluster.local:8888")
API_KEY = os.environ.get("CALDERA_API_KEY", "ADMIN123")


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
    # Filter out empty/unnamed profiles
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
