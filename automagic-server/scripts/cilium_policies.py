import os
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

NAMESPACE = "piap"
GROUP = "cilium.io"
VERSION = "v2"
PLURAL = "ciliumnetworkpolicies"

POLICY_NAMES = ["piap-zero-trust"]

# piap services that should be locked down under zero trust.
# automagic is intentionally excluded — it must always be reachable from the LAN.
_PIAP_RESTRICTED_SERVICES = [
    "nginx", "splunk", "rdp-server", "ssh-server", "dashy", "sse-check", "kubectl-mcp",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_api():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CustomObjectsApi()


def _get_core_api():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


def _patch_service_traffic_policy(svc_name, policy):
    """Set externalTrafficPolicy on a piap service. Returns True if found, False if 404."""
    try:
        _get_core_api().patch_namespaced_service(
            svc_name, NAMESPACE, {"spec": {"externalTrafficPolicy": policy}}
        )
        return True
    except ApiException as e:
        if e.status == 404:
            return False
        raise


def _node_ip():
    """Return NODE_IP injected by the Kubernetes Downward API (status.hostIP)."""
    ip = os.environ.get("NODE_IP", "")
    if not ip:
        raise RuntimeError("NODE_IP environment variable is not set.")
    return ip


def _build_zero_trust_policy():
    """
    CiliumNetworkPolicy for the piap namespace.

    All workload pods except automagic only accept ingress from NODE_IP/32.

    Why NODE_IP/32?
      The Resource Connector runs as a Docker container on the same VM.
      Docker masquerades (SNATs) its traffic to the host's LAN IP before it
      reaches k3s, so pods see NODE_IP as the connector's source address.
      With externalTrafficPolicy: Local on every restricted service, real
      client IPs are preserved for NodePort traffic — direct LAN clients
      (e.g. 10.10.5.50) are therefore NOT NODE_IP and get blocked.
    """
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "piap-zero-trust", "namespace": NAMESPACE},
        "spec": {
            "endpointSelector": {
                "matchExpressions": [
                    {
                        "key": "io.kompose.service",
                        "operator": "NotIn",
                        "values": ["automagic"],
                    }
                ]
            },
            "ingress": [{"fromCIDR": [f"{_node_ip()}/32"]}],
        },
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def apply_zero_trust():
    """
    Apply Zero Trust:
      1. Patch restricted piap services to externalTrafficPolicy: Local so that
         real client IPs are visible to Cilium (no NodePort SNAT for external traffic).
      2. Apply a CiliumNetworkPolicy that only allows ingress from NODE_IP/32
         (the connector's Docker-NAT'd address).
    """
    api = _get_api()
    results = []

    # Step 1 — preserve real source IPs on restricted services
    for svc in _PIAP_RESTRICTED_SERVICES:
        if _patch_service_traffic_policy(svc, "Local"):
            results.append(f"Service {svc}: externalTrafficPolicy=Local")

    # Step 2 — apply network policy
    policy = _build_zero_trust_policy()
    name = policy["metadata"]["name"]
    try:
        api.create_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL, policy)
        results.append(f"Created policy: {name}")
    except ApiException as e:
        if e.status == 409:
            api.replace_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL, name, policy)
            results.append(f"Updated policy: {name}")
        else:
            raise

    return results


def apply_allow_all():
    """
    Remove Zero Trust:
      1. Delete the CiliumNetworkPolicy (Cilium defaults to allow-all with no policies).
      2. Restore externalTrafficPolicy: Cluster on all previously patched services.
    """
    api = _get_api()
    results = []

    # Step 1 — remove policy
    for name in POLICY_NAMES:
        try:
            api.delete_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL, name)
            results.append(f"Deleted policy: {name}")
        except ApiException as e:
            if e.status == 404:
                results.append(f"Policy not found (already removed): {name}")
            else:
                raise

    # Step 2 — restore default traffic policy
    for svc in _PIAP_RESTRICTED_SERVICES:
        if _patch_service_traffic_policy(svc, "Cluster"):
            results.append(f"Service {svc}: externalTrafficPolicy=Cluster")

    return results


def get_active_policies():
    """Return names of active CiliumNetworkPolicies in the piap namespace."""
    api = _get_api()
    try:
        result = api.list_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL)
        return [item["metadata"]["name"] for item in result.get("items", [])]
    except Exception:
        return []
