from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

NAMESPACE = "piap"
GROUP = "cilium.io"
VERSION = "v2"
PLURAL = "ciliumnetworkpolicies"

POLICY_NAMES = ["piap-zero-trust"]

# Cisco's setup_connector.sh always assigns 240.0.0.0/29 to the Docker bridge
# used by the Resource Connector container — this is fixed across every machine.
#
# With externalTrafficPolicy: Cluster (default), Cilium SNATs ALL NodePort traffic
# (connector AND LAN clients) to NODE_IP, making them indistinguishable in the pod.
#
# With externalTrafficPolicy: Local (applied below during zero trust), Cilium
# preserves real source IPs — connector traffic arrives from 240.0.0.x, LAN clients
# from their actual IP (e.g. 10.10.5.50).  The 240.0.0.0/29 CIDR then correctly
# allows the connector and blocks direct LAN access.
CONNECTOR_CIDR = "240.0.0.0/29"

# piap services to lock down. automagic is excluded — always reachable from LAN.
_PIAP_RESTRICTED_SERVICES = [
    "nginx", "splunk", "rdp-server", "ssh-server", "dashy", "sse-check", "kubectl-mcp",
]

POLICY_ZERO_TRUST = {
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
        "ingress": [{"fromCIDR": [CONNECTOR_CIDR]}],
    },
}


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


def _apply_policy(api, policy):
    """Create or replace a CiliumNetworkPolicy, handling resourceVersion correctly."""
    name = policy["metadata"]["name"]
    ns = policy["metadata"]["namespace"]
    try:
        api.create_namespaced_custom_object(GROUP, VERSION, ns, PLURAL, policy)
        return f"Created policy: {name}"
    except ApiException as e:
        if e.status == 409:
            # Kubernetes requires resourceVersion for updates — fetch it first.
            existing = api.get_namespaced_custom_object(GROUP, VERSION, ns, PLURAL, name)
            policy["metadata"]["resourceVersion"] = existing["metadata"]["resourceVersion"]
            api.replace_namespaced_custom_object(GROUP, VERSION, ns, PLURAL, name, policy)
            return f"Updated policy: {name}"
        raise


def _delete_policy(api, name, namespace):
    try:
        api.delete_namespaced_custom_object(GROUP, VERSION, namespace, PLURAL, name)
        return f"Deleted policy: {name}"
    except ApiException as e:
        if e.status == 404:
            return f"Policy not found (already removed): {name}"
        raise


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def apply_zero_trust():
    """
    Apply Zero Trust:
      1. Switch restricted piap services to externalTrafficPolicy: Local so Cilium
         sees real client IPs (no NodePort SNAT) — connector traffic stays at
         240.0.0.x, LAN clients stay at their real IPs.
      2. Apply CiliumNetworkPolicy allowing ingress only from 240.0.0.0/29.
    """
    api = _get_api()
    results = []

    for svc in _PIAP_RESTRICTED_SERVICES:
        if _patch_service_traffic_policy(svc, "Local"):
            results.append(f"Service {svc}: externalTrafficPolicy=Local")

    results.append(_apply_policy(api, dict(POLICY_ZERO_TRUST)))
    return results


def apply_allow_all():
    """
    Remove Zero Trust:
      1. Delete the CiliumNetworkPolicy (Cilium defaults to allow-all with no policies).
      2. Restore externalTrafficPolicy: Cluster on all previously patched services.
    """
    api = _get_api()
    results = []

    for name in POLICY_NAMES:
        results.append(_delete_policy(api, name, NAMESPACE))

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
