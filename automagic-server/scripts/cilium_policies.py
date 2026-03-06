import os

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

NAMESPACE = "piap"
GROUP = "cilium.io"
VERSION = "v2"
PLURAL = "ciliumnetworkpolicies"

POLICY_NAMES = ["piap-zero-trust"]

# piap services to lock down. automagic is excluded — always reachable from LAN.
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


def _get_connector_source_cidr():
    """
    Return the CIDR that connector traffic appears to come from inside pods.

    The Connector runs as a Docker container on the host.  Docker masquerades
    its traffic to the host's primary NIC IP before it reaches the NodePort.
    Pods therefore see the host's InternalIP as the source — the same IP that
    `hostname -I | awk '{print $1}'` (SERVER_IP) returns during setup, and
    confirmed by the SSE check page showing 10.0.0.180 for connector traffic.

    Note: network.cilium.io/ipv4-cilium-host is Cilium's *virtual* gateway
    interface — a different IP from the physical NIC — and is NOT what pods
    see as the connector source.  We read InternalIP from node.status.addresses
    instead.

    Falls back to '240.0.0.0/29' (Docker bridge) if the node cannot be read.
    """
    node_name = os.environ.get("NODE_NAME")
    if not node_name:
        return "240.0.0.0/29"
    try:
        node = _get_core_api().read_node(node_name)
        for addr in (node.status.addresses or []):
            if addr.type == "InternalIP":
                return f"{addr.address}/32"
    except Exception:
        pass
    return "240.0.0.0/29"


def _build_zero_trust_policy(connector_cidr):
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
            "ingress": [{"fromCIDR": [connector_cidr]}],
        },
    }


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
         preserves real client IPs — connector traffic masquerades to the host's
         InternalIP, LAN clients keep their real IPs (e.g. 10.10.2.x).
      2. Apply CiliumNetworkPolicy allowing ingress only from the host InternalIP/32.
    """
    connector_cidr = _get_connector_source_cidr()
    api = _get_api()
    results = []

    for svc in _PIAP_RESTRICTED_SERVICES:
        if _patch_service_traffic_policy(svc, "Local"):
            results.append(f"Service {svc}: externalTrafficPolicy=Local")

    results.append(_apply_policy(api, _build_zero_trust_policy(connector_cidr)))
    results.append(f"Connector CIDR: {connector_cidr}")
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
