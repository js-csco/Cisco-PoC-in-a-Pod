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


DOCKER_BRIDGE_CIDR = "240.0.0.0/29"


def _get_connector_source_cidr():
    """
    Return /32 CIDR of the IP that connector traffic appears from inside pods.

    Hubble confirms source IP = the node's cilium_host interface IP.
    Docker masquerades connector traffic (240.0.0.x on docker0) to this IP.

    The CiliumNode CRD (spec.addresses[type=CiliumInternalIP]) holds the
    cilium_host IP — this differs from the k8s Node InternalIP (the LAN/
    management NIC, e.g. 10.10.5.63 vs the cilium_host 10.0.0.180).

    The network.cilium.io/ipv4-cilium-host node annotation is NOT used —
    it is unset on this cluster, so we read the CiliumNode object directly.
    """
    node_name = os.environ.get("NODE_NAME")
    if not node_name:
        return DOCKER_BRIDGE_CIDR
    try:
        api = _get_api()
        cilium_node = api.get_cluster_custom_object(GROUP, VERSION, "ciliumnodes", node_name)
        for addr in cilium_node.get("spec", {}).get("addresses", []):
            if addr.get("type") == "CiliumInternalIP":
                return f"{addr['ip']}/32"
    except Exception:
        pass
    return DOCKER_BRIDGE_CIDR


def _build_zero_trust_policy(connector_cidr):
    # Allow from every CIDR/entity that connector traffic might be classified as:
    #   1. fromCIDR cilium_host/32  — exact match when Cilium uses post-masquerade IP
    #   2. fromCIDR 240.0.0.0/29   — Docker bridge, in case Cilium uses pre-masquerade IP
    #   3. fromEntities host        — covers cases where cilium_host traffic gets "host" identity
    # LAN clients (e.g. 10.10.2.2) match none of these — they keep their real IPs and
    # have "world" identity, so they remain blocked.
    cidrs = [connector_cidr]
    if connector_cidr != DOCKER_BRIDGE_CIDR:
        cidrs.append(DOCKER_BRIDGE_CIDR)

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
            "ingress": [
                {"fromCIDR": cidrs},
                {"fromEntities": ["host"]},
            ],
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
         preserves real client IPs — connector traffic masquerades to cilium_host,
         LAN clients keep their real IPs (e.g. 10.10.2.x).
      2. Apply CiliumNetworkPolicy allowing ingress from cilium_host CIDR,
         Docker bridge CIDR, and host entity — covering all possible Cilium
         identity classifications for connector traffic.
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
