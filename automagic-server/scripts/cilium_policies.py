import os
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

NAMESPACE = "piap"
GROUP = "cilium.io"
VERSION = "v2"
PLURAL = "ciliumnetworkpolicies"

POLICY_NAMES = ["piap-zero-trust"]

# The Resource Connector runs as a Docker container on the same VM as k3s.
# When it routes traffic to pods, Docker NATs it to the node's LAN IP.
# Pods therefore see NODE_IP (the VM's LAN IP) as the connector source —
# not the docker-internal 240.x address.
# NODE_IP is injected automatically via the Kubernetes Downward API.
def _build_zero_trust_policy():
    node_ip = os.environ.get("NODE_IP", "")
    if not node_ip:
        raise RuntimeError("NODE_IP environment variable is not set.")
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "piap-zero-trust",
            "namespace": NAMESPACE,
        },
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
                {
                    "fromCIDR": [f"{node_ip}/32"]
                }
            ],
        },
    }


def _get_api():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CustomObjectsApi()


def apply_zero_trust():
    """Apply Zero Trust policy: workload pods only accept traffic from the Resource Connector (NODE_IP)."""
    api = _get_api()
    policy = _build_zero_trust_policy()
    name = policy["metadata"]["name"]
    results = []
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
    """Remove Zero Trust policies — Cilium defaults to allow-all with no policies."""
    api = _get_api()
    results = []
    for name in POLICY_NAMES:
        try:
            api.delete_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL, name)
            results.append(f"Deleted policy: {name}")
        except ApiException as e:
            if e.status == 404:
                results.append(f"Policy not found (already removed): {name}")
            else:
                raise
    return results


def get_active_policies():
    """Return names of active CiliumNetworkPolicies in the piap namespace."""
    api = _get_api()
    try:
        result = api.list_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL)
        return [item["metadata"]["name"] for item in result.get("items", [])]
    except Exception:
        return []
