import os

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

NAMESPACE = "piap"
GROUP = "cilium.io"
VERSION = "v2"
PLURAL = "ciliumnetworkpolicies"

POLICY_NAMES = ["piap-zero-trust"]

# Docker bridge CIDR — injected at deploy time by the setup script via a K8s
# ConfigMap (piap-network-config / docker-bridge-cidr).  Falls back to Docker's
# standard default so the policy is never empty even if the ConfigMap is absent.
DOCKER_BRIDGE_CIDR = os.environ.get("DOCKER_BRIDGE_CIDR", "172.17.0.0/16")

# Zero trust policy: restricts all workload pods (everything except automagic)
# to only accept ingress from the Cisco Resource Connector Docker container.
# The connector runs as a plain Docker container on the host's default bridge.
# Traffic it forwards reaches pods with source IP in DOCKER_BRIDGE_CIDR.
POLICY_ZERO_TRUST = {
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
                "fromCIDR": [DOCKER_BRIDGE_CIDR]
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
    """Apply Zero Trust policy: workload pods only accept traffic from the connector Docker bridge."""
    api = _get_api()
    results = []
    name = POLICY_ZERO_TRUST["metadata"]["name"]
    try:
        api.create_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL, POLICY_ZERO_TRUST)
        results.append(f"Created policy: {name}")
    except ApiException as e:
        if e.status == 409:
            api.replace_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL, name, POLICY_ZERO_TRUST)
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
