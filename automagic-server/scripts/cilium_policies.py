from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

NAMESPACE = "piap"
GROUP = "cilium.io"
VERSION = "v2"
PLURAL = "ciliumnetworkpolicies"

POLICY_NAMES = ["piap-zero-trust", "piap-connector-allow"]

# Zero trust policy: restricts all workload pods (everything except automagic and connector)
# to only accept ingress traffic from the connector pod.
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
                    "values": ["automagic", "connector"],
                }
            ]
        },
        "ingress": [
            {
                "fromEndpoints": [
                    {"matchLabels": {"app": "connector"}}
                ]
            }
        ],
    },
}

# Connector policy: allows the connector pod all ingress and egress so the
# Cisco Secure Access tunnel to the SSE cloud continues to work.
POLICY_CONNECTOR_ALLOW = {
    "apiVersion": "cilium.io/v2",
    "kind": "CiliumNetworkPolicy",
    "metadata": {
        "name": "piap-connector-allow",
        "namespace": NAMESPACE,
    },
    "spec": {
        "endpointSelector": {
            "matchLabels": {"app": "connector"}
        },
        "ingress": [{}],
        "egress": [{}],
    },
}


def _get_api():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CustomObjectsApi()


def apply_zero_trust():
    """Apply Zero Trust policies: workload pods only accept traffic from connector."""
    api = _get_api()
    results = []
    for policy in [POLICY_ZERO_TRUST, POLICY_CONNECTOR_ALLOW]:
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
