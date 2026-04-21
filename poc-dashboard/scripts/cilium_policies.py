from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

NAMESPACE = "piap"
GROUP = "cilium.io"
VERSION = "v2"
PLURAL = "ciliumnetworkpolicies"

POLICY_NAMES = ["piap-zero-trust"]

# piap services to lock down under Zero Trust.
# poc-dashboard, playbook, and httpbin (test tool) are excluded — always reachable from LAN.
# Hubble UI is in kube-system and unaffected by this namespace policy.
_PIAP_RESTRICTED_SERVICES = [
    "splunk", "rdp-server", "ssh-server", "sse-check", "kubectl-mcp", "saml-app",
]

# Docker bridge subnet assigned via daemon.json bip=240.0.0.1/29.
# Docker's ip-masq=false means the connector's 240.0.0.x source IP is preserved
# all the way to the pod — Cilium's TC hook on docker0 handles NodePort traffic
# directly in eBPF without going through POSTROUTING MASQUERADE.
DOCKER_BRIDGE_CIDR = "240.0.0.0/29"


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


def _build_zero_trust_policy():
    # Connector traffic arrives with source 240.0.0.x — no masquerade.
    # LAN clients (e.g. 10.10.2.2) have "world" identity and are blocked.
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "piap-zero-trust", "namespace": NAMESPACE},
        "spec": {
            "endpointSelector": {
                "matchExpressions": [
                    {
                        "key": "app",
                        "operator": "NotIn",
                        "values": ["poc-dashboard", "playbook", "httpbin"],
                    }
                ]
            },
            "ingress": [
                {"fromCIDR": [DOCKER_BRIDGE_CIDR]},
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
         preserves real client IPs — 240.0.0.x is the connector, LAN clients keep
         their real IPs (e.g. 10.10.2.x) and are blocked by the policy.
      2. Apply CiliumNetworkPolicy allowing ingress only from 240.0.0.0/29
         (the Docker bridge subnet configured in daemon.json bip).
    """
    api = _get_api()
    results = []

    for svc in _PIAP_RESTRICTED_SERVICES:
        if _patch_service_traffic_policy(svc, "Local"):
            results.append(f"Service {svc}: externalTrafficPolicy=Local")

    results.append(_apply_policy(api, _build_zero_trust_policy()))
    results.append(f"Connector CIDR: {DOCKER_BRIDGE_CIDR}")
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


# ---------------------------------------------------------------------------
# httpbin test pod helpers
# ---------------------------------------------------------------------------

def _get_apps_api():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.AppsV1Api()


def _ensure_httpbin():
    """Create httpbin deployment and ClusterIP service if they do not already exist."""
    apps_v1 = _get_apps_api()
    core_v1 = _get_core_api()

    try:
        apps_v1.read_namespaced_deployment("httpbin", NAMESPACE)
    except ApiException as e:
        if e.status == 404:
            apps_v1.create_namespaced_deployment(
                NAMESPACE,
                client.V1Deployment(
                    metadata=client.V1ObjectMeta(
                        name="httpbin", namespace=NAMESPACE, labels={"app": "httpbin"}
                    ),
                    spec=client.V1DeploymentSpec(
                        replicas=1,
                        selector=client.V1LabelSelector(match_labels={"app": "httpbin"}),
                        template=client.V1PodTemplateSpec(
                            metadata=client.V1ObjectMeta(labels={"app": "httpbin"}),
                            spec=client.V1PodSpec(
                                containers=[
                                    client.V1Container(
                                        name="httpbin",
                                        image="kennethreitz/httpbin",
                                        ports=[client.V1ContainerPort(container_port=80)],
                                        resources=client.V1ResourceRequirements(
                                            requests={"cpu": "50m", "memory": "64Mi"},
                                            limits={"cpu": "200m", "memory": "128Mi"},
                                        ),
                                    )
                                ]
                            ),
                        ),
                    ),
                ),
            )
        else:
            raise

    try:
        core_v1.read_namespaced_service("httpbin", NAMESPACE)
    except ApiException as e:
        if e.status == 404:
            core_v1.create_namespaced_service(
                NAMESPACE,
                client.V1Service(
                    metadata=client.V1ObjectMeta(
                        name="httpbin", namespace=NAMESPACE, labels={"app": "httpbin"}
                    ),
                    spec=client.V1ServiceSpec(
                        type="ClusterIP",
                        selector={"app": "httpbin"},
                        ports=[client.V1ServicePort(name="http", port=80, target_port=80)],
                    ),
                ),
            )
        else:
            raise


def exec_in_httpbin(command):
    """Execute a command list in the first running httpbin pod. Returns stdout+stderr."""
    from kubernetes.stream import stream as kube_stream
    v1 = _get_core_api()
    pods = v1.list_namespaced_pod(NAMESPACE, label_selector="app=httpbin")
    running = [p for p in pods.items if p.status.phase == "Running"]
    if not running:
        return "__notfound__"
    try:
        return kube_stream(
            v1.connect_get_namespaced_pod_exec,
            running[0].metadata.name,
            NAMESPACE,
            command=command,
            stderr=True, stdin=False, stdout=True, tty=False,
        ) or ""
    except Exception as e:
        return f"__error__: {e}"


# ---------------------------------------------------------------------------
# L7 HTTP policy
# ---------------------------------------------------------------------------

def _build_l7_http_policy():
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "piap-l7-http", "namespace": NAMESPACE},
        "spec": {
            "endpointSelector": {"matchLabels": {"app": "httpbin"}},
            "ingress": [
                {
                    "fromEndpoints": [{}],
                    "toPorts": [
                        {
                            "ports": [{"port": "80", "protocol": "TCP"}],
                            "rules": {"http": [{"method": "GET"}]},
                        }
                    ],
                }
            ],
        },
    }


def apply_l7_http():
    _ensure_httpbin()
    return _apply_policy(_get_api(), _build_l7_http_policy())


def remove_l7_http():
    return _delete_policy(_get_api(), "piap-l7-http", NAMESPACE)


# ---------------------------------------------------------------------------
# DNS / FQDN egress policy
# ---------------------------------------------------------------------------

def _build_dns_egress_policy():
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "piap-dns-egress", "namespace": NAMESPACE},
        "spec": {
            "endpointSelector": {"matchLabels": {"app": "httpbin"}},
            "egress": [
                # Allow DNS queries through Cilium's DNS proxy
                {
                    "toPorts": [
                        {
                            "ports": [
                                {"port": "53", "protocol": "UDP"},
                                {"port": "53", "protocol": "TCP"},
                            ],
                            "rules": {"dns": [{"matchPattern": "*"}]},
                        }
                    ]
                },
                # Allow outbound connections only to *.cisco.com
                {
                    "toFQDNs": [
                        {"matchPattern": "*.cisco.com"},
                        {"matchName": "cisco.com"},
                    ],
                    "toPorts": [
                        {
                            "ports": [
                                {"port": "443", "protocol": "TCP"},
                                {"port": "80", "protocol": "TCP"},
                            ]
                        }
                    ],
                },
            ],
        },
    }


def apply_dns_egress():
    _ensure_httpbin()
    return _apply_policy(_get_api(), _build_dns_egress_policy())


def remove_dns_egress():
    return _delete_policy(_get_api(), "piap-dns-egress", NAMESPACE)


# ---------------------------------------------------------------------------
# Network Policy Map — custom fine-grained policies
# ---------------------------------------------------------------------------

CUSTOM_LABEL = "poc-dashboard-custom"
PROTECTED_SERVICES = {"poc-dashboard", "playbook", "hubble-ui"}

# Virtual nodes that are not K8s services in the piap namespace but always appear.
# - resource-connector: Docker bridge (external, 240.0.0.x)
# - hubble-ui:          lives in kube-system, not piap
# - lan:                represents direct LAN clients (no K8s object at all)
_VIRTUAL_NODES = {"resource-connector", "hubble-ui", "lan"}

# Services that are always reachable from LAN regardless of Zero Trust mode.
LAN_ALWAYS_REACHABLE = ["poc-dashboard", "playbook", "hubble-ui"]

# Ordered list used for the diagram.
_DIAGRAM_SERVICES = [
    {"id": "lan",                "label": "LAN",                  "protected": False},
    {"id": "resource-connector", "label": "Resource Connector",   "cidr": DOCKER_BRIDGE_CIDR, "protected": False},
    {"id": "poc-dashboard",      "label": "PoC Dashboard",        "protected": True},
    {"id": "ssh-server",         "label": "SSH Server",           "protected": False},
    {"id": "rdp-server",         "label": "RDP Server",           "protected": False},
    {"id": "saml-app",           "label": "SAML App",             "protected": False},
    {"id": "kubectl-mcp",        "label": "Kubectl MCP",          "protected": False},
    {"id": "playbook",           "label": "PoC Playbook",         "protected": True},
    {"id": "sse-check",          "label": "SSE Check",            "protected": False},
    {"id": "uptime-kuma",        "label": "Uptime Kuma",          "protected": False},
    {"id": "hubble-ui",          "label": "Hubble UI",            "protected": True},
]

# Services that get the Zero Trust treatment (mirroring _PIAP_RESTRICTED_SERVICES)
_ZERO_TRUST_TARGETS = set(_PIAP_RESTRICTED_SERVICES)


def get_diagram_nodes():
    """Return node list for the chord diagram, supplemented with live K8s service data."""
    core = _get_core_api()
    try:
        live = {s.metadata.name for s in core.list_namespaced_service(NAMESPACE).items}
    except Exception:
        live = set()

    nodes = []
    for svc in _DIAGRAM_SERVICES:
        sid = svc["id"]
        if sid in _VIRTUAL_NODES or sid in live:
            nodes.append(dict(svc))
    return nodes


def get_custom_policies():
    """Return custom CiliumNetworkPolicies created by this tool."""
    api = _get_api()
    try:
        items = api.list_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL).get("items", [])
    except Exception:
        return []
    result = []
    for item in items:
        if item.get("metadata", {}).get("labels", {}).get("managed-by") == CUSTOM_LABEL:
            ann = item.get("metadata", {}).get("annotations", {})
            result.append({
                "name":        item["metadata"]["name"],
                "source":      ann.get("piap/source", "?"),
                "destination": ann.get("piap/destination", "?"),
                "port":        ann.get("piap/port", "*"),
                "protocol":    ann.get("piap/protocol", "TCP"),
                "action":      ann.get("piap/action", "allow"),
            })
    return result


def _custom_policy_name(source, destination, port, action):
    raw = f"piap-adv-{source[:10]}-{destination[:10]}-{str(port).replace('*','any')}-{action}"
    return raw.replace("/", "-")[:63].rstrip("-")


def apply_custom_policies(policies):
    """Apply a list of policy dicts.  Returns list of result dicts."""
    api = _get_api()
    results = []
    for p in policies:
        src  = p.get("source", "")
        dst  = p.get("destination", "")
        port = str(p.get("port", "*"))
        proto = p.get("protocol", "TCP").upper()
        action = p.get("action", "allow").lower()

        if dst in PROTECTED_SERVICES and action == "deny":
            results.append({"ok": False, "name": f"{src}→{dst}", "error": f"{dst} is protected — deny not allowed"})
            continue

        name = _custom_policy_name(src, dst, port, action)
        policy = {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {
                "name": name,
                "namespace": NAMESPACE,
                "labels": {"managed-by": CUSTOM_LABEL},
                "annotations": {
                    "piap/source":      src,
                    "piap/destination": dst,
                    "piap/port":        port,
                    "piap/protocol":    proto,
                    "piap/action":      action,
                },
            },
            "spec": {},
        }

        # endpointSelector: select destination pod
        policy["spec"]["endpointSelector"] = {"matchLabels": {"app": dst}}

        # ingress rule — source
        ingress = {}
        if src == "resource-connector":
            ingress["fromCIDR"] = [DOCKER_BRIDGE_CIDR]
        else:
            ingress["fromEndpoints"] = [{"matchLabels": {"app": src}}]

        # port filter (optional)
        if port not in ("*", "any", ""):
            ingress["toPorts"] = [{"ports": [{"port": port, "protocol": proto}]}]

        if action == "allow":
            policy["spec"]["ingress"] = [ingress]
        else:
            policy["spec"]["ingressDeny"] = [ingress]

        try:
            msg = _apply_policy(api, policy)
            results.append({"ok": True, "name": name, "result": msg})
        except Exception as e:
            results.append({"ok": False, "name": name, "error": str(e)})

    return results


def delete_custom_policy(name):
    return _delete_policy(_get_api(), name, NAMESPACE)
