"""
DefenseClaw + OpenClaw — AI Agent security governance for the k3s cluster.

Deploys DefenseClaw Gateway and OpenClaw agent into the cluster and
provides status checks.
"""
import os
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

NAMESPACE = "defenseclaw"
GATEWAY_IMAGE = "ghcr.io/cisco-ai-defense/defenseclaw-gateway:latest"
OPENCLAW_IMAGE = "ghcr.io/cisco-ai-defense/openclaw:latest"


def _core():
    config.load_incluster_config()
    return client.CoreV1Api()


def _apps():
    config.load_incluster_config()
    return client.AppsV1Api()


def get_status():
    """Return status dict for DefenseClaw components in the cluster."""
    status = {
        "namespace_exists": False,
        "gateway": {"ready": 0, "desired": 0, "state": "not deployed"},
        "openclaw": {"ready": 0, "desired": 0, "state": "not deployed"},
    }
    try:
        core = _core()
        core.read_namespace(NAMESPACE)
        status["namespace_exists"] = True
    except ApiException:
        return status

    apps = _apps()
    for name, key in [("defenseclaw-gateway", "gateway"), ("openclaw-agent", "openclaw")]:
        try:
            dep = apps.read_namespaced_deployment(name, NAMESPACE)
            desired = dep.spec.replicas or 1
            ready = dep.status.ready_replicas or 0
            status[key] = {
                "ready": ready,
                "desired": desired,
                "state": "running" if ready >= desired else "starting",
            }
        except ApiException:
            pass

    return status


def deploy_environment():
    """Create the namespace and deploy DefenseClaw Gateway + OpenClaw agent."""
    config.load_incluster_config()
    core = client.CoreV1Api()
    apps = client.AppsV1Api()

    # ── 1. Namespace ─────────────────────────────────────────────────────
    try:
        core.create_namespace(
            client.V1Namespace(metadata=client.V1ObjectMeta(name=NAMESPACE))
        )
    except ApiException as e:
        if e.status != 409:
            raise

    # ── 2. DefenseClaw Gateway Deployment ────────────────────────────────
    gw_dep = client.V1Deployment(
        metadata=client.V1ObjectMeta(name="defenseclaw-gateway", namespace=NAMESPACE),
        spec=client.V1DeploymentSpec(
            replicas=1,
            selector=client.V1LabelSelector(match_labels={"app": "defenseclaw-gateway"}),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": "defenseclaw-gateway"}),
                spec=client.V1PodSpec(
                    containers=[
                        client.V1Container(
                            name="gateway",
                            image=GATEWAY_IMAGE,
                            ports=[
                                client.V1ContainerPort(container_port=8080, name="api"),
                                client.V1ContainerPort(container_port=9090, name="ws"),
                            ],
                            env=[
                                client.V1EnvVar(name="DEFENSECLAW_MODE", value="action"),
                                client.V1EnvVar(name="DEFENSECLAW_LOG_LEVEL", value="info"),
                            ],
                        )
                    ],
                ),
            ),
        ),
    )
    _apply_deployment(apps, "defenseclaw-gateway", NAMESPACE, gw_dep)

    # ── 3. Gateway Service ───────────────────────────────────────────────
    svc = client.V1Service(
        metadata=client.V1ObjectMeta(name="defenseclaw-gateway", namespace=NAMESPACE),
        spec=client.V1ServiceSpec(
            selector={"app": "defenseclaw-gateway"},
            ports=[
                client.V1ServicePort(name="api", port=8080, target_port=8080),
                client.V1ServicePort(name="ws", port=9090, target_port=9090),
            ],
        ),
    )
    try:
        core.create_namespaced_service(NAMESPACE, svc)
    except ApiException as e:
        if e.status != 409:
            raise

    # ── 4. OpenClaw Agent Deployment ─────────────────────────────────────
    oc_dep = client.V1Deployment(
        metadata=client.V1ObjectMeta(name="openclaw-agent", namespace=NAMESPACE),
        spec=client.V1DeploymentSpec(
            replicas=1,
            selector=client.V1LabelSelector(match_labels={"app": "openclaw-agent"}),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": "openclaw-agent"}),
                spec=client.V1PodSpec(
                    containers=[
                        client.V1Container(
                            name="openclaw",
                            image=OPENCLAW_IMAGE,
                            env=[
                                client.V1EnvVar(
                                    name="DEFENSECLAW_GATEWAY",
                                    value=f"http://defenseclaw-gateway.{NAMESPACE}.svc.cluster.local:8080",
                                ),
                            ],
                        )
                    ],
                ),
            ),
        ),
    )
    _apply_deployment(apps, "openclaw-agent", NAMESPACE, oc_dep)


def _apply_deployment(apps, name, namespace, dep):
    """Create or update a Deployment."""
    try:
        apps.create_namespaced_deployment(namespace, dep)
    except ApiException as e:
        if e.status == 409:
            apps.patch_namespaced_deployment(name, namespace, dep)
        else:
            raise
