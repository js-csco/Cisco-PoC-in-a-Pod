"""
Splunk helper — availability checks, HEC health, and Fluent Bit management.
"""
import os
import datetime
import requests
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

SPLUNK_URL     = os.environ.get("SPLUNK_URL",      "http://splunk.piap.svc.cluster.local:8000")
SPLUNK_HEC_URL = os.environ.get("SPLUNK_HEC_URL",  "http://splunk.piap.svc.cluster.local:8088")
HEC_TOKEN      = os.environ.get("SPLUNK_HEC_TOKEN", "piap-hec-token")

NAMESPACE            = "piap"
FLUENT_BIT_DAEMONSET = "fluent-bit"
FLUENT_BIT_CONFIGMAP = "fluent-bit-config"


def _core():
    config.load_incluster_config()
    return client.CoreV1Api()


def _apps():
    config.load_incluster_config()
    return client.AppsV1Api()


def is_available():
    try:
        r = requests.get(f"{SPLUNK_URL}/en-US/account/login", timeout=5, allow_redirects=True)
        return r.status_code in (200, 303)
    except Exception:
        return False


def hec_is_healthy():
    try:
        r = requests.get(
            f"{SPLUNK_HEC_URL}/services/collector/health",
            headers={"Authorization": f"Splunk {HEC_TOKEN}"},
            timeout=5,
        )
        return r.status_code == 200
    except Exception:
        return False


def get_forwarder_status():
    """Return (desired, ready) pod counts for the Fluent Bit DaemonSet, or (None, None)."""
    try:
        ds = _apps().read_namespaced_daemon_set(FLUENT_BIT_DAEMONSET, NAMESPACE)
        return (ds.status.desired_number_scheduled or 0, ds.status.number_ready or 0)
    except ApiException:
        return (None, None)


def get_enabled_sources():
    """Return which log sources are currently @INCLUDEd in the Fluent Bit config."""
    try:
        cm = _core().read_namespaced_config_map(FLUENT_BIT_CONFIGMAP, NAMESPACE)
        main = cm.data.get("fluent-bit.conf", "")
        return {
            "tetragon": "@INCLUDE input-tetragon.conf" in main,
            "hubble":   "@INCLUDE input-hubble.conf"   in main,
            "cilium":   "@INCLUDE input-cilium.conf"   in main,
        }
    except ApiException:
        return {"tetragon": True, "hubble": True, "cilium": True}


def configure_log_forwarding(sources: dict):
    """
    Patch the Fluent Bit ConfigMap to enable/disable log sources,
    then trigger a DaemonSet rollout so pods pick up the new config.
    """
    includes = []
    if sources.get("tetragon"):
        includes.append("    @INCLUDE input-tetragon.conf")
    if sources.get("hubble"):
        includes.append("    @INCLUDE input-hubble.conf")
    if sources.get("cilium"):
        includes.append("    @INCLUDE input-cilium.conf")

    includes_block = "\n".join(includes) if includes else "    # all sources disabled"

    new_main = (
        "[SERVICE]\n"
        "    Flush           5\n"
        "    Log_Level       info\n"
        "    Daemon          off\n"
        "    Parsers_File    parsers.conf\n"
        "    HTTP_Server     On\n"
        "    HTTP_Listen     0.0.0.0\n"
        "    HTTP_Port       2020\n\n"
        f"{includes_block}\n"
        "    @INCLUDE output-splunk.conf\n"
    )

    core = _core()
    cm = core.read_namespaced_config_map(FLUENT_BIT_CONFIGMAP, NAMESPACE)
    cm.data["fluent-bit.conf"] = new_main
    core.patch_namespaced_config_map(FLUENT_BIT_CONFIGMAP, NAMESPACE, cm)

    # Bump a pod-template annotation to trigger a rolling restart of the DaemonSet
    now = datetime.datetime.utcnow().isoformat() + "Z"
    _apps().patch_namespaced_daemon_set(
        FLUENT_BIT_DAEMONSET, NAMESPACE,
        {"spec": {"template": {"metadata": {"annotations": {
            "kubectl.kubernetes.io/restartedAt": now
        }}}}}
    )
