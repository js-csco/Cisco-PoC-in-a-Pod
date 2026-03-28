"""
Trivy — container image vulnerability scanning for the k3s cluster.

Discovers every container image running across all namespaces, launches a
Kubernetes Job to scan them with Trivy, and parses the results into a
per-image severity summary.
"""
import json
import requests
import urllib3
from datetime import datetime
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NAMESPACE = "piap"
TRIVY_IMAGE = "aquasec/trivy:latest"

# Track which scan jobs have already been forwarded to Splunk
_forwarded_jobs = set()


def _core():
    config.load_incluster_config()
    return client.CoreV1Api()


def _batch():
    config.load_incluster_config()
    return client.BatchV1Api()


# ── Image discovery ───────────────────────────────────────────────────────────

def get_cluster_images():
    """Return sorted list of unique container images running across all namespaces."""
    core = _core()
    images = set()
    try:
        pods = core.list_pod_for_all_namespaces()
        for pod in pods.items:
            for cs in (pod.status.container_statuses or []):
                if cs.image:
                    images.add(cs.image)
            for cs in (pod.status.init_container_statuses or []):
                if cs.image:
                    images.add(cs.image)
    except Exception:
        pass
    return sorted(images)


# ── Scan Job management ──────────────────────────────────────────────────────

def _cleanup_old_jobs():
    """Delete previous trivy-scan Jobs so only the latest remains."""
    batch = _batch()
    try:
        jobs = batch.list_namespaced_job(NAMESPACE, label_selector="app=trivy-scan")
        for job in jobs.items:
            batch.delete_namespaced_job(
                job.metadata.name, NAMESPACE,
                propagation_policy="Background",
            )
    except Exception:
        pass


def run_scan():
    """
    Launch a Kubernetes Job that scans all cluster images with Trivy.
    Returns the Job name.
    """
    images = get_cluster_images()
    if not images:
        raise RuntimeError("No container images found in the cluster")

    _cleanup_old_jobs()

    batch = _batch()
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    job_name = f"trivy-scan-{timestamp}"

    # Build scan script — one trivy call per image with delimiters for parsing
    lines = [
        "trivy image --download-db-only --no-progress 2>/dev/null",
    ]
    for img in images:
        lines.append(f'echo "###TRIVY_IMAGE:{img}###"')
        lines.append(
            f'trivy image --format json --no-progress --skip-db-update '
            f'"{img}" 2>/dev/null || echo \'{{"Results":[]}}\''
        )
        lines.append('echo "###TRIVY_END###"')
    scan_script = "\n".join(lines)

    container = client.V1Container(
        name="trivy",
        image=TRIVY_IMAGE,
        command=["/bin/sh", "-c", scan_script],
        volume_mounts=[
            client.V1VolumeMount(name="trivy-cache", mount_path="/root/.cache"),
        ],
        resources=client.V1ResourceRequirements(
            requests={"memory": "256Mi", "cpu": "200m"},
            limits={"memory": "512Mi", "cpu": "500m"},
        ),
    )

    job = client.V1Job(
        metadata=client.V1ObjectMeta(
            name=job_name, namespace=NAMESPACE,
            labels={"app": "trivy-scan"},
        ),
        spec=client.V1JobSpec(
            backoff_limit=0,
            ttl_seconds_after_finished=3600,
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(
                    labels={"app": "trivy-scan", "job-name": job_name},
                ),
                spec=client.V1PodSpec(
                    containers=[container],
                    restart_policy="Never",
                    volumes=[
                        client.V1Volume(
                            name="trivy-cache",
                            host_path=client.V1HostPathVolumeSource(
                                path="/opt/trivy-cache", type="DirectoryOrCreate",
                            ),
                        ),
                    ],
                ),
            ),
        ),
    )

    batch.create_namespaced_job(NAMESPACE, job)
    return job_name


# ── Status & results ─────────────────────────────────────────────────────────

def get_scan_status():
    """
    Get the status of the most recent Trivy scan job.
    Returns dict with state, job_name, message.
    """
    try:
        batch = _batch()
        jobs = batch.list_namespaced_job(NAMESPACE, label_selector="app=trivy-scan")
    except Exception:
        return {"state": "no_scan", "job_name": None, "message": "No scans found"}

    if not jobs.items:
        return {"state": "no_scan", "job_name": None, "message": "No scans found"}

    latest = sorted(
        jobs.items, key=lambda j: j.metadata.creation_timestamp, reverse=True
    )[0]
    name = latest.metadata.name

    if latest.status.succeeded and latest.status.succeeded > 0:
        return {"state": "completed", "job_name": name, "message": "Scan completed"}
    if latest.status.failed and latest.status.failed > 0:
        return {"state": "failed", "job_name": name, "message": "Scan failed — check pod logs"}
    if latest.status.active and latest.status.active > 0:
        return {"state": "running", "job_name": name, "message": "Scanning images..."}
    return {"state": "pending", "job_name": name, "message": "Scan starting..."}


def get_scan_results():
    """
    Parse results from the most recent completed Trivy scan.
    Returns list of dicts: [{image, critical, high, medium, low, total}, ...]
    sorted by severity (most critical first).
    """
    status = get_scan_status()
    if status["state"] != "completed":
        return []

    core = _core()
    try:
        pods = core.list_namespaced_pod(
            NAMESPACE, label_selector=f"job-name={status['job_name']}"
        )
        if not pods.items:
            return []
        logs = core.read_namespaced_pod_log(
            pods.items[0].metadata.name, NAMESPACE, container="trivy",
        )
    except Exception:
        return []

    results = []
    sections = logs.split("###TRIVY_IMAGE:")
    for section in sections[1:]:
        try:
            header, rest = section.split("###", 1)
            image = header.strip()
            json_text = rest.split("###TRIVY_END###")[0].strip()

            data = json.loads(json_text)
            critical = high = medium = low = 0

            for result_block in data.get("Results", []):
                for vuln in result_block.get("Vulnerabilities", []):
                    sev = vuln.get("Severity", "").upper()
                    if sev == "CRITICAL":
                        critical += 1
                    elif sev == "HIGH":
                        high += 1
                    elif sev == "MEDIUM":
                        medium += 1
                    elif sev == "LOW":
                        low += 1

            results.append({
                "image": image,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "total": critical + high + medium + low,
            })
        except (ValueError, json.JSONDecodeError, IndexError, KeyError):
            continue

    results.sort(key=lambda r: (-r["critical"], -r["high"], r["image"]))
    return results


# ── Splunk HEC forwarding ────────────────────────────────────────────────────

def forward_to_splunk(results, job_name):
    """
    Send Trivy scan results to Splunk via HEC.
    Each image becomes one event (sourcetype=trivy:image:scan).
    Only forwards once per job_name to avoid duplicates on page refresh.
    """
    if not results or job_name in _forwarded_jobs:
        return

    from scripts.splunk import SPLUNK_HEC_URL, HEC_TOKEN, hec_is_healthy

    if not hec_is_healthy():
        return

    headers = {"Authorization": f"Splunk {HEC_TOKEN}"}
    hec_url = f"{SPLUNK_HEC_URL}/services/collector/event"

    for r in results:
        event = {
            "sourcetype": "trivy:image:scan",
            "source": "trivy",
            "event": {
                "scan_job": job_name,
                "image": r["image"],
                "critical": r["critical"],
                "high": r["high"],
                "medium": r["medium"],
                "low": r["low"],
                "total": r["total"],
            },
        }
        try:
            requests.post(hec_url, json=event, headers=headers, verify=False, timeout=5)
        except Exception:
            pass

    _forwarded_jobs.add(job_name)


# ── Splunk dashboard creation ─────────────────────────────────────────────────

TRIVY_DASHBOARD_XML = """\
<dashboard version="1.1" theme="dark">
  <label>Trivy — Vulnerability Scanner</label>
  <description>Container image CVE scan results from the k3s cluster</description>

  <row>
    <panel>
      <single>
        <title>Critical</title>
        <search><query>sourcetype="trivy:image:scan" | stats latest(critical) as count by image | stats sum(count) as Critical</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="colorBy">value</option>
        <option name="rangeColors">["0x2e7d32","0xb71c1c"]</option>
        <option name="rangeValues">[0]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>High</title>
        <search><query>sourcetype="trivy:image:scan" | stats latest(high) as count by image | stats sum(count) as High</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="colorBy">value</option>
        <option name="rangeColors">["0x2e7d32","0xe65100"]</option>
        <option name="rangeValues">[0]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Medium</title>
        <search><query>sourcetype="trivy:image:scan" | stats latest(medium) as count by image | stats sum(count) as Medium</query><earliest>-24h@h</earliest><latest>now</latest></search>
      </single>
    </panel>
    <panel>
      <single>
        <title>Low</title>
        <search><query>sourcetype="trivy:image:scan" | stats latest(low) as count by image | stats sum(count) as Low</query><earliest>-24h@h</earliest><latest>now</latest></search>
      </single>
    </panel>
  </row>

  <row>
    <panel>
      <table>
        <title>Vulnerabilities by Image</title>
        <search><query>sourcetype="trivy:image:scan" | dedup image | table image critical high medium low total | sort -critical -high</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="drilldown">none</option>
        <format type="color" field="critical"><colorPalette type="list">[#FFFFFF,#fce4ec,#e53935]</colorPalette><scale type="threshold">0,1</scale></format>
        <format type="color" field="high"><colorPalette type="list">[#FFFFFF,#fff3e0,#e65100]</colorPalette><scale type="threshold">0,1</scale></format>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <chart>
        <title>Top Vulnerable Images</title>
        <search><query>sourcetype="trivy:image:scan" | dedup image | eval label=replace(image,"^.*/","") | chart values(critical) as Critical values(high) as High by label | sort -Critical -High | head 10</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">bar</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.fieldColors">{"Critical":0xe53935,"High":0xe65100}</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Vulnerability Posture Over Time</title>
        <search><query>sourcetype="trivy:image:scan" | stats sum(critical) as Critical sum(high) as High by scan_job _time | timechart latest(Critical) as Critical latest(High) as High</query><earliest>-7d@d</earliest><latest>now</latest></search>
        <option name="charting.chart">area</option>
        <option name="charting.fieldColors">{"Critical":0xe53935,"High":0xe65100}</option>
      </chart>
    </panel>
  </row>

</dashboard>
"""


def create_splunk_dashboard():
    """
    Create (or update) the Trivy dashboard in Splunk via the REST API.
    Returns the dashboard URL path.
    """
    from scripts.splunk import SPLUNK_API_URL, SPLUNK_PASSWORD

    mgmt_url = SPLUNK_API_URL.replace("http://", "https://")
    dashboard_name = "trivy_vulnerability_scanner"
    endpoint = f"{mgmt_url}/servicesNS/admin/search/data/ui/views"

    # Try to create
    resp = requests.post(
        endpoint,
        auth=("admin", SPLUNK_PASSWORD),
        data={
            "name": dashboard_name,
            "eai:data": TRIVY_DASHBOARD_XML,
        },
        verify=False,
        timeout=15,
    )

    # If it already exists, update it
    if resp.status_code == 409:
        resp = requests.post(
            f"{endpoint}/{dashboard_name}",
            auth=("admin", SPLUNK_PASSWORD),
            data={"eai:data": TRIVY_DASHBOARD_XML},
            verify=False,
            timeout=15,
        )

    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Failed to create dashboard ({resp.status_code}): {resp.text[:300]}")

    return f"/app/search/{dashboard_name}"
