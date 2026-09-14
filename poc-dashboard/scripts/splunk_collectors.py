"""
Cloud -> Splunk collectors.

Deploys small in-cluster pollers that pull from a Cisco cloud API over OUTBOUND
HTTPS and POST the results to the INTERNAL Splunk HEC
(splunk.piap.svc.cluster.local:8088). The poller initiates the connection
outbound, so the HEC never has to be exposed to the internet. Each source writes
to its own Splunk index so it's clear in the demo which component fed the data.

Sources:
  * cii            — Identity Intelligence GraphQL (listEndUsers)
  * duo            — Duo Admin API v2 authentication logs
  * secure_access  — Secure Access Reporting API (activity)

Each collector is a Deployment ("collector-<source>") in the piap namespace with
its API credentials in a Secret and its poller script in a ConfigMap. Deploying
is idempotent (patch on 409); removing deletes all three objects.
"""
import textwrap
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

NAMESPACE = "piap"
HEC_URL = "http://splunk.piap.svc.cluster.local:8088"
HEC_TOKEN = "piap-hec-token"
DEFAULT_INTERVAL = "300"  # seconds between polls


def _apps():
    config.load_incluster_config()
    return client.AppsV1Api()


def _core():
    config.load_incluster_config()
    return client.CoreV1Api()


# ── Poller scripts (run in python:3.12-slim after `pip install requests`) ────
# Each loops forever: pull from the source API, POST events to the internal HEC,
# sleep INTERVAL. Poll cursors persist in-process between iterations.

_CII_POLLER = r'''
import os, time, requests, urllib3
urllib3.disable_warnings()
TOKEN_URL=os.environ["CII_TOKEN_URL"]; CID=os.environ["CII_CLIENT_ID"]
CSEC=os.environ["CII_CLIENT_SECRET"]; API=os.environ["CII_API_URL"]
AUD=os.environ.get("CII_AUDIENCE") or None
HEC=os.environ["HEC_URL"]; HTOK=os.environ["HEC_TOKEN"]
INDEX=os.environ.get("INDEX","cii"); INTERVAL=int(os.environ.get("INTERVAL","300"))

def token():
    b={"client_id":CID,"client_secret":CSEC,"grant_type":"client_credentials"}
    if AUD: b["audience"]=AUD
    r=requests.post(TOKEN_URL,json=b,timeout=15)
    if r.status_code not in (200,201): r=requests.post(TOKEN_URL,data=b,timeout=15)
    r.raise_for_status(); return r.json()["access_token"]

def gql(t,q,v):
    r=requests.post(API,headers={"Authorization":"Bearer "+t,"Content-Type":"application/json"},
                    json={"query":q,"variables":v},timeout=30)
    r.raise_for_status(); d=r.json()
    if d.get("errors"): raise RuntimeError(str(d["errors"])[:300])
    return d["data"]

Q='query($p:Int){listEndUsers(input:{},pageSize:$p){items{displayName login status emails endUserTrustScore{score}} pageToken}}'
QB='query($p:Int){listEndUsers(input:{},pageSize:$p){items{displayName login status emails} pageToken}}'

def hec(ev):
    requests.post(HEC+"/services/collector/event",headers={"Authorization":"Splunk "+HTOK},
                  json={"index":INDEX,"sourcetype":"cii:enduser","event":ev},timeout=15,verify=False)

print("[cii] collector starting", flush=True)
while True:
    try:
        t=token()
        try: data=gql(t,Q,{"p":200})
        except Exception: data=gql(t,QB,{"p":200})
        items=(data.get("listEndUsers",{}) or {}).get("items",[]) or []
        for u in items: hec(u)
        print("[cii] pushed %d end users" % len(items), flush=True)
    except Exception as e:
        print("[cii] error: %s" % e, flush=True)
    time.sleep(INTERVAL)
'''

_DUO_POLLER = r'''
import os, time, base64, hmac, hashlib, email.utils, urllib.parse, requests, urllib3, json
urllib3.disable_warnings()
HOST=os.environ["DUO_HOST"]; IKEY=os.environ["DUO_IKEY"]; SKEY=os.environ["DUO_SKEY"]
HEC=os.environ["HEC_URL"]; HTOK=os.environ["HEC_TOKEN"]
INDEX=os.environ.get("INDEX","duo"); INTERVAL=int(os.environ.get("INTERVAL","300"))

# Minimal Duo Admin API v2 signing (sig v2, form-encoded canonicalization).
def duo_get(path, params):
    now=email.utils.formatdate()
    canon=[now, "GET", HOST.lower(), path,
           "&".join("%s=%s" % (urllib.parse.quote(k,"~"), urllib.parse.quote(str(params[k]),"~"))
                    for k in sorted(params))]
    canon="\n".join(canon)
    sig=hmac.new(SKEY.encode(), canon.encode(), hashlib.sha1).hexdigest()
    auth=base64.b64encode(("%s:%s" % (IKEY, sig)).encode()).decode()
    url="https://%s%s?%s" % (HOST, path, urllib.parse.urlencode(params))
    r=requests.get(url, headers={"Date":now, "Authorization":"Basic "+auth}, timeout=30)
    r.raise_for_status(); return r.json().get("response", {})

def hec(ev):
    requests.post(HEC+"/services/collector/event",headers={"Authorization":"Splunk "+HTOK},
                  json={"index":INDEX,"sourcetype":"duo:authentication","event":ev},timeout=15,verify=False)

mintime=int(time.time()*1000)-INTERVAL*1000
print("[duo] collector starting", flush=True)
while True:
    try:
        now=int(time.time()*1000)
        resp=duo_get("/admin/v2/logs/authentication", {"mintime":mintime,"maxtime":now,"limit":"1000"})
        logs=resp.get("authlogs",[]) if isinstance(resp,dict) else []
        for ev in logs: hec(ev)
        mintime=now+1
        print("[duo] pushed %d auth logs" % len(logs), flush=True)
    except Exception as e:
        print("[duo] error: %s" % e, flush=True)
    time.sleep(INTERVAL)
'''

_SECURE_ACCESS_POLLER = r'''
import os, time, base64, requests, urllib3
urllib3.disable_warnings()
KEY=os.environ["CSA_KEY"]; SEC=os.environ["CSA_SECRET"]
HEC=os.environ["HEC_URL"]; HTOK=os.environ["HEC_TOKEN"]
INDEX=os.environ.get("INDEX","secure_access"); INTERVAL=int(os.environ.get("INTERVAL","300"))
BASE="https://api.sse.cisco.com"

def token():
    enc=base64.b64encode(("%s:%s" % (KEY,SEC)).encode()).decode()
    r=requests.post(BASE+"/auth/v2/token",headers={"Authorization":"Basic "+enc},timeout=15)
    r.raise_for_status(); return r.json()["access_token"]

def hec(ev):
    requests.post(HEC+"/services/collector/event",headers={"Authorization":"Splunk "+HTOK},
                  json={"index":INDEX,"sourcetype":"secure_access:activity","event":ev},timeout=15,verify=False)

frm=int(time.time()*1000)-INTERVAL*1000
print("[secure_access] collector starting", flush=True)
while True:
    try:
        t=token(); now=int(time.time()*1000)
        r=requests.get(BASE+"/reports/v2/activity",headers={"Authorization":"Bearer "+t},
                       params={"from":frm,"to":now,"limit":"1000"},timeout=30)
        r.raise_for_status()
        data=r.json().get("data",[]) if isinstance(r.json(),dict) else []
        for ev in data: hec(ev)
        frm=now+1
        print("[secure_access] pushed %d activity events" % len(data), flush=True)
    except Exception as e:
        print("[secure_access] error: %s" % e, flush=True)
    time.sleep(INTERVAL)
'''

# Registry: source key -> config. `pip` lists extra packages the poller needs.
SOURCES = {
    "cii": {
        "index": "cii",
        "script": _CII_POLLER,
        "pip": "requests urllib3",
        "cred_env": ["CII_TOKEN_URL", "CII_CLIENT_ID", "CII_CLIENT_SECRET", "CII_API_URL", "CII_AUDIENCE"],
        "label": "Identity Intelligence",
    },
    "duo": {
        "index": "duo",
        "script": _DUO_POLLER,
        "pip": "requests urllib3",
        "cred_env": ["DUO_HOST", "DUO_IKEY", "DUO_SKEY"],
        "label": "Duo Admin API logs",
    },
    "secure_access": {
        "index": "secure_access",
        "script": _SECURE_ACCESS_POLLER,
        "pip": "requests urllib3",
        "cred_env": ["CSA_KEY", "CSA_SECRET"],
        "label": "Secure Access reporting",
    },
}


def _names(source_key):
    return {
        "deployment": f"collector-{source_key}",
        "secret": f"collector-{source_key}-creds",
        "configmap": f"collector-{source_key}-script",
    }


def deploy_collector(source_key, creds, interval=DEFAULT_INTERVAL):
    """
    Deploy (or update) the in-cluster poller for `source_key`.

    creds: dict of the source's credential env vars (see SOURCES[key]["cred_env"]).
    Returns the source label on success; raises on error.
    """
    if source_key not in SOURCES:
        raise ValueError(f"Unknown collector source: {source_key}")
    cfg = SOURCES[source_key]
    names = _names(source_key)
    core = _core()
    apps = _apps()

    # 1. Secret with the source credentials (blank values allowed for optionals)
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name=names["secret"], namespace=NAMESPACE),
        string_data={k: str(creds.get(k, "") or "") for k in cfg["cred_env"]},
    )
    _apply(core.create_namespaced_secret, core.patch_namespaced_secret, names["secret"], secret)

    # 2. ConfigMap with the poller script
    cm = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name=names["configmap"], namespace=NAMESPACE),
        data={"poller.py": cfg["script"]},
    )
    _apply(core.create_namespaced_config_map, core.patch_namespaced_config_map, names["configmap"], cm)

    # 3. Deployment running the poller
    env = [client.V1EnvVar(
        name=k,
        value_from=client.V1EnvVarSource(
            secret_key_ref=client.V1SecretKeySelector(name=names["secret"], key=k, optional=True)
        ),
    ) for k in cfg["cred_env"]]
    env += [
        client.V1EnvVar(name="HEC_URL", value=HEC_URL),
        client.V1EnvVar(name="HEC_TOKEN", value=HEC_TOKEN),
        client.V1EnvVar(name="INDEX", value=cfg["index"]),
        client.V1EnvVar(name="INTERVAL", value=str(interval)),
    ]

    container = client.V1Container(
        name="poller",
        image="python:3.12-slim",
        command=["/bin/sh", "-c"],
        args=[f"pip install --quiet --no-cache-dir {cfg['pip']} && exec python /app/poller.py"],
        env=env,
        volume_mounts=[client.V1VolumeMount(name="script", mount_path="/app", read_only=True)],
        resources=client.V1ResourceRequirements(
            requests={"memory": "128Mi", "cpu": "50m"},
            limits={"memory": "256Mi", "cpu": "250m"},
        ),
    )
    dep = client.V1Deployment(
        metadata=client.V1ObjectMeta(name=names["deployment"], namespace=NAMESPACE,
                                     labels={"app": names["deployment"]}),
        spec=client.V1DeploymentSpec(
            replicas=1,
            selector=client.V1LabelSelector(match_labels={"app": names["deployment"]}),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": names["deployment"]}),
                spec=client.V1PodSpec(
                    containers=[container],
                    volumes=[client.V1Volume(
                        name="script",
                        config_map=client.V1ConfigMapVolumeSource(name=names["configmap"]),
                    )],
                ),
            ),
        ),
    )
    _apply(apps.create_namespaced_deployment, apps.patch_namespaced_deployment, names["deployment"], dep)
    return cfg["label"]


def collector_status(source_key):
    """Return 'running' | 'starting' | 'not deployed' for a collector.

    Catches broadly (incl. missing in-cluster config) so a dashboard render
    outside the cluster degrades gracefully rather than erroring.
    """
    names = _names(source_key)
    try:
        apps = _apps()
        dep = apps.read_namespaced_deployment(names["deployment"], NAMESPACE)
        ready = dep.status.ready_replicas or 0
        return "running" if ready >= (dep.spec.replicas or 1) else "starting"
    except Exception:
        return "not deployed"


def remove_collector(source_key):
    """Delete the collector Deployment, Secret and ConfigMap (idempotent)."""
    names = _names(source_key)
    core = _core()
    apps = _apps()
    for delete, name in (
        (apps.delete_namespaced_deployment, names["deployment"]),
        (core.delete_namespaced_secret, names["secret"]),
        (core.delete_namespaced_config_map, names["configmap"]),
    ):
        try:
            delete(name, NAMESPACE)
        except ApiException as e:
            if e.status != 404:
                raise


def _apply(create_fn, patch_fn, name, body):
    """Create the object, or patch it if it already exists (409)."""
    try:
        create_fn(NAMESPACE, body)
    except ApiException as e:
        if e.status == 409:
            patch_fn(name, NAMESPACE, body)
        else:
            raise
