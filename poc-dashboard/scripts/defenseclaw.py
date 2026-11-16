"""
DefenseClaw + OpenClaw — AI Agent security governance for the k3s cluster.

Deploys a single-container Pod running:
  - OpenClaw    — AI agent + WebChat UI (Node.js, port 18789)
  - DefenseClaw — gateway, guardrail proxy and OpenClaw plugin. The plugin runs
                  inside OpenClaw, routes every LLM call through the guardrail
                  proxy and sends every tool call to the DefenseClaw gateway for
                  a verdict before it runs.

DefenseClaw requires both to run as the same OS user with the same home
directory, and `defenseclaw setup` has to restart OpenClaw to load the plugin,
so they share one container.
"""
import json, textwrap, secrets, base64
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.stream import stream

# Cilium policy constants
_CILIUM_GROUP = "cilium.io"
_CILIUM_VERSION = "v2"
_CILIUM_PLURAL = "ciliumnetworkpolicies"
_ISOLATION_POLICY_NAME = "ai-agent-isolation"

NAMESPACE = "defenseclaw"
DEPLOYMENT_NAME = "ai-agent"

# Optional agent integrations configured from the dashboard "Connect
# Integrations" section. Each is stored as its own Kubernetes Secret and is
# injected into the agent/gateway containers only when present.
MISTRAL_SECRET = "mistral-api-key"          # MISTRAL_API_KEY (legacy; superseded by llm-config)
SPLUNK_O11Y_SECRET = "splunk-o11y"          # SPLUNK_AO_REALM, SPLUNK_AO_O11Y_TOKEN
DUO_AGENT_SECRET = "duo-agent-identity"     # DUO_ISSUER, DUO_CLIENT_ID, DUO_CLIENT_SECRET, DUO_SCOPES

# LLM provider config — OpenClaw is provider-agnostic, so the dashboard lets you
# pick any provider and paste its key. Stored as one Secret with the provider id,
# the model ref, the provider's key env-var name (OpenClaw convention
# <PROVIDER>_API_KEY) and the key itself.
LLM_CONFIG_SECRET = "llm-config"
_PROVIDER_DEFAULT_MODEL = {
    "anthropic": "anthropic/claude-sonnet-5",
    "openai": "openai/gpt-5.6-sol",
    "mistral": "mistral/mistral-large-latest",
}


def _llm_key_env(provider):
    """OpenClaw's auth env var for a provider, e.g. anthropic -> ANTHROPIC_API_KEY."""
    return (provider or "").strip().upper().replace("-", "_") + "_API_KEY"

# Versions DefenseClaw is tested against: OpenClaw 2026.6.8, 2026.9.8 and
# 2026.10.9 (see DefenseClaw's OpenClaw connector docs). DefenseClaw 0.x only
# speaks gateway protocol 3, which current OpenClaw releases reject.
OPENCLAW_VERSION = "2026.10.9"
DEFENSECLAW_VERSION = "1.0.9"
DEFENSECLAW_INSTALLER = (
    f"https://github.com/cisco-ai-defense/defenseclaw/releases/download/"
    f"{DEFENSECLAW_VERSION}/install.sh"
)
CONTAINER_NAME = "ai-agent"
READY_FILE = "/tmp/defenseclaw-ready"

AGENT_STARTUP_SCRIPT = textwrap.dedent("""\
    set -e
    export HOME=/root
    export PATH="$HOME/.local/bin:$PATH"

    echo "[agent] Installing system packages..."
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends curl ca-certificates git >/dev/null

    echo "[agent] Installing OpenClaw {openclaw_version}..."
    npm install -g "openclaw@{openclaw_version}" --no-fund --no-audit --loglevel=error

    mkdir -p "$HOME/.openclaw"
    cp /config/openclaw.json "$HOME/.openclaw/openclaw.json"

    # Providers that aren't built in (anthropic/openai are) ship as plugins
    # that need explicit capability consent before the gateway will start
    # with them configured.
    for plugin in $OPENCLAW_PROVIDER_PLUGINS; do
        echo "[agent] Installing OpenClaw provider plugin '$plugin'..."
        openclaw plugins install "$plugin" --accept-capabilities 2>&1 | tail -3
    done

    # `defenseclaw setup` needs a running OpenClaw gateway to attach to.
    echo "[agent] Starting OpenClaw for DefenseClaw setup..."
    openclaw gateway > /tmp/openclaw-bootstrap.log 2>&1 &
    OPENCLAW_PID=$!
    for i in $(seq 1 90); do
        curl -sf -o /dev/null http://127.0.0.1:18789/ && break
        sleep 2
    done

    echo "[agent] Installing DefenseClaw {defenseclaw_version}..."
    curl -fsSL "{installer}" | bash -s -- --yes --version "{defenseclaw_version}" --connector openclaw

    echo "[agent] Configuring DefenseClaw for OpenClaw (action mode)..."
    defenseclaw quickstart --connector openclaw --mode action --scanner local --no-judge
    # The default pack only blocks CRITICAL; HIGH also covers leaked
    # credentials and environment dumps in tool calls.
    defenseclaw guardrail block-at HIGH

    # OpenClaw only loads the DefenseClaw plugin on start.
    kill "$OPENCLAW_PID"
    wait "$OPENCLAW_PID" || true

    touch {ready_file}
    echo "[agent] Starting OpenClaw with DefenseClaw..."
    exec openclaw gateway
""").format(
    openclaw_version=OPENCLAW_VERSION,
    defenseclaw_version=DEFENSECLAW_VERSION,
    installer=DEFENSECLAW_INSTALLER,
    ready_file=READY_FILE,
)


def _core():
    config.load_incluster_config()
    return client.CoreV1Api()


def _apps():
    config.load_incluster_config()
    return client.AppsV1Api()


def get_status():
    """Return status dict for the ai-agent Deployment."""
    status = {
        "namespace_exists": False,
        "api_key_set": False,
        "llm_configured": False,
        "llm_provider": "",
        "llm_model": "",
        "mistral_key_set": False,
        "splunk_o11y_set": False,
        "duo_agent_set": False,
        "gateway": {"ready": 0, "desired": 0, "state": "not deployed"},
        "openclaw": {"ready": 0, "desired": 0, "state": "not deployed"},
    }
    try:
        core = _core()
        core.read_namespace(NAMESPACE)
        status["namespace_exists"] = True
    except ApiException:
        return status

    # Check if the legacy Anthropic API key secret exists
    try:
        core.read_namespaced_secret("anthropic-api-key", NAMESPACE)
        status["api_key_set"] = True
    except ApiException:
        pass

    # LLM provider config (new, generic). Falls back to the legacy anthropic key.
    try:
        sec = core.read_namespaced_secret(LLM_CONFIG_SECRET, NAMESPACE)
        data = sec.data or {}
        prov = data.get("LLM_PROVIDER")
        mdl = data.get("LLM_MODEL")
        status["llm_provider"] = base64.b64decode(prov).decode() if prov else ""
        status["llm_model"] = base64.b64decode(mdl).decode() if mdl else ""
        status["llm_configured"] = True
    except ApiException:
        if status["api_key_set"]:
            status["llm_provider"] = "anthropic"
            status["llm_model"] = _PROVIDER_DEFAULT_MODEL["anthropic"]
            status["llm_configured"] = True

    # Check optional integration secrets (Mistral, Splunk O11y, Duo identity)
    for status_key, secret_name in (
        ("mistral_key_set", MISTRAL_SECRET),
        ("splunk_o11y_set", SPLUNK_O11Y_SECRET),
        ("duo_agent_set", DUO_AGENT_SECRET),
    ):
        try:
            core.read_namespaced_secret(secret_name, NAMESPACE)
            status[status_key] = True
        except ApiException:
            pass

    try:
        apps = _apps()
        dep = apps.read_namespaced_deployment(DEPLOYMENT_NAME, NAMESPACE)
        desired = dep.spec.replicas or 1
        ready = dep.status.ready_replicas or 0
        overall = "running" if ready >= desired else "starting"

        # OpenClaw and the DefenseClaw gateway share one container, so both
        # status cards follow that container.
        pod_list = core.list_namespaced_pod(
            NAMESPACE, label_selector=f"app={DEPLOYMENT_NAME}", limit=1
        )
        if pod_list.items:
            pod = pod_list.items[0]
            for cs in (pod.status.container_statuses or []):
                if cs.ready:
                    state = {"ready": 1, "desired": 1, "state": "running"}
                elif cs.state and cs.state.waiting:
                    reason = cs.state.waiting.reason or "waiting"
                    state = {"ready": 0, "desired": 1, "state": reason}
                else:
                    state = {"ready": 0, "desired": 1, "state": overall}
                keys = ("openclaw", "gateway") if cs.name == CONTAINER_NAME else (
                    "openclaw" if cs.name == "openclaw" else "gateway",)
                for key in keys:
                    status[key] = state
        else:
            for key in ("gateway", "openclaw"):
                status[key] = {"ready": ready, "desired": desired, "state": overall}
    except ApiException:
        pass

    # Read the gateway auth token from the ConfigMap so the UI can build
    # a working URL with #token=<value>
    try:
        cm = core.read_namespaced_config_map("ai-agent-config", NAMESPACE)
        oc_cfg = json.loads(cm.data.get("openclaw.json", "{}"))
        status["auth_token"] = oc_cfg.get("gateway", {}).get("auth", {}).get("token", "")
    except Exception:
        status["auth_token"] = ""

    return status


def save_api_key(api_key: str):
    """Store the Anthropic API key as a Kubernetes Secret."""
    config.load_incluster_config()
    core = client.CoreV1Api()

    # Ensure namespace exists
    try:
        core.create_namespace(
            client.V1Namespace(metadata=client.V1ObjectMeta(name=NAMESPACE))
        )
    except ApiException as e:
        if e.status != 409:
            raise

    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name="anthropic-api-key", namespace=NAMESPACE),
        string_data={"ANTHROPIC_API_KEY": api_key},
    )
    try:
        core.create_namespaced_secret(NAMESPACE, secret)
    except ApiException as e:
        if e.status == 409:
            core.patch_namespaced_secret("anthropic-api-key", NAMESPACE, secret)
        else:
            raise


def save_llm_provider(provider, api_key, model=None):
    """Store the chosen LLM provider + model + API key for the agent.

    `provider` is any OpenClaw provider id (anthropic, openai, mistral, …). The
    key is stored under the provider's env-var name (<PROVIDER>_API_KEY) and
    injected at deploy; OpenClaw's primary model is set to `model`.
    """
    provider = (provider or "anthropic").strip().lower()
    model = (model or "").strip() or _PROVIDER_DEFAULT_MODEL.get(provider, "")
    key_env = _llm_key_env(provider)

    config.load_incluster_config()
    core = client.CoreV1Api()
    try:
        core.create_namespace(
            client.V1Namespace(metadata=client.V1ObjectMeta(name=NAMESPACE))
        )
    except ApiException as e:
        if e.status != 409:
            raise

    _upsert_secret(core, LLM_CONFIG_SECRET, {
        "LLM_PROVIDER": provider,
        "LLM_MODEL": model,
        "LLM_API_KEY_NAME": key_env,
        "LLM_API_KEY": api_key,
    })
    return {"provider": provider, "model": model, "key_env": key_env}


def _read_llm_config(core):
    """Resolve the active LLM config, falling back to the legacy anthropic-api-key
    secret, then to Anthropic defaults. Returns provider/model and the Secret +
    key to source the API key env var from at deploy time."""
    try:
        sec = core.read_namespaced_secret(LLM_CONFIG_SECRET, NAMESPACE)
        data = sec.data or {}

        def _d(k):
            v = data.get(k)
            return base64.b64decode(v).decode() if v else ""

        provider = _d("LLM_PROVIDER") or "anthropic"
        return {
            "provider": provider,
            "model": _d("LLM_MODEL") or _PROVIDER_DEFAULT_MODEL.get(provider, ""),
            "key_env": _d("LLM_API_KEY_NAME") or _llm_key_env(provider),
            "secret": LLM_CONFIG_SECRET,
            "secret_key": "LLM_API_KEY",
        }
    except ApiException:
        # Legacy: key stored directly under the anthropic-api-key secret.
        return {
            "provider": "anthropic",
            "model": _PROVIDER_DEFAULT_MODEL["anthropic"],
            "key_env": "ANTHROPIC_API_KEY",
            "secret": "anthropic-api-key",
            "secret_key": "ANTHROPIC_API_KEY",
        }


def _upsert_secret(core, name, string_data):
    """Create or patch a namespaced Secret with the given string_data.

    Patching merges keys, so saving one field of a multi-field secret leaves the
    others intact.
    """
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name=name, namespace=NAMESPACE),
        string_data=string_data,
    )
    try:
        core.create_namespaced_secret(NAMESPACE, secret)
    except ApiException as e:
        if e.status == 409:
            core.patch_namespaced_secret(name, NAMESPACE, secret)
        else:
            raise


def save_integration_settings(mistral_key=None, splunk_realm=None,
                              splunk_token=None, duo_issuer=None,
                              duo_client_id=None, duo_client_secret=None,
                              duo_scopes=None):
    """Store optional agent integration settings as Kubernetes Secrets.

    Groups (only groups with at least one non-empty value are written, so the
    form can update one integration at a time):

      - Mistral LLM key -> Secret 'mistral-api-key' (MISTRAL_API_KEY)
      - Splunk Observability Cloud / Agent Observability (SaaS) -> Secret
        'splunk-o11y' (SPLUNK_AO_REALM, SPLUNK_AO_O11Y_TOKEN)
      - Duo Agentic Identity confidential client -> Secret 'duo-agent-identity'
        (DUO_ISSUER, DUO_CLIENT_ID, DUO_CLIENT_SECRET, DUO_SCOPES)

    Returns a dict indicating which groups were written.
    """
    config.load_incluster_config()
    core = client.CoreV1Api()

    # Ensure namespace exists
    try:
        core.create_namespace(
            client.V1Namespace(metadata=client.V1ObjectMeta(name=NAMESPACE))
        )
    except ApiException as e:
        if e.status != 409:
            raise

    saved = {"mistral": False, "splunk_o11y": False, "duo_agent": False}

    if mistral_key:
        _upsert_secret(core, MISTRAL_SECRET, {"MISTRAL_API_KEY": mistral_key})
        saved["mistral"] = True

    splunk_data = {}
    if splunk_realm:
        splunk_data["SPLUNK_AO_REALM"] = splunk_realm
    if splunk_token:
        splunk_data["SPLUNK_AO_O11Y_TOKEN"] = splunk_token
    if splunk_data:
        _upsert_secret(core, SPLUNK_O11Y_SECRET, splunk_data)
        saved["splunk_o11y"] = True

    duo_data = {}
    if duo_issuer:
        duo_data["DUO_ISSUER"] = duo_issuer
    if duo_client_id:
        duo_data["DUO_CLIENT_ID"] = duo_client_id
    if duo_client_secret:
        duo_data["DUO_CLIENT_SECRET"] = duo_client_secret
    if duo_scopes:
        duo_data["DUO_SCOPES"] = duo_scopes
    if duo_data:
        _upsert_secret(core, DUO_AGENT_SECRET, duo_data)
        saved["duo_agent"] = True

    return saved


def deploy_environment():
    """Create the namespace and deploy the ai-agent Pod (OpenClaw + DefenseClaw)."""
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

    # ── 2. Pre-generate the gateway auth token ─────────────────────────
    # Kept in the ConfigMap so the dashboard can build the WebChat URL.
    shared_token = secrets.token_hex(32)

    # Resolve the configured LLM provider/model (generic — any OpenClaw provider).
    llm = _read_llm_config(core)
    primary_model = llm["model"] or "anthropic/claude-sonnet-5"
    model_catalog = {
        "anthropic/claude-sonnet-5": {"alias": "Sonnet"},
        "anthropic/claude-opus-5": {"alias": "Opus"},
    }
    # Every non-built-in provider referenced here needs its plugin installed
    # (with capability consent) or the OpenClaw gateway refuses to start, so
    # only list Mistral when it is actually configured.
    try:
        core.read_namespaced_secret(MISTRAL_SECRET, NAMESPACE)
        model_catalog["mistral/mistral-large-latest"] = {"alias": "Mistral Large"}
    except ApiException:
        pass
    if primary_model and primary_model not in model_catalog:
        model_catalog[primary_model] = {"alias": primary_model.split("/")[-1]}
    provider_plugins = sorted(
        {m.split("/")[0] for m in model_catalog} - {"anthropic", "openai"}
    )

    openclaw_config = json.dumps({
        "gateway": {
            "mode": "local",
            "bind": "lan",
            "port": 18789,
            "auth": {"token": shared_token},
            "controlUi": {"allowedOrigins": ["*"]},
        },
        "agents": {
            "defaults": {
                "model": {"primary": primary_model},
                "models": model_catalog,
            }
        }
    }, indent=2)

    cm = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name="ai-agent-config", namespace=NAMESPACE),
        data={"openclaw.json": openclaw_config},
    )
    try:
        core.create_namespaced_config_map(NAMESPACE, cm)
    except ApiException as e:
        if e.status == 409:
            core.patch_namespaced_config_map("ai-agent-config", NAMESPACE, cm)
        else:
            raise

    # ── 3. Deployment ────────────────────────────────────────────────────
    config_volume = client.V1Volume(
        name="config",
        config_map=client.V1ConfigMapVolumeSource(name="ai-agent-config"),
    )

    # LLM API key env — named for the chosen provider (ANTHROPIC_API_KEY,
    # OPENAI_API_KEY, MISTRAL_API_KEY, …), sourced from whichever Secret holds it.
    api_key_env = client.V1EnvVar(
        name=llm["key_env"],
        value_from=client.V1EnvVarSource(
            secret_key_ref=client.V1SecretKeySelector(
                name=llm["secret"], key=llm["secret_key"], optional=True,
            )
        ),
    )
    llm_provider_env = client.V1EnvVar(name="LLM_PROVIDER", value=llm["provider"])
    provider_plugins_env = client.V1EnvVar(
        name="OPENCLAW_PROVIDER_PLUGINS", value=" ".join(provider_plugins),
    )

    # Optional integration env sourced from dashboard-managed Secrets. Each uses
    # optional=True so the deployment succeeds whether or not it's configured.
    # The agent consumes these to send GenAI traces to Splunk
    # Observability Cloud (Agent Observability) and to authenticate as a Duo
    # Agentic Identity confidential client.
    def _secret_env(var, secret_name):
        return client.V1EnvVar(
            name=var,
            value_from=client.V1EnvVarSource(
                secret_key_ref=client.V1SecretKeySelector(
                    name=secret_name, key=var, optional=True,
                )
            ),
        )

    integration_env = [
        _secret_env("MISTRAL_API_KEY", MISTRAL_SECRET),
        _secret_env("SPLUNK_AO_REALM", SPLUNK_O11Y_SECRET),
        _secret_env("SPLUNK_AO_O11Y_TOKEN", SPLUNK_O11Y_SECRET),
        _secret_env("DUO_ISSUER", DUO_AGENT_SECRET),
        _secret_env("DUO_CLIENT_ID", DUO_AGENT_SECRET),
        _secret_env("DUO_CLIENT_SECRET", DUO_AGENT_SECRET),
        _secret_env("DUO_SCOPES", DUO_AGENT_SECRET),
    ]

    agent_container = client.V1Container(
        name=CONTAINER_NAME,
        image="node:24-slim",
        command=["/bin/bash", "-c"],
        args=[AGENT_STARTUP_SCRIPT],
        ports=[
            client.V1ContainerPort(container_port=18789, name="webchat"),
        ],
        env=[api_key_env, llm_provider_env, provider_plugins_env] + integration_env,
        volume_mounts=[
            client.V1VolumeMount(name="config", mount_path="/config", read_only=True),
        ],
        readiness_probe=client.V1Probe(
            _exec=client.V1ExecAction(command=[
                "sh", "-c",
                f"test -f {READY_FILE} && curl -sf -o /dev/null http://127.0.0.1:18789/",
            ]),
            initial_delay_seconds=30,
            period_seconds=10,
            failure_threshold=3,
        ),
        resources=client.V1ResourceRequirements(
            requests={"memory": "1Gi", "cpu": "300m"},
            limits={"memory": "3Gi", "cpu": "2"},
        ),
    )

    dep = client.V1Deployment(
        metadata=client.V1ObjectMeta(name=DEPLOYMENT_NAME, namespace=NAMESPACE),
        spec=client.V1DeploymentSpec(
            replicas=1,
            strategy=client.V1DeploymentStrategy(type="Recreate"),
            selector=client.V1LabelSelector(match_labels={"app": DEPLOYMENT_NAME}),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": DEPLOYMENT_NAME}),
                spec=client.V1PodSpec(
                    containers=[agent_container],
                    volumes=[config_volume],
                ),
            ),
        ),
    )
    try:
        apps.create_namespaced_deployment(NAMESPACE, dep)
    except ApiException as e:
        if e.status != 409:
            raise
        # Replace rather than patch: a strategic-merge patch merges containers
        # by name and would keep containers from an older pod layout.
        existing = apps.read_namespaced_deployment(DEPLOYMENT_NAME, NAMESPACE)
        dep.metadata.resource_version = existing.metadata.resource_version
        apps.replace_namespaced_deployment(DEPLOYMENT_NAME, NAMESPACE, dep)

    # ── 4. Services ──────────────────────────────────────────────────────
    svc = client.V1Service(
        metadata=client.V1ObjectMeta(name="ai-agent", namespace=NAMESPACE),
        spec=client.V1ServiceSpec(
            type="NodePort",
            selector={"app": DEPLOYMENT_NAME},
            ports=[
                client.V1ServicePort(
                    name="webchat", port=18789, target_port=18789, node_port=31789,
                ),
            ],
        ),
    )
    try:
        core.create_namespaced_service(NAMESPACE, svc)
    except ApiException as e:
        if e.status != 409:
            raise
        # Replace so ports from older layouts are dropped (a patch merges them).
        existing = core.read_namespaced_service("ai-agent", NAMESPACE)
        svc.metadata.resource_version = existing.metadata.resource_version
        svc.spec.cluster_ip = existing.spec.cluster_ip
        core.replace_namespaced_service("ai-agent", NAMESPACE, svc)


# ═══════════════════════════════════════════════════════════════════════════
# Commands inside the running agent (device pairing, DefenseClaw audit log)
# ═══════════════════════════════════════════════════════════════════════════

def _agent_exec(command):
    """Run a shell command in the agent container and return its stdout."""
    core = _core()
    pods = core.list_namespaced_pod(
        NAMESPACE, label_selector=f"app={DEPLOYMENT_NAME}",
        field_selector="status.phase=Running",
    ).items
    if not pods:
        raise RuntimeError("AI agent pod is not running")
    # _preload_content=False: with preloading, the client may rewrite JSON
    # output into a Python repr.
    resp = stream(
        core.connect_get_namespaced_pod_exec, pods[0].metadata.name, NAMESPACE,
        container=CONTAINER_NAME,
        command=["sh", "-c", f'export PATH="$HOME/.local/bin:$PATH"; {command} 2>/dev/null'],
        stderr=True, stdin=False, stdout=True, tty=False,
        _preload_content=False,
    )
    resp.run_forever(timeout=60)
    out = resp.read_stdout() or ""
    resp.close()
    return out


def approve_pending_devices():
    """Approve every pending OpenClaw device pairing request.

    Browsers that open the WebChat UI over the LAN must be paired once
    (OpenClaw only auto-approves loopback connections). Returns the number of
    requests approved.
    """
    pending = json.loads(_agent_exec("openclaw devices list --json") or "{}").get("pending", [])
    for req in pending:
        _agent_exec(f"openclaw devices approve {req['requestId']}")
    return len(pending)


def get_audit_events(limit=25):
    """Return the newest DefenseClaw alerts (blocks, scan findings, quarantines)."""
    try:
        return json.loads(_agent_exec(f"defenseclaw alerts --json -n {int(limit)}") or "[]")
    except Exception:
        return []


# ═══════════════════════════════════════════════════════════════════════════
# Network isolation via CiliumNetworkPolicy
# ═══════════════════════════════════════════════════════════════════════════

def _custom_api():
    config.load_incluster_config()
    return client.CustomObjectsApi()


def _build_isolation_policy():
    """
    CiliumNetworkPolicy that isolates the AI agent pod:
      - Ingress: allow from anywhere (users need to reach the WebChat UI)
      - Egress:  allow DNS (kube-dns) + external HTTPS (LLM API)
      - Egress to all other cluster pods is BLOCKED
    """
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": _ISOLATION_POLICY_NAME, "namespace": NAMESPACE},
        "spec": {
            "endpointSelector": {
                "matchLabels": {"app": DEPLOYMENT_NAME}
            },
            "ingress": [
                {}  # allow all ingress (WebChat UI must be reachable)
            ],
            "egress": [
                # Allow DNS resolution (kube-dns in kube-system)
                {
                    "toEndpoints": [
                        {"matchLabels": {"k8s:io.kubernetes.pod.namespace": "kube-system",
                                         "k8s-app": "kube-dns"}}
                    ],
                    "toPorts": [
                        {"ports": [{"port": "53", "protocol": "UDP"},
                                   {"port": "53", "protocol": "TCP"}]}
                    ],
                },
                # Allow external HTTPS only (Anthropic API, GitHub for install)
                {
                    "toEntities": ["world"],
                    "toPorts": [
                        {"ports": [{"port": "443", "protocol": "TCP"}]}
                    ],
                },
            ],
        },
    }


def get_isolation_status():
    """Check if the isolation policy is active."""
    try:
        api = _custom_api()
        api.get_namespaced_custom_object(
            _CILIUM_GROUP, _CILIUM_VERSION, NAMESPACE, _CILIUM_PLURAL,
            _ISOLATION_POLICY_NAME,
        )
        return True
    except ApiException:
        return False


def isolate_agent():
    """Apply CiliumNetworkPolicy to isolate the AI agent from the cluster."""
    api = _custom_api()
    policy = _build_isolation_policy()
    try:
        api.create_namespaced_custom_object(
            _CILIUM_GROUP, _CILIUM_VERSION, NAMESPACE, _CILIUM_PLURAL, policy,
        )
    except ApiException as e:
        if e.status == 409:
            existing = api.get_namespaced_custom_object(
                _CILIUM_GROUP, _CILIUM_VERSION, NAMESPACE, _CILIUM_PLURAL,
                _ISOLATION_POLICY_NAME,
            )
            policy["metadata"]["resourceVersion"] = existing["metadata"]["resourceVersion"]
            api.replace_namespaced_custom_object(
                _CILIUM_GROUP, _CILIUM_VERSION, NAMESPACE, _CILIUM_PLURAL,
                _ISOLATION_POLICY_NAME, policy,
            )
        else:
            raise


def unisolate_agent():
    """Remove the isolation policy — agent can reach cluster services again."""
    try:
        api = _custom_api()
        api.delete_namespaced_custom_object(
            _CILIUM_GROUP, _CILIUM_VERSION, NAMESPACE, _CILIUM_PLURAL,
            _ISOLATION_POLICY_NAME,
        )
    except ApiException as e:
        if e.status != 404:
            raise
