"""
Build the "PoC in a Pod" Splunk app.

Creates (idempotently, via the Splunk management REST API):
  * a `splunker` user (password C1sco12345)
  * the `poc_in_a_pod` app (label "PoC in a Pod")
  * a set of dashboards spanning every PoC data source (each source has its own
    index — see scripts.splunk.POC_INDEXES)
  * a nav menu listing them

Dashboards are intentionally robust: they lean on event counts / stats / top so
they still render even before field extractions are tuned for a given tenant.
"""
import requests
import urllib3

from scripts.splunk import SPLUNK_PASSWORD, _mgmt_url

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

APP = "poc_in_a_pod"
APP_LABEL = "PoC in a Pod"
SPLUNKER_USER = "splunker"
SPLUNKER_PW = "C1sco12345"


def _auth():
    return ("admin", SPLUNK_PASSWORD)


# ── User ────────────────────────────────────────────────────────────────────
def create_splunker_user(role="admin"):
    """Create (or update the password of) the splunker user. Returns status."""
    url = f"{_mgmt_url()}/services/authentication/users"
    r = requests.post(
        url, auth=_auth(),
        data={"name": SPLUNKER_USER, "password": SPLUNKER_PW, "roles": role},
        verify=False, timeout=15,
    )
    if r.status_code in (200, 201):
        return "created"
    if r.status_code in (400, 409) and "already exists" in r.text.lower():
        requests.post(
            f"{url}/{SPLUNKER_USER}", auth=_auth(),
            data={"password": SPLUNKER_PW, "roles": role},
            verify=False, timeout=15,
        )
        return "updated"
    raise RuntimeError(f"Failed to create user ({r.status_code}): {r.text[:200]}")


# ── App + views + nav ─────────────────────────────────────────────────────────
def _ensure_app():
    # Create the app scaffold (409 if it already exists — that's fine).
    requests.post(
        f"{_mgmt_url()}/services/apps/local", auth=_auth(),
        data={"name": APP, "template": "barebones", "visible": "true", "label": APP_LABEL},
        verify=False, timeout=30,
    )
    # Ensure label + visibility via app.conf [ui].
    requests.post(
        f"{_mgmt_url()}/servicesNS/nobody/{APP}/configs/conf-app/ui", auth=_auth(),
        data={"label": APP_LABEL, "is_visible": "true"},
        verify=False, timeout=15,
    )


def _upsert_view(name, xml):
    base = f"{_mgmt_url()}/servicesNS/nobody/{APP}/data/ui/views"
    r = requests.post(base, auth=_auth(), data={"name": name, "eai:data": xml}, verify=False, timeout=30)
    if r.status_code == 409:
        r = requests.post(f"{base}/{name}", auth=_auth(), data={"eai:data": xml}, verify=False, timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Failed to upsert view '{name}' ({r.status_code}): {r.text[:200]}")


def _upsert_nav(xml):
    base = f"{_mgmt_url()}/servicesNS/nobody/{APP}/data/ui/nav"
    r = requests.post(base, auth=_auth(), data={"name": "default", "eai:data": xml}, verify=False, timeout=15)
    if r.status_code == 409:
        requests.post(f"{base}/default", auth=_auth(), data={"eai:data": xml}, verify=False, timeout=15)


# ── Dashboards (SimpleXML) ────────────────────────────────────────────────────
def _panel_events_over_time(title, spl):
    return f"""
  <panel>
    <title>{title}</title>
    <chart>
      <search><query>{spl}</query><earliest>-24h@h</earliest><latest>now</latest></search>
      <option name="charting.chart">line</option>
    </chart>
  </panel>"""


_OVERVIEW = """<dashboard version="1.1" theme="light">
  <label>PoC in a Pod — Overview</label>
  <description>Single pane of glass — which PoC components are feeding Splunk.</description>
  <row>
    <panel>
      <title>Events by source (index) — last 24h</title>
      <chart>
        <search><query>index=cii OR index=duo OR index=secure_access OR index=defenseclaw OR index=piap_host OR index=piap_connector OR index=piap_security
| stats count by index | sort -count</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <title>Ingest over time by source</title>
      <chart>
        <search><query>index=cii OR index=duo OR index=secure_access OR index=defenseclaw OR index=piap_host OR index=piap_connector OR index=piap_security
| timechart span=10m count by index</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>
</dashboard>"""


_VM_METRICS = """<dashboard version="1.1" theme="light">
  <label>VM Metrics &amp; More</label>
  <description>Ubuntu VM host telemetry from the Universal Forwarder (piap_host / piap_connector) and OpenTelemetry node metrics.</description>
  <row>
    <panel>
      <title>Host CPU utilization (OpenTelemetry, best-effort)</title>
      <chart>
        <search><query>| mstats avg(system.cpu.utilization) AS cpu WHERE index=piap_metrics span=1m</query><earliest>-4h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
    <panel>
      <title>Host log volume (syslog)</title>
      <chart>
        <search><query>index=piap_host | timechart span=10m count by sourcetype</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>SSH / authentication activity (auth.log)</title>
      <table>
        <search><query>index=piap_host sourcetype=linux_secure ("Accepted" OR "Failed" OR "sudo")
| rex field=_raw "(?&lt;action&gt;Accepted|Failed) (?&lt;method&gt;\\w+) for (?&lt;acct&gt;\\S+) from (?&lt;src_ip&gt;\\d+\\.\\d+\\.\\d+\\.\\d+)"
| stats count by action, acct, src_ip | sort -count | head 20</query><earliest>-24h@h</earliest><latest>now</latest></search>
      </table>
    </panel>
    <panel>
      <title>Connector / Docker log volume</title>
      <chart>
        <search><query>index=piap_connector | timechart span=10m count</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
  </row>
</dashboard>"""


_ZERO_TRUST = """<dashboard version="1.1" theme="light">
  <label>Zero Trust — All Connections</label>
  <description>Every connection through the Zero Trust stack — identity (Duo), access (Secure Access), and network flows (Cilium/Hubble).</description>
  <row>
    <panel>
      <title>Connections over time by layer</title>
      <chart>
        <search><query>index=duo OR index=secure_access OR index=piap_security
| eval layer=case(index=="duo","Identity (Duo)", index=="secure_access","Access (Secure Access)", index=="piap_security","Network (Cilium/Tetragon)", 1==1, index)
| timechart span=10m count by layer</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    <panel>
      <title>Allowed vs blocked / denied</title>
      <chart>
        <search><query>index=duo OR index=secure_access
| eval decision=coalesce(verdict, action, result, "unknown")
| stats count by decision | sort -count</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Recent connections (identity → access → network)</title>
      <table>
        <search><query>index=duo OR index=secure_access OR index=piap_security
| eval user=coalesce('user.name', user, identity, src_identity)
| eval decision=coalesce(verdict, action, result)
| table _time, index, user, decision, _raw | sort -_time | head 50</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="drilldown">none</option>
      </table>
    </panel>
  </row>
</dashboard>"""


_IDENTITY = """<dashboard version="1.1" theme="light">
  <label>Identity Intelligence — User Risk</label>
  <description>End-user risk / trust scores from Cisco Identity Intelligence (index=cii).</description>
  <row>
    <panel>
      <title>Riskiest users (lowest trust score)</title>
      <table>
        <search><query>index=cii sourcetype=cii:enduser
| eval score=coalesce('endUserTrustScore.score', endUserTrustScore_score)
| stats latest(score) AS trust_score latest(status) AS status by login
| sort trust_score | head 25</query><earliest>-24h@h</earliest><latest>now</latest></search>
      </table>
    </panel>
    <panel>
      <title>End users by status</title>
      <chart>
        <search><query>index=cii sourcetype=cii:enduser | stats dc(login) AS users by status</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
</dashboard>"""


_DUO = """<dashboard version="1.1" theme="light">
  <label>Duo Authentication &amp; MFA</label>
  <description>Duo authentication events from the Admin API (index=duo).</description>
  <row>
    <panel>
      <title>Authentications over time by result</title>
      <chart>
        <search><query>index=duo sourcetype=duo:authentication | timechart span=10m count by result</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    <panel>
      <title>Factors used</title>
      <chart>
        <search><query>index=duo sourcetype=duo:authentication | stats count by factor | sort -count</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Denied authentications by reason</title>
      <table>
        <search><query>index=duo sourcetype=duo:authentication result=denied
| stats count by reason, "user.name" | sort -count | head 20</query><earliest>-24h@h</earliest><latest>now</latest></search>
      </table>
    </panel>
  </row>
</dashboard>"""


_SECURE_ACCESS = """<dashboard version="1.1" theme="light">
  <label>Secure Access — Web / DNS / DLP</label>
  <description>Cisco Secure Access activity from the Reporting API (index=secure_access).</description>
  <row>
    <panel>
      <title>Verdicts over time</title>
      <chart>
        <search><query>index=secure_access | eval decision=coalesce(verdict, action) | timechart span=10m count by decision</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    <panel>
      <title>Top categories</title>
      <chart>
        <search><query>index=secure_access | stats count by categories | sort -count | head 10</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Top blocked destinations</title>
      <table>
        <search><query>index=secure_access (verdict=BLOCKED OR action=blocked)
| stats count by domain, destination | sort -count | head 20</query><earliest>-24h@h</earliest><latest>now</latest></search>
      </table>
    </panel>
  </row>
</dashboard>"""


_RUNTIME = """<dashboard version="1.1" theme="light">
  <label>Runtime &amp; Network Security</label>
  <description>Cilium network policy + Tetragon runtime process events (index=piap_security).</description>
  <row>
    <panel>
      <title>Security events over time by source</title>
      <chart>
        <search><query>index=piap_security | timechart span=10m count by sourcetype</query><earliest>-24h@h</earliest><latest>now</latest></search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    <panel>
      <title>Top process executions (Tetragon)</title>
      <table>
        <search><query>index=piap_security ("process_exec" OR tetragon OR binary)
| stats count by binary | sort -count | head 20</query><earliest>-24h@h</earliest><latest>now</latest></search>
      </table>
    </panel>
  </row>
</dashboard>"""


DASHBOARDS = {
    "overview": _OVERVIEW,
    "vm_metrics": _VM_METRICS,
    "zero_trust": _ZERO_TRUST,
    "identity_intelligence": _IDENTITY,
    "duo_authentication": _DUO,
    "secure_access": _SECURE_ACCESS,
    "runtime_security": _RUNTIME,
}

_NAV = """<nav search_view="search">
  <view name="overview" default="true"/>
  <view name="vm_metrics"/>
  <view name="zero_trust"/>
  <view name="identity_intelligence"/>
  <view name="duo_authentication"/>
  <view name="secure_access"/>
  <view name="runtime_security"/>
  <view name="search"/>
</nav>"""


def build_app():
    """Create the splunker user, the app, all dashboards and the nav. Idempotent."""
    result = {"user": None, "views": [], "errors": []}
    try:
        result["user"] = create_splunker_user()
    except Exception as e:
        result["errors"].append(f"user: {e}")

    _ensure_app()
    for name, xml in DASHBOARDS.items():
        try:
            _upsert_view(name, xml)
            result["views"].append(name)
        except Exception as e:
            result["errors"].append(f"{name}: {e}")

    try:
        _upsert_nav(_NAV)
    except Exception as e:
        result["errors"].append(f"nav: {e}")

    return result


def app_exists():
    """Return True if the poc_in_a_pod app is present in Splunk."""
    try:
        r = requests.get(
            f"{_mgmt_url()}/servicesNS/nobody/{APP}/data/ui/views?output_mode=json&count=1",
            auth=_auth(), verify=False, timeout=10,
        )
        return r.status_code == 200
    except Exception:
        return False
