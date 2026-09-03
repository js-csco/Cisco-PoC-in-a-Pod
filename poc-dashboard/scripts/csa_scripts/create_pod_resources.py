import requests
import json

# ✅ Adjust this for your region:
BASE_URL = "https://api.sse.cisco.com"  # use your regional endpoint

# --------------------------
#  Helper Functions
# --------------------------

def get_first_connector_id(token, connector_group_name=None):
    """
    Returns the connector group ID matching connector_group_name, or the only
    available connector group when no name is given.  Raises a descriptive
    exception if the name doesn't match or if multiple groups exist and no
    name was provided.
    """
    url = f"{BASE_URL}/deployments/v2/connectorGroups"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    r = requests.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    data = r.json().get("data") or r.json().get("items") or []
    if not data:
        raise Exception("No connector groups found in your SSE organization. "
                        "Make sure the Resource Connector is installed and has registered.")

    if connector_group_name:
        matches = [c for c in data if c.get("name") == connector_group_name]
        if not matches:
            available = ", ".join(c.get("name", "?") for c in data)
            raise Exception(
                f"Connector group '{connector_group_name}' not found. "
                f"Available groups: {available}"
            )
        connector = matches[0]
    elif len(data) == 1:
        connector = data[0]
    else:
        names = ", ".join(c.get("name", "?") for c in data)
        raise Exception(
            f"Multiple connector groups found ({names}). "
            "Please specify the Connector Group Name in the form."
        )

    connector_id = connector.get("id") or connector.get("connectorGroupId")
    connector_name = connector.get("name")
    print(f"✅ Connector found: {connector_name} (ID: {connector_id})")
    return connector_id, connector_name


def get_private_resource_groups(token):
    """
    Returns all existing private resource groups.
    """
    url = f"{BASE_URL}/policies/v2/privateResourceGroups"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    r = requests.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json().get("items", []) or r.json().get("data", [])


def create_private_resource_group(token, vm_ip, connector_id):
    """
    Creates the 'PoC in a Pod' resource group if not already existing.
    """
    name = "PoC in a Pod"
    existing = get_private_resource_groups(token)
    for group in existing:
        if group.get("name") == name:
            print(f"✅ Resource group '{name}' already exists.")
            return group

    url = f"{BASE_URL}/policies/v2/privateResourceGroups"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "name": name,
        "description": f"Private resources for PoC at {vm_ip}",
        "resourceIds": []
    }

    print("➡️ Creating private resource group:", payload)
    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create private resource group: {r.status_code} - {r.text}")

    print(f"✅ Created resource group '{name}'.")
    return r.json()


def create_private_resources(token, vm_ip, resource_group_id):
    """
    Creates the private resources linked to the PoC in a Pod group.
    """
    url = f"{BASE_URL}/policies/v2/privateResources"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }



    # fqdn_prefix is the subdomain used for the browser access URL.
    # Browser-based (clientless) access is enabled automatically for every
    # HTTP/HTTPS resource — Cisco Secure Access only permits browser-based ZTNA
    # when all resource addresses use the HTTP or HTTPS protocols. SSH and RDP
    # resources therefore get Secure Client access only.
    resources = [
        {"name": "PoC Dashboard",      "port": 30200, "protocol": "HTTP/HTTPS"},
        {"name": "PoC Playbook",       "port": 30250, "protocol": "HTTP/HTTPS"},
        {"name": "OpenSSH Server",     "port": 30022, "protocol": "SSH"},
        {"name": "Splunk Dashboard",   "port": 30500, "protocol": "HTTP/HTTPS"},
        {"name": "RDP Server",         "port": 30389, "protocol": "RDP-TCP"},
        {"name": "Hubble UI",          "port": 30800, "protocol": "HTTP/HTTPS"},
        {"name": "SSE Check",          "port": 30550, "protocol": "HTTP/HTTPS"},
        {"name": "Caldera C2",         "port": 30600, "protocol": "HTTP/HTTPS"},
        {"name": "Uptime Kuma",        "port": 30300, "protocol": "HTTP/HTTPS"},
        {"name": "SAML App",           "port": 30400, "protocol": "HTTP/HTTPS"},
        {"name": "AI Agent",           "port": 31789, "protocol": "HTTP/HTTPS"},
    ]


    existing = get_private_resources(token)
    existing_names = [res.get("name") for res in existing]
    created = []

    for res in resources:
        if res["name"] in existing_names:
            print(f"✅ Resource '{res['name']}' already exists.")
            continue

        # Browser-based access requires HTTP/HTTPS; enable it for every such resource.
        browser_enabled = "HTTP" in res["protocol"].upper()

        access_types = [{"type": "client", "reachableAddresses": [vm_ip]}]
        if browser_enabled:
            fqdn_prefix = res["name"].lower().replace(" ", "-")
            access_types.insert(0, {
                "type": "browser",
                "externalFQDNPrefix": fqdn_prefix,
                "protocol": "HTTP"
            })

        payload = {
            "name": res["name"],
            "description": f"{res['name']} for VM {vm_ip}",
            "resourceAddresses": [
                {
                    "destinationAddr": [vm_ip],
                    "protocolPorts": [
                        {"protocol": res["protocol"], "ports": str(res["port"])}
                    ]
                }
            ],
            "accessTypes": access_types,
            "resourceGroupIds": [resource_group_id]
        }

        r = requests.post(url, headers=headers, json=payload, timeout=15)
        print("Response:", r.status_code, r.text)

        if r.status_code not in (200, 201):
            raise Exception(f"Failed to create private resource: {r.status_code} - {r.text}")

        print(f"✅ Created private resource '{res['name']}'")
        created.append(r.json())

    return created


def get_private_resources(token):
    """
    Returns all existing private resources.
    """
    url = f"{BASE_URL}/policies/v2/privateResources"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    r = requests.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json().get("items", []) or r.json().get("data", [])


def get_browser_access_table(token):
    """
    Builds a table of private resources with their internal address and, when
    browser-based (clientless ZTNA) access is enabled, the external browser URL.

    Returns a list of dicts:
        {"name", "internal_address", "browser_address"}

    The browser address is buried in the Secure Access dashboard under each
    resource's accessTypes -> browserBasedAccessResponse.externalFQDN; this
    surfaces it so it can be shown next to the "Create Pod Resources" button.
    """
    rows = []
    for res in get_private_resources(token):
        name = res.get("name", "?")

        # Internal address: destinationAddr[:port] from the first resource address.
        internal = ""
        addresses = res.get("resourceAddresses") or []
        if addresses:
            first = addresses[0] or {}
            dests = first.get("destinationAddr") or []
            host = dests[0] if dests else ""
            ports = ""
            proto_ports = first.get("protocolPorts") or []
            if proto_ports:
                ports = str(proto_ports[0].get("ports", "")).strip()
            internal = f"{host}:{ports}" if host and ports else host

        # Browser address: externalFQDN on the browser access type (if enabled).
        browser = ""
        for at in (res.get("accessTypes") or []):
            if not isinstance(at, dict):
                continue
            if at.get("type") == "browser" or "externalFQDN" in at or "externalFQDNPrefix" in at:
                fqdn = at.get("externalFQDN") or at.get("externalFQDNPrefix") or ""
                if fqdn:
                    browser = fqdn if fqdn.startswith("http") else f"https://{fqdn}"
                break

        rows.append({
            "name": name,
            "internal_address": internal,
            "browser_address": browser,
        })

    # Sort alphabetically for a stable, readable table.
    rows.sort(key=lambda r: r["name"].lower())
    return rows

