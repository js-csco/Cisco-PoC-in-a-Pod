from flask import flash
import requests
import json

# ✅ Adjust this for your region:
BASE_URL = "https://api.sse.cisco.com"  # use your regional endpoint

# --------------------------
#  Helper Functions
# --------------------------

def get_first_connector_id(token):
    """
    Returns the first connector group ID.
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
        raise Exception("No connector groups found.")
    
    connector = data[0]
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
    Creates the 7 private resources linked to the PoC in a Pod group.
    """
    url = f"{BASE_URL}/policies/v2/privateResources"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }



    # add more resources here:
    resources = [
        {"name": "Dashy Overview", "port": 9000, "protocol": "Any"},
        {"name": "Automagic Server", "port": 9100, "protocol": "Any"},
        {"name": "Kanboard Test Guide", "port": 8090, "protocol": "Any"},
        {"name": "OpenSSH Server", "port": 2222, "protocol": "Any"},
        {"name": "Web Server", "port": 8080, "protocol": "Any"},
        {"name": "Automation Server", "port": 8200, "protocol": "Any"},
        {"name": "RDP Server", "port": 3390, "protocol": "Any"},
    ]


    existing = get_private_resources(token)
    existing_names = [res.get("name") for res in existing]
    created = []

    for res in resources:
        if res["name"] in existing_names:
            print(f"✅ Resource '{res['name']}' already exists.")
            continue

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
            "accessTypes": [
                {
                    "type": "client", 
                    "reachableAddresses": [vm_ip]
                }
            ],
            "resourceGroupIds": [ resource_group_id ]
        }

        r = requests.post(url, headers=headers, json=payload, timeout=15)
        print("Response:", r.status_code, r.text)

        if r.status_code not in (200, 201):
            raise Exception(f"Failed to create private resource: {r.status_code} - {r.text}")

        flash(f"✅ Created private resource '{res['name']}'")
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

