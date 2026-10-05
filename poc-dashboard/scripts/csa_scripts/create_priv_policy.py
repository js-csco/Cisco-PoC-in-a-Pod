import requests
import json

# ✅ Adjust this for your region:
BASE_URL = "https://api.sse.cisco.com"  # use your regional endpoint

RULE_NAME = "Roaming User - PoC in a Pod Apps"
POC_RESOURCE_GROUP_NAME = "PoC in a Pod"

# --------------------------
#  Helper Functions
# --------------------------


def _get_poc_private_resource_ids(token, group_name=POC_RESOURCE_GROUP_NAME):
    """Return the numeric IDs of the PoC private resources.

    The access rule must target the resources by their real IDs via
    ``umbrella.destination.private_resource_ids`` — the old rule used a
    non-existent attribute (``umbrella.destination.private_resource_types`` =
    ``["groups"]``) that matched nothing on the destination side, so ZTA traffic
    fell through to the default private deny ("firewall is blocking").

    Prefers resources that belong to the "PoC in a Pod" group; if group
    membership can't be determined, falls back to every private resource.
    """
    # Imported lazily to avoid a circular import at module load.
    from scripts.csa_scripts.create_pod_resources import (
        get_private_resources, get_private_resource_groups
    )

    resources = get_private_resources(token)

    group_id = None
    try:
        for g in get_private_resource_groups(token):
            if g.get("name") == group_name:
                group_id = g.get("id") or g.get("resourceGroupId")
                break
    except Exception as e:
        print(f"  Could not list private resource groups: {e}")

    def _rid(res):
        return res.get("id") or res.get("resourceId")

    def _group_ids(res):
        groups = res.get("resourceGroupIds") or res.get("resourceGroups") or []
        out = []
        for gg in groups:
            out.append(gg.get("id") if isinstance(gg, dict) else gg)
        return out

    matched = [
        _rid(res) for res in resources
        if _rid(res) is not None and group_id is not None and group_id in _group_ids(res)
    ]
    all_ids = [_rid(res) for res in resources if _rid(res) is not None]

    chosen = matched if matched else all_ids

    # De-duplicate while preserving order.
    seen, ids = set(), []
    for i in chosen:
        if i not in seen:
            seen.add(i)
            ids.append(i)
    return ids


def _delete_existing_rule_by_name(token, name):
    """Best-effort delete of any access rule with the given name.

    Rule names are unique per org, so a second POST would 400. Removing the old
    (broken) rule first makes re-running the button fix the policy in place.
    """
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        r = requests.get(f"{BASE_URL}/policies/v2/rules", headers=headers, timeout=15)
        if r.status_code not in (200, 201):
            print(f"  Could not list existing rules: {r.status_code} - {r.text}")
            return
        data = r.json()
        rules = data if isinstance(data, list) else data.get("items", data.get("data", []))
        for rule in rules:
            if rule.get("ruleName") == name:
                rid = rule.get("ruleId") or rule.get("id")
                if rid:
                    d = requests.delete(f"{BASE_URL}/policies/v2/rules/{rid}",
                                        headers=headers, timeout=15)
                    print(f"  Removed existing rule '{name}' (id={rid}): {d.status_code}")
    except Exception as e:
        print(f"  Could not remove existing rule '{name}': {e}")


def create_private_access_policy(token, resource_ids=None):
    """
    Creates a Private Access rule that allows all ZTA-enrolled devices to reach
    the PoC in a Pod private resources.

    The destination is scoped to the actual private resource IDs
    (``umbrella.destination.private_resource_ids``) — the documented, working
    attribute — rather than the invalid ``private_resource_types`` the old rule
    used (which matched nothing, so Secure Access blocked the traffic).
    """
    if resource_ids is None:
        resource_ids = _get_poc_private_resource_ids(token)

    if not resource_ids:
        raise Exception(
            "No private resources found in Secure Access. Click "
            "'Create Pod Resources' first, then create the Private Access Policy."
        )

    # Remove any pre-existing rule with the same name (e.g. the old broken one)
    # so re-running fixes the policy instead of failing on the unique name.
    _delete_existing_rule_by_name(token, RULE_NAME)

    url = f"{BASE_URL}/policies/v2/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "ruleName": RULE_NAME,
        "ruleDescription": "Allows traffic from all ZTA-enrolled devices to the PoC in a Pod private resources, so you can reach the PoC apps remotely.",
        "rulePriority": 1,
        "ruleAction": "allow",
        "ruleAccess": "private_network",
        "ruleIsEnabled": True,
        "ruleSettings": [
            {
                "settingId": 5,
                "settingName": "umbrella.logLevel",
                "settingValue": "LOG_ALL"
            },
            {
                "settingId": 9,
                "settingName": "umbrella.default.traffic",
                "settingValue": "PRIVATE_NETWORK"
            }
        ],
        "ruleConditions": [
            {
                # All ZTA-enrolled devices (identity type).
                "attributeOperator": "INTERSECT",
                "attributeValue": [57],
                "attributeName": "umbrella.source.identity_type_ids"
            },
            {
                # Scope to the PoC private resources by their real IDs. This is
                # the documented attribute for private-access destinations
                # (see create-rule docs example: private_resource_ids=[1640]).
                "attributeOperator": "INTERSECT",
                "attributeValue": resource_ids,
                "attributeName": "umbrella.destination.private_resource_ids"
            }
        ]
    }

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create private access policy: {r.status_code} - {r.text}")

    print(f"✅ Created private access policy targeting {len(resource_ids)} resource(s): {resource_ids}")
    return r.json()

