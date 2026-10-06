import requests
import json

# ✅ Adjust this for your region:
BASE_URL = "https://api.sse.cisco.com"  # use your regional endpoint

RULE_NAME = "Roaming User - PoC in a Pod Apps"
POC_USERS_GROUP_NAME = "PoC Users"
POC_RESOURCE_GROUP_NAME = "PoC in a Pod"

# --------------------------
#  Helper Functions
# --------------------------


def _find_directory_group_id(token, group_name=POC_USERS_GROUP_NAME):
    """Resolve a directory group's numeric identity ID for use in a rule's
    ``umbrella.source.identity_ids`` condition.

    Access rules reference identities by numeric ID, not by name. Directory
    (SCIM/AD) group IDs come from the Reporting API:
        GET /reports/v2/identities?identitytypes=directory_group
    which needs the ``reports.utilities:read`` scope on the API key. Returns the
    id (as stored by the API) or None if it can't be resolved (e.g. the scope is
    missing or the group hasn't synced yet), so the caller can fall back to Any.
    """
    url = f"{BASE_URL}/reports/v2/identities"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers,
                         params={"identitytypes": "directory_group", "limit": 100},
                         timeout=15)
        if r.status_code not in (200, 201):
            print(f"  Could not list directory groups ({r.status_code}): {r.text}")
            return None
        data = r.json()
        items = data.get("data") or data.get("identities") or (data if isinstance(data, list) else [])
        for it in items:
            label = it.get("label") or it.get("name") or ""
            if label == group_name or group_name.lower() in label.lower():
                gid = it.get("id") or it.get("identityId") or it.get("originId")
                if gid is not None:
                    print(f"  Matched directory group '{label}' -> {gid}")
                    return gid
        print(f"  Directory group '{group_name}' not found in reporting identities.")
    except Exception as e:
        print(f"  Directory group lookup failed: {e}")
    return None


def _find_resource_group_id(token, group_name=POC_RESOURCE_GROUP_NAME):
    """Resolve the private resource group's ID for use in a rule's
    ``umbrella.destination.private_application_group_ids`` condition. Returns the
    id or None (caller falls back to Any destination)."""
    from scripts.csa_scripts.create_pod_resources import get_private_resource_groups
    try:
        for g in get_private_resource_groups(token):
            if g.get("name") == group_name:
                gid = g.get("id") or g.get("resourceGroupId")
                if gid is not None:
                    print(f"  Matched resource group '{group_name}' -> {gid}")
                    return gid
        print(f"  Resource group '{group_name}' not found.")
    except Exception as e:
        print(f"  Resource group lookup failed: {e}")
    return None


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


def create_private_access_policy(token):
    """
    Creates the Private Access rule, scoped as narrowly as the IDs allow:

      * Source      → the "PoC Users" directory group (umbrella.source.identity_ids)
      * Destination → the "PoC in a Pod" resource group
                      (umbrella.destination.private_application_group_ids)

    Access rules reference identities and resources by numeric ID, not by name,
    so the IDs are resolved first. If either ID can't be resolved (e.g. the
    Reporting API scope is missing, or the group hasn't synced yet), that side
    gracefully falls back to "Any" (umbrella.source.all / umbrella.destination.all)
    so the rule still works instead of silently blocking. The applied scope is
    returned so the UI can show exactly what was used.

    Returns a tuple: (rule_json, scope_summary_str).
    """
    # Remove any pre-existing rule with the same name (e.g. an earlier rule)
    # so re-running replaces it instead of failing on the unique name.
    _delete_existing_rule_by_name(token, RULE_NAME)

    # --- Source condition: PoC Users group, else Any ---
    group_id = _find_directory_group_id(token, POC_USERS_GROUP_NAME)
    if group_id is not None:
        source_cond = {
            "attributeName": "umbrella.source.identity_ids",
            "attributeOperator": "INTERSECT",
            "attributeValue": [group_id],
        }
        source_note = f"source = PoC Users group ({group_id})"
    else:
        source_cond = {
            "attributeName": "umbrella.source.all",
            "attributeOperator": "=",
            "attributeValue": True,
        }
        source_note = "source = Any (PoC Users group ID not resolvable)"

    # --- Destination condition: PoC in a Pod resource group, else Any ---
    resource_group_id = _find_resource_group_id(token, POC_RESOURCE_GROUP_NAME)
    if resource_group_id is not None:
        dest_cond = {
            "attributeName": "umbrella.destination.private_application_group_ids",
            "attributeOperator": "INTERSECT",
            "attributeValue": [resource_group_id],
        }
        dest_note = f"destination = PoC in a Pod resource group ({resource_group_id})"
    else:
        dest_cond = {
            "attributeName": "umbrella.destination.all",
            "attributeOperator": "=",
            "attributeValue": True,
        }
        dest_note = "destination = Any (resource group not found)"

    scope_summary = f"{source_note}; {dest_note}"

    url = f"{BASE_URL}/policies/v2/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "ruleName": RULE_NAME,
        "ruleDescription": "Private Access rule for the PoC: allows the PoC Users group to reach the PoC in a Pod private resource group. Falls back to Any on whichever ID can't be resolved.",
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
        "ruleConditions": [source_cond, dest_cond]
    }

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create private access policy: {r.status_code} - {r.text}")

    print(f"✅ Created private access policy ({scope_summary}).")
    return r.json(), scope_summary

