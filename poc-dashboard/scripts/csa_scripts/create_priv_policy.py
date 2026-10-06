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


def _find_poc_resource_ids(token, group_name=POC_RESOURCE_GROUP_NAME):
    """Resolve the numeric IDs of the private *resources* in the PoC group for
    use in a rule's ``umbrella.destination.private_resource_ids`` condition.

    NOTE: the rule attribute for a resource *group* (``private_application_group_ids``)
    does NOT accept a private-resource-group ID — those are different objects, and
    the rules API rejects it ("… were not found"). The documented, accepted way to
    scope a private destination is by the individual resource IDs via
    ``private_resource_ids``. We therefore list the resources and keep the ones in
    the "PoC in a Pod" group (falling back to all resources if membership can't be
    determined). Returns a list of IDs (possibly empty)."""
    from scripts.csa_scripts.create_pod_resources import (
        get_private_resources, get_private_resource_groups
    )

    group_id = None
    try:
        for g in get_private_resource_groups(token):
            if g.get("name") == group_name:
                group_id = g.get("id") or g.get("resourceGroupId")
                break
    except Exception as e:
        print(f"  Could not list private resource groups: {e}")

    try:
        resources = get_private_resources(token)
    except Exception as e:
        print(f"  Could not list private resources: {e}")
        return []

    def _rid(res):
        return res.get("id") or res.get("resourceId")

    def _group_ids(res):
        out = []
        for gg in (res.get("resourceGroupIds") or res.get("resourceGroups") or []):
            out.append(gg.get("id") if isinstance(gg, dict) else gg)
        return out

    matched = [
        _rid(res) for res in resources
        if _rid(res) is not None and group_id is not None and group_id in _group_ids(res)
    ]
    all_ids = [_rid(res) for res in resources if _rid(res) is not None]
    chosen = matched if matched else all_ids

    seen, ids = set(), []
    for i in chosen:
        if i not in seen:
            seen.add(i)
            ids.append(i)
    if ids:
        print(f"  Matched {len(ids)} PoC resource(s): {ids}")
    else:
        print("  No private resources found.")
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


def create_private_access_policy(token):
    """
    Creates the Private Access rule, scoped as narrowly as the IDs allow:

      * Source      → the "PoC Users" directory group (umbrella.source.identity_ids)
      * Destination → the "PoC in a Pod" resources, by individual resource ID
                      (umbrella.destination.private_resource_ids)

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

    # --- Destination condition: the PoC in a Pod resources, else Any ---
    # Scope by individual resource IDs (private_resource_ids) — the resource
    # *group* attribute (private_application_group_ids) does not accept a
    # private-resource-group ID and is rejected by the rules API.
    resource_ids = _find_poc_resource_ids(token, POC_RESOURCE_GROUP_NAME)
    if resource_ids:
        dest_cond = {
            "attributeName": "umbrella.destination.private_resource_ids",
            "attributeOperator": "INTERSECT",
            "attributeValue": resource_ids,
        }
        dest_note = f"destination = {len(resource_ids)} PoC in a Pod resource(s)"
    else:
        dest_cond = {
            "attributeName": "umbrella.destination.all",
            "attributeOperator": "=",
            "attributeValue": True,
        }
        dest_note = "destination = Any (no PoC resources found)"

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

