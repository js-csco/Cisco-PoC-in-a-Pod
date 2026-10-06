import requests
import json

# ✅ Adjust this for your region:
BASE_URL = "https://api.sse.cisco.com"  # use your regional endpoint

RULE_NAME = "Roaming User - PoC in a Pod Apps"

# --------------------------
#  Helper Functions
# --------------------------


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
    Creates a Private Access rule with **Any source → Any destination**.

    Scoping the rule to ZTA-enrolled devices (``identity_type_ids``) did not
    match in this environment, so the ZTA client's traffic was blocked. An
    Any/Any allow rule is intentionally over-permissive — you would never ship
    this in production — but it's the only shape that reliably lets the PoC
    traffic through, so it's used here for the demo.

    Conditions use the documented "match everything" attributes from the
    create-rule API reference:
        {"attributeName":"umbrella.source.all","attributeValue":true,"attributeOperator":"="}
        {"attributeName":"umbrella.destination.all","attributeValue":true,"attributeOperator":"="}
    """
    # Remove any pre-existing rule with the same name (e.g. an earlier scoped
    # one) so re-running replaces it instead of failing on the unique name.
    _delete_existing_rule_by_name(token, RULE_NAME)

    url = f"{BASE_URL}/policies/v2/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "ruleName": RULE_NAME,
        "ruleDescription": "Private Access demo rule: Any source to Any destination. Intentionally over-permissive (never use in production) — used only so the PoC ZTA client can reach the pod apps remotely.",
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
                # Any source.
                "attributeOperator": "=",
                "attributeValue": True,
                "attributeName": "umbrella.source.all"
            },
            {
                # Any destination.
                "attributeOperator": "=",
                "attributeValue": True,
                "attributeName": "umbrella.destination.all"
            }
        ]
    }

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create private access policy: {r.status_code} - {r.text}")

    print("✅ Created private access policy (Any source → Any destination).")
    return r.json()

