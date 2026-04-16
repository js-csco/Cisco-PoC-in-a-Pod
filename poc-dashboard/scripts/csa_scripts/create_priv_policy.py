import requests
import json

# ✅ Adjust this for your region:
BASE_URL = "https://api.sse.cisco.com"  # use your regional endpoint

# --------------------------
#  Helper Functions
# --------------------------


def create_private_access_policy(token):
    """
    Creates a Private Access Policy that allows access to given private resources.
    """
    url = f"{BASE_URL}/policies/v2/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "ruleName": "Roaming User - PoC in a Pod Apps",
        "ruleDescription": "This is one Private Access Policy that allows traffic from all ZTA-Enrolled Devices to the PoC in a Pod Apps - so that you can manage your PoC from Remote",
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
                "attributeId": 5,
                "attributeOperator": "INTERSECT",
                "attributeValue": [
                    57
                ],
                "attributeName": "umbrella.source.identity_type_ids"
            },
            {
                "attributeId": 35,
                "attributeOperator": "INTERSECT",
                "attributeValue": [
                    "groups"
                ],
                "attributeName": "umbrella.destination.private_resource_types"
            }
        ]
    }
    
    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create private access policy: {r.status_code} - {r.text}")

    print(f"✅ Created private access policy.")
    return r.json()

