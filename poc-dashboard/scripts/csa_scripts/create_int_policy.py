import requests
import json


BASE_URL = "https://api.sse.cisco.com"  

# --------------------------
#  Helper Functions
# --------------------------

# Policy 1
def create_int_warn_policy(token):
    """
    Creates a Internet Access Policy - Warn
    """
    url = f"{BASE_URL}/policies/v2/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "ruleDescription": "Warn Page for Roaming Devices to Gen AI Category Apps. Decryption in Security Profile is required for the Warn Page.",
        "ruleIsEnabled": True,
        "ruleIsDefault": False,
        "ruleSettings": [
            {
            "settingId": 5,
            "settingValue": "LOG_ALL",
            "settingName": "umbrella.logLevel"
            },
            {
            "settingId": 9,
            "settingValue": "PUBLIC_INTERNET",
            "settingName": "umbrella.default.traffic"
            }
        ],
        "rulePriority": 1,
        "ruleConditions": [
            {
            "attributeName": "umbrella.destination.category_ids",
            "attributeValue": [
                212
            ],
            "attributeId": 3,
            "attributeOperator": "INTERSECT"
            },
            {
            "attributeName": "umbrella.source.identity_type_ids",
            "attributeValue": [
                34,
                9
            ],
            "attributeId": 5,
            "attributeOperator": "INTERSECT"
            }
        ],
        "ruleAction": "warn",
        "ruleIName": None,
        "ruleName": "Roaming Devices - Warn - Page Gen AI Apps - Decryption required",
        "ruleExternalId": None,
        "ruleAccess": "public_internet"
    }
    
    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create internet access policy: {r.status_code} - {r.text}")

    print(f"✅ Created private access policy.")
    return r.json()

# Policy 2
def create_inet_isolate_policy(token):
    """
    Creates a Internet Access Policy - Isolate
    """
    url = f"{BASE_URL}/policies/v2/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "ruleName": "Roaming Devices - Isolate - News Websites - Decryption required",
        "ruleIName": None,
        "ruleAction": "isolate",
        "ruleDescription": "Browser Isolation for Roaming Devices to News Websites. Decryption in Security Profile is required for the Browser Isolation.",
        "ruleIsEnabled": True,
        "ruleExternalId": None,
        "ruleSettings": [
            {
                "settingValue": "LOG_ALL",
                "settingName": "umbrella.logLevel",
                "settingId": 5
            },
            {
                "settingValue": "PUBLIC_INTERNET",
                "settingName": "umbrella.default.traffic",
                "settingId": 9
            }
        ],
        "ruleIsDefault": False,
        "rulePriority": 2,
        "ruleConditions": [
            {
                "attributeValue": [
                    179
                ],
                "attributeOperator": "INTERSECT",
                "attributeId": 3,
                "attributeName": "umbrella.destination.category_ids"
            },
            {
                "attributeValue": [
                    34,
                    9
                ],
                "attributeOperator": "INTERSECT",
                "attributeId": 5,
                "attributeName": "umbrella.source.identity_type_ids"
            }
        ],
        "ruleAccess": "public_internet"
    }
    
    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create internet access policy: {r.status_code} - {r.text}")

    print(f"✅ Created private access policy.")
    return r.json()

# Policy 3
def create_int_block_content_policy(token):
    """
    Creates a Internet Access Policy - Block Content
    """
    url = f"{BASE_URL}/policies/v2/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "ruleConditions": [
            {
                "attributeId": 3,
                "attributeName": "umbrella.destination.category_ids",
                "attributeOperator": "INTERSECT",
                "attributeValue": [
                    1
                ]
            },
            {
                "attributeId": 5,
                "attributeName": "umbrella.source.identity_type_ids",
                "attributeOperator": "INTERSECT",
                "attributeValue": [
                    34,
                    9
                ]
            }
        ],
        "ruleDescription": "Block Access for Roaming Devices to Alcohol Websites. Decryption in Security Profile is required for the Block Page.",
        "ruleIsEnabled": True,
        "rulePriority": 3,
        "ruleIName": None,
        "ruleSettings": [
            {
                "settingValue": "LOG_ALL",
                "settingId": 5,
                "settingName": "umbrella.logLevel"
            },
            {
                "settingValue": "PUBLIC_INTERNET",
                "settingId": 9,
                "settingName": "umbrella.default.traffic"
            }
        ],
        "ruleName": "Roaming Devices - Block - Alcohol Websites - Decryption required",
        "ruleIsDefault": False,
        "ruleExternalId": None,
        "ruleAction": "block",
        "ruleAccess": "public_internet"
    }  
    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create internet access policy: {r.status_code} - {r.text}")

    print(f"✅ Created private access policy.")
    return r.json()

# Policy 4
def create_int_block_apps_policy(token):
    """
    Creates a Internet Access Policy - Block DeepSeek App
    """
    url = f"{BASE_URL}/policies/v2/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "ruleIsDefault": False,
        "ruleDescription": "Block Access for Roaming Devices to DeppSeek AI. Decryption in Security Profile is required for the Block Page.",
        "rulePriority": 4,
        "ruleAction": "block",
        "ruleConditions": [
            {
                "attributeId": 5,
                "attributeName": "umbrella.source.identity_type_ids",
                "attributeOperator": "INTERSECT",
                "attributeValue": [
                    34,
                    9
                ]
            },
            {
                "attributeValue": [
                    1023819,
                    1025844
                ],
                "attributeName": "umbrella.destination.application_ids",
                "attributeId": 7,
                "attributeOperator": "INTERSECT"
            }
        ],
        "ruleName": "Roaming Devices - Block - DeepSeek AI - Decryption required",
        "ruleSettings": [
            {
                "settingName": "umbrella.logLevel",
                "settingValue": "LOG_ALL",
                "settingId": 5
            },
            {
                "settingName": "umbrella.default.traffic",
                "settingValue": "PUBLIC_INTERNET",
                "settingId": 9
            }
        ],
        "ruleExternalId": None,
        "ruleIName": None,
        "ruleIsEnabled": True,
        "ruleAccess": "public_internet"
    }
    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create internet access policy: {r.status_code} - {r.text}")

    print(f"✅ Created private access policy.")
    return r.json()

# Policy 5
def create_allow_all_policy(token):
    """
    Creates a Internet Access Policy - Allow Rest/internet
    """
    url = f"{BASE_URL}/policies/v2/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "ruleName": "Roaming Devices - Allow - All Internet - Decryption required",
        "ruleDescription": "Allow Access for Roaming Devices to all Destinations. Decryption in Security Profile is required for Advanced Security.",
        "ruleConditions": [
            {
                "attributeId": 5,
                "attributeOperator": "INTERSECT",
                "attributeValue": [
                    34,
                    9
                ],
                "attributeName": "umbrella.source.identity_type_ids"
            },
            {
                "attributeId": 15,
                "attributeOperator": "=",
                "attributeValue": True,
                "attributeName": "umbrella.destination.all"
            }
        ],
        "ruleSettings": [
            {
                "settingId": 5,
                "settingName": "umbrella.logLevel",
                "settingValue": "LOG_ALL"
            },
            {
                "settingId": 9,
                "settingName": "umbrella.default.traffic",
                "settingValue": "PUBLIC_INTERNET"
            }
        ],
        "rulePriority": 7,
        "ruleIName": None,
        "ruleAction": "allow",
        "ruleIsEnabled": True,
        "ruleIsDefault": False,
        "ruleExternalId": None,
        "ruleAccess": "public_internet"
    }

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create internet access policy: {r.status_code} - {r.text}")

    print(f"✅ Created private access policy.")
    return r.json()


# --------------------------
#  URL Filtering (SWG) — Destination Lists
# --------------------------
#
# Specific URLs (e.g. reddit.com, reddit.com/r/Cisco/) cannot be matched by the
# content-category attribute used above. They require a Destination List:
#   1. POST /policies/v2/destinationlists           -> create the list, read its "id"
#   2. POST /policies/v2/destinationlists/{id}/destinations -> add the URLs
#   3. POST /policies/v2/rules                       -> rule condition references the list id
#
# The tenant is empty when the dashboard button is pressed, so the lists are
# created on the fly and their ids are fed straight into the rules below.

def _create_url_destination_list(token, name, access, destinations):
    """
    Creates a Destination List and populates it with URL/domain destinations.

    access:        "allow" or "block"
    destinations:  list of URL/domain strings, e.g. ["reddit.com"]

    Returns the new destination list id.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    # 1️⃣ Create the (empty) destination list
    create_url = f"{BASE_URL}/policies/v2/destinationlists"
    create_payload = {
        "access": access,       # "allow" | "block"
        "isGlobal": False,
        "name": name
    }
    r = requests.post(create_url, headers=headers, json=create_payload, timeout=15)
    print("Destination List Response:", r.status_code, r.text)
    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create destination list: {r.status_code} - {r.text}")

    body = r.json()
    # Response may be the object itself or wrapped in {"data": {...}}
    data = body.get("data", body)
    list_id = data.get("id") or data.get("destinationListId")
    if not list_id:
        raise Exception(f"Could not read destination list id from response: {body}")

    # 2️⃣ Add the URL destinations to the list
    dest_url = f"{BASE_URL}/policies/v2/destinationlists/{list_id}/destinations"
    dest_payload = [{"destination": d, "comment": name} for d in destinations]
    r = requests.post(dest_url, headers=headers, json=dest_payload, timeout=15)
    print("Add Destinations Response:", r.status_code, r.text)
    if r.status_code not in (200, 201):
        raise Exception(f"Failed to add destinations to list {list_id}: {r.status_code} - {r.text}")

    print(f"✅ Created destination list '{name}' (id={list_id}) with {len(destinations)} destination(s).")
    return list_id


# Policy 6 — URL Allow (more specific, must sit ABOVE the block rule)
def create_url_allow_policy(token, allow_list_id):
    """
    Creates a Secure Web Gateway URL Allow rule for the r/Cisco subreddit.
    Priority 5 so it is evaluated before the Reddit block (priority 6) and the
    Allow-all (priority 7) — otherwise the broader rules would swallow it.
    """
    url = f"{BASE_URL}/policies/v2/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "ruleName": "Roaming Devices - Allow - Reddit r/Cisco - Decryption required",
        "ruleDescription": "Allow Access for Roaming Devices to the r/Cisco subreddit while the rest of Reddit is blocked. Decryption in Security Profile is required.",
        "ruleIsEnabled": True,
        "ruleIsDefault": False,
        "ruleIName": None,
        "ruleExternalId": None,
        "rulePriority": 5,
        "ruleAction": "allow",
        "ruleAccess": "public_internet",
        "ruleSettings": [
            {
                "settingId": 5,
                "settingName": "umbrella.logLevel",
                "settingValue": "LOG_ALL"
            },
            {
                "settingId": 9,
                "settingName": "umbrella.default.traffic",
                "settingValue": "PUBLIC_INTERNET"
            }
        ],
        "ruleConditions": [
            {
                "attributeId": 5,
                "attributeName": "umbrella.source.identity_type_ids",
                "attributeOperator": "INTERSECT",
                "attributeValue": [34, 9]
            },
            {
                # NOTE: attributeId 8 / umbrella.destination.destination_list_ids is
                # the best-known value for referencing a destination list in a rule
                # condition. Verify against the tenant (GET /policies/v2/rules on a
                # rule that uses a destination list) — a wrong id returns a clear 400.
                "attributeId": 8,
                "attributeName": "umbrella.destination.destination_list_ids",
                "attributeOperator": "INTERSECT",
                "attributeValue": [allow_list_id]
            }
        ]
    }

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create internet access policy: {r.status_code} - {r.text}")

    print(f"✅ Created URL Allow policy (r/Cisco).")
    return r.json()


# Policy 7 — URL Block (broad, sits BELOW the allow rule)
def create_url_block_policy(token, block_list_id):
    """
    Creates a Secure Web Gateway URL Block rule for Reddit.
    Priority 6 so the r/Cisco allow (priority 5) wins for that sub-path while the
    rest of reddit.com is blocked.
    """
    url = f"{BASE_URL}/policies/v2/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "ruleName": "Roaming Devices - Block - Reddit - Decryption required",
        "ruleDescription": "Block Access for Roaming Devices to Reddit. Decryption in Security Profile is required for the Block Page.",
        "ruleIsEnabled": True,
        "ruleIsDefault": False,
        "ruleIName": None,
        "ruleExternalId": None,
        "rulePriority": 6,
        "ruleAction": "block",
        "ruleAccess": "public_internet",
        "ruleSettings": [
            {
                "settingId": 5,
                "settingName": "umbrella.logLevel",
                "settingValue": "LOG_ALL"
            },
            {
                "settingId": 9,
                "settingName": "umbrella.default.traffic",
                "settingValue": "PUBLIC_INTERNET"
            }
        ],
        "ruleConditions": [
            {
                "attributeId": 5,
                "attributeName": "umbrella.source.identity_type_ids",
                "attributeOperator": "INTERSECT",
                "attributeValue": [34, 9]
            },
            {
                # See note in create_url_allow_policy about attributeId 8.
                "attributeId": 8,
                "attributeName": "umbrella.destination.destination_list_ids",
                "attributeOperator": "INTERSECT",
                "attributeValue": [block_list_id]
            }
        ]
    }

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create internet access policy: {r.status_code} - {r.text}")

    print(f"✅ Created URL Block policy (Reddit).")
    return r.json()


# Orchestrator — create both destination lists, then both URL rules in order
def create_url_filtering_policies(token):
    """
    Creates the Reddit URL filtering demo:
      • Allow destination list  -> reddit.com/r/Cisco/  -> Allow rule (priority 5)
      • Block destination list  -> reddit.com           -> Block rule (priority 6)

    Net effect for AD users + roaming devices: only r/Cisco is reachable on Reddit.
    """
    allow_list_id = _create_url_destination_list(
        token,
        name="PoC - Allow - Reddit r/Cisco",
        access="allow",
        destinations=["reddit.com/r/Cisco/"]
    )
    block_list_id = _create_url_destination_list(
        token,
        name="PoC - Block - Reddit",
        access="block",
        destinations=["reddit.com"]
    )

    allow_rule = create_url_allow_policy(token, allow_list_id)
    block_rule = create_url_block_policy(token, block_list_id)

    return {"allow_rule": allow_rule, "block_rule": block_rule}


