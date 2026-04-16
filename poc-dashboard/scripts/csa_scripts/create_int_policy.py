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
        "rulePriority": 5,
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


