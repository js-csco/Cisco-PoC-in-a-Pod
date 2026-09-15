"""
AI-Proposed Internet Access Policies.

A curated set of high-value Secure Access internet-access rules that are all
configurable purely via the Policies API (POST /policies/v2/rules, plus
destination lists for the sanctioned-AI use case). Every rule is scoped to the
same source as the rest of the PoC — AD Users + Roaming Devices
(identity_type_ids [34, 9]) — because there is a single test client.

Rules (evaluated top-down; priorities 1..6 so they sit above a catch-all
Allow-all if the core Internet Access set is also present):

  1. Block   Anonymizers, proxies, personal VPNs & tunneling (evasion)
  2. Isolate Newly seen / dynamic-DNS / potentially-harmful domains (zero-day)
  3. Block   File sharing & piracy
  4. Block   Unacceptable use (adult, weapons, drugs, hate, etc.)
  5. Allow   Sanctioned AI (OpenAI/ChatGPT) via destination list
  6. Block   All other Generative AI (content category)
"""
import requests

from scripts.csa_scripts.create_int_policy import (
    BASE_URL,
    ROAMING_IDENTITY_IDS,
    CATEGORY_GEN_AI,
    _create_url_destination_list,
)

# --------------------------
#  Content-category bundles (IDs from the Secure Access Reporting API /categories)
# --------------------------
# Evasion: Unauthorized IP Tunnel Access (106), DNS Tunneling VPN (110),
#          Personal VPN (144), Filter Avoidance / anonymizers & proxies (171)
EVASION_CATEGORY_IDS = [106, 110, 144, 171]

# Risky-but-unknown: Dynamic DNS (61), Newly Seen Domains (108),
#                    Potentially Harmful (109)
RISKY_UNKNOWN_CATEGORY_IDS = [61, 108, 109]

# File sharing & piracy: File Transfer Services (118), Illegal Downloads (122),
#                        Infringing Intellectual Property (153),
#                        Peer File Transfer (186)
FILE_SHARING_CATEGORY_IDS = [118, 122, 153, 186]

# Acceptable-use policy: Weapons (30), Pornography (44), Adult (161),
#                        Child Abuse Content (166), Extreme (170),
#                        Hate Speech (174), Illegal Drugs (176)
AUP_CATEGORY_IDS = [30, 44, 161, 166, 170, 174, 176]

# Corporate-sanctioned AI tools that stay allowed while the rest of Gen AI
# is blocked.
SANCTIONED_AI_DESTINATIONS = ["chatgpt.com", "openai.com", "chat.openai.com"]


# --------------------------
#  Condition / settings builders
# --------------------------
def _identity_condition():
    """Source match: AD Users + Roaming Devices (the single test client)."""
    return {
        "attributeId": 5,
        "attributeName": "umbrella.source.identity_type_ids",
        "attributeOperator": "INTERSECT",
        "attributeValue": ROAMING_IDENTITY_IDS,
    }


def _category_condition(category_ids):
    return {
        "attributeId": 3,
        "attributeName": "umbrella.destination.category_ids",
        "attributeOperator": "INTERSECT",
        "attributeValue": category_ids,
    }


def _destination_list_condition(list_id):
    return {
        "attributeId": 8,
        "attributeName": "umbrella.destination.destination_list_ids",
        "attributeOperator": "INTERSECT",
        "attributeValue": [list_id],
    }


def _default_settings():
    return [
        {"settingId": 5, "settingName": "umbrella.logLevel", "settingValue": "LOG_ALL"},
        {"settingId": 9, "settingName": "umbrella.default.traffic", "settingValue": "PUBLIC_INTERNET"},
    ]


def _post_rule(token, name, description, action, priority, conditions):
    """Create a single Access-policy rule and return the API response JSON."""
    url = f"{BASE_URL}/policies/v2/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "ruleName": name,
        "ruleDescription": description,
        "ruleIsEnabled": True,
        "ruleIsDefault": False,
        "ruleIName": None,
        "ruleExternalId": None,
        "rulePriority": priority,
        "ruleAction": action,
        "ruleAccess": "public_internet",
        "ruleSettings": _default_settings(),
        "ruleConditions": conditions,
    }

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(
            f"Failed to create AI-proposed internet access policy '{name}': "
            f"{r.status_code} - {r.text}"
        )

    print(f"✅ Created AI-proposed policy: {name}")
    return r.json()


# --------------------------
#  Orchestrator
# --------------------------
def create_ai_proposed_policies(token):
    """
    Create the full AI-proposed internet-access rule set. Returns a dict of the
    individual API responses keyed by use case.
    """
    results = {}

    # 1 — Block anonymizers / proxies / personal VPNs / tunneling
    results["evasion"] = _post_rule(
        token,
        "AI-Proposed - Block - Anonymizers & Evasion - Decryption required",
        "Block Roaming Devices from anonymizers, proxies, personal VPNs and tunneling used to bypass Secure Access. Decryption in Security Profile is required for the Block Page.",
        "block",
        1,
        [_category_condition(EVASION_CATEGORY_IDS), _identity_condition()],
    )

    # 2 — Isolate unknown / risky domains (zero-day phishing containment)
    results["risky"] = _post_rule(
        token,
        "AI-Proposed - Isolate - Unknown & Risky Domains - Decryption required",
        "Browser-isolate Roaming Devices for newly seen, dynamic-DNS and potentially-harmful domains to contain zero-day phishing. Decryption in Security Profile is required for Browser Isolation.",
        "isolate",
        2,
        [_category_condition(RISKY_UNKNOWN_CATEGORY_IDS), _identity_condition()],
    )

    # 3 — Block file sharing & piracy
    results["file_sharing"] = _post_rule(
        token,
        "AI-Proposed - Block - File Sharing & Piracy - Decryption required",
        "Block Roaming Devices from file-sharing, peer-transfer and piracy sites to reduce data exfiltration and IP loss. Decryption in Security Profile is required for the Block Page.",
        "block",
        3,
        [_category_condition(FILE_SHARING_CATEGORY_IDS), _identity_condition()],
    )

    # 4 — Block unacceptable-use content (AUP)
    results["aup"] = _post_rule(
        token,
        "AI-Proposed - Block - Unacceptable Use (AUP) - Decryption required",
        "Block Roaming Devices from adult, weapons, drugs, hate and other AUP-violating content. Decryption in Security Profile is required for the Block Page.",
        "block",
        4,
        [_category_condition(AUP_CATEGORY_IDS), _identity_condition()],
    )

    # 5/6 — AI governance: allow sanctioned AI (higher priority) then block the rest
    allow_list_id = _create_url_destination_list(
        token,
        name="AI-Proposed - Allow - Sanctioned AI",
        access="allow",
        destinations=SANCTIONED_AI_DESTINATIONS,
    )
    results["ai_allow"] = _post_rule(
        token,
        "AI-Proposed - Allow - Sanctioned AI - Decryption required",
        "Allow Roaming Devices to the corporate-sanctioned AI tools (OpenAI/ChatGPT) while all other Gen AI is blocked. Decryption in Security Profile is required.",
        "allow",
        5,
        [_destination_list_condition(allow_list_id), _identity_condition()],
    )
    results["ai_block"] = _post_rule(
        token,
        "AI-Proposed - Block - Unsanctioned Gen AI - Decryption required",
        "Block Roaming Devices from all other Generative AI applications and sites. Decryption in Security Profile is required for the Block Page.",
        "block",
        6,
        [_category_condition([CATEGORY_GEN_AI]), _identity_condition()],
    )

    return results
