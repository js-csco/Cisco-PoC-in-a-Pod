import requests

BASE_URL = "https://api.sse.cisco.com"


def _get_all_pages(url, headers):
    """
    Paginates through a Cisco SSE Admin/Policy API collection using limit + page.
    Default returns up to 200 records; page is 1-indexed.
    Keeps fetching until a short page is returned (last page).
    Returns a flat list of all items.
    """
    all_items = []
    limit = 200
    page = 1

    while True:
        r = requests.get(url, headers=headers, params={"limit": limit, "page": page}, timeout=15)
        if r.status_code not in (200, 201):
            raise Exception(f"GET {url} failed: {r.status_code} - {r.text}")

        data = r.json()
        # Response may be a bare list or {"items": [...], "meta": {...}}
        if isinstance(data, list):
            batch = data
        else:
            batch = data.get("items", data.get("data", []))

        all_items.extend(batch)
        print(f"  fetched page={page}, got {len(batch)} items (total so far: {len(all_items)})")

        if len(batch) < limit:
            break  # last page
        page += 1

    return all_items


def list_dlp_classifications(token):
    """
    Fetches ALL real-time DLP classifications, paginating past the 100-record limit.
    Returns a flat list of classification objects.
    """
    url = f"{BASE_URL}/policies/v2/dlp/classifications"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    print("Fetching real-time DLP classifications...")
    return _get_all_pages(url, headers)


def list_ai_guardrail_classifications(token):
    """
    Fetches ALL AI Guardrail classifications, paginating past the 100-record limit.
    Returns a flat list of classification objects.
    """
    url = f"{BASE_URL}/policies/v2/dlp/aiGuardrails/classifications"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    print("Fetching AI Guardrail classifications...")
    return _get_all_pages(url, headers)


def create_ai_guardrail_rule(token):
    """
    Creates an AI Guardrails DLP rule covering Security, Safety and Privacy guardrails.
    Structure modelled on a confirmed working rule from the tenant.
    Applies to all AD users and roaming devices.
    """
    # High-level guardrail classification UUIDs (confirmed from existing tenant rule)
    GUARDRAIL_CLASSIFICATION_IDS = [
        "7e27f96e-b6fe-11ef-a825-0242ac120002",  # Security Guardrail
        "ae792674-b6fe-11ef-a825-0242ac120002",  # Safety Guardrail
        "d309239a-b6fd-11ef-a825-0242ac120002",  # Privacy Guardrail
    ]

    url = f"{BASE_URL}/policies/v2/dlp/aiGuardrails/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = {
        "name": "DLP Rule - AI Guardrails",
        "description": "Blocks sharing of sensitive data (security, safety, privacy) with AI applications.",
        "enabled": True,
        "action": "BLOCK",
        "severity": "ALERT",
        "type": "AI_DEFENSE",
        "secureIcapEnabled": False,
        "identities": [
            {
                "originId": 0,
                "originTypeId": 7,
                "details": "{\"id\":7,\"name\":\"directory_user\",\"label\":\"AD Users\",\"description\":\"Active Directory user\",\"children\":2}"
            },
            {
                "originId": 0,
                "originTypeId": 9,
                "details": "{\"id\":9,\"name\":\"roaming\",\"label\":\"Roaming Computers\",\"description\":\"Roaming devices\",\"children\":1}"
            }
        ],
        "applications": [
            {"id": 46060, "trafficDirection": "REQUEST"}
        ],
        "classifications": GUARDRAIL_CLASSIFICATION_IDS,
        "scannableContexts": ["FILENAME", "CONTENT"],
        "mipTags": [],
        "notifyOwner": False,
        "notifyActor": False,
        "labels": []
    }

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("AI Guardrail Rule Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create AI Guardrail rule: {r.status_code} - {r.text}")

    print("✅ AI Guardrail DLP rule created (Security + Safety + Privacy Guardrail).")
    return r.json()


def create_realtime_dlp_rule(token):
    """
    Creates a Real-Time DLP rule using built-in classification UUIDs confirmed
    from an existing working rule in the tenant.
    """
    # Confirmed classification UUIDs from existing working real-time DLP rule
    PCI_CLASSIFICATION_ID = "39b3b945-2e21-4831-bbbc-86fc5200ddf7"   # Built-in PCI Classification
    PII_CLASSIFICATION_ID = "726c599d-6f08-44a9-a72d-f178d1281765"   # Built-in PII Classification

    url = f"{BASE_URL}/policies/v2/dlp/realTime/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = {
        "name": "DLP Rule - Real-Time",
        "description": "Blocks upload/sharing of PCI and PII classified data in real-time.",
        "enabled": True,
        "action": "BLOCK",
        "severity": "WARNING",
        "type": "INLINE",
        "secureIcapEnabled": True,
        "identities": [
            {
                "originId": 0,
                "originTypeId": 9,
                "details": "{\"id\":9,\"name\":\"roaming\",\"label\":\"Roaming Computers\",\"description\":\"Roaming devices\",\"children\":1}"
            },
            {
                "originId": 0,
                "originTypeId": 7,
                "details": "{\"id\":7,\"name\":\"directory_user\",\"label\":\"AD Users\",\"description\":\"Active Directory user\",\"children\":6}"
            }
        ],
        "applications": [],
        "classifications": [PCI_CLASSIFICATION_ID, PII_CLASSIFICATION_ID],
        "labelFileParameters": {"mipData": {}, "labelsData": []},
        "scannableContexts": ["FILENAME", "CONTENT"],
        "mipTags": [],
        "notifyOwner": False,
        "notifyActor": False,
        "labels": []
    }

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Real-Time DLP Rule Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create Real-Time DLP rule: {r.status_code} - {r.text}")

    print("✅ Real-Time DLP rule created (Built-in PCI + PII Classification).")
    return r.json()
