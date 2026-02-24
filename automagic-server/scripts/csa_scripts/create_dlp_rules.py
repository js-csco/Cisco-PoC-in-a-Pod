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
    Creates an AI Guardrails DLP rule covering all available classifications.
    UUIDs confirmed from GET /policies/v2/dlp/aiGuardrails/classifications.
    """
    # All confirmed AI Guardrail classification UUIDs
    ALL_CLASSIFICATION_IDS = [
        "6c312991-b6fa-11ef-a825-0242ac120002",  # American Bankers Association (ABA) Routing Number (US)
        "f435c215-b6fa-11ef-a825-0242ac120002",  # Bank Account Number (US)
        "c5628ff6-b6fb-11ef-a825-0242ac120002",  # Code Detection (Response)
        "77879429-b6fa-11ef-a825-0242ac120002",  # Credit Card Number
        "96fd3c92-b6f4-11ef-a825-0242ac120002",  # Driver's License Number (US)
        "e0b313e6-b6f3-11ef-a825-0242ac120002",  # Email Address
        "1625bcae-ed2b-11ef-9cc0-0242ac120002",  # Harassment
        "7bcb4e89-ed2a-11ef-9cc0-0242ac120002",  # Hate Speech
        "5332220b-b6fb-11ef-a825-0242ac120002",  # Individual Taxpayer Identification Number (ITIN) (US)
        "248b4bdd-b6fb-11ef-a825-0242ac120002",  # International Bank Account Number (IBAN)
        "193300a0-b6f4-11ef-a825-0242ac120002",  # IP Address
        "cc176031-b6f9-11ef-a825-0242ac120002",  # Medical License Number (US)
        "050a5aa3-b6fa-11ef-a825-0242ac120002",  # National Health Service (NHS) Number
        "ff2831a5-b6f4-11ef-a825-0242ac120002",  # Passport Number (US)
        "57caa2e9-b6f4-11ef-a825-0242ac120002",  # Phone Number
        "908b86e4-ed2b-11ef-9cc0-0242ac120002",  # Profanity
        "9714ca31-b6fb-11ef-a825-0242ac120002",  # Prompt Injection
        "cfd4a699-ed2a-11ef-9cc0-0242ac120002",  # Sexual Content & Exploitation
        "4ac5af67-ed2b-11ef-9cc0-0242ac120002",  # Social Division & Polarization
        "987bfdaf-b6f5-11ef-a825-0242ac120002",  # Social Security Number (SSN) (US)
        "cbc4d6f1-ed2b-11ef-9cc0-0242ac120002",  # Violence & Public Safety Threats
    ]

    url = f"{BASE_URL}/policies/v2/dlp/aiGuardrails/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = {
        "name": "joschwei - Block Sensitive Data to AI Apps (All Categories)",
        "description": "Blocks sharing of all sensitive data categories with AI applications.",
        "enabled": False,
        "action": "BLOCK",
        "severity": "HIGH",
        "type": "AI_DEFENSE",
        "identities": [],
        "excludedIdentities": [],
        "classifications": ALL_CLASSIFICATION_IDS,
        "allDestinationsScope": "ALL",
        "applications": [],
        "applicationCategories": [],
        "scannableContexts": ["CONTENT"],
        "notifyOwner": False,
        "notifyActor": False
    }

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("AI Guardrail Rule Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create AI Guardrail rule: {r.status_code} - {r.text}")

    print("✅ AI Guardrail DLP rule created (all 21 classifications).")
    return r.json()


def create_realtime_dlp_rule(token):
    """
    Creates a Real-Time DLP rule to block AWS and Azure cloud credentials.
    Uses hardcoded UUIDs confirmed from GET /policies/v2/dlp/classifications.
    """
    # Confirmed UUIDs from GET /policies/v2/dlp/classifications
    AWS_SECRET_KEY_ID = "087d53f6-3d90-43bd-a27c-5dfcc7c7959b"   # AWS - Secret Key
    AZURE_ACCESS_KEY_ID = "de1a5f26-b48a-45e7-af8f-919669472cb1"  # Azure - Access Key

    url = f"{BASE_URL}/policies/v2/dlp/realTime/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = {
        "name": "joschwei - Block Cloud Credentials (AWS / Azure)",
        "description": "Blocks upload/sharing of AWS and Azure access keys and secrets in real-time.",
        "enabled": False,
        "action": "BLOCK",
        "severity": "HIGH",
        "identities": [],
        "excludedIdentities": [],
        "classifications": [AWS_SECRET_KEY_ID, AZURE_ACCESS_KEY_ID],
        "allDestinationsScope": "ALL",
        "scannableContexts": ["CONTENT"],
        "notifyOwner": False,
        "notifyActor": False
    }

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Real-Time DLP Rule Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create Real-Time DLP rule: {r.status_code} - {r.text}")

    print("✅ Real-Time DLP rule created (AWS Secret Key + Azure Access Key).")
    return r.json()
