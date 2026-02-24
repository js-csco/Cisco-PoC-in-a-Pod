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
    Creates an AI Guardrails DLP rule to block sharing PII / emails with AI apps.
    Dynamically looks up the 'Privacy' classification UUID via paginated API calls.
    """
    items = list_ai_guardrail_classifications(token)

    privacy_id = None
    for c in items:
        name = c.get("name", "").lower()
        cid = c.get("id") or c.get("uuid") or c.get("classificationId")
        if "privacy" in name or "pii" in name:
            privacy_id = cid
            print(f"  Found AI Guardrail classification: '{c.get('name')}' → {cid}")
            break

    if not privacy_id:
        available = ", ".join(c.get("name", "?") for c in items)
        raise Exception(f"Could not find Privacy/PII AI Guardrail classification. Available ({len(items)}): {available}")

    url = f"{BASE_URL}/policies/v2/dlp/aiGuardrails/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = {
        "name": "joschwei - Block PII and Emails to AI Apps",
        "description": "Blocks sharing of PII and email addresses with AI applications.",
        "enabled": False,
        "action": "BLOCK",
        "severity": "HIGH",
        "type": "AI_DEFENSE",
        "identities": [],
        "excludedIdentities": [],
        "classifications": [privacy_id],
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

    print("✅ AI Guardrail DLP rule created.")
    return r.json()


def create_realtime_dlp_rule(token):
    """
    Creates a Real-Time DLP rule to block email addresses and IBANs.
    Dynamically looks up classification UUIDs via paginated API calls.
    """
    items = list_dlp_classifications(token)

    email_id = None
    iban_id = None
    for c in items:
        name = c.get("name", "").lower()
        cid = c.get("id") or c.get("uuid") or c.get("classificationId")
        if email_id is None and "email" in name:
            email_id = cid
            print(f"  Found classification: '{c.get('name')}' → {cid}")
        if iban_id is None and "iban" in name:
            iban_id = cid
            print(f"  Found classification: '{c.get('name')}' → {cid}")
        if email_id and iban_id:
            break

    missing = [n for n, v in [("Email Address", email_id), ("IBAN", iban_id)] if not v]
    if missing:
        available = ", ".join(c.get("name", "?") for c in items)
        raise Exception(f"Could not find classification(s): {missing}. Available ({len(items)}): {available}")

    url = f"{BASE_URL}/policies/v2/dlp/realTime/rules"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = {
        "name": "joschwei - Block Email Addresses and IBANs",
        "description": "Blocks upload/sharing of email addresses and IBAN numbers in real-time.",
        "enabled": False,
        "action": "BLOCK",
        "severity": "HIGH",
        "identities": [],
        "excludedIdentities": [],
        "classifications": [email_id, iban_id],
        "allDestinationsScope": "ALL",
        "scannableContexts": ["CONTENT"],
        "notifyOwner": False,
        "notifyActor": False
    }

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Real-Time DLP Rule Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create Real-Time DLP rule: {r.status_code} - {r.text}")

    print("✅ Real-Time DLP rule created.")
    return r.json()
