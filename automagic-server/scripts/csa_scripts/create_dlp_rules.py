from flask import flash
import requests

BASE_URL = "https://api.sse.cisco.com"


def create_ai_guardrail_rule(token):
    """
    Creates an AI Guardrails DLP rule to block sharing PII / emails with AI apps.
    Fill in the classifications list with the UUIDs from:
      GET /policies/v2/dlp/aiGuardrails/classifications
    """
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
        # TODO: Add AI Guardrail classification UUIDs (e.g. Privacy)
        # from GET /policies/v2/dlp/aiGuardrails/classifications
        "classifications": [],
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
    Creates a Real-Time DLP rule to block sharing of email addresses and IBANs.
    Fill in the classifications list with the UUIDs from:
      GET /policies/v2/dlp/classifications
    """
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
        # TODO: Add Real-Time classification UUIDs for Email Address and IBAN
        # from GET /policies/v2/dlp/classifications
        "classifications": [],
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
