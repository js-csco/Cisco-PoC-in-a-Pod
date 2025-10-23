from flask import flash
import requests
import json


BASE_URL = "https://api.sse.cisco.com"  

# --------------------------
#  Helper Functions
# --------------------------

def follow_recom(token):
    """
    Returns the first connector group ID.
    """
    url = f"{BASE_URL}/policies/v2/settings"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    payload = [
        {
            "settingName": "umbrella.m365Compatibility",
            "settingValue": True,
            "settingId": 4,
            "isGlobal": True
        }
    ]

    r = requests.post(url, headers=headers, json=payload, timeout=15)
    print("Response:", r.status_code, r.text)

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to update global settings (MSFT365 Bypass).")

    flash(f"✅ Cisco Recommendations applied.")

    # potential adjustment to none value
    return None
