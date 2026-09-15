"""
"Steve" — one button that creates every policy from the customer test-case
list that is configurable via the Secure Access Policies API.

Everything is scoped to the single test client (AD Users + Roaming Devices,
identity_type_ids [34, 9]) exactly like the other buttons, and each policy is
created independently so one failure never aborts the batch — the orchestrator
returns a per-policy result summary.

Coverage of the source list:
  DNS Security      Domain Allow / Block (malware, DoH, gambling, VPN)      ✅
  Secure Web GW     URL Block/Allow/Warn, Do-Not-Decrypt exclude           ✅
  RBI               Isolate grey sites / demo / webmail / pastebin         ✅
  AI Access         Block model / Allow model                             ✅
  AI Access / DLP   AI Guardrails, real-time DLP                          ✅ (reused)
  CASB              Block uploads / posts                                 🟡 (domain-level, partial)
  AI Supply Chain   Permit by risk score                                  🟡 (domain-level, partial)

Not created (not configurable via the documented Policies API):
  SWG File-type block, App Risk Profile, Time-of-Day; FWaaS geo/TLD/L7;
  CASB tenant control; Host DLP (print / cut-paste); Enterprise Browser
  copy-paste / watermarking; specific DLP classifications (OCR / ML / RegEx /
  Data Label) that depend on tenant-configured classifications.
"""
import requests

from scripts.csa_scripts.create_int_policy import (
    BASE_URL,
    MALICIOUS_CATEGORY_IDS,
    CATEGORY_GEN_AI,
    CATEGORY_GAMBLING,
    CATEGORY_SHOPPING,
    _create_url_destination_list,
)
from scripts.csa_scripts.create_ai_int_policy import (
    _post_rule,
    _identity_condition,
    _category_condition,
    _destination_list_condition,
)
from scripts.csa_scripts.create_dlp_rules import (
    create_realtime_dlp_rule,
    create_ai_guardrail_rule,
    create_scoped_ai_guardrail_rule,
)

# Content-category IDs (Reporting API /categories scheme, as used by the rules API)
CATEGORY_PERSONAL_VPN = 144      # Personal VPN
CATEGORY_WEBMAIL = 162           # Web-based Email

# Do-Not-Decrypt uses a DIFFERENT category-ID scheme than the rules API.
# From the API docs example: Finance = 426, Adult = 415, Web-based Email = 416.
DND_CATEGORY_FINANCE = 426


def _dl_rule(token, name, description, action, priority, destinations):
    """Create a destination list for the given domains, then a rule that
    references it. List access mirrors the rule action (block vs. allow)."""
    access = "block" if action == "block" else "allow"
    list_id = _create_url_destination_list(
        token, name=f"Steve - {name}", access=access, destinations=destinations
    )
    return _post_rule(
        token,
        f"Steve - {name} - Decryption required",
        description,
        action,
        priority,
        [_destination_list_condition(list_id), _identity_condition()],
    )


def _cat_rule(token, name, description, action, priority, category_ids):
    """Create a content-category rule scoped to the test client."""
    return _post_rule(
        token,
        f"Steve - {name} - Decryption required",
        description,
        action,
        priority,
        [_category_condition(category_ids), _identity_condition()],
    )


def _create_do_not_decrypt(token):
    """
    Best-effort Do-Not-Decrypt list for Health & Finance (SWG "Decrypt Exclude").
    Health is covered by a domain list (mayoclinic.org); Finance by the
    Do-Not-Decrypt category scheme (426). Field requirements can vary by tenant,
    so this is labelled a partial policy.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    domain_list_id = _create_url_destination_list(
        token,
        name="Steve - Do Not Decrypt - Domains",
        access="allow",
        destinations=["mayoclinic.org"],
    )
    payload = {
        "name": "Steve - Do Not Decrypt - Health & Finance (partial policy)",
        "decryptExceptionCategories": [{"categoryId": DND_CATEGORY_FINANCE}],
        "exceptiondomainlistId": domain_list_id,
        "bundleTypeId": 2,
    }
    r = requests.post(
        f"{BASE_URL}/policies/v2/doNotDecryptLists", headers=headers, json=payload, timeout=15
    )
    print("Do Not Decrypt Response:", r.status_code, r.text)
    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create Do Not Decrypt list: {r.status_code} - {r.text}")
    print("✅ Created Do Not Decrypt list (Health & Finance).")
    return r.json()


def create_steve_policies(token):
    """
    Create every API-configurable policy from the test-case list. Returns a list
    of {"policy": <label>, "status": "created"|"failed", "error": <str?>} so the
    caller can surface a summary. Priorities 1..N insert the rules at the top of
    the Access policy; allow/isolate rules are ordered above the broader blocks.
    """
    results = []

    def run(label, fn):
        try:
            fn()
            results.append({"policy": label, "status": "created"})
        except Exception as e:  # keep going — one failure must not abort Steve
            results.append({"policy": label, "status": "failed", "error": str(e)})

    # ---- Allows / isolates first (must sit above the broad blocks) ----
    run(
        "DNS Domain Allow — Umbrella",
        lambda: _dl_rule(
            token, "Allow - Umbrella", "Allow the Umbrella/Secure Access marketing domain (DNS Domain Allow / else).",
            "allow", 1, ["umbrella.cisco.com"],
        ),
    )
    run(
        "AI Access — Allow sanctioned model (ChatGPT)",
        lambda: _dl_rule(
            token, "Allow - Sanctioned AI (ChatGPT)", "Allow the corporate-sanctioned AI model (OpenAI/ChatGPT).",
            "allow", 2, ["chatgpt.com", "openai.com"],
        ),
    )
    run(
        "SWG URL Allow — Reddit r/Cisco",
        lambda: _dl_rule(
            token, "Allow - Reddit r/Cisco", "Allow the r/Cisco subreddit while the rest of Reddit is blocked.",
            "allow", 3, ["reddit.com/r/Cisco/"],
        ),
    )
    run(
        "AI Supply Chain — Permit by risk score (partial policy)",
        lambda: _dl_rule(
            token, "Allow (partial policy) - AI Supply Chain Permit", "Permit the Hugging Face model hub. NOTE: risk-score conditions are not API-configurable, so this is a domain-level allow (partial policy).",
            "allow", 4, ["huggingface.co"],
        ),
    )
    run(
        "RBI — Isolate grey site (bazaar.abuse.ch)",
        lambda: _dl_rule(
            token, "Isolate - Grey Site (RBI)", "Browser-isolate a grey/unknown-reputation site (Remote Browser Isolation).",
            "isolate", 5, ["bazaar.abuse.ch"],
        ),
    )
    run(
        "RBI — Isolate demo (rbi.demo.checkumbrella.com)",
        lambda: _dl_rule(
            token, "Isolate - RBI Demo", "Browser-isolate the Cisco RBI demo destination.",
            "isolate", 6, ["rbi.demo.checkumbrella.com"],
        ),
    )
    run(
        "RBI + DLP — Isolate pastebin",
        lambda: _dl_rule(
            token, "Isolate - Pastebin (RBI + DLP)", "Browser-isolate pastebin.com (RBI; DLP inspection applies within isolation).",
            "isolate", 7, ["pastebin.com"],
        ),
    )
    run(
        "RBI — Isolate webmail category",
        lambda: _cat_rule(
            token, "Isolate - Webmail", "Browser-isolate Web-based Email (e.g. Yahoo Mail) via the Webmail content category.",
            "isolate", 8, [CATEGORY_WEBMAIL],
        ),
    )

    # ---- Blocks / warns ----
    run(
        "DNS Domain Block — Malware / Talos (malicious sites)",
        lambda: _cat_rule(
            token, "Block - Malicious Sites", "Block malicious destinations (malware, phishing, C2, exploits, cryptomining) — DNS Domain Block Malware + Talos SWG block.",
            "block", 9, MALICIOUS_CATEGORY_IDS,
        ),
    )
    run(
        "DNS Domain Block — DNS over HTTPS (dns.google)",
        lambda: _dl_rule(
            token, "Block - DNS over HTTPS", "Block the public DoH resolver dns.google/dns-query (DNS Domain Block).",
            "block", 10, ["dns.google"],
        ),
    )
    run(
        "DNS Domain Block content — Gambling (DraftKings)",
        lambda: _cat_rule(
            token, "Block - Gambling", "Block the Gambling content category (e.g. draftkings.com).",
            "block", 11, [CATEGORY_GAMBLING],
        ),
    )
    run(
        "DNS Domain Block content — VPN (NordVPN)",
        lambda: _cat_rule(
            token, "Block - VPN", "Block the Personal VPN content category (e.g. nordvpn.com).",
            "block", 12, [CATEGORY_PERSONAL_VPN],
        ),
    )
    run(
        "SWG URL Warn — Shopping (Macy's)",
        lambda: _cat_rule(
            token, "Warn - Shopping", "Warn page for the Shopping content category (e.g. macys.com).",
            "warn", 13, [CATEGORY_SHOPPING],
        ),
    )
    run(
        "SWG URL Block — Reddit",
        lambda: _dl_rule(
            token, "Block - Reddit", "Block reddit.com (the r/Cisco allow above takes precedence).",
            "block", 14, ["reddit.com"],
        ),
    )
    run(
        "AI Access — Block model (DeepSeek / other Gen AI)",
        lambda: _cat_rule(
            token, "Block - Unsanctioned Gen AI", "Block the Generative AI content category (e.g. deepseek.com); sanctioned ChatGPT allow above wins.",
            "block", 15, [CATEGORY_GEN_AI],
        ),
    )
    run(
        "CASB — Block uploads (partial policy)",
        lambda: _dl_rule(
            token, "Block (partial policy) - CASB Uploads", "Block the file-upload service filesend.io. NOTE: activity-level 'upload only' control is not API-configurable, so this is a domain-level block (partial policy).",
            "block", 16, ["filesend.io"],
        ),
    )
    run(
        "CASB — Block posts (partial policy)",
        lambda: _dl_rule(
            token, "Block (partial policy) - CASB Posts", "Block facebook.com. NOTE: activity-level 'block posts only' control is not API-configurable, so this is a domain-level block (partial policy).",
            "block", 17, ["facebook.com"],
        ),
    )

    # ---- Do Not Decrypt (SWG Decrypt Exclude) ----
    run("SWG Decrypt Exclude — Health & Finance (partial policy)", lambda: _create_do_not_decrypt(token))

    # ---- DLP / AI Guardrails (reuse the proven DLP helpers) ----
    run("DLP — Real-Time (Financial Data / PCI + PII)", lambda: create_realtime_dlp_rule(token))
    run("AI Access — AI Guardrails (Security / Safety / Privacy; DLP Block Code)", lambda: create_ai_guardrail_rule(token))
    run("AI Access — AI Guardrails scoped to ChatGPT (DLP Block Finance)", lambda: create_scoped_ai_guardrail_rule(token))

    return results
