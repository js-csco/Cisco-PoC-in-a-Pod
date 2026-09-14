"""
Cisco Identity Intelligence (formerly Oort) public API client.

Identity Intelligence is a SEPARATE product from the Duo Admin API, with its own
public GraphQL API and OAuth 2.0 client-credentials auth. Create an API client in
the Identity Intelligence console (Integrations -> Add Integration -> Add API
Client -> Copy all) to obtain: client_id, client_secret, token URL, and the
GraphQL API URL (and, for clients created before Sept 2025, an audience).

Docs: https://docs.oort.io/public-api

This module is used two ways:
  * The dashboard reads it directly (with session creds) for the read-only
    "Risky Users" panel on the Duo tab.
  * The in-cluster CII->Splunk collector embeds the same token + query logic.
"""
import time
import requests

# Simple in-process token cache (per credentials fingerprint).
_token_cache = {}


def get_access_token(token_url, client_id, client_secret, audience=None):
    """Exchange client credentials for a bearer token (cached ~10h)."""
    key = (token_url, client_id, audience or "")
    cached = _token_cache.get(key)
    if cached and cached["expires_at"] > time.time() + 60:
        return cached["token"]

    body = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }
    if audience:
        body["audience"] = audience

    resp = requests.post(token_url, json=body, timeout=15)
    if resp.status_code not in (200, 201):
        # Some tenants expect form-encoded rather than JSON — retry once.
        resp = requests.post(token_url, data=body, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError(f"No access_token in token response: {str(data)[:200]}")

    # Tokens are valid ~10h; fall back to 1h if expires_in is absent.
    expires_in = int(data.get("expires_in", 3600))
    _token_cache[key] = {"token": token, "expires_at": time.time() + expires_in}
    return token


def _graphql(api_url, token, query, variables=None):
    """Execute a GraphQL query and return the `data` object, raising on errors."""
    resp = requests.post(
        api_url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        json={"query": query, "variables": variables or {}},
        timeout=20,
    )
    resp.raise_for_status()
    payload = resp.json()
    if payload.get("errors"):
        raise RuntimeError(f"GraphQL error: {str(payload['errors'])[:300]}")
    return payload.get("data", {})


def ping(api_url, token):
    """Return True if the API responds to the ping query."""
    data = _graphql(api_url, token, "query { ping }")
    return bool(data.get("ping"))


def check_credentials(token_url, client_id, client_secret, api_url, audience=None):
    """Validate creds end-to-end: token exchange + a ping. Raises on failure."""
    token = get_access_token(token_url, client_id, client_secret, audience)
    ping(api_url, token)
    return True


# Field selections. Trust-score subfields vary by tenant schema, so we try a
# richer query first and gracefully fall back to the always-present fields.
_LIST_QUERY_WITH_SCORE = """
query ($pageSize: Int, $pageToken: String) {
  listEndUsers(input: {}, pageSize: $pageSize, pageToken: $pageToken) {
    items { displayName login status emails endUserTrustScore { score } }
    pageToken
  }
}
"""

_LIST_QUERY_BASIC = """
query ($pageSize: Int, $pageToken: String) {
  listEndUsers(input: {}, pageSize: $pageSize, pageToken: $pageToken) {
    items { displayName login status emails }
    pageToken
  }
}
"""


def list_end_users(api_url, token, page_size=50, page_token=None):
    """
    Fetch a page of end users. Returns {"items": [...], "page_token": <str|None>}.
    Falls back to the basic field set if the trust-score selection isn't valid
    for this tenant's schema.
    """
    variables = {"pageSize": page_size, "pageToken": page_token}
    try:
        data = _graphql(api_url, token, _LIST_QUERY_WITH_SCORE, variables)
    except Exception:
        data = _graphql(api_url, token, _LIST_QUERY_BASIC, variables)

    conn = data.get("listEndUsers", {}) or {}
    return {"items": conn.get("items", []) or [], "page_token": conn.get("pageToken")}


def _trust_score(user):
    """Best-effort extraction of a numeric trust score from an end-user object."""
    ts = user.get("endUserTrustScore")
    if isinstance(ts, dict):
        for key in ("score", "value", "trustScore"):
            if isinstance(ts.get(key), (int, float)):
                return ts[key]
    return None


def list_risky_users(token_url, client_id, client_secret, api_url, audience=None, limit=50):
    """
    Return up to `limit` end users sorted by ascending trust score (riskiest
    first when scores are available). Each row: display_name, email, status,
    trust_score. Used by the read-only Risky Users panel.
    """
    token = get_access_token(token_url, client_id, client_secret, audience)
    page = list_end_users(api_url, token, page_size=min(limit, 500))
    rows = []
    for u in page["items"][:limit]:
        rows.append({
            "display_name": u.get("displayName") or "",
            "email": u.get("login") or "",
            "status": u.get("status") or "",
            "trust_score": _trust_score(u),
        })
    # Sort riskiest (lowest score) first; users without a score go last.
    rows.sort(key=lambda r: (r["trust_score"] is None, r["trust_score"] if r["trust_score"] is not None else 0))
    return rows
