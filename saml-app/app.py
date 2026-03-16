"""
SAML Demo App — a minimal SAML 2.0 Service Provider for Duo SSO.

Shows how Duo SSO authenticates users via SAML and demonstrates
Duo Passport (remembered device across browsers).
"""
import os
import json
import xml.etree.ElementTree as ET
from flask import (
    Flask, request, redirect, session, render_template,
    url_for, make_response, jsonify
)
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "saml-demo-secret-key")

# Persistent IDP config — stored in-memory (survives across requests, not restarts)
_idp_config = {
    "entity_id": "",
    "sso_url": "",
    "slo_url": "",
    "cert": "",
}


def _load_idp_config():
    """Load IDP config from env vars as defaults, override with runtime config."""
    return {
        "entity_id": _idp_config["entity_id"] or os.environ.get("IDP_ENTITY_ID", ""),
        "sso_url": _idp_config["sso_url"] or os.environ.get("IDP_SSO_URL", ""),
        "slo_url": _idp_config["slo_url"] or os.environ.get("IDP_SLO_URL", ""),
        "cert": _idp_config["cert"] or os.environ.get("IDP_CERT", ""),
    }


def _saml_settings(sp_host_override=None):
    """Build python3-saml settings dict."""
    sp_host = sp_host_override or os.environ.get("SP_HOST") or "http://localhost:9400"
    idp = _load_idp_config()

    return {
        "strict": False,
        "debug": True,
        "sp": {
            "entityId": f"{sp_host}/metadata",
            "assertionConsumerService": {
                "url": f"{sp_host}/acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": f"{sp_host}/sls",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": idp["entity_id"],
            "singleSignOnService": {
                "url": idp["sso_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": idp["slo_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": idp["cert"],
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": False,
            "wantNameId": True,
            "wantAttributeStatement": False,
        },
    }


def _prepare_request():
    """Translate Flask request into the dict python3-saml expects."""
    return {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "server_port": request.environ.get("SERVER_PORT", "9400"),
        "script_name": request.path,
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
        "query_string": request.query_string.decode("utf-8"),
    }


def _is_configured():
    """Check whether the IdP settings have been provided."""
    idp = _load_idp_config()
    return bool(idp["sso_url"])


def _parse_idp_metadata(xml_string):
    """Extract IDP entity_id, sso_url, slo_url, cert from SAML metadata XML."""
    ns = {
        "md": "urn:oasis:names:tc:SAML:2.0:metadata",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    }
    root = ET.fromstring(xml_string)

    entity_id = root.attrib.get("entityID", "")

    sso_url = ""
    sso_el = root.find(".//md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']", ns)
    if sso_el is not None:
        sso_url = sso_el.attrib.get("Location", "")

    slo_url = ""
    slo_el = root.find(".//md:IDPSSODescriptor/md:SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']", ns)
    if slo_el is not None:
        slo_url = slo_el.attrib.get("Location", "")

    cert = ""
    cert_el = root.find(".//md:IDPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns)
    if cert_el is not None and cert_el.text:
        cert = cert_el.text.strip().replace("\n", "").replace("\r", "")

    return {
        "entity_id": entity_id,
        "sso_url": sso_url,
        "slo_url": slo_url,
        "cert": cert,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Landing page — two-section layout: Admin setup + User auth."""
    user = session.get("saml_user")
    attrs = session.get("saml_attrs", {})
    configured = _is_configured()
    return render_template("index.html",
                           user=user, attrs=attrs, configured=configured)


@app.route("/upload-idp-metadata", methods=["POST"])
def upload_idp_metadata():
    """Accept Duo IdP metadata XML and configure SAML."""
    f = request.files.get("idp_metadata")
    if not f:
        return jsonify({"ok": False, "error": "No file uploaded"}), 400
    try:
        xml_bytes = f.read()
        parsed = _parse_idp_metadata(xml_bytes)
        if not parsed["sso_url"]:
            return jsonify({"ok": False, "error": "Could not find SSO URL in metadata XML"}), 400
        _idp_config.update(parsed)
        return jsonify({"ok": True, "entity_id": parsed["entity_id"], "sso_url": parsed["sso_url"]})
    except ET.ParseError as e:
        return jsonify({"ok": False, "error": f"Invalid XML: {e}"}), 400


@app.route("/reset-idp", methods=["POST"])
def reset_idp():
    """Clear the IdP configuration so the admin can re-configure."""
    _idp_config.update({"entity_id": "", "sso_url": "", "slo_url": "", "cert": ""})
    session.clear()
    return jsonify({"ok": True})


@app.route("/login")
def login():
    """Initiate SAML login — redirect to Duo SSO."""
    if not _is_configured():
        return "SAML not configured. Complete the Admin Setup first.", 400
    sp_host = f"http://{request.host}"
    auth = OneLogin_Saml2_Auth(_prepare_request(), _saml_settings(sp_host_override=sp_host))
    return redirect(auth.login())


@app.route("/acs", methods=["POST"])
def acs():
    """Assertion Consumer Service — receives SAML response from Duo."""
    sp_host = f"http://{request.host}"
    auth = OneLogin_Saml2_Auth(_prepare_request(), _saml_settings(sp_host_override=sp_host))
    auth.process_response()
    errors = auth.get_errors()

    if errors:
        return f"SAML Error: {', '.join(errors)}<br>Reason: {auth.get_last_error_reason()}", 400

    session["saml_user"] = auth.get_nameid()
    session["saml_attrs"] = dict(auth.get_attributes())
    session["saml_session"] = auth.get_session_index()
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    """Clear local session."""
    session.clear()
    return redirect(url_for("index"))


@app.route("/metadata")
def metadata():
    """SP metadata — download XML for Duo Admin."""
    try:
        sp_host = f"http://{request.host}"
        settings = OneLogin_Saml2_Settings(_saml_settings(sp_host_override=sp_host), sp_validation_only=True)
        sp_metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(sp_metadata)
        if errors:
            return f"Metadata validation errors: {', '.join(errors)}", 500
        resp = make_response(sp_metadata, 200)
        resp.headers["Content-Type"] = "text/xml"
        resp.headers["Content-Disposition"] = "attachment; filename=saml-sp-metadata.xml"
        return resp
    except Exception as e:
        return f"Failed to generate SP metadata: {e}", 500


@app.route("/health")
def health():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9400, debug=False)
