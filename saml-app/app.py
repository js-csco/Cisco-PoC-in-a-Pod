"""
SAML Demo App — a minimal SAML 2.0 Service Provider for Duo SSO.

Shows how Duo SSO authenticates users via SAML and demonstrates
Duo Passport (remembered device across browsers).
"""
import os
import json
from flask import (
    Flask, request, redirect, session, render_template,
    url_for, make_response
)
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "saml-demo-secret-key")

# ---------------------------------------------------------------------------
# SAML config is built dynamically from env vars so the admin can configure
# it through the Automagic UI without touching files.
# ---------------------------------------------------------------------------
def _saml_settings(sp_host_override=None):
    """Build python3-saml settings dict from environment variables."""
    sp_host = sp_host_override or os.environ.get("SP_HOST") or "http://localhost:9400"

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
            "entityId": os.environ.get("IDP_ENTITY_ID", ""),
            "singleSignOnService": {
                "url": os.environ.get("IDP_SSO_URL", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": os.environ.get("IDP_SLO_URL", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": os.environ.get("IDP_CERT", ""),
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
    url_data = request.url.split("?")
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
    return bool(os.environ.get("IDP_SSO_URL"))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Landing page — shows login button or user info."""
    user = session.get("saml_user")
    attrs = session.get("saml_attrs", {})
    configured = _is_configured()
    return render_template("index.html",
                           user=user, attrs=attrs, configured=configured)


@app.route("/login")
def login():
    """Initiate SAML login — redirect to Duo SSO."""
    if not _is_configured():
        return "SAML not configured. Set IdP details via Automagic first.", 400
    auth = OneLogin_Saml2_Auth(_prepare_request(), _saml_settings())
    return redirect(auth.login())


@app.route("/acs", methods=["POST"])
def acs():
    """Assertion Consumer Service — receives SAML response from Duo."""
    auth = OneLogin_Saml2_Auth(_prepare_request(), _saml_settings())
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
    """SP metadata — use this URL when configuring Duo."""
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
