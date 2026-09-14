from flask import Flask, render_template, request, redirect, url_for, flash, session
import requests, base64, time
from scripts.csa_scripts.create_pod_resources import (
    get_first_connector_id,
    create_private_resource_group,
    create_private_resources,
    get_browser_access_table
)
from scripts.csa_scripts.create_priv_policy import (
    create_private_access_policy
)
from scripts.csa_scripts.create_recom import (
    follow_recom
)
from scripts.csa_scripts.create_int_policy import (
    create_int_block_malicious_policy,
    create_int_warn_policy,
    create_int_warn_shopping_policy,
    create_inet_isolate_policy,
    create_int_block_content_policy,
    create_int_block_apps_policy,
    create_allow_all_policy,
    create_url_filtering_policies
)
from scripts.csa_scripts.create_ai_int_policy import (
    create_ai_proposed_policies
)
from scripts.csa_scripts.create_steve_policies import (
    create_steve_policies
)
from scripts.csa_scripts.create_dlp_rules import (
    create_ai_guardrail_rule,
    create_scoped_ai_guardrail_rule,
    create_realtime_dlp_rule
)


app = Flask(__name__)

############# App.Route Overview ##############
@app.route('/')
def overview():
    return render_template('overview.html')

############# App.Route Links ##############
@app.route('/links')
def links():
    return render_template('links.html')

# Auth

app.secret_key = "cisco-poc-in-a-pod"
token_cache = {"access_token": None, "expires_at": 0}


# -------- AUTH --------
def get_access_token(api_key, api_secret):
    credentials = f"{api_key}:{api_secret}"
    encoded = base64.b64encode(credentials.encode()).decode()
    url = "https://api.sse.cisco.com/auth/v2/token"
    headers = {"Authorization": f"Basic {encoded}"}
    response = requests.post(url, headers=headers, timeout=10)
    response.raise_for_status()
    data = response.json()
    token_cache["access_token"] = data.get("access_token")
    token_cache["expires_at"] = time.time() + data.get("expires_in", 3600)
    return token_cache["access_token"]


def ensure_valid_token(api_key, api_secret):
    if not token_cache["access_token"] or time.time() >= token_cache["expires_at"]:
        return get_access_token(api_key, api_secret)
    return token_cache["access_token"]



############# App.Route Overview ##############
@app.route("/secure-access", methods=["GET", "POST"])
def secure_access():
    
    # If token is gone (e.g. after a rebuild), try to restore it from session credentials
    if not token_cache.get("access_token"):
        session.pop("authenticated", None)
        stored_key = session.get("csa_api_key")
        stored_secret = session.get("csa_api_secret")
        if stored_key and stored_secret:
            try:
                get_access_token(stored_key, stored_secret)
                session["authenticated"] = True
            except Exception:
                pass  # credentials may be expired; user will see the form pre-filled

    if request.method == "POST":
        # Use form values if provided, otherwise fall back to session-stored credentials
        api_key = request.form.get("api_key", "").strip() or session.get("csa_api_key", "")
        api_secret = request.form.get("api_secret", "").strip() or session.get("csa_api_secret", "")
        action = request.form.get("action")

        # Persist credentials to session whenever they are explicitly submitted
        if request.form.get("api_key", "").strip():
            session["csa_api_key"] = api_key
            session["csa_api_secret"] = api_secret

        # NEEDS NO AUTHENTICATION
        # Goto CSA Dashboard & manual config
        if action ==  "create_profile":
            # Link to Dashboard — org ID sourced from the SSE API token claims if available
            return redirect("https://dashboard.sse.cisco.com/secure/securityprofiles")

        try:
            token = ensure_valid_token(api_key, api_secret)

            # Action: AUTHENTICATE
            if action == "auth":
                # 1️⃣ Authenticate and persist credentials
                token = get_access_token(api_key, api_secret)
                session["csa_api_key"] = api_key
                session["csa_api_secret"] = api_secret

                # 2️⃣ Mark the session as authenticated so the UI updates
                session["authenticated"] = True

                # 3️⃣ Let the user know
                flash("✅ Authentication successful! Token stored for 60 min.")


            # NEEDS AUTHENTICATION

            # Action: CREATE PRIVATE RESOURCES
            if action == "create_pod":
                if not session.get("authenticated"):
                    flash("⚠️ Please authenticate first.")
                    return redirect(url_for("secure_access"))

                vm_ip = request.form.get("vm_ip", "").strip()
                if not vm_ip:
                    flash("⚠️ IP address missing.")
                    return redirect(url_for("secure_access"))

                connector_group_name = request.form.get("connector_group_name", "").strip() or None
                connector_id, connector_name = get_first_connector_id(token, connector_group_name)
                group = create_private_resource_group(token, vm_ip, connector_id)
                group_id = group.get("id") or group.get("resourceGroupId")
                created = create_private_resources(token, vm_ip, group_id)
                flash(f"✅ Private resources created.")


            # Action: CREATE PRIVATE ACCESS
            elif action == "create_private":
                if not session.get("authenticated"):
                    flash("⚠️ Please authenticate first.")
                    return redirect(url_for("secure_access"))

                token = token_cache.get("access_token")
                if not token:
                    flash("⚠️ Missing token — please re-authenticate.")
                    return redirect(url_for("secure_access"))

                # Create the policy
                policy = create_private_access_policy(token)
                flash(f"✅ Private Access Policy created successfully.")

            # Action: FOLLOW CISCO RECOMMENDATIONS
            elif action == "follow_recom":
                if not session.get("authenticated"):
                    flash("⚠️ Please authenticate first.")
                    return redirect(url_for("secure_access"))

                token = token_cache.get("access_token")
                if not token:
                    flash("⚠️ Missing token — please re-authenticate.")
                    return redirect(url_for("secure_access"))
                
                ### start API Call in script /scripts/.py files
                # Follow recommendations
                follow_recom(token)
                flash(f"✅ Follow recommendations successful")

                ### start API Call in script /scripts/.py files


            # Action: CREATE DLP RULES
            elif action == "create_dlp":
                if not session.get("authenticated"):
                    flash("⚠️ Please authenticate first.")
                    return redirect(url_for("secure_access"))

                token = token_cache.get("access_token")
                if not token:
                    flash("⚠️ Missing token — please re-authenticate.")
                    return redirect(url_for("secure_access"))

                create_ai_guardrail_rule(token)
                create_scoped_ai_guardrail_rule(token)
                create_realtime_dlp_rule(token)
                flash("✅ DLP rules created.")

            # Action: CREATE INTERNET ACCESS
            elif action == "create_internet":
                if not session.get("authenticated"):
                    flash("⚠️ Please authenticate first.")
                    return redirect(url_for("secure_access"))

                # Rules are created low-to-high priority number (evaluated top-down).

                # block malicious sites (prio 1)
                block_malicious = create_int_block_malicious_policy(token)

                # warn — Gen AI (prio 2)
                warn = create_int_warn_policy(token)

                # warn — Shopping (prio 3)
                warn_shopping = create_int_warn_shopping_policy(token)

                # isolate — News (prio 4)
                isolate = create_inet_isolate_policy(token)

                # block content — Alcohol & Gambling (prio 5)
                block_content = create_int_block_content_policy(token)

                # block apps — DeepSeek (prio 6)
                block_app = create_int_block_apps_policy(token)

                # URL filtering (SWG) — Allow cisco.reddit.com (prio 7) + Block Reddit (prio 8)
                url_filtering = create_url_filtering_policies(token)

                # allow all (prio 9 — must stay below the URL rules above)
                allow_all = create_allow_all_policy(token)

                flash("✅ Internet Access policies created.")

            # Action: CREATE AI-PROPOSED INTERNET ACCESS
            elif action == "create_ai_internet":
                if not session.get("authenticated"):
                    flash("⚠️ Please authenticate first.")
                    return redirect(url_for("secure_access"))

                create_ai_proposed_policies(token)
                flash("✅ AI-Proposed Internet Access policies created.")

            # Action: CREATE ALL POLICIES FROM THE TEST-CASE LIST ("Steve")
            elif action == "create_steve":
                if not session.get("authenticated"):
                    flash("⚠️ Please authenticate first.")
                    return redirect(url_for("secure_access"))

                results = create_steve_policies(token)
                created = [r for r in results if r["status"] == "created"]
                failed = [r for r in results if r["status"] != "created"]
                flash(f"✅ Steve created {len(created)} of {len(results)} policies.")
                for r in failed:
                    flash(f"⚠️ {r['policy']}: {r.get('error', 'failed')}")


        except Exception as e:
            flash(f"⚠️ Error in app.py: {e}")

        return redirect(url_for("secure_access"))

    return render_template('secure-access.html')


@app.route('/api/secure-access/browser-resources')
def secure_access_browser_resources():
    """
    Returns the private resources with their internal address and browser-based
    (clientless ZTNA) external URL, for the popup next to the Create Pod
    Resources button.
    """
    from flask import jsonify

    token = token_cache.get("access_token")
    if not token:
        stored_key = session.get("csa_api_key")
        stored_secret = session.get("csa_api_secret")
        if stored_key and stored_secret:
            try:
                token = ensure_valid_token(stored_key, stored_secret)
            except Exception:
                token = None
    if not token:
        return jsonify({"ok": False, "error": "Not authenticated — please authenticate first.", "resources": []}), 401

    try:
        rows = get_browser_access_table(token)
        return jsonify({"ok": True, "resources": rows})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "resources": []}), 500


############# App.Route Duo ##############
@app.route('/duo', methods=['GET', 'POST'])
def duo():
    if request.method == 'POST':
        # Get credentials from form
        api_hostname = request.form.get('api_hostname')
        integration_key = request.form.get('integration_key')
        secret_key = request.form.get('secret_key')
        action = request.form.get('action')

        # Cisco Identity Intelligence uses its OWN API credentials (separate from
        # the Duo Admin API), so handle saving/testing them before the Duo-cred
        # gate below.
        if action == 'save_cii_creds':
            cii_token_url = request.form.get('cii_token_url', '').strip()
            cii_client_id = request.form.get('cii_client_id', '').strip()
            cii_client_secret = request.form.get('cii_client_secret', '').strip()
            cii_api_url = request.form.get('cii_api_url', '').strip()
            cii_audience = request.form.get('cii_audience', '').strip()
            if not all([cii_token_url, cii_client_id, cii_client_secret, cii_api_url]):
                flash("⚠️ Provide Token URL, Client ID, Client Secret, and API URL for Identity Intelligence.")
                return redirect(url_for('duo'))
            try:
                from scripts.identity_intelligence import check_credentials
                check_credentials(cii_token_url, cii_client_id, cii_client_secret,
                                  cii_api_url, cii_audience or None)
                session['cii_token_url'] = cii_token_url
                session['cii_client_id'] = cii_client_id
                session['cii_client_secret'] = cii_client_secret
                session['cii_api_url'] = cii_api_url
                session['cii_audience'] = cii_audience
                session['cii_authenticated'] = True
                flash("✅ Identity Intelligence API connected (token + ping OK).")
            except Exception as e:
                session['cii_authenticated'] = False
                flash(f"⚠️ Identity Intelligence connection failed: {e}")
            return redirect(url_for('duo'))

        # Store credentials in session whenever explicitly submitted
        if api_hostname and integration_key and secret_key:
            session['duo_api_hostname'] = api_hostname
            session['duo_integration_key'] = integration_key
            session['duo_secret_key'] = secret_key

        # Fall back to session-stored credentials
        api_hostname = api_hostname or session.get('duo_api_hostname')
        integration_key = integration_key or session.get('duo_integration_key')
        secret_key = secret_key or session.get('duo_secret_key')

        if not all([api_hostname, integration_key, secret_key]):
            flash("⚠️ Please provide all Duo credentials (API hostname, integration key, and secret key)")
            return redirect(url_for('duo'))

        try:
            # Action: AUTHENTICATE
            if action == 'auth':
                from scripts.duo.duo_automation import check_credentials
                check_credentials(api_hostname, integration_key, secret_key)
                session['duo_authenticated'] = True
                flash("✅ Authentication successful!")
                return redirect(url_for('duo'))

            # Action: SETUP DUO (Complete setup with up to 3 users)
            if action == 'setup_duo':
                # Collect up to 3 users; skip rows where either field is blank
                users_list = []
                for i in range(1, 4):
                    email = request.form.get(f'user_email_{i}', '').strip()
                    if email:
                        users_list.append({'email': email, 'username': email})

                # Validate at least one user is provided
                if not users_list:
                    flash("⚠️ Please provide at least one email address")
                    return redirect(url_for('duo'))
                
                # Import and call the complete setup function
                from scripts.duo.duo_automation import setup_duo_complete
                
                result = setup_duo_complete(
                    api_hostname=api_hostname,
                    integration_key=integration_key,
                    secret_key=secret_key,
                    users_list=users_list
                )

                flash("✅ Duo setup complete.")
                if result['errors']:
                    for error in result['errors']:
                        flash(f"⚠️ {error}")

            # Action: CONFIGURE GLOBAL POLICY
            if action == 'configure_policy':
                from scripts.duo.duo_automation import configure_global_policy
                result = configure_global_policy(
                    api_hostname=api_hostname,
                    integration_key=integration_key,
                    secret_key=secret_key
                )
                if result['success']:
                    flash("✅ Global policy configured.")
                    for warning in result.get('warnings', []):
                        flash(f"⚠️ {warning}")
                else:
                    flash(f"⚠️ {result['error']}")

            # Action: ASSIGN POC USERS TO IDENTITY INTELLIGENCE SSO APP
            if action == 'assign_cii_group':
                from scripts.duo.duo_automation import assign_group_to_identity_intelligence
                result = assign_group_to_identity_intelligence(
                    api_hostname=api_hostname,
                    integration_key=integration_key,
                    secret_key=secret_key,
                )
                if result['success']:
                    flash(f"✅ Restricted '{result['integration_name']}' to the PoC Users group.")
                else:
                    flash(f"⚠️ {result['error']}")

            # Action: CREATE SAML APP
            if action == 'create_saml_app':
                from scripts.duo.duo_automation import (
                    create_integration, get_integration_metadata_url, fetch_and_push_idp_metadata
                )
                sp_base_url = f"http://{request.host.split(':')[0]}:30400"
                result = create_integration(
                    api_hostname=api_hostname,
                    integration_key=integration_key,
                    secret_key=secret_key,
                    name="PoC in a Pod: SAML App",
                    integration_type="sso-generic",
                    sso_config={
                        'acs_urls': [{'url': f"{sp_base_url}/acs"}],
                        'entity_id': f"{sp_base_url}/metadata",
                        'nameid_attribute': 'email',
                        'nameid_format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                        'sign_assertion': True,
                        'sign_response': True,
                        'signing_algorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
                    }
                )
                if result['success']:
                    app_ikey = result['integration_key']
                    session['saml_app_ikey'] = app_ikey

                    meta_result = get_integration_metadata_url(
                        api_hostname, integration_key, secret_key, app_ikey
                    )
                    if meta_result['success'] and meta_result['metadata_url']:
                        push_result = fetch_and_push_idp_metadata(
                            meta_result['metadata_url'], sp_base_url
                        )
                        if push_result['success']:
                            flash("✅ SAML App created and auto-configured — ready to test.")
                            session['saml_app_configured'] = True
                        else:
                            flash("✅ SAML App created — download IdP metadata XML from Duo and upload manually.")
                            session['saml_app_configured'] = False
                    else:
                        flash("✅ SAML App created — download IdP metadata XML from Duo Admin Panel and upload manually.")
                        session['saml_app_configured'] = False
                else:
                    flash(f"⚠️ {result['error']}")

        except Exception as e:
            flash(f"⚠️ Error: {str(e)}")
        
        return redirect(url_for('duo'))
    
    return render_template('duo.html')


@app.route('/api/identity-intelligence/risky-users')
def identity_intelligence_risky_users():
    """Read-only feed for the Risky Users panel — top end users by trust score."""
    from flask import jsonify
    if not session.get('cii_authenticated'):
        return jsonify({"ok": False, "error": "Connect Identity Intelligence first.", "users": []}), 401
    try:
        from scripts.identity_intelligence import list_risky_users
        users = list_risky_users(
            token_url=session.get('cii_token_url'),
            client_id=session.get('cii_client_id'),
            client_secret=session.get('cii_client_secret'),
            api_url=session.get('cii_api_url'),
            audience=session.get('cii_audience') or None,
            limit=50,
        )
        return jsonify({"ok": True, "users": users})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "users": []}), 500


@app.route('/cilium', methods=['GET', 'POST'])
def cilium():
    from scripts.cilium_policies import (
        apply_zero_trust, apply_allow_all, get_active_policies,
        apply_l7_http, remove_l7_http,
        apply_dns_egress, remove_dns_egress,
        exec_in_httpbin,
    )

    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == 'allow_all':
                apply_allow_all()
                flash("✅ Allow All Traffic")

            elif action == 'zero_trust':
                apply_zero_trust()
                flash("✅ Zero Trust Segmentation")

            # ── L7 HTTP ──────────────────────────────────────────────────
            elif action == 'apply_l7':
                apply_l7_http()
                flash("✅ L7 HTTP Policy applied — httpbin accepts GET only")
            elif action == 'remove_l7':
                remove_l7_http()
                flash("✅ L7 HTTP Policy removed")
            elif action == 'test_l7_get':
                try:
                    resp = requests.get("http://httpbin/get", timeout=5)
                    if resp.status_code == 200:
                        flash("✅ GET /get → 200 OK")
                    else:
                        flash(f"⚠️ GET /get → {resp.status_code}")
                except requests.exceptions.ConnectionError:
                    flash("⚠️ httpbin not reachable — pod may still be starting, try again in a few seconds")
            elif action == 'test_l7_post':
                try:
                    resp = requests.post("http://httpbin/post", timeout=5)
                    if resp.status_code == 403:
                        flash("🔒 POST /post → 403 Forbidden — blocked by Cilium L7 policy")
                    elif resp.status_code == 200:
                        flash("✅ POST /post → 200 OK — policy not active")
                    else:
                        flash(f"⚠️ POST /post → {resp.status_code}")
                except requests.exceptions.ConnectionError:
                    flash("⚠️ httpbin not reachable — pod may still be starting, try again in a few seconds")

            # ── DNS egress ───────────────────────────────────────────────
            elif action == 'apply_dns':
                apply_dns_egress()
                flash("✅ DNS Egress Filter applied — only *.cisco.com is permitted outbound")
            elif action == 'remove_dns':
                remove_dns_egress()
                flash("✅ DNS Egress Filter removed")
            elif action in ('test_dns_allow', 'test_dns_block'):
                domain = "www.cisco.com" if action == 'test_dns_allow' else "hp.com"
                code = (
                    "import urllib.request, ssl\n"
                    "ctx = ssl._create_unverified_context()\n"
                    "try:\n"
                    f"    r = urllib.request.urlopen('https://{domain}', timeout=5, context=ctx)\n"
                    "    print('__ok__:' + str(r.status))\n"
                    "except Exception as e:\n"
                    "    print('__fail__:' + str(e))\n"
                )
                out = exec_in_httpbin(["python3", "-c", code])
                if "__notfound__" in out:
                    flash("⚠️ httpbin pod not running — apply a policy first to deploy it")
                elif "__ok__" in out:
                    if action == 'test_dns_allow':
                        flash(f"✅ {domain} → reachable")
                    else:
                        flash(f"⚠️ {domain} → reachable — DNS filter not active")
                else:
                    if action == 'test_dns_block':
                        flash(f"🔒 {domain} → blocked (DNS filtered by Cilium)")
                    else:
                        flash(f"⚠️ {domain} → {out[:120]}")

        except Exception as e:
            flash(f"⚠️ Error applying Cilium policy: {e}")
        return redirect(url_for('cilium'))

    active_policies = []
    policy_error = None
    try:
        active_policies = get_active_policies()
    except Exception as e:
        policy_error = str(e)

    from scripts.cilium_policies import _PIAP_RESTRICTED_SERVICES, LAN_ALWAYS_REACHABLE
    return render_template(
        'cilium.html',
        active_policies=active_policies,
        policy_error=policy_error,
        zero_trust_targets=list(_PIAP_RESTRICTED_SERVICES),
        lan_always_reachable=LAN_ALWAYS_REACHABLE,
    )


@app.route('/cilium/run', methods=['POST'])
def cilium_run():
    from flask import jsonify
    from scripts.cilium_policies import (
        exec_in_httpbin,
        apply_l7_http, remove_l7_http, apply_dns_egress, remove_dns_egress,
    )
    data = request.get_json(force=True)
    action = data.get('action', '')

    def _exec(cmd_list):
        """Exec command in httpbin pod. Returns (output_str, not_found_bool)."""
        out = exec_in_httpbin(cmd_list)
        return out.replace('__error__: ', 'exec error: ').strip(), '__notfound__' in out

    def _run():
        # ── Policy deploy/remove (AJAX, no page reload) ──────────────────────
        if action == 'deploy_l7':
            result, httpbin_status = apply_l7_http()
            note = '\nhttpbin pod starting — image pull takes ~60 s. Run tests once the pod is ready.' if httpbin_status == 'created' else ''
            return {'command': 'Apply L7 HTTP Policy', 'output': str(result) + note,
                    'ok': True, 'policy': 'piap-l7-http', 'active': True, 'httpbin_created': httpbin_status == 'created'}

        elif action == 'remove_l7':
            result = remove_l7_http()
            return {'command': 'Remove L7 HTTP Policy', 'output': str(result),
                    'ok': True, 'policy': 'piap-l7-http', 'active': False}

        elif action == 'deploy_dns':
            result, httpbin_status = apply_dns_egress()
            note = '\nhttpbin pod starting — image pull takes ~60 s. Run tests once the pod is ready.' if httpbin_status == 'created' else ''
            return {'command': 'Apply DNS Egress Filter', 'output': str(result) + note,
                    'ok': True, 'policy': 'piap-dns-egress', 'active': True, 'httpbin_created': httpbin_status == 'created'}

        elif action == 'remove_dns':
            result = remove_dns_egress()
            return {'command': 'Remove DNS Egress Filter', 'output': str(result),
                    'ok': True, 'policy': 'piap-dns-egress', 'active': False}

        # ── L7 HTTP tests — exec inside httpbin pod so the test is independent
        #    of whether the dashboard→httpbin TCP path is healthy after policy
        #    teardown (Cilium L7 proxy reconfiguration can briefly break it).
        elif action == 'curl_get':
            cmd = 'curl -s -o /dev/null -w "%{http_code}" http://httpbin/get'
            code = (
                'import urllib.request\n'
                'try:\n'
                '    r = urllib.request.urlopen("http://httpbin/get", timeout=5)\n'
                '    print("HTTP " + str(r.status))\n'
                'except urllib.error.HTTPError as e: print("HTTP " + str(e.code))\n'
                'except Exception as e: print("Error: " + str(e))\n'
            )
            out, nf = _exec(['python3', '-c', code])
            if nf:
                return {'command': cmd, 'output': 'httpbin pod not running — deploy a policy first', 'ok': False}
            ok = 'HTTP 200' in out
            return {'command': cmd, 'output': out + (' — OK' if ok else ''), 'ok': ok}

        elif action == 'curl_post':
            cmd = 'curl -s -o /dev/null -w "%{http_code}" -X POST http://httpbin/post'
            code = (
                'import urllib.request\n'
                'req = urllib.request.Request("http://httpbin/post", data=b"{}", method="POST")\n'
                'try:\n'
                '    r = urllib.request.urlopen(req, timeout=5)\n'
                '    print("HTTP " + str(r.status))\n'
                'except urllib.error.HTTPError as e: print("HTTP " + str(e.code))\n'
                'except Exception as e: print("Error: " + str(e))\n'
            )
            out, nf = _exec(['python3', '-c', code])
            if nf:
                return {'command': cmd, 'output': 'httpbin pod not running — deploy a policy first', 'ok': False}
            if 'HTTP 200' in out:
                return {'command': cmd, 'output': 'HTTP 200 — OK (policy not active)', 'ok': True}
            if 'HTTP 403' in out:
                return {'command': cmd, 'output': 'HTTP 403 — blocked by Cilium L7 policy', 'ok': False}
            return {'command': cmd, 'output': out or 'No response', 'ok': False}

        # ── DNS egress tests ──────────────────────────────────────────────────
        elif action in ('dns_cisco', 'dns_badguys'):
            domain = 'www.cisco.com' if action == 'dns_cisco' else 'hp.com'
            cmd = f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 https://{domain}'
            code = (
                'import urllib.request, ssl\n'
                'ctx = ssl._create_unverified_context()\n'
                'try:\n'
                f'    r = urllib.request.urlopen("https://{domain}", timeout=5, context=ctx)\n'
                '    print("__ok__:" + str(r.status))\n'
                'except Exception as e:\n'
                '    print("__fail__:" + str(e))\n'
            )
            out, nf = _exec(['python3', '-c', code])
            if nf:
                return {'command': cmd, 'output': 'httpbin pod not running — deploy a policy first', 'ok': False}
            reached = '__ok__' in out
            if action == 'dns_cisco':
                note = f'{domain} → reachable' if reached else f'{domain} → blocked or unreachable'
                ok = reached
            else:
                note = f'{domain} → BLOCKED by DNS filter' if not reached else f'{domain} → reachable (DNS filter not active)'
                ok = not reached
            return {'command': cmd, 'output': note, 'ok': ok}

        # ── Custom command (exec inside httpbin pod) ──────────────────────────
        elif action == 'custom':
            cmd_str = data.get('command', '').strip()
            if not cmd_str:
                return {'command': '', 'output': 'No command entered', 'ok': False}
            out, nf = _exec(['sh', '-c', cmd_str])
            if nf:
                return {'command': cmd_str, 'output': 'httpbin pod not running — deploy a policy first', 'ok': False}
            return {'command': cmd_str, 'output': out or '(no output)', 'ok': True}

        return {'command': '', 'output': 'Unknown action', 'ok': False}

    try:
        return jsonify(_run())
    except Exception as e:
        return jsonify({'command': '', 'output': f'Error: {e}', 'ok': False})


@app.route('/api/cilium/nodes')
def cilium_nodes():
    from flask import jsonify
    from scripts.cilium_policies import get_diagram_nodes
    return jsonify(get_diagram_nodes())


@app.route('/api/cilium/custom-policies')
def cilium_custom_policies_api():
    from flask import jsonify
    from scripts.cilium_policies import get_custom_policies
    return jsonify(get_custom_policies())


@app.route('/api/cilium/apply-custom', methods=['POST'])
def cilium_apply_custom():
    from flask import jsonify
    from scripts.cilium_policies import apply_custom_policies
    data = request.get_json(force=True)
    result = apply_custom_policies(data.get('policies', []))
    ok = all(r.get('ok') for r in result)
    return jsonify({'ok': ok, 'results': result})


@app.route('/api/cilium/delete-custom/<name>', methods=['DELETE'])
def cilium_delete_custom(name):
    from flask import jsonify
    from scripts.cilium_policies import delete_custom_policy
    try:
        msg = delete_custom_policy(name)
        return jsonify({'ok': True, 'result': msg})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@app.route('/tetragon', methods=['GET', 'POST'])
def tetragon():
    from scripts.tetragon_policies import deploy_policies, remove_policies, get_active_policies

    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == 'deploy':
                results = deploy_policies()
                for r in results:
                    flash(f"✅ {r}")
                flash("Tetragon TracingPolicies deployed.")
            elif action == 'remove':
                results = remove_policies()
                for r in results:
                    flash(f"✅ {r}")
                flash("Tetragon TracingPolicies removed.")
            elif action in ('simulate', 'simulate_recon'):
                from scripts.tetragon_policies import simulate_recon
                job_name = simulate_recon()
                flash(f"🔍 Recon simulation launched — Job: {job_name}")
                flash("Watch the live event stream for shell execution events.")
            elif action == 'simulate_credentials':
                from scripts.tetragon_policies import simulate_credentials
                job_name = simulate_credentials()
                flash(f"🔑 Credential hunting simulation launched — Job: {job_name}")
                flash("Watch for sensitive-file-read and k8s-secret-access events.")
            elif action == 'simulate_persistence':
                from scripts.tetragon_policies import simulate_persistence
                job_name = simulate_persistence()
                flash(f"🪝 Persistence simulation launched — Job: {job_name}")
                flash("Watch for shell execution and file write events.")
            elif action == 'stop_attacks':
                from scripts.tetragon_policies import stop_attacks
                deleted = stop_attacks()
                if deleted:
                    flash(f"🛑 Stopped {len(deleted)} simulation job(s): {', '.join(deleted)}")
                else:
                    flash("No running simulation jobs found.")
        except Exception as e:
            flash(f"⚠️ Error: {e}")
        return redirect(url_for('tetragon'))

    active_policies = []
    policy_error = None
    try:
        active_policies = get_active_policies()
    except Exception as e:
        policy_error = str(e)

    running_sims = set()
    try:
        from scripts.tetragon_policies import get_running_simulations
        running_sims = get_running_simulations()
    except Exception:
        pass

    return render_template('tetragon.html', active_policies=active_policies,
                           policy_error=policy_error, running_sims=running_sims)


@app.route('/tetragon/events')
def tetragon_events():
    """JSON endpoint polled by the frontend for live Tetragon events."""
    from flask import jsonify
    from scripts.tetragon_policies import get_tetragon_events
    try:
        raw_events = get_tetragon_events(max_lines=200)
        events = []
        for ev in raw_events:
            # Normalise the Tetragon JSON schema into a flat display dict
            process_exec = ev.get("process_exec") or {}
            process_kprobe = ev.get("process_kprobe") or {}
            process_exit = ev.get("process_exit") or {}

            proc = (
                process_exec.get("process")
                or process_kprobe.get("process")
                or process_exit.get("process")
                or {}
            )

            events.append({
                "time": ev.get("time", ""),
                "type": ev.get("process_exec") and "exec"
                        or ev.get("process_kprobe") and "kprobe"
                        or ev.get("process_exit") and "exit"
                        or "unknown",
                "binary": proc.get("binary", ""),
                "arguments": proc.get("arguments", ""),
                "pod": (proc.get("pod") or {}).get("name", ""),
                "namespace": (proc.get("pod") or {}).get("namespace", ""),
                "action": process_kprobe.get("action", ""),
                "func_name": process_kprobe.get("function_name", ""),
            })
        pod_filter = request.args.get('pod', '').strip()
        if pod_filter:
            events = [e for e in events if e.get('pod', '').startswith(pod_filter)]
        return jsonify({"events": events[-50:], "total": len(events)})
    except Exception as e:
        return jsonify({"events": [], "error": str(e)})

@app.route('/tetragon/run', methods=['POST'])
def tetragon_run():
    """JSON endpoint for simulation actions — avoids full page reload."""
    from flask import jsonify
    data = request.get_json(force=True)
    action = data.get('action')
    try:
        if action == 'simulate_recon':
            from scripts.tetragon_policies import simulate_recon
            job_name = simulate_recon()
            return jsonify({'ok': True, 'message': f'Recon launched — Job: {job_name}', 'sim': 'recon'})
        elif action == 'simulate_credentials':
            from scripts.tetragon_policies import simulate_credentials
            job_name = simulate_credentials()
            return jsonify({'ok': True, 'message': f'Credential hunting launched — Job: {job_name}', 'sim': 'credentials'})
        elif action == 'simulate_persistence':
            from scripts.tetragon_policies import simulate_persistence
            job_name = simulate_persistence()
            return jsonify({'ok': True, 'message': f'Persistence simulation launched — Job: {job_name}', 'sim': 'persistence'})
        elif action == 'stop_attacks':
            from scripts.tetragon_policies import stop_attacks
            deleted = stop_attacks()
            msg = f'Stopped {len(deleted)} job(s): {", ".join(deleted)}' if deleted else 'No running jobs found.'
            return jsonify({'ok': True, 'message': msg, 'sim': None})
        else:
            return jsonify({'ok': False, 'message': f'Unknown action: {action}'})
    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)})


def _collector_session_creds(source):
    """Return the collector credential env for a source from the session, or None
    if the credentials for that source haven't been entered yet."""
    if source == 'cii' and session.get('cii_authenticated'):
        return {
            "CII_TOKEN_URL": session.get('cii_token_url'),
            "CII_CLIENT_ID": session.get('cii_client_id'),
            "CII_CLIENT_SECRET": session.get('cii_client_secret'),
            "CII_API_URL": session.get('cii_api_url'),
            "CII_AUDIENCE": session.get('cii_audience', ''),
        }
    if source == 'duo' and all([session.get('duo_api_hostname'), session.get('duo_integration_key'), session.get('duo_secret_key')]):
        return {
            "DUO_HOST": session.get('duo_api_hostname'),
            "DUO_IKEY": session.get('duo_integration_key'),
            "DUO_SKEY": session.get('duo_secret_key'),
        }
    if source == 'secure_access' and all([session.get('csa_api_key'), session.get('csa_api_secret')]):
        return {
            "CSA_KEY": session.get('csa_api_key'),
            "CSA_SECRET": session.get('csa_api_secret'),
        }
    return None


@app.route('/splunk', methods=['GET', 'POST'])
def splunk():
    from scripts.splunk import (
        is_available, hec_is_healthy,
        SPLUNKBASE_APPS, get_splunkbase_app_status,
    )

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'provision_k8s_dashboard':
            from scripts.splunk import provision_k8s_dashboard
            try:
                provision_k8s_dashboard()
                flash("✅ Kubernetes Infrastructure dashboard provisioned — click 'Open Dashboard' to view it.")
            except Exception as e:
                flash(f"⚠️ Dashboard provisioning failed: {e}")
            return redirect(url_for('splunk'))

        if action == 'deploy_splunk':
            from scripts.splunk import deploy_splunk
            license_content = request.form.get('license_content', '').strip()
            if not license_content:
                flash("A Splunk Enterprise license is required. Paste your .lic file contents to deploy.")
                return redirect(url_for('splunk'))
            try:
                deploy_splunk(license_content)
                flash("Splunk deployed with Enterprise license — allow ~5 min for startup.")
            except Exception as e:
                flash(f"Deployment failed: {e}")
            return redirect(url_for('splunk'))

        if action == 'restart_splunk':
            from scripts.splunk import restart_splunk
            try:
                restart_splunk()
                flash("Splunk is restarting — allow ~2 minutes for it to come back online.")
            except Exception as e:
                flash(f"Restart failed: {e}")
            return redirect(url_for('splunk'))

        if action == 'install_app':
            from scripts.splunk import install_splunkbase_app
            app_id  = request.form.get('app_id', '').strip()
            sb_user = request.form.get('splunkbase_username', '').strip() or session.get('splunkbase_username', '')
            sb_pass = request.form.get('splunkbase_password', '').strip()
            # Ignore the masked placeholder; fall back to the session-stored password
            if not sb_pass or sb_pass.startswith('•'):
                sb_pass = session.get('splunkbase_password', '')
            # Persist whatever was explicitly entered for reuse by the orchestration
            if sb_user:
                session['splunkbase_username'] = sb_user
            if sb_pass:
                session['splunkbase_password'] = sb_pass
            if not app_id or not sb_user or not sb_pass:
                flash("App ID, Splunk.com username, and password are all required.")
            else:
                app_ids = [aid.strip() for aid in app_id.split(',') if aid.strip()]
                for aid in app_ids:
                    app_name = next((a['display'] for a in SPLUNKBASE_APPS if str(a['id']) == aid), aid)
                    try:
                        install_splunkbase_app(int(aid), sb_user, sb_pass)
                        flash(f"{app_name} installed — restart Splunk to activate.")
                    except Exception as e:
                        flash(f"{app_name} install failed: {e}")
            return redirect(url_for('splunk'))

        # ── Save Splunk.com credentials in session (for Cisco app install) ──
        if action == 'save_splunk_creds':
            sb_user = request.form.get('splunkbase_username', '').strip()
            sb_pass = request.form.get('splunkbase_password', '').strip()
            if sb_user:
                session['splunkbase_username'] = sb_user
            # Ignore the masked placeholder so we don't overwrite a stored password
            if sb_pass and not sb_pass.startswith('•'):
                session['splunkbase_password'] = sb_pass
            flash("✅ Splunk.com credentials saved for this session.")
            return redirect(url_for('splunk'))

        # ── Send to Splunk: per-component indexes + receiver ────────────────
        if action == 'provision_indexes':
            from scripts.splunk import ensure_indexes, enable_splunktcp_receiver
            try:
                idx = ensure_indexes()
                rcv = enable_splunktcp_receiver(9997)
                created = sum(1 for v in idx.values() if v in ('created', 'exists'))
                flash(f"✅ Provisioned {created}/{len(idx)} indexes; UF receiver on 9997: {rcv}.")
            except Exception as e:
                flash(f"⚠️ Index provisioning failed: {e}")
            return redirect(url_for('splunk'))

        # ── Send to Splunk: deploy a cloud->Splunk collector ────────────────
        if action == 'deploy_collector':
            from scripts.splunk_collectors import deploy_collector, SOURCES
            from scripts.splunk import ensure_indexes
            source = request.form.get('source', '').strip()
            if source not in SOURCES:
                flash(f"⚠️ Unknown collector source: {source}")
                return redirect(url_for('splunk'))

            creds = _collector_session_creds(source)
            if not creds:
                where = {'cii': 'Identity Intelligence on the Duo tab',
                         'duo': 'Duo on the Duo tab',
                         'secure_access': 'Secure Access on the Secure Access tab'}.get(source, 'its tab')
                flash(f"⚠️ Enter/authenticate {where} first.")
                return redirect(url_for('splunk'))

            try:
                ensure_indexes([SOURCES[source]['index']])
                label = deploy_collector(source, creds)
                flash(f"✅ {label} collector deployed — polling into index '{SOURCES[source]['index']}'.")
            except Exception as e:
                flash(f"⚠️ Collector deploy failed: {e}")
            return redirect(url_for('splunk'))

        # ── One-click orchestration: finish Splunk setup end-to-end ─────────
        if action == 'run_automation':
            from scripts.splunk import ensure_indexes, enable_splunktcp_receiver
            from scripts.splunk_app import build_app, APP_LABEL, SPLUNKER_USER
            from scripts.splunk_collectors import deploy_collector, SOURCES

            if not is_available():
                flash("⚠️ Splunk isn't ready yet — wait for it to finish starting, then run automation.")
                return redirect(url_for('splunk'))

            steps = []
            # 1) Per-component indexes + UF receiver
            try:
                ensure_indexes()
                rcv = enable_splunktcp_receiver(9997)
                steps.append(f"Indexes provisioned; UF receiver on 9997: {rcv}")
            except Exception as e:
                steps.append(f"⚠️ indexes/receiver: {e}")
            # 2) 'PoC in a Pod' app + splunker user + dashboards
            try:
                res = build_app()
                steps.append(f"'{APP_LABEL}' app + '{SPLUNKER_USER}' user + {len(res.get('views', []))} dashboards")
                for err in res.get('errors', []):
                    steps.append(f"⚠️ app: {err}")
            except Exception as e:
                steps.append(f"⚠️ app: {e}")
            # 3) Deploy collectors for every source whose creds are already in session
            deployed, skipped = [], []
            for source in ('cii', 'duo', 'secure_access'):
                creds = _collector_session_creds(source)
                if not creds:
                    skipped.append(source)
                    continue
                try:
                    ensure_indexes([SOURCES[source]['index']])
                    deploy_collector(source, creds)
                    deployed.append(source)
                except Exception as e:
                    steps.append(f"⚠️ collector {source}: {e}")
            if deployed:
                steps.append("Collectors deployed: " + ", ".join(deployed))
            if skipped:
                steps.append("Collectors skipped (add credentials, then re-run): " + ", ".join(skipped))
            # 4) DefenseClaw dashboard (best-effort)
            try:
                from scripts.defenseclaw import create_splunk_dashboard
                create_splunk_dashboard()
                steps.append("DefenseClaw dashboard created")
            except Exception as e:
                steps.append(f"DefenseClaw dashboard skipped ({e})")

            # 5) Cisco Splunkbase apps (coexist) — only if Splunk.com creds are saved
            sb_user = session.get('splunkbase_username')
            sb_pass = session.get('splunkbase_password')
            if sb_user and sb_pass:
                from scripts.splunk import install_splunkbase_app, restart_splunk
                # Add-on before app; Security Cloud last.
                cisco_app_ids = [7569, 5558, 7404]
                installed = []
                for aid in cisco_app_ids:
                    try:
                        install_splunkbase_app(aid, sb_user, sb_pass)
                        installed.append(str(aid))
                    except Exception as e:
                        steps.append(f"⚠️ Splunkbase app {aid}: {e}")
                if installed:
                    steps.append("Installed Cisco apps: " + ", ".join(installed))
                    try:
                        restart_splunk()
                        steps.append("Splunk restarting to activate the apps (~2 min)")
                    except Exception as e:
                        steps.append(f"⚠️ restart after app install: {e}")
            else:
                steps.append("Cisco Splunkbase apps skipped (save Splunk.com credentials to include)")

            flash("✅ Splunk automation complete.")
            for s in steps:
                flash(("⚠️ " not in s and "• " or "") + s)
            return redirect(url_for('splunk'))

        if action == 'remove_collector':
            from scripts.splunk_collectors import remove_collector, SOURCES
            source = request.form.get('source', '').strip()
            try:
                remove_collector(source)
                flash(f"✅ Removed {SOURCES.get(source, {}).get('label', source)} collector.")
            except Exception as e:
                flash(f"⚠️ Collector removal failed: {e}")
            return redirect(url_for('splunk'))

        # ── Send to Splunk: DefenseClaw AI-agent dashboard (consolidated here) ─
        if action == 'create_defenseclaw_dashboard':
            from scripts.defenseclaw import create_splunk_dashboard
            try:
                path = create_splunk_dashboard()
                flash(f"✅ DefenseClaw dashboard created — open it at {path}")
            except Exception as e:
                flash(f"⚠️ DefenseClaw dashboard creation failed: {e}")
            return redirect(url_for('splunk'))

        # ── Build the 'PoC in a Pod' Splunk app (splunker user + dashboards) ──
        if action == 'build_poc_app':
            from scripts.splunk_app import build_app, APP_LABEL, SPLUNKER_USER
            try:
                res = build_app()
                flash(f"✅ '{APP_LABEL}' app built — user '{SPLUNKER_USER}' {res.get('user') or 'ready'}, "
                      f"{len(res.get('views', []))} dashboards.")
                for err in res.get('errors', []):
                    flash(f"⚠️ {err}")
            except Exception as e:
                flash(f"⚠️ Failed to build the app: {e}")
            return redirect(url_for('splunk'))

    splunk_available = is_available()
    app_status = get_splunkbase_app_status() if splunk_available else {}

    from scripts.splunk import k8s_dashboard_exists, otel_collector_running
    # Cloud->Splunk collector statuses + whether each source's creds are ready
    from scripts.splunk_collectors import collector_status
    collectors = {
        "cii": {
            "status": collector_status("cii"),
            "creds_ready": bool(session.get('cii_authenticated')),
            "label": "Identity Intelligence", "index": "cii", "creds_where": "Duo tab",
        },
        "duo": {
            "status": collector_status("duo"),
            "creds_ready": bool(session.get('duo_api_hostname') and session.get('duo_integration_key') and session.get('duo_secret_key')),
            "label": "Duo Admin API logs", "index": "duo", "creds_where": "Duo tab",
        },
        "secure_access": {
            "status": collector_status("secure_access"),
            "creds_ready": bool(session.get('csa_api_key') and session.get('csa_api_secret')),
            "label": "Secure Access reporting", "index": "secure_access", "creds_where": "Secure Access tab",
        },
    }

    return render_template(
        'splunk.html',
        splunk_available=splunk_available,
        hec_healthy=hec_is_healthy() if splunk_available else False,
        server_ip=request.host.split(':')[0],
        splunkbase_apps=SPLUNKBASE_APPS,
        app_status=app_status,
        k8s_dashboard_exists=k8s_dashboard_exists() if splunk_available else False,
        otel_running=otel_collector_running() if splunk_available else False,
        collectors=collectors,
    )

@app.route('/splunk/status')
def splunk_status():
    from scripts.splunk import get_pod_status, is_available, hec_is_healthy
    status = get_pod_status()
    status["splunk_available"] = is_available()
    status["hec_healthy"] = hec_is_healthy() if status["splunk_available"] else False
    from flask import jsonify
    return jsonify(status)

@app.route('/ai-agents', methods=['GET', 'POST'])
def ai_agents():
    from scripts.defenseclaw import (get_status, deploy_environment, save_api_key,
                                      isolate_agent, unisolate_agent, get_isolation_status,
                                      create_splunk_dashboard)
    from scripts.splunk import hec_is_healthy

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'save_api_key':
            api_key = request.form.get('api_key', '').strip()
            if api_key and not api_key.startswith('•'):
                try:
                    save_api_key(api_key)
                    flash("Anthropic API key saved.")
                except Exception as e:
                    flash(f"Failed to save API key: {e}")
            else:
                flash("Please enter a valid API key.")
            return redirect(url_for('ai_agents'))

        if action == 'deploy':
            try:
                deploy_environment()
                flash("AI Agent environment deployed — containers are installing and starting up. This takes 1-2 minutes.")
            except Exception as e:
                flash(f"Deployment failed: {e}")
            return redirect(url_for('ai_agents'))

        if action == 'isolate':
            try:
                isolate_agent()
                flash("AI Agent isolated — egress to cluster pods is blocked. Only DNS, Splunk HEC (audit logs), and external HTTPS (Anthropic API) are allowed.")
            except Exception as e:
                flash(f"Isolation failed: {e}")
            return redirect(url_for('ai_agents'))

        if action == 'unisolate':
            try:
                unisolate_agent()
                flash("AI Agent isolation removed — full network access restored.")
            except Exception as e:
                flash(f"Failed to remove isolation: {e}")
            return redirect(url_for('ai_agents'))

        if action == 'create_dashboard':
            try:
                path = create_splunk_dashboard()
                flash(f"Splunk dashboard created — open it at {path}")
            except Exception as e:
                flash(f"Dashboard creation failed: {e}")
            return redirect(url_for('ai_agents'))

    status = get_status()
    status["isolated"] = get_isolation_status()
    status["hec_healthy"] = hec_is_healthy()
    return render_template('ai-agents.html', status=status)

@app.route('/help')
def help_page():
    return render_template('help.html')



if __name__ == "__main__":
    # Run Flask on port 8080 and listen on all interfaces.
    # debug=False disables the Werkzeug file-reloader which would call os.execv()
    # on every file-system change (hostPath mount) and cause the container to exit.
    app.run(host="0.0.0.0", port=8080, debug=False)