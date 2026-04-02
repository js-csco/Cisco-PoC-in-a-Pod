from flask import Flask, render_template, request, redirect, url_for, flash, session
import requests, base64, time
from scripts.csa_scripts.create_pod_resources import (
    get_first_connector_id,
    create_private_resource_group,
    create_private_resources
)
from scripts.csa_scripts.create_priv_policy import (
    create_private_access_policy
)
from scripts.csa_scripts.create_recom import (
    follow_recom
)
from scripts.csa_scripts.create_int_policy import (
    create_int_warn_policy,
    create_inet_isolate_policy,
    create_int_block_content_policy,
    create_int_block_apps_policy,
    create_allow_all_policy
)
from scripts.csa_scripts.create_dlp_rules import (
    create_ai_guardrail_rule,
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

app.secret_key = "supersecret"
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
            # Link to Dashboard!
            return redirect("https://dashboard.sse.cisco.com/org/8219751/secure/securityprofiles")

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
                    return redirect(url_for("index"))
            
                vm_ip = request.form.get("vm_ip", "").strip()
                if not vm_ip:
                    flash("⚠️ IP address missing.")
                    return redirect(url_for("index"))

                # this always gets the first connector in the list - array[0]
                # reason: in this PoC tenant should only be one resouce connector
                connector_id, connector_name = get_first_connector_id(token)
                flash(f"🔗 Using Connector: {connector_name} (ID: {connector_id})")

                # creation of private resource group
                # this can then be used for the private access policy
                group = create_private_resource_group(token, vm_ip, connector_id)
                flash(f"✅ Resource Group '{group.get('name')}' ready.")

                # create a private resource for each container
                group_id = group.get("id") or group.get("resourceGroupId")
                created = create_private_resources(token, vm_ip, group_id)
                flash(f"✅ {len(created)} Private Resources created.")


            # Action: CREATE PRIVATE ACCESS
            elif action == "create_private":
                if not session.get("authenticated"):
                    flash("⚠️ Please authenticate first.")
                    return redirect(url_for("index"))

                token = token_cache.get("access_token")
                if not token:
                    flash("⚠️ Missing token — please re-authenticate.")
                    return redirect(url_for("index"))

                # Create the policy
                policy = create_private_access_policy(token)
                flash(f"✅ Private Access Policy created successfully.")

            # Action: FOLLOW CISCO RECOMMENDATIONS
            elif action =="follow_recom":
                flash ("Follow Recommendations")

                if not session.get("authenticated"):
                    flash("⚠️ Please authenticate first.")
                    return redirect(url_for("index"))

                token = token_cache.get("access_token")
                if not token:
                    flash("⚠️ Missing token — please re-authenticate.")
                    return redirect(url_for("index"))
                
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
                flash("✅ AI Guardrails rule created: Block PII / Emails to AI Apps.")

                create_realtime_dlp_rule(token)
                flash("✅ Real-Time DLP rule created: Block Email Addresses and IBANs.")

            # Action: CREATE INTERNET ACCESS
            elif action == "create_internet":
                # warn
                warn = create_int_warn_policy(token)

                # isolate
                isolate = create_inet_isolate_policy(token)

                # block content
                block_content = create_int_block_content_policy(token)

                # block apps
                block_app = create_int_block_apps_policy(token)

                # allow all
                allow_all = create_allow_all_policy(token)

                flash(f"✅ Internet Access polcies successfully created.")


        except Exception as e:
            flash(f"⚠️ Error in app.py: {e}")

        return redirect(url_for("secure_access"))

    return render_template('secure-access.html')


############# App.Route Duo ##############
@app.route('/duo', methods=['GET', 'POST'])
def duo():
    if request.method == 'POST':
        # Get credentials from form
        api_hostname = request.form.get('api_hostname')
        integration_key = request.form.get('integration_key')
        secret_key = request.form.get('secret_key')
        action = request.form.get('action')

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
                    username = request.form.get(f'user_username_{i}', '').strip()
                    if email and username:
                        users_list.append({'email': email, 'username': username})

                # Validate at least one user is provided
                if not users_list:
                    flash("⚠️ Please provide at least one email and username")
                    return redirect(url_for('duo'))
                
                # Import and call the complete setup function
                from scripts.duo.duo_automation import setup_duo_complete
                
                result = setup_duo_complete(
                    api_hostname=api_hostname,
                    integration_key=integration_key,
                    secret_key=secret_key,
                    users_list=users_list
                )
                
                # Display results
                for user in result['users_created']:
                    flash(f"✅ User '{user['username']}' created (ID: {user['user_id']})")

                for user in result['users_existing']:
                    flash(f"ℹ️ User '{user['username']}' already exists (ID: {user['user_id']})")

                if result['group_created']:
                    flash(f"✅ Group 'PoC Users' created (ID: {result['group_id']})")
                else:
                    flash(f"ℹ️ Using existing 'PoC Users' group (ID: {result['group_id']})")

                if result['users_added_to_group'] > 0:
                    flash(f"✅ {result['users_added_to_group']} user(s) added to 'PoC Users' group")
                
                # Next step: enrollment guidance
                if result['users_created']:
                    flash("📋 Next step: Go to the Duo Admin Dashboard → Users and share the enrollment link and code with the user. Enrollment works best in an incognito window.")

                # Display any errors
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
                    flash("✅ Global Policy configured — New User Policy set to require enrollment, authentication methods set to recommended only, risk-based factor selection disabled")
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
                    if result.get('already_exists'):
                        flash(f"ℹ️ SAML App already exists — Integration Key: {app_ikey}")
                    else:
                        flash(f"✅ SAML App created — Integration Key: {app_ikey}")

                    if result.get('sso_error'):
                        flash(f"⚠️ SSO config could not be set via API: {result['sso_error']}. You may need to configure ACS URL and Entity ID manually in the Duo Admin Panel.")

                    # Try to auto-configure the SAML app with Duo IdP metadata
                    meta_result = get_integration_metadata_url(
                        api_hostname, integration_key, secret_key, app_ikey
                    )
                    if meta_result['success'] and meta_result['metadata_url']:
                        push_result = fetch_and_push_idp_metadata(
                            meta_result['metadata_url'], sp_base_url
                        )
                        if push_result['success']:
                            flash(f"✅ SAML App auto-configured with Duo IdP metadata — ready to test!")
                            session['saml_app_configured'] = True
                        else:
                            flash(f"⚠️ Could not auto-configure SAML app: {push_result['error']}. Download the IdP metadata XML from Duo and upload it manually.")
                            session['saml_app_configured'] = False
                    else:
                        flash(f"⚠️ Could not retrieve metadata URL from Duo. Download the IdP metadata XML from the Duo Admin Panel and upload it to the SAML app.")
                        session['saml_app_configured'] = False

                    session['saml_app_ikey'] = app_ikey
                else:
                    flash(f"⚠️ {result['error']}")

        except Exception as e:
            flash(f"⚠️ Error: {str(e)}")
        
        return redirect(url_for('duo'))
    
    return render_template('duo.html')


@app.route('/cilium', methods=['GET', 'POST'])
def cilium():
    from scripts.cilium_policies import apply_zero_trust, apply_allow_all, get_active_policies

    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == 'allow_all':
                results = apply_allow_all()
            elif action == 'zero_trust':
                results = apply_zero_trust()
            else:
                results = []
            for msg in results:
                flash(f"✅ {msg}")
        except Exception as e:
            flash(f"⚠️ Error applying Cilium policy: {e}")
        return redirect(url_for('cilium'))

    active_policies = []
    policy_error = None
    try:
        active_policies = get_active_policies()
    except Exception as e:
        policy_error = str(e)

    return render_template('cilium.html', active_policies=active_policies, policy_error=policy_error)

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

@app.route('/caldera', methods=['GET', 'POST'])
def caldera():
    from scripts.caldera import (is_available, is_deployed, get_agents, get_operations,
                                  setup_demo_adversaries, get_demo_adversaries,
                                  cleanup_stale_agents)

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'deploy_caldera':
            from scripts.caldera import deploy_caldera
            try:
                deploy_caldera()
                flash("✅ Caldera deployed — allow ~60 s for the C2 server to start.")
            except Exception as e:
                flash(f"⚠️ Deployment failed: {e}")
        elif action == 'setup_demo':
            try:
                msgs = setup_demo_adversaries()
                for m in msgs:
                    flash(f"✅ {m}")
            except Exception as e:
                flash(f"⚠️ Setup failed: {e}")
        elif action == 'run_operation':
            from scripts.caldera import run_operation
            adversary_id = request.form.get('adversary_id', '').strip()
            op_name = request.form.get('op_name', 'PoC Attack').strip()
            try:
                op = run_operation(op_name, adversary_id)
                flash(f"⚔️ '{op_name}' launched — watch Tetragon below for detections!")
            except Exception as e:
                flash(f"⚠️ Failed to launch: {e}")
        return redirect(url_for('caldera'))

    caldera_deployed = is_deployed()
    caldera_available = is_available()
    agents, operations, demo_scenarios = [], [], []
    if caldera_available:
        try:
            cleanup_stale_agents()
            agents = get_agents()
        except Exception:
            pass
        try:
            operations = get_operations()
        except Exception:
            pass
        try:
            demo_scenarios = get_demo_adversaries()
        except Exception:
            pass

    return render_template('caldera.html',
                           caldera_deployed=caldera_deployed,
                           caldera_available=caldera_available,
                           agents=agents,
                           operations=operations,
                           demo_scenarios=demo_scenarios)


@app.route('/caldera/status')
def caldera_status():
    from flask import jsonify
    from scripts.caldera import is_available, get_operations
    import requests as _requests, os as _os
    if not is_available():
        return jsonify({"error": "Caldera offline"})
    try:
        caldera_url = _os.environ.get("CALDERA_URL", "http://caldera.piap.svc.cluster.local:8888")
        api_key = _os.environ.get("CALDERA_API_KEY", "ADMIN123")
        r = _requests.get(f"{caldera_url}/api/v2/agents",
                          headers={"KEY": api_key, "Content-Type": "application/json"},
                          timeout=5)
        r.raise_for_status()
        all_agents = r.json()
        return jsonify({
            "agents": all_agents,
            "operations": get_operations(),
        })
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route('/splunk', methods=['GET', 'POST'])
def splunk():
    from scripts.splunk import (
        is_available, hec_is_healthy,
        SPLUNKBASE_APPS, get_splunkbase_app_status,
    )

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'deploy_collectord':
            from scripts.splunk import deploy_collectord
            outcold_license = request.form.get('outcold_license', '').strip()
            if not outcold_license:
                flash("An Outcold Solutions license key is required. Request one at outcoldsolutions.com/pricing.")
            else:
                try:
                    deploy_collectord(outcold_license)
                    flash("Collectord deployed — DaemonSet rolling out to all nodes.")
                except Exception as e:
                    flash(f"Collectord deployment failed: {e}")
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
            sb_user = request.form.get('splunkbase_username', '').strip()
            sb_pass = request.form.get('splunkbase_password', '').strip()
            app_name = next((a['display'] for a in SPLUNKBASE_APPS if str(a['id']) == app_id), app_id)
            if not app_id or not sb_user or not sb_pass:
                flash("App ID, Splunk.com username, and password are all required.")
            else:
                try:
                    install_splunkbase_app(int(app_id), sb_user, sb_pass)
                    flash(f"{app_name} installed — restart Splunk to activate.")
                except Exception as e:
                    flash(f"Install failed: {e}")
            return redirect(url_for('splunk'))

    splunk_available = is_available()
    app_status = get_splunkbase_app_status() if splunk_available else {}

    from scripts.splunk import get_collectord_status
    collectord_status = get_collectord_status()

    return render_template(
        'splunk.html',
        splunk_available=splunk_available,
        hec_healthy=hec_is_healthy() if splunk_available else False,
        server_ip=request.host.split(':')[0],
        splunkbase_apps=SPLUNKBASE_APPS,
        app_status=app_status,
        collectord_status=collectord_status,
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