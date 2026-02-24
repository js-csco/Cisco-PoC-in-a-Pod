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
    
    # NEEDS AUTHENTICATION
    if not token_cache.get("access_token"):
        session.pop("authenticated", None)

    if request.method == "POST":
        api_key = request.form.get("api_key")
        api_secret = request.form.get("api_secret")
        action = request.form.get("action")

        # NEEDS NO AUTHENTICATION
        # Goto CSA Dashboard & manual config
        if action ==  "create_profile":
            # Link to Dashboard!
            return redirect("https://dashboard.sse.cisco.com/org/8219751/secure/securityprofiles")

        # Goto Kanboard
        if action == "gotokanboard":
            # Link to Kanboard on VM IP port 8090
            return redirect("https://www.cisco.com")

        try:
            token = ensure_valid_token(api_key, api_secret)

            # Action: AUTHENTICATE
            if action == "auth":
                # 1️⃣ Authenticate
                token = get_access_token(api_key, api_secret)

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
        
        # Store credentials in session for future use
        if api_hostname and integration_key and secret_key:
            session['duo_api_hostname'] = api_hostname
            session['duo_integration_key'] = integration_key
            session['duo_secret_key'] = secret_key
        
        # Validate credentials are provided (either from form or session)
        api_hostname = api_hostname or session.get('duo_api_hostname')
        integration_key = integration_key or session.get('duo_integration_key')
        secret_key = secret_key or session.get('duo_secret_key')
        
        if not all([api_hostname, integration_key, secret_key]):
            flash("⚠️ Please provide all Duo credentials (API hostname, integration key, and secret key)")
            return redirect(url_for('duo'))
        
        try:
            # Action: SETUP DUO (Complete setup with single user)
            if action == 'setup_duo':
                email = request.form.get('user_email', '').strip()
                username = request.form.get('user_username', '').strip()
                
                # Validate user is provided
                if not email or not username:
                    flash("⚠️ Please provide both email and username")
                    return redirect(url_for('duo'))
                
                # Create user list with single user
                users_list = [{
                    'email': email,
                    'username': username
                }]
                
                # Import and call the complete setup function
                from scripts.duo.duo_automation import setup_duo_complete
                
                result = setup_duo_complete(
                    api_hostname=api_hostname,
                    integration_key=integration_key,
                    secret_key=secret_key,
                    users_list=users_list
                )
                
                # Display results
                if result['users_created']:
                    user = result['users_created'][0]
                    flash(f"✅ User '{user['username']}' created (ID: {user['user_id']})")
                
                if result['users_existing']:
                    user = result['users_existing'][0]
                    flash(f"ℹ️ User '{user['username']}' already exists (ID: {user['user_id']})")
                
                if result['group_created']:
                    flash(f"✅ Group 'PoC Users' created (ID: {result['group_id']})")
                else:
                    flash(f"ℹ️ Using existing 'PoC Users' group (ID: {result['group_id']})")
                
                if result['users_added_to_group'] > 0:
                    flash(f"✅ User added to 'PoC Users' group")
                
                # Display any errors
                if result['errors']:
                    for error in result['errors']:
                        flash(f"⚠️ {error}")
            
            # Action: GET INTEGRATIONS (list all integrations)
            elif action == 'get_integrations':
                from scripts.duo.duo_automation import list_integrations
                
                integrations = list_integrations(
                    api_hostname=api_hostname,
                    integration_key=integration_key,
                    secret_key=secret_key
                )
                
                if integrations:
                    flash(f"📋 Found {len(integrations)} integration(s):")
                    for integration in integrations:
                        name = integration.get('name', 'N/A')
                        int_type = integration.get('type', 'N/A')
                        int_key = integration.get('integration_key', 'N/A')
                        flash(f"• {name} | Type: {int_type} | Key: {int_key}")
                else:
                    flash("ℹ️ No integrations found")
            
            # Action: CREATE INTEGRATIONS
            elif action == 'create_integrations':
                from scripts.duo.duo_automation import create_integration
                
                # Create Generic SAML Integration
                saml_result = create_integration(
                    api_hostname=api_hostname,
                    integration_key=integration_key,
                    secret_key=secret_key,
                    name='PoC Secure Access - SAML and Identity',
                    integration_type='sso-generic'
                )
                
                if saml_result['success']:
                    flash(f"✅ Generic SAML integration created successfully")
                    flash(f"   Name: PoC Secure Access - SAML and Identity")
                    flash(f"   Type: sso-generic")
                    flash(f"🔑 Integration Key: {saml_result['integration_key']}")
                    flash(f"🔐 Secret Key: {saml_result['secret_key']}")
                    flash(f"🆔 Integration ID: {saml_result['integration_id']}")
                    flash(f"✅ Integration assigned to 'PoC Users' group")
                else:
                    flash(f"⚠️ Error creating integration: {saml_result['error']}")
        
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
                for r in results:
                    flash(f"✅ {r}")
                flash("Traffic mode set to: Allow All")
            elif action == 'zero_trust':
                results = apply_zero_trust()
                for r in results:
                    flash(f"✅ {r}")
                flash("Traffic mode set to: Zero Trust Application Access")
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
            elif action == 'simulate':
                from scripts.tetragon_policies import simulate_attack
                job_name = simulate_attack()
                flash(f"🚨 Attack simulation launched — Job: {job_name}")
                flash("Watch the live event stream below for Tetragon detections.")
        except Exception as e:
            flash(f"⚠️ Error: {e}")
        return redirect(url_for('tetragon'))

    active_policies = []
    policy_error = None
    try:
        active_policies = get_active_policies()
    except Exception as e:
        policy_error = str(e)

    return render_template('tetragon.html', active_policies=active_policies, policy_error=policy_error)


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
        return jsonify({"events": events[-50:], "total": len(events)})
    except Exception as e:
        return jsonify({"events": [], "error": str(e)})

@app.route('/kubectl-mcp')
def kubectl_mcp():
    return render_template('kubectl-mcp.html')

@app.route('/splunk')
def splunk():
    return render_template('splunk.html')

@app.route('/help')
def help_page():
    return render_template('help.html')



if __name__ == "__main__":
    # Run Flask on port 9100 and listen on all interfaces
    app.run(host="0.0.0.0", port=8080, debug=True)