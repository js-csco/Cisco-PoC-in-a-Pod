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

        return redirect(url_for("secure-access"))

    return render_template('secure-access.html')


@app.route('/duo')
def duo():
    return render_template('duo.html')

@app.route('/cilium')
def cilium():
    return render_template('cilium.html')

@app.route('/tetragon')
def tetragon():
    return render_template('tetragon.html')

@app.route('/splunk')
def splunk():
    return render_template('splunk.html')

@app.route('/help')
def help_page():
    return render_template('help.html')



if __name__ == "__main__":
    # Run Flask on port 9100 and listen on all interfaces
    app.run(host="0.0.0.0", port=8080, debug=True)