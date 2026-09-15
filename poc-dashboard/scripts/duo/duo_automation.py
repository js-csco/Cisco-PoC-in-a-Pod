"""
Duo Admin API Automation
Creates users, groups, manages group membership, and creates integrations for PoC environments
"""

import json
import re
import requests
import duo_client


def derive_name_fields(email, username=None):
    """Derive human-name fields from an email address (or username).

    Duo pushes users to Cisco Secure Access via SCIM, where the attribute
    mapping is:

        Duo attribute  ->  SCIM / application attribute
        realname       ->  displayName
        firstname      ->  name.givenName
        lastname       ->  name.familyName
        username       ->  userName
        email          ->  emails

    The dashboard only collects an email address, so without deriving these
    name fields the user arrives in Secure Access with an empty display name and
    no given/family name. We split the email's local part on common separators
    (``.  _  -  +``) to produce sensible values, e.g. ``john.doe@corp.com`` ->
    firstname "John", lastname "Doe", realname "John Doe".

    Returns a dict with ``firstname``, ``lastname`` and ``realname`` keys.
    """
    local = (email or username or "").split("@")[0]
    parts = [p for p in re.split(r"[._\-+]+", local) if p]

    if len(parts) >= 2:
        firstname = parts[0].capitalize()
        lastname = " ".join(p.capitalize() for p in parts[1:])
    elif len(parts) == 1:
        firstname = parts[0].capitalize()
        lastname = ""
    else:
        firstname = ""
        lastname = ""

    realname = " ".join(p for p in (firstname, lastname) if p).strip()
    if not realname:
        realname = local or (email or username or "")

    return {"firstname": firstname, "lastname": lastname, "realname": realname}


def check_credentials(api_hostname, integration_key, secret_key):
    """Verify Duo Admin API credentials. Raises on failure."""
    admin = duo_client.Admin(
        ikey=integration_key,
        skey=secret_key,
        host=api_hostname,
    )
    admin.get_info_summary()


def assign_group_to_secure_access_app(api_hostname, integration_key, secret_key,
                                      group_id=None, group_name="PoC Users"):
    """Permit a Duo group on the Cisco Secure Access SSO application.

    Since March 2025 new Duo applications deny all users by default
    (``user_access = NO_USERS``), so the Cisco Secure Access app blocks the PoC
    users until a permitted group is added. This finds that SSO application and
    sets ``user_access = PERMITTED_GROUPS`` with ``group_id`` merged into the
    app's existing ``groups_allowed`` (merge, not overwrite, so any groups an
    admin already added are preserved).

    The Cisco Secure Access app is created by the admin (it can't be created via
    the v1/v2 API), so this is best-effort: if it doesn't exist yet the result
    reports ``found=False`` without raising.

    Returns a dict with keys: success, found, integration_key, name,
    groups_allowed, error.
    """
    admin_api = duo_client.Admin(
        ikey=integration_key,
        skey=secret_key,
        host=api_hostname,
    )
    result = {'success': False, 'found': False, 'integration_key': None,
              'name': None, 'groups_allowed': None, 'error': None}

    # Resolve the group ID from its name if not supplied.
    if not group_id:
        for g in admin_api.get_groups():
            if g.get('name') == group_name:
                group_id = g.get('group_id')
                break
        if not group_id:
            result['error'] = f"Group '{group_name}' not found."
            return result

    # Locate the Cisco Secure Access SSO application among the integrations.
    integrations = admin_api.json_api_call('GET', '/admin/v3/integrations', {})
    integrations = integrations if isinstance(integrations, list) else []

    def _is_secure_access(intg):
        name = (intg.get('name') or '').lower()
        itype = (intg.get('type') or '').lower()
        return 'secure-access' in itype or 'secure access' in name

    target = next((i for i in integrations if _is_secure_access(i)), None)
    if not target:
        result['error'] = ("Cisco Secure Access application not found in Duo. "
                           "Create it under Applications first, then re-run.")
        return result

    ikey = target.get('integration_key')
    result['integration_key'] = ikey
    result['name'] = target.get('name')

    # Read the app's current permitted groups so we merge instead of overwrite.
    try:
        detail = admin_api.json_api_call('GET', f'/admin/v3/integrations/{ikey}', {})
    except Exception:
        detail = target
    existing = detail.get('groups_allowed') or []
    group_ids = []
    for g in existing:
        gid = g.get('group_id') if isinstance(g, dict) else g
        if gid is not None and str(gid) not in group_ids:
            group_ids.append(str(gid))
    if str(group_id) not in group_ids:
        group_ids.append(str(group_id))

    admin_api.json_api_call('PUT', f'/admin/v3/integrations/{ikey}', {
        'user_access': 'PERMITTED_GROUPS',
        'groups_allowed': group_ids,
    })

    result['success'] = True
    result['found'] = True
    result['groups_allowed'] = group_ids
    print(f"✅ Permitted group '{group_name}' on Cisco Secure Access app "
          f"'{result['name']}' (groups_allowed={group_ids})")
    return result


def setup_duo_complete(api_hostname, integration_key, secret_key, users_list):
    """
    Complete Duo setup workflow:
    - Create all users
    - Create 'PoC Users' group
    - Add all users to group
    
    Args:
        api_hostname: Duo API hostname (e.g., api-xxxxx.duosecurity.com)
        integration_key: Duo integration key
        secret_key: Duo secret key
        users_list: List of dicts with 'username' and 'email' keys.
                   Email address is used as the username so both fields hold the
                   same value, e.g. [{'username': 'u@example.com', 'email': 'u@example.com'}]
    
    Returns:
        dict: Contains user_ids, group_id, and success status
    """
    print(f"\n========================================")
    print(f"Starting Duo Setup")
    print(f"API Hostname: {api_hostname}")
    print(f"Users to process: {len(users_list)}")
    print(f"Users list: {users_list}")
    print(f"========================================\n")
    
    # Initialize Duo Admin API client
    try:
        admin_api = duo_client.Admin(
            ikey=integration_key,
            skey=secret_key,
            host=api_hostname
        )
        print(f"✅ Duo Admin API client initialized successfully")
    except Exception as e:
        error_msg = f"Failed to initialize Duo Admin API client: {str(e)}"
        print(f"❌ {error_msg}")
        raise Exception(error_msg)
    
    result = {
        'users_created': [],
        'users_existing': [],
        'group_created': False,
        'group_id': None,
        'users_added_to_group': 0,
        'errors': []
    }
    
    # Step 1: Create all users
    print(f"\n=== STEP 1: Creating {len(users_list)} users ===")
    for user_data in users_list:
        username = user_data['username']
        email = user_data['email']
        
        print(f"Processing user: {email}")

        # Derive the name fields Secure Access expects via SCIM (displayName,
        # name.givenName, name.familyName) from the email address.
        names = derive_name_fields(email, username)

        try:
            # Check if user already exists
            print(f"Checking if user exists: {username}")
            existing_users = admin_api.json_api_call(
                'GET',
                '/admin/v1/users',
                {'username': username}
            )
            
            if existing_users and len(existing_users) > 0:
                user_id = existing_users[0].get('user_id')
                # Backfill the name fields so existing users (possibly created
                # before this fix, or by hand) also sync correctly to Secure
                # Access. update_user is idempotent.
                try:
                    admin_api.update_user(
                        user_id=user_id,
                        email=email,
                        realname=names['realname'],
                        firstname=names['firstname'],
                        lastname=names['lastname'],
                    )
                    print(f"✅ Updated name attributes for existing user: {username}")
                except Exception as e:
                    print(f"⚠️  Could not update name attributes for {username}: {e}")
                    result['errors'].append(f"Name update failed for {username}: {str(e)}")
                result['users_existing'].append({
                    'username': username,
                    'email': email,
                    'user_id': user_id
                })
                print(f"ℹ️  User already exists: {username} (ID: {user_id})")
            else:
                # Create new user with the full set of attributes Secure Access
                # needs (realname -> displayName, firstname -> name.givenName,
                # lastname -> name.familyName, username -> userName).
                print(f"Creating new user: {username}")
                user_response = admin_api.add_user(
                    username=username,
                    email=email,
                    realname=names['realname'],
                    firstname=names['firstname'],
                    lastname=names['lastname'],
                    status='active'
                )
                user_id = user_response.get('user_id')
                result['users_created'].append({
                    'username': username,
                    'email': email,
                    'user_id': user_id
                })
                print(f"✅ User created: {username} (ID: {user_id})")
                
                # Send enrollment email
                try:
                    admin_api.json_api_call(
                        'POST',
                        '/admin/v1/users/enroll',
                        {
                            'username': username,
                            'email': email,
                            'valid_secs': '86400'  # 24 hours
                        }
                    )
                    print(f"✅ Enrollment email sent to {email}")
                except Exception as e:
                    print(f"⚠️  Could not send enrollment email to {email}: {e}")
                    result['errors'].append(f"Enrollment email failed for {username}: {str(e)}")
        
        except Exception as e:
            error_msg = f"Failed to create user {username}: {str(e)}"
            print(f"❌ {error_msg}")
            result['errors'].append(error_msg)
    
    # Collect all user IDs (both created and existing)
    all_user_ids = []
    for user in result['users_created'] + result['users_existing']:
        all_user_ids.append(user['user_id'])
    
    print(f"\nTotal users processed: Created={len(result['users_created'])}, Existing={len(result['users_existing'])}")
    print(f"Total user IDs collected: {len(all_user_ids)}")
    
    if not all_user_ids:
        error_msg = "No users were created or found. Cannot proceed with group creation."
        print(f"❌ {error_msg}")
        result['errors'].append(error_msg)
        return result
    
    # Step 2: Create 'PoC Users' group
    print(f"\n=== STEP 2: Creating 'PoC Users' group ===")
    try:
        groups = admin_api.get_groups()
        poc_group = None
        
        for group in groups:
            if group.get('name') == 'PoC Users':
                poc_group = group
                result['group_id'] = group.get('group_id')
                result['group_created'] = False
                print(f"ℹ️  Group 'PoC Users' already exists (ID: {result['group_id']})")
                break
        
        if not poc_group:
            group_response = admin_api.json_api_call(
                'POST',
                '/admin/v1/groups',
                {
                    'name': 'PoC Users',
                    'desc': 'Proof of Concept test users group'
                }
            )
            result['group_id'] = group_response.get('group_id')
            result['group_created'] = True
            print(f"✅ Group created: PoC Users (ID: {result['group_id']})")
    
    except Exception as e:
        error_msg = f"Failed to create/find group: {str(e)}"
        print(f"❌ {error_msg}")
        result['errors'].append(error_msg)
        raise Exception(error_msg)
    
    # Step 3: Add all users to 'PoC Users' group
    print(f"\n=== STEP 3: Adding users to 'PoC Users' group ===")
    for user_id in all_user_ids:
        try:
            # Check if user is already in group
            user_groups = admin_api.json_api_call(
                'GET',
                f'/admin/v1/users/{user_id}/groups',
                {}
            )
            
            already_in_group = any(g.get('group_id') == result['group_id'] for g in user_groups)
            
            if not already_in_group:
                admin_api.add_user_group(
                    user_id=user_id,
                    group_id=result['group_id']
                )
                result['users_added_to_group'] += 1
                print(f"✅ User {user_id} added to 'PoC Users' group")
            else:
                print(f"ℹ️  User {user_id} already in 'PoC Users' group")
        
        except Exception as e:
            error_msg = f"Failed to add user {user_id} to group: {str(e)}"
            print(f"⚠️  {error_msg}")
            result['errors'].append(error_msg)

    # Step 4: Permit the 'PoC Users' group on the Cisco Secure Access SSO app.
    # New Duo apps deny all users by default, so add the group if the app
    # already exists. Best-effort: if the app hasn't been created yet, just
    # report it (non-fatal) so the admin can re-run after creating it.
    print(f"\n=== STEP 4: Adding 'PoC Users' group to Cisco Secure Access application ===")
    try:
        sa_result = assign_group_to_secure_access_app(
            api_hostname, integration_key, secret_key,
            group_id=result['group_id'], group_name='PoC Users'
        )
        result['secure_access_app'] = sa_result
        if sa_result['success']:
            print(f"✅ 'PoC Users' permitted on Cisco Secure Access app "
                  f"'{sa_result['name']}'")
        elif not sa_result['found']:
            # Not created yet — informational, not an error.
            print(f"ℹ️  {sa_result['error']}")
        else:
            print(f"⚠️  {sa_result['error']}")
            result['errors'].append(sa_result['error'])
    except Exception as e:
        msg = f"Failed to assign group to Cisco Secure Access app: {str(e)}"
        print(f"⚠️  {msg}")
        result['errors'].append(msg)
        result['secure_access_app'] = {'success': False, 'found': False, 'error': msg}

    return result


def configure_global_policy(api_hostname, integration_key, secret_key):
    """
    Configure the Global Policy via Duo Admin API v2:
    - New User Policy: require enrollment
    - Authentication methods: recommended only
      - 2FA: webauthn-platform, webauthn-roaming, duo-push
      - Passwordless SSO: webauthn-platform-pwl, webauthn-roaming-pwl, duo-push-pwl
    - Blocked: desktop, duo-passcode, phonecall, hardware-token, sms
    - Risk-based Factor Selection: disabled
    - User Location: left as default (no change)

    Returns:
        dict with 'success', 'before', 'after', and 'error' keys
    """
    admin_api = duo_client.Admin(
        ikey=integration_key,
        skey=secret_key,
        host=api_hostname
    )

    result = {
        'success': False,
        'before': None,
        'after': None,
        'error': None
    }

    try:
        # Step 1: Retrieve the current global policy
        print("\n=== Configuring Global Policy ===")
        print("Step 1: Retrieving current global policy...")

        current_policy = admin_api.get_policy_v2("global")
        result['before'] = current_policy
        pretty_before = json.dumps(current_policy, indent=2, sort_keys=True, default=str)
        print(f"Current global policy:\n{pretty_before}")

        # Step 2: Update global policy sections
        print("\nStep 2: Updating global policy (new user policy, auth methods, risk-based factor selection)...")

        json_request = {
            "sections": {
                "new_user": {
                    "new_user_behavior": "enroll",
                },
                "authentication_methods": {
                    "allowed_auth_list": [
                        "duo-push",
                        "webauthn-platform",
                        "webauthn-roaming",
                        "duo-push-pwl",
                        "webauthn-platform-pwl",
                        "webauthn-roaming-pwl",
                    ],
                    "blocked_auth_list": [
                        "desktop",
                        "duo-passcode",
                        "phonecall",
                        "hardware-token",
                        "sms",
                    ],
                },
                "risk_based_factor_selection": {
                    "limit_to_risk_based_auth_methods": False,
                },
            },
        }

        print(f"Update request:\n{json.dumps(json_request, indent=2)}")

        updated_policy = admin_api.update_policy_v2("global", json_request)
        result['after'] = updated_policy
        result['success'] = True

        pretty_after = json.dumps(updated_policy, indent=2, sort_keys=True, default=str)
        print(f"\n✅ Global policy updated successfully")
        print(f"Updated policy:\n{pretty_after}")

    except Exception as e:
        error_msg = f"Failed to configure global policy: {str(e)}"
        print(f"❌ {error_msg}")
        result['error'] = error_msg

    return result


def list_integrations(api_hostname, integration_key, secret_key):
    """
    List all integrations in the Duo account
    
    Args:
        api_hostname: Duo API hostname
        integration_key: Duo integration key
        secret_key: Duo secret key
    
    Returns:
        list: List of integration objects
    """
    admin_api = duo_client.Admin(
        ikey=integration_key,
        skey=secret_key,
        host=api_hostname
    )
    
    try:
        # Get all integrations using the v3 API endpoint
        integrations = admin_api.json_api_call(
            'GET',
            '/admin/v3/integrations',
            {}
        )
        
        print(f"\n=== INTEGRATIONS LIST ===")
        print(f"Found {len(integrations)} integration(s)")
        for integration in integrations:
            print(f"  • {integration.get('name')} (Type: {integration.get('type')}, Key: {integration.get('integration_key')})")
        
        return integrations
    
    except Exception as e:
        print(f"❌ Error listing integrations: {e}")
        return []


def create_integration(api_hostname, integration_key, secret_key, name, integration_type, group_name="PoC Users", sso_config=None):
    """
    Create a new integration and assign it to a group.
    For SSO integrations, the sso config is included in the create call (required by v3 API).

    Args:
        api_hostname: Duo API hostname
        integration_key: Duo integration key
        secret_key: Duo secret key
        name: Name of the integration
        integration_type: Type of integration (e.g., 'sso-cisco-secure-access', 'sso-generic')
        group_name: Name of the group to assign (default: 'PoC Users')
        sso_config: Optional dict of SSO/SAML parameters for SSO integrations

    Returns:
        dict: Integration details or error
    """
    admin_api = duo_client.Admin(
        ikey=integration_key,
        skey=secret_key,
        host=api_hostname
    )

    result = {
        'success': False,
        'integration_key': None,
        'secret_key': None,
        'integration_id': None,
        'error': None
    }

    try:
        # Step 1: Find the group ID
        print(f"\n=== Creating Integration: {name} ===")
        print(f"Step 1: Finding group '{group_name}'")

        groups = admin_api.json_api_call('GET', '/admin/v1/groups', {})
        group_id = None

        for group in groups:
            if group.get('name') == group_name:
                group_id = group.get('group_id')
                print(f"✅ Found group '{group_name}' (ID: {group_id})")
                break

        if not group_id:
            error_msg = f"Group '{group_name}' not found. Please create the group first."
            print(f"❌ {error_msg}")
            result['error'] = error_msg
            return result

        # Step 2: Check if integration already exists
        print(f"Step 2: Checking for existing integration '{name}'")
        existing = admin_api.json_api_call('GET', '/admin/v3/integrations', {})
        for integration in (existing if isinstance(existing, list) else []):
            if integration.get('name') == name:
                existing_ikey = integration.get('integration_key')
                print(f"ℹ️  Integration '{name}' already exists (Key: {existing_ikey})")
                result['success'] = True
                result['integration_key'] = existing_ikey
                result['already_exists'] = True
                return result

        # Step 3: Create the integration (include sso.saml_config to pass validation)
        print(f"Step 3: Creating integration with type '{integration_type}'")

        create_params = {
            'name': name,
            'type': integration_type,
            'user_access': 'PERMITTED_GROUPS',
            'groups_allowed': [group_id],
        }

        if sso_config:
            create_params['sso'] = {'saml_config': sso_config}

        print(f"   Create params: {json.dumps(create_params, indent=2, default=str)}")

        integration_response = admin_api.json_api_call(
            'POST',
            '/admin/v3/integrations',
            create_params
        )

        app_ikey = integration_response.get('integration_key')
        result['success'] = True
        result['integration_key'] = app_ikey
        result['secret_key'] = integration_response.get('secret_key')
        result['integration_id'] = integration_response.get('integration_id')

        print(f"✅ Integration created successfully")
        print(f"   Name: {name}")
        print(f"   Type: {integration_type}")
        print(f"   Integration Key: {app_ikey}")
        print(f"   Integration ID: {result['integration_id']}")
        print(f"   Group Assigned: {group_name}")

        return result

    except Exception as e:
        error_msg = f"Failed to create integration: {str(e)}"
        print(f"❌ {error_msg}")
        result['error'] = error_msg
        return result


def get_integration_metadata_url(api_hostname, integration_key, secret_key, app_integration_key):
    """
    Retrieve the IdP SAML metadata URL for an SSO integration.

    Fetches integration details from the Duo Admin API v3 and extracts
    the metadata_url from the SSO configuration.

    Args:
        api_hostname: Duo API hostname
        integration_key: Admin API integration key
        secret_key: Admin API secret key
        app_integration_key: The integration key of the SSO app to query

    Returns:
        dict with 'success', 'metadata_url', and 'error' keys
    """
    admin_api = duo_client.Admin(
        ikey=integration_key,
        skey=secret_key,
        host=api_hostname,
    )

    result = {'success': False, 'metadata_url': None, 'error': None}

    try:
        print(f"\n=== Retrieving integration details for {app_integration_key} ===")
        details = admin_api.json_api_call(
            'GET',
            f'/admin/v3/integrations/{app_integration_key}',
            {}
        )

        print(f"Integration details keys: {list(details.keys()) if isinstance(details, dict) else type(details)}")
        pretty = json.dumps(details, indent=2, default=str)
        print(f"Full response:\n{pretty}")

        # Look for metadata_url in the sso section
        sso = details.get('sso', {}) if isinstance(details, dict) else {}
        metadata_url = sso.get('metadata_url', '')

        if metadata_url:
            result['success'] = True
            result['metadata_url'] = metadata_url
            print(f"✅ Found metadata URL: {metadata_url}")
        else:
            # Try to find it in other places in the response
            metadata_url = details.get('metadata_url', '')
            if metadata_url:
                result['success'] = True
                result['metadata_url'] = metadata_url
                print(f"✅ Found metadata URL (top-level): {metadata_url}")
            else:
                result['error'] = "No metadata_url found in integration details"
                print(f"⚠️ {result['error']}")

    except Exception as e:
        result['error'] = f"Failed to get integration details: {str(e)}"
        print(f"❌ {result['error']}")

    return result


def fetch_and_push_idp_metadata(metadata_url, saml_app_base_url):
    """
    Fetch IdP metadata XML from Duo and push it to the SAML app.

    Args:
        metadata_url: The Duo SSO IdP metadata URL
        saml_app_base_url: Base URL of the SAML app (e.g., http://10.10.5.66:30400)

    Returns:
        dict with 'success', 'entity_id', 'sso_url', and 'error' keys
    """
    result = {'success': False, 'entity_id': None, 'sso_url': None, 'error': None}

    try:
        # Step 1: Fetch the IdP metadata XML from Duo as raw bytes to avoid
        # charset mis-detection (requests defaults text/xml to ISO-8859-1 per
        # RFC 2616, which can corrupt the byte stream when re-encoded)
        print(f"\n=== Fetching IdP metadata from {metadata_url} ===")
        resp = requests.get(metadata_url, timeout=15)
        resp.raise_for_status()
        metadata_bytes = resp.content
        print(f"✅ Fetched metadata XML ({len(metadata_bytes)} bytes)")

        # Step 2: Push raw bytes via multipart upload — same path the browser
        # uses — avoiding any JSON string encoding/decoding of the XML
        print(f"Pushing metadata to {saml_app_base_url}/upload-idp-metadata ...")
        push_resp = requests.post(
            f"{saml_app_base_url}/upload-idp-metadata",
            files={'idp_metadata': ('idp-metadata.xml', metadata_bytes, 'application/xml')},
            timeout=10,
        )
        push_resp.raise_for_status()
        push_data = push_resp.json()

        if push_data.get('ok'):
            result['success'] = True
            result['entity_id'] = push_data.get('entity_id')
            result['sso_url'] = push_data.get('sso_url')
            print(f"✅ SAML app configured — Entity ID: {result['entity_id']}")
        else:
            result['error'] = push_data.get('error', 'Unknown error from SAML app')
            print(f"❌ {result['error']}")

    except requests.RequestException as e:
        result['error'] = f"HTTP error: {str(e)}"
        print(f"❌ {result['error']}")

    return result