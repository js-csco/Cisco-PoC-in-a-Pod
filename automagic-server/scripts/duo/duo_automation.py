"""
Duo Admin API Automation
Creates users, groups, manages group membership, and creates integrations for PoC environments
"""

import json
import duo_client


def check_credentials(api_hostname, integration_key, secret_key):
    """Verify Duo Admin API credentials. Raises on failure."""
    admin = duo_client.Admin(
        ikey=integration_key,
        skey=secret_key,
        host=api_hostname,
    )
    admin.get_info_summary()


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
        users_list: List of dicts with 'username' and 'email' keys
                   e.g., [{'username': 'user1', 'email': 'user1@example.com'}]
    
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
        
        print(f"Processing user: {username} with email: {email}")
        
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
                result['users_existing'].append({
                    'username': username,
                    'email': email,
                    'user_id': user_id
                })
                print(f"ℹ️  User already exists: {username} (ID: {user_id})")
            else:
                # Create new user
                print(f"Creating new user: {username}")
                user_response = admin_api.add_user(
                    username=username,
                    email=email,
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


def create_integration(api_hostname, integration_key, secret_key, name, integration_type, group_name="PoC Users"):
    """
    Create a new integration and assign it to a group
    
    Args:
        api_hostname: Duo API hostname
        integration_key: Duo integration key
        secret_key: Duo secret key
        name: Name of the integration
        integration_type: Type of integration (e.g., 'sso-cisco-secure-access', 'sso-generic')
        group_name: Name of the group to assign (default: 'PoC Users')
    
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
        
        # Step 2: Create the integration
        print(f"Step 2: Creating integration with type '{integration_type}'")
        
        integration_response = admin_api.json_api_call(
            'POST',
            '/admin/v3/integrations',
            {
                'name': name,
                'type': integration_type,
                'user_access': 'PERMITTED_GROUPS',
                'groups_allowed': [group_id]
            }
        )
        
        result['success'] = True
        result['integration_key'] = integration_response.get('integration_key')
        result['secret_key'] = integration_response.get('secret_key')
        result['integration_id'] = integration_response.get('integration_id')
        
        print(f"✅ Integration created successfully")
        print(f"   Name: {name}")
        print(f"   Type: {integration_type}")
        print(f"   Integration Key: {result['integration_key']}")
        print(f"   Integration ID: {result['integration_id']}")
        print(f"   Group Assigned: {group_name}")
        
        return result
    
    except Exception as e:
        error_msg = f"Failed to create integration: {str(e)}"
        print(f"❌ {error_msg}")
        result['error'] = error_msg
        return result