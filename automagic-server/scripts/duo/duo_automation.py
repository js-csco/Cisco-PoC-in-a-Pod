"""
Duo Admin API Automation
Creates users, groups, and manages group membership for PoC environments
"""

import duo_client


def create_user_and_group(api_hostname, integration_key, secret_key, username, email):
    """
    Complete workflow: Create user, create 'PoC Users' group, and add user to group
    
    Args:
        api_hostname: Duo API hostname (e.g., api-xxxxx.duosecurity.com)
        integration_key: Duo integration key
        secret_key: Duo secret key
        username: Username for the new user
        email: Email for the new user
    
    Returns:
        dict: Contains user_id, group_id, and success status
    """
    # Initialize Duo Admin API client
    admin_api = duo_client.Admin(
        ikey=integration_key,
        skey=secret_key,
        host=api_hostname
    )
    
    result = {
        'user_created': False,
        'group_created': False,
        'user_added_to_group': False,
        'user_id': None,
        'group_id': None,
        'username': username,
        'email': email
    }
    
    try:
        # Step 1: Create the user
        user_response = admin_api.add_user(
            username=username,
            email=email,
            status='active'  # User is active by default
        )
        result['user_id'] = user_response.get('user_id')
        result['user_created'] = True
        print(f"✅ User created: {username} (ID: {result['user_id']})")
        
    except Exception as e:
        print(f"⚠️ Error creating user: {e}")
        raise Exception(f"Failed to create user: {str(e)}")
    
    try:
        # Step 2: Check if 'PoC Users' group exists, if not create it
        groups = admin_api.get_groups()
        poc_group = None
        
        for group in groups:
            if group.get('name') == 'PoC Users':
                poc_group = group
                result['group_id'] = group.get('group_id')
                print(f"ℹ️ Group 'PoC Users' already exists (ID: {result['group_id']})")
                break
        
        # Create group if it doesn't exist
        if not poc_group:
            group_response = admin_api.add_group(
                name='PoC Users',
                desc='Proof of Concept test users group'
            )
            result['group_id'] = group_response.get('group_id')
            result['group_created'] = True
            print(f"✅ Group created: PoC Users (ID: {result['group_id']})")
        
    except Exception as e:
        print(f"⚠️ Error with group: {e}")
        raise Exception(f"Failed to create/find group: {str(e)}")
    
    try:
        # Step 3: Add user to 'PoC Users' group
        admin_api.update_user(
            user_id=result['user_id'],
            groups=[result['group_id']]
        )
        result['user_added_to_group'] = True
        print(f"✅ User {username} added to 'PoC Users' group")
        
    except Exception as e:
        print(f"⚠️ Error adding user to group: {e}")
        raise Exception(f"Failed to add user to group: {str(e)}")
    
    return result


def create_passwordless_enrollment(api_hostname, integration_key, secret_key):
    """
    Configure passwordless enrollment policy
    
    Note: This may require manual configuration in Duo Admin Panel
    as not all enrollment settings are available via API
    """
    admin_api = duo_client.Admin(
        ikey=integration_key,
        skey=secret_key,
        host=api_hostname
    )
    
    # TODO: Implement passwordless enrollment configuration
    # This might need to be done through the Duo Admin Panel UI
    print("ℹ️ Passwordless enrollment may require manual configuration in Duo Admin Panel")
    return {'status': 'manual_configuration_required'}


def create_authentication_policy(api_hostname, integration_key, secret_key):
    """
    Create authentication policy for PoC users
    
    Note: Authentication policies are typically configured in the Duo Admin Panel
    """
    admin_api = duo_client.Admin(
        ikey=integration_key,
        skey=secret_key,
        host=api_hostname
    )
    
    # TODO: Implement authentication policy creation
    # This might need to be done through the Duo Admin Panel UI
    print("ℹ️ Authentication policy may require manual configuration in Duo Admin Panel")
    return {'status': 'manual_configuration_required'}


def create_saml_integration(api_hostname, integration_key, secret_key):
    """
    Create Cisco Secure Access SAML integration
    
    Note: SAML integrations typically require manual configuration
    """
    admin_api = duo_client.Admin(
        ikey=integration_key,
        skey=secret_key,
        host=api_hostname
    )
    
    # TODO: Implement SAML integration creation
    # This will likely need manual configuration in Duo Admin Panel
    print("ℹ️ SAML integration requires manual configuration in Duo Admin Panel")
    return {'status': 'manual_configuration_required'}